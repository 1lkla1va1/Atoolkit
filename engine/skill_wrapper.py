"""External wrapper for a verifiable Skill-mode run.

Direct Skill use remains a useful diagnostic mode, but it cannot establish an
independent authority.  This wrapper owns init -> constrained agent -> stop ->
finalize and only accepts a Codex subprocess whose workspace root is the run
directory.
"""
from __future__ import annotations

import argparse
import inspect
import json
import os
import pathlib
import signal
import subprocess
import time
from typing import Any

try:  # Support both package import and ``python engine/skill_wrapper.py``.
    from .finalize import finalize_run
    from .run_authority import (
        create_run_plan,
        ensure_project_identity,
        run_plan_path,
        validate_session_id,
    )
    from .runtime_manifest import create_run_manifest
except ImportError:  # pragma: no cover - exercised by subprocess CLI tests
    from finalize import finalize_run
    from run_authority import (
        create_run_plan,
        ensure_project_identity,
        run_plan_path,
        validate_session_id,
    )
    from runtime_manifest import create_run_manifest


class SkillWrapperError(RuntimeError):
    pass


_FORBIDDEN_CODEX_OPTIONS = {
    "-C", "--cd", "--add-dir", "--dangerously-bypass-approvals-and-sandbox",
    "--dangerously-bypass-hook-trust", "-p", "--profile", "--profile-v2",
    "-c", "--config",
}
_SHORT_VALUE_OPTIONS = ("-C", "-p", "-c", "-s")

_PROCESS_GROUP_TERM_GRACE_SECONDS = 2.0
_PROCESS_GROUP_KILL_GRACE_SECONDS = 2.0
_PROCESS_GROUP_POLL_SECONDS = 0.02


def _process_containment_verified() -> bool:
    """Return whether this backend can contain descendants that call setsid.

    A POSIX process group is cleanup, not a containment boundary: a child may
    create a new session and outlive the saved PGID.  Until this wrapper is
    hosted by a cgroup/job/container supervisor with an attested empty state,
    Skill execution remains useful diagnostics but cannot mutate project truth
    or claim trusted delivery.
    """
    return False


def _validate_codex_command(command: list[str]) -> None:
    if not command or pathlib.Path(command[0]).name != "codex":
        raise SkillWrapperError("trusted Skill wrapper only accepts a codex exec subprocess")
    if len(command) < 2 or command[1] != "exec":
        raise SkillWrapperError("trusted Skill wrapper requires `codex exec ...`")
    for index, item in enumerate(command[2:], start=2):
        option = item.split("=", 1)[0]
        attached_short = next((
            short for short in _SHORT_VALUE_OPTIONS
            if item.startswith(short) and item != short
        ), "")
        if attached_short in _FORBIDDEN_CODEX_OPTIONS:
            raise SkillWrapperError(
                f"wrapper owns Codex trust option {attached_short}; caller cannot override it")
        if option in _FORBIDDEN_CODEX_OPTIONS:
            raise SkillWrapperError(
                f"wrapper owns Codex trust option {option}; caller cannot override it")
        sandbox_option = option in {"-s", "--sandbox"} or attached_short == "-s"
        if sandbox_option:
            if attached_short == "-s":
                value = item[len("-s"):].removeprefix("=")
            else:
                value = item.split("=", 1)[1] if "=" in item else (
                    command[index + 1] if index + 1 < len(command) else "")
            if value != "workspace-write":
                raise SkillWrapperError("wrapped Skill sandbox must be workspace-write")


def _process_group_exists(pgid: int) -> bool:
    """Probe a saved POSIX process group id; only ESRCH means quiescent."""
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # EPERM still proves that the process group exists.
        return True
    return True


def _wait_for_process_group_exit(
    pgid: int,
    *,
    leader: subprocess.Popen,
    timeout: float,
) -> bool:
    """Wait until killpg(pgid, 0) reports ESRCH.

    ``leader.poll()`` is used only to reap our direct child.  Its result is
    deliberately not a completion condition: descendants can outlive a
    successfully reaped process-group leader.
    """
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        leader.poll()
        if not _process_group_exists(pgid):
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(_PROCESS_GROUP_POLL_SECONDS, remaining))


def _quiesce_process_group(
    leader: subprocess.Popen,
    *,
    pgid: int,
) -> None:
    """TERM, then KILL, and require the complete saved group to disappear."""
    if not _process_group_exists(pgid):
        return
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError as exc:
        raise SkillWrapperError(
            f"cannot signal Codex process group {pgid} with SIGTERM: {exc}"
        ) from exc
    if _wait_for_process_group_exit(
        pgid,
        leader=leader,
        timeout=_PROCESS_GROUP_TERM_GRACE_SECONDS,
    ):
        return

    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except OSError as exc:
        raise SkillWrapperError(
            f"cannot signal Codex process group {pgid} with SIGKILL: {exc}"
        ) from exc
    if _wait_for_process_group_exit(
        pgid,
        leader=leader,
        timeout=_PROCESS_GROUP_KILL_GRACE_SECONDS,
    ):
        return
    raise SkillWrapperError(
        f"Codex process group {pgid} is still alive after SIGKILL; "
        "refusing to finalize a non-quiescent run"
    )


def _run_agent_process(command: list[str], *, cwd: pathlib.Path) -> int:
    """Wait for Codex and prove its isolated process group is quiescent."""
    child = subprocess.Popen(command, cwd=cwd, start_new_session=True)
    # start_new_session makes the child the group leader.  Save the PGID while
    # the leader is unquestionably ours; never rediscover it after leader exit.
    pgid = child.pid
    try:
        exit_code = child.wait()
    except BaseException as exc:
        try:
            _quiesce_process_group(child, pgid=pgid)
        except SkillWrapperError as cleanup_exc:
            raise cleanup_exc from exc
        raise
    _quiesce_process_group(child, pgid=pgid)
    return exit_code


def _load_admitted_cells(path: pathlib.Path | None) -> list[dict[str, Any] | str]:
    if path is None:
        return []
    value = json.loads(path.read_text(encoding="utf-8"))
    rows = value.get("surfaces") or value.get("endpoints") if isinstance(value, dict) else value
    if not isinstance(rows, list):
        raise SkillWrapperError("--inventory must contain a surfaces/endpoints list")
    return [row for row in rows if isinstance(row, (dict, str))]


def _is_within(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def run_wrapped_skill(
    *,
    run_dir: pathlib.Path,
    project_dir: pathlib.Path,
    authority_dir: pathlib.Path,
    target: str,
    project_name: str,
    command: list[str],
    inventory_path: pathlib.Path | None = None,
    base_path: str = "/",
    base_path_explicit: bool = False,
    authorized_scopes: list[str] | None = None,
    authz: str = "",
    allow_unrestricted_egress: bool = False,
) -> dict[str, Any]:
    run = run_dir.resolve()
    project = project_dir.resolve()
    authority = authority_dir.resolve()
    _validate_codex_command(command)
    try:
        session_id = validate_session_id(run.name)
    except ValueError as exc:
        raise SkillWrapperError(str(exc)) from exc
    if _is_within(authority, run) or _is_within(authority, project):
        raise SkillWrapperError("authority must be outside agent run/project writable roots")
    run.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(run, 0o700)
    authority.mkdir(parents=True, exist_ok=True, mode=0o700)

    identity = ensure_project_identity(
        authority,
        project_dir=project,
        project_name=project_name,
        primary_target=target,
        base_path=base_path,
        base_path_explicit=base_path_explicit,
    )
    cells = _load_admitted_cells(inventory_path)
    create_run_plan(
        authority,
        project_id=identity["project_id"],
        session_id=session_id,
        admitted_cells=cells,
    )
    plan_path = run_plan_path(authority, session_id)
    manifest_kwargs: dict[str, Any] = {
        "mode": "skill",
        "project": project_name,
        "session_id": session_id,
        "primary_target": target,
        "authorized_scopes": authorized_scopes or [target],
        "authz": authz,
        "authority_dir": authority,
        "run_plan_path": plan_path,
    }
    containment_verified = _process_containment_verified()
    optional = {
        "project_id": identity["project_id"],
        "base_path": base_path,
        "base_path_explicit": base_path_explicit,
        "authorization_assurance": (
            ("unrestricted_user_accepted" if allow_unrestricted_egress
             else "preexec_enforced")
            if containment_verified else "unverified"
        ),
    }
    parameters = inspect.signature(create_run_manifest).parameters
    manifest_kwargs.update({k: v for k, v in optional.items() if k in parameters})
    manifest = create_run_manifest(run, **manifest_kwargs)

    # Codex receives only the run directory as its workspace-write root.  Do
    # not enable network unless the operator explicitly accepts the downgrade.
    child = list(command)
    if "--sandbox" not in child and "-s" not in child:
        child[2:2] = ["--sandbox", "workspace-write"]
    child[2:2] = [
        "--ignore-user-config",
        "-c", "sandbox_workspace_write.network_access=false",
    ]
    if allow_unrestricted_egress:
        child.extend(["-c", "sandbox_workspace_write.network_access=true"])
    agent_exit_code = _run_agent_process(child, cwd=run)
    # subprocess.run waits for the agent process. A nonzero agent exit is still
    # finalized as diagnostics; finalizer decides delivery truth.
    assurance = (
        ("unrestricted_user_accepted" if allow_unrestricted_egress
         else "preexec_enforced")
        if containment_verified else "unverified"
    )
    delivery = finalize_run(
        run_dir=run,
        project_dir=project,
        authority_dir=authority,
        allow_empty=True,
        authority_trusted=containment_verified,
        authorization_assurance=assurance,
        project_name=project_name,
        primary_target=target,
        base_path=base_path,
        base_path_explicit=base_path_explicit,
        runtime_closure_pass=bool(
            containment_verified and agent_exit_code == 0),
        runtime_summary={
            "agent_exit_code": agent_exit_code,
            "process_containment_verified": containment_verified,
        },
    )
    delivery["agent_exit_code"] = agent_exit_code
    delivery["manifest_sha256"] = manifest.get("manifest_sha256", "")
    return delivery


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Atoolkit external Skill wrapper (diagnostic unless containment is attested)")
    parser.add_argument("--run-dir", required=True, type=pathlib.Path)
    parser.add_argument("--project-dir", required=True, type=pathlib.Path)
    parser.add_argument("--authority-dir", required=True, type=pathlib.Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--project-name", default="target")
    parser.add_argument("--inventory", type=pathlib.Path)
    parser.add_argument("--base-path", default="/")
    parser.add_argument("--base-path-explicit", action="store_true")
    parser.add_argument("--allow", action="append", default=[])
    parser.add_argument("--authz", default="")
    parser.add_argument("--allow-unrestricted-egress", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    try:
        delivery = run_wrapped_skill(
            run_dir=args.run_dir,
            project_dir=args.project_dir,
            authority_dir=args.authority_dir,
            target=args.target,
            project_name=args.project_name,
            command=command,
            inventory_path=args.inventory,
            base_path=args.base_path,
            base_path_explicit=args.base_path_explicit,
            authorized_scopes=[args.target, *args.allow],
            authz=args.authz,
            allow_unrestricted_egress=args.allow_unrestricted_egress,
        )
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"status": "error", "exit_code": 3,
                          "error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False))
        return 3
    print(json.dumps(delivery, ensure_ascii=False, indent=2))
    return int(delivery.get("exit_code", 3))


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["SkillWrapperError", "run_wrapped_skill"]
