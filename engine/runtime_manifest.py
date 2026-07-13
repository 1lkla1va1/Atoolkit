"""Deterministic runtime provenance helpers for Atoolkit runs.

The manifest is local provenance, not a cryptographic signature.  Callers may
place the authoritative copy outside the model-writable session directory via
``authority_dir`` while retaining an identical session copy for portability.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from typing import Any, Iterable

try:
    from .host_policy import authorization_scope_from_url, normalize_authorized_scopes
    from .version import __version__
except ImportError:  # pragma: no cover - direct script fallback
    from host_policy import authorization_scope_from_url, normalize_authorized_scopes
    from version import __version__


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(str(value).encode("utf-8"))


def sha256_file(path: str | pathlib.Path) -> str:
    digest = hashlib.sha256()
    with pathlib.Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json_sha256(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return sha256_bytes(payload)


def _atomic_write_json(path: pathlib.Path, value: dict[str, Any]) -> pathlib.Path:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temporary_path = pathlib.Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            directory_fd = None
        if directory_fd is not None:
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if temporary_path.exists():
            temporary_path.unlink()
    return path


def load_manifest(path: str | pathlib.Path) -> dict[str, Any]:
    manifest_path = pathlib.Path(path)
    try:
        value = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid runtime manifest {manifest_path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"runtime manifest must be an object: {manifest_path}")
    return value


def _run_git(source_root: pathlib.Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), *args],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip()


def _source_files(source_root: pathlib.Path) -> list[pathlib.Path]:
    listed = _run_git(
        source_root, "ls-files", "--cached", "--others", "--exclude-standard",
    )
    if listed:
        candidates = [source_root / line for line in listed.splitlines() if line.strip()]
    else:
        candidates = list(source_root.rglob("*"))
    excluded = {".git", "runs", "__pycache__", ".pytest_cache"}
    return sorted(
        (path for path in candidates
         if path.is_file() and not any(part in excluded for part in path.relative_to(source_root).parts)),
        key=lambda path: path.relative_to(source_root).as_posix(),
    )


def source_tree_sha256(source_root: str | pathlib.Path) -> str:
    root = pathlib.Path(source_root).resolve()
    digest = hashlib.sha256()
    for path in _source_files(root):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        try:
            content_digest = bytes.fromhex(sha256_file(path))
        except OSError:
            continue
        digest.update(content_digest)
    return digest.hexdigest()


def _instruction_records(
    values: Iterable[dict[str, Any]] | None,
    source_root: pathlib.Path,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for value in values or []:
        raw_path = pathlib.Path(str(value.get("path") or "")).expanduser()
        path = raw_path if raw_path.is_absolute() else source_root / raw_path
        resolved = path.resolve(strict=False)
        record = {
            "kind": str(value.get("kind") or "instruction"),
            "path": str(resolved),
            "exists": resolved.is_file(),
            "sha256": sha256_file(resolved) if resolved.is_file() else "",
            "injected": bool(value.get("injected", False)),
        }
        if value.get("injected_sha256"):
            record["injected_sha256"] = str(value["injected_sha256"])
            record["file_matches_injected"] = (
                bool(record["sha256"])
                and record["sha256"] == record["injected_sha256"])
        records.append(record)
    return records


def create_run_manifest(
    run_dir: str | pathlib.Path,
    *,
    mode: str,
    project: str,
    session_id: str,
    primary_target: str,
    authorized_scopes: list[str] | tuple[str, ...],
    authz: str = "",
    instruction_sources: Iterable[dict[str, Any]] | None = None,
    source_root: str | pathlib.Path | None = None,
    authority_dir: str | pathlib.Path | None = None,
) -> dict[str, Any]:
    """Create the immutable-start provenance record and write it atomically."""
    run_base = pathlib.Path(run_dir).resolve()
    run_base.mkdir(parents=True, exist_ok=True)
    manifest_path = run_base / "run_manifest.json"
    if manifest_path.is_file():
        existing = load_manifest(manifest_path)
        expected = {
            "mode": str(mode),
            "project": str(project),
            "session_id": str(session_id),
            "primary_target": str(primary_target).strip(),
        }
        mismatched = {
            key: {"existing": existing.get(key), "requested": value}
            for key, value in expected.items() if existing.get(key) != value
        }
        if mismatched:
            raise ValueError(
                f"immutable runtime manifest identity mismatch: {mismatched}")
        authority_path = pathlib.Path(
            str(existing.get("authority_path") or manifest_path)).expanduser()
        if not authority_path.is_absolute() or not authority_path.is_file():
            raise ValueError("immutable runtime manifest authority is missing")
        if load_manifest(authority_path) != existing:
            raise ValueError("immutable runtime manifest differs from authority copy")
        return existing
    source = pathlib.Path(source_root or pathlib.Path(__file__).resolve().parents[1]).resolve()
    primary_scope = authorization_scope_from_url(primary_target)
    if not primary_scope:
        raise ValueError("primary_target must be an absolute HTTP(S) URL")
    scopes = normalize_authorized_scopes([primary_scope, *list(authorized_scopes or [])])
    if not scopes:
        raise ValueError("authorized_scopes must contain at least the primary target")

    revision = _run_git(source, "rev-parse", "HEAD") or "unknown"
    git_status = _run_git(source, "status", "--porcelain=v1")
    if authority_dir is None:
        project_dir = (run_base.parent.parent
                       if run_base.parent.name == "sessions" else run_base.parent)
        authority_base = project_dir / ".atoolkit"
    else:
        authority_base = pathlib.Path(authority_dir).resolve()
    authority_path = authority_base / "manifests" / f"{session_id}.json"
    try:
        authority_path.resolve(strict=False).relative_to(run_base)
    except ValueError:
        pass
    else:
        raise ValueError("authority manifest must be outside the model-writable run directory")
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "atoolkit_version": __version__,
        "source_revision": revision,
        "source_dirty": bool(git_status),
        "source_tree_sha256": source_tree_sha256(source),
        "mode": str(mode),
        "project": str(project),
        "session_id": str(session_id),
        "primary_target": str(primary_target).strip(),
        "authorized_scopes": scopes,
        "authz_sha256": sha256_text(authz),
        "instruction_sources": _instruction_records(instruction_sources, source),
        "reporting_schema_version": 2,
        "project_state_schema_version": 1,
        "authority_path": str(authority_path),
        "created_at": _utc_now(),
    }
    _atomic_write_json(authority_path, manifest)
    if authority_path != manifest_path:
        _atomic_write_json(manifest_path, manifest)
    return manifest


def write_run_receipt(
    output_path: str | pathlib.Path,
    *,
    manifest_path: str | pathlib.Path,
    artifacts: dict[str, str | pathlib.Path],
    project_state_delta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    session_manifest = pathlib.Path(manifest_path).resolve()
    if not session_manifest.is_file():
        raise ValueError(f"manifest does not exist: {session_manifest}")
    manifest = load_manifest(session_manifest)
    manifest_file = pathlib.Path(
        str(manifest.get("authority_path") or session_manifest)).expanduser()
    if not manifest_file.is_absolute() or not manifest_file.is_file():
        raise ValueError("authoritative manifest does not exist")
    manifest_file = manifest_file.resolve()
    if manifest_file == session_manifest:
        raise ValueError("receipt cannot trust a self-authorized session manifest")
    if load_manifest(manifest_file) != manifest:
        raise ValueError("session manifest differs from authority manifest")
    artifact_records: dict[str, dict[str, Any]] = {}
    for name, raw_path in sorted(artifacts.items()):
        path = pathlib.Path(raw_path).resolve()
        if not path.is_file():
            raise ValueError(f"receipt artifact does not exist: {path}")
        artifact_records[str(name)] = {
            "path": str(path),
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
        }
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "atoolkit_version": __version__,
        "manifest_path": str(manifest_file),
        "manifest_sha256": sha256_file(manifest_file),
        "artifacts": artifact_records,
        "project_state_delta_sha256": (
            canonical_json_sha256(project_state_delta)
            if project_state_delta is not None else ""
        ),
        "created_at": _utc_now(),
    }
    receipt["receipt_sha256"] = canonical_json_sha256(receipt)
    _atomic_write_json(pathlib.Path(output_path), receipt)
    return receipt


def _file_check(path: pathlib.Path) -> dict[str, Any]:
    if not path.exists():
        return {"status": "missing", "path": str(path), "sha256": ""}
    if not path.is_file():
        return {"status": "invalid", "path": str(path), "sha256": ""}
    size = path.stat().st_size
    return {
        "status": "empty" if size == 0 else "ok",
        "path": str(path),
        "size": size,
        "sha256": sha256_file(path),
    }


def doctor(
    repo_root: str | pathlib.Path,
    *,
    codex_home: str | pathlib.Path | None = None,
) -> dict[str, Any]:
    """Inspect instruction resolution without changing user configuration."""
    root = pathlib.Path(repo_root).resolve()
    home = pathlib.Path(codex_home or pathlib.Path.home() / ".codex").expanduser().resolve()
    project_agents = _file_check(root / "AGENTS.md")
    compatibility_agents = _file_check(root / "codex" / "AGENTS.md")
    if (project_agents["status"] == compatibility_agents["status"] == "ok"
            and project_agents["sha256"] != compatibility_agents["sha256"]):
        compatibility_agents["status"] = "drift"

    global_agents = _file_check(home / "AGENTS.md")
    header_path = root / "codex" / "_agents_header.md"
    core_path = root / "skill" / "核心技能文件.v3.md"
    agents_source = {
        "status": "missing", "expected_sha256": "",
        "root_matches": False, "compatibility_matches": False,
    }
    if header_path.is_file() and core_path.is_file():
        core_lines = core_path.read_bytes().splitlines(keepends=True)
        expected = header_path.read_bytes() + b"".join(core_lines[1:])
        expected_sha = sha256_bytes(expected)
        agents_source = {
            "status": "ok",
            "expected_sha256": expected_sha,
            "root_matches": project_agents.get("sha256") == expected_sha,
            "compatibility_matches": compatibility_agents.get("sha256") == expected_sha,
        }
        if not (agents_source["root_matches"]
                and agents_source["compatibility_matches"]):
            agents_source["status"] = "drift"

    skill_path = root / "SKILL.md"
    changelog_path = root / "CHANGELOG.md"
    skill_text = skill_path.read_text(encoding="utf-8") if skill_path.is_file() else ""
    changelog_text = (changelog_path.read_text(encoding="utf-8")
                      if changelog_path.is_file() else "")
    skill_match = re.search(r"^version:\s*([^\s]+)\s*$", skill_text, re.M)
    changelog_match = re.search(r"^##\s+([^\s]+)\s+-", changelog_text, re.M)
    versions = {
        "engine": __version__,
        "skill": skill_match.group(1) if skill_match else "",
        "changelog_latest": changelog_match.group(1) if changelog_match else "",
    }
    version_consistency = {
        "status": "ok" if len(set(versions.values())) == 1 and all(versions.values()) else "drift",
        "versions": versions,
    }
    alias = home / "prompts" / "src.md"
    if not alias.exists() and not alias.is_symlink():
        src_alias = {"status": "missing", "path": str(alias), "resolved_path": ""}
    else:
        resolved = alias.resolve(strict=False)
        try:
            resolved.relative_to(root)
            status = "project"
        except ValueError:
            status = "foreign"
        src_alias = {
            "status": status,
            "path": str(alias),
            "resolved_path": str(resolved),
            "symlink": alias.is_symlink(),
        }
    checks = {
        "project_agents": project_agents,
        "compatibility_agents": compatibility_agents,
        "agents_source_consistency": agents_source,
        "version_consistency": version_consistency,
        "global_agents": global_agents,
        "src_alias": src_alias,
    }
    fatal = (
        project_agents["status"] != "ok"
        or compatibility_agents["status"] in {"invalid", "drift"}
        or agents_source["status"] != "ok"
        or version_consistency["status"] != "ok"
    )
    return {
        "schema_version": 1,
        "atoolkit_version": __version__,
        "repo_root": str(root),
        "codex_home": str(home),
        "ok": not fatal,
        "checks": checks,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Atoolkit runtime provenance utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)
    init_parser = subparsers.add_parser(
        "init-manifest", help="create the pre-network immutable run manifest")
    init_parser.add_argument("--run-dir", required=True, type=pathlib.Path)
    init_parser.add_argument("--mode", choices=["engine", "skill"], default="skill")
    init_parser.add_argument("--project", default="")
    init_parser.add_argument("--session-id", default="")
    init_parser.add_argument("--primary-target", required=True)
    init_parser.add_argument("--allow", action="append", default=[])
    init_parser.add_argument("--authz", default="")
    init_parser.add_argument("--authz-file", type=pathlib.Path)
    init_parser.add_argument("--instruction", action="append", required=True)
    init_parser.add_argument("--source-root", type=pathlib.Path)
    init_parser.add_argument("--authority-dir", type=pathlib.Path)
    receipt_parser = subparsers.add_parser(
        "receipt", help="bind final artifacts to the immutable start manifest")
    receipt_parser.add_argument("--run-dir", required=True, type=pathlib.Path)
    receipt_parser.add_argument("--manifest", type=pathlib.Path)
    receipt_parser.add_argument("--output", type=pathlib.Path)
    receipt_parser.add_argument(
        "--artifact", action="append", default=[], metavar="NAME=PATH")
    receipt_parser.add_argument("--project-state-delta", type=pathlib.Path)
    doctor_parser = subparsers.add_parser("doctor")
    doctor_parser.add_argument("repo_root", type=pathlib.Path)
    doctor_parser.add_argument("--codex-home", type=pathlib.Path)
    doctor_parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "init-manifest":
        authz = args.authz
        if args.authz_file:
            authz = args.authz_file.read_text(encoding="utf-8")
        run_dir = args.run_dir.resolve()
        authority_dir = args.authority_dir
        if authority_dir is None:
            project_dir = run_dir.parent.parent if run_dir.parent.name == "sessions" else run_dir.parent
            authority_dir = project_dir / ".atoolkit"
        instructions = []
        for value in args.instruction:
            instruction_path = pathlib.Path(value).expanduser()
            if not instruction_path.is_absolute():
                instruction_path = pathlib.Path(args.source_root or pathlib.Path.cwd()) / instruction_path
            if not instruction_path.is_file() or instruction_path.stat().st_size == 0:
                parser.error(f"injected instruction is missing or empty: {instruction_path}")
            instructions.append({
                "kind": "skill_instruction", "path": str(instruction_path),
                "injected": True,
            })
        result = create_run_manifest(
            run_dir,
            mode=args.mode,
            project=args.project or (
                run_dir.parent.parent.name if run_dir.parent.name == "sessions"
                else run_dir.parent.name),
            session_id=args.session_id or run_dir.name,
            primary_target=args.primary_target,
            authorized_scopes=args.allow or [args.primary_target],
            authz=authz,
            instruction_sources=instructions,
            source_root=args.source_root,
            authority_dir=authority_dir,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.command == "receipt":
        run_dir = args.run_dir.resolve()
        artifacts: dict[str, pathlib.Path] = {}
        for value in args.artifact:
            name, separator, raw_path = value.partition("=")
            if not separator or not name.strip() or not raw_path.strip():
                parser.error("--artifact must use NAME=PATH")
            path = pathlib.Path(raw_path).expanduser()
            artifacts[name.strip()] = path if path.is_absolute() else run_dir / path
        if not artifacts:
            for name, filename in (
                ("summary", "summary.json"),
                ("finding_validation", "finding_validation.json"),
                ("coverage_ledger", "coverage-ledger.json"),
                ("candidate_ledger", "candidate-ledger.json"),
            ):
                path = run_dir / filename
                if path.is_file():
                    artifacts[name] = path
        if not artifacts:
            parser.error("no receipt artifacts found; pass --artifact NAME=PATH")
        delta = None
        if args.project_state_delta:
            delta = json.loads(args.project_state_delta.read_text(encoding="utf-8"))
        result = write_run_receipt(
            args.output or run_dir / "run_receipt.json",
            manifest_path=args.manifest or run_dir / "run_manifest.json",
            artifacts=artifacts,
            project_state_delta=delta,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    if args.command == "doctor":
        result = doctor(args.repo_root, codex_home=args.codex_home)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["ok"] else 1
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "canonical_json_sha256",
    "create_run_manifest",
    "doctor",
    "load_manifest",
    "sha256_file",
    "source_tree_sha256",
    "write_run_receipt",
]
