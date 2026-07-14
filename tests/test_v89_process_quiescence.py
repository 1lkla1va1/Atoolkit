from __future__ import annotations

import os
import pathlib
import signal
import subprocess
import sys
import time

import pytest

from codex import codex_adapter
from engine import skill_wrapper


_DESCENDANT = r"""
import os
import pathlib
import signal
import sys
import time

signal.signal(signal.SIGTERM, signal.SIG_IGN)
pathlib.Path(sys.argv[1]).write_text(
    f"{os.getpid()}:{os.getpgrp()}", encoding="utf-8"
)
for fd in (1, 2):
    try:
        os.close(fd)
    except OSError:
        pass
while True:
    time.sleep(60)
"""


def _leader_command(descendant_state: pathlib.Path) -> list[str]:
    leader = f"""
import pathlib
import subprocess
import sys
import time

state = pathlib.Path({str(descendant_state)!r})
subprocess.Popen([sys.executable, "-c", {_DESCENDANT!r}, str(state)])
deadline = time.monotonic() + 5
while not state.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
if not state.exists():
    raise SystemExit(4)
"""
    return [sys.executable, "-c", leader]


def _read_descendant_state(path: pathlib.Path) -> tuple[int, int]:
    pid, pgid = path.read_text(encoding="utf-8").split(":", 1)
    return int(pid), int(pgid)


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group contract")
def test_skill_wrapper_waits_for_saved_group_after_leader_exit(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    """An exited leader must not hide a TERM-ignoring, stdout-closed child."""
    monkeypatch.setattr(skill_wrapper, "_PROCESS_GROUP_TERM_GRACE_SECONDS", 0.1)
    monkeypatch.setattr(skill_wrapper, "_PROCESS_GROUP_KILL_GRACE_SECONDS", 2.0)
    state = tmp_path / "skill-descendant.txt"

    started = time.monotonic()
    exit_code = skill_wrapper._run_agent_process(
        _leader_command(state), cwd=tmp_path
    )
    elapsed = time.monotonic() - started

    _descendant_pid, pgid = _read_descendant_state(state)
    assert exit_code == 0
    assert elapsed >= 0.08  # SIGTERM was ignored, so escalation was required.
    assert not skill_wrapper._process_group_exists(pgid)


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group contract")
def test_codex_cleanup_does_not_return_early_on_reaped_leader(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    monkeypatch.setattr(codex_adapter, "_PROCESS_GROUP_TERM_GRACE_SECONDS", 0.1)
    monkeypatch.setattr(codex_adapter, "_PROCESS_GROUP_KILL_GRACE_SECONDS", 2.0)
    state = tmp_path / "adapter-descendant.txt"
    leader = subprocess.Popen(
        _leader_command(state), cwd=tmp_path, start_new_session=True
    )
    pgid = leader.pid
    leader._atoolkit_process_group_id = pgid  # type: ignore[attr-defined]
    try:
        assert leader.wait(timeout=5) == 0
        assert leader.poll() == 0
        _descendant_pid, descendant_pgid = _read_descendant_state(state)
        assert descendant_pgid == pgid

        codex_adapter.CodexAdapter._terminate_process(leader)
        assert not codex_adapter._process_group_exists(pgid)
    finally:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group contract")
def test_non_quiescent_group_raises_instead_of_allowing_finalize(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ReapedLeader:
        def poll(self) -> int:
            return 0

    sent: list[int] = []
    monkeypatch.setattr(skill_wrapper, "_process_group_exists", lambda _pgid: True)
    monkeypatch.setattr(skill_wrapper, "_PROCESS_GROUP_TERM_GRACE_SECONDS", 0.0)
    monkeypatch.setattr(skill_wrapper, "_PROCESS_GROUP_KILL_GRACE_SECONDS", 0.0)
    monkeypatch.setattr(
        skill_wrapper.os,
        "killpg",
        lambda _pgid, sig: sent.append(sig),
    )

    with pytest.raises(skill_wrapper.SkillWrapperError, match="refusing to finalize"):
        skill_wrapper._quiesce_process_group(ReapedLeader(), pgid=424242)
    assert sent == [signal.SIGTERM, signal.SIGKILL]


def test_wrapper_does_not_call_finalizer_when_quiescence_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    finalized: list[bool] = []
    monkeypatch.setattr(
        skill_wrapper,
        "ensure_project_identity",
        lambda *_args, **_kwargs: {"project_id": "project-fixture"},
    )
    monkeypatch.setattr(skill_wrapper, "create_run_plan", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        skill_wrapper,
        "run_plan_path",
        lambda authority, session_id: authority / f"{session_id}.plan.json",
    )
    monkeypatch.setattr(
        skill_wrapper,
        "create_run_manifest",
        lambda _run, **_kwargs: {"manifest_sha256": "fixture"},
    )
    monkeypatch.setattr(
        skill_wrapper,
        "_run_agent_process",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            skill_wrapper.SkillWrapperError("process group is not quiescent")
        ),
    )
    monkeypatch.setattr(
        skill_wrapper,
        "finalize_run",
        lambda **_kwargs: finalized.append(True),
    )

    with pytest.raises(skill_wrapper.SkillWrapperError, match="not quiescent"):
        skill_wrapper.run_wrapped_skill(
            run_dir=tmp_path / "run",
            project_dir=tmp_path / "project",
            authority_dir=tmp_path / "authority",
            target="https://target.example",
            project_name="fixture",
            command=["codex", "exec"],
        )
    assert finalized == []


def test_uncontained_or_failed_agent_is_diagnostic_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
) -> None:
    captured: dict = {}
    monkeypatch.setattr(
        skill_wrapper,
        "ensure_project_identity",
        lambda *_args, **_kwargs: {"project_id": "project-fixture"},
    )
    monkeypatch.setattr(skill_wrapper, "create_run_plan", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        skill_wrapper, "run_plan_path",
        lambda authority, session_id: authority / f"{session_id}.plan.json")
    monkeypatch.setattr(
        skill_wrapper, "create_run_manifest",
        lambda _run, **_kwargs: {"manifest_sha256": "fixture"})
    monkeypatch.setattr(skill_wrapper, "_run_agent_process", lambda *_a, **_k: 7)

    def fake_finalize(**kwargs):
        captured.update(kwargs)
        return {"status": "incomplete", "exit_code": 2}

    monkeypatch.setattr(skill_wrapper, "finalize_run", fake_finalize)

    delivery = skill_wrapper.run_wrapped_skill(
        run_dir=tmp_path / "run-diag",
        project_dir=tmp_path / "project",
        authority_dir=tmp_path / "authority",
        target="https://target.example",
        project_name="fixture",
        command=["codex", "exec"],
    )

    assert delivery["agent_exit_code"] == 7
    assert captured["authority_trusted"] is False
    assert captured["authorization_assurance"] == "unverified"
    assert captured["runtime_closure_pass"] is False
    assert captured["runtime_summary"] == {
        "agent_exit_code": 7,
        "process_containment_verified": False,
    }
