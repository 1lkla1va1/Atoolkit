from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

import engine.runtime_manifest as runtime_manifest
from engine.run_authority import (
    append_monotonic_event,
    canonical_digest,
    create_run_plan,
    ensure_project_identity,
    record_target_fingerprint,
    run_plan_path,
    validate_session_id,
)
from engine.runtime_manifest import create_run_manifest, validate_manifest_binding
from engine.reporting.validate import (
    ValidationContext,
    _authority_method_resolution_gate,
)
from engine.safe_io import UnsafePathError
from engine.skill_wrapper import (
    SkillWrapperError,
    _validate_codex_command,
    run_wrapped_skill,
)


def _manifest_publish_fixture(tmp_path, session_id="manifest-race"):
    project = tmp_path / "project"
    run = project / "sessions" / session_id
    run.mkdir(parents=True)
    authority = project / ".atoolkit"
    source = tmp_path / "source"
    source.mkdir(exist_ok=True)
    (source / "SKILL.md").write_text("frozen instruction\n", encoding="utf-8")
    identity = ensure_project_identity(
        authority,
        project_dir=project,
        project_name="shop",
        primary_target="https://shop.example/",
    )
    create_run_plan(
        authority,
        project_id=identity["project_id"],
        session_id=session_id,
        admitted_cells=[],
    )
    kwargs = {
        "mode": "engine",
        "project": "shop",
        "project_id": identity["project_id"],
        "session_id": session_id,
        "primary_target": "https://shop.example/",
        "authorized_scopes": ["https://shop.example/"],
        "source_root": source,
        "authority_dir": authority,
        "run_plan_path": run_plan_path(authority, session_id),
    }
    return run, authority, source, kwargs


def _bound_manifest(tmp_path, *, method_resolution_items=(), budget=None):
    project = tmp_path / "project"
    run = project / "sessions" / "run-authority"
    run.mkdir(parents=True)
    authority = project / ".atoolkit"
    identity = ensure_project_identity(
        authority,
        project_dir=project,
        project_name="shop",
        primary_target="https://shop.example/",
    )
    create_run_plan(
        authority,
        project_id=identity["project_id"],
        session_id=run.name,
        admitted_cells=[{
            "asset": "https://shop.example:443",
            "endpoint": "/api/orders/{id}",
            "method": "GET",
            "param": "id",
            "role": "buyer",
            "vuln_class": "idor",
        }],
        method_resolution_items=method_resolution_items,
        budget=budget,
    )
    manifest = create_run_manifest(
        run,
        mode="engine",
        project="shop",
        project_id=identity["project_id"],
        session_id=run.name,
        primary_target="https://shop.example/",
        authorized_scopes=["https://shop.example/"],
        authz="authorized fixture",
        authority_dir=authority,
        run_plan_path=run_plan_path(authority, run.name),
    )
    return project, run, authority, manifest


def _context(run, manifest):
    return ValidationContext.from_manifest(
        manifest, manifest_path=run / "run_manifest.json")


@pytest.mark.parametrize("authority_input", ["manifest", "identity", "run_plan"])
def test_manifest_binding_rejects_multiply_linked_authority_inputs(
    tmp_path,
    authority_input,
):
    _project, run, authority, manifest = _bound_manifest(tmp_path)
    source = {
        "manifest": authority / "manifests" / f"{run.name}.json",
        "identity": authority / "authority_identity.json",
        "run_plan": run_plan_path(authority, run.name),
    }[authority_input]
    os.link(source, run / f"{authority_input}-alias.json")

    binding = validate_manifest_binding(
        manifest,
        run_dir=run,
        manifest_path=run / "run_manifest.json",
        authority_dir=authority,
    )

    assert binding["ok"] is False
    assert any(
        authority_input in str(item.get("code") or "")
        or authority_input in str(item.get("reason") or "")
        or "hard links" in str(item.get("reason") or "")
        for item in binding["errors"]
    )


@pytest.mark.parametrize(
    "session_id", ["HEAD", "head", "Head", "PROJECT", "project", "Project"])
def test_reserved_authority_session_names_fail_before_publication(
    tmp_path,
    session_id,
):
    project = tmp_path / "project"
    run = project / "sessions" / session_id
    authority = tmp_path / "authority"

    with pytest.raises(ValueError, match="reserved"):
        validate_session_id(session_id)
    with pytest.raises(ValueError, match="reserved"):
        create_run_plan(
            authority,
            project_id="proj_fixture",
            session_id=session_id,
            admitted_cells=[],
        )
    assert not authority.exists()

    with pytest.raises(ValueError, match="reserved"):
        create_run_manifest(
            run,
            mode="engine",
            project="fixture",
            project_id="proj_fixture",
            session_id=session_id,
            primary_target="https://t.example/",
            authorized_scopes=["https://t.example/"],
            authority_dir=authority,
        )
    assert not run.exists()
    assert not authority.exists()

    with pytest.raises(SkillWrapperError, match="reserved"):
        run_wrapped_skill(
            run_dir=run,
            project_dir=project,
            authority_dir=authority,
            target="https://t.example/",
            project_name="fixture",
            inventory_path=None,
            command=["codex", "exec", "fixture"],
        )
    assert not run.exists()
    assert not authority.exists()

    binding = validate_manifest_binding(
        {"session_id": session_id}, run_dir=run)
    assert any(
        error.get("code") == "manifest_session_reserved"
        for error in binding["errors"]
    )


def test_run_plan_is_bound_to_manifest_project_session_and_digest(tmp_path):
    _project, run, authority, manifest = _bound_manifest(tmp_path)

    binding = validate_manifest_binding(
        manifest,
        run_dir=run,
        manifest_path=run / "run_manifest.json",
        authority_dir=authority,
    )

    assert binding["ok"] is True
    assert manifest["run_plan_sha256"]
    assert manifest["project_id"]


def test_manifest_concurrent_same_identity_projects_one_authority_winner(
    tmp_path, monkeypatch,
):
    run, authority, _source, kwargs = _manifest_publish_fixture(tmp_path)
    barrier = threading.Barrier(8)
    original = runtime_manifest.create_json_exclusive

    def synchronized(path, value, **options):
        if pathlib.Path(path).parent.name == "manifests":
            barrier.wait()
        return original(path, value, **options)

    monkeypatch.setattr(runtime_manifest, "create_json_exclusive", synchronized)

    def publish(_index):
        return create_run_manifest(run, authz="same authorization", **kwargs)

    with ThreadPoolExecutor(max_workers=8) as pool:
        manifests = list(pool.map(publish, range(8)))

    authority_value = json.loads(
        (authority / "manifests" / f"{run.name}.json").read_text(encoding="utf-8")
    )
    session_value = json.loads((run / "run_manifest.json").read_text(encoding="utf-8"))
    assert all(value == authority_value for value in manifests)
    assert session_value == authority_value


def test_manifest_concurrent_identity_conflict_has_one_winner(
    tmp_path, monkeypatch,
):
    run, authority, _source, kwargs = _manifest_publish_fixture(
        tmp_path, "manifest-conflict")
    barrier = threading.Barrier(2)
    original = runtime_manifest.create_json_exclusive

    def synchronized(path, value, **options):
        if pathlib.Path(path).parent.name == "manifests":
            barrier.wait()
        return original(path, value, **options)

    monkeypatch.setattr(runtime_manifest, "create_json_exclusive", synchronized)

    def publish(authz):
        try:
            value = create_run_manifest(run, authz=authz, **kwargs)
        except ValueError as exc:
            return "error", str(exc)
        return "winner", value["authz_sha256"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(publish, ("authorization-a", "authorization-b")))

    assert sorted(item[0] for item in results) == ["error", "winner"]
    assert "immutable runtime manifest identity mismatch" in next(
        item[1] for item in results if item[0] == "error"
    )
    authority_value = json.loads(
        (authority / "manifests" / f"{run.name}.json").read_text(encoding="utf-8")
    )
    assert json.loads((run / "run_manifest.json").read_text()) == authority_value


def test_manifest_recovers_authority_only_publish_without_replacing_winner(
    tmp_path, monkeypatch,
):
    run, authority, source, kwargs = _manifest_publish_fixture(
        tmp_path, "manifest-recovery")
    original_projection_write = runtime_manifest._atomic_write_json

    def crash_before_projection(_path, _value):
        raise RuntimeError("injected crash before session projection")

    monkeypatch.setattr(
        runtime_manifest, "_atomic_write_json", crash_before_projection)
    with pytest.raises(RuntimeError, match="injected crash"):
        create_run_manifest(run, authz="stable authorization", **kwargs)

    authority_path = authority / "manifests" / f"{run.name}.json"
    frozen = authority_path.read_bytes()
    assert not (run / "run_manifest.json").exists()

    # Recovery must project the original authority bytes even if mutable
    # source provenance changed after the authority-only publish.
    (source / "SKILL.md").write_text("changed after crash\n", encoding="utf-8")
    monkeypatch.setattr(
        runtime_manifest, "_atomic_write_json", original_projection_write)
    recovered = create_run_manifest(
        run, authz="stable authorization", **kwargs)

    assert authority_path.read_bytes() == frozen
    assert json.loads(frozen) == recovered
    assert json.loads((run / "run_manifest.json").read_bytes()) == recovered


def test_out_of_budget_unresolved_hint_does_not_block_frozen_run(tmp_path):
    _project, run, _authority, manifest = _bound_manifest(tmp_path)
    unresolved = [{
        "asset": "https://shop.example:443",
        "endpoint": "/api/mystery",
        "method": "",
        "in_run_scope": False,
    }]

    reasons = _authority_method_resolution_gate(
        _context(run, manifest),
        [{"asset": "https://shop.example:443", "endpoint": "/health",
          "method": "GET"}],
        unresolved,
    )

    assert reasons == []


def test_planned_unresolved_hint_remains_an_open_denominator(tmp_path):
    item = {
        "asset": "https://shop.example:443",
        "endpoint": "/api/mystery",
        "method": "",
        "in_run_scope": True,
    }
    _project, run, _authority, manifest = _bound_manifest(
        tmp_path, method_resolution_items=[item])

    reasons = _authority_method_resolution_gate(
        _context(run, manifest), [], [item])

    assert "inventory_unresolved_open" in reasons


def test_session_cannot_mark_planned_method_hint_out_of_scope(tmp_path):
    planned = {
        "asset": "https://shop.example:443",
        "endpoint": "/api/mystery",
        "method": "",
        "in_run_scope": True,
    }
    _project, run, _authority, manifest = _bound_manifest(
        tmp_path, method_resolution_items=[planned])
    forged = {**planned, "in_run_scope": False}

    reasons = _authority_method_resolution_gate(
        _context(run, manifest), [], [forged])

    assert "authority_method_scope_mismatch" in reasons
    assert "inventory_unresolved_open" in reasons


def test_planned_method_resolution_requires_parent_event_attestation(tmp_path):
    planned = {
        "asset": "https://shop.example:443",
        "endpoint": "/api/mystery/{id}",
        "method": "",
        "in_run_scope": True,
    }
    _project, run, authority, manifest = _bound_manifest(
        tmp_path, method_resolution_items=[planned])
    resolved = {
        "asset": "https://shop.example:443",
        "endpoint": "/api/mystery/42",
        "method": "POST",
    }
    context = _context(run, manifest)

    unattested = _authority_method_resolution_gate(context, [resolved], [])
    append_monotonic_event(
        authority,
        session_id=run.name,
        stream="discovery",
        event={"surface": resolved},
    )
    attested = _authority_method_resolution_gate(context, [resolved], [])

    assert "authority_method_resolution_unattested" in unattested
    assert attested == []


def test_authority_run_plan_tamper_fails_binding(tmp_path):
    _project, run, authority, manifest = _bound_manifest(tmp_path)
    plan_path = run_plan_path(authority, run.name)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["admitted_cells"] = []
    plan_path.write_text(json.dumps(plan), encoding="utf-8")

    binding = validate_manifest_binding(
        manifest,
        run_dir=run,
        manifest_path=run / "run_manifest.json",
        authority_dir=authority,
    )

    assert binding["ok"] is False
    codes = {item["code"] for item in binding["errors"]}
    assert "run_plan_digest_mismatch" in codes
    assert "run_plan_self_hash_mismatch" in codes


def test_run_plan_concurrent_publish_is_complete_and_create_only(tmp_path):
    authority = tmp_path / ".atoolkit"
    barrier = threading.Barrier(32)

    def publish(_index):
        barrier.wait()
        return create_run_plan(
            authority,
            project_id="proj-concurrent",
            session_id="run-concurrent",
            admitted_cells=["cell-a", "cell-b"],
            candidate_baseline=["finding-a"],
            budget={"max_turns": 10},
        )

    with ThreadPoolExecutor(max_workers=32) as pool:
        plans = list(pool.map(publish, range(32)))

    assert len({plan["plan_sha256"] for plan in plans}) == 1
    published = json.loads(
        run_plan_path(authority, "run-concurrent").read_text(encoding="utf-8")
    )
    assert published == plans[0]
    assert published["plan_sha256"] == canonical_digest({
        key: value for key, value in published.items() if key != "plan_sha256"
    })


def test_run_plan_concurrent_denominator_conflict_fails_closed(tmp_path):
    authority = tmp_path / ".atoolkit"
    barrier = threading.Barrier(2)

    def publish(cell):
        barrier.wait()
        try:
            plan = create_run_plan(
                authority,
                project_id="proj-conflict",
                session_id="run-conflict",
                admitted_cells=[cell],
            )
        except ValueError as exc:
            return "error", str(exc)
        return "published", plan["admitted_cells"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(publish, ("cell-a", "cell-b")))

    assert sorted(result[0] for result in results) == ["error", "published"]
    assert "immutable run plan mismatch" in next(
        result[1] for result in results if result[0] == "error"
    )


def test_monotonic_event_stream_is_valid_under_64_threads(tmp_path):
    authority = tmp_path / ".atoolkit"
    barrier = threading.Barrier(64)

    def emit(index):
        barrier.wait()
        return append_monotonic_event(
            authority,
            session_id="run-events",
            stream="candidate",
            event={"index": index},
        )

    with ThreadPoolExecutor(max_workers=64) as pool:
        emitted = list(pool.map(emit, range(64)))

    assert {record["sequence"] for record in emitted} == set(range(1, 65))
    event_path = authority / "events" / "run-events" / "candidate.jsonl"
    records = [json.loads(line) for line in event_path.read_text().splitlines()]
    assert len(records) == 64
    previous = ""
    for sequence, record in enumerate(records, 1):
        assert record["sequence"] == sequence
        assert record["previous_event_sha256"] == previous
        assert record["event_sha256"] == canonical_digest({
            key: value for key, value in record.items() if key != "event_sha256"
        })
        previous = record["event_sha256"]


def test_monotonic_event_tail_read_rejects_symlink(tmp_path):
    authority = tmp_path / ".atoolkit"
    stream_dir = authority / "events" / "run-events"
    stream_dir.mkdir(parents=True)
    outside = tmp_path / "outside.jsonl"
    outside.write_text('{"sequence": 999}\n', encoding="utf-8")
    (stream_dir / "candidate.jsonl").symlink_to(outside)

    with pytest.raises(UnsafePathError):
        append_monotonic_event(
            authority,
            session_id="run-events",
            stream="candidate",
            event={"index": 1},
        )
    assert outside.read_text(encoding="utf-8") == '{"sequence": 999}\n'


def test_target_fingerprint_concurrent_conflict_checks_winner(tmp_path):
    authority = tmp_path / ".atoolkit"
    barrier = threading.Barrier(2)

    def publish(fingerprint):
        barrier.wait()
        try:
            record = record_target_fingerprint(
                authority,
                project_id="proj-fingerprint",
                session_id="run-fingerprint",
                fingerprint=fingerprint,
            )
        except ValueError as exc:
            return "error", str(exc)
        return "published", record["fingerprint"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(publish, ("deploy-a", "deploy-b")))

    assert sorted(result[0] for result in results) == ["error", "published"]
    assert "immutable target fingerprint record mismatch" in next(
        result[1] for result in results if result[0] == "error"
    )


def test_resume_cannot_broaden_authorized_scope_or_change_authz(tmp_path):
    _project, run, authority, manifest = _bound_manifest(tmp_path)

    with pytest.raises(ValueError, match="identity mismatch"):
        create_run_manifest(
            run,
            mode="engine",
            project="shop",
            project_id=manifest["project_id"],
            session_id=run.name,
            primary_target="https://shop.example/",
            authorized_scopes=["https://shop.example/", "https://other.example/"],
            authz="broadened after start",
            authority_dir=authority,
            run_plan_path=run_plan_path(authority, run.name),
        )


@pytest.mark.parametrize("command", [
    ["codex", "exec", "--dangerously-bypass-approvals-and-sandbox", "task"],
    ["codex", "exec", "--sandbox", "danger-full-access", "task"],
    ["codex", "exec", "--add-dir", "/tmp", "task"],
    ["codex", "exec", "-C", "/tmp", "task"],
    ["codex", "exec", "-c", "sandbox_workspace_write.network_access=true", "task"],
    ["codex", "exec", "-C/tmp", "task"],
    ["codex", "exec", "-pprivileged", "task"],
    ["codex", "exec", "-csandbox_workspace_write.network_access=true", "task"],
    ["codex", "exec", "-sdanger-full-access", "task"],
])
def test_skill_wrapper_rejects_caller_trust_overrides(command):
    with pytest.raises(SkillWrapperError):
        _validate_codex_command(command)


@pytest.mark.parametrize("script", ["finalize.py", "skill_wrapper.py"])
def test_authority_cli_scripts_support_direct_help(script):
    result = subprocess.run(
        [sys.executable, str(pathlib.Path(__file__).parents[1] / "engine" / script),
         "--help"],
        cwd=pathlib.Path(__file__).parents[1],
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout.lower()
