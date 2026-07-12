from __future__ import annotations

import pytest
import os
import subprocess

from engine.enforce import ACCEPTED, REJECTED, guardian_check, is_authorized_host
from engine.host_policy import authorization_scope_from_url, is_authorized_url
from engine.reporting.validate import _target_allowed
from engine.verify import (
    CONFIRMED,
    INCONCLUSIVE,
    REFUTED,
    Request,
    Response,
    VerifyResult,
    _NoRedirect,
    replay,
    verify_id_tamper,
    verify_idor,
)
from run import _secure_write_text, safe_session_dir, safe_session_id
from codex.codex_adapter import CodexAdapter
from engine.orchestrator import CognitiveState, _conclude, harvest_evidence, run_session


def test_authorization_matches_parsed_authority_not_substrings():
    scopes = ["t.example"]
    assert is_authorized_url("https://t.example/api", scopes)
    assert not is_authorized_url("https://t.example.evil.test/api", scopes)
    assert not is_authorized_url("https://evil.test/?next=https://t.example", scopes)
    assert not is_authorized_url("https://t.example@evil.test/api", scopes)
    assert not is_authorized_url("file://t.example/etc/passwd", scopes)


def test_subdomains_require_explicit_wildcard_scope():
    assert not is_authorized_url("https://api.t.example/x", ["t.example"])
    assert is_authorized_url("https://api.t.example/x", ["*.t.example"])
    assert not is_authorized_url("https://t.example/x", ["*.t.example"])


def test_target_derived_scope_pins_effective_port():
    scope = authorization_scope_from_url("http://192.0.2.10:8180/app")
    assert scope == "http://192.0.2.10:8180/app"
    assert is_authorized_url("http://192.0.2.10:8180/app/api", [scope])
    assert not is_authorized_url("https://192.0.2.10:8180/app/api", [scope])
    assert not is_authorized_url("http://192.0.2.10:8180/application", [scope])
    assert not is_authorized_url("http://192.0.2.10:8180/app/%2e%2e/private", [scope])
    assert not is_authorized_url("http://192.0.2.10:8080/api", [scope])


def test_all_authorization_callers_reject_disguised_hosts():
    bad = "https://t.example.evil.test/api"
    assert not is_authorized_host(bad, ["t.example"])
    assert not _target_allowed(bad, ["t.example"])

    report = (
        "---\nseverity: P1\ntitle: 订单越权读取\n"
        f"target: {bad}\ntype: IDOR\n---\n"
        "实测攻击者越权读取了受害者订单与地址。\n"
        "```\ncurl 'https://t.example.evil.test/api'\n"
        "HTTP/1.1 200 OK\n返回了受害者数据\n```\n" + "证据充分。" * 40
    )
    verdict = guardian_check(report, authorized_hosts=["t.example"])
    assert verdict.result == REJECTED
    assert verdict.level == 8


def test_legacy_guardian_requires_target_and_inline_response_evidence(tmp_path):
    no_target = (
        "---\nseverity: P1\ntitle: 订单越权读取\ntype: IDOR\n---\n"
        "实测越权读取了受害者订单。\n```\ncurl https://t.example/api\n"
        "HTTP/1.1 200 OK\n返回受害者数据\n```\n" + "证据。" * 80
    )
    assert guardian_check(no_target).result == REJECTED

    (tmp_path / "authz.md").write_text("not response evidence", encoding="utf-8")
    no_response = (
        "---\nseverity: P1\ntitle: 订单越权读取\n"
        "target: https://t.example\ntype: IDOR\n---\n"
        "实测越权读取了受害者订单。\n```\ncurl https://t.example/api\n```\n"
        + "证据。" * 80
    )
    verdict = guardian_check(no_response, evidence_dir=str(tmp_path),
                             authorized_hosts=["t.example"])
    assert verdict.result != ACCEPTED
    assert verdict.level == 4


def test_verify_guard_rejects_before_transport_runs():
    called = False

    def transport(_req):
        nonlocal called
        called = True
        return Response(200, {}, "unexpected")

    with pytest.raises(PermissionError):
        replay(Request("GET", "https://t.example.evil.test/x"), transport, ["t.example"])
    assert called is False


def test_verify_guard_rejects_host_header_confusion():
    with pytest.raises(PermissionError):
        replay(
            Request("GET", "https://t.example/x", {"Host": "evil.test"}),
            lambda _req: Response(200, {}, "unexpected"),
            ["t.example"],
        )


def test_urllib_redirect_handler_never_follows_implicitly():
    handler = _NoRedirect()
    assert handler.redirect_request(None, None, 302, "Found", {}, "https://evil.test") is None


def test_id_tamper_replaces_query_values_before_replay():
    seen: list[str] = []

    def transport(req):
        seen.append(req.url)
        return Response(200, {}, '{"owner":"victim"}')

    result = verify_id_tamper(
        Request("GET", "https://t.example/api/order?order_id=1001"),
        "order_id", ["1002", "1003"], lambda body: "victim" in body,
        transport, ["t.example"],
    )
    assert result.result == CONFIRMED
    assert seen == [
        "https://t.example/api/order?order_id=1002",
        "https://t.example/api/order?order_id=1003",
    ]


def test_id_tamper_replaces_legacy_path_prefix():
    seen: list[str] = []

    def transport(req):
        seen.append(req.url)
        return Response(200, {}, '{"owner":"victim"}')

    result = verify_id_tamper(
        Request("GET", "https://t.example/api/orders/1001"),
        "orders/", ["1002", "1003"], lambda body: "victim" in body,
        transport, ["t.example"],
    )
    assert result.result == CONFIRMED
    assert seen[-1].endswith("/api/orders/1003")


def test_id_tamper_is_inconclusive_when_parameter_was_not_replaced():
    called = False

    def transport(_req):
        nonlocal called
        called = True
        return Response(200, {}, '{"owner":"victim"}')

    result = verify_id_tamper(
        Request("GET", "https://t.example/api/orders/current"),
        "missing_id", ["1002", "1003"], lambda body: "victim" in body,
        transport, ["t.example"],
    )
    assert result.result == INCONCLUSIVE
    assert called is False


def test_idor_verifier_requires_explicit_owner_and_valid_baseline():
    req = Request("GET", "https://t.example/api/order/1")
    identities = {"alice": {"Cookie": "owner"}, "attacker": {"Cookie": "other"}}
    result = verify_idor(
        req, identities, "victim", lambda _req: Response(200, {}, "victim"),
        ["t.example"], owner_label="owner",
    )
    assert result.result == INCONCLUSIVE

    identities = {"owner": {"Cookie": "owner"}, "attacker": {"Cookie": "other"}}
    result = verify_idor(
        req, identities, "victim", lambda _req: Response(0, {}, "transport error"),
        ["t.example"], owner_label="owner",
    )
    assert result.result == INCONCLUSIVE


def test_refuted_replay_removes_legacy_finding_from_accepted(tmp_path):
    report = (
        "---\nseverity: P1\ntitle: 订单详情 IDOR 越权读取\n"
        "target: https://t.example\ntype: IDOR\n---\n"
        "实测攻击者越权读取了受害者订单和地址。\n"
        "```\ncurl https://t.example/api/order/1\n"
        "HTTP/1.1 200 OK\n返回了受害者订单\n```\n" + "证据充分。" * 40
    )
    (tmp_path / "report_idor.md").write_text(report, encoding="utf-8")
    evidence = harvest_evidence(tmp_path, authorized_hosts=["t.example"])
    state = CognitiveState("s", "https://t.example")
    out = _conclude(
        "VULN_FOUND", evidence, tmp_path, state, ["t.example"], 1,
        verify_fn=lambda _report: VerifyResult(REFUTED, "owner-only baseline"),
    )
    assert out["accepted"] == []
    assert out["verification_rejected"]
    assert out["status"] == "incomplete"


def test_legacy_markdown_is_candidate_only_and_cannot_close_coverage(tmp_path):
    report = (
        "---\nseverity: P1\ntitle: 订单详情 IDOR 越权读取\n"
        "target: https://t.example\ntype: IDOR\n---\n"
        "实测攻击者越权读取了受害者订单和地址。\n"
        "```\ncurl https://t.example/api/order/1\n"
        "HTTP/1.1 200 OK\n返回了受害者订单\n```\n" + "证据充分。" * 40
    )
    (tmp_path / "report_idor.md").write_text(report, encoding="utf-8")
    evidence = harvest_evidence(tmp_path, authorized_hosts=["t.example"])
    state = CognitiveState(
        "s", "https://t.example", vuln_classes=["IDOR"])
    state.seed_matrix(["GET /api/order/{id}"])
    state.update(
        "CELL: /api/order/{id} | IDOR | PASS | legacy report only",
        evidence,
    )
    cell = state._find_cell("GET /api/order/{id}", "IDOR")
    assert cell and cell["state"] == "untested"

    out = _conclude(
        "VULN_FOUND", evidence, tmp_path, state, ["t.example"], 1,
        verify_fn=lambda _report: VerifyResult(CONFIRMED, "replay looked positive"),
    )
    assert out["accepted"] == []
    assert out["findings"] == []
    assert len(out["legacy_candidates"]) == 1
    assert out["legacy_guardian"]["candidate"] == 1
    assert out["status"] != "vuln_found"


@pytest.mark.parametrize("bad", ["../escape", "/tmp/escape", "a/b", "..", "", "a" * 129])
def test_session_id_rejects_path_traversal(bad):
    with pytest.raises(ValueError):
        safe_session_id(bad)


def test_session_dir_rejects_existing_symlink(tmp_path):
    base = tmp_path / "sessions"
    base.mkdir()
    target = tmp_path / "outside"
    target.mkdir()
    (base / "linked").symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError):
        safe_session_dir(base, "linked")


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_private_writer_uses_owner_only_permissions(tmp_path):
    path = tmp_path / "session" / "cookies.txt"
    _secure_write_text(path, "Cookie: secret")
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700


def test_codex_stream_close_terminates_child(monkeypatch, tmp_path):
    class Sink:
        def write(self, _value):
            return None

        def close(self):
            return None

    class FakeProc:
        stdin = Sink()
        stdout = iter(["first line\n", "second line\n"])

        def wait(self):
            return 0

    fake = FakeProc()
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: fake)
    adapter = CodexAdapter(workdir=str(tmp_path))
    terminated: list[object] = []
    monkeypatch.setattr(adapter, "_terminate_process", lambda proc: terminated.append(proc))
    stream = adapter.run("prompt", session_id="s")
    assert next(stream) == "first line\n"
    stream.close()
    assert terminated == [fake]


def test_cross_chunk_danger_command_is_detected_and_stream_closed(tmp_path):
    class SplitAdapter:
        name = "split"

        def __init__(self):
            self.closed = False

        def run(self, prompt, *, session_id):
            try:
                yield "/bin/zsh -lc 'curl -X DE"
                yield "LETE https://t.example/api/orders/999'"
                yield "this must not be consumed"
            finally:
                self.closed = True

    adapter = SplitAdapter()
    out = run_session(
        adapter,
        target="https://t.example",
        authz="demo",
        core_skill="test",
        workdir=str(tmp_path / "project" / "sessions" / "run1"),
        authorized_hosts=["t.example"],
        endpoints=["GET /api/orders/999"],
        vuln_classes=["IDOR"],
        max_turns=1,
        verbose=False,
    )
    assert out["status"] == "needs_confirm"
    assert adapter.closed is True
