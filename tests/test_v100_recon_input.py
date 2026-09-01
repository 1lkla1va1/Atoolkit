"""v10.0：侦察输入自动化层（engine/recon）回归测试。

全部用本地 ``http.server`` 线程 mock，禁止任何真实外网请求；被动源用桩函数。
场景（design/迭代方案v10.0 §3.5）：
  1 全在册种子 → 快照落盘 → surface.bootstrap 解析出 mock 端点（回路打通）
  2 scope 外候选 → scope 外 server 零请求 + 审计 skip 行
  3 seeds 含 scope 外 URL → ValueError，零请求
  4 --passive 未传 → 被动源零调用；传入 → 桩数据写进摘要与 historical 文件
  5 max_pages 上限 + max_file_bytes 截断（审计行 truncated: true）
  6 重定向门（P0-1）：跨 scope 302 被拦 / 同 scope 正常跟随 / 6 跳链第 5 跳后放弃
  7 限速：模拟时钟断言相邻请求间隔 ≥ 1/rps（禁止真实墙钟）
  8 元文件（_recon_audit.jsonl / recon-summary.jsonl）不被 bootstrap 误消费
"""
from __future__ import annotations

import http.server
import json
import pathlib
import threading
import time

import pytest

from engine import surface
from engine.host_policy import is_authorized_url
from engine.recon import passive as recon_passive
from engine.recon.collect import collect_recon
from engine.recon.emit import AUDIT_NAME, SUMMARY_NAME


# ── 本地 mock HTTP 服务（零外网） ─────────────────────────────────────────
class _MockHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        self.server.requests.append((self.path, time.monotonic()))
        entry = self.server.routes.get(self.path)
        if entry is None:
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        status, headers, body = entry
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def log_message(self, *args) -> None:  # 静默
        pass


def _http_server(routes: dict):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _MockHandler)
    server.routes = routes
    server.requests = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _shutdown(server, thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def _base(server) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}"


def _audit_rows(out_dir: pathlib.Path) -> list[dict]:
    lines = (out_dir / AUDIT_NAME).read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _summary(out_dir: pathlib.Path) -> dict:
    return json.loads((out_dir / SUMMARY_NAME).read_text(encoding="utf-8"))


def _paths(server) -> list[str]:
    return [path for path, _ in server.requests]


# ── 场景 1：recon 输出 → surface.bootstrap 消费回路 ───────────────────────
def test_scenario1_in_scope_roundtrip(tmp_path) -> None:
    routes = {
        "/": (200, [], (
            "<html><head><script src=\"/static/app.js\"></script></head><body>"
            "<form action=\"/api/login\" method=\"POST\">"
            "<input name=\"username\"><input name=\"password\"></form>"
            "<a href=\"/about\">about</a></body></html>").encode()),
        "/static/app.js": (200, [], (
            "fetch(\"/api/orders/1001\");\n"
            "axios.post(\"/api/pay\", {amount: 1});\n").encode()),
        "/about": (200, [], (
            "<html><body><a href=\"/api/profile\">p</a></body></html>").encode()),
        "/api/profile": (200, [], "{\"ok\": true}".encode()),
    }
    server, thread = _http_server(routes)
    try:
        base = _base(server)
        out = tmp_path / "recon"
        summary = collect_recon([base + "/"], [base], out, rps=1000)
        assert summary["pages"] >= 3
        assert summary["js"] == 1
        assert list((out / "js").rglob("*.js"))
        assert (out / AUDIT_NAME).is_file()
        assert (out / SUMMARY_NAME).is_file()
        # recon-summary.jsonl 是单行 JSON 且含输入回显
        echoed = _summary(out)
        assert echoed["seeds"] == [base + "/"]
        assert echoed["authorized_scopes"] == [base]
        # bootstrap 消费回路：表单 + JS 调用点端点全部解析出来
        endpoints = surface.bootstrap(out)
        by_path = {row["endpoint"]: row for row in endpoints}
        assert "/api/login" in by_path
        assert by_path["/api/login"]["method"] == "POST"
        assert "username" in by_path["/api/login"]["params"]
        assert "/api/orders/1001" in by_path
        assert "/api/pay" in by_path
        assert by_path["/api/pay"]["method"] == "POST"
        assert "/api/profile" in by_path
    finally:
        _shutdown(server, thread)


# ── 场景 2：scope 外候选零请求 + 审计 skip 行 ─────────────────────────────
def test_scenario2_out_of_scope_candidates(tmp_path) -> None:
    routes_a = {
        "/": (200, [], (
            "<html><body>"
            f"<a href=\"http://OUT_HOST/x\">evil</a>"
            f"<script src=\"http://OUT_HOST/evil.js\"></script>"
            "</body></html>").encode()),
    }
    routes_b = {
        "/x": (200, [], "nope".encode()),
        "/evil.js": (200, [], "nope".encode()),
    }
    server_a, thread_a = _http_server(routes_a)
    server_b, thread_b = _http_server(routes_b)
    try:
        # 用占位符回填 scope 外 server 的真实端口
        out_base = _base(server_b)
        routes_a["/"] = (200, [], routes_a["/"][2].replace(b"OUT_HOST",
                                                            out_base.encode()))
        base_a = _base(server_a)
        out = tmp_path / "recon"
        summary = collect_recon([base_a + "/"], [base_a], out, rps=1000)
        assert _paths(server_b) == []           # scope 外 server 零请求
        assert summary["skipped_out_of_scope"] >= 2
        rows = _audit_rows(out)
        skip_urls = {row["url"] for row in rows
                     if row["action"] == "skip" and row["scope"] == "out"}
        assert any("/x" in url for url in skip_urls)
        assert any("/evil.js" in url for url in skip_urls)
    finally:
        _shutdown(server_a, thread_a)
        _shutdown(server_b, thread_b)


# ── 场景 3：seeds 含 scope 外 URL → ValueError，零请求 ────────────────────
def test_scenario3_seed_out_of_scope_fail_closed(tmp_path) -> None:
    routes_a = {"/": (200, [], b"<html></html>")}
    routes_b = {"/": (200, [], b"<html></html>")}
    server_a, thread_a = _http_server(routes_a)
    server_b, thread_b = _http_server(routes_b)
    try:
        base_a, base_b = _base(server_a), _base(server_b)
        assert is_authorized_url(base_a, [base_a])
        assert not is_authorized_url(base_b, [base_a])
        with pytest.raises(ValueError):
            collect_recon([base_a + "/", base_b + "/"], [base_a],
                          tmp_path / "recon", rps=1000)
        # fail closed：一个请求都不发（含在册 seed）
        assert _paths(server_a) == []
        assert _paths(server_b) == []
    finally:
        _shutdown(server_a, thread_a)
        _shutdown(server_b, thread_b)


# ── 场景 4：被动源默认关 / 显式开 ─────────────────────────────────────────
def test_scenario4_passive_default_off_and_on(tmp_path, monkeypatch) -> None:
    calls: list[str] = []

    def _fake_crtsh(fetcher, host):
        calls.append("crtsh")
        return ["sub.example.com", "api.example.com"], None

    def _fake_wayback(fetcher, host, scopes):
        calls.append("wayback")
        return ["https://example.com/api/legacy.php",
                "https://evil.example/api/steal.php"], 1, None

    monkeypatch.setattr(recon_passive, "fetch_crtsh_subdomains", _fake_crtsh)
    monkeypatch.setattr(recon_passive, "fetch_wayback_urls", _fake_wayback)

    routes = {"/": (200, [], b"<html></html>")}
    server, thread = _http_server(routes)
    try:
        base = _base(server)
        # 默认关：被动源函数零调用
        out_off = tmp_path / "recon-off"
        summary_off = collect_recon([base + "/"], [base], out_off, rps=1000)
        assert calls == []
        assert summary_off["subdomains"] == []
        # 显式开：桩数据写进摘要与 historical 文件
        out_on = tmp_path / "recon-on"
        summary_on = collect_recon([base + "/"], [base], out_on, rps=1000,
                                   passive=True)
        assert calls == ["crtsh", "wayback"]
        assert summary_on["subdomains"] == ["sub.example.com", "api.example.com"]
        hist = out_on / "historical" / "example.com.urls.json"
        assert hist.is_file()
        urls = json.loads(hist.read_text(encoding="utf-8"))
        assert urls == ["https://example.com/api/legacy.php"]
        # bootstrap 把历史 URL 当发现提示消费（method 留空，不造幻影 GET 格）
        endpoints = {row["endpoint"]: row for row in surface.bootstrap(out_on)}
        assert "/api/legacy.php" in endpoints
        assert endpoints["/api/legacy.php"]["method"] == ""
        # scope 外 host 的历史 URL 被丢弃并计数
        assert summary_on["skipped_out_of_scope"] >= 1
    finally:
        _shutdown(server, thread)


# ── 场景 5：max_pages 上限 + max_file_bytes 截断 ──────────────────────────
def test_scenario5_caps(tmp_path) -> None:
    routes = {"/": (200, [], b"<html>" + b"".join(
        f"<a href=\"/p{i}\">p{i}</a>".encode() for i in range(6)) + b"</html>")}
    routes.update({f"/p{i}": (200, [], b"<html>page</html>") for i in range(6)})
    server, thread = _http_server(routes)
    try:
        base = _base(server)
        out = tmp_path / "recon-pages"
        summary = collect_recon([base + "/"], [base], out, rps=1000, max_pages=3)
        assert summary["pages"] == 3
        assert len(list((out / "pages").rglob("*.html"))) == 3
        assert summary["stopped"] == "max_pages"
        assert "/p3" not in _paths(server)
    finally:
        _shutdown(server, thread)

    routes_big = {
        "/": (200, [], b"<html>hello " + b"A" * 5000 + b"</html>"),
    }
    server2, thread2 = _http_server(routes_big)
    try:
        base = _base(server2)
        out = tmp_path / "recon-trunc"
        summary = collect_recon([base + "/"], [base], out, rps=1000,
                                max_file_bytes=1024)
        assert summary["pages"] == 1
        snapshot = next((out / "pages").rglob("*.html"))
        assert snapshot.stat().st_size == 1024
        assert summary["total_bytes_written"] == 1024
        rows = _audit_rows(out)
        assert any(row["truncated"] is True and row["bytes"] == 1024
                   for row in rows)
    finally:
        _shutdown(server2, thread2)


# ── 场景 6：重定向门（安全关键，闭合 P0-1） ───────────────────────────────
def test_scenario6a_redirect_out_of_scope_blocked(tmp_path) -> None:
    routes_a = {"/jump": (302, [("Location", "REDIR_B/x")], b"")}
    routes_b = {"/x": (200, [], b"leak")}
    server_a, thread_a = _http_server(routes_a)
    server_b, thread_b = _http_server(routes_b)
    try:
        routes_a["/jump"] = (302, [("Location", _base(server_b) + "/x")], b"")
        base_a = _base(server_a)
        out = tmp_path / "recon"
        summary = collect_recon([base_a + "/jump"], [base_a], out, rps=1000)
        assert _paths(server_b) == []                 # 跨 scope 跳转零请求
        assert summary["pages"] == 0
        rows = _audit_rows(out)
        assert any(row["action"] == "skip"
                   and row["reason"] == "redirect_out_of_scope"
                   and "/x" in row["url"] for row in rows)
        assert summary["skipped_out_of_scope"] >= 1
    finally:
        _shutdown(server_a, thread_a)
        _shutdown(server_b, thread_b)


def test_scenario6b2_redirect_relative_links_use_final_url(tmp_path) -> None:
    """P2-2 回归：seed 经 in-scope 302 落到 /docs/page 后，页内相对链接必须按
    final_url（落点目录）解析；按原始 URL 解析会错抓诱饵路径。"""
    routes = {
        "/jump": (302, [("Location", "/docs/page")], b""),
        "/docs/page": (200, [], (
            "<html><body>"
            "<a href=\"item.html\">item</a>"
            "<script src=\"js/app.js\"></script>"
            "</body></html>").encode()),
        "/docs/item.html": (200, [], b"<html>item</html>"),
        "/docs/js/app.js": (200, [], b"fetch(\"/api/x\");"),
        # 错误基准（原始 URL /jump）会解析出的诱饵路径——不应被请求
        "/item.html": (200, [], b"decoy"),
        "/js/app.js": (200, [], b"decoy"),
    }
    server, thread = _http_server(routes)
    try:
        base = _base(server)
        out = tmp_path / "recon"
        summary = collect_recon([base + "/jump"], [base], out, rps=1000)
        paths = _paths(server)
        assert "/docs/page" in paths
        assert "/docs/item.html" in paths          # 按 final_url 正确解析
        assert "/docs/js/app.js" in paths
        assert "/item.html" not in paths           # 诱饵零请求
        assert "/js/app.js" not in paths
        assert summary["js"] == 1
        assert len(list((out / "js").rglob("*.js"))) == 1
    finally:
        _shutdown(server, thread)


def test_scenario6b_redirect_in_scope_followed(tmp_path) -> None:
    routes = {
        "/jump2": (302, [("Location", "/landing")], b""),
        "/landing": (200, [], b"<html><body>landing</body></html>"),
    }
    server, thread = _http_server(routes)
    try:
        base = _base(server)
        out = tmp_path / "recon"
        summary = collect_recon([base + "/jump2"], [base], out, rps=1000)
        assert summary["pages"] == 1                  # 同 scope 跳转正常跟随落盘
        snapshot = next((out / "pages").rglob("*.html"))
        assert b"landing" in snapshot.read_bytes()
        # 快照哈希取最初请求的 URL（/jump2），审计记录原始 + 最终 URL
        rows = _audit_rows(out)
        assert any(row["reason"] == "redirect" and row["status"] == 302
                   for row in rows)
        final_rows = [row for row in rows if row["status"] == 200]
        assert any(row["original_url"] == base + "/jump2"
                   and row["final_url"] == base + "/landing"
                   for row in final_rows)
    finally:
        _shutdown(server, thread)


def test_scenario6c_redirect_hop_limit(tmp_path) -> None:
    routes = {f"/h{i}": (302, [("Location", f"/h{i + 1}")], b"")
              for i in range(1, 7)}
    routes["/h7"] = (200, [], b"<html>never</html>")
    server, thread = _http_server(routes)
    try:
        base = _base(server)
        out = tmp_path / "recon"
        collect_recon([base + "/h1"], [base], out, rps=1000)
        paths = _paths(server)
        assert paths == ["/h1", "/h2", "/h3", "/h4", "/h5", "/h6"]  # 第 5 跳后放弃
        assert "/h7" not in paths
        rows = _audit_rows(out)
        assert any(row["action"] == "skip"
                   and row["reason"] == "redirect_hop_limit"
                   for row in rows)
    finally:
        _shutdown(server, thread)


# ── 场景 7：限速（模拟时钟，禁止真实墙钟） ────────────────────────────────
def test_scenario7_rate_limit_fake_clock(tmp_path, monkeypatch) -> None:
    class _FakeClock:
        def __init__(self) -> None:
            self.now = 1000.0
            self.sleeps: list[float] = []

        def monotonic(self) -> float:
            return self.now

        def sleep(self, seconds: float) -> None:
            self.sleeps.append(seconds)
            self.now += seconds

    clock = _FakeClock()
    monkeypatch.setattr(time, "monotonic", clock.monotonic)
    monkeypatch.setattr(time, "sleep", clock.sleep)

    routes = {"/": (200, [], b"<html>" + b"".join(
        f"<a href=\"/p{i}\">p{i}</a>".encode() for i in range(4)) + b"</html>")}
    routes.update({f"/p{i}": (200, [], b"<html>page</html>") for i in range(4)})
    server, thread = _http_server(routes)
    try:
        base = _base(server)
        collect_recon([base + "/"], [base], tmp_path / "recon", rps=10,
                      max_pages=5)
        paths = _paths(server)
        assert len(paths) == 5                        # 抓 5 页
        assert len(clock.sleeps) >= 4                 # 相邻请求之间有 sleep
        assert all(s >= 0.0999 for s in clock.sleeps)  # rps=10 → 间隔 ≥ 0.1s
        # 用请求时刻（模拟时钟）断言相邻间隔 ≥ 0.1s
        stamps = [stamp for _, stamp in server.requests]
        intervals = [b - a for a, b in zip(stamps, stamps[1:])]
        assert all(interval >= 0.0999 for interval in intervals)
    finally:
        _shutdown(server, thread)


# ── 场景 8：元文件不被 bootstrap 误消费 ───────────────────────────────────
def test_scenario8_meta_files_not_consumed(tmp_path) -> None:
    routes = {
        "/": (200, [], (
            "<html><body><a href=\"/api/real\">r</a></body></html>").encode()),
    }
    server, thread = _http_server(routes)
    try:
        base = _base(server)
        out = tmp_path / "recon"
        collect_recon([base + "/"], [base], out, rps=1000)
        # 元文件里故意埋入 /api/fake（jsonl 后缀不应被 bootstrap 消费）
        with (out / AUDIT_NAME).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"url": "/api/fake", "action": "fetch"}) + "\n")
        with (out / SUMMARY_NAME).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"note": "/api/fake.php"}) + "\n")
        endpoints = {row["endpoint"] for row in surface.bootstrap(out)}
        assert "/api/real" in endpoints               # 真实端点照常解析
        assert "/api/fake" not in endpoints           # 元文件字符串零泄漏
        assert "/api/fake.php" not in endpoints
    finally:
        _shutdown(server, thread)
