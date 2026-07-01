#!/usr/bin/env python3
"""run.py —— 一条命令起一次授权 SRC 会话。

把 engine 三件套(orchestrator+enforce+verify) + Codex 适配器接成入口。
本文件只做接线，不含新逻辑（逻辑在 engine/ 与 codex/）。

用法：
  # 真实跑（用 Codex）
  python3 run.py --target https://t.example --authz "仅限 https://t.example，已授权" \
      --cookie 'session=...' [--model gpt-5.5-codex] [--allow t2.example] \
      [--identity owner:session=A --identity attacker:session=B --victim-marker '收货地址']

  # 不接模型/网络，自检接线是否通（用 MockAdapter）
  python3 run.py --dry-run --target https://t.example --authz "demo"

换模型：改 --model 即可；换运行时：把 CodexAdapter 换成别的 ModelAdapter（本文件 1 处）。
"""
from __future__ import annotations
import argparse, inspect, sys, time, re, pathlib

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from engine.orchestrator import run_session, MockAdapter          # noqa: E402
from engine.verify import (verify_idor, extract_poc, urllib_transport,  # noqa: E402
                           VerifyResult, INCONCLUSIVE)


def host_of(url: str) -> str:
    m = re.match(r"https?://([^/:]+)", url)
    return m.group(1) if m else url


def build_verify_fn(identities: dict, victim_marker: str, hosts: list[str]):
    """对 Guardian accepted 的报告做确定性重放复验。无身份/无标记则不复验。"""
    if not identities or not victim_marker:
        return None
    def verify_fn(report_md: str) -> VerifyResult:
        req = extract_poc(report_md)
        if req is None:
            return VerifyResult(INCONCLUSIVE, "报告无可解析 PoC")
        return verify_idor(req, identities, victim_marker, urllib_transport, hosts)
    return verify_fn


def main():
    ap = argparse.ArgumentParser(description="起一次授权 SRC 会话（engine 三件套接线）")
    ap.add_argument("--target", required=True, help="授权目标 URL")
    ap.add_argument("--authz", required=True, help="授权说明文本，或授权文件路径")
    ap.add_argument("--cookie", default="", help="人已拿到的新鲜 Cookie/Session")
    ap.add_argument("--bearer", default="", help="人已拿到的新鲜 Bearer JWT（与 --cookie 二选一）")
    ap.add_argument("--auth-scheme", choices=["cookie", "bearer"], default="cookie",
                    help="--identity 凭据的注入方式：cookie→Cookie 头；bearer→Authorization: Bearer")
    ap.add_argument("--model", default="gpt-5.5-codex", help="模型名（换模型只改这里）")
    ap.add_argument("--allow", action="append", default=[], help="额外授权 host（可多次）")
    ap.add_argument("--identity", action="append", default=[],
                    help="复验身份 label:cred（cookie 模式如 owner:session=A；bearer 模式如 owner:eyJ...；可多次）")
    ap.add_argument("--victim-marker", default="", help="证明越权的受害者数据特征串")
    ap.add_argument("--owned-id", action="append", default=[],
                    help="本会话自有对象 id（可多次）；改删类命中其中即自动放行，否则熔断交人工")
    ap.add_argument("--confirm-policy", choices=["halt", "allow"], default="halt",
                    help="改删他人/未知 id 时：halt=熔断停手交人工(默认)；allow=放行(信任场景)")
    ap.add_argument("--hint", default="", help="攻击面提示(按意图触发)，注入 prompt 的 skill_hint 槽；或提示文件路径")
    ap.add_argument("--endpoints", default="",
                    help="覆盖矩阵的攻击面来源：文件路径(每行一个 endpoint，# 起注释) 或逗号分隔；"
                         "无来源则矩阵为空、退化为旧的「首洞即结」行为")
    ap.add_argument("--vuln-class", action="append", default=[],
                    help="覆盖矩阵的漏洞类(列)，可多次；缺省用引擎内置 OWASP/SRC 主流类")
    ap.add_argument("--enable-auth-flow-column", action="store_true",
                    help="显式启用 auth endpoint 的认证绕过/枚举列；自定义 --vuln-class 时也生效")
    ap.add_argument("--max-turns", type=int, default=50)
    ap.add_argument("--sid", default="", help="会话 ID（默认按时间生成）")
    ap.add_argument("--resume", action="store_true",
                    help="断点续测：复用 --sid 的 runs/<sid>/state.json 承接覆盖进度（无则照常新开）")
    ap.add_argument("--dry-run", action="store_true", help="用 MockAdapter，不接模型/网络")
    args = ap.parse_args()

    # 会话目录与落盘（runs/ 已被 .gitignore）
    sid = args.sid or time.strftime("sess-%Y%m%d-%H%M%S")
    wd = ROOT / "runs" / sid
    wd.mkdir(parents=True, exist_ok=True)
    authz = (pathlib.Path(args.authz).read_text(encoding="utf-8")
             if pathlib.Path(args.authz).exists() else args.authz)
    (wd / "authz.md").write_text(authz, encoding="utf-8")
    # 会话凭据：cookie 或 bearer（落盘到 cookies.txt 供模型读取，runs/ 已 gitignore）
    cred = args.bearer or args.cookie
    cred_line = (f"Authorization: Bearer {args.bearer}" if args.bearer
                 else (f"Cookie: {args.cookie}" if args.cookie else ""))
    if cred:
        (wd / "cookies.txt").write_text(cred_line, encoding="utf-8")

    skill = (ROOT / "skill" / "核心技能文件.v2.md").read_text(encoding="utf-8")
    hosts = [host_of(args.target)] + args.allow

    # 覆盖矩阵的攻击面来源（支柱 2）：文件(每行一个，# 注释) 或逗号分隔；无来源 → 空矩阵退化旧行为
    endpoints: list[str] = []
    if args.endpoints:
        p = pathlib.Path(args.endpoints)
        raw = p.read_text(encoding="utf-8") if p.exists() else args.endpoints.replace(",", "\n")
        endpoints = [ln.strip() for ln in raw.splitlines()
                     if ln.strip() and not ln.lstrip().startswith("#")]

    identities = {}
    for spec in args.identity:
        label, _, val = spec.partition(":")
        val = val.strip()
        auth = ({"Authorization": f"Bearer {val}"} if args.auth_scheme == "bearer"
                else {"Cookie": val})
        identities[label.strip()] = auth

    # 适配器：唯一与模型耦合处（换运行时改这里）
    if args.dry_run:
        adapter, verify_fn = MockAdapter(wd), None      # dry-run 不联网复验
    else:
        from codex.codex_adapter import CodexAdapter
        adapter = CodexAdapter(model=args.model, workdir=str(wd), allow_hosts=hosts)
        verify_fn = build_verify_fn(identities, args.victim_marker, hosts)

    target = args.target + (f"\n（本会话凭据见 {wd/'cookies.txt'}，按其中的 header 行原样带上）" if cred else "")

    print(f"▶ 会话 {sid} ｜ 模型 {'mock' if args.dry_run else args.model} ｜ 授权 host {hosts}")
    print(f"  复验: {'开（'+','.join(identities)+'）' if verify_fn else '关'} ｜ 工作目录 {wd}")
    auth_flow_note = " + auth-flow gated" if (args.enable_auth_flow_column or not args.vuln_class) else ""
    print(f"  覆盖矩阵: {len(endpoints)} endpoint × "
          f"{len(args.vuln_class) or '内置'} 类{auth_flow_note} "
          f"{'(空→退化为首洞即结)' if not endpoints else ''}")
    print("─" * 60)
    hint = (pathlib.Path(args.hint).read_text(encoding="utf-8")
            if args.hint and pathlib.Path(args.hint).exists() else args.hint)
    if args.resume and not (wd / "state.json").exists():
        print(f"  ⚠ --resume 但 {wd/'state.json'} 不存在 → 按新会话起（无进度可承接）")
    run_kwargs = {
        "target": target,
        "authz": authz,
        "core_skill": skill,
        "workdir": str(wd),
        "authorized_hosts": hosts,
        "max_turns": args.max_turns,
        "verify_fn": verify_fn,
        "owned_ids": set(args.owned_id),
        "confirm_policy": args.confirm_policy,
        "skill_hint": hint,
        "endpoints": endpoints,
        "vuln_classes": (args.vuln_class or None),
        "resume": args.resume,
    }
    if "enable_auth_flow_column" in inspect.signature(run_session).parameters:
        run_kwargs["enable_auth_flow_column"] = (
            True if args.enable_auth_flow_column else None
        )
    res = run_session(adapter, **run_kwargs)
    print("─" * 60)
    print(f"终态: {res['status']} ｜ 标记: {res.get('marker')} ｜ 轮次: {res['turn']}")
    if "accepted" in res:          # error/needs_confirm 终态返回里没有 Guardian 账本
        print(f"Guardian: accepted={res['accepted']} demoted={res['demoted']} rejected={res['rejected']} "
              f"负向留证={res.get('negatives', 0)}")
        cov = res.get("coverage")
        if cov:
            print(f"覆盖矩阵: 闭合 {cov.get('closed', 0)}/{cov.get('total', 0)} "
                  f"(PASS={cov.get('positive', 0)} "
                  f"NEG={cov.get('negative_with_evidence', 0)} "
                  f"SHALLOW={cov.get('shallow_negative', 0)} "
                  f"SKIP={cov.get('skipped', 0)} "
                  f"未测={cov.get('untested', 0)} "
                  f"OPEN={cov.get('open_risk', 0)} "
                  f"NEEDS={cov.get('needs_account', 0)})")
        led = (res.get("coverage_ledger") or {}).get("stats")
        if led:
            print(f"coverage-ledger: 闭合 {led.get('closed', 0)}/{led.get('total', 0)} "
                  f"(confirmed={led.get('confirmed', 0)} "
                  f"not_vulnerable={led.get('not_vulnerable', 0)} "
                  f"not_applicable={led.get('not_applicable', 0)} "
                  f"not_tested={led.get('not_tested', 0)} "
                  f"blocked={led.get('blocked', 0)} "
                  f"high_value_open={led.get('high_value_open', 0)})")
            if res.get("coverage_ledger_path"):
                print(f"coverage-ledger 文件: {res['coverage_ledger_path']}")
        gate = res.get("session_gate")
        if gate:
            reasons = gate.get("reasons") or []
            first = reasons[0] if reasons else {}
            why = first.get("predicate") or "ok"
            action = first.get("action") or first.get("detail") or ""
            suffix = f" ｜ {why}{(': ' + action) if action else ''}" if reasons else ""
            print(f"session-gate: {gate.get('result')}{suffix} ｜ reasons={len(reasons)}")
    elif res.get("reason"):
        print(f"原因: {res['reason']}")
        if res.get("cmd"):
            print(f"暂停命令: {res['cmd']}")
    if res.get("verified"):
        print(f"确定性复验: {res['verified']}")
    if res.get("interrupted"):
        print(f"⚠ 流式中断已抢救（{res.get('error')}）；已落盘证据在 {wd}")
        print(f"  断点续测: python3 run.py --sid {sid} --resume --target {args.target} --authz <...> [--cookie/--bearer ...]")
    print(f"证据/报告/状态/日志: {wd}（事件流见 events.jsonl）")
    return 0 if res["status"] == "vuln_found" else 1


if __name__ == "__main__":
    raise SystemExit(main())
