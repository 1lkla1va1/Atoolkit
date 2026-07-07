"""
engine/orchestrator.py —— 模型无关编排外壳的心脏。

把四件套串成一个会跑的循环（落地实施方案 §3/§4/§5/§6）：
  ModelAdapter(唯一耦合) + enforce(硬约束) + CognitiveState(外部状态) + prompt 拼装。

设计铁律（与模型无关）：
  - 硬约束在外壳，不在 prompt：危险命令实时拦截、授权 host 校验、Guardian 质检、终态裁定。
  - 状态在系统，不在模型记忆：CognitiveState 每轮落盘 + 每轮全量重注入。
  - 换模型只换 adapter，本文件零改动。

广度支柱 1+2：
  - 支柱 1 · 不首洞即停：收到 VULN_FOUND 不再立即 return；会话终止改为三选一——
    ① 覆盖矩阵全格闭合 ② 预算耗尽(max_turns / 无进展超时) ③ 危险闸 block/needs_confirm。
  - 支柱 2 · 覆盖台账：CognitiveState 持有「攻击面 × 漏洞类」矩阵，每格四态
    untested/positive/negative/skipped，负向也留证（harvest 吃 negative_*.md）。
    矩阵是「待测疆域清单(WHAT)」，不是「测试顺序(HOW/ORDER)」——外壳只负责别漏格、别假完成。

自检：`python3 engine/orchestrator.py` 用内置 MockAdapter 端到端跑一遍（无需真实模型）。
"""
from __future__ import annotations
import re, time, json, pathlib
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict, fields
from fnmatch import fnmatch
from typing import Iterator, Protocol

try:                                  # 支持「脚本直跑」与「包内导入」两种方式
    from enforce import (guardian_check, guardian_check_finding, triage, extract_executed_cmds,
                         classify_action, is_authorized_host, finalize,
                         ACCEPTED, BLOCK, CONFIRM)
    from ledger import CoverageLedger, derive_coverage, surfaces_from_legacy_cell
    from knowledge import (load_cards, match_cards, render_skill_hint, resolve_negative_state,
                           negative_sufficient, positive_depth_floor_for, risk_dimensions_for)
    from session_gate import evaluate_session_gate
    from dedupe import aggregate_findings
    from surface import extract_endpoint_paths, is_saturated
    from planner import HIGH_VALUE_TAGS, plan_surfaces, classify_endpoint_domain, filter_surfaces_by_domain
    from vuln_classes import norm_vc, norm_vc_candidates, is_chainable, _squash_ws
    from graph import FactIntentGraph, IntentRuleEngine, merge_agent_graphs, intent_work_queue, merge_run_to_blackboard
    from reporting.collect import collect_structured_findings
    from reporting.render_md import render_final_report, render_coverage_gaps
    from candidate import (CandidateLedger, parse_candidate_lines, parse_triage_lines,
                           parse_reprobe_lines, parse_spread_lines, compute_depth_score,
                           recompute_depth_score, compute_coverage_gaps, coverage_gaps_nonempty,
                           top_work_queue, render_dimension_checklist, render_work_queue,
                           render_proof_ready_block, PROPOSED, TRIAGING, PROOF_READY,
                           CONFIRMED, ROOT_CAUSE_SPREAD, REFUTED, BLOCKED, DUPLICATE)
except ImportError:
    from engine.enforce import (guardian_check, guardian_check_finding, triage, extract_executed_cmds,
                                classify_action, is_authorized_host, finalize,
                                ACCEPTED, BLOCK, CONFIRM)
    from engine.ledger import CoverageLedger, derive_coverage, surfaces_from_legacy_cell
    from engine.knowledge import (load_cards, match_cards, render_skill_hint, resolve_negative_state,
                                  negative_sufficient, positive_depth_floor_for, risk_dimensions_for)
    from engine.session_gate import evaluate_session_gate
    from engine.dedupe import aggregate_findings
    from engine.surface import extract_endpoint_paths, is_saturated
    from engine.planner import HIGH_VALUE_TAGS, plan_surfaces, classify_endpoint_domain, filter_surfaces_by_domain
    from engine.vuln_classes import norm_vc, norm_vc_candidates, is_chainable, _squash_ws
    from engine.graph import FactIntentGraph, IntentRuleEngine, merge_agent_graphs, intent_work_queue, merge_run_to_blackboard
    from engine.reporting.collect import collect_structured_findings
    from engine.reporting.render_md import render_final_report, render_coverage_gaps
    from engine.candidate import (CandidateLedger, parse_candidate_lines, parse_triage_lines,
                                  parse_reprobe_lines, parse_spread_lines, compute_depth_score,
                                  recompute_depth_score, compute_coverage_gaps, coverage_gaps_nonempty,
                                  top_work_queue, render_dimension_checklist, render_work_queue,
                                  render_proof_ready_block, PROPOSED, TRIAGING, PROOF_READY,
                                  CONFIRMED, ROOT_CAUSE_SPREAD, REFUTED, BLOCKED, DUPLICATE)

STATUS_RE = re.compile(r'^\s*(VULN_FOUND|LOW_ROI|NEED_INPUT|ERROR)\s*$', re.M)

# 模型对「单格」声明覆盖结论的通道（外壳维护矩阵的唯一信号源之一）：
#   CELL: <endpoint> | <漏洞类> | PASS|NEG|SKIP | <理由/证据文件名>
# 这是「结论」不是「顺序」：模型自主决定先测哪格、用什么手法，台账只收口。
CELL_RE = re.compile(
    r'^\s*CELL\s*[:：]\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(PASS|NEG|SKIP)\s*(?:\|\s*(.*?))?\s*$',
    re.M | re.I)

# 覆盖格状态。LEGACY_NEGATIVE 只用于 load migration，新代码不得再写入。
UNTESTED = "untested"
POSITIVE = "positive"
NEGATIVE_WITH_EVIDENCE = "negative_with_evidence"
SHALLOW_NEGATIVE = "shallow_negative"
SKIPPED = "skipped"
LEGACY_NEGATIVE = "negative"

# 默认漏洞类（OWASP/SRC 主流；可由 run_session 参数覆盖）。这是「类清单」非「顺序」。
DEFAULT_VULN_CLASSES = ["未授权访问", "越权/IDOR", "SQLi", "XSS", "SSRF",
                        "命令执行/RCE", "文件读取/穿越", "CSRF", "业务逻辑"]
AUTH_FLOW_CLASS = "认证绕过/枚举"
AUTH_KEYWORDS = (
    "register", "login", "reset-password", "password", "captcha", "sms",
    "verify-code", "change-audit", "admin", "token", "session",
)

# v8.5.1: vuln_class 归一化统一迁移到 engine/vuln_classes.py
# norm_vc(), norm_vc_candidates(), is_chainable(), _squash_ws() 从该模块导入（见上方 import）


# 路径归一化（确定性，与模型无关）：把具体 id 形态折叠成占位符，使
#   /api/orders/1001、/api/orders/8f3e-uuid、/api/orders?id=123 与矩阵行 /api/orders/{id} 同格。
# 只归一「行键」用于比对，不改写矩阵里存的真实 endpoint 文案。
_UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
                      r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
_HEXID_RE = re.compile(r'^[0-9a-fA-F]{12,}$')             # 长十六进制 id（如 mongo ObjectId）

def _norm_path(ep: str) -> str:
    """把路径里的数字段 / uuid 段 / {id} 占位 / ?id=123 查询统一折叠成 `{}`，得到可比对的归一键。
    先剥 `scheme://host:port`（真实报告 frontmatter target 常是完整 URL，端口随 host 一起剥），
    使种子行 `/api/user-info` 与报告 `http://host:9000/api/user-info` 从源头归一同形（S1）。"""
    ep = (ep or "").strip()
    ep = re.sub(r'^https?://[^/]+', '', ep)              # S1：剥 scheme://host:port
    ep = ep.split("#", 1)[0]
    path, _, query = ep.partition("?")
    segs = []
    for seg in path.split("/"):
        if seg == "":
            segs.append(seg)
            continue
        if (seg.isdigit() or _UUID_RE.match(seg) or _HEXID_RE.match(seg)
                or (seg.startswith("{") and seg.endswith("}"))):
            segs.append("{}")
        else:
            segs.append(seg)
    norm = "/".join(segs)
    if query:                                            # 含 id 形态的 query → 也折叠，便于 /x?id=1 == /x?id={}
        q = re.sub(r'(=)(\d+|[0-9a-fA-F-]{12,})(?=&|$)', r'={}', query)
        norm = f"{norm}?{q}"
    return norm


def _strip_detail_suffix(norm_path: str) -> str:
    return norm_path[:-3] if norm_path.endswith("/{}") else norm_path


def _same_or_list_detail_path(a: str, b: str) -> bool:
    """Return true for exact normalized path or collection/detail siblings.

    This is intentionally not baked into _norm_path: list/detail equivalence is
    only safe in narrow report-mapping contexts where evidence exists.
    """
    na, nb = _norm_path(a), _norm_path(b)
    return na == nb or _strip_detail_suffix(na) == nb or _strip_detail_suffix(nb) == na


# ── feature 分组（② per-feature 纵深循环）────────────────────────────────────
# 只用于 next_untested 的「建议顺序」：把同一功能/模块的格聚到一起、推完再跨 feature，
# 让模型按功能纵深闭环（列表→详情→改→删→多步→跨账户）而非按漏洞类横扫。
# 不参与闭合判定、不教手法；启发式可能分错组——仅影响建议先后，不影响正确性。
_FEAT_SKIP_SEGS = {"api", "v1", "v2", "v3", "rest", "service", "services", "app", "web"}

# 剥 CRUD/动作前缀 + 属性后缀 → 提取领域名词，使 /api/my-bugs, /api/submit-bug,
# /api/update-bug-status, /api/bugslist 都归到 feature="bug"。
_ACTION_WORDS = frozenset({
    "get", "set", "put", "post", "delete", "del", "remove", "create",
    "add", "new", "update", "edit", "modify", "save", "load", "fetch",
    "list", "search", "find", "query", "check", "verify", "validate",
    "submit", "approve", "reject", "my", "sub", "all", "pull", "push",
    "upload", "download",
})
_QUALIFIER_SUFFIXES = frozenset({
    "list", "info", "detail", "details", "status", "top", "log", "logs",
    "count", "stats", "summary",
})


def _singularize(noun: str) -> str:
    if len(noun) > 4 and noun.endswith("ses"):
        return noun[:-2]
    if len(noun) > 4 and noun.endswith("ies"):
        return noun[:-3] + "y"
    if len(noun) > 3 and noun.endswith("s") and not noun.endswith("ss"):
        return noun[:-1]
    return noun


def _feature_of(ep: str) -> str:
    """把 endpoint 启发式归到一个 feature/模块：取第一个有意义路径段，剥去 CRUD 动词前缀
    与属性后缀（get-/update-/-info/-status），再基础去复数，使同领域 endpoint 归同 feature。
    例：/api/my-bugs, /api/submit-bug, /api/update-bug-status, /api/bugslist → 'bug'。
    判不出 → 'default'。"""
    for seg in _norm_path(ep).split("?", 1)[0].split("/"):
        seg = seg.strip()
        if not seg or seg == "{}" or seg.lower() in _FEAT_SKIP_SEGS:
            continue
        raw = seg.lower()
        parts = re.split(r'[-_]', raw)
        while parts and parts[0] in _ACTION_WORDS:
            parts.pop(0)
        while parts and parts[-1] in _QUALIFIER_SUFFIXES:
            parts.pop()
        if not parts:
            return _singularize(raw)
        noun = parts[0]
        if len(parts) == 1:
            for suf in sorted(_QUALIFIER_SUFFIXES, key=len, reverse=True):
                if noun.endswith(suf) and len(noun) > len(suf):
                    noun = noun[:-len(suf)]
                    break
        return _singularize(noun)
    return "default"


def _is_auth_endpoint(ep: str, feature: str = "") -> bool:
    hay = f"{ep} {feature}".lower()
    return any(k in hay for k in AUTH_KEYWORDS)


def _classes_for_endpoint(base_classes: list[str], ep: str, feature: str,
                          enable_auth: bool) -> list[str]:
    cols = list(base_classes)
    if enable_auth and _is_auth_endpoint(ep, feature) and AUTH_FLOW_CLASS not in cols:
        cols.append(AUTH_FLOW_CLASS)
    return cols


def _endpoint_parts(item: str | dict) -> tuple[str, str, dict]:
    if isinstance(item, dict):
        ep = (item.get("endpoint") or item.get("path") or item.get("url") or "").strip()
        feature = (item.get("feature") or "").strip()
        surface = {k: v for k, v in item.items()
                   if k not in {"endpoint", "path", "url"} and v not in (None, "", [], {})}
        return ep, feature or _feature_of(ep), surface
    ep = (item or "").strip()
    return ep, _feature_of(ep), {}


def _listify(v) -> list:
    if v in (None, "", [], {}):
        return []
    return v if isinstance(v, list) else [v]


def _cell_risk_tags(cell: dict) -> list[str]:
    surface = cell.get("surface") if isinstance(cell.get("surface"), dict) else {}
    return [str(x).lower() for x in _listify(surface.get("risk_tags")) + _listify(cell.get("risk_tags"))]


def _cell_high_value(cell: dict) -> bool:
    tags = set(_cell_risk_tags(cell))
    hay = f"{cell.get('endpoint', '')} {cell.get('vuln', '')} {cell.get('feature', '')}".lower()
    return bool(tags & HIGH_VALUE_TAGS) or any(
        x in hay for x in (
            "auth", "认证", "login", "register", "password", "token", "session",
            "pay", "payment", "refund", "recharge", "amount", "order", "admin",
            "ssrf", "upload", "file", "越权", "idor",
        )
    )


def _merge_surface(old: dict | None, new: dict | None) -> dict:
    merged = dict(old or {})
    for key, value in (new or {}).items():
        if key == "feature":
            continue
        vals = _listify(value)
        if not vals:
            continue
        if key in {"method", "params", "source"}:
            cur = _listify(merged.get(key))
            for x in vals:
                if x not in cur:
                    cur.append(x)
            merged[key] = cur
        else:
            merged.setdefault(key, value)
    return merged


def _cell_schema(ep: str, vc: str, feature: str, surface: dict | None = None) -> dict:
    return {
        "endpoint": ep,
        "vuln": vc,
        "feature": feature or _feature_of(ep),
        "state": UNTESTED,
        "reason": "",
        "evidence": "",
        "next_actions": [],
        "needs": [],
        "needed_roles": [],
        "surface": dict(surface or {}),
    }


# ── 模型适配接缝（唯一与模型耦合处；实现见 codex/codex_adapter.py 等）──────
class ModelAdapter(Protocol):
    name: str
    def run(self, prompt: str, *, session_id: str) -> Iterator[str]: ...


# ── 认知状态对象（§6：外部维护，每轮落盘 + 重注入）──────────────────────
@dataclass
class CognitiveState:
    sid: str
    target: str
    phase: str = "testing"
    hypotheses: list = field(default_factory=list)   # [{id,text,status,evidence}]
    verified: list = field(default_factory=list)
    todo: list = field(default_factory=list)
    evidence_files: list = field(default_factory=list)
    directives: list = field(default_factory=list)   # 外壳注入的强制指令
    turn: int = 0
    last_progress_ts: float = field(default_factory=time.time)
    # ── 支柱 2：覆盖矩阵（攻击面 × 漏洞类），外壳维护，每轮回灌 ──
    vuln_classes: list = field(default_factory=lambda: list(DEFAULT_VULN_CLASSES))
    matrix: dict = field(default_factory=dict)       # key "ep::class" -> cell schema

    # —— 矩阵：初始化/查询/推进 ————————————————————————————
    def seed_matrix(self, endpoints: list[str | dict], *, enable_auth_flow_column: bool = True):
        """从攻击面清单 × 漏洞类铺满矩阵（全格初始 untested）。无 endpoint → 空矩阵（退化为旧行为）。"""
        for item in endpoints:
            ep, feat, surface = _endpoint_parts(item)
            if not ep:
                continue
            for vc in _classes_for_endpoint(self.vuln_classes, ep, feat, enable_auth_flow_column):
                k = self._key(ep, vc)
                if k not in self.matrix:
                    self.matrix[k] = _cell_schema(ep, vc, feat, surface)
                else:
                    cell = self.matrix[k]
                    if not cell.get("feature"):
                        cell["feature"] = feat
                    cell["surface"] = _merge_surface(cell.get("surface"), surface)

    @staticmethod
    def _key(ep: str, vc: str) -> str:
        return f"{ep.strip()}::{vc.strip()}"

    def _find_cell(self, ep: str, vc: str, *, allow_sibling: bool = False) -> dict | None:
        """按 endpoint+漏洞类定位格。匹配收紧（防 S2 子串互含误闭）：
          1) 精确 key 命中（保留）。
          2) 回退：endpoint **归一化后段级相等**（/api/orders/1001 ↔ /api/orders/{id}），
             禁止 `/api` 这类短串子串命中长 endpoint；漏洞类完全相等或类子串。"""
        ep, vc = ep.strip(), vc.strip()
        k = self._key(ep, vc)
        if k in self.matrix:
            return self.matrix[k]
        nep = _norm_path(ep)
        # S2：漏洞类先经同义词归一（去空白 + 复合按 `/` 拆段映射到列名），得到候选列名集合；
        # 再与各格列名（同样归一）比对——命中任一候选即配上。修掉 `越权 / IDOR` 内嵌空格、
        # 以及 `任意文件上传` 与列名零字面重叠导致的失配。
        vc_cands = {_squash_ws(c).lower() for c in norm_vc_candidates(vc)}
        vc_cands.add(_squash_ws(vc).lower())              # 原始去空白形也作候选（直配精确列名）
        sibling_candidates = []
        for cell in self.matrix.values():
            ep_ok = _norm_path(cell["endpoint"]) == nep   # 段级（归一后）相等，不再短串子串
            cvl = _squash_ws(cell["vuln"]).lower()
            cell_cands = {_squash_ws(c).lower() for c in norm_vc_candidates(cell["vuln"])}
            cell_cands.add(cvl)
            vc_ok = bool(vc_cands & cell_cands)           # 候选列名集合相交即配
            if ep_ok and vc_ok:
                return cell
            if allow_sibling and vc_ok and _same_or_list_detail_path(cell["endpoint"], ep):
                sibling_candidates.append(cell)
        if allow_sibling and len(sibling_candidates) == 1:
            return sibling_candidates[0]
        return None

    def set_cell(
        self,
        ep: str,
        vc: str,
        new_state: str,
        reason: str = "",
        evidence: str = "",
        *,
        next_actions: list[str] | None = None,
        needs: list[str] | None = None,
        needed_roles: list[str] | None = None,
        require_evidence: bool | None = None,
    ) -> tuple[bool, str]:
        """推进单格。物理证据 > 声明；无充分证据的 NEG 只能落 shallow_negative。"""
        if new_state == LEGACY_NEGATIVE:
            raise ValueError("legacy negative is read-only; use resolve_negative_state")
        cell = self._find_cell(ep, vc, allow_sibling=(new_state == POSITIVE and bool(evidence)))
        if cell is None:                            # 映射不到已 seed 的格 → 丢弃，绝不新增幽灵格(S1)
            return (False, f"{ep} × {vc} 无对应已 seed 格 → 丢弃(不扩大分母)")
        if cell.get("state") in (POSITIVE, NEGATIVE_WITH_EVIDENCE) and new_state == SHALLOW_NEGATIVE:
            return (False, f"{cell['endpoint']} × {cell['vuln']} 已有充分证据 → 忽略较弱 shallow_negative")
        if require_evidence is None:
            require_evidence = new_state in (POSITIVE, NEGATIVE_WITH_EVIDENCE)
        if new_state == SKIPPED and not reason:
            return (False, "skipped 必须有 reason")
        if new_state in (POSITIVE, NEGATIVE_WITH_EVIDENCE) and require_evidence and not evidence:
            cell["reason"] = (reason or "")[:200]   # 记下声明，但不闭格（防伪完成）
            if cell.get("state") not in (POSITIVE, NEGATIVE_WITH_EVIDENCE, SKIPPED):
                cell["state"] = UNTESTED
            return (False, f"声明 {new_state} 但无物理证据 → 暂不闭格")
        cell["state"] = new_state
        cell["reason"] = (reason or "")[:200]
        if evidence:
            cell["evidence"] = evidence
        if next_actions is not None:
            cell["next_actions"] = list(next_actions)
        if needs is not None:
            cell["needs"] = list(needs)
        if needed_roles is not None:
            cell["needed_roles"] = list(needed_roles)
        return (True, f"{cell['endpoint']} × {cell['vuln']} → {new_state}")

    def matrix_stats(self) -> dict:
        c = {UNTESTED: 0, POSITIVE: 0, NEGATIVE_WITH_EVIDENCE: 0,
             SHALLOW_NEGATIVE: 0, SKIPPED: 0}
        needs_account = 0
        for cell in self.matrix.values():
            c[cell["state"]] = c.get(cell["state"], 0) + 1
            if cell.get("needs"):
                needs_account += 1
        c["total"] = len(self.matrix)
        c["needs_account"] = needs_account
        c["closed"] = c[POSITIVE] + c[NEGATIVE_WITH_EVIDENCE] + c[SKIPPED]
        c["open_risk"] = c[UNTESTED] + c[SHALLOW_NEGATIVE] + needs_account
        return c

    def matrix_closed(self) -> bool:
        """全格闭合 = 无 untested / shallow_negative / needs 格。空矩阵退化为旧行为。"""
        return bool(self.matrix) and all(
            c["state"] not in (UNTESTED, SHALLOW_NEGATIVE) and not c.get("needs")
            for c in self.matrix.values()
        )

    def next_untested(self, n: int = 8) -> list[dict]:
        """高价值 surface 队列：浅阴性/next_actions 最先，高价值面其次，
        已开工 feature 内未闭格优先。只排「建议顺序」，不改闭合判定。"""
        def _feat(c):
            return c.get("feature") or _feature_of(c["endpoint"])
        def _priority(c):
            if c["state"] == SHALLOW_NEGATIVE:
                return 0
            if c.get("next_actions"):
                return 1
            if c["state"] == UNTESTED and not c.get("needs") and _cell_high_value(c):
                return 2
            if c["state"] == UNTESTED and not c.get("needs"):
                return 3
            if c.get("needs"):
                return 4
            return 5
        todo = [c for c in self.matrix.values() if _priority(c) < 5]
        if not todo:
            return []
        started = {_feat(c) for c in self.matrix.values()
                   if c["state"] not in (UNTESTED, SHALLOW_NEGATIVE)}
        todo.sort(key=lambda c: (
            _priority(c),
            0 if _feat(c) in started else 1,
            _feat(c),
            c.get("endpoint", ""),
            c.get("vuln", ""),
        ))
        return todo[:n]

    # —— 状态并进（每轮把模型输出 + 已落盘证据 + 覆盖回填并进系统）——
    def update(self, text: str, evidence: dict, maintain_matrix: bool = True,
               cards: list[dict] | None = None,
               candidate_ledger: "CandidateLedger | None" = None,
               surface_ctx: dict | None = None) -> list[str]:
        """把模型本轮输出 + 已落盘证据并进状态。返回本轮闭格说明（供日志）。
        maintain_matrix=False（无 endpoint 来源的退化模式）时不维护矩阵，保持旧行为。

        v6.1: 若传入 candidate_ledger，解析 DIM/TRIAGE/REPROBE/SPREAD 协议行，
        调用 CandidateLedger.apply() 落盘候选 + 回填 surface 候选统计（§10.2）。
        surface_ctx 提供 DIM 行的 surface 绑定上下文（surface_id/endpoint/method/param）。
        """
        for m in re.findall(r'(?:假设|怀疑|可能存在)[:：]\s*(.+)', text):
            h = m.strip()[:120]
            if h and all(h != x.get("text") for x in self.hypotheses):
                self.hypotheses.append({"id": f"H{len(self.hypotheses)+1}",
                                        "text": h, "status": "verifying", "evidence": None})
        self.evidence_files = evidence.get("files", [])

        notes: list[str] = []
        if not maintain_matrix:
            if candidate_ledger:
                notes.extend(candidate_ledger.apply(
                    text, turn=self.turn, cards=cards,
                    link_callback=None))
            return notes
        # 模型 CELL: 行声明的 (endpoint, 类) —— endpoint 的权威来源（优先级最高，见 S1）。
        # 报告正文常只含具体 id 形态(/api/orders/1001)，靠 CELL 声明的矩阵行端点定位真格。
        cell_decl = [(ep.strip(), vc.strip(), verdict.upper())
                     for ep, vc, verdict, _ in CELL_RE.findall(text)]
        # 1) 报告(positive)：endpoint 权威优先级 ① CELL 声明 ② frontmatter ③ 正文猜测(兜底)
        for rep in evidence.get("report_objs", []):
            ep, vc = _report_cell(rep, cell_decls=cell_decl)
            if ep and vc:
                ok, msg = self.set_cell(ep, vc, POSITIVE, reason="已出报告",
                                        evidence=rep.get("file", "report"))
                if ok:
                    notes.append(f"[PASS] {msg}")
                # 映射失败(无对应 seed 格)：丢弃该闭格动作，留 untested，绝不新增幽灵格
        # 1b) structured finding(positive)：只有 validation accepted 的 normalized finding 才能闭格。
        for nf in evidence.get("normalized_findings", []):
            ep = nf.get("endpoint", "")
            vc = nf.get("vuln_class") or nf.get("class") or nf.get("root_cause", "")
            if ep and vc:
                ok, msg = self.set_cell(ep, vc, POSITIVE, reason="已出 structured finding",
                                        evidence=nf.get("evidence_file", "finding.json"))
                if ok:
                    notes.append(f"[PASS] {msg}")
        # 2) 负向留证(negative_*.md / 覆盖日志)：吃负向通道，让「已测无注入」也能闭格
        for neg in evidence.get("negatives", []):
            ep, vc = neg.get("endpoint", ""), neg.get("vuln", "")
            if ep and vc:
                cell = self._find_cell(ep, vc)
                if not cell:
                    continue
                new_state, missing = resolve_negative_state(cell, neg, cards=cards or [])
                ok, msg = self.set_cell(
                    ep, vc, new_state,
                    reason=neg.get("reason", "已测，无利用"),
                    evidence=neg.get("file", "") if new_state == NEGATIVE_WITH_EVIDENCE else "",
                    next_actions=neg.get("next_actions") or missing,
                    require_evidence=None,
                )
                if ok:
                    notes.append(f"[NEG] {msg}")
        # 3) 模型对单格的显式声明（PASS/NEG/SKIP）：SKIP 直接闭格；PASS/NEG 仍需证据撑腰
        for ep, vc, verdict, reason in CELL_RE.findall(text):
            verdict = verdict.upper()
            if verdict == "SKIP":
                ok, msg = self.set_cell(ep, vc, SKIPPED, reason=reason or "模型跳过(带理由)",
                                        require_evidence=False)
                if ok:
                    notes.append(f"[SKIP] {msg} ｜ {reason}")
            elif verdict in ("PASS", "NEG"):
                # 证据靠 1)/2) 的物理通道闭格；这里仅在已有证据时确认，无证据则不闭格、记下声明
                cell = self._find_cell(ep, vc)
                if verdict == "PASS":
                    if cell and cell.get("evidence"):
                        self.set_cell(ep, vc, POSITIVE, reason=reason, evidence=cell["evidence"])
                    else:
                        self.set_cell(ep, vc, POSITIVE, reason=reason, require_evidence=True)
                elif cell and cell.get("evidence") and cell.get("state") in (
                    NEGATIVE_WITH_EVIDENCE, SHALLOW_NEGATIVE,
                ):
                    cell["reason"] = (reason or cell.get("reason", ""))[:200]
                else:
                    self.set_cell(
                        ep, vc, SHALLOW_NEGATIVE,
                        reason=reason or "模型声明已测无利用，但缺少充分物理证据",
                        next_actions=["补充 negative_*.md，至少 3 个独立向量与响应证据"],
                        require_evidence=False,
                    )
        # v6.1 §10.2: 解析 DIM/TRIAGE/REPROBE/SPREAD 协议行 → 候选落盘 + 回填 surface
        if candidate_ledger:
            notes.extend(candidate_ledger.apply(
                text, turn=self.turn, cards=cards,
                surface_ctx=surface_ctx))
        return notes

    def inject_directive(self, s: str):
        self.directives.append(s)

    def _matrix_block(self) -> str:
        """覆盖台账回灌：清单模板（PASS/NEG/SKIP/未测），并点名下一批未覆盖格。
        只列疆域与状态，不排顺序、不教手法（守哲学锚点 #3）。"""
        if not self.matrix:
            return ""
        s = self.matrix_stats()
        sym = {POSITIVE: "PASS", NEGATIVE_WITH_EVIDENCE: "NEG",
               SHALLOW_NEGATIVE: "≈", SKIPPED: "SKIP", UNTESTED: "·"}
        nxt = self.next_untested()
        queue_lines = []
        for idx, c in enumerate(nxt, start=1):
            actions = c.get("next_actions") or []
            action_s = f"；next={actions[0]}" if actions else ""
            hv_s = "；high-value" if _cell_high_value(c) else ""
            queue_lines.append(
                f"  {idx}. {c['endpoint']} × {c['vuln']} [{sym.get(c['state'], '?')}]{hv_s}{action_s}"
            )
        queue_s = "\n".join(queue_lines) if queue_lines else "  （无，全格已闭合）"
        nxt_s = "；".join(f"{c['endpoint']}×{c['vuln']}" for c in nxt) or "（无，全格已闭合）"
        return (
            "## 覆盖台账（攻击面 × 漏洞类 · 系统维护 · Top 队列）\n"
            f"- 进度: 闭合 {s['closed']}/{s['total']}　(PASS={s[POSITIVE]} "
            f"NEG={s[NEGATIVE_WITH_EVIDENCE]} SHALLOW={s[SHALLOW_NEGATIVE]} "
            f"SKIP={s[SKIPPED]} 未测={s[UNTESTED]} OPEN={s['open_risk']} NEEDS={s['needs_account']})\n"
            "- ⚙ 本轮只注入 Top 8 待测队列（浅阴性/next_actions/高价值面优先）：\n"
            f"{queue_s}\n"
            f"- ⚙ 尚未覆盖（Top 8，自主选序，逐项产出 finding 包 / negative_*.md / CELL SKIP）: {nxt_s}\n"
            "- ⚙ 状态含义：已充分测无利用 → negative_with_evidence（NEG）；"
            "浅测无果/证据不足 → shallow_negative（≈，不闭合，需 next_actions）。\n"
            "- ⚙ 单格收口方式（三选一，物理证据为准）：\n"
            "    · 确认漏洞 → `findings/finding_<id>/finding.json` + request/response/poc（PASS，证据=finding 包）\n"
            "    · 已测无利用 → `negative_*.md`（NEG，需含 `endpoint:`/`vuln:`/`vectors:` + 响应证据片段）\n"
            "    · 跳过 → 输出一行 `CELL: <endpoint> | <类> | SKIP | <理由>`\n"
            "- ⚙ 闭一格后用一行声明结论：`CELL: <endpoint> | <类> | PASS|NEG|SKIP | <理由>`，"
            "然后继续下一未覆盖格，直至全格闭合或预算耗尽。\n"
        )

    def to_prompt_block(self) -> str:
        if self.turn == 0:
            return ""                                 # 首轮无历史状态
        d = "\n".join(f"  - ⚙ {x}" for x in self.directives[-3:])
        head = (
            "## 当前认知状态（系统维护，以此为准，勿依赖你的记忆）\n"
            f"- 阶段: {self.phase} ｜ 轮次: {self.turn}\n"
            f"- 假设: {[h['text'] for h in self.hypotheses] or '（无）'}\n"
            f"- 已验证: {self.verified or '（无）'}\n"
            f"- 待测 TODO: {self.todo or '（无）'}\n"
            f"- 已落盘证据: {[pathlib.Path(f).name for f in self.evidence_files] or '（无）'}\n"
            + (f"- 外壳指令:\n{d}\n" if d else "")
        )
        return head + ("\n" + self._matrix_block() if self.matrix else "")

    def save(self, path: pathlib.Path):
        path.write_text(json.dumps(asdict(self), ensure_ascii=False, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: pathlib.Path) -> "CognitiveState":
        """从 state.json 还原认知状态（断点续测）。按 dataclass 字段过滤，容忍跨版本 schema 漂移。"""
        data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        matrix = data.get("matrix") or {}
        for cell in matrix.values():
            ep = cell.get("endpoint", "")
            cell.setdefault("vuln", "")
            cell.setdefault("feature", _feature_of(ep))
            cell.setdefault("reason", "")
            cell.setdefault("evidence", "")
            cell.setdefault("next_actions", [])
            cell.setdefault("needs", [])
            cell.setdefault("needed_roles", [])
            cell.setdefault("surface", {})
            if cell.get("state") == LEGACY_NEGATIVE:
                if cell.get("evidence"):
                    cell["state"] = NEGATIVE_WITH_EVIDENCE
                else:
                    cell["state"] = SHALLOW_NEGATIVE
                    if not cell.get("next_actions"):
                        cell["next_actions"] = ["补充独立探测向量与响应证据"]
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    def restart_with(self, summary: str):
        """超轮数熔断：压缩为摘要，开新会话续测，证据不丢（矩阵保留，跨会话承接覆盖度）。"""
        self.verified = self.verified + [f"[轮次{self.turn}摘要] {summary}"]
        self.hypotheses = [h for h in self.hypotheses if h["status"] == "verifying"][:5]
        self.directives = []
        self.turn = 0


# ── 报告 → 覆盖格映射（确定性，与模型无关）────────────────────────────────
def _report_cell(rep: dict, cell_decls: list | None = None) -> tuple[str, str]:
    """猜报告归属的 (endpoint, 漏洞类)。endpoint 权威优先级（S1）：
       ① 模型 `CELL: PASS` 行显式声明的 endpoint（与报告类/正文路径归一后吻合则采信，作权威）
       ② 报告 frontmatter 的 `target`/`endpoint` 字段
       ③ 正文猜测（抓首个 /路径）——仅作最后兜底。
    猜不到则返回空，不强行闭格（保守，宁缺毋滥）。"""
    fm = rep.get("fm", {})
    body = rep.get("body", "")
    title = fm.get("title", "")
    vc = (fm.get("type", "") or "").strip()

    # ③ 正文/标题里抓首个 /路径（兜底候选，常为具体 id 形态 /api/orders/1001）
    m = re.search(r'(/[\w\-./{}]+)', title + " " + body)
    body_ep = m.group(1).strip() if m else ""

    # ② frontmatter 权威路径
    fm_ep = (fm.get("target", "") or fm.get("endpoint", "") or "").strip()
    # 真实报告 target 常是完整 URL(http://host:9000/api/user-info)；统一剥 scheme://host:port，
    # 返回纯路径作 endpoint（S1：剥过 host 的结果真正用作返回值，不只用于有效性判断）。
    fm_ep = re.sub(r'^https?://[^/]+', '', fm_ep)
    # target 常是站点根(https://t.example) 而非路径；只有当它含 / 路径段才当 endpoint 用
    if fm_ep and not re.search(r'/[\w\-]', fm_ep):
        fm_ep = ""

    # ① CELL: PASS 声明的 endpoint —— 若其归一路径与「正文路径」或「frontmatter 路径」同形，
    #    或其漏洞类与报告 type 吻合，则采信 CELL 声明的端点（它正是矩阵行的权威写法）。
    if cell_decls:
        cand_eps = [x for x in (body_ep, fm_ep) if x]
        for d_ep, d_vc, d_verdict in cell_decls:
            if d_verdict != "PASS":
                continue
            vc_match = vc and (vc.lower() in d_vc.lower() or d_vc.lower() in vc.lower())
            ep_match = any(_same_or_list_detail_path(d_ep, x) for x in cand_eps)
            if ep_match or (vc_match and not cand_eps):
                return (d_ep, (vc or d_vc).strip())

    ep = fm_ep or body_ep                      # ② 优先 frontmatter，③ 否则正文兜底
    return (ep.strip(), vc.strip())


# ── 证据采集（确定性，与模型无关）────────────────────────────────────────
_SETUP_FILES = {
    "state.json", "authz.md", "cookies.txt", "events.jsonl", "summary.json",
    "final_report.md", "coverage-ledger.json", "inventory.json",
    "candidate-ledger.json", "coverage_gaps.md",
}  # 会话输入/状态/日志/汇总，非证据进展


def count_evidence_files(workdir: pathlib.Path) -> int:
    """只数证据文件、不读内容（给每轮「跑模型前」的进展基线用）。
    F1：harvest_evidence 会整本读每个 .md，早期为拿 prev 计数白跑一次全量 harvest、
    连大 JS bundle / .http 也被无谓读全文；这里只 iterdir 计数，O(目录项) 无读盘。"""
    if not workdir.exists():
        return 0
    count = sum(1 for f in workdir.iterdir() if f.is_file() and f.name not in _SETUP_FILES)
    findings_dir = workdir / "findings"
    if findings_dir.exists():
        for f in findings_dir.glob("finding_*/*"):
            if f.is_file() and f.name not in _SETUP_FILES:
                count += 1
    return count


def harvest_evidence(workdir: pathlib.Path, authorized_hosts: list[str] | None = None) -> dict:
    """采集三类：report_*.md(阳性) / negative_*.md(阴性留证) / 其它原始证据文件。
    负向通道是支柱 2 的核心修复：让「已测无注入」也留档、能进矩阵，不再蒸发。
    F1：只对 .md 候选读全文；其它文件（大 JS bundle / .http 原始包等）只记名不读，
    避免每轮把整目录全量读盘——读盘成本不再随 recon 文件大小×轮数线性膨胀。"""
    reports, negatives, files = [], [], []
    if workdir.exists():
        for f in sorted(workdir.iterdir()):
            if not f.is_file() or f.name in _SETUP_FILES:
                continue
            files.append(str(f))
            if f.suffix != ".md":                  # 非 .md 不是报告/负向候选 → 只记名，绝不读全文
                continue
            name = f.name.lower()
            txt = f.read_text(encoding="utf-8", errors="ignore")
            if name.startswith("negative_"):
                negatives.append(_parse_negative(txt, str(f)))
            elif "severity" in txt[:200]:
                reports.append({"text": txt, "fm": _fm(txt), "body": _body(txt), "file": str(f)})
        findings_dir = workdir / "findings"
        if findings_dir.exists():
            for f in sorted(findings_dir.glob("finding_*/*")):
                if f.is_file() and f.name not in _SETUP_FILES:
                    files.append(str(f))
    structured = collect_structured_findings(workdir, authorized_hosts=authorized_hosts)
    return {"reports": [r["text"] for r in reports],   # 兼容旧 triage 入参（list[str]）
            "report_objs": reports,                    # 带解析的报告对象（供矩阵映射）
            "negatives": negatives, "files": files,
            "finding_objs": structured["finding_objs"],
            "finding_validation": {
                "accepted": structured["accepted"],
                "rejected": structured["rejected"],
            },
            "normalized_findings": structured["normalized"]}


def _fm(txt: str) -> dict:
    fm = {}
    m = re.match(r"\s*---\s*\n(.*?)\n---\s*\n", txt, re.S)
    if m:
        for line in m.group(1).splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                fm[k.strip().lower()] = v.strip()
    return fm


def _body(txt: str) -> str:
    m = re.match(r"\s*---\s*\n.*?\n---\s*\n(.*)$", txt, re.S)
    return m.group(1) if m else txt


def _negative_header(txt: str) -> dict:
    stripped = txt.lstrip()
    m = re.match(r"\s*---\s*\n(.*?)\n---\s*\n", txt, re.S)
    lines = (m.group(1).splitlines() if m else stripped.splitlines()[:40])
    fm, cur_key = {}, ""
    for line in lines:
        if re.match(r"^\s+-\s+", line) and cur_key:
            fm.setdefault(cur_key, [])
            if isinstance(fm[cur_key], list):
                fm[cur_key].append(re.sub(r"^\s+-\s+", "", line).strip())
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            cur_key = k.strip().lower()
            val = v.strip()
            fm[cur_key] = val if val else []
            continue
        if line.strip() and fm and not m:
            break
    return fm


def _parse_negative(txt: str, path: str) -> dict:
    """负向留证文件格式（轻量，模型可读可写）：
        endpoint: /api/user-info
        vuln: SQLi
        reason: 185 探测无注入 / sort 参数仅整数白名单
        <证据片段：curl + 响应，证明确实测过>
    至少要含 endpoint+vuln 才算有效负向证据（物理证据 > 声明）。"""
    fm = _negative_header(txt)
    vectors = fm.get("vectors") or []
    if isinstance(vectors, str):
        vectors = [v.strip() for v in re.split(r"[,，;；]", vectors) if v.strip()]
    next_actions = fm.get("next_actions") or []
    if isinstance(next_actions, str):
        next_actions = [x.strip() for x in re.split(r"[,，;；]", next_actions) if x.strip()]
    evidence_types = fm.get("evidence_types") or []
    if isinstance(evidence_types, str):
        evidence_types = [x.strip() for x in re.split(r"[,，;；]", evidence_types) if x.strip()]
    identities = fm.get("identities") or []
    if isinstance(identities, str):
        identities = [x.strip() for x in re.split(r"[,，;；]", identities) if x.strip()]
    roles = fm.get("roles") or []
    if isinstance(roles, str):
        roles = [x.strip() for x in re.split(r"[,，;；]", roles) if x.strip()]
    body = _body(txt)
    fallback_hits = re.findall(r"\b(?:curl|HTTP/1\.1|HTTP/2|status)\b|响应", body, re.I)
    response_count = len(fallback_hits)
    if not vectors:
        vectors = [x.lower() for x in fallback_hits[:3]]
    return {
        "endpoint": fm.get("endpoint", ""),
        "vuln": fm.get("vuln", "") or fm.get("type", ""),
        "reason": fm.get("reason", "已测，无可利用结果"),
        "file": path,
        "vectors": vectors,
        "next_actions": next_actions,
        "evidence_types": evidence_types,
        "identities": identities,
        "roles": roles,
        "response_count": response_count,
    }


def made_progress(prev_files: int, evidence: dict) -> bool:
    return len(evidence.get("files", [])) > prev_files


def _log_event(wd: pathlib.Path, event: dict) -> None:
    """把一条会话事件 append 进 runs/<sid>/events.jsonl —— 纯磁盘，零 token（永不回灌 prompt）。
    给「做了哪些 / 从哪轮中断 / 收口到哪」留一条可追溯的持久线，补上现在只 print 不落盘的盲区。
    best-effort：日志本身出错绝不影响会话（被 SETUP 排除，不会被 harvest 当证据）。"""
    try:
        rec = {"ts": round(time.time(), 3), **event}
        with (pathlib.Path(wd) / "events.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _sync_coverage_ledger(state: CognitiveState, wd: pathlib.Path,
                          candidates: list[dict] | None = None) -> CoverageLedger:
    """Persist coverage-ledger.json as the run's authoritative coverage artifact.

    The old matrix still drives prompt compatibility; this sync layer migrates
    and merges it into the new endpoint/method/param/role/risk-tag ledger so
    existing closed cells are visible to session-gate and offline evaluation.

    v6.1: if a candidate list is provided, backfill each surface's
    candidate_count/deepest_status/depth_score from it (§4.2 双向耦合).
    """
    path = pathlib.Path(wd) / "coverage-ledger.json"
    metadata = {"sid": state.sid, "target": state.target, "source": "orchestrator"}
    if path.exists():
        try:
            metadata.update(CoverageLedger.load(path).metadata)
        except Exception:
            pass
    ledger = CoverageLedger(metadata=metadata)
    for cell in state.matrix.values():
        for surface in surfaces_from_legacy_cell(cell):
            legacy_vuln = str(surface.get("legacy_vuln") or "").strip()
            if legacy_vuln and surface.get("source") == "legacy-matrix":
                tag = "legacy-" + (re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "-", legacy_vuln.lower()).strip("-") or "vuln")
                risk_tags = list(surface.get("risk_tags") or [])
                if tag not in risk_tags:
                    risk_tags.append(tag)
                surface["risk_tags"] = risk_tags
                sid = str(surface.get("surface_id") or "")
                if tag not in sid:
                    surface["surface_id"] = f"{sid} {{{tag}}}"
            ledger.add_surface(surface)
    if not state.matrix:
        migrated = CoverageLedger.from_state(asdict(state))
        for surface in migrated.surfaces:
            ledger.add_surface(surface)
    # v6.1 §4.2: backfill candidate-aware columns from the candidate ledger
    if candidates:
        ledger.backfill_from_candidates(candidates)
    ledger.metadata.update({
        "sid": state.sid,
        "target": state.target,
        "synced_from": "CognitiveState.matrix",
        "updated_at": round(time.time(), 3),
    })
    ledger.save(path)
    return ledger


def _discover_and_register_endpoints(
    text: str, state: "CognitiveState", inventory_path: pathlib.Path,
    auth_flow_enabled: bool, verbose: bool,
    exclude_endpoints: list[str] | None = None,
    target_domains: list[str] | None = None,
) -> list[str]:
    """P1-3: 从模型回复抽 endpoint 路径，与 inventory/state.matrix 比对；新 endpoint
    经 ``plan_surfaces`` 补风险格进 matrix，并标 ``discovered_during_testing=true``、
    ``source="discovered_in_testing"`` 追加进 inventory.json。

    inventory 不存在则跳过（无台账可比对，--endpoints-only/ad-hoc 路径无 bootstrap 台账）。
    务实战现：只抽 ``/api/*`` 与 ``*.php`` 路径字面量（``surface.extract_endpoint_paths``），
    用 ``_norm_path`` 归一比对防 ``/api/orders/1001`` 与 ``/api/orders/{id}`` 重复登记。
    返回新登记的 endpoint 列表（供事件日志）。
    """
    if not inventory_path.exists():
        return []
    candidates = [
        ep for ep in extract_endpoint_paths(text)
        if not _endpoint_excluded(ep, exclude_endpoints or [])
    ]
    if not candidates:
        return []
    try:
        inv_data = json.loads(inventory_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    inv_records = inv_data.get("endpoints") if isinstance(inv_data, dict) else inv_data
    if not isinstance(inv_records, list):
        inv_records = []
    known_norm: set[str] = set()
    for rec in inv_records:
        ep = rec.get("endpoint", "") if isinstance(rec, dict) else str(rec)
        if ep:
            known_norm.add(_norm_path(ep))
    for cell in state.matrix.values():
        ep = cell.get("endpoint", "")
        if ep:
            known_norm.add(_norm_path(ep))
    new_eps: list[str] = []
    for ep in candidates:
        nep = _norm_path(ep)
        if nep in known_norm:
            continue
        known_norm.add(nep)                       # 防本轮重复登记
        new_eps.append(ep)
    if not new_eps:
        return []
    # 补风险格进 matrix：经 plan_surfaces 补 roles/risk_tags/params，与 run.py seed 同形
    state.seed_matrix(plan_surfaces(new_eps, target_domains=target_domains), enable_auth_flow_column=auth_flow_enabled)
    # 追加进 inventory（discovered_during_testing=true, source=discovered_in_testing）
    now_iso = datetime.fromtimestamp(time.time(), tz=timezone.utc).isoformat()
    for ep in new_eps:
        inv_records.append({
            "endpoint": ep,
            "method": "GET",                      # 模型文本抽取无 method 上下文，默认 GET
            "source": "discovered_in_testing",
            "last_seen": now_iso,
            "discovered_during_testing": True,
        })
    saturated = is_saturated(inv_records)
    inventory_path.write_text(
        json.dumps({"endpoints": inv_records, "saturation_reached": saturated},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    if verbose:
        shown = "；".join(new_eps[:5])
        print(f"            [discovery] 新登记 endpoint {len(new_eps)} 个: {shown}  饱和={saturated}")
    return new_eps


def _endpoint_excluded(endpoint: str, patterns: list[str]) -> bool:
    ep = str(endpoint or "").strip().lower()
    for raw in patterns or []:
        pat = str(raw or "").strip().lower()
        if pat and (fnmatch(ep, pat) or pat in ep):
            return True
    return False


def _knowledge_hint_for_state(state: CognitiveState, cards: list[dict] | None) -> str:
    """Render card hints for the next open cells only, keeping prompt growth bounded."""
    if not state.matrix or not cards:
        return ""
    selected, seen = [], set()
    for cell in state.next_untested(8):
        for card in match_cards(cell, cards):
            cid = card.get("id")
            if cid and cid not in seen:
                seen.add(cid)
                selected.append(card)
    return render_skill_hint(selected)


def _surface_neg_obj(surface: dict) -> dict | None:
    """Build a knowledge.negative_sufficient negative-evidence object from a
    ledger surface, if it carries one. Mirrors session_gate._negative_obj_from_surface."""
    neg = surface.get("negative")
    if isinstance(neg, dict):
        return neg
    obj = {
        "vectors": _listify(surface.get("vectors")),
        "response_count": int(surface.get("response_count", 0) or 0),
        "evidence_types": _listify(surface.get("evidence_types")),
        "identities": _listify(surface.get("identities")),
    }
    if any(obj[k] for k in ("vectors", "response_count", "evidence_types", "identities")):
        return obj
    return None


def _build_candidate_block(state: "CognitiveState", candidate_ledger: "CandidateLedger | None",
                           cards: list[dict] | None, *, candidate_top_n: int = 8) -> str:
    """v6.1 §10.2: 构造 candidate_block 注入 assemble_prompt。

    - recall 相：注入 Top surface 的风险维应答表（§3.1）
    - 非 recall 相：注入 Top N 候选工作队列（§5 优先级）
    - proof 保底：注入达 depth_floor 待证候选清单（§5）
    """
    if not candidate_ledger or not candidate_ledger.candidates:
        # 无候选时：对 Top surface 注入风险维应答表（recall 相）
        if state.matrix and cards:
            blocks: list[str] = []
            for cell in state.next_untested(3):
                surface = {
                    "endpoint": cell.get("endpoint", ""),
                    "risk_tags": _cell_risk_tags(cell),
                    "vuln": cell.get("vuln", ""),
                    "params": _listify((cell.get("surface") or {}).get("params")),
                }
                blocks.append(render_dimension_checklist(surface, cards))
            return "\n\n".join(blocks) if blocks else ""
        return ""
    parts: list[str] = []
    # 工作队列（§5 优先级）
    wq = render_work_queue(candidate_ledger.candidates, candidate_top_n)
    if wq:
        parts.append(wq)
    # proof 保底（§5）
    pr = render_proof_ready_block(candidate_ledger.candidates)
    if pr:
        parts.append(pr)
    return "\n\n".join(parts)


def _clamp_ratio(value: float, default: float = 0.3) -> float:
    try:
        v = float(value)
    except Exception:
        return default
    return max(0.0, min(1.0, v))


def _candidate_status_counts(candidate_ledger: "CandidateLedger | None") -> dict[str, int]:
    counts: dict[str, int] = {}
    if not candidate_ledger:
        return counts
    for cand in candidate_ledger.candidates:
        status = str(cand.get("status") or PROPOSED)
        counts[status] = counts.get(status, 0) + 1
    return counts


def _open_surface_pressure(state: "CognitiveState") -> dict[str, int]:
    pressure = {"high_value_open": 0, "open": 0, "shallow": 0, "needs": 0}
    for cell in state.matrix.values():
        if cell.get("state") in (UNTESTED, SHALLOW_NEGATIVE) or cell.get("needs"):
            pressure["open"] += 1
        if cell.get("state") == SHALLOW_NEGATIVE:
            pressure["shallow"] += 1
        if cell.get("needs"):
            pressure["needs"] += 1
        if cell.get("state") == UNTESTED and _cell_high_value(cell):
            pressure["high_value_open"] += 1
    return pressure


def _select_loop_phase(
    *,
    state: "CognitiveState",
    candidate_ledger: "CandidateLedger | None",
    turn: int,
    max_turns: int,
    loop_mode: str,
    proof_budget_floor: float,
) -> tuple[str, str]:
    """Pick the deterministic outer-loop phase for this turn.

    This does not choose an exploit technique. It only decides whether the next
    model turn should spend attention on recall, triage, proof packaging, or
    coverage closure. That keeps the loop efficient without replacing the
    model's security reasoning.
    """
    counts = _candidate_status_counts(candidate_ledger)
    pressure = _open_surface_pressure(state)
    remaining = max(0, int(max_turns) - int(turn))
    proof_floor_turns = max(1, round(max(1, int(max_turns)) * _clamp_ratio(proof_budget_floor)))

    if counts.get(PROOF_READY, 0):
        return "proof", "proof_ready 候选已达 depth_floor，先出 finding 包，避免已证漏洞漏进报告"
    if remaining <= proof_floor_turns and any(counts.get(s, 0) for s in (TRIAGING, CONFIRMED, ROOT_CAUSE_SPREAD)):
        return "proof", f"剩余预算 {remaining} 轮已进入 proof 保底窗口，停止扩张，优先收证/成报"
    if pressure["shallow"]:
        return "close", "存在 shallow_negative，先补阴性 depth floor 或改为 blocked/needs_input"
    if not candidate_ledger or not candidate_ledger.candidates:
        return "recall", "尚无候选，先对 Top surface 做逐维 CANDIDATE/NONE 应答"
    if loop_mode == "coverage-first" and pressure["high_value_open"]:
        return "coverage", "coverage-first 且仍有高价值 surface 未测，优先消灭覆盖缺口"
    if counts.get(PROPOSED, 0) or counts.get(TRIAGING, 0):
        return "triage", "已有候选，按工作队列推进到 proof_ready/refuted/blocked"
    if pressure["high_value_open"]:
        return "coverage", "候选队列暂空但高价值 surface 未闭合，回到覆盖面 recall"
    return "close", "无更高优先级候选，收口剩余 surface 与 coverage gaps"


def _build_loop_control_block(
    *,
    phase: str,
    reason: str,
    loop_mode: str,
    turn: int,
    max_turns: int,
    candidate_ledger: "CandidateLedger | None",
    state: "CognitiveState",
    lens: list[str] | None,
    adversarial_pass: bool,
    no_flow_surfaces: bool,
) -> str:
    counts = _candidate_status_counts(candidate_ledger)
    pressure = _open_surface_pressure(state)
    queue = top_work_queue(candidate_ledger.candidates, 3) if candidate_ledger else []
    q_lines = []
    for cand in queue:
        q_lines.append(
            f"  - {cand.get('candidate_id','')} [{cand.get('status','')}] "
            f"{cand.get('endpoint','')} depth={cand.get('depth_score',0)}/{cand.get('depth_floor',1)} "
            f"{cand.get('hypothesis','')[:80]}"
        )
    if not q_lines:
        for cell in state.next_untested(3):
            q_lines.append(
                f"  - surface {cell.get('endpoint','')} × {cell.get('vuln','')} "
                f"state={cell.get('state','')}"
            )
    lens_s = ", ".join(lens or []) or "default"
    adversarial_s = "on" if adversarial_pass else "off"
    flow_s = "off" if no_flow_surfaces else "on"
    return (
        "## Loop 编排器（系统调度 · 本轮只做一个焦点）\n"
        f"- phase: {phase}；mode: {loop_mode}；turn: {turn + 1}/{max_turns}；reason: {reason}\n"
        f"- pressure: open={pressure['open']} high_value_open={pressure['high_value_open']} "
        f"shallow={pressure['shallow']} needs={pressure['needs']}；candidates={counts or {}}\n"
        f"- lens: {lens_s}；adversarial_pass={adversarial_s}；flow_surfaces={flow_s}\n"
        "- 规则: 不要横扫全站；只推进下面 Top 队列中的一个候选或一个 surface，完成后用 "
        "DIM/TRIAGE/SPREAD/REPROBE/CELL/negative/finding 落盘回报。\n"
        + "\n".join(q_lines)
    )


def _current_surface_ctx(state: "CognitiveState", cards: list[dict] | None) -> dict | None:
    """v6.1: 构造当前正在测的 surface 的绑定上下文（供 DIM 行解析）。

    取 next_untested 的第一个格，构建 surface_id/endpoint/method/param/depth_floor。
    depth_floor 从 knowledge 卡派生（§6.1）。
    """
    nxt = state.next_untested(1)
    if not nxt:
        return None
    cell = nxt[0]
    surface = cell.get("surface") if isinstance(cell.get("surface"), dict) else {}
    endpoint = cell.get("endpoint", "")
    method = str(surface.get("method") or cell.get("method") or "GET").upper()
    param = ""
    params = _listify(surface.get("params")) or _listify(surface.get("param"))
    if params:
        param = str(params[0])
    roles = surface.get("roles") or cell.get("needed_roles") or ["unknown"]
    risk_tags = _cell_risk_tags(cell)
    # build surface_id (reuse ledger.make_surface_id via import-free local form)
    sid_parts = [method, endpoint]
    if param:
        sid_parts.append(param)
    sid_parts.append(f"[{','.join(roles) if isinstance(roles, list) else roles}]")
    if risk_tags:
        sid_parts.append("{" + ",".join(risk_tags) + "}")
    surface_id = " ".join(sid_parts)
    # depth_floor from cards
    depth_floor = 1
    if cards:
        depth_floor = positive_depth_floor_for(
            {"endpoint": endpoint, "risk_tags": risk_tags, "vuln": cell.get("vuln", ""),
             "params": params}, cards)
    return {"surface_id": surface_id, "endpoint": endpoint, "method": method,
            "param": param, "depth_floor": depth_floor}


# ── 主循环（§3 + 支柱 1：不首洞即停，覆盖闭合/预算/危险闸三选一终止）──────
def run_session(adapter: ModelAdapter, *, target: str, authz: str, core_skill: str,
                workdir: str, authorized_hosts: list[str],
                max_turns: int = 50, no_progress_timeout: float = 20 * 60,
                verify_fn=None, owned_ids: set | None = None,
                confirm_policy: str = "halt", skill_hint: str = "",
                endpoints: list[str] | None = None,
                vuln_classes: list[str] | None = None,
                enable_auth_flow_column: bool | None = None,
                resume: bool = False,
                verbose: bool = True,
                # v6.1 §10.3 flags
                candidate_top_n: int = 8,
                loop_mode: str = "recall-first",
                adversarial_pass: bool = False,
                lens: list[str] | None = None,
                proof_budget_floor: float = 0.3,
                no_flow_surfaces: bool = False,
                exclude_endpoints: list[str] | None = None,
                # v8.5: domain-scoped testing (Cairn architecture §10.2)
                target_domains: list[str] | None = None) -> dict:
    """verify_fn(report_md) -> verify.VerifyResult，可选：对 accepted 报告做确定性重放复验。
    owned_ids：本会话自有对象 id，改删类命中其中则自动放行。
    confirm_policy："halt"=改删他人/未知 id 时熔断停手交人工(默认)；"allow"=放行(信任场景)。
    endpoints：攻击面清单（覆盖矩阵的行来源）。无来源 → 矩阵为空 → 退化为旧的「首个终态标记即结」行为。
    vuln_classes：漏洞类（矩阵的列）。默认 DEFAULT_VULN_CLASSES。

    终止语义（支柱 1）：收到 VULN_FOUND 不再立即 return；终止三选一——
      ① 覆盖矩阵全格闭合（matrix_closed）② 预算耗尽(max_turns / no_progress_timeout)
      ③ 危险闸 block / needs_confirm。矩阵为空时退化：首个终态标记即 _conclude。"""
    sid = pathlib.Path(workdir).name
    wd = pathlib.Path(workdir); wd.mkdir(parents=True, exist_ok=True)
    ev_dir = str(wd.resolve())                            # 钉死的落盘绝对目录
    inventory_path = wd / "inventory.json"                # P1-3：endpoint 台账（与 coverage-ledger.json 同目录）
    state_path = wd / "state.json"
    resumed = bool(resume and state_path.exists())
    auth_flow_enabled = (vuln_classes is None) if enable_auth_flow_column is None else enable_auth_flow_column
    # v8.5: Domain-scoped testing (Cairn architecture §10.2)
    # Resolve target_domains: explicit param > run_scope.json > None (no filter)
    bb_dir = pathlib.Path(wd).parent.parent                 # runs/{target}/
    if not target_domains:
        scope_path = bb_dir / "run_scope.json"
        if scope_path.exists():
            try:
                scope_data = json.loads(scope_path.read_text(encoding="utf-8"))
                td = scope_data.get("target_domains", [])
                if td:
                    target_domains = td
            except Exception:
                pass
    # v8.5.1: Domain soft priority — no longer drops endpoints.
    # plan_surfaces annotates domain_scores + _domain_priority.
    # Target-domain surfaces test first, others test later but are never skipped.
    if target_domains and endpoints:
        surfaces = plan_surfaces(endpoints, target_domains=target_domains)
        if surfaces:
            endpoints = surfaces
        if verbose:
            print(f"  [domain] 域范围限定: {', '.join(target_domains)}  "
                  f"过滤后 {len(endpoints) if isinstance(endpoints, list) else '?'} surfaces")
    if resumed:                                           # 断点续测：载回上次状态，承接覆盖进度
        state = CognitiveState.load(state_path)
        state.target = target
        state.vuln_classes = list(vuln_classes or state.vuln_classes or DEFAULT_VULN_CLASSES)
        state.seed_matrix(endpoints or [], enable_auth_flow_column=auth_flow_enabled)  # 幂等：保留已闭格，仅补新攻击面
        start_turn = state.turn + 1                       # 从「最后完成轮」之后继续
        s0 = state.matrix_stats()
        state.inject_directive(
            f"断点续测：已闭 {s0['closed']}/{s0['total']} 格，从未覆盖格继续，勿重测已闭格")
    else:
        state = CognitiveState(sid=sid, target=target,
                               vuln_classes=list(vuln_classes or DEFAULT_VULN_CLASSES))
        state.seed_matrix(endpoints or [], enable_auth_flow_column=auth_flow_enabled)
        start_turn = 0
    has_matrix = bool(state.matrix)
    # v8.5: inject domain scope directive
    if target_domains:
        state.inject_directive(
            f"域范围测试：本次聚焦 [{', '.join(target_domains)}] 域，"
            f"优先覆盖域内 surface，域外仅在直觉发现高危时追测")
    coverage_ledger = _sync_coverage_ledger(state, wd)
    knowledge_cards = load_cards() if has_matrix else []
    # v6.1: 候选台账 —— 落盘 candidate-ledger.json，不全在对话里（§4.1）
    candidate_ledger_path = wd / "candidate-ledger.json"
    candidate_ledger = CandidateLedger.load(candidate_ledger_path) if has_matrix else None
    # v8.4: Fact-Intent Graph 初始化
    graph = FactIntentGraph()
    graph_path = pathlib.Path(wd) / "fact_intent_graph.json"
    skip_surfaces = []
    # 读取项目级 Blackboard（跨 run 知识继承）
    bb_path = bb_dir / "blackboard.json"
    if bb_path.exists():
        try:
            bb_data = json.loads(bb_path.read_text(encoding="utf-8"))
            skip_surfaces = graph.import_from_blackboard(bb_data)
        except Exception:
            pass  # blackboard 读取失败不阻塞主流程
    if graph_path.exists():
        try:
            saved = json.loads(graph_path.read_text(encoding="utf-8"))
            graph.facts = saved.get("facts", [])
            graph.intents = saved.get("intents", [])
            graph._next_fact_id = saved.get("_next_fact_id", len(graph.facts) + 1)
            graph._next_intent_id = saved.get("_next_intent_id", len(graph.intents) + 1)
        except Exception:
            pass
    last_progress = time.time()
    last_marker = None
    _log_event(wd, {"ev": "start", "target": target, "resumed": resumed,
                    "start_turn": start_turn,
                    "loop": {"mode": loop_mode, "candidate_top_n": candidate_top_n,
                             "proof_budget_floor": proof_budget_floor,
                             "adversarial_pass": adversarial_pass,
                             "lens": lens or [], "flow_surfaces": not no_flow_surfaces},
                    "coverage": state.matrix_stats() if has_matrix else None,
                    "coverage_ledger": derive_coverage(coverage_ledger)})

    for turn in range(start_turn, max_turns):
        state.turn = turn
        dynamic_hint = _knowledge_hint_for_state(state, knowledge_cards)
        combined_hint = "\n\n".join(x for x in (skill_hint, dynamic_hint) if x)
        # v6.1 §10.2: 构造 candidate_block（风险维应答表/工作队列/proof保底）
        candidate_block = _build_candidate_block(state, candidate_ledger, knowledge_cards,
                                                  candidate_top_n=candidate_top_n)
        loop_phase = loop_reason = ""
        if has_matrix:
            loop_phase, loop_reason = _select_loop_phase(
                state=state,
                candidate_ledger=candidate_ledger,
                turn=turn,
                max_turns=max_turns,
                loop_mode=loop_mode,
                proof_budget_floor=proof_budget_floor,
            )
            loop_control = _build_loop_control_block(
                phase=loop_phase,
                reason=loop_reason,
                loop_mode=loop_mode,
                turn=turn,
                max_turns=max_turns,
                candidate_ledger=candidate_ledger,
                state=state,
                lens=lens,
                adversarial_pass=adversarial_pass,
                no_flow_surfaces=no_flow_surfaces,
            )
            candidate_block = "\n\n".join(x for x in (loop_control, candidate_block) if x)
        # v8.4: Graph context for model
        graph_stats = graph.stats()
        pending_intents = graph.get_pending_intents(limit=5)
        if pending_intents or graph_stats["total_facts"] > 0:
            graph_context_lines = [
                f"\n[Fact-Intent Graph] facts={graph_stats['total_facts']} intents={graph_stats['total_intents']} pending_high={graph_stats['high_priority_pending']}",
            ]
            for intent in pending_intents:
                graph_context_lines.append(
                    f"  → Intent {intent['intent_id']}: {intent['description']} [{intent['priority']}]")
            graph_context = "\n".join(graph_context_lines)
        else:
            graph_context = ""
        if graph_context:
            candidate_block = "\n\n".join(x for x in (candidate_block, graph_context) if x)
        prompt = assemble_prompt(core_skill, authz, target, state,
                                 skill_hint=combined_hint, evidence_dir=ev_dir,
                                 candidate_block=candidate_block)
        prev = count_evidence_files(wd)                       # S3：本轮跑模型「之前」的证据计数（F1：只数不读，免一次全量 harvest）
        text_parts = []
        try:                                                  # 流式中断（网络波动/适配器异常）→ 抢救本轮
            for chunk in adapter.run(prompt, session_id=sid): # 流式
                for cmd in extract_executed_cmds(chunk):      # ⚙ 只判「已执行命令」，不判数据/叙述
                    verdict, why = classify_action(cmd, owned_ids)
                    if verdict == BLOCK:                      # ⛔ 灾难必杀（整表/整库/宿主级）→ 终止②(危险闸)
                        if verbose: print(f"  [turn {turn}] ⛔ 灾难命令必杀: {why} → 终止\n      命令: {cmd[:200]}")
                        state.save(state_path)
                        coverage_ledger = _sync_coverage_ledger(state, wd)
                        _log_event(wd, {"ev": "halt", "kind": "block", "turn": turn,
                                        "why": why, "cmd": cmd[:200],
                                        "coverage_ledger": derive_coverage(coverage_ledger)})
                        return {"status": "error", "reason": f"danger:{why}", "cmd": cmd[:200],
                                "turn": turn, "state": asdict(state)}
                    if verdict == CONFIRM and confirm_policy != "allow":   # ⏸ 改删他人/未知 → 熔断交人工(终止②)
                        if verbose: print(f"  [turn {turn}] ⏸ 需人工确认: {why} → 暂停\n      命令: {cmd[:200]}")
                        state.inject_directive(f"在改删类操作处暂停待确认：{why}")
                        state.save(state_path)
                        coverage_ledger = _sync_coverage_ledger(state, wd)
                        _log_event(wd, {"ev": "halt", "kind": "confirm", "turn": turn,
                                        "why": why, "cmd": cmd[:200],
                                        "coverage_ledger": derive_coverage(coverage_ledger)})
                        return {"status": "needs_confirm", "reason": why, "cmd": cmd[:200],
                                "turn": turn, "state": asdict(state)}
                text_parts.append(chunk)
        except Exception as e:
            # 中途断流：抢救本轮——已落盘证据本就独立于流(模型自己写的)，这里把已抓文本并进状态、
            # 采证、存盘、记日志，再走 _conclude 把已证报告过一遍 Guardian，标 interrupted（可 --resume 续）。
            text = "".join(text_parts)
            evidence = harvest_evidence(wd, authorized_hosts=authorized_hosts)
            state.update(text, evidence, maintain_matrix=has_matrix, cards=knowledge_cards,
                         candidate_ledger=candidate_ledger)
            state.save(state_path)
            if candidate_ledger is not None:
                candidate_ledger.save(candidate_ledger_path)
            coverage_ledger = _sync_coverage_ledger(
                state, wd, candidates=candidate_ledger.candidates if candidate_ledger else None)
            _log_event(wd, {"ev": "interrupt", "turn": turn, "error": repr(e)[:300],
                            "files": len(evidence["files"]),
                            "coverage": state.matrix_stats() if has_matrix else None,
                            "coverage_ledger": derive_coverage(coverage_ledger)})
            if verbose:
                print(f"  [turn {turn}] ⚠ 流式中断已抢救: {repr(e)[:120]} → 收口（可 --resume 续）")
            out = _conclude(last_marker, evidence, wd, state, authorized_hosts, turn, verify_fn,
                            candidate_ledger=candidate_ledger, cards=knowledge_cards, graph=graph)
            out.update(status="interrupted", interrupted=True, error=repr(e)[:300])
            return out
        text = "".join(text_parts)

        evidence = harvest_evidence(wd, authorized_hosts=authorized_hosts)  # N1：本轮跑模型「之后」采集一次，复用
        # P1-3：深测中新发现 endpoint —— 先 seed 进 matrix，使本轮 CELL/报告能闭到新格。
        # 无 inventory（--endpoints-only/ad-hoc）或无矩阵时跳过，保持旧行为。
        if has_matrix:
            _discover_and_register_endpoints(
                text, state, inventory_path, auth_flow_enabled, verbose,
                exclude_endpoints=exclude_endpoints, target_domains=target_domains)
        # v6.1: 构造当前 surface_ctx（DIM 行的 surface 绑定上下文）
        _surface_ctx = _current_surface_ctx(state, knowledge_cards) if has_matrix else None
        notes = state.update(text, evidence, maintain_matrix=has_matrix,
                             cards=knowledge_cards,
                             candidate_ledger=candidate_ledger,
                             surface_ctx=_surface_ctx)  # 并进状态 + 回填矩阵 → 闭格说明
        # v8.5: 从候选台账生成结构化 Fact + Intent（替代 v8.4 的 state.verified 空字段循环）
        # 使用 fact_from_candidate 填充 endpoint/vuln_class/params/chain 等字段，
        # 使 IntentRuleEngine 8 条规则能被真正触发。
        # v8.5.1: _chainable_vuln replaced by is_chainable() from vuln_classes.py
        if candidate_ledger is not None:
            for cand in candidate_ledger.candidates:
                cid = cand.get("candidate_id", "")
                if not cid:
                    continue
                existing = [f for f in graph.facts if f.get("source_candidate_id") == cid]
                if existing:
                    continue
                c_status = cand.get("status", "")
                if c_status in (CONFIRMED, ROOT_CAUSE_SPREAD):
                    fact_data = graph.fact_from_candidate(cand, fact_type="confirmed")
                    # Infer chain_feasible when vuln_class is in chainable set
                    if (not fact_data.get("chain_feasible")
                            and is_chainable(fact_data.get("vuln_class", ""))):
                        fact_data["chain_feasible"] = True
                    graph.add_fact(fact_data)
                elif c_status == REFUTED:
                    # Negative fact: enables WAF bypass Rule 5 if WAF keywords present
                    hypothesis = cand.get("hypothesis", "")
                    evidence_text = " ".join(str(e) for e in cand.get("evidence_refs", []))
                    summary_text = f"{hypothesis} {evidence_text}".strip()
                    if summary_text:
                        neg_data = graph.fact_from_candidate(cand, fact_type="negative")
                        neg_data["summary"] = summary_text
                        graph.add_fact(neg_data)
        else:
            # Fallback: no candidate ledger (no matrix mode) — use state.verified
            for finding_id in (state.verified or []):
                existing = [f for f in graph.facts
                           if f.get("source_candidate_id") == finding_id]
                if not existing and finding_id:
                    fact_data = {
                        "source_type": "confirmed",
                        "source_candidate_id": finding_id,
                        "endpoint": "",
                        "summary": finding_id,
                    }
                    graph.add_fact(fact_data)
        state.save(wd / "state.json")
        if candidate_ledger is not None:
            candidate_ledger.save(candidate_ledger_path)
        # v8.4: persist Graph
        graph_path.write_text(json.dumps({
            "facts": graph.facts,
            "intents": graph.intents,
            "_next_fact_id": graph._next_fact_id,
            "_next_intent_id": graph._next_intent_id,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        coverage_ledger = _sync_coverage_ledger(
            state, wd,
            candidates=candidate_ledger.candidates if candidate_ledger else None)
        if made_progress(prev, evidence) or notes:            # 本轮新增证据 or 新闭格 → 进展刷新计时
            last_progress = time.time()
        if verbose:
            st = state.matrix_stats() if has_matrix else None
            extra = f" 矩阵{st['closed']}/{st['total']}" if st else ""
            print(f"  [turn {turn}] 输出{len(text)}字 证据{len(evidence['files'])}个 "
                  f"假设{len(state.hypotheses)}{extra}")
            for n in notes:
                print(f"            {n}")

        marker = STATUS_RE.search(text)
        if marker:
            last_marker = marker.group(1)
            if not has_matrix:                                # 退化：无矩阵 → 旧行为，首个标记即结
                return _conclude(last_marker, evidence, wd, state, authorized_hosts, turn, verify_fn,
                                 candidate_ledger=candidate_ledger, cards=knowledge_cards, graph=graph)
            # 有矩阵：VULN_FOUND/LOW_ROI 不立即 return。
            # NEED_INPUT/ERROR 视为「需人工/系统中断」→ 仍然立即收口（属终止②的人工/系统侧）。
            if last_marker in ("NEED_INPUT", "ERROR"):
                return _conclude(last_marker, evidence, wd, state, authorized_hosts, turn, verify_fn,
                                 candidate_ledger=candidate_ledger, cards=knowledge_cards, graph=graph)
            # 否则：注入「继续下一未覆盖格」指令，进入下一轮（支柱 1 的机制化「继续测试」）
            nxt = state.next_untested()
            if nxt:
                tip = "；".join(f"{c['endpoint']}×{c['vuln']}" for c in nxt)
                state.inject_directive(f"已闭部分格，继续未覆盖格（自主选序）：{tip}")

        _log_event(wd, {"ev": "turn", "turn": turn, "marker": marker.group(1) if marker else None,
                        "out_chars": len(text), "files": len(evidence["files"]),
                        "loop_phase": loop_phase, "loop_reason": loop_reason,
                        "notes": notes, "coverage": state.matrix_stats() if has_matrix else None,
                        "coverage_ledger": derive_coverage(coverage_ledger)})

        # ① 覆盖矩阵全格闭合 → 收口终止
        if has_matrix and state.matrix_closed():
            if verbose: print(f"  [turn {turn}] ✅ 覆盖矩阵全格闭合 → 收口")
            return _conclude(last_marker, evidence, wd, state, authorized_hosts, turn, verify_fn,
                             candidate_ledger=candidate_ledger, cards=knowledge_cards, graph=graph)

        if time.time() - last_progress > no_progress_timeout: # ⚙ 无进展切向（不终止，仅推动）
            state.inject_directive("无进展超时，立刻切换到下一未覆盖格，重读速查卡")
            last_progress = time.time()

    # ② 预算耗尽（max_turns）→ 总结 + 收口（演示里直接结一次；真实场景可 restart 续测）
    if verbose and has_matrix:
        st = state.matrix_stats()
        print(f"  [budget] 达到轮数上限 {max_turns}，矩阵闭合 {st['closed']}/{st['total']} → 收口")
    state.restart_with(summary="达到轮数上限，按已落盘证据与覆盖台账收口")
    return _conclude(last_marker, harvest_evidence(wd, authorized_hosts=authorized_hosts),
                     wd, state, authorized_hosts, max_turns, verify_fn,
                     candidate_ledger=candidate_ledger, cards=knowledge_cards, graph=graph)


# ── Prompt 拼装（§4：约束放头尾，易变放中间）──────────────────────────────
def assemble_prompt(core_skill: str, authz: str, target: str,
                    state: CognitiveState, skill_hint: str = "",
                    private_ctx: str = "", evidence_dir: str = "",
                    candidate_block: str = "") -> str:
    cheats = "## 速查卡（再贴一遍）\n- 现象≠结果 · 无PoC≠漏洞 · 可能不报 · 替换ID测3-5个 · 20min无进展换面 · 单格闭合后继续下一未覆盖格"
    # 硬性落盘约束：钉死绝对目录，否则模型可能写到 /tmp 等处，导致采集层(harvest)看不到、
    # 合格报告被漏判为 low_roi。与具体项目无关，任何目标通用。
    drop = (f"# 落盘约束（硬性，先读）\n"
            f"本会话所有证据与报告**必须写入此绝对目录**，写到 /tmp、$TMPDIR 或别处一律不计入、视为未提交：\n"
            f"  {evidence_dir}\n"
            f"漏洞确立时优先写 `findings/finding_<id>/finding.json` + request/response/poc；"
            f"旧环境才兼容 `report_*.md`（含 severity/title/target frontmatter），原始包用 `*.http`。\n"
            f"已测无利用的格用 `negative_*.md`（含 `endpoint:`/`vuln:`/`reason:`/`vectors:` 头 + 响应证据片段），让阴性也留档。"
            ) if evidence_dir else ""
    parts = [
        f"# 授权文档\n{authz}",                       # [1] 头：合法边界
        f"# 核心技能文件（边界+报告标准，置顶）\n{core_skill}",  # [2] 头：软约束
        drop,                                          # [3] 落盘目录硬约束
        f"# 目标\n{target}\n{private_ctx}",            # [4] 目标+私有线索
        state.to_prompt_block(),                       # [5] 认知状态 + 覆盖台账（长会话才有）
        candidate_block,                               # [5b] v6.1: 候选台账（风险维应答表/工作队列/proof保底）
        f"# 攻击面提示（按意图触发）\n{skill_hint}" if skill_hint else "",  # [6]
        cheats,                                        # [7] 尾：抗遗忘
    ]
    return "\n\n".join(p for p in parts if p.strip())


def _conclude(marker, evidence, wd, state, authorized_hosts, turn, verify_fn=None,
              candidate_ledger: "CandidateLedger | None" = None,
              cards: list[dict] | None = None,
              graph=None) -> dict:
    """Guardian 质检所有报告 → 物理证据裁定终态（证据可翻案）；可选确定性重放复验。
    支柱 2：终态附带覆盖台账统计与负向留证数，让「测了什么/收口到哪」可见。

    v6.1: 候选台账闭环 —— 阴性 depth floor 闭环校验（§6.2）、四类缺口渲染（§8.2）、
    proof_ready 无 finding → 终态强制 incomplete（§D6）。
    """
    triage_ledger = triage(evidence["reports"], evidence_dir=str(wd),
                           authorized_hosts=authorized_hosts)
    structured_guardian_accepted = []
    structured_guardian_rejected = []
    normalized_by_path = {
        str(nf.get("raw_finding_path") or nf.get("evidence_file") or ""): nf
        for nf in evidence.get("normalized_findings", [])
    }
    normalized_structured = []
    for item in evidence.get("finding_objs", []):
        finding_path = pathlib.Path(item.get("path") or "")
        verdict = guardian_check_finding(item.get("finding") or {}, finding_path.parent,
                                         authorized_hosts=authorized_hosts)
        if verdict.result == ACCEPTED:
            structured_guardian_accepted.append({"verdict": verdict, **item})
            rel = ""
            try:
                rel = finding_path.resolve().relative_to(pathlib.Path(wd).resolve()).as_posix()
            except ValueError:
                rel = str(finding_path)
            if rel in normalized_by_path:
                normalized_structured.append(normalized_by_path[rel])
        else:
            structured_guardian_rejected.append({
                "id": item.get("id") or finding_path.parent.name,
                "path": str(finding_path),
                "reasons": [f"guardian:{verdict.result}:L{verdict.level}:{verdict.reason}"],
            })
    has_valid = (len(triage_ledger[ACCEPTED]) + len(structured_guardian_accepted)) > 0
    status = finalize(marker, has_valid)
    cand_list = candidate_ledger.candidates if candidate_ledger else []
    coverage_ledger = _sync_coverage_ledger(state, wd, candidates=cand_list)
    # v6.1 §6.2: 阴性 depth floor 闭环校验 —— 对每个 not_vulnerable surface 复核
    # negative_sufficient；不达 floor 的降级回 not_tested（防浅阴性伪装成 not_vulnerable）。
    if cards is not None:
        for surface in coverage_ledger.surfaces:
            if (str(surface.get("status", "")) == "not_vulnerable"
                    and not surface.get("negative_depth_checked")):
                neg_obj = _surface_neg_obj(surface)
                if neg_obj is not None:
                    sufficient, _missing = negative_sufficient(surface, neg_obj, cards)
                    if not sufficient:
                        surface["status"] = "not_tested"
                        surface.setdefault("next_actions", []).append(
                            "阴性证据不达 depth floor，补向量")
    # P1-3：discovery 饱和标志（来自 inventory.json，重算以权威；无 inventory → None）
    saturation_reached = None
    inv_path = pathlib.Path(wd) / "inventory.json"
    if inv_path.exists():
        try:
            inv_data = json.loads(inv_path.read_text(encoding="utf-8"))
            inv_recs = inv_data.get("endpoints") if isinstance(inv_data, dict) else inv_data
            saturation_reached = is_saturated(inv_recs or [])
        except Exception:
            saturation_reached = None
    # v6.1: finding_candidate_ids = 有 confirmed/root_cause_spread 候选（已出 finding）
    finding_cand_ids = {str(c.get("candidate_id", ""))
                        for c in cand_list
                        if c.get("status") in (CONFIRMED, "root_cause_spread")}
    session_gate = evaluate_session_gate(
        coverage_ledger,
        evidence_dir=str(wd),
        ledger_path=pathlib.Path(wd) / "coverage-ledger.json",
        inventory_path=inv_path,
        candidates=cand_list or None,
        finding_candidate_ids=finding_cand_ids,
    )
    open_risk_cells, needs_cells, shallow_negative_cells = [], [], []
    if state.matrix:
        for cell in state.matrix.values():
            rec = {
                "endpoint": cell.get("endpoint", ""),
                "vuln": cell.get("vuln", ""),
                "state": cell.get("state", ""),
                "reason": cell.get("reason", ""),
                "evidence": cell.get("evidence", ""),
                "next_actions": cell.get("next_actions", []),
                "needs": cell.get("needs", []),
                "needed_roles": cell.get("needed_roles", []),
            }
            if cell.get("state") in (UNTESTED, SHALLOW_NEGATIVE):
                open_risk_cells.append(rec)
            if cell.get("needs"):
                needs_cells.append(rec)
            if cell.get("state") == SHALLOW_NEGATIVE:
                shallow_negative_cells.append(rec)
    if status == "low_roi":
        if open_risk_cells:
            status = "incomplete"
        elif needs_cells:
            status = "needs_input"
    gate_result = session_gate.get("result")
    if gate_result and gate_result != "pass":
        status = {
            "incomplete": "incomplete",
            "needs_input": "needs_input",
            "error": "error",
        }.get(gate_result, "incomplete")
    verified = []
    if verify_fn:                                             # 可选：对 accepted 做确定性重放
        for v, rep in triage_ledger[ACCEPTED]:
            try: verified.append((v.severity, verify_fn(rep).result))
            except Exception as e: verified.append((v.severity, f"verify_error:{e}"))
    state.save(wd / "state.json")
    # P1-2：覆盖完成度指标 —— ledger 中 next_actions 非空的 surface 数。
    open_next_actions_count = sum(
        1 for s in coverage_ledger.surfaces if s.get("next_actions"))
    # P2-3：accepted 报告按根因聚合（同 endpoint+root_cause+affected_role 不重复计）。
    findings = aggregate_findings([rep for _, rep in triage_ledger[ACCEPTED]])
    # v6.1 §8.2: 四类缺口清单（发现但没测/测了没深入/阻塞未恢复/漏进报告）
    demoted_count = len(triage_ledger["demoted"])
    verify_uncertain_count = sum(1 for _sev, v in verified if v == "inconclusive") if verify_fn else 0
    coverage_gaps = compute_coverage_gaps(
        cand_list,
        finding_candidate_ids=finding_cand_ids,
        surfaces=coverage_ledger.surfaces,
        demoted_count=demoted_count,
        verify_uncertain_count=verify_uncertain_count,
    )
    # 渲染独立 coverage_gaps.md
    render_coverage_gaps(coverage_gaps, pathlib.Path(wd) / "coverage_gaps.md")
    # v6.1 §D6: proof_ready 无 finding → 终态强制 incomplete（治"没进报告"头号原因）
    if coverage_gaps.get("proof_ready_without_finding"):
        if status in ("vuln_found", "low_roi"):
            status = "incomplete"
    # v6.1 §8.2 铁律：四类缺口任一非空，终态不得 complete
    if coverage_gaps_nonempty(coverage_gaps) and status == "complete":
        status = "incomplete"
    final_report_path = ""
    final_report_status = "not_generated"
    if structured_guardian_accepted:
        final_report_status = "complete" if gate_result == "pass" else "draft_incomplete"
        final_report_path = str(render_final_report(
            structured_guardian_accepted,
            pathlib.Path(wd) / "final_report.md",
            target_name=(state.target.splitlines()[0] if getattr(state, "target", "") else "目标"),
            status=final_report_status,
            session_gate=session_gate,
            open_risk_cells=open_risk_cells,
            coverage_stats=(derive_coverage(coverage_ledger).get("stats") or {}),
            coverage_gaps=coverage_gaps,
        ))
    out = {
        "status": status, "marker": marker, "turn": turn,
        "accepted": (
            [v.severity for v, _ in triage_ledger[ACCEPTED]]
            + [item["verdict"].severity for item in structured_guardian_accepted]
        ),
        "findings": findings,                       # 聚合后（accepted 原样保留，不丢信息）
        "normalized_findings": normalized_structured,
        "structured_findings": {
            "accepted": len(structured_guardian_accepted),
            "rejected": len(evidence.get("finding_validation", {}).get("rejected", []))
                        + len(structured_guardian_rejected),
        },
        "finding_validation": {
            "accepted": evidence.get("finding_validation", {}).get("accepted", []),
            "rejected": evidence.get("finding_validation", {}).get("rejected", [])
                        + structured_guardian_rejected,
        },
        "final_report_path": final_report_path,
        "final_report_status": final_report_status,
        "verified": verified,
        "demoted": len(triage_ledger["demoted"]),
        "rejected": len(triage_ledger["rejected"]) + len(structured_guardian_rejected),
        "negatives": len(evidence.get("negatives", [])),
        "coverage": state.matrix_stats() if state.matrix else None,
        "coverage_ledger": derive_coverage(coverage_ledger),
        "coverage_ledger_path": str((pathlib.Path(wd) / "coverage-ledger.json").resolve()),
        "session_gate": session_gate,
        "open_risk_cells": open_risk_cells,
        "needs_cells": needs_cells,
        "blocked_cells": needs_cells,
        "shallow_negative_cells": shallow_negative_cells,
        "open_next_actions_count": open_next_actions_count,
        "saturation_reached": saturation_reached,
        # v6.1: 候选台账统计 + 四类缺口清单
        "candidate_stats": (candidate_ledger.stats() if candidate_ledger else {}),
        "coverage_gaps": coverage_gaps,
        "coverage_gaps_nonempty": coverage_gaps_nonempty(coverage_gaps),
        "candidate_ledger_path": str((pathlib.Path(wd) / "candidate-ledger.json").resolve()) if candidate_ledger else "",
        "hit_count": None,                          # 无 oracle；有 oracle 时由 run.py 算
        # v8.4: Fact-Intent Graph 统计
        "graph_stats": graph.stats() if graph else {},
        "state": asdict(state),
    }
    # v8.5: Cross-run blackboard write-back (Cairn architecture §9.7)
    # Merge this run's discoveries into the project-level blackboard so the
    # next run can inherit facts, intents, and negatives.
    if graph:
        try:
            run_id = pathlib.Path(wd).name
            _bb_path = pathlib.Path(wd).parent.parent / "blackboard.json"
            # Construct run_negatives from evidence negative records
            _run_negatives = []
            for neg in evidence.get("negatives", []):
                _ep = neg.get("endpoint", "")
                _vc = neg.get("vuln", neg.get("vuln_class", ""))
                _run_negatives.append({
                    "surface_key": f"{_ep}::{_vc}",
                    "endpoint": _ep,
                    "param": neg.get("param", ""),
                    "vuln_class": _vc,
                    "vectors_tried": neg.get("vectors_tried", 1),
                    "depth_sufficient": neg.get("depth_sufficient", False),
                    "file": neg.get("file", ""),
                })
            merge_run_to_blackboard(str(_bb_path), graph, run_id, _run_negatives)
        except Exception:
            pass  # blackboard write failure is non-fatal
    _log_event(wd, {"ev": "end", "status": status, "marker": marker, "turn": turn,
                    "accepted": out["accepted"], "demoted": out["demoted"],
                    "rejected": out["rejected"], "coverage": out["coverage"],
                    "findings": len(findings),
                    "structured_findings": out["structured_findings"],
                    "final_report_path": final_report_path,
                    "final_report_status": final_report_status,
                    "open_next_actions_count": open_next_actions_count,
                    "saturation_reached": saturation_reached,
                    "coverage_ledger": out["coverage_ledger"],
                    "candidate_stats": out.get("candidate_stats", {}),
                    "coverage_gaps_nonempty": out.get("coverage_gaps_nonempty", False),
                    "session_gate": session_gate})
    return out


# ── 自检：MockAdapter 端到端跑一遍（无需真实模型）─────────────────────────
class MockAdapter:
    """脚本化的假模型，演示支柱 1+2 新行为：
      - 给定 3 endpoint × 默认类 矩阵，逐轮闭格（出报告/负向留证/跳过），
      - 第一份报告后宣布 VULN_FOUND 但**不立即终止**（验证持续循环），
      - 直至矩阵全格闭合或预算耗尽而收口。"""
    name = "mock"
    def __init__(self, wd): self.wd = pathlib.Path(wd); self._t = 0

    def run(self, prompt, *, session_id):
        self._t += 1
        wd = self.wd
        if self._t == 1:
            # 第一轮：出一份**现实报态**报告——endpoint 只在正文且为具体 id 形态(/api/orders/1001)，
            # title 不再字面写矩阵行 /api/orders/{id}，target 是站点根（非路径）。
            # 旧 _report_cell 会把正文首个 /路径(/api/orders/1001) 当 endpoint → 与矩阵行 /api/orders/{id}
            # 既不子串包含、又 set_cell 动态补出幽灵格(撑大分母、真格仍 untested)。修复后靠 CELL: 权威端点闭到真格。
            (wd / "report_idor.md").write_text(
                "---\nseverity: P1\ntitle: 订单越权读取（水平越权）\n"
                "target: https://t.example\ntype: 越权/IDOR\n---\n"
                "换用 B 账号 Cookie 越权读取了 A 用户 /api/orders/1001 订单，提取了收货地址与金额。\n"
                "```\ncurl 'https://t.example/api/orders/1001' -H 'Cookie: B'\n"
                "HTTP/1.1 200 ... 返回了 A 的订单数据\n```\n" + "证据充分。" * 30,
                encoding="utf-8")
            yield "已落盘 report_idor.md，换 3 个 ID 重放均成功越权。\n"
            yield "CELL: /api/orders/{id} | 越权/IDOR | PASS | 已出报告，3 ID 重放\n"
            yield "\nVULN_FOUND\n"                  # ⚙ 支柱1：有矩阵时不再立即终止
        elif self._t == 2:
            # 第二轮：负向留证（SQLi 测了无注入），证明「负向也进台账」不蒸发。
            # T3 知识卡抬高了 /api/user-info×SQLi 的阴性门槛（命中 input-validation /
            # single-param / single-payload-family / no-echo / tested-endpoint-not-param 五卡，
            # 合计要求 ≥5 向量 + 7 类 evidence_types + ≥2 响应）。这里把脚本化证据加厚到
            # 真正充分：5 个独立 payload 家族向量 + 多参数/多家族/二阶/逐参数证据 + 双响应，
            # 让它闭为 negative_with_evidence（演示「合格阴性仍能闭合」），而非落 shallow_negative。
            (wd / "negative_sqli_userinfo.md").write_text(
                "endpoint: /api/user-info\nvuln: SQLi\n"
                "reason: 多参数多 payload 家族二阶证据齐全，185 探测无回显/无时间差/无带外\n"
                "vectors:\n"
                "  - time-based\n"
                "  - error-based\n"
                "  - boolean-blind\n"
                "  - sort-param\n"
                "  - oob-dns\n"
                "evidence_types:\n"
                "  - baseline\n"
                "  - boundary_result\n"
                "  - type_result\n"
                "  - multi_param_coverage\n"
                "  - multi_payload_family_coverage\n"
                "  - per_param_evidence\n"
                "  - second_order_evidence\n"
                "identities:\n"
                "  - owner\n"
                "  - peer\n"
                "curl 'https://t.example/api/user-info?uid=1 AND SLEEP(5)' → 无延迟，HTTP/1.1 200 正常\n"
                "curl 'https://t.example/api/user-info?sort=1;--' → 无报错，HTTP/1.1 200 正常\n"
                "带外回调通道未收到 DNS 请求（second_order_evidence 已采集，无二阶可观测信号）\n",
                encoding="utf-8")
            yield "对 /api/user-info 做了 185 次 SQLi 探测，均无注入，已写 negative_sqli_userinfo.md。\n"
            yield "CELL: /api/user-info | SQLi | NEG | 185探测无注入，已留证\n"
            yield "\nLOW_ROI\n"
        else:
            # 其余轮：把所有剩余未测格批量跳过（带理由），推动矩阵闭合 → 触发终止①
            lines = []
            for line in prompt.splitlines():
                m = re.search(r'尚未覆盖.*?: (.+)$', line)
                if m and "（无" not in m.group(1):
                    for cellspec in m.group(1).split("；"):
                        if "×" in cellspec:
                            ep, _, vc = cellspec.partition("×")
                            lines.append(f"CELL: {ep.strip()} | {vc.strip()} | SKIP | 该面不适用此类/低ROI，跳过")
            yield "对剩余未覆盖格逐一判定：均低 ROI 或不适用，带理由跳过。\n"
            yield "\n".join(lines) + "\n"


if __name__ == "__main__":
    import tempfile
    wd = pathlib.Path(tempfile.mkdtemp()) / "runs" / "sess-demo"
    wd.mkdir(parents=True)
    skill = "（此处注入 核心技能文件.v2.md；演示用占位）"
    skill_path = pathlib.Path(__file__).resolve().parent.parent / "skill" / "核心技能文件.v2.md"
    if skill_path.exists():
        skill = skill_path.read_text(encoding="utf-8")

    print("=== A) 有覆盖矩阵：持续循环 + 矩阵闭合终止（支柱 1+2）===")
    eps = ["/api/orders/{id}", "/api/user-info", "/api/upload"]
    res = run_session(MockAdapter(wd), target="https://t.example",
                      authz="仅限 https://t.example，已授权。",
                      core_skill=skill, workdir=str(wd),
                      authorized_hosts=["t.example"], max_turns=8,
                      endpoints=eps)
    cov = res.get("coverage") or {}
    print("--- 结果 ---")
    print(f"终态: {res['status']}  ｜ 标记: {res.get('marker')}  ｜ 轮次: {res['turn']}")
    print(f"Guardian: accepted={res['accepted']} demoted={res['demoted']} rejected={res['rejected']} 负向留证={res['negatives']}")
    print(f"覆盖矩阵: 闭合 {cov.get('closed')}/{cov.get('total')} "
          f"(PASS={cov.get('positive')} NEG={cov.get('negative_with_evidence')} "
          f"SHALLOW={cov.get('shallow_negative')} SKIP={cov.get('skipped')} 未测={cov.get('untested')})")
    assert res['turn'] >= 2, "应持续多轮，而非首洞即停"
    assert cov.get('untested') == 0, "矩阵应全格闭合"
    assert cov.get('total') == 27, f"矩阵 total 应恒为 3×9=27（不被幽灵格撑大），实得 {cov.get('total')}"
    assert cov.get('positive', 0) >= 1 and cov.get('negative_with_evidence', 0) >= 1, "应有阳性报告与充分阴性留证"
    assert cov.get('shallow_negative', 0) == 0, "A 段充分阴性样例不应落浅阴性"
    assert res.get('findings') and len(res['findings']) >= 1, "_conclude 应输出聚合后的 findings"
    assert res.get('open_next_actions_count') is not None, "_conclude 应输出 open_next_actions_count"
    assert res.get('hit_count') is None, "无 oracle 时 _conclude 的 hit_count 应为 None"
    # 现实报态报告应闭到真格 /api/orders/{id}（而非误闭/补出 /api/orders/1001 幽灵格）
    mtx = res['state']['matrix']
    real_cell = mtx.get("/api/orders/{id}::越权/IDOR")
    assert real_cell and real_cell['state'] == POSITIVE, \
        "现实报态报告应闭到真格 /api/orders/{id}×越权/IDOR=positive"
    assert "/api/orders/1001::越权/IDOR" not in mtx, "不得新增 /api/orders/1001 幽灵格"
    print("✅ 持续循环 + 矩阵闭合 + 负向留档 + 现实报态闭真格(无幽灵格) 全部满足")

    # —— A2) 薄阴性被 shallow 谓词拦 → _conclude 终态 incomplete（P0-2 生效）——————
    # 同一面 /api/user-info×SQLi，仅给 3 向量 + 3 证据类型（不满足抬高的卡门槛）→
    # 落 shallow_negative，且 _conclude 终态 incomplete、带 next_actions（缺什么补什么）。
    print("\n=== A2) 薄阴性被 shallow 谓词拦 → _conclude 终态 incomplete（P0-2）===")
    wd_thin = pathlib.Path(tempfile.mkdtemp()) / "runs" / "sess-thin"
    wd_thin.mkdir(parents=True)
    cards_a2 = load_cards()
    st_thin = CognitiveState(sid="thin", target="https://t.example", vuln_classes=["SQLi"])
    st_thin.seed_matrix(["/api/user-info"], enable_auth_flow_column=False)
    thin_neg = {"endpoint": "/api/user-info", "vuln": "SQLi",
                "reason": "薄阴性：仅 3 向量、缺二阶/多参数/多家族证据",
                "file": "negative_thin.md",
                "vectors": ["time-based", "sort-param", "boundary"],
                "evidence_types": ["baseline", "boundary_result", "type_result"],
                "response_count": 1, "identities": [], "roles": []}
    st_thin.update("", {"files": [], "negatives": [thin_neg]}, cards=cards_a2)
    assert st_thin.matrix["/api/user-info::SQLi"]["state"] == SHALLOW_NEGATIVE, \
        "薄阴性（3向量/缺二阶证据）应被抬高后的卡门槛拦为 shallow_negative"
    out_thin = _conclude("LOW_ROI", {"reports": [], "negatives": [], "files": []},
                         wd_thin, st_thin, ["t.example"], 0)
    assert out_thin["status"] == "incomplete", f"薄阴性终态应为 incomplete，实得 {out_thin['status']}"
    assert out_thin["shallow_negative_cells"], "应有 shallow_negative_cells"
    assert out_thin["open_next_actions_count"] >= 1, "薄阴性应带 next_actions（缺什么补什么）"
    print(f"  薄阴性: cell=shallow_negative 终态={out_thin['status']} "
          f"next_actions={out_thin['open_next_actions_count']}")
    print("✅ 薄阴性被 shallow 谓词拦、_conclude 终态 incomplete（P0-2 生效）")

    # —— H) finding 按根因聚合（P2-3：同 endpoint+root_cause+affected_role 聚合）————
    print("\n=== H) finding 按根因聚合（P2-3：同 endpoint+root_cause+affected_role 聚合）===")
    rep_ha = (
        "---\nseverity: P1\ntitle: 订单越权读取（水平越权）\n"
        "target: https://t.example/api/orders/{id}\ntype: 越权/IDOR\naffected_role: 普通用户\n---\n"
        "换 B 账号 Cookie 越权读取了 A 用户 /api/orders/1001 订单，提取了收货地址。\n"
        "```\ncurl 'https://t.example/api/orders/1001' -H 'Cookie: B'\nHTTP/1.1 200 返回了 A 的订单\n```\n"
        + "证据充分。" * 30)
    rep_hb = (
        "---\nseverity: P2\ntitle: 订单越权删除（水平越权）\n"
        "target: https://t.example/api/orders/{id}\ntype: 越权/IDOR\naffected_role: 普通用户\n---\n"
        "换 B 账号 Cookie 越权删除了 A 用户 /api/orders/1001 订单。\n"
        "```\ncurl -X DELETE 'https://t.example/api/orders/1001' -H 'Cookie: B'\nHTTP/1.1 200 已删除 A 的订单\n```\n"
        + "证据充分。" * 30)
    agg = aggregate_findings([rep_ha, rep_hb])
    assert len(agg) == 1, f"同 endpoint+root_cause+role 应聚合为 1 个 finding，实得 {len(agg)}"
    f0 = agg[0]
    assert len(f0["facets"]) == 2, f"应有两个 facets（两份表现），实得 {f0['facets']}"
    assert f0["severity"] == "P1", f"primary severity 应取最高(P1)，实得 {f0['severity']}"
    assert f0["endpoint"] == "/api/orders/{id}", f"endpoint 应归一，实得 {f0['endpoint']}"
    assert f0["root_cause"] == "越权/IDOR" and f0["affected_role"] == "普通用户"
    assert f0["report_count"] == 2, "report_count 应为 2"
    # 同根因两 facet 不重复计入 critical：聚合后只有 1 个 finding，critical 计数为 1 而非 2
    crit = sum(1 for f in agg if f["severity"] == "P1")
    assert crit == 1, f"同根因两 facet 不应重复计 critical，实得 {crit}"
    # 不同 role 不聚合
    rep_hc = rep_hb.replace("affected_role: 普通用户", "affected_role: 商户")
    agg2 = aggregate_findings([rep_ha, rep_hb, rep_hc])
    assert len(agg2) == 2, f"不同 role 应分为 2 个 finding，实得 {len(agg2)}"
    # 价值排序：越权/IDOR(tier 3) 应排在低价值信息泄露(tier 5)之前
    rep_leak = ("---\nseverity: P2\ntitle: 接口响应头泄露版本号\ntarget: https://t.example/api/version\n"
                "type: 信息泄露\naffected_role: 匿名\n---\n"
                "响应头泄露了服务器版本号。\n```\ncurl -I 'https://t.example/api/version'\nHTTP/1.1 200\n```\n"
                + "证据。" * 40)
    agg3 = aggregate_findings([rep_leak, rep_ha])
    assert agg3[0]["root_cause"] == "越权/IDOR" and agg3[1]["root_cause"] == "信息泄露", \
        "价值排序：越权(tier3) 应排在信息泄露(tier5) 之前"
    print(f"  聚合: 2 份同根因报告 → {len(agg)} finding, facets={len(f0['facets'])}, "
          f"severity={f0['severity']}, primary_impact={f0['primary_impact'][:24]}…")
    print(f"  不同 role 拆分: {len(agg2)} finding ｜ 价值排序: {agg3[0]['root_cause']} → {agg3[1]['root_cause']}")
    print("✅ finding 按根因聚合（同根因不重复计 critical、不同 role 分开、价值排序）满足")

    print("\n=== C) 现实报态报告 → _report_cell 映射单测（S1/S2 修复点）===")
    # 模拟真实报告：endpoint 只在正文且为具体 id 形态；frontmatter target 是站点根；CELL 行声明矩阵行端点。
    rep_real = {"fm": {"title": "订单越权读取（水平越权）", "target": "https://t.example",
                       "type": "越权/IDOR"},
                "body": "越权读取了 A 用户 /api/orders/1001 订单", "file": "report_idor.md"}
    # 修复前：返回 ('/api/orders/1001','越权/IDOR') → set_cell 补幽灵格。
    ep_no_decl, vc_no_decl = _report_cell(rep_real, cell_decls=[])
    print(f"  无 CELL 声明时(纯兜底): endpoint={ep_no_decl}  （会落到具体 id 形态，靠归一化在 _find_cell 收口）")
    ep_decl, vc_decl = _report_cell(
        rep_real, cell_decls=[("/api/orders/{id}", "越权/IDOR", "PASS")])
    print(f"  有 CELL 权威声明时: endpoint={ep_decl}  vuln={vc_decl}")
    assert ep_decl == "/api/orders/{id}", "CELL 声明应作权威 endpoint"
    # 验证归一化：即使兜底拿到具体 id，_find_cell 也能段级归一命中真格、且 set_cell 不补幽灵格。
    st_c = CognitiveState(sid="c", target="https://t.example")
    st_c.seed_matrix(["/api/orders/{id}"])
    before = len(st_c.matrix)
    ok, _ = st_c.set_cell("/api/orders/1001", "越权/IDOR", POSITIVE,
                          evidence="report_idor.md")
    assert ok and len(st_c.matrix) == before, "具体 id 应归一命中真格闭格，不新增幽灵格"
    assert st_c.matrix["/api/orders/{id}::越权/IDOR"]["state"] == POSITIVE
    # S2 反例：短串 /api 不得命中 /api/user 等已 seed 格
    st_s2 = CognitiveState(sid="s2", target="https://t.example")
    st_s2.seed_matrix(["/api/user", "/api/user-info", "/api/users"])
    assert st_s2._find_cell("/api", "SQLi") is None, "短串 /api 不得子串误命中 /api/user"
    assert st_s2._find_cell("/api/user", "SQLi") is st_s2.matrix["/api/user::SQLi"], "精确段级仍应命中"
    print("✅ S1 权威端点 + 路径归一化 + 不补幽灵格 + S2 短串不误命中 全部满足")

    print("\n=== C2) list/detail sibling 阳性唯一 fallback（不放宽 NEG/SKIP）===")
    assert _norm_path("/api/my-bugs") != _norm_path("/api/my-bugs/{id}")
    assert _feature_of("/api/my-bugs") == _feature_of("/api/my-bugs/{id}") == "bug"
    rep_sib = {
        "fm": {"target": "http://t/api/my-bugs/{id}", "type": "越权 / IDOR", "title": "P2 IDOR"},
        "body": "复现见 /api/my-bugs/123",
        "file": "report.md",
    }
    ep_sib, _vc_sib = _report_cell(rep_sib, cell_decls=[("/api/my-bugs", "越权/IDOR", "PASS")])
    assert ep_sib == "/api/my-bugs", "PASS CELL 声明应允许 list/detail sibling 作为权威 endpoint"
    st_sib = CognitiveState(sid="sib", target="http://t")
    st_sib.seed_matrix(["/api/my-bugs"])
    before_sib = len(st_sib.matrix)
    ok, _ = st_sib.set_cell("/api/my-bugs/123", "越权 / IDOR", POSITIVE,
                            evidence="report.md")
    assert ok and len(st_sib.matrix) == before_sib
    assert st_sib.matrix["/api/my-bugs::越权/IDOR"]["state"] == POSITIVE
    st_no_sib = CognitiveState(sid="nosib", target="http://t", vuln_classes=["SQLi"])
    st_no_sib.seed_matrix(["/api/my-bugs/{id}"])
    ok, _ = st_no_sib.set_cell("/api/my-bugs", "SQLi", SHALLOW_NEGATIVE,
                               reason="声明无注入", require_evidence=False)
    assert not ok, "NEG/SHALLOW 不得使用 list/detail sibling fallback"
    st_amb = CognitiveState(sid="amb", target="http://t")
    st_amb.seed_matrix(["/api/my-bugs", "/api/my-bugs/{id}"])
    ok, _ = st_amb.set_cell("/api/my-bugs/123", "越权/IDOR", POSITIVE,
                            evidence="report.md")
    assert ok and st_amb.matrix["/api/my-bugs/{id}::越权/IDOR"]["state"] == POSITIVE
    assert st_amb.matrix["/api/my-bugs::越权/IDOR"]["state"] == UNTESTED
    print("✅ list/detail sibling fallback 仅用于带证据阳性报告，且精确命中优先")

    print("\n=== D) 真实历史报态 → 矩阵命中（焊死真实失败模式·防回归）===")
    # 焊进真实失败模式：frontmatter target 是完整 URL(含 host:port)、无 CELL 行、
    # type 用带空格的复合写法(`越权 / IDOR`、`任意文件上传`)；seed 矩阵行用相对路径。
    # 修复前：① host 没剥 → endpoint 永远配不上相对路径种子行；② 类名带空格/同义词对不齐 → 命中 0。
    st_d = CognitiveState(sid="d", target="http://test.linglongsec.com:9000")
    seed_eps = ["/api/user-info", "/api/pull-content", "/api/upload-image",
                "/api/get-users", "/api/system-log", "/api/update-bug-status",
                "/api/my-bugs/{id}"]
    st_d.seed_matrix(seed_eps)
    total_before = len(st_d.matrix)
    real_reports = [
        # (target 完整 URL, type 复合带空格, 期望命中的列名)
        ("http://test.linglongsec.com:9000/api/user-info",       "越权 / IDOR",           "越权/IDOR"),
        ("http://test.linglongsec.com:9000/api/pull-content",    "SSRF / 未授权内网访问",  "SSRF"),
        ("http://test.linglongsec.com:9000/api/upload-image",    "任意文件上传",          "文件读取/穿越"),
        ("http://test.linglongsec.com:9000/api/upload-image",    "存储型 XSS / 任意文件上传", "XSS"),
        ("http://test.linglongsec.com:9000/api/update-bug-status", "越权 / 业务逻辑",      "越权/IDOR"),
        ("http://test.linglongsec.com:9000/api/get-users",       "未授权访问 / 敏感信息泄露", "未授权访问"),
        ("http://test.linglongsec.com:9000/api/my-bugs/123",     "越权 / IDOR",           "越权/IDOR"),
        ("http://test.linglongsec.com:9000/api/system-log",      "越权 / 敏感信息泄露",    "越权/IDOR"),
    ]
    hit = 0
    for tgt, typ, _expect in real_reports:
        rep = {"fm": {"title": "真实报告", "target": tgt, "type": typ},
               "body": "已越权/已读取，证据见 http 包。", "file": "report_real.md"}
        # 无 CELL 声明（cell_decls=[]）——纯真实报态
        ep, vc = _report_cell(rep, cell_decls=[])
        ok, _msg = st_d.set_cell(ep, vc, POSITIVE, reason="已出报告",
                                 evidence=rep["file"])
        if ok:
            hit += 1
    stats_d = st_d.matrix_stats()
    print(f"  真实报态 {len(real_reports)} 份 → 命中闭格 {hit}/{len(real_reports)}  "
          f"｜ matrix total {stats_d['total']}（seed={total_before}，无幽灵格则相等）")
    assert hit == len(real_reports), \
        f"真实报态报告应全部闭到对应真格，实得 {hit}/{len(real_reports)}（修复前=0）"
    assert stats_d["total"] == total_before, \
        f"matrix total 不得被撑大（无幽灵格），seed={total_before} 实得={stats_d['total']}"
    # 逐格核验：每份报告至少把它「某一命中的已知列格」闭成 positive（复合 type 落到任一命中列即可）。
    def _ep_has_positive(ep: str) -> bool:
        nep = _norm_path(ep)
        return any(c["state"] == POSITIVE for c in st_d.matrix.values()
                   if _norm_path(c["endpoint"]) == nep)
    assert _ep_has_positive("/api/user-info"),        "user-info 越权/IDOR 应闭真格"
    assert _ep_has_positive("/api/pull-content"),     "pull-content SSRF/未授权 复合应闭到任一命中列"
    assert _ep_has_positive("/api/get-users"),        "get-users 未授权访问 应闭真格"
    assert _ep_has_positive("/api/my-bugs/123"),      "具体 id 应归一命中 my-bugs/{id} 真格"
    assert st_d.matrix["/api/my-bugs/{id}::越权/IDOR"]["state"] == POSITIVE, "具体 id 应归一命中 {id} 真格"
    # 越权/IDOR 列必须命中（带空格复合写法 `越权 / IDOR` 修复前因内嵌空格失配）
    assert st_d.matrix["/api/user-info::越权/IDOR"]["state"] == POSITIVE, "`越权 / IDOR` 带空格应归一命中"
    # 上传类（`任意文件上传`，与列名零字面重叠）必须经同义词落到文件操作列
    assert st_d.matrix["/api/upload-image::文件读取/穿越"]["state"] == POSITIVE, "上传类应经同义词落到文件列"
    print("✅ 真实报态(完整URL target + 无CELL + 带空格复合type) 全部闭到真格、无幽灵格")

    print("\n=== G/J/K/L) v3.3 状态迁移、浅阴性、auth-flow、surface 与终态 override ===")
    wdG = pathlib.Path(tempfile.mkdtemp()) / "runs" / "sess-v33"
    wdG.mkdir(parents=True)
    legacy_state = {
        "sid": "legacy", "target": "https://t.example",
        "matrix": {
            "/api/a::SQLi": {"endpoint": "/api/a", "vuln": "SQLi", "state": "negative", "evidence": "negative_a.md"},
            "/api/b::SQLi": {"endpoint": "/api/b", "vuln": "SQLi", "state": "negative", "evidence": ""},
        },
    }
    (wdG / "state.json").write_text(json.dumps(legacy_state, ensure_ascii=False), encoding="utf-8")
    st_g = CognitiveState.load(wdG / "state.json")
    assert st_g.matrix["/api/a::SQLi"]["state"] == NEGATIVE_WITH_EVIDENCE
    assert st_g.matrix["/api/b::SQLi"]["state"] == SHALLOW_NEGATIVE
    assert st_g.matrix["/api/b::SQLi"]["next_actions"], "旧 negative 无 evidence 应补复测动作"

    st_neg = CognitiveState(sid="neg", target="https://t.example", vuln_classes=["SQLi"])
    st_neg.seed_matrix(["/api/user-info"], enable_auth_flow_column=False)
    st_neg.update("CELL: /api/user-info | SQLi | NEG | 只声明无注入", {"files": []})
    assert st_neg.matrix["/api/user-info::SQLi"]["state"] == SHALLOW_NEGATIVE
    assert not st_neg.matrix_closed(), "CELL NEG 无物理证据应为 shallow_negative，不闭合"
    one_vec = {"endpoint": "/api/user-info", "vuln": "SQLi", "reason": "单向量",
               "file": "negative_one.md", "vectors": ["time-based"], "response_count": 1}
    st_neg.update("", {"files": [], "negatives": [one_vec]})
    assert st_neg.matrix["/api/user-info::SQLi"]["state"] == SHALLOW_NEGATIVE
    three_vec = {"endpoint": "/api/user-info", "vuln": "SQLi", "reason": "三向量",
                 "file": "negative_three.md", "vectors": ["time-based", "sort-param", "boundary"],
                 "response_count": 1}
    st_neg.update("", {"files": [], "negatives": [three_vec]})
    assert st_neg.matrix["/api/user-info::SQLi"]["state"] == NEGATIVE_WITH_EVIDENCE
    assert st_neg.matrix_closed(), "三向量 + 响应证据应闭合为 negative_with_evidence"

    st_auth = CognitiveState(sid="auth", target="https://t.example")
    st_auth.seed_matrix(["/api/register", "/api/orders"], enable_auth_flow_column=True)
    assert len(st_auth.matrix) == 19, f"默认 gated auth total 应为 19，实得 {len(st_auth.matrix)}"
    assert "/api/register::认证绕过/枚举" in st_auth.matrix
    assert "/api/orders::认证绕过/枚举" not in st_auth.matrix
    st_auth.seed_matrix(["/api/register", "/api/orders"], enable_auth_flow_column=True)
    assert len(st_auth.matrix) == 19, "重复 seed 不应扩大分母"
    st_custom = CognitiveState(sid="custom", target="https://t.example", vuln_classes=["SQLi"])
    st_custom.seed_matrix(["/api/register"], enable_auth_flow_column=False)
    assert len(st_custom.matrix) == 1
    st_custom2 = CognitiveState(sid="custom2", target="https://t.example", vuln_classes=["SQLi"])
    st_custom2.seed_matrix(["/api/register"], enable_auth_flow_column=True)
    assert len(st_custom2.matrix) == 2

    st_surface = CognitiveState(sid="surface", target="https://t.example", vuln_classes=["SQLi"])
    st_surface.seed_matrix(["/api/create-order"], enable_auth_flow_column=False)
    ok, _ = st_surface.set_cell("/api/create-order", "SQLi", POSITIVE,
                                reason="已出报告", evidence="report_order.md")
    assert ok
    st_surface.seed_matrix([{"endpoint": "/api/create-order", "params": ["order_time"],
                             "method": "POST", "source": "js:app.js"}],
                           enable_auth_flow_column=False)
    surf_cell = st_surface.matrix["/api/create-order::SQLi"]
    assert len(st_surface.matrix) == 1 and surf_cell["state"] == POSITIVE
    assert surf_cell["evidence"] == "report_order.md"
    assert "order_time" in surf_cell["surface"].get("params", [])

    st_inc = CognitiveState(sid="inc", target="https://t.example", vuln_classes=["SQLi"])
    st_inc.seed_matrix(["/api/open"], enable_auth_flow_column=False)
    st_inc.set_cell("/api/open", "SQLi", SHALLOW_NEGATIVE, reason="证据不足", require_evidence=False)
    out_inc = _conclude("LOW_ROI", {"reports": [], "negatives": [], "files": []},
                        wdG, st_inc, ["t.example"], 0)
    assert out_inc["status"] == "incomplete" and out_inc["shallow_negative_cells"]
    st_need = CognitiveState(sid="need", target="https://t.example", vuln_classes=["SQLi"])
    st_need.seed_matrix(["/api/need"], enable_auth_flow_column=False)
    st_need.set_cell("/api/need", "SQLi", SKIPPED, reason="需账号",
                     needs=["account"], needed_roles=["admin"], require_evidence=False)
    out_need = _conclude("LOW_ROI", {"reports": [], "negatives": [], "files": []},
                         wdG, st_need, ["t.example"], 0)
    assert out_need["status"] == "needs_input" and out_need["needs_cells"]
    print("✅ v3.3 G/J/K/L: 迁移、浅阴性、充分阴性、auth-flow、surface merge、终态 override 全部满足")

    print("\n=== I) Phase 2 知识卡 live loop 接通 ===")
    cards_i = load_cards()
    assert cards_i and any(c.get("id") == "input-validation" for c in cards_i), "应加载知识卡"
    st_i = CognitiveState(sid="i", target="https://t.example", vuln_classes=["SQLi"])
    st_i.seed_matrix([{"endpoint": "/api/search", "params": ["keyword", "sort"]}],
                     enable_auth_flow_column=False)
    hint_i = _knowledge_hint_for_state(st_i, cards_i)
    assert "输入校验" in hint_i and "阴性闭合" in hint_i, "open cell 应触发知识卡提示"
    weak_neg = {"endpoint": "/api/search", "vuln": "SQLi", "reason": "默认够但卡不足",
                "file": "negative_search.md", "vectors": ["baseline", "boundary", "type"],
                "response_count": 1, "evidence_types": ["baseline", "boundary_result", "type_result"]}
    st_i.update("", {"files": [], "negatives": [weak_neg]}, cards=cards_i)
    assert st_i.matrix["/api/search::SQLi"]["state"] == SHALLOW_NEGATIVE, \
        "知识卡应提高输入校验阴性门槛，响应证据不足时不闭合"
    # 加厚到满足抬高的卡门槛（5 向量 + 多参数/多家族/二阶/逐参数证据 + 双响应）才闭合
    strong_neg = {
        "endpoint": "/api/search", "vuln": "SQLi", "reason": "多参数多家族二阶证据齐全",
        "file": "negative_search.md",
        "vectors": ["time-based", "error-based", "boolean-blind", "sort-param", "oob-dns"],
        "response_count": 2,
        "evidence_types": ["baseline", "boundary_result", "type_result",
                           "multi_param_coverage", "multi_payload_family_coverage",
                           "per_param_evidence", "second_order_evidence"],
        "identities": [], "roles": [],
    }
    st_i.update("", {"files": [], "negatives": [strong_neg]}, cards=cards_i)
    assert st_i.matrix["/api/search::SQLi"]["state"] == NEGATIVE_WITH_EVIDENCE
    print("✅ Phase 2: 知识卡加载、提示注入、卡增强 negative_sufficiency 全部接通")

    print("\n=== B) 无 endpoint 来源：退化为旧行为（首个终态标记即结）===")
    wd2 = pathlib.Path(tempfile.mkdtemp()) / "runs" / "sess-legacy"
    wd2.mkdir(parents=True)
    res2 = run_session(MockAdapter(wd2), target="https://t.example",
                       authz="仅限 https://t.example，已授权。",
                       core_skill=skill, workdir=str(wd2),
                       authorized_hosts=["t.example"], max_turns=5)  # 无 endpoints
    print(f"终态: {res2['status']}  ｜ 标记: {res2.get('marker')}  ｜ 轮次: {res2['turn']}  ｜ 覆盖矩阵: {res2.get('coverage')}")
    assert res2['turn'] == 0 and res2['status'] == 'vuln_found', "无矩阵应退化为首洞即结(首轮 turn=0)"
    print("✅ 退化路径正确（向后兼容）")

    # ── E) 事件日志(零token) + 中断抢救 + 断点续测 ───────────────────────────
    print("\n=== E) events.jsonl 落盘 + 中断抢救 + 断点续测 ===")

    class BoomAdapter:                       # 模型写完报告后流式断掉（模拟网络波动）
        name = "boom"
        def __init__(self, wd): self.wd = pathlib.Path(wd)
        def run(self, prompt, *, session_id):
            (self.wd / "report_boom.md").write_text(
                "---\nseverity: P1\ntitle: 订单越权读取\ntarget: https://t.example\ntype: 越权/IDOR\n---\n"
                "换用 B 账号 Cookie 越权读取了 A 用户 /api/x 订单，提取了收货地址与金额。\n"
                "```\ncurl 'https://t.example/api/x' -H 'Cookie: B'\nHTTP/1.1 200 ... 返回了 A 的订单\n```\n"
                + "证据充分。" * 30, encoding="utf-8")
            yield "已落盘 report_boom.md\n"
            raise ConnectionError("simulated network drop mid-stream")

    class SkipAllAdapter:                    # 续测：把提示里剩余未覆盖格逐一带理由 SKIP
        name = "skipall"
        def __init__(self, wd): self.wd = pathlib.Path(wd)
        def run(self, prompt, *, session_id):
            lines = []
            for line in prompt.splitlines():
                m = re.search(r'尚未覆盖.*?: (.+)$', line)
                if m and "（无" not in m.group(1):
                    for cs in m.group(1).split("；"):
                        if "×" in cs:
                            ep, _, vc = cs.partition("×")
                            lines.append(f"CELL: {ep.strip()} | {vc.strip()} | SKIP | 续测补格")
            yield "续测：剩余未覆盖格逐一带理由跳过。\n"
            yield "\n".join(lines) + "\n"

    wd3 = pathlib.Path(tempfile.mkdtemp()) / "runs" / "sess-boom"
    wd3.mkdir(parents=True)
    eps3 = ["/api/x", "/api/y"]
    res3 = run_session(BoomAdapter(wd3), target="https://t.example",
                       authz="仅限 https://t.example，已授权。", core_skill=skill,
                       workdir=str(wd3), authorized_hosts=["t.example"],
                       max_turns=6, endpoints=eps3, verbose=False)
    # 中断抢救：状态为 interrupted，但断前已落盘的报告仍被 Guardian 收下
    assert res3["status"] == "interrupted" and res3.get("interrupted"), "断流应收口为 interrupted"
    assert "P1" in res3["accepted"], "断前已落盘的报告应被抢救并 accepted"
    assert (wd3 / "state.json").exists(), "中断也要存盘供续测"
    # 事件日志：纯磁盘落盘，且不被 harvest 当证据（不污染文件计数）
    log_lines = (wd3 / "events.jsonl").read_text(encoding="utf-8").splitlines()
    evs = [json.loads(l)["ev"] for l in log_lines]
    assert "start" in evs and "interrupt" in evs, f"events.jsonl 应含 start/interrupt，实得 {evs}"
    assert "events.jsonl" not in [pathlib.Path(f).name for f in harvest_evidence(wd3)["files"]], \
        "events.jsonl 不得被 harvest 当证据"
    cov3 = res3["coverage"]
    print(f"  中断抢救: status={res3['status']} accepted={res3['accepted']} "
          f"覆盖 {cov3['closed']}/{cov3['total']}  事件流={evs}")

    # 断点续测：复用同一 sid 目录，承接已闭格，把剩余 untested 补完
    saved_closed = res3["coverage"]["closed"]
    res4 = run_session(SkipAllAdapter(wd3), target="https://t.example",
                       authz="仅限 https://t.example，已授权。", core_skill=skill,
                       workdir=str(wd3), authorized_hosts=["t.example"],
                       max_turns=6, endpoints=eps3, resume=True, verbose=False)
    assert res4["coverage"]["untested"] == 0, "续测后应全格闭合"
    assert res4["coverage"]["positive"] >= 1, "续测应保留中断前已闭的阳性格(不重测/不丢)"
    start_evs = [json.loads(l) for l in (wd3 / "events.jsonl").read_text(encoding="utf-8").splitlines()
                 if json.loads(l)["ev"] == "start"]
    assert any(e.get("resumed") for e in start_evs), "应记录到一次 resumed=True 的 start"
    assert start_evs[-1]["start_turn"] >= 1, "续测应从 turn>=1 接续，非从 0 重来"
    print(f"  断点续测: 承接已闭 {saved_closed} → 终态闭合 "
          f"{res4['coverage']['closed']}/{res4['coverage']['total']} "
          f"(PASS={res4['coverage']['positive']})  start_turn={start_evs[-1]['start_turn']}")
    print("✅ 事件日志(零token·不污染证据) + 中断抢救(已证报告不丢) + 断点续测(承接覆盖) 全部满足")

    # ── F) 采证只读 .md：大文件不被全量读盘（F1 回归）─────────────────────────
    print("\n=== F) harvest 只读 .md + prev 只数不读（F1 效率回归）===")
    wdF = pathlib.Path(tempfile.mkdtemp()) / "runs" / "sess-harvest"
    wdF.mkdir(parents=True)
    (wdF / "report_x.md").write_text(
        "---\nseverity: P1\ntitle: t\ntarget: https://t.example\ntype: 越权/IDOR\n---\n"
        "换用 B 账号越权读取了 A 用户订单。\n```\ncurl x\n```\n" + "证据" * 80, encoding="utf-8")
    (wdF / "negative_y.md").write_text(
        "endpoint: /api/y\nvuln: SQLi\nreason: 探测无注入\n", encoding="utf-8")
    big = "x" * 500_000                              # 两个 500KB 非 .md 文件：旧实现会整本读两遍
    (wdF / "vendors~bundle.js").write_text(big, encoding="utf-8")
    (wdF / "raw.http").write_text("GET /api/x HTTP/1.1\nHost: t.example\n" + big, encoding="utf-8")
    _orig_rt = pathlib.Path.read_text
    _read = {"bytes": 0}
    def _tracked_rt(self, *a, **k):                  # 探针：累计 harvest 实际读了多少字节
        s = _orig_rt(self, *a, **k); _read["bytes"] += len(s); return s
    pathlib.Path.read_text = _tracked_rt
    try:
        evF = harvest_evidence(wdF)
    finally:
        pathlib.Path.read_text = _orig_rt
    cntF = count_evidence_files(wdF)                 # 只数不读，restore 后调用（本就不读盘）
    assert len(evF["files"]) == 4 == cntF, f"应列 4 个证据文件且与 count 一致，实得 files={len(evF['files'])} count={cntF}"
    assert len(evF["report_objs"]) == 1 and len(evF["negatives"]) == 1, "只 .md 被解析为报告/负向，大文件不解析"
    assert _read["bytes"] < 50_000, f"harvest 不应整本读两个 500KB 大文件(只读 .md)，实读 {_read['bytes']} 字节"
    print(f"  harvest 读盘 {_read['bytes']} 字节（两个 500KB 大文件未被读）｜ files=4 报告=1 负向=1 ｜ count_evidence_files=4")
    print("✅ F1: 大文件不被全量读盘 + prev 计数只数不读")

    print(f"\n状态落盘: {wd/'state.json'}")
