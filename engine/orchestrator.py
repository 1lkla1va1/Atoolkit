"""
engine/orchestrator.py —— 模型无关编排外壳的心脏。

把四件套串成一个会跑的循环（落地实施方案 §3/§4/§5/§6）：
  ModelAdapter(唯一耦合) + enforce(硬约束) + CognitiveState(外部状态) + prompt 拼装。

设计铁律（与模型无关）：
  - 硬约束在外壳，不在 prompt：危险命令实时拦截、授权 host 校验、Guardian 质检、终态裁定。
  - 状态在系统，不在模型记忆：CognitiveState 每轮落盘 + 每轮全量重注入。
  - 换模型只换 adapter，本文件零改动。

广度支柱 1+2（见 design/广度提升设计.md §2）：
  - 支柱 1 · 不首洞即停：收到 VULN_FOUND 不再立即 return；会话终止改为三选一——
    ① 覆盖矩阵全格闭合 ② 预算耗尽(max_turns / 无进展超时) ③ 危险闸 block/needs_confirm。
  - 支柱 2 · 覆盖台账：CognitiveState 持有「攻击面 × 漏洞类」矩阵，每格四态
    untested/positive/negative/skipped，负向也留证（harvest 吃 negative_*.md）。
    矩阵是「待测疆域清单(WHAT)」，不是「测试顺序(HOW/ORDER)」——外壳只负责别漏格、别假完成。

自检：`python3 engine/orchestrator.py` 用内置 MockAdapter 端到端跑一遍（无需真实模型）。
"""
from __future__ import annotations
import re, time, json, pathlib
from dataclasses import dataclass, field, asdict, fields
from typing import Iterator, Protocol

try:                                  # 支持「脚本直跑」与「包内导入」两种方式
    from enforce import (guardian_check, triage, extract_executed_cmds,
                         classify_action, is_authorized_host, finalize,
                         ACCEPTED, BLOCK, CONFIRM)
    from ledger import CoverageLedger, derive_coverage, surfaces_from_legacy_cell
    from knowledge import load_cards, match_cards, render_skill_hint, resolve_negative_state
    from session_gate import evaluate_session_gate
except ImportError:
    from engine.enforce import (guardian_check, triage, extract_executed_cmds,
                                classify_action, is_authorized_host, finalize,
                                ACCEPTED, BLOCK, CONFIRM)
    from engine.ledger import CoverageLedger, derive_coverage, surfaces_from_legacy_cell
    from engine.knowledge import load_cards, match_cards, render_skill_hint, resolve_negative_state
    from engine.session_gate import evaluate_session_gate

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

# 漏洞类同义词归一表（纯「类名归一化映射」非方法论，不含 payload）：把真实报告 `type`
# 字段里的常见措辞，归一到 DEFAULT_VULN_CLASSES 的列名。报告 type 常为 `A / B` 复合写法，
# 由 _norm_vuln() 按 `/` 拆分逐段归一、命中任一已知列即可落格（见 _find_cell）。
# 键已去空白、小写化；值是 DEFAULT_VULN_CLASSES 中的真实列名（不臆造列名）。
VULN_SYNONYMS = {
    # —— 越权 / IDOR / 业务逻辑越权 → 越权/IDOR 列 ——
    "越权": "越权/IDOR", "idor": "越权/IDOR", "bac": "越权/IDOR",
    "业务逻辑越权": "越权/IDOR", "水平越权": "越权/IDOR", "垂直越权": "越权/IDOR",
    "brokenaccesscontrol": "越权/IDOR", "对象级授权缺失": "越权/IDOR",
    # —— 未授权访问 / 敏感信息泄露 → 未授权访问 列 ——
    "未授权访问": "未授权访问", "未授权": "未授权访问", "未授权内网访问": "未授权访问",
    "敏感信息泄露": "未授权访问", "信息泄露": "未授权访问",
    # —— 上传类 → 文件读取/穿越 列（DEFAULT 无独立上传列，归到文件操作列；纯归一非手法）——
    "任意文件上传": "文件读取/穿越", "文件上传": "文件读取/穿越", "上传": "文件读取/穿越",
    "文件读取": "文件读取/穿越", "路径穿越": "文件读取/穿越", "目录穿越": "文件读取/穿越",
    # —— XSS 各形态 → XSS 列 ——
    "xss": "XSS", "存储型xss": "XSS", "反射型xss": "XSS", "domxss": "XSS",
    # —— SQLi → SQLi 列 ——
    "sql注入": "SQLi", "sqli": "SQLi", "sql": "SQLi",
    # —— SSRF → SSRF 列 ——
    "ssrf": "SSRF", "服务端请求伪造": "SSRF",
    # —— 业务逻辑 → 业务逻辑 列 ——
    "业务逻辑": "业务逻辑",
    # —— RCE / 命令执行 → 命令执行/RCE 列 ——
    "rce": "命令执行/RCE", "命令执行": "命令执行/RCE", "代码执行": "命令执行/RCE",
}


def _squash_ws(s: str) -> str:
    """去掉所有空白：`越权 / IDOR` → `越权/IDOR`，使带内嵌空格的复合写法可与列名比对。"""
    return re.sub(r'\s+', '', s or "")


def _norm_vuln(vc: str) -> list[str]:
    """把报告 type（可能是 `A / B` 复合、带空格）归一为一组候选列名：
       去空白 → 按 `/` 拆段 → 每段查同义词表（小写键），命中即映射到列名，否则保留原段去空白形。
       命中任一已知列即可落格（一份报告落到它命中的那个列格）。整体也作为一个候选（便于精确列名直配）。"""
    raw = _squash_ws(vc)
    cands: list[str] = []
    if raw:
        cands.append(VULN_SYNONYMS.get(raw.lower(), raw))
    for seg in raw.split("/"):
        seg = seg.strip()
        if not seg:
            continue
        cands.append(VULN_SYNONYMS.get(seg.lower(), seg))
    # 去重保序
    seen, out = set(), []
    for c in cands:
        if c and c not in seen:
            seen.add(c); out.append(c)
    return out

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
        vc_cands = {_squash_ws(c).lower() for c in _norm_vuln(vc)}
        vc_cands.add(_squash_ws(vc).lower())              # 原始去空白形也作候选（直配精确列名）
        sibling_candidates = []
        for cell in self.matrix.values():
            ep_ok = _norm_path(cell["endpoint"]) == nep   # 段级（归一后）相等，不再短串子串
            cvl = _squash_ws(cell["vuln"]).lower()
            cell_cands = {_squash_ws(c).lower() for c in _norm_vuln(cell["vuln"])}
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

    def next_untested(self, n: int = 6) -> list[dict]:
        """② feature-aware：优先推完「已开工(已有闭格)但未完」的 feature，再起新 feature，
        同 feature 的未覆盖格聚在一起——只排「建议顺序」，不改闭合判定。
        load 兜底：老 state.json 的 cell 无 `feature` 键 → 现场按 endpoint 启发式补。"""
        def _feat(c):
            return c.get("feature") or _feature_of(c["endpoint"])
        def _priority(c):
            if c["state"] == SHALLOW_NEGATIVE:
                return 0
            if c["state"] == UNTESTED and not c.get("needs"):
                return 1
            if c.get("needs"):
                return 2
            return 3
        todo = [c for c in self.matrix.values() if _priority(c) < 3]
        if not todo:
            return []
        started = {_feat(c) for c in self.matrix.values()
                   if c["state"] not in (UNTESTED, SHALLOW_NEGATIVE)}
        # 稳定排序：已开工 feature(0) 先于未开工(1)；同档按 feature 名聚合，组内保持插入序。
        todo.sort(key=lambda c: (_priority(c), 0 if _feat(c) in started else 1, _feat(c)))
        return todo[:n]

    # —— 状态并进（每轮把模型输出 + 已落盘证据 + 覆盖回填并进系统）——
    def update(self, text: str, evidence: dict, maintain_matrix: bool = True,
               cards: list[dict] | None = None) -> list[str]:
        """把模型本轮输出 + 已落盘证据并进状态。返回本轮闭格说明（供日志）。
        maintain_matrix=False（无 endpoint 来源的退化模式）时不维护矩阵，保持旧行为。"""
        for m in re.findall(r'(?:假设|怀疑|可能存在)[:：]\s*(.+)', text):
            h = m.strip()[:120]
            if h and all(h != x.get("text") for x in self.hypotheses):
                self.hypotheses.append({"id": f"H{len(self.hypotheses)+1}",
                                        "text": h, "status": "verifying", "evidence": None})
        self.evidence_files = evidence.get("files", [])

        notes: list[str] = []
        if not maintain_matrix:
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
        # 按 endpoint 聚合成清单
        by_ep: dict[str, list] = {}
        for cell in self.matrix.values():
            by_ep.setdefault(cell["endpoint"], []).append(cell)
        lines = []
        for ep in sorted(by_ep):
            tags = " ".join(f"{c['vuln']}={sym.get(c['state'], '?')}" for c in by_ep[ep])
            lines.append(f"  - {ep}: {tags}")
        nxt = self.next_untested()
        nxt_s = "；".join(f"{c['endpoint']}×{c['vuln']}" for c in nxt) or "（无，全格已闭合）"
        return (
            "## 覆盖台账（攻击面 × 漏洞类 · 系统维护 · 待测疆域非测试顺序）\n"
            f"- 进度: 闭合 {s['closed']}/{s['total']}　(PASS={s[POSITIVE]} "
            f"NEG={s[NEGATIVE_WITH_EVIDENCE]} SHALLOW={s[SHALLOW_NEGATIVE]} "
            f"SKIP={s[SKIPPED]} 未测={s[UNTESTED]} OPEN={s['open_risk']} NEEDS={s['needs_account']})\n"
            + "\n".join(lines) + "\n"
            f"- ⚙ 尚未覆盖（自主选序，先测哪格你定）: {nxt_s}\n"
            "- ⚙ 状态含义：已充分测无利用 → negative_with_evidence（NEG）；"
            "浅测无果/证据不足 → shallow_negative（≈，不闭合，需 next_actions）。\n"
            "- ⚙ 单格收口方式（三选一，物理证据为准）：\n"
            "    · 出报告 → `report_*.md`（PASS，证据=报告）\n"
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
_SETUP_FILES = {"state.json", "authz.md", "cookies.txt", "events.jsonl"}  # 会话输入/状态/日志，非证据


def count_evidence_files(workdir: pathlib.Path) -> int:
    """只数证据文件、不读内容（给每轮「跑模型前」的进展基线用）。
    F1：harvest_evidence 会整本读每个 .md，早期为拿 prev 计数白跑一次全量 harvest、
    连大 JS bundle / .http 也被无谓读全文；这里只 iterdir 计数，O(目录项) 无读盘。"""
    if not workdir.exists():
        return 0
    return sum(1 for f in workdir.iterdir() if f.is_file() and f.name not in _SETUP_FILES)


def harvest_evidence(workdir: pathlib.Path) -> dict:
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
    return {"reports": [r["text"] for r in reports],   # 兼容旧 triage 入参（list[str]）
            "report_objs": reports,                    # 带解析的报告对象（供矩阵映射）
            "negatives": negatives, "files": files}


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


def _sync_coverage_ledger(state: CognitiveState, wd: pathlib.Path) -> CoverageLedger:
    """Persist coverage-ledger.json as the run's authoritative coverage artifact.

    The old matrix still drives prompt compatibility; this sync layer migrates
    and merges it into the new endpoint/method/param/role/risk-tag ledger so
    existing closed cells are visible to session-gate and offline evaluation.
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
    ledger.metadata.update({
        "sid": state.sid,
        "target": state.target,
        "synced_from": "CognitiveState.matrix",
        "updated_at": round(time.time(), 3),
    })
    ledger.save(path)
    return ledger


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
                verbose: bool = True) -> dict:
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
    state_path = wd / "state.json"
    resumed = bool(resume and state_path.exists())
    auth_flow_enabled = (vuln_classes is None) if enable_auth_flow_column is None else enable_auth_flow_column
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
    coverage_ledger = _sync_coverage_ledger(state, wd)
    knowledge_cards = load_cards() if has_matrix else []
    last_progress = time.time()
    last_marker = None
    _log_event(wd, {"ev": "start", "target": target, "resumed": resumed,
                    "start_turn": start_turn,
                    "coverage": state.matrix_stats() if has_matrix else None,
                    "coverage_ledger": derive_coverage(coverage_ledger)})

    for turn in range(start_turn, max_turns):
        state.turn = turn
        dynamic_hint = _knowledge_hint_for_state(state, knowledge_cards)
        combined_hint = "\n\n".join(x for x in (skill_hint, dynamic_hint) if x)
        prompt = assemble_prompt(core_skill, authz, target, state,
                                 skill_hint=combined_hint, evidence_dir=ev_dir)
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
            evidence = harvest_evidence(wd)
            state.update(text, evidence, maintain_matrix=has_matrix, cards=knowledge_cards)
            state.save(state_path)
            coverage_ledger = _sync_coverage_ledger(state, wd)
            _log_event(wd, {"ev": "interrupt", "turn": turn, "error": repr(e)[:300],
                            "files": len(evidence["files"]),
                            "coverage": state.matrix_stats() if has_matrix else None,
                            "coverage_ledger": derive_coverage(coverage_ledger)})
            if verbose:
                print(f"  [turn {turn}] ⚠ 流式中断已抢救: {repr(e)[:120]} → 收口（可 --resume 续）")
            out = _conclude(last_marker, evidence, wd, state, authorized_hosts, turn, verify_fn)
            out.update(status="interrupted", interrupted=True, error=repr(e)[:300])
            return out
        text = "".join(text_parts)

        evidence = harvest_evidence(wd)                       # N1：本轮跑模型「之后」采集一次，复用
        notes = state.update(text, evidence, maintain_matrix=has_matrix,
                             cards=knowledge_cards)  # 并进状态 + 回填矩阵 → 闭格说明
        state.save(wd / "state.json")
        coverage_ledger = _sync_coverage_ledger(state, wd)
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
                return _conclude(last_marker, evidence, wd, state, authorized_hosts, turn, verify_fn)
            # 有矩阵：VULN_FOUND/LOW_ROI 不立即 return。
            # NEED_INPUT/ERROR 视为「需人工/系统中断」→ 仍然立即收口（属终止②的人工/系统侧）。
            if last_marker in ("NEED_INPUT", "ERROR"):
                return _conclude(last_marker, evidence, wd, state, authorized_hosts, turn, verify_fn)
            # 否则：注入「继续下一未覆盖格」指令，进入下一轮（支柱 1 的机制化「继续测试」）
            nxt = state.next_untested()
            if nxt:
                tip = "；".join(f"{c['endpoint']}×{c['vuln']}" for c in nxt)
                state.inject_directive(f"已闭部分格，继续未覆盖格（自主选序）：{tip}")

        _log_event(wd, {"ev": "turn", "turn": turn, "marker": marker.group(1) if marker else None,
                        "out_chars": len(text), "files": len(evidence["files"]),
                        "notes": notes, "coverage": state.matrix_stats() if has_matrix else None,
                        "coverage_ledger": derive_coverage(coverage_ledger)})

        # ① 覆盖矩阵全格闭合 → 收口终止
        if has_matrix and state.matrix_closed():
            if verbose: print(f"  [turn {turn}] ✅ 覆盖矩阵全格闭合 → 收口")
            return _conclude(last_marker, evidence, wd, state, authorized_hosts, turn, verify_fn)

        if time.time() - last_progress > no_progress_timeout: # ⚙ 无进展切向（不终止，仅推动）
            state.inject_directive("无进展超时，立刻切换到下一未覆盖格，重读速查卡")
            last_progress = time.time()

    # ② 预算耗尽（max_turns）→ 总结 + 收口（演示里直接结一次；真实场景可 restart 续测）
    if verbose and has_matrix:
        st = state.matrix_stats()
        print(f"  [budget] 达到轮数上限 {max_turns}，矩阵闭合 {st['closed']}/{st['total']} → 收口")
    state.restart_with(summary="达到轮数上限，按已落盘证据与覆盖台账收口")
    return _conclude(last_marker, harvest_evidence(wd), wd, state, authorized_hosts, max_turns, verify_fn)


# ── Prompt 拼装（§4：约束放头尾，易变放中间）──────────────────────────────
def assemble_prompt(core_skill: str, authz: str, target: str,
                    state: CognitiveState, skill_hint: str = "",
                    private_ctx: str = "", evidence_dir: str = "") -> str:
    cheats = "## 速查卡（再贴一遍）\n- 现象≠结果 · 无PoC≠漏洞 · 可能不报 · 替换ID测3-5个 · 20min无进展换面 · 单格闭合后继续下一未覆盖格"
    # 硬性落盘约束：钉死绝对目录，否则模型可能写到 /tmp 等处，导致采集层(harvest)看不到、
    # 合格报告被漏判为 low_roi。与具体项目无关，任何目标通用。
    drop = (f"# 落盘约束（硬性，先读）\n"
            f"本会话所有证据与报告**必须写入此绝对目录**，写到 /tmp、$TMPDIR 或别处一律不计入、视为未提交：\n"
            f"  {evidence_dir}\n"
            f"报告用 `report_*.md`（含 severity/title/target frontmatter），原始包用 `*.http`。\n"
            f"已测无利用的格用 `negative_*.md`（含 `endpoint:`/`vuln:`/`reason:`/`vectors:` 头 + 响应证据片段），让阴性也留档。"
            ) if evidence_dir else ""
    parts = [
        f"# 授权文档\n{authz}",                       # [1] 头：合法边界
        f"# 核心技能文件（边界+报告标准，置顶）\n{core_skill}",  # [2] 头：软约束
        drop,                                          # [3] 落盘目录硬约束
        f"# 目标\n{target}\n{private_ctx}",            # [4] 目标+私有线索
        state.to_prompt_block(),                       # [5] 认知状态 + 覆盖台账（长会话才有）
        f"# 攻击面提示（按意图触发）\n{skill_hint}" if skill_hint else "",  # [6]
        cheats,                                        # [7] 尾：抗遗忘
    ]
    return "\n\n".join(p for p in parts if p.strip())


def _conclude(marker, evidence, wd, state, authorized_hosts, turn, verify_fn=None) -> dict:
    """Guardian 质检所有报告 → 物理证据裁定终态（证据可翻案）；可选确定性重放复验。
    支柱 2：终态附带覆盖台账统计与负向留证数，让「测了什么/收口到哪」可见。"""
    triage_ledger = triage(evidence["reports"], evidence_dir=str(wd),
                           authorized_hosts=authorized_hosts)
    has_valid = len(triage_ledger[ACCEPTED]) > 0              # 有 accepted 才算有效报告
    status = finalize(marker, has_valid)
    coverage_ledger = _sync_coverage_ledger(state, wd)
    session_gate = evaluate_session_gate(
        coverage_ledger,
        evidence_dir=str(wd),
        ledger_path=pathlib.Path(wd) / "coverage-ledger.json",
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
    out = {
        "status": status, "marker": marker, "turn": turn,
        "accepted": [v.severity for v, _ in triage_ledger[ACCEPTED]],
        "verified": verified,
        "demoted": len(triage_ledger["demoted"]), "rejected": len(triage_ledger["rejected"]),
        "negatives": len(evidence.get("negatives", [])),
        "coverage": state.matrix_stats() if state.matrix else None,
        "coverage_ledger": derive_coverage(coverage_ledger),
        "coverage_ledger_path": str((pathlib.Path(wd) / "coverage-ledger.json").resolve()),
        "session_gate": session_gate,
        "open_risk_cells": open_risk_cells,
        "needs_cells": needs_cells,
        "blocked_cells": needs_cells,
        "shallow_negative_cells": shallow_negative_cells,
        "state": asdict(state),
    }
    _log_event(wd, {"ev": "end", "status": status, "marker": marker, "turn": turn,
                    "accepted": out["accepted"], "demoted": out["demoted"],
                    "rejected": out["rejected"], "coverage": out["coverage"],
                    "coverage_ledger": out["coverage_ledger"],
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
            # 第二轮：负向留证（SQLi 测了无注入），证明「负向也进台账」不蒸发
            (wd / "negative_sqli_userinfo.md").write_text(
                "endpoint: /api/user-info\nvuln: SQLi\n"
                "reason: 185 个探测无回显/无时间差，sort/uid 均整数白名单\n"
                "vectors:\n"
                "  - time-based\n"
                "  - sort-param\n"
                "  - boundary\n"
                "evidence_types:\n"
                "  - baseline\n"
                "  - boundary_result\n"
                "  - type_result\n"
                "curl 'https://t.example/api/user-info?uid=1 AND SLEEP(5)' → 无延迟，HTTP/1.1 200 正常\n",
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
    # 现实报态报告应闭到真格 /api/orders/{id}（而非误闭/补出 /api/orders/1001 幽灵格）
    mtx = res['state']['matrix']
    real_cell = mtx.get("/api/orders/{id}::越权/IDOR")
    assert real_cell and real_cell['state'] == POSITIVE, \
        "现实报态报告应闭到真格 /api/orders/{id}×越权/IDOR=positive"
    assert "/api/orders/1001::越权/IDOR" not in mtx, "不得新增 /api/orders/1001 幽灵格"
    print("✅ 持续循环 + 矩阵闭合 + 负向留档 + 现实报态闭真格(无幽灵格) 全部满足")

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
    st_d = CognitiveState(sid="d", target="http://t.example:9000")
    seed_eps = ["/api/user-info", "/api/pull-content", "/api/upload-image",
                "/api/get-users", "/api/system-log", "/api/update-bug-status",
                "/api/my-bugs/{id}"]
    st_d.seed_matrix(seed_eps)
    total_before = len(st_d.matrix)
    real_reports = [
        # (target 完整 URL, type 复合带空格, 期望命中的列名)
        ("http://t.example:9000/api/user-info",       "越权 / IDOR",           "越权/IDOR"),
        ("http://t.example:9000/api/pull-content",    "SSRF / 未授权内网访问",  "SSRF"),
        ("http://t.example:9000/api/upload-image",    "任意文件上传",          "文件读取/穿越"),
        ("http://t.example:9000/api/upload-image",    "存储型 XSS / 任意文件上传", "XSS"),
        ("http://t.example:9000/api/update-bug-status", "越权 / 业务逻辑",      "越权/IDOR"),
        ("http://t.example:9000/api/get-users",       "未授权访问 / 敏感信息泄露", "未授权访问"),
        ("http://t.example:9000/api/my-bugs/123",     "越权 / IDOR",           "越权/IDOR"),
        ("http://t.example:9000/api/system-log",      "越权 / 敏感信息泄露",    "越权/IDOR"),
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
    strong_neg = dict(weak_neg, response_count=2)
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
