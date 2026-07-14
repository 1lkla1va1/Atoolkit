"""
engine/candidate.py —— v6.1 候选台账（榨干—深测—进报告 三支柱的数据层）。

v6 提出候选层但未落地（engine/candidate.py 不存在）；v6.1 落地 schema v1.1。
本模块把"榨干"从模型自觉改成外壳强制的**确定性骨架**：

  - schema v1.1：候选落盘 ``candidate-ledger.json``，不全在对话里（§4.1）
  - ``parse_candidate_lines``：解析模型 ``DIM/CANDIDATE/NONE`` 协议行（§3.1）
  - ``CandidateLedger``：读写 ``candidate-ledger.json``，``apply()`` 落盘 + 回填 surface
  - ``candidate_diversity_key``：多维差异键，换皮重述过不了语义饱和（§3.2，治 D7）
  - ``compute_depth_score``：按磁盘证据计分（不信任模型自报）（§6.1）
  - ``scan_reprobe_triggers``：再探测触发器扫描（§6.3，治 D4 闭了就不回头）
  - ``derive_spread_candidates``：根因扩散派生（§7，治 D5 榨干也榨深）
  - ``work_queue_priority``：合并优先级工作队列（§5，治 D3 固定比例）
  - ``compute_coverage_gaps``：四类缺口清单（§8.2，治 D6 没进报告）

设计铁律（与 orchestrator/knowledge/ledger 一致）：
  - 纯确定性、与模型无关：只读协议行 + 磁盘证据，不判手法。
  - payload-free：候选只记假设/证据需求/下一步探测方向，不含具体攻击串。
  - 不导入 orchestrator（避免循环依赖）；depth_floor 由 knowledge 派生。
"""
from __future__ import annotations

import json
import pathlib
import re
import time
from typing import Any

try:
    from .knowledge import (positive_depth_meets, positive_depth_floor_for,
                            risk_dimensions_for)
    from .safe_io import atomic_write_text
except ImportError:  # pragma: no cover - script execution fallback
    from knowledge import (positive_depth_meets, positive_depth_floor_for,
                           risk_dimensions_for)
    from safe_io import atomic_write_text


# ── 候选状态机（§4.1：v6 六态 + 深度）─────────────────────────────────────
PROPOSED = "proposed"
TRIAGING = "triaging"
PROOF_READY = "proof_ready"
CONFIRMED = "confirmed"
ROOT_CAUSE_SPREAD = "root_cause_spread"
REFUTED = "refuted"
BLOCKED = "blocked"
DUPLICATE = "duplicate"

# 候选可推进到的"活跃"状态（非终态、非 duplicate），工作队列会排这些。
ACTIVE_STATUSES = {PROPOSED, TRIAGING, PROOF_READY, CONFIRMED, ROOT_CAUSE_SPREAD, REFUTED, BLOCKED}

# ── 协议行正则（§3.1 / §10.2：模型 ↔ 外壳的候选通道）────────────────────────
# DIM: <dimension> | CANDIDATE: <hypothesis> | need:<evidence_need> | P2 | probe:<next_probe>
# DIM: <dimension> | NONE: <reason>
DIM_RE = re.compile(
    r'^\s*DIM\s*[:：]\s*(.+?)\s*\|\s*(CANDIDATE|NONE)\s*[:：]\s*(.+?)\s*(?:\|\s*(.*))?\s*$',
    re.M | re.I)

# TRIAGE: <cand_id> | proof_ready|refuted|blocked|needs_more | reason | evidence_ref | next_action
TRIAGE_RE = re.compile(
    r'^\s*TRIAGE\s*[:：]\s*(\S+)\s*\|\s*(proof_ready|refuted|blocked|needs_more|confirmed)'
    r'\s*(?:\|\s*(.*))?\s*$',
    re.M | re.I)

# REPROBE: <cand_id> | trigger | reason
REPROBE_RE = re.compile(
    r'^\s*REPROBE\s*[:：]\s*(\S+)\s*\|\s*(\S+)\s*(?:\|\s*(.*))?\s*$',
    re.M | re.I)

# SPREAD: <cand_id> | root_cause | sibling_endpoint|sibling_param|escalation
SPREAD_RE = re.compile(
    r'^\s*SPREAD\s*[:：]\s*(\S+)\s*\|\s*(.+?)\s*(?:\|\s*(.*))?\s*$',
    re.M | re.I)


# ── endpoint 归一化（与 dedupe._norm_endpoint 同意图，自洽避免循环导入）──────────
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _norm_endpoint(ep: str) -> str:
    ep = re.sub(r"^https?://[^/]+", "", (ep or "").strip())
    ep = ep.split("#", 1)[0]
    path = ep.split("?", 1)[0]
    segs = []
    for seg in path.split("/"):
        if seg == "":
            segs.append(seg)
        elif (seg.isdigit() or _UUID_RE.match(seg) or (seg.startswith("{") and seg.endswith("}"))):
            segs.append("{}")
        else:
            segs.append(seg)
    return "/".join(segs)


def _norm(value: Any) -> str:
    return re.sub(r"\s+", "", str(value or "")).strip().lower()


def _as_list(value: Any) -> list:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


# ── 候选 schema v1.1（§4.1）──────────────────────────────────────────────
def make_candidate(
    *,
    surface_id: str,
    endpoint: str,
    method: str = "GET",
    param: str = "",
    role: str = "",
    object: str = "",
    vuln_class: str = "",
    risk_dimension: str = "",
    hypothesis: str,
    evidence_need: str = "",
    next_probe: str = "",
    priority: str = "P3",
    depth_floor: int = 1,
    source: str = "recall",
    turn: int = 0,
    **extra,
) -> dict[str, Any]:
    """构造一个 schema v1.1 候选。depth_floor 由调用方从 knowledge 派生。"""
    return {
        "candidate_id": "",
        "surface_id": surface_id,
        "endpoint": endpoint,
        "method": method.upper(),
        "param": param,
        "role": role,
        "object": object,
        "vuln_class": vuln_class,
        "risk_dimension": risk_dimension,
        "hypothesis": hypothesis,
        "evidence_need": evidence_need,
        "next_probe": next_probe,
        "priority": priority,
        "status": PROPOSED,
        "depth_score": 0,
        "depth_floor": depth_floor,
        "evidence_refs": [],
        "vectors": [],            # 已落盘的独立探测向量（外壳从证据填充）
        "roles_tested": [],       # 已对比的角色
        "objects_tested": [],     # 已对比的对象
        "blocker": None,
        "reprobe_triggers": [],
        "root_cause": None,
        "root_cause_spread_done": False,
        "source": source,
        "created_turn": turn,
        "updated_turn": turn,
        **extra,
    }


# ── 多维差异键（§3.2，治 D7 语义饱和）─────────────────────────────────────
def candidate_diversity_key(cand: dict[str, Any]) -> frozenset[str]:
    """升级 v6 的 endpoint+vuln_class+role+root_cause 为多维差异键。

    新候选若 diversity_key ⊆ 已有候选并集 → 标 ``duplicate``，不计新增。
    recall 退出条件从"连续 K 轮无新增"改为"连续 K 轮所有新候选全 duplicate"。
    """
    return frozenset({
        _norm_endpoint(cand.get("endpoint", "")),
        _norm(cand.get("vuln_class", "")),
        _norm(cand.get("param", "")),
        _norm(cand.get("role", "")),
        _norm(cand.get("object", "")),
        _norm(cand.get("root_cause", "")),
        _norm(cand.get("state_transition", "")),
        _norm(cand.get("risk_dimension", "")),
    })


def is_duplicate_of(new_cand: dict[str, Any], existing: list[dict[str, Any]]) -> bool:
    """新候选的 diversity_key 是否被已有候选并集覆盖（⊆）→ 换皮重述过不了。"""
    new_key = candidate_diversity_key(new_cand)
    if not new_key:
        return False
    for old in existing:
        if new_key <= candidate_diversity_key(old):
            return True
    return False


# ── parse_candidate_lines：解析模型 DIM/CANDIDATE/NONE 协议行（§3.1）──────────
def _parse_dim_tail(tail: str) -> dict[str, str]:
    """解析 CANDIDATE 行的可选尾段：need: / priority / probe: 等 | 分隔字段。"""
    out: dict[str, str] = {}
    if not tail:
        return out
    for part in tail.split("|"):
        part = part.strip()
        if not part:
            continue
        low = part.lower()
        if low.startswith("need"):
            out["evidence_need"] = part.split(":", 1)[-1].strip()
        elif low.startswith("probe"):
            out["next_probe"] = part.split(":", 1)[-1].strip()
        elif re.match(r"^p[1-3]$", low):
            out["priority"] = part.upper()
        elif low.startswith("role"):
            out["role"] = part.split(":", 1)[-1].strip()
        elif low.startswith("object"):
            out["object"] = part.split(":", 1)[-1].strip()
        elif low.startswith("vuln") or low.startswith("class"):
            out["vuln_class"] = part.split(":", 1)[-1].strip()
        else:
            # 无标签段：若还没 priority 且像 Pn 则采信，否则忽略（不教手法）
            pass
    return out


def parse_candidate_lines(text: str, *, surface_id: str = "", endpoint: str = "",
                          method: str = "", param: str = "",
                          depth_floor: int = 1, turn: int = 0,
                          source: str = "recall") -> list[dict[str, Any]]:
    """解析模型输出的 DIM/CANDIDATE/NONE 协议行 → 候选清单。

    模型对每个风险维必须应答：有假设就写 CANDIDATE，没有就写 NONE:<reason>。
    只 CANDIDATE 行生成候选；NONE 行被记录到返回的每条的 ``none_answers`` 字段
    （供饱和检测：每个强插维都有候选或 NONE 应答）。

    返回 list[dict]，每个 dict 是 ``make_candidate`` 同形的候选。
    """
    candidates: list[dict[str, Any]] = []
    none_answers: list[dict[str, str]] = []
    for m in DIM_RE.finditer(text or ""):
        dimension = m.group(1).strip()
        kind = m.group(2).upper()
        rest = m.group(3).strip()
        tail = m.group(4) or ""
        if kind == "NONE":
            none_answers.append({"dimension": dimension, "reason": rest})
            continue
        # CANDIDATE
        fields = _parse_dim_tail(tail)
        cand = make_candidate(
            surface_id=surface_id,
            endpoint=endpoint,
            method=method,
            param=param,
            hypothesis=rest,
            risk_dimension=dimension,
            evidence_need=fields.get("evidence_need", ""),
            next_probe=fields.get("next_probe", ""),
            priority=fields.get("priority", "P3"),
            role=fields.get("role", ""),
            object=fields.get("object", ""),
            vuln_class=fields.get("vuln_class", ""),
            depth_floor=depth_floor,
            source=source,
            turn=turn,
        )
        candidates.append(cand)
    # 把 none_answers 挂在第一个候选上（供饱和检测读取）；无候选时单独返回占位
    if candidates:
        candidates[0]["_none_answers"] = none_answers
    elif none_answers:
        candidates.append(make_candidate(
            surface_id=surface_id, endpoint=endpoint, method=method, param=param,
            hypothesis="(all dimensions answered NONE)",
            depth_floor=depth_floor, source=source, turn=turn,
            _none_answers=none_answers))
    return candidates


# ── parse_triage_lines / parse_reprobe_lines / parse_spread_lines（§10.2）─────
def parse_triage_lines(text: str) -> list[dict[str, str]]:
    """解析 TRIAGE: <cand_id> | verdict | reason | evidence_ref | next_action 行。"""
    out: list[dict[str, str]] = []
    for m in TRIAGE_RE.finditer(text or ""):
        parts = (m.group(3) or "").split("|")
        out.append({
            "candidate_id": m.group(1).strip(),
            "verdict": m.group(2).strip().lower(),
            "reason": parts[0].strip() if len(parts) > 0 else "",
            "evidence_ref": parts[1].strip() if len(parts) > 1 else "",
            "next_action": parts[2].strip() if len(parts) > 2 else "",
        })
    return out


def parse_reprobe_lines(text: str) -> list[dict[str, str]]:
    """解析 REPROBE: <cand_id> | trigger | reason 行。"""
    out: list[dict[str, str]] = []
    for m in REPROBE_RE.finditer(text or ""):
        out.append({
            "candidate_id": m.group(1).strip(),
            "trigger": m.group(2).strip(),
            "reason": (m.group(3) or "").strip(),
        })
    return out


def parse_spread_lines(text: str) -> list[dict[str, str]]:
    """解析 SPREAD: <cand_id> | root_cause | sibling_endpoint|sibling_param|escalation 行。"""
    out: list[dict[str, str]] = []
    for m in SPREAD_RE.finditer(text or ""):
        out.append({
            "candidate_id": m.group(1).strip(),
            "root_cause": m.group(2).strip(),
            "targets": (m.group(3) or "").strip(),
        })
    return out


# ── depth_score 计算（§6.1：按磁盘证据计分，不信任模型自报）──────────────────
def compute_depth_score(candidate: dict[str, Any], all_candidates: list[dict] | None = None) -> int:
    """按已落盘证据计分（§6.1）。

    +1：≥1 个独立向量有响应证据
    +1：≥3 个独立向量（payload 家族/对象 id/角色）有响应证据
    +1：≥2 角色 或 ≥2 对象 的对比响应证据
    +1：根因扩散已做（同根因在兄弟端点/参数/角色验证过）

    vectors/roles_tested/objects_tested 由外壳从磁盘证据填充（不信任模型自报）。
    """
    score = 0
    has_response = bool(candidate.get("evidence_refs"))
    vectors = {_norm(v) for v in _as_list(candidate.get("vectors"))}
    roles = {_norm(r) for r in _as_list(candidate.get("roles_tested"))}
    objects = {_norm(o) for o in _as_list(candidate.get("objects_tested"))}

    if has_response and len(vectors) >= 1:
        score += 1
    if has_response and len(vectors) >= 3:
        score += 1
    if has_response and (len(roles) >= 2 or len(objects) >= 2):
        score += 1
    rc = candidate.get("root_cause")
    if rc and all_candidates and has_response:
        siblings = [c for c in all_candidates
                    if _norm(c.get("root_cause")) == _norm(rc)
                    and c.get("candidate_id") != candidate.get("candidate_id")
                    and c.get("status") in (CONFIRMED, ROOT_CAUSE_SPREAD)
                    and c.get("evidence_refs")
                    and (
                        _norm_endpoint(c.get("endpoint", "")) != _norm_endpoint(candidate.get("endpoint", ""))
                        or _norm(c.get("param")) != _norm(candidate.get("param"))
                        or _norm(c.get("role")) != _norm(candidate.get("role"))
                    )]
        if siblings:
            score += 1
            candidate["root_cause_spread_done"] = True
    return score


def recompute_depth_score(candidate: dict[str, Any], all_candidates: list[dict] | None = None) -> int:
    """重算并回填 depth_score，返回新值。"""
    score = compute_depth_score(candidate, all_candidates)
    candidate["depth_score"] = score
    return score


# ── value_tier：候选价值档（影响工作队列排序，不影响成立性）──────────────────
def _value_tier(cand: dict[str, Any]) -> int:
    """价值档（与 dedupe._value_tier 同意图，自洽避免导入）：
      1 认证绕过 → 2 支付/余额 → 3 对象级授权 → 4 输入验证/文件/跳转 → 5 低价值。"""
    rc = _norm(cand.get("root_cause") or cand.get("vuln_class") or cand.get("risk_dimension"))
    ep = _norm(cand.get("endpoint", ""))
    if any(k in rc or k in ep for k in ("认证", "auth", "登录", "注册", "找回", "token", "session", "枚举")):
        return 1
    if any(k in rc or k in ep for k in ("支付", "余额", "退款", "payment", "refund", "金额",
                                        "amount", "recharge", "积分", "points", "优惠", "coupon",
                                        "balance", "抽奖", "lottery")):
        return 2
    if any(k in rc or k in ep for k in ("越权", "idor", "bac", "对象", "ownership", "未授权", "unauth")):
        return 3
    if any(k in rc or k in ep for k in ("信息泄露", "信息暴露", "配置", "sourcemap", "指纹", "infoleak")):
        return 5
    return 4


def is_high_value(cand: dict[str, Any]) -> bool:
    return _value_tier(cand) <= 3


# ── 合并优先级工作队列（§5，治 D3 固定比例）─────────────────────────────────
def work_queue_priority(cand: dict[str, Any]) -> tuple:
    """单一优先级队列排序键（§5）。相别只是软提示，proof_ready 永远最前。

    proof 保底：已达 depth_floor 的候选永远最前 → "已经挖到能证的，先证完再挖"。
    """
    status = cand.get("status", PROPOSED)
    depth_floor = int(cand.get("depth_floor", 1) or 1)
    depth_score = int(cand.get("depth_score", 0) or 0)
    if status == PROOF_READY:
        return (0, _value_tier(cand), -depth_score)
    if status == TRIAGING and depth_score < depth_floor:
        return (1, _value_tier(cand))
    if status == PROPOSED and is_high_value(cand):
        return (2, _value_tier(cand))
    if status == CONFIRMED and not cand.get("root_cause_spread_done"):
        return (3, _value_tier(cand), -depth_score)
    if status == PROPOSED:
        return (4, _value_tier(cand))
    if status == REFUTED and cand.get("reprobe_triggers"):
        return (4,)  # §6.3 再探测
    if status == BLOCKED and cand.get("blocker", {}).get("recoverable"):
        return (5,)
    return (9,)


def top_work_queue(candidates: list[dict[str, Any]], n: int = 8) -> list[dict[str, Any]]:
    """取 Top N 候选工作队列（§5 优先级），注入 prompt 用。"""
    active = [c for c in (candidates or []) if c.get("status") in ACTIVE_STATUSES
              and c.get("status") != DUPLICATE]
    active.sort(key=work_queue_priority)
    return active[:n]


# ── 再探测触发器扫描（§6.3，治 D4：闭了就不回头）─────────────────────────────
# 触发类型：new_role / new_object_class / new_sibling_endpoint / same_root_cause_confirmed / depth_floor_raised
def scan_reprobe_triggers(
    candidates: list[dict[str, Any]],
    *,
    new_roles: list[str] | None = None,
    new_object_classes: list[str] | None = None,
    new_endpoints: list[str] | None = None,
    confirmed_root_causes: list[str] | None = None,
    depth_floors: dict[str, int] | None = None,
) -> list[dict[str, Any]]:
    """扫描 refuted 候选的 reprobe_triggers，命中即标记重开（refuted→proposed）。

    返回命中清单 [{candidate_id, trigger, reason}]。调用方据此把候选 status 改回 proposed。
    """
    new_roles = {_norm(r) for r in (new_roles or [])}
    new_objects = {_norm(o) for o in (new_object_classes or [])}
    new_eps = {_norm_endpoint(e) for e in (new_endpoints or [])}
    confirmed_rcs = {_norm(r) for r in (confirmed_root_causes or [])}
    floors = depth_floors or {}

    hits: list[dict[str, Any]] = []
    for cand in candidates or []:
        if cand.get("status") != REFUTED:
            continue
        cid = cand.get("candidate_id", "")
        triggers = _as_list(cand.get("reprobe_triggers"))
        for trig in triggers:
            t = _norm(trig.get("type") if isinstance(trig, dict) else trig)
            if t == "new_role" and new_roles:
                hits.append({"candidate_id": cid, "trigger": "new_role",
                             "reason": f"新角色到账: {new_roles}"})
            elif t == "new_object_class" and new_objects:
                hits.append({"candidate_id": cid, "trigger": "new_object_class",
                             "reason": f"新对象类: {new_objects}"})
            elif t == "new_sibling_endpoint" and new_eps:
                hits.append({"candidate_id": cid, "trigger": "new_sibling_endpoint",
                             "reason": f"同流新端点: {new_eps}"})
            elif t == "same_root_cause_confirmed" and confirmed_rcs:
                cand_rc = _norm(cand.get("root_cause"))
                if cand_rc and cand_rc in confirmed_rcs:
                    hits.append({"candidate_id": cid, "trigger": "same_root_cause_confirmed",
                                 "reason": f"同根因新确认: {cand_rc}"})
            elif t == "depth_floor_raised":
                sid = cand.get("surface_id", "")
                new_floor = floors.get(sid, 0)
                if new_floor > int(cand.get("depth_floor", 0) or 0):
                    hits.append({"candidate_id": cid, "trigger": "depth_floor_raised",
                                 "reason": f"floor {cand.get('depth_floor')}→{new_floor}"})
    return hits


# ── 根因扩散派生（§7，治 D5：榨干也榨深）─────────────────────────────────────
SPREAD_DEPTH_LIMIT = 2  # §11.4：扩散深度上限（默认 2 层），防爆炸


def derive_spread_candidates(
    confirmed_cand: dict[str, Any],
    *,
    sibling_endpoints: list[str] | None = None,
    sibling_params: list[str] | None = None,
    escalations: list[str] | None = None,
    turn: int = 0,
    depth: int = 0,
) -> list[dict[str, Any]]:
    """confirmed 候选确认后，派生同根因扩散候选（§7）。

    不立即进报告，先触发 root_cause_spread：
      - 同根因 × 兄弟端点
      - 同根因 × 兄弟参数
      - 同根因 × 升级路径（P3→P1）
    扩散候选走正常队列；确认后合并为同一 finding 的 facets。
    """
    if depth >= SPREAD_DEPTH_LIMIT:
        return []
    root_cause = confirmed_cand.get("root_cause") or confirmed_cand.get("vuln_class", "")
    if not root_cause:
        return []
    base = {
        "vuln_class": confirmed_cand.get("vuln_class", ""),
        "root_cause": root_cause,
        "priority": confirmed_cand.get("priority", "P3"),
        "depth_floor": confirmed_cand.get("depth_floor", 1),
        "source": f"spread:from:{confirmed_cand.get('candidate_id', '')}",
        "created_turn": turn,
        "updated_turn": turn,
        "_spread_depth": depth + 1,
    }
    spread: list[dict[str, Any]] = []
    for ep in sibling_endpoints or []:
        if _norm_endpoint(ep) == _norm_endpoint(confirmed_cand.get("endpoint", "")):
            continue
        spread.append(make_candidate(
            surface_id="", endpoint=ep, method=confirmed_cand.get("method", "GET"),
            param=confirmed_cand.get("param", ""),
            hypothesis=f"同根因扩散：{root_cause} @ {ep}",
            next_probe=f"验证 {root_cause} 在 {ep} 是否同样存在",
            **{k: v for k, v in base.items() if k not in ("_spread_depth",)},
            _spread_depth=depth + 1,
        ))
    for p in sibling_params or []:
        if _norm(p) == _norm(confirmed_cand.get("param", "")):
            continue
        spread.append(make_candidate(
            surface_id=confirmed_cand.get("surface_id", ""),
            endpoint=confirmed_cand.get("endpoint", ""),
            method=confirmed_cand.get("method", "GET"), param=p,
            hypothesis=f"同根因扩散：{root_cause} × 参数 {p}",
            next_probe=f"验证 {root_cause} 在参数 {p} 是否同样存在",
            **{k: v for k, v in base.items() if k not in ("_spread_depth",)},
            _spread_depth=depth + 1,
        ))
    for esc in escalations or []:
        spread.append(make_candidate(
            surface_id=confirmed_cand.get("surface_id", ""),
            endpoint=confirmed_cand.get("endpoint", ""),
            method=confirmed_cand.get("method", "GET"),
            param=confirmed_cand.get("param", ""),
            hypothesis=f"升级路径：{esc}",
            next_probe=f"验证升级：{esc}",
            priority="P1",  # 升级路径默认提级
            **{k: v for k, v in base.items() if k not in ("_spread_depth", "priority")},
            _spread_depth=depth + 1,
        ))
    return spread


# ── 四类缺口清单（§8.2，治 D6：没进报告）─────────────────────────────────────
def compute_coverage_gaps(
    candidates: list[dict[str, Any]] | None,
    *,
    finding_candidate_ids: set[str] | None = None,
    surfaces: list[dict[str, Any]] | None = None,
    demoted_count: int = 0,
    verify_uncertain_count: int = 0,
) -> dict[str, list[dict[str, Any]]]:
    """计算四类缺口清单（§8.2），供 _conclude 渲染 coverage_gaps.md + final_report 附录。

    ① 发现了但没测：proposed/triaging 候选，无 finding
    ② 测了但没深入：confirmed 但 root_cause_spread 未做；not_vulnerable 但 depth 未校验
    ③ 阻塞未恢复：blocked 且 blocker 可恢复但 next_actions 未清
    ④ 漏进报告：proof_ready 无 finding；demoted；verify=不确定

    铁律：四类任一非空，终态不得 complete。
    """
    finding_ids = finding_candidate_ids or set()
    gaps: dict[str, list[dict[str, Any]]] = {
        "untested_candidates": [],
        "shallow_confirmed_or_negative": [],
        "recoverable_blocked": [],
        "proof_ready_without_finding": [],
    }
    for c in candidates or []:
        cid = c.get("candidate_id", "")
        status = c.get("status", "")
        if status in (PROPOSED, TRIAGING) and cid not in finding_ids:
            gaps["untested_candidates"].append({
                "candidate_id": cid, "surface_id": c.get("surface_id", ""),
                "endpoint": c.get("endpoint", ""), "hypothesis": c.get("hypothesis", ""),
                "next_probe": c.get("next_probe", ""), "status": status,
            })
        if status == CONFIRMED and not c.get("root_cause_spread_done"):
            gaps["shallow_confirmed_or_negative"].append({
                "candidate_id": cid, "surface_id": c.get("surface_id", ""),
                "endpoint": c.get("endpoint", ""), "root_cause": c.get("root_cause", ""),
                "kind": "confirmed_without_spread",
            })
        if status == BLOCKED:
            blocker = c.get("blocker") or {}
            if blocker.get("recoverable") and _as_list(c.get("next_actions")):
                gaps["recoverable_blocked"].append({
                    "candidate_id": cid, "surface_id": c.get("surface_id", ""),
                    "endpoint": c.get("endpoint", ""), "blocker": blocker,
                    "next_actions": c.get("next_actions", []),
                })
        if status == PROOF_READY and cid not in finding_ids:
            gaps["proof_ready_without_finding"].append({
                "candidate_id": cid, "surface_id": c.get("surface_id", ""),
                "endpoint": c.get("endpoint", ""), "hypothesis": c.get("hypothesis", ""),
                "evidence_refs": c.get("evidence_refs", []),
            })
    # ② also: not_vulnerable surfaces without negative_depth_checked (§6.2)
    for s in surfaces or []:
        if s.get("status") == "not_vulnerable" and not s.get("negative_depth_checked"):
            gaps["shallow_confirmed_or_negative"].append({
                "surface_id": s.get("surface_id", ""),
                "endpoint": s.get("endpoint", ""), "kind": "shallow_negative_unchecked",
            })
    # ④ also: demoted / verify uncertain counts
    if demoted_count or verify_uncertain_count:
        gaps["proof_ready_without_finding"].append({
            "kind": "demoted_or_uncertain",
            "demoted_count": demoted_count,
            "verify_uncertain_count": verify_uncertain_count,
        })
    return gaps


def coverage_gaps_nonempty(gaps: dict[str, list]) -> bool:
    """四类缺口任一非空 → 终态不得 complete（§8.2 铁律）。"""
    return any(gaps.get(k) for k in
               ("untested_candidates", "shallow_confirmed_or_negative",
                "recoverable_blocked", "proof_ready_without_finding"))


# ── CandidateLedger：读写 candidate-ledger.json（§4.1 / §10.2）────────────────
class CandidateLedger:
    """候选台账：落盘 ``candidate-ledger.json``，不全在对话里。

    ``apply()`` 解析模型协议行（DIM/TRIAGE/REPROBE/SPREAD）→ 落盘 + 回填 surface
    的 candidate_count/depth_score/deepest_status（通过调用方传入的 link_callback）。
    """

    def __init__(self, candidates: list[dict[str, Any]] | None = None,
                 metadata: dict[str, Any] | None = None):
        self.metadata = dict(metadata or {})
        self.candidates: list[dict[str, Any]] = list(candidates or [])
        self._next_id = self._compute_next_id()

    def _compute_next_id(self) -> int:
        max_n = 0
        for c in self.candidates:
            cid = str(c.get("candidate_id") or "")
            m = re.match(r"cand_(\d+)", cid)
            if m:
                max_n = max(max_n, int(m.group(1)))
        return max_n + 1

    def _assign_id(self, cand: dict[str, Any]) -> str:
        if not cand.get("candidate_id"):
            cand["candidate_id"] = f"cand_{self._next_id:03d}"
            self._next_id += 1
        return cand["candidate_id"]

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": "1.1", "metadata": self.metadata,
                "candidates": self.candidates}

    @classmethod
    def load(cls, path: str | pathlib.Path) -> "CandidateLedger":
        p = pathlib.Path(path)
        if not p.exists():
            return cls()
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls(data.get("candidates") or [], metadata=data.get("metadata") or {})

    def save(self, path: str | pathlib.Path) -> None:
        destination = pathlib.Path(path)
        atomic_write_text(
            destination,
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2),
            root=destination.parent,
            reject_leaf_symlink=True,
        )

    def get(self, candidate_id: str) -> dict[str, Any] | None:
        for c in self.candidates:
            if c.get("candidate_id") == candidate_id:
                return c
        return None

    def find_by_surface(self, surface_id: str) -> list[dict[str, Any]]:
        return [c for c in self.candidates if c.get("surface_id") == surface_id]

    def add(self, cand: dict[str, Any], *, existing: list[dict] | None = None) -> dict[str, Any] | None:
        """添加候选，做 diversity_key 去重（§3.2）。duplicate 返回 None。"""
        if existing is None:
            existing = self.candidates
        if is_duplicate_of(cand, existing):
            cand["status"] = DUPLICATE
            cand["candidate_id"] = cand.get("candidate_id") or self._assign_id(cand)
            self.candidates.append(cand)
            return None
        self._assign_id(cand)
        self.candidates.append(cand)
        return cand

    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for c in self.candidates:
            s = c.get("status", PROPOSED)
            counts[s] = counts.get(s, 0) + 1
        counts["total"] = len(self.candidates)
        counts["high_value_open"] = sum(
            1 for c in self.candidates
            if is_high_value(c) and c.get("status") in (PROPOSED, TRIAGING, PROOF_READY, BLOCKED))
        return counts

    def apply(self, text: str, *, turn: int = 0,
              link_callback=None, cards: list[dict] | None = None,
              surface_ctx: dict | None = None) -> list[str]:
        """解析模型本轮协议行 → 落盘候选状态变更，返回变更说明（供日志）。

        link_callback(surface_id, status, depth_score) 由调用方传入，用于回填
        CoverageLedger surface 的 candidate_count/deepest_status/depth_score。
        surface_ctx 提供 DIM 行的 surface 绑定上下文（surface_id/endpoint/method/param/
        depth_floor），使候选能 link 到正确的 surface。
        """
        notes: list[str] = []
        sctx = surface_ctx or {}

        # 1) DIM/CANDIDATE：新候选入账（diversity_key 去重）
        for cand in self.candidates:
            cand.pop("_none_answers", None)  # 清上轮临时字段
        new_cands_raw = []
        # parse_candidate_lines 用 surface_ctx 绑定候选到当前 surface（§3.1）
        dim_cands = parse_candidate_lines(
            text,
            surface_id=sctx.get("surface_id", ""),
            endpoint=sctx.get("endpoint", ""),
            method=sctx.get("method", ""),
            param=sctx.get("param", ""),
            depth_floor=sctx.get("depth_floor", 1),
            turn=turn)
        for cand in dim_cands:
            none = cand.pop("_none_answers", [])
            added = self.add(cand)
            if added:
                notes.append(f"[CANDIDATE] {added['candidate_id']}: {added.get('hypothesis','')[:60]}")
                if link_callback and added.get("surface_id"):
                    link_callback(added["surface_id"], status=added.get("status", PROPOSED),
                                  depth_score=0)
            else:
                notes.append(f"[DUPLICATE] 换皮重述被 diversity_key 拦")
            if none:
                self.metadata.setdefault("none_answers", []).extend(none)

        # 2) TRIAGE：推进候选状态（proof_ready 需达 depth_floor）
        for tri in parse_triage_lines(text):
            cand = self.get(tri["candidate_id"])
            if not cand:
                notes.append(f"[TRIAGE] {tri['candidate_id']} 不存在 → 丢弃")
                continue
            verdict = tri["verdict"]
            # depth_floor 闸门（§6.1）：不到 floor 不许 proof_ready
            if verdict == "proof_ready":
                recompute_depth_score(cand, self.candidates)
                # 从 knowledge 卡重算 depth_floor
                floor = positive_depth_floor_for(cand, cards) if cards else int(cand.get("depth_floor", 1) or 1)
                cand["depth_floor"] = max(int(cand.get("depth_floor", 1) or 1), floor)
                if int(cand.get("depth_score", 0)) < int(cand.get("depth_floor", 1) or 1):
                    cand["status"] = TRIAGING
                    notes.append(f"[TRIAGE] {tri['candidate_id']} proof_ready 被拒："
                                 f"depth_score {cand['depth_score']} < floor {cand['depth_floor']} → 退回 triaging")
                    continue
            if verdict == "confirmed":
                # Model text can declare readiness, not truth.  A candidate is
                # upgraded to CONFIRMED only when a proof-confirmed structured
                # root finding is bound by the orchestrator.
                cand["reported_verdict"] = "confirmed"
                cand["status"] = PROOF_READY
            else:
                cand["status"] = verdict if verdict != "needs_more" else TRIAGING
            if tri["evidence_ref"]:
                refs = _as_list(cand.get("evidence_refs"))
                if tri["evidence_ref"] not in refs:
                    refs.append(tri["evidence_ref"])
                cand["evidence_refs"] = refs
            if tri["next_action"]:
                cand.setdefault("next_actions", []).append(tri["next_action"])
            cand["updated_turn"] = turn
            if link_callback and cand.get("surface_id"):
                link_callback(cand["surface_id"], status=cand["status"],
                              depth_score=int(cand.get("depth_score", 0) or 0))
            notes.append(f"[TRIAGE] {tri['candidate_id']} → {cand['status']}")

        # 3) REPROBE：记录触发器
        for rep in parse_reprobe_lines(text):
            cand = self.get(rep["candidate_id"])
            if not cand:
                continue
            triggers = _as_list(cand.get("reprobe_triggers"))
            triggers.append({"type": rep["trigger"], "reason": rep["reason"]})
            cand["reprobe_triggers"] = triggers
            cand["updated_turn"] = turn
            notes.append(f"[REPROBE] {rep['candidate_id']} += {rep['trigger']}")

        # 4) SPREAD：根因扩散
        for spr in parse_spread_lines(text):
            cand = self.get(spr["candidate_id"])
            if not cand:
                continue
            cand["root_cause"] = spr["root_cause"]
            # A SPREAD line is a plan, not proof.  Completion/depth credit is
            # derived only after a distinct sibling candidate has raw evidence.
            cand["spread_requested"] = True
            cand.setdefault("spread_targets", []).append(spr["targets"])
            cand["updated_turn"] = turn
            notes.append(f"[SPREAD] {spr['candidate_id']} 已登记扩散计划；等待独立兄弟证据")
            if link_callback and cand.get("surface_id"):
                link_callback(cand["surface_id"], status=cand["status"],
                              depth_score=int(cand.get("depth_score", 0) or 0))

        return notes

    def reprobe_scan(self, *, new_roles=None, new_object_classes=None,
                     new_endpoints=None, confirmed_root_causes=None,
                     depth_floors=None) -> list[dict[str, Any]]:
        """扫描 refuted 候选的 reprobe_triggers，命中即 refuted→proposed 重开（§6.3）。"""
        hits = scan_reprobe_triggers(
            self.candidates, new_roles=new_roles, new_object_classes=new_object_classes,
            new_endpoints=new_endpoints, confirmed_root_causes=confirmed_root_causes,
            depth_floors=depth_floors)
        for hit in hits:
            cand = self.get(hit["candidate_id"])
            if cand and cand.get("status") == REFUTED:
                cand["status"] = PROPOSED
                cand["updated_turn"] = cand.get("updated_turn", 0)
        return hits

    def spread_derive(self, candidate_id: str, *, sibling_endpoints=None,
                      sibling_params=None, escalations=None, turn: int = 0) -> list[dict[str, Any]]:
        """对 confirmed 候选派生扩散候选（§7）。"""
        cand = self.get(candidate_id)
        if not cand:
            return []
        spread = derive_spread_candidates(
            cand, sibling_endpoints=sibling_endpoints, sibling_params=sibling_params,
            escalations=escalations, turn=turn)
        for s in spread:
            self.add(s)
        return spread


# ── recall 饱和检测（§3.2：连续 K 轮全 duplicate）─────────────────────────────
def recall_saturated(duplicate_streak: int, k: int = 3) -> bool:
    """recall 退出条件：连续 K 轮所有新候选全 duplicate → 换皮重述过不了。"""
    return duplicate_streak >= k


# ── prompt 注入辅助（§3.1 风险维应答表 + §5 工作队列）──────────────────────────
def render_dimension_checklist(surface: dict[str, Any], cards: list[dict] | None = None,
                               answered_dims: set[str] | None = None) -> str:
    """渲染「风险维应答表」注入 prompt（§3.1）。

    外壳按 surface 的 risk_tags 展开成维清单，模型必须对每一维应答：
      [dimension] ? CANDIDATE: <假设> | need:<证据需求> | P2 | probe:<下一步>
      [dimension] ? NONE: <为何不是>
    """
    dims = risk_dimensions_for(surface, cards)
    answered = answered_dims or set()
    lines = ["## 风险维应答表（逐维必答，不许跳过）"]
    for dim in dims:
        mark = "✓" if _norm(dim) in {_norm(a) for a in answered} else "?"
        lines.append(f"  [{dim}] {mark} CANDIDATE: <假设> | need:<证据需求> | P1-P3 | probe:<下一步>")
        lines.append(f"           或 NONE: <为何不是此维>")
    lines.append("- 每维必答：有假设就写 CANDIDATE，没有就写 NONE:<reason>，不许跳过。")
    return "\n".join(lines)


def render_work_queue(candidates: list[dict[str, Any]], n: int = 8) -> str:
    """渲染 Top N 候选工作队列注入 prompt（§5 优先级）。"""
    top = top_work_queue(candidates, n)
    if not top:
        return ""
    lines = ["## 候选工作队列（§5 优先级：proof_ready 保底最前）"]
    for i, c in enumerate(top, 1):
        lines.append(
            f"  {i}. [{c.get('status','')}] {c.get('candidate_id','')} "
            f"{c.get('endpoint','')} × {c.get('risk_dimension','')} "
            f"depth={c.get('depth_score',0)}/{c.get('depth_floor',1)} "
            f"{c.get('hypothesis','')[:50]}")
    return "\n".join(lines)


def render_proof_ready_block(candidates: list[dict[str, Any]]) -> str:
    """渲染「达 depth_floor 待证候选」清单 + finding schema 提醒（§5 proof 保底）。"""
    ready = [c for c in (candidates or []) if c.get("status") == PROOF_READY]
    if not ready:
        return ""
    lines = ["## ⚠ proof_ready 待证候选（已达 depth_floor，优先出 finding 包）"]
    for c in ready:
        lines.append(
            f"  - {c.get('candidate_id','')} {c.get('endpoint','')} "
            f"{c.get('hypothesis','')[:60]} 证据={c.get('evidence_refs',[])}")
    lines.append("- 这些候选已达 depth_floor，本轮优先写 findings/finding_<id>/finding.json 出证。")
    return "\n".join(lines)


__all__ = [
    "PROPOSED", "TRIAGING", "PROOF_READY", "CONFIRMED", "ROOT_CAUSE_SPREAD",
    "REFUTED", "BLOCKED", "DUPLICATE", "ACTIVE_STATUSES",
    "make_candidate", "candidate_diversity_key", "is_duplicate_of",
    "parse_candidate_lines", "parse_triage_lines", "parse_reprobe_lines", "parse_spread_lines",
    "compute_depth_score", "recompute_depth_score",
    "work_queue_priority", "top_work_queue", "is_high_value",
    "scan_reprobe_triggers", "derive_spread_candidates",
    "compute_coverage_gaps", "coverage_gaps_nonempty",
    "CandidateLedger", "recall_saturated",
    "render_dimension_checklist", "render_work_queue", "render_proof_ready_block",
]
