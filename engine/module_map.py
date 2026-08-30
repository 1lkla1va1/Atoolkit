"""Read-only module map derived view (v9.7 prototype).

Clusters a run's discovered endpoints into business modules using
deterministic signals (URL path prefix, recon provenance file, optional
feature-graph), then renders a human-readable map plus a scale assessment
that advises whether the target should be split into per-module runs.

This module is a *derived view only*: it reads ``inventory.json``,
``coverage-ledger.json`` and (optionally) ``feature-graph.json`` from a run
directory and writes ``module_map.json`` / ``module_map.md``.  It never
mutates any authoritative artifact (project state, coverage ledger,
inventory) and must not be consumed as an authority input.
"""
from __future__ import annotations

import json
import pathlib
import re
from typing import Any, Iterable

try:
    from .ledger import (
        STATUS_EXPLORING,
        STATUS_NOT_TESTED,
        CoverageLedger,
        is_high_value,
        normalize_status,
    )
    from .safe_io import atomic_write_json, atomic_write_text
except ImportError:  # pragma: no cover - flat-layout fallback
    from ledger import (  # type: ignore[no-redef]
        STATUS_EXPLORING,
        STATUS_NOT_TESTED,
        CoverageLedger,
        is_high_value,
        normalize_status,
    )
    from safe_io import atomic_write_json, atomic_write_text  # type: ignore[no-redef]

SCHEMA_VERSION = 1

# Scale assessment thresholds (initial heuristics; calibrate after replays).
SMALL_ENDPOINT_MAX = 80
SMALL_MODULE_MAX = 3
LARGE_ENDPOINT_MIN = 300
LARGE_MODULE_MIN = 8
LARGE_CELL_MIN = 500

# Groups smaller than this are folded into ``_misc``.
MIN_GROUP_SIZE = 3

# If a first-segment group grows beyond this size, try re-splitting it by
# the second path segment (keeps flat APIs from collapsing into one blob).
DOMINANT_GROUP_MIN = 6

_STATIC_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".map", ".woff", ".woff2", ".ttf", ".eot", ".webp", ".txt",
}

# Label keyword table: module label -> keywords matched (case-insensitive,
# substring) against path segments and recon provenance file basenames.
_LABEL_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("管理后台", ("admin", "manage", "console", "backend", "dashboard")),
    ("商户", ("merchant", "seller", "vendor", "shop_admin")),
    ("用户", ("user", "member", "account", "profile", "customer")),
    ("认证", ("login", "register", "auth", "captcha", "sms", "verify",
              "password", "reset", "logout", "token")),
    ("交易支付", ("pay", "order", "trade", "recharge", "refund", "cart",
                  "checkout", "lottery", "points", "coupon", "balance")),
    ("文件", ("upload", "download", "file", "export", "import", "image")),
    ("公共", ("common", "public", "home", "index", "announce", "notice")),
)

_PROBE_PATTERNS = (
    re.compile(r"^\.well-known"),
    re.compile(r"\.(htaccess|git|env|svn|DS_Store)$", re.IGNORECASE),
    re.compile(r"(^|[/_])(probe|scanner|favicon)", re.IGNORECASE),
)

_SPECIAL_LABELS = {
    "_misc": "杂项（小组件合并）",
    "_pages": "页面（单段路径）",
    "_probe": "探针/静态",
}


def _path_of(endpoint: str) -> str:
    path = str(endpoint or "").split("?", 1)[0].split("#", 1)[0].strip()
    return path or "/"


def _segments(path: str) -> list[str]:
    return [seg for seg in path.split("/") if seg]


def _is_probe_path(path: str) -> bool:
    segments = _segments(path)
    if any(segment.startswith(".") for segment in segments):
        return True
    if any(pattern.search(path) for pattern in _PROBE_PATTERNS):
        return True
    suffix = pathlib.PurePosixPath(segments[-1] if segments else "").suffix.lower()
    return suffix in _STATIC_EXTENSIONS


def _group_key(path: str, depth: int) -> str:
    segments = _segments(path)
    if not segments:
        return "_root"
    return "/".join(segments[:depth])


# Base-prefix stripping: recon often records the same endpoint both as
# ``/api/x.php`` (from JS) and ``/range/pentest/shop/api/x.php`` (from HTML
# pages under the deployment base).  A leading prefix is stripped only when
# stripping it actually merges duplicates — i.e. the majority of the paths
# carrying it collide with paths that do not.  This strips deployment
# directories (``/range/pentest/shop``) without eating real structure like
# ``/api/`` (whose stripped forms do not collide).
_BASE_PREFIX_MIN_SHARE = 0.5
_BASE_PREFIX_MAX_DEPTH = 4


def _strip_base_prefixes(rows: list[dict[str, Any]]) -> list[str]:
    """Normalize absolute paths in-place by dropping deployment base dirs.

    Returns the stripped segments (in order) so ledger/feature-graph paths
    can be normalized with the same base.
    """
    stripped: list[str] = []
    for _ in range(_BASE_PREFIX_MAX_DEPTH):
        pairs: list[tuple[str, str]] = []
        for row in rows:
            path = _path_of(row.get("endpoint", ""))
            if path.startswith("/") and len(_segments(path)) >= 2:
                pairs.append((path, str(row.get("method") or "").upper()))
        if not pairs:
            return stripped
        counts: dict[str, int] = {}
        for path, _method in pairs:
            counts[_segments(path)[0]] = counts.get(_segments(path)[0], 0) + 1
        outside_all = {
            ("/" + "/".join(_segments(_path_of(row.get("endpoint", "")))),
             str(row.get("method") or "").upper())
            for row in rows
            if not _path_of(row.get("endpoint", "")).startswith("/")
        }
        # Evaluate every leading segment with a qualifying share, then strip
        # the candidate whose stripping actually merges the most duplicates.
        best_prefix: list[str] = []
        best_collisions = 0
        best_threshold = 0
        for segment, hits in counts.items():
            if not (_BASE_PREFIX_MIN_SHARE <= hits / len(pairs) < 1.0):
                continue
            family = [
                (segments, method)
                for path, method in pairs
                for segments in [_segments(path)]
                if segments[0] == segment
            ]
            family_segments = [segments for segments, _m in family]
            lcp = list(family_segments[0])
            for segments in family_segments[1:]:
                while lcp and segments[:len(lcp)] != lcp:
                    lcp.pop()
                if not lcp:
                    break
            if not lcp:
                continue
            outside = {
                ("/" + "/".join(_segments(p)), m)
                for p, m in pairs
                if _segments(p)[:1] != [segment]
            } | outside_all
            max_depth = min(len(lcp), min(len(s) for s in family_segments) - 1)
            for depth in range(1, max_depth + 1):
                collisions = sum(
                    1
                    for segments, method in family
                    if ("/" + "/".join(segments[depth:]), method) in outside
                )
                if collisions > best_collisions:
                    best_collisions = collisions
                    best_prefix = family_segments[0][:depth]
                    best_threshold = max(2, len(family) // 2)
        if not best_prefix or best_collisions < best_threshold:
            return stripped
        stripped.extend(best_prefix)
        for row in rows:
            path = _path_of(row.get("endpoint", ""))
            segments = _segments(path)
            if (path.startswith("/")
                    and segments[:len(best_prefix)] == best_prefix
                    and len(segments) > len(best_prefix)):
                row["endpoint"] = "/" + "/".join(segments[len(best_prefix):])
    return stripped


def _strip_known_base(path: str, base_segments: list[str]) -> str:
    segments = _segments(_path_of(path))
    if (base_segments and path.startswith("/")
            and segments[:len(base_segments)] == base_segments
            and len(segments) > len(base_segments)):
        return "/" + "/".join(segments[len(base_segments):])
    return _path_of(path)


def _merge_duplicate_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge rows that resolve to the same (path, method) after stripping."""
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        path = _path_of(row.get("endpoint", ""))
        method = str(row.get("method") or "").upper() or "GET"
        key = (path, method)
        existing = merged.get(key)
        if existing is None:
            entry = dict(row)
            entry["endpoint"] = path
            entry["method"] = method
            merged[key] = entry
            continue
        params = list(dict.fromkeys(
            [str(p) for p in (existing.get("params") or [])]
            + [str(p) for p in (row.get("params") or [])]))
        existing["params"] = params
        provenance = list(existing.get("provenance") or [])
        seen_prov = {
            (str(p.get("source_file") or ""), str(p.get("source_kind") or ""))
            for p in provenance if isinstance(p, dict)
        }
        for prov in row.get("provenance") or []:
            if not isinstance(prov, dict):
                continue
            marker = (str(prov.get("source_file") or ""),
                      str(prov.get("source_kind") or ""))
            if marker not in seen_prov:
                seen_prov.add(marker)
                provenance.append(prov)
        existing["provenance"] = provenance
    return list(merged.values())


def _provenance_basenames(row: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for prov in row.get("provenance") or []:
        if isinstance(prov, dict):
            src = str(prov.get("source_file") or "")
            if src:
                names.append(pathlib.PurePosixPath(src).name)
    src = str(row.get("source_file") or "")
    if src:
        names.append(pathlib.PurePosixPath(src).name)
    return names


def _label_scores(haystacks: Iterable[str]) -> dict[str, int]:
    scores: dict[str, int] = {}
    lowered = [text.lower() for text in haystacks if text]
    for label, keywords in _LABEL_KEYWORDS:
        hits = sum(
            1
            for text in lowered
            for keyword in keywords
            if keyword in text
        )
        if hits:
            scores[label] = hits
    return scores


def _infer_label(module_id: str, rows: list[dict[str, Any]]) -> str:
    haystacks = [module_id.replace("_", "/")]
    for row in rows:
        haystacks.extend(_segments(_path_of(row.get("endpoint", ""))))
        haystacks.extend(_provenance_basenames(row))
    scores = _label_scores(haystacks)
    if not scores:
        return "未标注"
    priority = {label: index for index, (label, _kw) in enumerate(_LABEL_KEYWORDS)}
    ranked = sorted(scores, key=lambda label: (scores[label], -priority[label]),
                    reverse=True)
    top = ranked[0]
    if len(ranked) > 1 and scores[ranked[1]] >= scores[top] * 0.6:
        return f"{top}/{ranked[1]}"
    return top


def _load_inventory(run: pathlib.Path) -> list[dict[str, Any]]:
    path = run / "inventory.json"
    if not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    # Accept both the current endpoint-inventory schema (``endpoints``) and
    # the older attack-surface schema (``surfaces``, e.g. v8.x runs).
    rows = None
    if isinstance(data, dict):
        rows = data.get("endpoints") or data.get("surfaces")
    elif isinstance(data, list):
        rows = data
    if not isinstance(rows, list):
        return []
    return [row for row in rows if isinstance(row, dict) and row.get("endpoint")]


def _load_ledger_surfaces(run: pathlib.Path) -> list[dict[str, Any]]:
    """Load raw ledger surfaces, preserving legacy fields like ``role``.

    ``CoverageLedger`` normalization collapses the legacy singular ``role``
    into ``roles=["unknown"]``; the map view wants the real value, so legacy
    ``matrix`` state is the only path that goes through ``CoverageLedger``.
    """
    path = run / "coverage-ledger.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if isinstance(data, dict) and isinstance(data.get("surfaces"), list):
        return [s for s in data["surfaces"] if isinstance(s, dict)]
    if isinstance(data, dict) and isinstance(data.get("matrix"), dict):
        return CoverageLedger.from_state(data).surfaces
    return []


def _surface_roles(surface: dict[str, Any]) -> list[str]:
    roles = [str(r) for r in (surface.get("roles") or []) if r]
    if not roles and surface.get("role"):
        roles = [str(surface["role"])]
    return roles


def _load_feature_endpoints(run: pathlib.Path) -> dict[str, list[str]]:
    """Best-effort endpoint path -> feature_ids cross-check map.

    Only consumed when a Threat Mode ``feature-graph.json`` exists; any
    schema drift silently degrades to an empty map (the cross-check column
    is informational, never authoritative).
    """
    path = run / "feature-graph.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    features = data.get("features") if isinstance(data, dict) else None
    if not isinstance(features, list):
        return {}
    mapping: dict[str, list[str]] = {}
    for feature in features:
        if not isinstance(feature, dict):
            continue
        fid = str(feature.get("id") or feature.get("feature_id") or "").strip()
        if not fid:
            continue
        endpoints = feature.get("endpoints") or feature.get("paths") or []
        if isinstance(endpoints, str):
            endpoints = [endpoints]
        for entry in endpoints:
            path = entry.get("path") if isinstance(entry, dict) else entry
            path = str(path or "").split("?", 1)[0]
            if path:
                mapping.setdefault(path, [])
                if fid not in mapping[path]:
                    mapping[path].append(fid)
    return mapping


def _initial_groups(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        path = _path_of(row.get("endpoint", ""))
        if _is_probe_path(path):
            key = "_probe"
        elif len(_segments(path)) <= 1:
            key = "_pages"
        else:
            key = _group_key(path, 1)
        groups.setdefault(key, []).append(row)
    return groups


def _split_dominant(groups: dict[str, list[dict[str, Any]]],
                    ) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for key, rows in groups.items():
        if key in ("_probe", "_pages") or len(rows) < DOMINANT_GROUP_MIN:
            out.setdefault(key, []).extend(rows)
            continue
        subgroups: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            sub = _group_key(_path_of(row.get("endpoint", "")), 2)
            subgroups.setdefault(sub, []).append(row)
        # A subgroup only counts as a real sub-module when it could survive
        # the small-group merge on its own; pairs of duplicate methods on
        # one endpoint must not trigger a split into singletons.
        meaningful = sum(1 for sub in subgroups.values()
                         if len(sub) >= MIN_GROUP_SIZE)
        if meaningful >= 2:
            for sub, sub_rows in sorted(subgroups.items()):
                out.setdefault(sub, []).extend(sub_rows)
        else:
            out.setdefault(key, []).extend(rows)
    return out


def _merge_small_groups(groups: dict[str, list[dict[str, Any]]],
                        ) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    misc: list[dict[str, Any]] = []
    for key, rows in sorted(groups.items()):
        if key in ("_probe", "_pages") or len(rows) >= MIN_GROUP_SIZE:
            out.setdefault(key, []).extend(rows)
        else:
            misc.extend(rows)
    if misc:
        out["_misc"] = misc
    return out


def _coverage_index(surfaces: list[dict[str, Any]],
                    base_segments: list[str] | None = None,
                    ) -> dict[tuple[str, str], list[dict[str, Any]]]:
    index: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for surface in surfaces:
        endpoint = _strip_known_base(
            str(surface.get("endpoint", "")), base_segments or [])
        method = str(surface.get("method") or "").upper()
        index.setdefault((endpoint, method), []).append(surface)
    return index


def _status_counts(surfaces: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for surface in surfaces:
        status = normalize_status(str(surface.get("status") or STATUS_NOT_TESTED))
        counts[status] = counts.get(status, 0) + 1
    return counts


def build_module_map(run_dir: str | pathlib.Path) -> dict[str, Any]:
    """Build the module map dict for one run directory (read-only inputs)."""
    run = pathlib.Path(run_dir).resolve()
    rows = _load_inventory(run)
    surfaces = _load_ledger_surfaces(run)
    if not rows:
        # Ledger-only fallback: derive endpoint rows from ledger surfaces
        # (legacy runs without an endpoint inventory).
        seen_rows: set[tuple[str, str]] = set()
        for surface in surfaces:
            path = _path_of(surface.get("endpoint", ""))
            if not path or path == "/":
                continue
            method = str(surface.get("method") or "").upper() or "GET"
            if (path, method) in seen_rows:
                continue
            seen_rows.add((path, method))
            param = str(surface.get("param") or "").strip("- ")
            rows.append({
                "endpoint": path,
                "method": method,
                "params": [param] if param else [],
            })
    base_segments = _strip_base_prefixes(rows)
    rows = _merge_duplicate_rows(rows)
    feature_map = {
        _strip_known_base(path, base_segments): fids
        for path, fids in _load_feature_endpoints(run).items()
    }

    coverage = _coverage_index(surfaces, base_segments)

    groups = _merge_small_groups(_split_dominant(_initial_groups(rows)))

    modules: list[dict[str, Any]] = []
    for module_id in sorted(groups):
        members = groups[module_id]
        endpoints: list[dict[str, Any]] = []
        module_surfaces: list[dict[str, Any]] = []
        for row in members:
            path = _path_of(row.get("endpoint", ""))
            method = str(row.get("method") or "").upper() or "GET"
            module_surfaces.extend(coverage.get((path, method), []))
            endpoints.append({
                "method": method,
                "path": path,
                "params": [str(p) for p in (row.get("params") or [])],
                "sources": sorted(set(_provenance_basenames(row))),
                "feature_ids": feature_map.get(path, []),
            })
        roles = sorted({
            role
            for surface in module_surfaces
            for role in _surface_roles(surface)
        })
        feature_ids = sorted({
            fid
            for endpoint in endpoints
            for fid in endpoint.get("feature_ids", [])
        })
        label = _SPECIAL_LABELS.get(module_id) or _infer_label(module_id, members)
        modules.append({
            "module_id": module_id,
            "label": label,
            "endpoint_count": len(endpoints),
            "endpoints": endpoints,
            "roles": roles,
            "coverage": _status_counts(module_surfaces),
            "high_value_open": sum(
                1
                for surface in module_surfaces
                if is_high_value(surface)
                and normalize_status(str(surface.get("status") or ""))
                in {STATUS_NOT_TESTED, STATUS_EXPLORING}
            ),
            "feature_ids": feature_ids,
        })

    role_count = len({
        role for module in modules for role in module.get("roles", [])
    })
    cell_count = sum(
        sum(module.get("coverage", {}).values()) for module in modules
    )
    endpoint_count = sum(module["endpoint_count"] for module in modules)
    counted_modules = [m for m in modules if m["module_id"] != "_probe"]
    scale = scale_assessment(
        endpoint_count=endpoint_count,
        module_count=len(counted_modules),
        role_count=role_count,
        cell_count=cell_count,
        high_value_open=sum(m["high_value_open"] for m in modules),
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "module_map",
        "derived": True,
        "run_dir": str(run),
        "scale": scale,
        "modules": modules,
    }


def scale_assessment(*, endpoint_count: int, module_count: int,
                     role_count: int, cell_count: int,
                     high_value_open: int) -> dict[str, Any]:
    """Classify target scale and advise on per-module run splitting."""
    if (endpoint_count > LARGE_ENDPOINT_MIN
            or module_count > LARGE_MODULE_MIN
            or cell_count > LARGE_CELL_MIN):
        level = "large"
        advice = ("建议按模块分块：每个 Run 冻结一个模块的分母，"
                  "跨 Run 用 next-run-agenda 续测。")
    elif endpoint_count < SMALL_ENDPOINT_MAX and module_count <= SMALL_MODULE_MAX:
        level = "small"
        advice = "规模较小：单 Run 覆盖即可，无需分块。"
    else:
        level = "medium"
        advice = "中等规模：可分块，按模块轮换 Run；先人工核对本图聚类质量。"
    return {
        "endpoint_count": endpoint_count,
        "module_count": module_count,
        "role_count": role_count,
        "cell_count": cell_count,
        "high_value_open": high_value_open,
        "level": level,
        "advice": advice,
        "thresholds": {
            "small_endpoint_max": SMALL_ENDPOINT_MAX,
            "small_module_max": SMALL_MODULE_MAX,
            "large_endpoint_min": LARGE_ENDPOINT_MIN,
            "large_module_min": LARGE_MODULE_MIN,
            "large_cell_min": LARGE_CELL_MIN,
        },
    }


def render_module_map_md(map_dict: dict[str, Any]) -> str:
    """Render the human-readable module map (derived view, not authority)."""
    scale = map_dict.get("scale") or {}
    lines = [
        "# Module Map（派生视图 · 非权威输入）",
        "",
        f"- run_dir: `{map_dict.get('run_dir', '')}`",
        f"- 端点数: {scale.get('endpoint_count', 0)} · "
        f"模块数: {scale.get('module_count', 0)} · "
        f"角色数: {scale.get('role_count', 0)} · "
        f"覆盖格: {scale.get('cell_count', 0)} · "
        f"未闭高价值格: {scale.get('high_value_open', 0)}",
        f"- 规模判定: **{scale.get('level', '?')}** — {scale.get('advice', '')}",
        "",
        "## 模块",
        "",
    ]
    for module in map_dict.get("modules") or []:
        coverage = module.get("coverage") or {}
        coverage_text = ", ".join(f"{k}={v}" for k, v in sorted(coverage.items())) or "无记录"
        lines.append(f"### `{module.get('module_id')}` — {module.get('label')}"
                     f"（{module.get('endpoint_count', 0)} 端点）")
        lines.append("")
        lines.append(f"- roles: {', '.join(module.get('roles') or []) or '未记录'}")
        lines.append(f"- 覆盖: {coverage_text} · 未闭高价值格: {module.get('high_value_open', 0)}")
        if module.get("feature_ids"):
            lines.append(f"- feature 对照: {', '.join(module['feature_ids'])}")
        lines.append("")
        lines.append("| method | path | params | 来源 |")
        lines.append("|---|---|---|---|")
        for endpoint in module.get("endpoints") or []:
            params = ", ".join(endpoint.get("params") or []) or "-"
            sources = ", ".join(endpoint.get("sources") or []) or "-"
            lines.append(
                f"| {endpoint.get('method')} | `{endpoint.get('path')}` "
                f"| {params} | {sources} |")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_module_map(run_dir: str | pathlib.Path) -> dict[str, Any]:
    """Build, write ``module_map.json``/``module_map.md`` and return a summary."""
    run = pathlib.Path(run_dir).resolve()
    map_dict = build_module_map(run)
    atomic_write_json(run / "module_map.json", map_dict, root=run)
    atomic_write_text(run / "module_map.md", render_module_map_md(map_dict), root=run)
    scale = map_dict["scale"]
    summary_line = (
        f"map: level={scale['level']} endpoints={scale['endpoint_count']} "
        f"modules={scale['module_count']} cells={scale['cell_count']} "
        f"high_value_open={scale['high_value_open']}")
    print(summary_line)
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "direct_diagnostic",
        "authority_trusted": False,
        "derived_view": True,
        "scale": scale,
        "artifacts": ["module_map.json", "module_map.md"],
        "summary": summary_line,
    }


__all__ = [
    "build_module_map",
    "render_module_map_md",
    "scale_assessment",
    "write_module_map",
]
