"""Governance-tax runtime metrics for the Direct-Skill runtime (v9.8.1 W5a).

Measurement only, best-effort by contract: callers wrap the write in
try/except and surface failures through a ``metrics_error`` field, so a
metrics failure (disk/permission) can never fail init/observe/checkpoint.
Direct mode has no token ledger — phase wall-clock seconds plus call counts
are the proxy for "where the budget went" (design §1.5 honesty boundary).
"""
from __future__ import annotations

import contextlib
import json
import pathlib
import time
from typing import Any, Iterator

try:
    from .safe_io import atomic_write_json, ensure_directory
except ImportError:  # pragma: no cover - script execution fallback
    from safe_io import atomic_write_json, ensure_directory

SCHEMA_VERSION = 1


class PhaseTimer:
    """Wall-clock stopwatch handle; ``seconds`` is finalized on exit."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.seconds = 0.0
        self._start = 0.0

    def __enter__(self) -> PhaseTimer:
        self._start = time.perf_counter()
        return self

    def __exit__(self, *exc: object) -> bool:
        self.seconds = time.perf_counter() - self._start
        return False


def phase_timer(name: str) -> PhaseTimer:
    """Context manager timing one phase with ``time.perf_counter``."""
    return PhaseTimer(name)


class PhaseRecorder:
    """Accumulate per-phase wall time and counters within one invocation."""

    def __init__(self) -> None:
        self.phases: dict[str, dict[str, Any]] = {}

    def record(self, name: str, seconds: float, **counters: Any) -> None:
        entry = self.phases.setdefault(
            name, {"calls": 0, "total_seconds": 0.0, "counters": {}})
        entry["calls"] += 1
        entry["total_seconds"] = round(
            entry["total_seconds"] + max(0.0, float(seconds)), 6)
        bucket = entry["counters"]
        for key, value in counters.items():
            bucket[key] = bucket.get(key, 0) + value

    @contextlib.contextmanager
    def phase(self, name: str) -> Iterator[None]:
        with phase_timer(name) as timer:
            yield
        self.record(name, timer.seconds)


def _merge_phase(
    target: dict[str, dict[str, Any]], name: str, entry: dict[str, Any],
) -> None:
    merged = target.setdefault(
        name, {"calls": 0, "total_seconds": 0.0, "counters": {}})
    merged["calls"] += int(entry.get("calls", 0) or 0)
    merged["total_seconds"] = round(
        merged["total_seconds"] + float(entry.get("total_seconds", 0.0) or 0.0), 6)
    bucket = merged["counters"]
    for key, value in (entry.get("counters") or {}).items():
        bucket[key] = bucket.get(key, 0) + value


def write_runtime_metrics(
    run: pathlib.Path,
    recorder: PhaseRecorder,
    *,
    event: str,
    mark_init: bool = False,
    mark_checkpoint: bool = False,
    first_init_at: float | None = None,
) -> dict[str, Any]:
    """Merge one invocation into the run metrics artifacts (two outputs).

    ``runtime-metrics.json`` is the cumulative latest snapshot (atomic write);
    one JSONL line per invocation is appended to ``state/metrics.jsonl``
    (append-only cross-checkpoint history).  ``first_init_at`` is pinned by
    the first init and never moved; ``last_checkpoint_at`` tracks the latest
    checkpoint write.  ``session_span_seconds`` is the wall-clock span between
    the two — an idle-inclusive lower-bound denominator for the governance
    share (Round-2 MAJOR-4); the primary signal stays the absolute per-phase
    totals, which are readable independently under ``by_phase``.
    """
    run = pathlib.Path(run).resolve()
    now = time.time()
    snapshot_path = run / "runtime-metrics.json"
    existing: dict[str, Any] = {}
    if snapshot_path.is_file() and not snapshot_path.is_symlink():
        try:
            value = json.loads(snapshot_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            value = None
        if isinstance(value, dict):
            existing = value
    by_phase: dict[str, dict[str, Any]] = {}
    for name, entry in (existing.get("by_phase") or {}).items():
        if isinstance(entry, dict):
            _merge_phase(by_phase, str(name), entry)
    for name, entry in recorder.phases.items():
        _merge_phase(by_phase, name, entry)
    first = existing.get("first_init_at")
    if first is None and mark_init:
        first = float(first_init_at) if first_init_at is not None else now
    last = now if mark_checkpoint else existing.get("last_checkpoint_at")
    span = None
    if first is not None and last is not None:
        span = round(max(0.0, float(last) - float(first)), 6)
    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "by_phase": by_phase,
        "first_init_at": first,
        "last_checkpoint_at": last,
        "session_span_seconds": span,
    }
    atomic_write_json(snapshot_path, snapshot, root=run, reject_leaf_symlink=True)
    ensure_directory(run / "state", root=run)
    history_path = run / "state" / "metrics.jsonl"
    if history_path.is_symlink():
        raise OSError(f"metrics history is a symlink: {history_path}")
    line = {
        "event": str(event),
        "ts": now,
        "phases": {
            name: {
                "seconds": entry["total_seconds"],
                "calls": entry["calls"],
                "counters": dict(entry.get("counters") or {}),
            }
            for name, entry in sorted(recorder.phases.items())
        },
    }
    with history_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(line, ensure_ascii=False, sort_keys=True) + "\n")
    return snapshot
