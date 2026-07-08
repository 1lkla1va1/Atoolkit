"""D4 + D5 + D6: orchestrator output must include scheduler_stats, low_roi_advisory, run_summary.md."""
import re
import pathlib
import pytest


def _read(path):
    return pathlib.Path(path).read_text(encoding="utf-8")


class TestD4_SchedulerStats:
    """D4: orchestrator output dict must contain scheduler_stats."""

    def test_scheduler_stats_in_result(self):
        src = _read("engine/orchestrator.py")
        # Look for scheduler_stats key in a dict literal or assignment
        has_key = bool(re.search(r"""["']scheduler_stats["']\s*:""", src))
        has_assign = bool(re.search(
            r"""scheduler_stats["']\s*\]\s*=\s*(?!\{\})""", src
        ))
        assert has_key or has_assign, (
            "D4 FAIL: orchestrator.py never sets scheduler_stats in output dict."
        )

    def test_scheduler_stats_not_empty(self):
        src = _read("engine/orchestrator.py")
        lines = src.split("\n")
        for line in lines:
            if "scheduler_stats" in line and "=" in line:
                if re.search(r"""scheduler_stats[^=]*=\s*\{\}""", line):
                    pytest.fail(f"D4 FAIL: scheduler_stats = {{}} in: {line.strip()}")
        found = any("scheduler_stats" in l for l in lines)
        assert found, "D4 FAIL: scheduler_stats not found in orchestrator.py"


class TestD5_LowRoiAdvisory:
    """D5: low_roi_advisory must be called in termination logic."""

    def test_low_roi_advisory_called(self):
        src = _read("engine/orchestrator.py")
        called = bool(re.search(r"low_roi_advisory\s*\(", src))
        assert called, (
            "D5 FAIL: low_roi_advisory() never called in orchestrator.py. "
            "PLAN: LOW_ROI invalid if high-value nodes untested."
        )


class TestD6_RunSummaryMd:
    """D6: run_summary.md must be generated after each run."""

    def test_run_summary_generation(self):
        orch = _read("engine/orchestrator.py")
        run = _read("run.py")
        combined = orch + run
        has = bool(re.search(r"run_summary\.md|run_summary_md", combined, re.IGNORECASE))
        assert has, (
            "D6 FAIL: no code generates run_summary.md. "
            "PLAN Section 7 requires it."
        )

    def test_run_summary_write_call(self):
        orch = _read("engine/orchestrator.py")
        run = _read("run.py")
        combined = orch + run
        has_write = bool(re.search(
            r"run_summary.*write_text|write_text.*run_summary",
            combined, re.IGNORECASE | re.DOTALL,
        ))
        has_open = bool(re.search(
            r"""run_summary.*open\(.*['"]w['"]""",
            combined, re.IGNORECASE | re.DOTALL,
        ))
        assert has_write or has_open, (
            "D6 FAIL: run_summary.md mentioned but no file write call found."
        )
