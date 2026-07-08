"""Blackboard v2 schema integrity tests."""
import re
import pathlib
import pytest


class TestBlackboardV2Schema:
    """Blackboard v2 must preserve fields needed for cross-run inheritance."""

    def _read_graph(self):
        return pathlib.Path("engine/graph.py").read_text(encoding="utf-8")

    def test_schema_v2_has_all_required_keys(self):
        src = self._read_graph()
        required = [
            "schema_version", "facts", "intents", "negatives",
            "dead_ends", "domains_covered", "surface_index",
        ]
        missing = [k for k in required if k not in src]
        assert not missing, f"Blackboard v2 missing keys in graph.py: {missing}"

    def test_total_runs_preserved(self):
        """Schema v2 must not drop total_runs (needed for 0.9^runs intent decay)."""
        src = self._read_graph()
        assert "total_runs" in src, (
            "Blackboard v2 does not handle total_runs. "
            "Intent decay 0.9^runs_since breaks without it."
        )

    def test_import_reads_v2_fields(self):
        src = self._read_graph()
        fn_match = re.search(
            r"def import_from_blackboard.*?(?=\ndef |\Z)", src, re.DOTALL
        )
        assert fn_match, "import_from_blackboard not found"
        body = fn_match.group(0)
        for field in ["negatives", "dead_ends", "intents"]:
            assert field in body, (
                f"import_from_blackboard does not read v2 field: {field}"
            )
