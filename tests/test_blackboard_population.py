"""D3: domains_covered and surface_index must be populated in blackboard v2."""
import pathlib
import pytest


class TestD3_BlackboardPopulation:
    """D3: orchestrator must fill domains_covered and surface_index with real data."""

    def _read_orchestrator(self):
        p = pathlib.Path("engine/orchestrator.py")
        assert p.exists(), f"{p} not found"
        return p.read_text(encoding="utf-8")

    def test_domains_covered_is_populated(self):
        """orchestrator must assign real data to domains_covered, not just setdefault({})."""
        src = self._read_orchestrator()
        lines = src.split("\n")
        real_assignments = []
        for i, line in enumerate(lines):
            if "domains_covered" in line:
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if "setdefault" in line and "{}" in line:
                    continue
                if "=" in line and "{}" not in line:
                    real_assignments.append((i + 1, stripped))
                elif ".update(" in line:
                    real_assignments.append((i + 1, stripped))
        assert len(real_assignments) > 0, (
            "D3 FAIL: domains_covered is only set via setdefault({}). "
            "No code populates it with actual domain coverage data."
        )

    def test_surface_index_is_populated(self):
        """orchestrator must assign real data to surface_index."""
        src = self._read_orchestrator()
        lines = src.split("\n")
        real_assignments = []
        for i, line in enumerate(lines):
            if "surface_index" in line:
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if "setdefault" in line and "{}" in line:
                    continue
                if "=" in line and "{}" not in line:
                    real_assignments.append((i + 1, stripped))
                elif ".update(" in line:
                    real_assignments.append((i + 1, stripped))
        assert len(real_assignments) > 0, (
            "D3 FAIL: surface_index is only set via setdefault({}). "
            "No code populates it with actual surface indexing data."
        )
