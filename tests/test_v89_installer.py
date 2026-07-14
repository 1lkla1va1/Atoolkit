from __future__ import annotations

import pathlib
import stat
import subprocess


ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "codex" / "install_workspace_agents.sh"
SOURCE = ROOT / "AGENTS.md"


def _run(workspace: pathlib.Path, *, force: bool = False) -> subprocess.CompletedProcess[str]:
    command = ["bash", str(INSTALLER), "--workspace", str(workspace)]
    if force:
        command.append("--force")
    return subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def _temporary_files(workspace: pathlib.Path) -> list[pathlib.Path]:
    return list(workspace.glob(".AGENTS.md.atoolkit-v89.tmp.*"))


def test_installer_creates_private_file_and_is_idempotent(tmp_path: pathlib.Path) -> None:
    first = _run(tmp_path)
    second = _run(tmp_path)

    destination = tmp_path / "AGENTS.md"
    assert first.returncode == second.returncode == 0
    assert destination.read_bytes() == SOURCE.read_bytes()
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert not _temporary_files(tmp_path)


def test_installer_refuses_conflict_then_force_keeps_exclusive_backup(
    tmp_path: pathlib.Path,
) -> None:
    destination = tmp_path / "AGENTS.md"
    old = b"workspace-owned instructions\n"
    destination.write_bytes(old)

    refused = _run(tmp_path)
    assert refused.returncode == 1
    assert "different content" in refused.stderr
    assert destination.read_bytes() == old

    installed = _run(tmp_path, force=True)
    backup = tmp_path / "AGENTS.md.pre-atoolkit-v89.backup"
    assert installed.returncode == 0
    assert destination.read_bytes() == SOURCE.read_bytes()
    assert backup.read_bytes() == old
    assert not backup.is_symlink()
    assert backup.stat().st_ino != destination.stat().st_ino
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert not _temporary_files(tmp_path)


def test_installer_force_refuses_precreated_backup_symlink_without_external_write(
    tmp_path: pathlib.Path,
) -> None:
    destination = tmp_path / "AGENTS.md"
    destination.write_bytes(b"workspace-owned instructions\n")
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside sentinel\n")
    backup = tmp_path / "AGENTS.md.pre-atoolkit-v89.backup"
    backup.symlink_to(outside)

    result = _run(tmp_path, force=True)

    assert result.returncode == 1
    assert "existing backup" in result.stderr
    assert outside.read_bytes() == b"outside sentinel\n"
    assert destination.read_bytes() == b"workspace-owned instructions\n"
    assert backup.is_symlink()
    assert not _temporary_files(tmp_path)


def test_installer_refuses_destination_symlink_without_external_write(
    tmp_path: pathlib.Path,
) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside sentinel\n")
    destination = tmp_path / "AGENTS.md"
    destination.symlink_to(outside)

    result = _run(tmp_path, force=True)

    assert result.returncode == 1
    assert "refusing to replace symlink" in result.stderr
    assert destination.is_symlink()
    assert outside.read_bytes() == b"outside sentinel\n"
    assert not _temporary_files(tmp_path)


def test_installer_force_never_overwrites_existing_regular_backup(
    tmp_path: pathlib.Path,
) -> None:
    destination = tmp_path / "AGENTS.md"
    destination.write_bytes(b"workspace-owned instructions\n")
    backup = tmp_path / "AGENTS.md.pre-atoolkit-v89.backup"
    backup.write_bytes(b"older backup\n")

    result = _run(tmp_path, force=True)

    assert result.returncode == 1
    assert "existing backup" in result.stderr
    assert backup.read_bytes() == b"older backup\n"
    assert destination.read_bytes() == b"workspace-owned instructions\n"
    assert not _temporary_files(tmp_path)
