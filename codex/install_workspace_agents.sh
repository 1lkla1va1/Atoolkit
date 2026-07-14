#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKSPACE=""
FORCE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace)
      WORKSPACE="${2:-}"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$WORKSPACE" ]]; then
  echo "usage: $0 --workspace /absolute/path [--force]" >&2
  exit 2
fi
if [[ "$WORKSPACE" != /* ]]; then
  echo "--workspace must be an absolute path" >&2
  exit 2
fi
if [[ ! -d "$WORKSPACE" || -L "$WORKSPACE" ]]; then
  echo "workspace must be an existing real directory: $WORKSPACE" >&2
  exit 2
fi

SOURCE="$ROOT/AGENTS.md"
python3 - "$SOURCE" "$WORKSPACE" "$FORCE" <<'PY'
from __future__ import annotations

import errno
import os
import secrets
import stat
import sys


class InstallRefused(RuntimeError):
    pass


source, workspace, force_text = sys.argv[1:]
force = force_text == "1"
destination = "AGENTS.md"
backup = "AGENTS.md.pre-atoolkit-v89.backup"
temporary = ""


def read_regular_at(directory_fd: int, name: str) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY
    if not hasattr(os, "O_NOFOLLOW"):
        raise InstallRefused("platform lacks O_NOFOLLOW; refusing unsafe install")
    flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise InstallRefused(f"refusing non-regular file: {workspace}/{name}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks), info
    finally:
        os.close(descriptor)


def read_source(path: str) -> bytes:
    flags = os.O_RDONLY
    if not hasattr(os, "O_NOFOLLOW"):
        raise InstallRefused("platform lacks O_NOFOLLOW; refusing unsafe install")
    descriptor = os.open(path, flags | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise InstallRefused(f"installer source is not a regular file: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("short write while staging AGENTS.md")
        offset += written


directory_flags = os.O_RDONLY
if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
    print("platform lacks directory no-follow primitives; refusing unsafe install", file=sys.stderr)
    raise SystemExit(1)
directory_flags |= os.O_DIRECTORY | os.O_NOFOLLOW

try:
    source_payload = read_source(source)
    directory_fd = os.open(workspace, directory_flags)
except (InstallRefused, OSError) as exc:
    print(str(exc), file=sys.stderr)
    raise SystemExit(1) from exc

try:
    existing_payload: bytes | None = None
    existing_info: os.stat_result | None = None
    try:
        existing_payload, existing_info = read_regular_at(directory_fd, destination)
    except FileNotFoundError:
        pass
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise InstallRefused(
                f"refusing to replace symlink: {workspace}/{destination}") from exc
        raise

    if existing_payload is not None and existing_payload != source_payload:
        if not force:
            raise InstallRefused(
                "AGENTS.md already exists with different content; "
                "inspect it or pass --force")
        try:
            os.link(
                destination,
                backup,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError as exc:
            raise InstallRefused(
                f"refusing to replace existing backup: {workspace}/{backup}") from exc

        # The hard link is an atomic, create-exclusive snapshot. Verify that
        # the source name did not change between the no-follow read and link.
        try:
            backup_payload, backup_info = read_regular_at(directory_fd, backup)
        except BaseException:
            os.unlink(backup, dir_fd=directory_fd)
            raise
        if (
            existing_info is None
            or (backup_info.st_dev, backup_info.st_ino)
            != (existing_info.st_dev, existing_info.st_ino)
            or backup_payload != existing_payload
        ):
            os.unlink(backup, dir_fd=directory_fd)
            raise InstallRefused(
                "AGENTS.md changed while creating backup; refusing raced install")
        os.fsync(directory_fd)

    temporary = f".AGENTS.md.atoolkit-v89.tmp.{os.getpid()}.{secrets.token_hex(8)}"
    temporary_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    temporary_fd = os.open(temporary, temporary_flags, 0o600, dir_fd=directory_fd)
    try:
        write_all(temporary_fd, source_payload)
        os.fchmod(temporary_fd, 0o600)
        os.fsync(temporary_fd)
    finally:
        os.close(temporary_fd)

    # renameat(2) semantics: replace the destination directory entry itself;
    # never follow a raced leaf symlink and never move into a raced directory.
    os.replace(
        temporary,
        destination,
        src_dir_fd=directory_fd,
        dst_dir_fd=directory_fd,
    )
    temporary = ""
    os.fsync(directory_fd)
except (InstallRefused, OSError) as exc:
    print(str(exc), file=sys.stderr)
    raise SystemExit(1) from exc
finally:
    if temporary:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
    os.close(directory_fd)

print(f"installed Atoolkit AGENTS.md -> {workspace}/{destination}")
PY
