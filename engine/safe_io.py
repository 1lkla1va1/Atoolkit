"""Symlink-safe, durability-oriented writes for parent-owned artifacts.

The model-writable run directory is an untrusted pathname namespace.  A plain
``Path.write_text`` follows a pre-created leaf symlink, while a check followed
by a write has an unavoidable race.  This module instead walks every parent
component using directory file descriptors and ``O_NOFOLLOW`` and performs
all final operations relative to the already-open parent directory.

Atomic replacement intentionally *replaces* a leaf symlink rather than
following it.  Append cannot safely replace an existing stream, so it rejects
a leaf symlink (and multiply-linked files) fail closed.  Strict parent-owned
writes may also reject a pre-existing multiply-linked leaf as namespace
tampering even though replacement itself would not follow that hard link.
"""
from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import os
import pathlib
import secrets
import stat
import threading
import time
from typing import Any, Iterator


class UnsafePathError(ValueError):
    """Raised when a destination cannot be reached without following links."""


_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_FILE_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[str, threading.RLock] = {}


def _require_primitives() -> None:
    if not getattr(os, "O_NOFOLLOW", 0) or not getattr(os, "O_DIRECTORY", 0):
        raise OSError("safe_io requires O_NOFOLLOW and O_DIRECTORY")
    if os.open not in os.supports_dir_fd or os.mkdir not in os.supports_dir_fd:
        raise OSError("safe_io requires openat/mkdirat directory-fd support")


def _absolute_lexical(path: str | os.PathLike[str]) -> pathlib.Path:
    raw = pathlib.Path(path).expanduser()
    if not raw.is_absolute():
        raw = pathlib.Path.cwd() / raw
    # abspath removes '.' and '..' lexically without resolving symlinks.
    return pathlib.Path(os.path.abspath(os.fspath(raw)))


def _target_and_root(
    path: str | os.PathLike[str],
    root: str | os.PathLike[str] | None,
) -> tuple[pathlib.Path, pathlib.Path]:
    if root is None:
        target = _absolute_lexical(path)
        anchor = pathlib.Path(target.anchor or os.sep)
        return target, anchor

    anchor = _absolute_lexical(root)
    raw = pathlib.Path(path).expanduser()
    target = _absolute_lexical(raw if raw.is_absolute() else anchor / raw)
    try:
        target.relative_to(anchor)
    except ValueError as exc:
        raise UnsafePathError(f"destination escapes safe root: {target}") from exc
    return target, anchor


def _unsafe_component(exc: OSError, path: pathlib.Path) -> UnsafePathError:
    return UnsafePathError(
        f"unsafe path component {path}: {exc.strerror or type(exc).__name__}")


def _open_child_directory(parent_fd: int, name: str, display: pathlib.Path) -> int:
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise _unsafe_component(exc, display) from exc
        raise
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise UnsafePathError(f"path component is not a directory: {display}")
    return descriptor


def _walk_directory(path: pathlib.Path, *, create: bool) -> int:
    """Open *path* without ever resolving a symlink, returning an owned fd."""
    _require_primitives()
    if not path.is_absolute():  # defensive: callers normalize before walking
        raise UnsafePathError(f"safe directory must be absolute: {path}")
    descriptor = os.open(path.anchor or os.sep, _DIRECTORY_FLAGS)
    current = pathlib.Path(path.anchor or os.sep)
    try:
        for component in path.parts[1:]:
            display = current / component
            try:
                child = _open_child_directory(descriptor, component, display)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    # A racing creator is accepted only if the new entry is a
                    # real directory; _open_child_directory performs the check.
                    pass
                except OSError as exc:
                    if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                        raise _unsafe_component(exc, display) from exc
                    raise
                child = _open_child_directory(descriptor, component, display)
            os.close(descriptor)
            descriptor = child
            current = display
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


@contextlib.contextmanager
def _open_parent(
    path: str | os.PathLike[str],
    *,
    root: str | os.PathLike[str] | None,
    create_parents: bool,
) -> Iterator[tuple[int, str, pathlib.Path]]:
    target, anchor = _target_and_root(path, root)
    if not target.name or target == anchor:
        raise UnsafePathError(f"destination must name a file: {target}")

    anchor_fd = _walk_directory(anchor, create=create_parents)
    descriptor = anchor_fd
    current = anchor
    try:
        relative_parent = target.parent.relative_to(anchor)
        for component in relative_parent.parts:
            if component in {"", "."}:
                continue
            display = current / component
            try:
                child = _open_child_directory(descriptor, component, display)
            except FileNotFoundError:
                if not create_parents:
                    raise
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = _open_child_directory(descriptor, component, display)
            os.close(descriptor)
            descriptor = child
            current = display
        yield descriptor, target.name, target
    finally:
        os.close(descriptor)


def ensure_directory(
    path: str | os.PathLike[str],
    *,
    root: str | os.PathLike[str] | None = None,
) -> pathlib.Path:
    """Create/open a directory tree without following parent symlinks."""
    target, anchor = _target_and_root(path, root)
    if root is not None:
        # Walking the full target also validates the anchor and every child.
        target.relative_to(anchor)
    descriptor = _walk_directory(target, create=True)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return target


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:  # pragma: no cover - defensive kernel contract check
            raise OSError("short write")
        view = view[written:]


def safe_read_bytes(
    path: str | os.PathLike[str],
    *,
    root: str | os.PathLike[str] | None = None,
    max_bytes: int | None = None,
) -> bytes:
    """Read a regular, singly-linked file without following any symlink."""
    with _open_parent(path, root=root, create_parents=False) as (parent_fd, leaf, target):
        try:
            descriptor = os.open(
                leaf,
                os.O_RDONLY | _FILE_NOFOLLOW,
                dir_fd=parent_fd,
            )
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise _unsafe_component(exc, target) from exc
            raise
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise UnsafePathError(f"read source is not a regular file: {target}")
            if info.st_nlink != 1:
                raise UnsafePathError(f"read source has multiple hard links: {target}")
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    return b"".join(chunks)
                total += len(chunk)
                if max_bytes is not None and total > int(max_bytes):
                    raise ValueError(
                        f"read source exceeds max_bytes={int(max_bytes)}: {target}")
                chunks.append(chunk)
        finally:
            os.close(descriptor)


def safe_read_text(
    path: str | os.PathLike[str],
    *,
    root: str | os.PathLike[str] | None = None,
    encoding: str = "utf-8",
) -> str:
    return safe_read_bytes(path, root=root).decode(encoding)


@contextlib.contextmanager
def exclusive_file_lock(
    path: str | os.PathLike[str],
    *,
    root: str | os.PathLike[str] | None = None,
    mode: int = 0o600,
) -> Iterator[pathlib.Path]:
    """Hold a pathname-scoped thread and process lock.

    ``flock`` alone does not provide a portable same-process thread mutex.
    The in-memory lock closes that gap, while the advisory file lock
    serializes independent parent processes.  The lock leaf and every parent
    are opened without following links.
    """
    target, _anchor = _target_and_root(path, root)
    key = str(target)
    with _LOCKS_GUARD:
        thread_lock = _LOCKS.setdefault(key, threading.RLock())
    with thread_lock:
        with _open_parent(path, root=root, create_parents=True) as (
            parent_fd, leaf, opened_target,
        ):
            try:
                descriptor = os.open(
                    leaf,
                    os.O_RDWR | os.O_CREAT | _FILE_NOFOLLOW,
                    mode,
                    dir_fd=parent_fd,
                )
            except OSError as exc:
                if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                    raise _unsafe_component(exc, opened_target) from exc
                raise
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode):
                    raise UnsafePathError(
                        f"lock destination is not a regular file: {opened_target}")
                if info.st_nlink != 1:
                    raise UnsafePathError(
                        f"lock destination has multiple hard links: {opened_target}")
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                try:
                    yield opened_target
                finally:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)


def atomic_write_bytes(
    path: str | os.PathLike[str],
    payload: bytes,
    *,
    root: str | os.PathLike[str] | None = None,
    mode: int = 0o600,
    reject_leaf_symlink: bool = False,
) -> pathlib.Path:
    """Atomically replace *path* without following parent or leaf symlinks.

    By default a leaf symlink is replaced as a directory entry, never
    followed.  Parent-owned mutable state can request the stricter
    ``reject_leaf_symlink`` contract so a pre-created symbolic *or hard-linked*
    leaf is treated as namespace tampering instead of being silently healed.
    The historical parameter name is retained for API compatibility.
    """
    data = bytes(payload)
    with _open_parent(path, root=root, create_parents=True) as (parent_fd, leaf, target):
        if reject_leaf_symlink:
            try:
                existing = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                existing = None
            if existing is not None:
                if stat.S_ISLNK(existing.st_mode):
                    raise UnsafePathError(
                        f"atomic destination is a symbolic link: {target}")
                if stat.S_ISREG(existing.st_mode) and existing.st_nlink != 1:
                    raise UnsafePathError(
                        f"atomic destination has multiple hard links: {target}")
        temporary = f".{leaf}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_NOFOLLOW,
                mode,
                dir_fd=parent_fd,
            )
            _write_all(descriptor, data)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            os.replace(
                temporary,
                leaf,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            os.fsync(parent_fd)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        return target


def atomic_write_text(
    path: str | os.PathLike[str],
    text: str,
    *,
    root: str | os.PathLike[str] | None = None,
    encoding: str = "utf-8",
    mode: int = 0o600,
    reject_leaf_symlink: bool = False,
) -> pathlib.Path:
    return atomic_write_bytes(
        path,
        str(text).encode(encoding),
        root=root,
        mode=mode,
        reject_leaf_symlink=reject_leaf_symlink,
    )


def atomic_write_json(
    path: str | os.PathLike[str],
    value: Any,
    *,
    root: str | os.PathLike[str] | None = None,
    mode: int = 0o600,
    reject_leaf_symlink: bool = False,
) -> pathlib.Path:
    payload = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    return atomic_write_text(
        path,
        payload,
        root=root,
        mode=mode,
        reject_leaf_symlink=reject_leaf_symlink,
    )


def create_json_exclusive(
    path: str | os.PathLike[str],
    value: Any,
    *,
    root: str | os.PathLike[str] | None = None,
    mode: int = 0o600,
) -> bool:
    """Publish a complete JSON file once; return ``False`` if it exists.

    Opening the final leaf with ``O_EXCL`` makes ownership exclusive but exposes
    an empty inode before the winner finishes writing.  A concurrent reader can
    therefore observe invalid JSON.  Write and fsync a private inode first, then
    hard-link it into the final name: link creation is both atomic and
    no-clobber, so the public leaf is complete from its first observable byte.
    """
    payload = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    with _open_parent(path, root=root, create_parents=True) as (parent_fd, leaf, _target):
        temporary = f".{leaf}.create-{os.getpid()}-{secrets.token_hex(8)}"
        descriptor: int | None = None
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_NOFOLLOW,
                mode,
                dir_fd=parent_fd,
            )
            _write_all(descriptor, payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
            try:
                os.link(
                    temporary,
                    leaf,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                    follow_symlinks=False,
                )
                created = True
            except FileExistsError:
                created = False
            os.unlink(temporary, dir_fd=parent_fd)
            if created:
                os.fsync(parent_fd)
                return True

            # A concurrent publisher's leaf can very briefly have two links
            # until it removes its private name.  Wait only for that bounded
            # publication window; a persistent hard link remains unsafe.
            for _ in range(50):
                info = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    raise UnsafePathError(
                        f"exclusive destination is not a regular file: {_target}")
                if info.st_nlink == 1:
                    return False
                time.sleep(0.002)
            info = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            raise UnsafePathError(
                f"exclusive destination has multiple hard links: {_target}"
                f" (nlink={info.st_nlink})")
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass


def safe_append_bytes(
    path: str | os.PathLike[str],
    payload: bytes,
    *,
    root: str | os.PathLike[str] | None = None,
    mode: int = 0o600,
) -> pathlib.Path:
    """Append through an ``O_NOFOLLOW`` fd; symlink/hardlink targets fail."""
    with _open_parent(path, root=root, create_parents=True) as (parent_fd, leaf, target):
        try:
            descriptor = os.open(
                leaf,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND | _FILE_NOFOLLOW,
                mode,
                dir_fd=parent_fd,
            )
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise _unsafe_component(exc, target) from exc
            raise
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise UnsafePathError(f"append destination is not a regular file: {target}")
            if info.st_nlink != 1:
                raise UnsafePathError(f"append destination has multiple hard links: {target}")
            _write_all(descriptor, bytes(payload))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent_fd)
        return target


def safe_append_text(
    path: str | os.PathLike[str],
    text: str,
    *,
    root: str | os.PathLike[str] | None = None,
    encoding: str = "utf-8",
    mode: int = 0o600,
) -> pathlib.Path:
    return safe_append_bytes(path, str(text).encode(encoding), root=root, mode=mode)


__all__ = [
    "UnsafePathError",
    "atomic_write_bytes",
    "atomic_write_json",
    "atomic_write_text",
    "create_json_exclusive",
    "ensure_directory",
    "exclusive_file_lock",
    "safe_append_bytes",
    "safe_append_text",
    "safe_read_bytes",
    "safe_read_text",
]
