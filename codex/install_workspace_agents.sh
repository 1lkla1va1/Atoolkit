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

# v9.3: 单一授权真相 + IDE 薄 shim。两个文件只在不存在时生成（create-exclusive），
# 绝不覆盖用户已有内容；生成失败不阻塞主安装。
python3 - "$WORKSPACE" <<'PY'
from __future__ import annotations

import os
import sys

workspace = sys.argv[1]

AUTHZ_TEMPLATE = """# 授权声明（AUTHZ.md · 单一授权真相）

> 本文件是 Atoolkit 唯一由人维护的授权文件。各 IDE 的授权 shim 只指向本文件；
> 每个 Run 的 runs/<sid>/authz.md 可从本文件复制并按 Run 收窄。
> `engine.skill_runtime init --scope-file AUTHZ.md` 会机器消费下方 scope 列表。

## 授权 Scope（在册资产，超出即停）
- <https://target.example/ 或 host:port，每行一个>

## 派生资产（derived assets：仅在册端点签发凭证/流程触达时才可作为证据目标）
- <如 https://<bucket>.oss-cn-beijing.aliyuncs.com/ ，无则删除本节>

## 授权依据与有效期
- 依据：<SRC 平台/项目规则/合同编号>
- 有效期：<起止日期>

## 预授权动作
- 对上述 scope 的黑盒安全测试：发送/修改 HTTP 请求、参数 fuzz、认证/验证码
  绕过测试、多账号越权对比、OOB 回连（仅自建回连服务器）、写入 runs/ 产物。
- 中途扩资产：`python3 -m engine.skill_runtime scope --run-dir <run> --add <url> --reason <原因>`。

## 边界（立即停手并标 NEED_INPUT）
- 超出 scope 的任何资产（派生资产仅限验证在册端点签发的凭证/流程）
- 破坏性/不可逆操作：删数据、关服务、DoS、压测式爆破
"""

SHIM_TEMPLATE = """# 持久授权与运行约定（IDE shim · 由 Atoolkit installer 生成）

> 本文件是薄指针，授权细节只维护一份——AUTHZ.md。修改授权请改 AUTHZ.md，不要改本文件。

- 测试纪律与报告标准：遵循同目录 AGENTS.md（Atoolkit 指挥官文件）。
- 授权范围：以同目录 AUTHZ.md 的「授权 Scope / 派生资产」为准；scope 内动作
  均已预授权，无需逐条确认；越界或破坏性操作立即停手并标记 NEED_INPUT。
- 运行模式：本环境禁止 `python3 run.py`（Engine Mode 会拉起外部 codex/gpt 后端）；
  只走 Direct 模式六命令：preflight / init / observe / checkpoint / scope / report
  （`python3 -m engine.skill_runtime <cmd> --run-dir <run>`）。
"""


def create_exclusive(name: str, content: str) -> str:
    path = os.path.join(workspace, name)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return f"kept existing {name}"
    except OSError as exc:
        return f"skipped {name}: {exc}"
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    return f"generated {name}"


print(create_exclusive("AUTHZ.md", AUTHZ_TEMPLATE))
print(create_exclusive("AGENTS.local.md", SHIM_TEMPLATE))
PY
