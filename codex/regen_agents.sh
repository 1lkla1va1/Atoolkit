#!/usr/bin/env bash
# 从 skill/核心技能文件.v3.md 重新生成项目根 AGENTS.md 与 codex/AGENTS.md。
# 单一真相 = v3；项目根副本可被 Codex 对 runs/ 子目录自动加载，
# codex/AGENTS.md 仅作安装兼容副本。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$DIR")"
SRC="$ROOT/skill/核心技能文件.v3.md"
[ -f "$SRC" ] || { echo "找不到 $SRC"; exit 1; }

render() {
  { cat "$DIR/_agents_header.md"; tail -n +2 "$SRC"; }
}

if [ "${1:-}" = "--check" ]; then
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  render > "$tmp"
  for dst in "$ROOT/AGENTS.md" "$DIR/AGENTS.md"; do
    [ -f "$dst" ] || { echo "❌ 缺少 $dst"; exit 1; }
    cmp -s "$tmp" "$dst" || { echo "❌ $dst 与核心文件漂移"; exit 1; }
  done
  echo "✅ root/codex AGENTS.md 与 v3 核心文件一致"
  exit 0
fi

render > "$ROOT/AGENTS.md"
cp "$ROOT/AGENTS.md" "$DIR/AGENTS.md"
echo "✅ 已从 v3 重生成 $ROOT/AGENTS.md 与 $DIR/AGENTS.md（$(wc -l < "$ROOT/AGENTS.md" | tr -d ' ') 行）"
echo "   全局部署必须由用户显式执行；本脚本不覆盖 ~/.codex 或外部 /src。"
