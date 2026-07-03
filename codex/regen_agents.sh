#!/usr/bin/env bash
# 从 skill/核心技能文件.v3.md 重新生成 codex/AGENTS.md。
# 单一真相 = v3；改了 v3 跑一次本脚本，AGENTS.md 自动同步，避免两份漂移。
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$DIR")"
SRC="$ROOT/skill/核心技能文件.v3.md"
[ -f "$SRC" ] || { echo "找不到 $SRC"; exit 1; }
{ cat "$DIR/_agents_header.md"; tail -n +2 "$SRC"; } > "$DIR/AGENTS.md"
echo "✅ 已从 v3 重生成 $DIR/AGENTS.md（$(wc -l < "$DIR/AGENTS.md" | tr -d ' ') 行）"
echo "   部署：cp \"$DIR/AGENTS.md\" ~/.codex/AGENTS.md   或   项目根/AGENTS.md"
