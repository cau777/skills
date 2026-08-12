#!/usr/bin/env bash
# Copies every skill in this repo (any top-level directory containing a
# SKILL.md) into the local Claude and Codex skills directories.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CLAUDE_SKILLS_DIR="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}"
CODEX_SKILLS_DIR="${CODEX_SKILLS_DIR:-${CODEX_HOME:-$HOME/.codex}/skills}"

mkdir -p "$CLAUDE_SKILLS_DIR" "$CODEX_SKILLS_DIR"

installed=()

for skill_path in "$REPO_DIR"/*/; do
  skill_name="$(basename "$skill_path")"
  [ -f "$skill_path/SKILL.md" ] || continue

  for dest_root in "$CLAUDE_SKILLS_DIR" "$CODEX_SKILLS_DIR"; do
    dest="$dest_root/$skill_name"
    rm -rf "$dest"
    cp -r "$skill_path" "$dest"
  done

  installed+=("$skill_name")
done

if [ "${#installed[@]}" -eq 0 ]; then
  echo "No skills found in $REPO_DIR (expected subdirectories containing SKILL.md)."
  exit 1
fi

echo "Installed ${#installed[@]} skill(s): ${installed[*]}"
echo "  -> $CLAUDE_SKILLS_DIR"
echo "  -> $CODEX_SKILLS_DIR"
