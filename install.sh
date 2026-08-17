#!/usr/bin/env bash
# Installs Jetty's agent skills into the local Claude and Codex skills
# directories. It works from a checkout or when downloaded and piped to bash.
set -euo pipefail

REPO_URL="${JETTY_REPO_URL:-https://github.com/cau777/jetty-vm.git}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$SCRIPT_DIR"
TEMP_REPO_DIR=""

cleanup() {
  if [ -n "$TEMP_REPO_DIR" ]; then
    rm -rf "$TEMP_REPO_DIR"
  fi
}
trap cleanup EXIT

# A script received over stdin lives in a temporary directory, not a Jetty
# checkout. Fetch the repository so the skill directories are available.
if ! compgen -G "$REPO_DIR"'/*/SKILL.md' > /dev/null; then
  command -v git > /dev/null || {
    echo "git is required to install Jetty from the standalone script." >&2
    exit 1
  }
  TEMP_REPO_DIR="$(mktemp -d "${TMPDIR:-/tmp}/jetty-vm.XXXXXX")"
  git clone --depth=1 "$REPO_URL" "$TEMP_REPO_DIR"
  REPO_DIR="$TEMP_REPO_DIR"
fi

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
