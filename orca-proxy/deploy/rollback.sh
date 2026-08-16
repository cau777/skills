#!/usr/bin/env bash
set -euo pipefail

# Roll back a bad orca-proxy upgrade (design ticket #12's Q4): repoint
# ~/.orca-proxy/current at a previously-installed version and restart —
# no reinstall needed, since install.sh never deletes prior versioned
# installs under ~/.local/share/orca-proxy/.
#
# Usage: rollback.sh <version>   (e.g. the short git hash from a prior
# `install.sh` run — list available versions with `ls ~/.local/share/orca-proxy/`)

VERSION="${1:?usage: rollback.sh <version>}"
TARGET="$HOME/.local/share/orca-proxy/$VERSION"
CURRENT_LINK="$HOME/.orca-proxy/current"

if [ ! -d "$TARGET" ]; then
  echo "!! $TARGET does not exist — available versions:" >&2
  ls "$HOME/.local/share/orca-proxy/" >&2
  exit 1
fi

ln -sfn "$TARGET" "$CURRENT_LINK"
systemctl --user restart orca-proxy.service
sleep 2
systemctl --user is-active --quiet orca-proxy.service || {
  systemctl --user status orca-proxy.service --no-pager --lines=20
  echo "orca-proxy failed to restart after rollback — resolve before continuing" >&2
  exit 1
}
echo "Rolled back: current -> $TARGET"
