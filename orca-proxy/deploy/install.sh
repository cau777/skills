#!/usr/bin/env bash
set -euo pipefail

# orca-proxy first-time install / upgrade (design ticket #12).
#
# Blue-green: builds a fresh versioned install under
# ~/.local/share/orca-proxy/<version>/, then atomically repoints
# ~/.orca-proxy/current at it. Never overwrites an existing versioned
# install in place — a bad upgrade rolls back by repointing `current` back
# to the previous version and restarting the service, no reinstall needed.
#
# Run by the Provisioning Agent (orca-ssh-setup) per design ticket #14's Q7:
# checked first (systemctl --user status orca-proxy.service), only run if
# absent; the two sudo-requiring steps (sudoers file, iptables chain setup
# via the firewall-sync script) are attempted automatically and fall back to
# asking the user to run them if the session can't get a sudo prompt — the
# same line the current orca-ssh-setup skill already draws for
# `apt-get install mitmproxy`, not a stricter bar for this app.

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(cd "$REPO_DIR" && git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S)"
INSTALL_DIR="$HOME/.local/share/orca-proxy/$VERSION"
DATA_DIR="$HOME/.orca-proxy"
CURRENT_LINK="$DATA_DIR/current"
UNIT_DIR="$HOME/.config/systemd/user"
UNIT_PATH="$UNIT_DIR/orca-proxy.service"

if [ -e "$INSTALL_DIR" ]; then
  echo "!! $INSTALL_DIR already exists — refusing to overwrite an existing versioned install" >&2
  exit 1
fi

echo "Installing orca-proxy $VERSION to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$UNIT_DIR"

# Copy the source tree rather than symlinking it — a versioned install must
# stay immutable even if the working checkout later moves to a new commit.
cp -r "$REPO_DIR"/. "$INSTALL_DIR/source"
( cd "$INSTALL_DIR/source" && uv sync --no-dev )
ln -sfn "$INSTALL_DIR/source/.venv" "$INSTALL_DIR/venv"

# Stable, version-independent path for the systemd unit's `-s` argument —
# proxy_addon.py's real location inside site-packages varies by Python
# version, so it's copied to one fixed spot per versioned install instead.
cp "$INSTALL_DIR/source/src/orca_proxy/proxy_addon.py" "$INSTALL_DIR/proxy_addon.py"

echo "Writing systemd user unit"
cp "$REPO_DIR/deploy/orca-proxy.service" "$UNIT_PATH"

echo "Configuring sudoers for the firewall-sync helper"
SUDOERS_PATH="/etc/sudoers.d/orca-proxy-firewall-sync"
SUDOERS_CONTENT="$(sed "s/__USER__/$USER/g" "$REPO_DIR/deploy/orca-proxy-firewall-sync.sudoers.template")"
if command -v sudo >/dev/null && sudo -n true 2>/dev/null; then
  echo "$SUDOERS_CONTENT" | sudo -n tee "$SUDOERS_PATH" >/dev/null
  sudo -n chmod 0440 "$SUDOERS_PATH"
  sudo -n visudo -c -f "$SUDOERS_PATH"
else
  echo "!! Could not get a passwordless sudo prompt — run this yourself:" >&2
  echo "     echo '$SUDOERS_CONTENT' | sudo tee $SUDOERS_PATH && sudo chmod 0440 $SUDOERS_PATH" >&2
fi

# Atomic repoint — the only step that changes what "current" (and therefore
# the systemd unit and sudoers entry) actually points at.
ln -sfn "$INSTALL_DIR" "$CURRENT_LINK"

echo "Starting orca-proxy.service"
systemctl --user daemon-reload
systemctl --user enable --now orca-proxy.service
loginctl enable-linger "$USER" || echo "!! run manually: sudo loginctl enable-linger $USER" >&2

sleep 2
systemctl --user is-active --quiet orca-proxy.service || {
  systemctl --user status orca-proxy.service --no-pager --lines=20
  echo "orca-proxy failed to start — resolve before continuing" >&2
  exit 1
}

echo "orca-proxy $VERSION installed and running (current -> $INSTALL_DIR)"
