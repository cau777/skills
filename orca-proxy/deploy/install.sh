#!/usr/bin/env bash
set -euo pipefail

# orca-proxy first-time install / upgrade (design ticket #12).
#
# Must run as root:
#   sudo bash deploy/install.sh                     (from an existing checkout)
#   curl -fsSL https://raw.githubusercontent.com/cau777/jetty-vm/main/orca-proxy/deploy/install.sh | sudo bash
#
# Why root now, when the old install.sh ran as the target user and only
# sudo'd two small steps: the firewall-sync helper's sudoers NOPASSWD entry
# is only safe if nothing in the path it executes is writable by the user
# that entry names. The old layout resolved through
# ~/.orca-proxy/current/venv/bin/... — fully writable by that same user,
# so overwriting it and running `sudo` was a trivial root escalation. The
# fix installs a standalone copy of the helper to a root-owned location
# outside the user's home directory entirely, which this script can only do
# as root. Upgrading is accordingly now a deliberate "run this again as
# root" action rather than something a passwordless-sudo step does for you
# — see design.md's "Service installation and firewall-rule lifecycle"
# section.
#
# Everything *unprivileged* (the venv, the systemd --user unit, the data
# directory) is still built and owned by the target user, not root — this
# script only elevates for the two things that actually need it: writing
# the sudoers file, and installing the root-owned firewall-sync copy.

ORCA_PROXY_GIT_URL="${ORCA_PROXY_GIT_URL:-https://github.com/cau777/jetty-vm.git}"

if [ "$(id -u)" -ne 0 ]; then
  cat >&2 <<'MSG'
!! orca-proxy's installer must run as root:
     sudo bash deploy/install.sh
   or, with no local checkout:
     curl -fsSL https://raw.githubusercontent.com/cau777/jetty-vm/main/orca-proxy/deploy/install.sh | sudo bash
MSG
  exit 1
fi

# --- who is this actually for? ---
# `sudo bash install.sh` sets SUDO_USER to the invoking (non-root) account;
# `curl ... | sudo bash` does too, since sudo itself sets it regardless of
# how bash's stdin is fed. ORCA_PROXY_USER overrides for anything that
# doesn't go through sudo (e.g. already running as root some other way).
TARGET_USER="${ORCA_PROXY_USER:-${SUDO_USER:-}}"
if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
  echo "!! could not determine a non-root target user -- run via 'sudo', or set ORCA_PROXY_USER=<name>" >&2
  exit 1
fi
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
if [ -z "$TARGET_HOME" ] || [ ! -d "$TARGET_HOME" ]; then
  echo "!! $TARGET_USER has no home directory" >&2
  exit 1
fi
TARGET_UID="$(id -u "$TARGET_USER")"

as_user() {
  # Login shell so PATH/profile-sourced tooling (uv, etc.) resolves the same
  # way it would if $TARGET_USER ran this themselves; XDG_RUNTIME_DIR is
  # forced so `systemctl --user` reaches the right session bus even when
  # invoked from a root shell rather than a real login of that user.
  sudo -u "$TARGET_USER" -H env XDG_RUNTIME_DIR="/run/user/$TARGET_UID" bash -lc "$1"
}

CLEANUP_DIR=""
cleanup() { [ -n "$CLEANUP_DIR" ] && rm -rf "$CLEANUP_DIR"; }
trap cleanup EXIT

# --- get the source ---
if [ -n "${ORCA_PROXY_REPO:-}" ]; then
  REPO_DIR="$ORCA_PROXY_REPO"
elif [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ] \
     && [ -f "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/pyproject.toml" ]; then
  # Invoked as a real file (`sudo bash deploy/install.sh`, not piped) from
  # inside an actual checkout.
  REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
else
  # Piped (`curl ... | sudo bash`) -- BASH_SOURCE isn't a real file in that
  # mode, so there's no checkout to derive a path from. Fetch a fresh
  # sparse checkout of just orca-proxy/ instead.
  echo "No local checkout detected -- fetching orca-proxy from $ORCA_PROXY_GIT_URL"
  CLEANUP_DIR="$(mktemp -d)"
  git clone --quiet --depth 1 --filter=blob:none --sparse "$ORCA_PROXY_GIT_URL" "$CLEANUP_DIR/skills"
  git -C "$CLEANUP_DIR/skills" sparse-checkout set orca-proxy
  REPO_DIR="$CLEANUP_DIR/skills/orca-proxy"
fi

VERSION="${ORCA_PROXY_VERSION:-$(cd "$REPO_DIR" && git rev-parse --short HEAD 2>/dev/null || date +%Y%m%d%H%M%S)}"
INSTALL_DIR="$TARGET_HOME/.local/share/orca-proxy/$VERSION"
DATA_DIR="$TARGET_HOME/.orca-proxy"
CURRENT_LINK="$DATA_DIR/current"
UNIT_DIR="$TARGET_HOME/.config/systemd/user"
UNIT_PATH="$UNIT_DIR/orca-proxy.service"

if [ -e "$INSTALL_DIR" ]; then
  echo "!! $INSTALL_DIR already exists -- refusing to overwrite an existing versioned install" >&2
  exit 1
fi

echo "Installing orca-proxy $VERSION to $INSTALL_DIR (for $TARGET_USER)"
install -d -o "$TARGET_USER" -g "$TARGET_USER" "$INSTALL_DIR" "$DATA_DIR" "$UNIT_DIR"

# Copy the source tree rather than symlinking it — a versioned install must
# stay immutable even if the working checkout later moves to a new commit.
cp -r "$REPO_DIR"/. "$INSTALL_DIR/source"
chown -R "$TARGET_USER:$TARGET_USER" "$INSTALL_DIR"
as_user "cd $(printf '%q' "$INSTALL_DIR/source") && uv sync --no-dev"
# Created by the target user directly (they already own $INSTALL_DIR, as of
# the chown -R above) rather than root creating it then handing ownership
# over via a separate chown -h -- simpler, and sidesteps root creating a
# symlink cau777 doesn't end up owning.
as_user "ln -sfn $(printf '%q' "$INSTALL_DIR/source/.venv") $(printf '%q' "$INSTALL_DIR/venv")"

# Stable, version-independent path for the systemd unit's `-s` argument —
# proxy_addon.py's real location inside site-packages varies by Python
# version, so it's copied to one fixed spot per versioned install instead.
cp "$INSTALL_DIR/source/src/orca_proxy/proxy_addon.py" "$INSTALL_DIR/proxy_addon.py"
chown "$TARGET_USER:$TARGET_USER" "$INSTALL_DIR/proxy_addon.py"

echo "Writing systemd user unit"
install -o "$TARGET_USER" -g "$TARGET_USER" -m 0644 "$REPO_DIR/deploy/orca-proxy.service" "$UNIT_PATH"

echo "Installing the privileged firewall-sync helper (root-owned, outside $TARGET_USER's home)"
# A single, dependency-free, stdlib-only file (see its own module
# docstring) -- copied verbatim, not built/bundled from anything, and run
# against the system python3, never the target user's venv. That's the
# point: nothing the sudoers rule executes is writable by the user it
# grants NOPASSWD root to, and there's exactly one file to audit.
FIREWALL_BIN="/usr/local/sbin/orca-proxy-firewall-sync"
install -o root -g root -m 0755 "$REPO_DIR/deploy/orca-proxy-firewall-sync" "$FIREWALL_BIN"

echo "Configuring sudoers for the firewall-sync helper"
ORCA_PROXY_BRIDGE_VALUE="${ORCA_PROXY_BRIDGE:-mpqemubr0}"
ORCA_PROXY_PORT_VALUE="${ORCA_PROXY_PORT:-8443}"
DB_PATH="$DATA_DIR/state.sqlite"
SUDOERS_PATH="/etc/sudoers.d/orca-proxy-firewall-sync"
SUDOERS_CONTENT="$(sed \
  -e "s|__USER__|$TARGET_USER|g" \
  -e "s|__FIREWALL_BIN__|$FIREWALL_BIN|g" \
  -e "s|__DB_PATH__|$DB_PATH|g" \
  -e "s|__BRIDGE__|$ORCA_PROXY_BRIDGE_VALUE|g" \
  -e "s|__PROXY_PORT__|$ORCA_PROXY_PORT_VALUE|g" \
  "$REPO_DIR/deploy/orca-proxy-firewall-sync.sudoers.template")"
echo "$SUDOERS_CONTENT" > "$SUDOERS_PATH"
chmod 0440 "$SUDOERS_PATH"
visudo -c -f "$SUDOERS_PATH"

# Atomic repoint — the only step that changes what "current" (and therefore
# the systemd unit) actually points at. No longer sudoers-relevant: the
# firewall-sync helper lives outside this symlink chain entirely now.
# Created by the target user directly (they already own $DATA_DIR) for the
# same reason as the venv symlink above.
as_user "ln -sfn $(printf '%q' "$INSTALL_DIR") $(printf '%q' "$CURRENT_LINK")"

echo "Starting orca-proxy.service"
loginctl enable-linger "$TARGET_USER"
systemctl start "user@$TARGET_UID.service" 2>/dev/null || true
# `enable --now` is a no-op on an already-running unit -- it does NOT
# restart it. On an upgrade that silently leaves the OLD process running
# (old code, old config.firewall_sync_script_path() resolution, etc.)
# despite `current` having been correctly repointed -- the exact failure
# mode that motivated pinning the sudoers args in the first place stays
# invisible until something finally triggers a real reconcile call, which
# then 403s against the freshly-written sudoers file. `restart`
# unconditionally guarantees the new version is actually what's running.
as_user "systemctl --user daemon-reload && systemctl --user enable orca-proxy.service && systemctl --user restart orca-proxy.service"

sleep 2
as_user "systemctl --user is-active --quiet orca-proxy.service" || {
  as_user "systemctl --user status orca-proxy.service --no-pager --lines=20" || true
  echo "orca-proxy failed to start -- resolve before continuing" >&2
  exit 1
}

echo "orca-proxy $VERSION installed and running (current -> $INSTALL_DIR)"
echo "Privileged firewall-sync helper: $FIREWALL_BIN (root-owned, sudoers-gated for $TARGET_USER)"
