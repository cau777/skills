---
name: orca-ssh-setup
description: Provision a Multipass VM as an SSH run target for the current project (with coding-agent harnesses wired to the host-side model proxy) and connect it to Orca (onorca.dev) as an SSH-type project.
---

# Orca SSH Project Setup

Use this procedure when the user wants to run their current repo's Orca agents
on a dedicated local VM instead of their laptop, connected via SSH (Orca's
"SSH target" run mode — see https://www.onorca.dev/docs/ways-to-run, mode #2).

Scope note: this is **one long-lived VM per project**, reused across
worktrees/branches.

The end state: a running Multipass VM, reachable over SSH with key-based auth,
with the project's toolchain **and** the requested coding-agent harness(es)
installed and wired to a credential-free host proxy, and the user knows
exactly what to click/type in Orca to register it and start a worktree on it.

Work through the steps below in order. Do not skip step 2 — guessing at VM
sizing, base image, harness choice, or naming instead of confirming with the
user is the most common way this goes wrong.

## 1. Inspect the current repo to determine required technologies

From the repo root, gather enough signal to know what the VM needs installed.
Look for (not exhaustive — adapt to what you find):

- **Language/runtime version pins**: `.python-version`, `.nvmrc`,
  `.node-version`, `.ruby-version`, `.tool-versions` (asdf), `go.mod`
  (`go` directive), `rust-toolchain.toml`, `.java-version`.
- **Package managers / lockfiles**: `package-lock.json` / `pnpm-lock.yaml` /
  `yarn.lock` (npm/pnpm/yarn), `requirements.txt` / `pyproject.toml` /
  `poetry.lock` / `uv.lock` (pip/poetry/uv), `Gemfile.lock` (bundler),
  `Cargo.lock` (cargo), `go.sum` (go modules).
- **Containers/services the project depends on**: `docker-compose.yml`,
  `Dockerfile`, references to Postgres/Redis/etc. in env files or config.
- **Build/CI config** for the canonical install & test commands:
  `.github/workflows/*.yml`, `Makefile`, `justfile`, `package.json` scripts.
- **System-level deps**: anything imported/required that needs native
  libraries (e.g. `psycopg2`, `sharp`, `pillow`, CUDA-dependent packages).
- **Repo size / disk needs**: rough size of the working tree plus any large
  data/model directories the agent will need locally.

Summarize findings in a short list (language(s), versions, package manager,
services, anything unusual) before moving to step 2.

## 2. Clarify open questions with the user

Do not assume. Confirm at minimum:

- **Project/VM name** — propose one derived from the repo directory name
  (kebab-case, e.g. `orca-<reponame>`), but let the user override it.
- **VM resources** — default proposal: 4 CPUs, 8GB RAM, 40GB disk. Ask if the
  workload (large builds, ML training, big monorepo) needs more.
- **Base Ubuntu image** — default to the latest Multipass LTS image (check
  `multipass find` for the current default, e.g. `24.04`) unless the repo
  needs a specific OS version.
- **Which coding-agent harness(es) to install** — Codex CLI (`@openai/codex`),
  Claude Code (`@anthropic-ai/claude-code`), both, or neither. This decides
  what step 4 installs and whether steps 3/6 (proxy) run at all. Default to
  asking rather than assuming both, since the host-side proxy setup in step 3
  needs an explicit `-codex-login` / `-claude-login` per harness the user
  actually wants credentialed.
- **Credentials/secrets** the agent will need inside the VM (API keys, cloud
  creds, private registry auth, `.env` values) — ask how the user wants these
  provisioned (manually after setup, via a secrets file they'll copy in, etc).
  Do not ask the user to paste secrets into chat; ask *how* they want to
  deliver them.
- **Networking specifics** — anything the VM needs to reach (VPN, internal
  services) that isn't reachable by default from a Multipass VM.

Only proceed to provisioning once these are settled.

## 3. Set up the host-side model proxy (if any harness was requested)

Skip this step entirely if the user chose no harness in step 2.

Coding-agent credentials must **not** be baked into the VM — a live provider
session sitting on a machine that an agent runs with full sudo on is a bad
combination, and it means every rebuild/recreate of the VM costs another
interactive login. Instead, run a small host-side broker
([CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)) that holds the
real credentials and exposes a local, key-gated API. It runs once per
*machine* (share it across every project VM, not per project), bound to the
Multipass bridge interface (`mpqemubr0`) so any Multipass VM on this host can
reach it, and nothing outside the host can.

**3a. Check for an existing broker first** — it may already be set up from a
previous project:

```bash
systemctl --user status cli-proxy-api.service
```

If active, read its config (`~/.cli-proxy-api/config.yaml`) and skip straight
to 3d — do not reinstall or overwrite it.

**3b. Install it, pinned to an explicit version** (never track "latest" —
this holds a live provider session on disk, so an unattended upgrade is a
supply-chain event, not a convenience):

```bash
# Resolve and pin the current release once; record the version you land on.
VERSION=$(curl -fsS https://api.github.com/repos/router-for-me/CLIProxyAPI/releases/latest \
  | grep -m1 '"tag_name"' | sed -E 's/.*"v?([^"]+)".*/\1/')

ARCH=$(case "$(uname -m)" in x86_64) echo amd64;; aarch64|arm64) echo aarch64;; esac)
TARBALL="CLIProxyAPI_${VERSION}_linux_${ARCH}.tar.gz"
BASE="https://github.com/router-for-me/CLIProxyAPI/releases/download/v${VERSION}"
INSTALL_DIR="$HOME/.local/share/cli-proxy-api/cli-proxy-api-${VERSION}"

TMP=$(mktemp -d)
curl -fsSL "${BASE}/${TARBALL}" -o "${TMP}/${TARBALL}"
curl -fsSL "${BASE}/checksums.txt" -o "${TMP}/checksums.txt"
# Verify before extracting — refuse to proceed on a mismatch.
( cd "$TMP" && grep " ${TARBALL}\$" checksums.txt | sha256sum -c - )
mkdir -p "$INSTALL_DIR"
tar -xzf "${TMP}/${TARBALL}" -C "$INSTALL_DIR"
rm -rf "$TMP"
BINARY="${INSTALL_DIR}/cli-proxy-api"
```

**3c. Write the config**, only if `~/.cli-proxy-api/config.yaml` doesn't
already exist (never clobber one — it may already gate VMs from other
projects and hold their working credentials):

```bash
CFG_DIR="$HOME/.cli-proxy-api"
CFG="$CFG_DIR/config.yaml"
mkdir -p "$CFG_DIR"

if [ ! -f "$CFG" ]; then
  BIND_ADDR=$(ip -4 -o addr show mpqemubr0 2>/dev/null | grep -oP 'inet \K[\d.]+')
  if [ -z "$BIND_ADDR" ]; then
    BIND_ADDR="127.0.0.1"
    echo "!! mpqemubr0 not found (start Multipass first) — bound 127.0.0.1; VMs won't reach it yet." >&2
    echo "!! Once Multipass is running, update 'host:' in $CFG to the bridge IP and restart the service." >&2
  fi
  KEY=$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 32)

  cat > "$CFG" <<YAML
# CLIProxyAPI — host-side credential broker for VM-based coding-agent harnesses.
# Bound to the multipass bridge so per-project VMs can reach it and nothing
# else can; loopback and external interfaces are deliberately not served.
host: "${BIND_ADDR}"
port: 8317
auth-dir: "${CFG_DIR}"

# Clients (the harness CLIs inside each VM) must present this as a bearer
# token. It is not a provider credential — the real subscription tokens live
# in the auth-dir files and never leave this host.
api-keys:
  - "${KEY}"

debug: false

remote-management:
  allow-remote: false
  secret-key: ""
YAML
  chmod 600 "$CFG"
fi
```

**3d. Install and start it as a systemd *user* service**, so it survives
reboots without a login session (`enable-linger`) and restarts itself once
the bridge interface exists (`Restart=always` — the service may start before
Multipass has brought `mpqemubr0` up):

```bash
UNIT="$HOME/.config/systemd/user/cli-proxy-api.service"
mkdir -p "$(dirname "$UNIT")"
cat > "$UNIT" <<UNIT
[Unit]
Description=CLIProxyAPI (coding-agent credential broker)
After=network-online.target

[Service]
ExecStart=${BINARY} -config ${CFG}
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
UNIT

systemctl --user daemon-reload
systemctl --user enable --now cli-proxy-api.service
loginctl enable-linger "$USER" || echo "!! run manually: sudo loginctl enable-linger $USER" >&2

sleep 2
systemctl --user is-active --quiet cli-proxy-api.service || {
  systemctl --user status cli-proxy-api.service --no-pager --lines=20
  echo "broker failed to start — resolve before continuing" >&2
  exit 1
}
```

**3e. Do not log the harness(es) into the broker yourself.** Authentication
is an interactive OAuth/device flow that needs the user's own browser
session — hand them the exact command instead, one per harness they actually
requested in step 2 (skip the other):

```
~/.local/share/cli-proxy-api/cli-proxy-api-<version>/cli-proxy-api \
  -config ~/.cli-proxy-api/config.yaml -codex-login
~/.local/share/cli-proxy-api/cli-proxy-api-<version>/cli-proxy-api \
  -config ~/.cli-proxy-api/config.yaml -claude-login
```

Tell the user this only needs to happen **once per machine, ever** (not per
project, not per rebuild) — if the broker was already running from a
previous project's setup, it may already be logged in for the harness(es)
you need, so check `~/.cli-proxy-api/` for existing credential files before
asking the user to log in again. Credentials are picked up live — no restart
needed after login.

Read back `~/.cli-proxy-api/config.yaml` before moving on — it's the single
source of truth step 6 reads from (`host:`, `port:`, and the first entry
under `api-keys:`).

## 4. Create a properly named Multipass VM

Check Multipass is installed first (`multipass version`); if not, stop and
tell the user to install it (https://multipass.run) before continuing.

Launch the VM with the confirmed name and sizing:

```bash
multipass launch <image> \
  --name <vm-name> \
  --cpus <n> \
  --memory <n>G \
  --disk <n>G
```

**Required, unconditionally, before Orca ever connects:** install a C/C++
build toolchain. This has nothing to do with the target repo's own language —
Orca's SSH relay compiles `node-pty` (a native Node addon) on the remote host
the first time it connects, to power remote terminals. Skip this and the
first connection in Orca fails with:

```
Remote terminals are unavailable: node-pty's native binding is not loadable
on this host. If it is missing the C/C++ build tools needed to compile
node-pty, install make, a C++ compiler, and python3 on the remote host, then
reconnect. ...
```

Install it now so day-one connections work:

```bash
multipass exec <vm-name> -- sudo apt-get update -qq
multipass exec <vm-name> -- sudo apt-get install -y -qq build-essential python3
```

(`build-essential` pulls in `make` and `g++`; `python3` is the one
`node-gyp` dependency it doesn't already include.)

If the user already added the host in Orca and hit this error *before* these
were installed: installing them now is not enough by itself — Orca cached the
failed build attempt. Have the user reconnect the SSH host in Orca (remove
and re-add it under **Settings → SSH**, or use its "reconnect" action if one
is shown) so it retries the `node-pty` build against the now-present
toolchain; no VM or sshd restart is needed.

Then mount or clone the repo into the VM. Prefer cloning fresh inside the VM
over a live host mount, since Orca agents will run natively inside the VM and
a real git checkout avoids filesystem-passthrough edge cases:

```bash
multipass exec <vm-name> -- git clone <repo-url> ~/<reponame>
```

If the repo isn't pushed anywhere the VM can reach, use
`multipass mount <host-path> <vm-name>:<vm-path>` instead and note this as a
deviation to the user.

Install the toolchain identified in step 1 inside the VM (language runtime at
the pinned version, package manager, system libs), then install project
dependencies (`npm ci`, `pip install -r requirements.txt`, etc.) and confirm
the project's normal build/test command succeeds.

If any harness was requested in step 2, also install it now — both CLIs are
npm-distributed and need Node.js **22.x specifically** (`@anthropic-ai/claude-code`
requires node >=22; npm only warns, not fails, on an older node, so this must
be right at install time rather than caught later):

```bash
multipass exec <vm-name> -- bash -c '
  curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash - &&
  sudo apt-get install -y -qq nodejs
'
# then, per harness requested:
multipass exec <vm-name> -- sudo npm install -g @openai/codex
multipass exec <vm-name> -- sudo npm install -g @anthropic-ai/claude-code
```

Optionally drop a short note into each installed harness's global instructions
file (`~/.codex/AGENTS.md` for codex, `~/.claude/CLAUDE.md` for claude-code —
never the target repo's own `AGENTS.md`/`CLAUDE.md`) that it's running in a
disposable-feeling but actually persistent Multipass VM with full sudo, so the
agent doesn't over-hedge on system changes.

## 5. Set up SSH access

Multipass VMs run SSH by default but Orca needs a real, host-reachable
SSH endpoint with key-based auth (not `multipass shell`/`multipass exec`,
which tunnel through the Multipass daemon instead of plain SSH).

1. Get the VM's IP:
   ```bash
   multipass info <vm-name> | grep IPv4
   ```
2. Ensure the user has an SSH keypair (`~/.ssh/id_ed25519` or similar); if
   not, generate one (`ssh-keygen -t ed25519`).
3. Authorize that public key inside the VM:
   ```bash
   multipass exec <vm-name> -- bash -c \
     'mkdir -p ~/.ssh && echo "<contents of id_ed25519.pub>" >> ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys'
   ```
4. Verify from the host:
   ```bash
   ssh -i ~/.ssh/id_ed25519 ubuntu@<vm-ip> echo ok
   ```
   (default Multipass user is `ubuntu` unless the user customized it).
5. Note that the VM's IP can change across host reboots unless the user has
   set a static IP/DHCP reservation — flag this to the user, since a changed
   IP will break both the Orca SSH target and the proxy wiring below until
   updated.

Do not proceed to step 6 until the `ssh ... echo ok` check above succeeds.

## 6. Wire the installed harness(es) to the host proxy

Skip this step if no harness was requested in step 2.

Read the broker's own config as the source of truth — never hardcode the host
IP or key, since they're generated per-machine by `setup-proxy`:

```bash
CFG=~/.cli-proxy-api/config.yaml
PROXY_HOST=$(grep '^host:' "$CFG" | sed -E 's/host: *"([^"]*)"/\1/')
PROXY_PORT=$(grep '^port:' "$CFG" | sed -E 's/port: *//')
PROXY_KEY=$(awk '/^api-keys:/{getline; gsub(/.*"|".*/, ""); print; exit}' "$CFG")
PROXY_BASE_URL="http://${PROXY_HOST}:${PROXY_PORT}/v1"
```

For **codex**, write a credential-free `config.toml` pointing at the broker,
plus the key as an env var (both `/etc/environment` and `/etc/profile.d`, so
it's visible from an interactive shell, `ssh host <cmd>`, and `ssh host bash -s`
alike):

```bash
multipass exec <vm-name> -- bash -c "
  mkdir -p ~/.codex
  cat > ~/.codex/config.toml <<'TOML'
model = \"gpt-5.6-terra\"
model_provider = \"hostproxy\"

[model_providers.hostproxy]
name = \"hostproxy\"
base_url = \"${PROXY_BASE_URL}\"
wire_api = \"responses\"
env_key = \"HOSTPROXY_KEY\"
TOML
  sudo sed -i '/^HOSTPROXY_KEY=/d' /etc/environment
  printf 'HOSTPROXY_KEY=%s\n' '${PROXY_KEY}' | sudo tee -a /etc/environment >/dev/null
  printf 'export HOSTPROXY_KEY=%s\n' '${PROXY_KEY}' | sudo tee /etc/profile.d/orca-hostproxy-codex.sh >/dev/null
"
```

For **claude-code**, no config file — just the two env vars (note: **no
trailing `/v1`** here, the client appends `/v1/messages` itself, unlike
codex's `base_url` above which needs it):

```bash
multipass exec <vm-name> -- bash -c "
  ANTHROPIC_PROXY_BASE_URL='${PROXY_BASE_URL%/v1}'
  sudo sed -i '/^ANTHROPIC_BASE_URL=/d;/^ANTHROPIC_AUTH_TOKEN=/d' /etc/environment
  printf 'ANTHROPIC_BASE_URL=%s\nANTHROPIC_AUTH_TOKEN=%s\n' \"\$ANTHROPIC_PROXY_BASE_URL\" '${PROXY_KEY}' | sudo tee -a /etc/environment >/dev/null
  printf 'export ANTHROPIC_BASE_URL=%s\nexport ANTHROPIC_AUTH_TOKEN=%s\n' \"\$ANTHROPIC_PROXY_BASE_URL\" '${PROXY_KEY}' | sudo tee /etc/profile.d/orca-hostproxy-claude.sh >/dev/null
"
```

Then verify the whole chain with one unauthenticated-cost call (spends no
tokens, just proves the VM can reach the broker and the key is accepted) —
fail loudly here rather than let the user discover a bare connection error on
the harness's first real turn:

```bash
multipass exec <vm-name> -- curl -fsS -m 10 -H "Authorization: Bearer ${PROXY_KEY}" "${PROXY_BASE_URL}/models"
```

If this fails, check the broker on the host first
(`systemctl --user status cli-proxy-api.service`) before assuming the VM side
is wrong — a down broker fails every enabled harness identically.

## 7. Tell the user exactly how to add this as an Orca SSH project

Give the user these concrete, copy-pasteable steps (fill in the real values
you just set up):

1. Open Orca → **Settings → SSH**.
2. Add a new host with:
   - **Host/IP**: `<vm-ip>`
   - **User**: `ubuntu` (or the confirmed user)
   - **Identity file**: `~/.ssh/id_ed25519` (or whichever key was authorized)
   - **Name**: `<vm-name>` (so it's recognizable in the "Run on" picker)
3. Verify the connection in Orca's SSH settings (it should confirm git is
   available on the host).
4. Create a new worktree for the repo, and under **Run on**, select
   `<vm-name>` instead of Local.
5. Confirm the project directory Orca finds on the remote matches
   `~/<reponame>` (or wherever the repo was cloned in step 4).
6. If a harness was installed, tell the user which one(s) are ready to use
   with no further login step (`codex`, `claude`) — the proxy already
   authenticated them.

Remind the user that agents and `git worktree` will now execute on the VM,
while Orca's editor/diff/UI stay local; that stopping/deleting the Multipass
VM (`multipass stop|delete <vm-name>`) will break the SSH target until it's
recreated; and — if a harness was wired up — that the host-side proxy
(`cli-proxy-api.service`) is now a **shared, hard dependency** for every
project using it, not just this one: if it's down, every harness on every
such VM fails with a connection error, not an auth error.
