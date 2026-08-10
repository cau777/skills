---
name: orca-ssh-setup
description: Provision a Multipass VM as an SSH run target for the current project (with coding-agent harnesses wired to the host-side model proxy, and git/gh CLI wired to a host-side GitHub credential proxy) and connect it to Orca (onorca.dev) as an SSH-type project.
---

# Orca SSH Project Setup

Use this procedure when the user wants to run their current repo's Orca agents
on a dedicated local VM instead of their laptop, connected via SSH (Orca's
"SSH target" run mode — see https://www.onorca.dev/docs/ways-to-run, mode #2).

Scope note: this is **one long-lived VM per project**, reused across
worktrees/branches.

The end state: a running Multipass VM, reachable over SSH with key-based auth,
with the project's toolchain **and** the requested coding-agent harness(es)
installed and wired to a credential-free host proxy, git/gh CLI wired to a
credential-free host-side GitHub proxy (if requested), and the user knows
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
  what step 5 installs and whether steps 3/7 (proxy) run at all. Default to
  asking rather than assuming both, since the host-side proxy setup in step 3
  needs an explicit `-codex-login` / `-claude-login` per harness the user
  actually wants credentialed.
- **Whether the VM needs GitHub access** (cloning, pushing, opening
  PRs/issues via `git`/`gh`) — and if so, **which repo(s)/org(s)** and
  **which operations** (read-only clone/PR/issue-read, or also push and
  PR/issue-create). This decides whether step 4 (host-side GitHub proxy)
  runs and what its allowlist covers. Never `gh auth login` inside the VM or
  copy a GitHub token into it — see step 4 for why and what to do instead.
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
source of truth step 7 reads from (`host:`, `port:`, and the first entry
under `api-keys:`).

**Known bug in the snippet above** (fixed as of this writing, but re-check if
copying it standalone): the `awk` one-liner
`gsub(/.*"|".*/, "")` used to pull a value out of `- "KEY"` is wrong — POSIX
ERE alternation is leftmost-longest, so the greedy `.*"` branch consumes the
*entire* line (up through the final quote) when the value is the only thing
on it, leaving an empty string. Extract quoted YAML scalars like this
instead:

```bash
awk '/^host:/{getline; print; exit}' "$CFG" | sed -E 's/^[^"]*"([^"]*)".*/\1/'
```

(Adjust the `/^host:/` anchor per key; for `api-keys:` the value is on the
*next* line same as above, so `getline` first still applies.)

## 4. Set up the host-side GitHub credential proxy (if GitHub access was requested)

Skip this step entirely if step 2 established the VM needs no GitHub access.

Do not `gh auth login` inside the VM and do not copy a personal access token
into it — same reasoning as step 3: a live credential sitting on a
sudo-capable box the agent runs on is a bad combination, and a real GitHub
token is broader than any single repo (it typically has `repo`, `workflow`,
`read:org`, etc., scoped to the *account*, not to the one repo the agent is
supposed to touch). Instead, run a small host-side **mitmproxy** instance
that holds the real token (via `gh auth token`, read live off the host's own
`gh` login — never written to disk itself) and injects it *only* into
requests matching an explicit allowlist of `(client_ip, host, method,
path-prefix)` tuples; everything else gets a `403` before it ever reaches
GitHub. The VM's `git`/`gh` send a placeholder credential that only becomes
real once it passes through this proxy.

This runs **once per machine, shared across every project VM** — same as the
model proxy in step 3 — but unlike step 3's broker, its policy is keyed to
*which VM* is asking, not just which repo: `client_ip` in each allowlist
entry pins that permission to one VM's bridge IP. This matters as soon as
there's more than one VM on the host: without it, any VM behind the proxy
could reach any *other* VM's whitelisted repo, since they'd all be sharing
one proxy port. Each VM's entries live in their own commented, append-only
block in the addon script — onboarding a new VM means adding a block, never
editing an existing one.

**Sequencing note:** a VM's block needs its bridge IP, which doesn't exist
until the VM is created. So this step only gets the *shared infrastructure*
running (install mitmproxy, ensure the systemd service is up with whatever
blocks already exist from other projects). Writing *this* VM's block, and
smoke-testing it, happens in step 7 once step 5 has produced an IP.

**4a. Check for an existing instance first:**

```bash
systemctl --user status cli-github-proxy.service
```

If active, this is a shared host — leave `~/.mitm-github-proxy/gh_proxy.py`
alone for now (step 7 appends to it) and skip to 4d to confirm the bridge
IP/port. Do not restart or reconfigure a service that's already gating other
projects' VMs.

**4b. Install mitmproxy** (needs sudo; ask the user to run it themselves if
the session can't prompt for a password — do not silently skip and fall back
to a weaker setup):

```bash
sudo apt-get update -qq && sudo apt-get install -y -qq mitmproxy
```

**4c. If no instance exists yet, write the base addon script** — an empty
`ALLOWED` list plus the shared matching/injection logic. Step 7 appends a
commented block per VM below the `ALLOWED: list[...] = []` line; nothing
else in this file should need to change as VMs come and go:

```bash
mkdir -p ~/.mitm-github-proxy
cat > ~/.mitm-github-proxy/gh_proxy.py <<'PYEOF'
"""
gh_proxy.py — host-side mitmproxy addon for the orca-ssh-setup GitHub proxy.

Shared across every Multipass VM on this host — one proxy instance, one
port, many VMs. Each VM's permissions live in their own commented block
below, scoped to that VM's bridge IP. To onboard a new VM: APPEND a new
"ALLOWED += [...]" block with a "==== <vm-name> ... ====" comment header;
never edit or reorder an existing VM's block, and never widen an existing
entry to also cover a new VM — add a new entry instead. This keeps VMs
mutually isolated: a request from VM A's IP for a repo only VM B is
whitelisted for still gets a 403, even though the proxy backing both is the
same process.

Runs ONLY on the host, bound to the Multipass bridge interface. VMs never
hold a real GitHub credential; git/gh CLI inside each VM send a placeholder
Authorization header (see the SKILL for how that's wired), and this addon
swaps it for the real `gh auth token` value ONLY on requests that match an
entry in ALLOWED. Everything else — wrong VM, wrong repo, wrong path, wrong
method — gets a 403 before it ever reaches GitHub.

ALLOWED entries are (client_ip, host, method, path-prefix):
  - client_ip: the Multipass VM's bridge IP this entry applies to. "*"
    matches any VM reachable through this proxy — only use it for something
    genuinely meant to be shared across every VM on the host.
  - method: "*" matches any HTTP method.
  - path-prefix: matched against the request path with the query string
    stripped (so GET .../info/refs?service=... still matches on prefix).
"""

import base64
import subprocess
import time

from mitmproxy import http

ALLOWED: list[tuple[str, str, str, str]] = []

# ==== add each VM's block below this line, one block per VM, oldest first ====

_TOKEN_TTL_SECONDS = 300
_token_cache: dict[str, object] = {"value": None, "ts": 0.0}


def _current_token() -> str:
    now = time.time()
    if _token_cache["value"] is None or now - _token_cache["ts"] > _TOKEN_TTL_SECONDS:
        result = subprocess.run(
            ["gh", "auth", "token"], capture_output=True, text=True, check=True
        )
        _token_cache["value"] = result.stdout.strip()
        _token_cache["ts"] = now
    return _token_cache["value"]


def _client_ip(flow: http.HTTPFlow) -> str:
    peername = flow.client_conn.peername
    return peername[0] if peername else ""


def _is_allowed(client_ip: str, host: str, method: str, path: str) -> bool:
    return any(
        (c == "*" or c == client_ip)
        and host == h
        and (m == "*" or method == m)
        and path.startswith(p)
        for c, h, m, p in ALLOWED
    )


def request(flow: http.HTTPFlow) -> None:
    client_ip = _client_ip(flow)
    host = flow.request.pretty_host
    method = flow.request.method
    path = flow.request.path.split("?", 1)[0]

    if not _is_allowed(client_ip, host, method, path):
        flow.response = http.Response.make(
            403,
            f"blocked by orca-ssh-setup gh-proxy policy: "
            f"{client_ip} {method} {host}{path} is not whitelisted".encode(),
            {"Content-Type": "text/plain"},
        )
        return

    token = _current_token()
    if host == "api.github.com":
        flow.request.headers["Authorization"] = f"Bearer {token}"
    elif host == "github.com":
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        flow.request.headers["Authorization"] = f"Basic {basic}"
PYEOF
```

**4d. Run it as a systemd *user* service**, bound to the same Multipass
bridge IP the model proxy in step 3 uses (`10.14.105.1`-style address — reuse
`$BIND_ADDR` from step 3c if it's still in scope, otherwise re-derive it from
`mpqemubr0`), on a different port (`8888` is a reasonable default; check
`ss -ltnp` if unsure it's free). Skip creating the unit if 4a found the
service already active — just confirm it's using this bridge IP/port:

```bash
UNIT="$HOME/.config/systemd/user/cli-github-proxy.service"
mkdir -p "$(dirname "$UNIT")"
cat > "$UNIT" <<UNIT
[Unit]
Description=GitHub credential-injection mitmproxy (orca-ssh-setup gh-proxy)
After=network-online.target

[Service]
ExecStart=/usr/bin/mitmdump --mode regular --listen-host ${BIND_ADDR} --listen-port 8888 --set confdir=%h/.mitm-github-proxy -s %h/.mitm-github-proxy/gh_proxy.py
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
UNIT

systemctl --user daemon-reload
systemctl --user enable --now cli-github-proxy.service
sleep 2
systemctl --user is-active --quiet cli-github-proxy.service || {
  systemctl --user status cli-github-proxy.service --no-pager --lines=20
  echo "gh-proxy failed to start — resolve before continuing" >&2
  exit 1
}
```

The first start generates a mitmproxy CA at
`~/.mitm-github-proxy/mitmproxy-ca-cert.pem` — confirm it exists
(`ls ~/.mitm-github-proxy/*.pem`) before moving on; step 7 copies it into
the VM. With an empty (or other-VMs-only) `ALLOWED`, every request this
service sees right now is a 403 by design — that's expected until step 7
appends this VM's block.

## 5. Create a properly named Multipass VM

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
multipass exec <vm-name> -- bash -c 'git clone <repo-url> ~/<reponame>'
```

(Wrap in `bash -c '...'` rather than passing `~/<reponame>` as a bare
argument — `multipass exec` does not itself invoke a shell, so an unquoted
`~` gets expanded by the *host's* shell before multipass ever sees it,
producing a path under the host's home directory instead of the VM's.)

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

## 6. Set up SSH access

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

Do not proceed to step 7 until the `ssh ... echo ok` check above succeeds.

## 7. Wire the installed harness(es), and git/gh, to the host proxies

### Coding-agent harness(es)

Skip this subsection if no harness was requested in step 2.

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

### git / gh CLI

Skip this subsection if step 2 established the VM needs no GitHub access (in
which case step 4 was also skipped).

**Append this VM's allowlist block first** — step 4 deliberately left
`~/.mitm-github-proxy/gh_proxy.py`'s `ALLOWED` list empty (or untouched, on a
shared host) because it needed this VM's bridge IP, which now exists:

```bash
VM_IP=$(multipass info <vm-name> | awk '/IPv4/{print $2}')
```

Edit the script to insert a new commented block **after** the
`# ==== add each VM's block below this line ... ====` marker and after any
existing VMs' blocks — append-only, never touch a block that isn't this
VM's. Narrow the paths to exactly what step 2 confirmed (prefer separate
`pulls`/`issues`/`contents` entries over a blanket path; only include the
git smart-http entry if push access was requested):

```python
# ==== <vm-name> VM (<VM_IP>) — repo: <org>/<repo> ====
ALLOWED += [
    ("<VM_IP>", "api.github.com", "GET", "/repos/<org>/<repo>/pulls"),
    ("<VM_IP>", "api.github.com", "POST", "/repos/<org>/<repo>/pulls"),
    ("<VM_IP>", "api.github.com", "*", "/repos/<org>/<repo>/issues"),
    ("<VM_IP>", "api.github.com", "GET", "/repos/<org>/<repo>/contents"),
    ("<VM_IP>", "github.com", "*", "/<org>/<repo>.git/"),  # omit if no push access
]
```

mitmproxy hot-reloads an addon script when its mtime changes, but restart
explicitly to be certain the new block is live before wiring the VM to it:

```bash
systemctl --user restart cli-github-proxy.service
sleep 1
systemctl --user is-active --quiet cli-github-proxy.service || {
  systemctl --user status cli-github-proxy.service --no-pager --lines=20
  echo "gh-proxy failed to restart — resolve before continuing" >&2
  exit 1
}
```

There's no meaningful host-side smoke test for this block anymore — since
each entry is pinned to the VM's own bridge IP, a request curl'd from the
host itself gets a 403 regardless of path (the host isn't the VM). That's
expected, not a bug. The real test has to originate from the VM, so it
happens below once `gh`/`git` are wired up in it — don't skip that
verification.

Install `gh` in the VM (there's nothing to log it into — it stays
credential-free):

```bash
multipass exec <vm-name> -- bash -c '
set -e
sudo mkdir -p -m 755 /etc/apt/keyrings
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  | sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null
sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
  | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt-get update -qq
sudo apt-get install -y -qq gh
'
```

Read the gh-proxy's own bridge IP/port/CA the same way step 3's block reads
the model broker — from `~/.mitm-github-proxy/` on the host, not hardcoded:

```bash
GHPROXY_HOST=<bridge IP used in step 4d>
GHPROXY_PORT=8888
CA_PATH=~/.mitm-github-proxy/mitmproxy-ca-cert.pem
```

Copy the CA cert into the VM. **`multipass transfer` can fail with a
confusing sftp permission error** if the source file lives under a
non-world-traversable home directory (snap confinement on the multipass
daemon) — piping it through `multipass exec` as base64 sidesteps this:

```bash
B64=$(base64 -w0 "$CA_PATH")
multipass exec <vm-name> -- bash -c "echo '$B64' | base64 -d > /home/ubuntu/.gh-proxy-ca.pem"
```

Scope `git` to the proxy **per-host** (`http.https://github.com/.*`), not
globally — this is what keeps npm/apt/curl/everything else in the VM
unaffected by the proxy's default-deny policy. Also install a static
placeholder credential helper so `git push` doesn't hang prompting
interactively; the real value is swapped in by the proxy, never seen by git
or stored in the VM:

```bash
multipass exec <vm-name> -- bash -c "
  git config --global http.https://github.com/.proxy http://${GHPROXY_HOST}:${GHPROXY_PORT}
  git config --global http.https://github.com/.sslCAInfo /home/ubuntu/.gh-proxy-ca.pem
  git config --global credential.https://github.com.helper '!f() { echo username=x-access-token; echo password=placeholder; }; f'
"
```

For `gh`, there's no per-host config, so scope it with a wrapper script
instead of global env vars (a global `HTTPS_PROXY` would route *all* HTTPS
traffic in the VM — npm installs, curl calls the agent makes for other
things — through the gh-proxy, which default-denies anything not on the
allowlist and would break them). Install the real binary via apt as above
(lands at `/usr/bin/gh`), then shadow it from `/usr/local/bin` (earlier in
the default `$PATH`) with a wrapper that only sets these vars for `gh`
itself. `GH_TOKEN` is a placeholder, not a real credential — it exists so
`gh` believes it's authenticated and always sends *an* `Authorization`
header for the proxy to intercept and replace on allowlisted calls (and
irrelevant on blocked ones, since the proxy 403s before the fake header
would ever matter):

```bash
multipass exec <vm-name> -- bash -c "cat | sudo tee /usr/local/bin/gh > /dev/null <<'WRAP'
#!/usr/bin/env bash
export HTTPS_PROXY=\"http://${GHPROXY_HOST}:${GHPROXY_PORT}\"
export HTTP_PROXY=\"http://${GHPROXY_HOST}:${GHPROXY_PORT}\"
export SSL_CERT_FILE=\"/home/ubuntu/.gh-proxy-ca.pem\"
export GH_TOKEN=\"placeholder\"
exec /usr/bin/gh \"\$@\"
WRAP"
multipass exec <vm-name> -- sudo chmod +x /usr/local/bin/gh
```

Verify both the allowed and denied paths — a setup that only ever tested the
happy path won't catch an allowlist typo that's either too permissive or
blocks the thing the agent actually needs:

```bash
# allowed — expect a real (possibly empty) JSON response, not a proxy 403:
multipass exec <vm-name> -- bash -lc 'gh api repos/<org>/<repo>/issues'
# denied — expect "blocked by orca-ssh-setup gh-proxy policy" + HTTP 403:
multipass exec <vm-name> -- bash -lc 'gh api user'
# git through the proxy (works for any repo the allowlist covers):
multipass exec <vm-name> -- bash -lc 'git ls-remote <repo-url>'
```

`gh auth status` inside the VM will report the token as invalid — that's
expected and correct: `/user` isn't on the allowlist, so the proxy never
touches that call and `gh` never sees a real credential. Don't try to make
`gh auth status` pass; it passing would mean a real token reached the VM.

Also confirm the scoping didn't leak — unrelated traffic in the VM must be
completely unaffected by this proxy, since only `git`/`gh` are wired to it:

```bash
multipass exec <vm-name> -- bash -lc 'echo "HTTP_PROXY=[$HTTP_PROXY] HTTPS_PROXY=[$HTTPS_PROXY]"'  # both empty
multipass exec <vm-name> -- bash -lc 'npm view left-pad version'                                    # resolves normally
multipass exec <vm-name> -- bash -lc 'git ls-remote https://gitlab.com/gitlab-org/gitlab-foss.git HEAD'  # non-GitHub git remote, unaffected
```

Finally, verify the *agent* — not just a manual shell command — can actually
drive `gh` through this chain, since that's the thing that matters. Run it
non-interactively inside the VM with `-p`:

```bash
multipass exec <vm-name> -- bash -lc \
  'cd ~/<reponame> && claude -p "Run: gh api repos/<org>/<repo>/issues --jq \". | length\" and tell me the number." --output-format text'
```

If this comes back with `Permission for this action was denied by the
Claude Code auto mode classifier`, that's unrelated to the proxy — it's
Claude Code's own server-side classifier being extra cautious about
`--dangerously-skip-permissions` specifically in non-interactive contexts.
Don't reach for `--dangerously-skip-permissions` to work around it; instead
pre-grant the exact command in `~/.claude/settings.json` inside the VM
(`{"permissions": {"allow": ["Bash(gh api repos/<org>/<repo>/issues:*)"]}}`)
and retry without that flag. Remove any settings file you added purely to
run this check once it passes — it's a verification step, not part of the
intended end state.

## 8. Tell the user exactly how to add this as an Orca SSH project

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
   `~/<reponame>` (or wherever the repo was cloned in step 5).
6. If a harness was installed, tell the user which one(s) are ready to use
   with no further login step (`codex`, `claude`) — the proxy already
   authenticated them.
7. If GitHub access was wired up, tell the user exactly which repo(s) and
   operations the agent can use (`git clone`/`push`, `gh pr`/`issue`
   read/create) — and which it explicitly can't (anything off the
   allowlist, e.g. other repos or `gh api user`) — so they aren't surprised
   by a 403 mid-task.

Remind the user that agents and `git worktree` will now execute on the VM,
while Orca's editor/diff/UI stay local; that stopping/deleting the Multipass
VM (`multipass stop|delete <vm-name>`) will break the SSH target until it's
recreated; and that the host-side proxy(ies) wired up are now **shared, hard
dependencies** for every project using them, not just this one — if
`cli-proxy-api.service` is down, every harness on every such VM fails with a
connection error, not an auth error; if `cli-github-proxy.service` is down,
every VM's `git`/`gh` GitHub calls fail the same way.
