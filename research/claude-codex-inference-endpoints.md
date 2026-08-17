# Claude Code & Codex CLI: Inference-Endpoint Hostnames and Placeholder-Auth Mechanisms

Research for [cau777/jetty-vm#16](https://github.com/cau777/jetty-vm/issues/16) — distinct from
[#2](https://github.com/cau777/jetty-vm/issues/2)'s OAuth *refresh*-endpoint findings
(`platform.claude.com/v1/oauth/token`, `auth.openai.com/oauth/token`). This document is
about the hostname(s) used for **real model/inference calls**, and whether each CLI can be
coaxed into sending a request carrying a placeholder `Authorization`-shaped credential via a
native, non-proxy env var, without a fully-formed local credentials file and without an
interactive login prompt, while left pointed at its default/real base URL.

**Date:** 2026-08-16
**Method:** Primary-source only.
- **Codex**: [openai/codex](https://github.com/openai/codex) is a real, public source repo
  (Rust CLI + TypeScript SDK). Cloned at commit `9ded177ce7c1c0bd2047f902936c177612ab3434`
  (2026-08-16). All Codex citations below are `path/to/file.rs:line` references into that
  checkout unless noted otherwise.
- **Claude Code**: [anthropics/claude-code](https://github.com/anthropics/claude-code) is a
  *source-less* repo (issue tracker, CHANGELOG, marketplace/plugin scaffolding, CI scripts —
  no `cli.js`/TypeScript source; confirmed by cloning it at commit
  `0fa8c19d50f70f9f383fb6ff5ce5209575267d21`, 2026-08-16, and listing its contents). The
  published `@anthropic-ai/claude-code` npm package (`2.1.233`) is itself only a thin
  platform-detection wrapper (`cli-wrapper.cjs`, `install.cjs`) — the actual client is a
  compiled, single-file, minified JS bundle (`claude`, 324,598,064 bytes) shipped as the
  optional platform package `@anthropic-ai/claude-code-linux-x64@2.1.233`. That binary was
  downloaded (`npm pack @anthropic-ai/claude-code-linux-x64@2.1.233`) and read directly with
  `strings`/`grep` — this is treated as a primary source (it is literally the shipped
  executable), cited by matched literal snippet rather than by line number, since the bundle
  is one JS statement stream with no retained line breaks. Anthropic's own published docs
  (`code.claude.com/docs/en/*`, fetched live) are cited alongside as the vendor's documented
  description of the same behavior, and agree with what the binary does everywhere checked.

---

## Headline findings

**Real inference hostnames** (distinct from OAuth refresh):

| CLI | Auth mode | Inference hostname | Full request path |
|---|---|---|---|
| Claude Code | any (API key, bearer token, subscription OAuth) | `api.anthropic.com` | `POST https://api.anthropic.com/v1/messages` |
| Codex | API-key modes (`CODEX_API_KEY`/`OPENAI_API_KEY`-derived, `AuthMode::ApiKey`) | `api.openai.com` | `POST https://api.openai.com/v1/responses` |
| Codex | ChatGPT-plan modes (`AuthMode::Chatgpt`/`ChatgptAuthTokens`/`Headers`/`AgentIdentity`/`PersonalAccessToken`) | `chatgpt.com` | `POST https://chatgpt.com/backend-api/codex/responses` |

**Placeholder-auth answer, both CLIs: yes**, confirmed from source/binary, in both cases
without needing a credentials file and without an interactive browser login, **while left
pointed at the real default host**:

- **Claude Code**: set `ANTHROPIC_AUTH_TOKEN=<placeholder>`. It is sent verbatim as
  `Authorization: Bearer <value>` (confirmed both from the shipped binary's own header-builder
  function and from Anthropic's docs). It is checked *before* `~/.claude/.credentials.json`
  in the documented precedence order, and — confirmed directly from the binary's first-launch
  gate function — its mere presence suppresses the interactive login screen. `ANTHROPIC_BASE_URL`
  does **not** need to be set; the binary's base-URL resolver falls back to a hardcoded
  `"https://api.anthropic.com"` constant when it's unset, independently of the
  `ANTHROPIC_AUTH_TOKEN` check (the two are unrelated code paths). Leaving it unset is
  actually *preferable* for a transparent-MITM design, not just sufficient — Anthropic's own
  docs state that setting `ANTHROPIC_BASE_URL` to any non-`api.anthropic.com` value disables
  Remote Control and MCP tool search by default.

- **Codex**: set `CODEX_API_KEY=<placeholder>` and invoke `codex exec` (the non-interactive
  entrypoint — the one relevant to a VM/automation harness). Codex's own auth-loading function
  checks `CODEX_API_KEY` *first*, before any persisted `~/.codex/auth.json`, with the code
  comment "API key via env var takes precedence over any other auth method." It's sent as
  `Authorization: Bearer <value>` via `BearerAuthProvider`. No `openai_base_url` override is
  needed — the built-in `openai` provider's base URL defaults to `https://api.openai.com/v1`
  for API-key auth modes when unset. This only holds for entrypoints that pass
  `enable_codex_api_key_env: true` to the auth manager — confirmed true for `codex exec`
  (`session_source: SessionSource::Exec`, `client_name: "codex_exec"`), and confirmed **false**
  for the interactive TUI (`codex` with no subcommand) — so this mechanism is specifically an
  automation/headless-mode feature, not a general one.

The current `orca-ssh-setup` skill's pattern (explicit `ANTHROPIC_BASE_URL` +
`ANTHROPIC_AUTH_TOKEN` for Claude Code; a custom `[model_providers.hostproxy]` block with its
own `base_url` for Codex) exists **because it redirects to a different host** (the CLIProxyAPI
broker), not because base-URL overriding is required to use an auth-token env var at all. For
a transparent-MITM design where the real hostname (`api.anthropic.com` / `api.openai.com`) is
kept and traffic is intercepted at the network layer instead, the base-URL override becomes
unnecessary and — per Claude Code's own docs — actively counterproductive (see above).

---

## 1. Claude Code / Anthropic

### 1.1 Inference hostname and path

The shipped Linux x64 binary (`@anthropic-ai/claude-code-linux-x64@2.1.233`) contains the
literal path string `/v1/messages`. Its bundled config-constants object is:

```
Pjc={BASE_API_URL:"https://api.anthropic.com",CONSOLE_AUTHORIZE_URL:"https://platform.claude.com/oauth/authorize",CLAUDE_AI_AUTHORIZE_URL:"https://claude.com/cai/oauth...
```

`(shipped binary, matched literal snippet — see Method)`. This is the same constants object
whose `CONSOLE_AUTHORIZE_URL` is `platform.claude.com`, matching #2's independently-sourced
finding for the OAuth authorize/refresh host — corroborating that this object is in fact
Anthropic's real endpoint table, not an unrelated/decoy string.

`strings` also confirms a large family of first-party hostnames embedded in the binary,
including `api.anthropic.com`, `api-staging.anthropic.com`, `platform.claude.com`,
`code.claude.com`, `mcp-proxy.anthropic.com`, and several `*.mcp.claude.com` connector hosts
(gcal/gmail/slack/microsoft365) — `api.anthropic.com` is the one relevant to inference.

The base-URL resolution function itself, read directly out of the binary:

```
function cES(){return sYe()??V.ANTHROPIC_BASE_URL??Ua().BASE_API_URL}
```

`(shipped binary, matched literal snippet)` — `V` is the bundle's `process.env` accessor
object (confirmed by its other members, e.g. `V.CLAUDE_CODE_OAUTH_TOKEN`,
`V.CLAUDE_CODE_USE_BEDROCK`, matched throughout the bundle), `sYe()` is some higher-priority
override (not investigated further — likely a profile/gateway override, out of scope), and
`Ua().BASE_API_URL` resolves to the `Pjc` constants object above, i.e.
`"https://api.anthropic.com"`. So: **if `ANTHROPIC_BASE_URL` is unset, the resolved base URL
is the hardcoded `https://api.anthropic.com` — no other configuration is required to reach the
real endpoint.**

Anthropic's own docs corroborate this without stating the literal value directly: `Remote
Control is disabled when this points at a host other than api.anthropic.com` (from
`code.claude.com/docs/en/env-vars`, `ANTHROPIC_BASE_URL` entry, fetched live 2026-08-16) — i.e.
the docs treat `api.anthropic.com` as *the* first-party host, consistent with the binary's
hardcoded fallback.

### 1.2 `ANTHROPIC_AUTH_TOKEN`: header shape, precedence, and file/login bypass

**Header shape**, from the binary's own header-builder function:

```
function kTr(){let e=V.ANTHROPIC_AUTH_TOKEN;if(e)return`Bearer ${e}`;let t=V.ANTHROPIC_CUSTOM_HEADERS; ...
```

`(shipped binary, matched literal snippet)` — confirms `ANTHROPIC_AUTH_TOKEN`'s value is
prefixed with the literal string `"Bearer "` and returned as-is, with no format validation
against the value itself (any string works). This matches Anthropic's docs verbatim:

> **`ANTHROPIC_AUTH_TOKEN`**: "Custom value for the `Authorization` header (the value you set
> here will be prefixed with `Bearer `)"
> `(code.claude.com/docs/en/env-vars, fetched live 2026-08-16)`

By contrast, `ANTHROPIC_API_KEY` is sent as a **different header** (`X-Api-Key`, not
`Authorization`):

> **`ANTHROPIC_API_KEY`**: "API key sent as `X-Api-Key` header. ... In non-interactive mode
> (`-p`), the key is always used when present. In interactive mode, you are prompted to
> approve the key once before it overrides your subscription."
> `(code.claude.com/docs/en/env-vars, fetched live 2026-08-16)`

**This is the reason `ANTHROPIC_AUTH_TOKEN`, not `ANTHROPIC_API_KEY`, is the right placeholder
mechanism for a design that unconditionally overwrites the `Authorization` header** — an
`ANTHROPIC_API_KEY` placeholder would still result in a real request, but the credential would
ride on `X-Api-Key`, a header a MITM addon targeting `Authorization` wouldn't touch.

**Documented precedence** (`code.claude.com/docs/en/authentication`, "Authentication
precedence" section, fetched live 2026-08-16, quoted in full order):

1. Cloud provider credentials (`CLAUDE_CODE_USE_BEDROCK`/`_VERTEX`/`_FOUNDRY`)
2. **`ANTHROPIC_AUTH_TOKEN`** — "Sent as the `Authorization: Bearer` header. Use this when
   routing through an LLM gateway or proxy that authenticates with bearer tokens rather than
   Anthropic API keys."
3. `ANTHROPIC_API_KEY` — sent as `X-Api-Key`, with the one-time interactive approval prompt
   described above (not required in non-interactive/`-p` mode)
4. `apiKeyHelper` script output
5. `CLAUDE_CODE_OAUTH_TOKEN` — a long-lived token minted once via `claude setup-token`
6. Anthropic profile/federation credentials
7. Subscription OAuth from `/login` (the interactive browser flow) — **the default, and the
   lowest-priority source**, meaning any of 1–6 pre-empts it entirely.

**Login-screen bypass, confirmed structurally from the binary.** The first-launch
login-required gate:

```
function HL(){if(!bDo())return!1;if(Wh()||V.ANTHROPIC_UNIX_SOCKET||C8t()||eH()||V.ANTHROPIC_AUTH_TOKEN||V.CLAUDE_CODE_OAUTH_TOKEN||Ahe()||JB()||V.CLAUDE_CODE_USE_BEDROCK||V.CLAUDE_CODE_USE_VERTEX||V.CLAUDE_CODE_USE_FOUNDRY||V.CLAUDE_CODE_USE_ANTHROPIC_AWS||V.CLAUDE_CODE_USE_ANTHROPIC_GOOGLE_CLOUD||V.CLAUDE_CODE_USE_MANTLE)return!1; ...
function Mst(){return yhe()===null&&HL()}
```

`(shipped binary, matched literal snippet)` — `Mst()` (best read as "needs first-launch login
screen") is gated by `HL()`, which returns `false` — i.e. **no login screen needed** — whenever
`V.ANTHROPIC_AUTH_TOKEN` is truthy, among several other non-interactive auth sources. Note
`ANTHROPIC_BASE_URL` does **not** appear anywhere in this condition — `ANTHROPIC_AUTH_TOKEN`
alone, with `ANTHROPIC_BASE_URL` left unset, is sufficient to suppress the browser-login
screen. This matches the docs' own framing of the same behavior for the API-key case ("If
you've set the `ANTHROPIC_API_KEY` environment variable, Claude Code skips the login prompt
and asks you to approve the key instead" — `code.claude.com/docs/en/authentication`, "Log in
to Claude Code" section) — the binary shows `ANTHROPIC_AUTH_TOKEN` is in the *same* bypass
class, and unlike `ANTHROPIC_API_KEY` it is not listed anywhere in the docs as requiring even
a one-time approval prompt, which is corroborated by its absence from any prompt-related logic
found near `HL()`/`kTr()` in the binary.

**Credentials-file independence**, from the docs directly:

> "Claude Code manages `.credentials.json` through `/login` and `/logout`. To route requests
> through a custom API endpoint, set the `ANTHROPIC_BASE_URL` environment variable instead."
> `(code.claude.com/docs/en/authentication`, "Credential management" section)

> "`apiKeyHelper`, `ANTHROPIC_API_KEY`, and `ANTHROPIC_AUTH_TOKEN` apply to the CLI and the
> surfaces that wrap it... Claude Desktop and cloud sessions do not call `apiKeyHelper` or
> read these environment variables: they use OAuth"
> `(code.claude.com/docs/en/authentication`, same section)

I.e. `~/.claude/.credentials.json` is written/read only by the `/login`/`/logout` flow;
`ANTHROPIC_AUTH_TOKEN` is a structurally independent auth path that never touches it.

### 1.3 Net answer for Claude Code

Set `ANTHROPIC_AUTH_TOKEN=<any placeholder value>` in the VM's environment, leave
`ANTHROPIC_BASE_URL` **unset**, and run `claude` (interactive) or `claude -p ...`
(non-interactive/print mode — the mode a VM harness would actually use). The CLI:
- resolves its base URL to the hardcoded `https://api.anthropic.com` (§1.1),
- sends `POST https://api.anthropic.com/v1/messages` with `Authorization: Bearer <placeholder>`
  (§1.2),
- never touches `~/.claude/.credentials.json` (§1.2),
- never shows the interactive browser-login screen (§1.2, `HL()`).

A transparent MITM sitting on `api.anthropic.com:443` overwriting `Authorization` therefore
sees exactly the traffic shape the design needs, with zero local credential material beyond an
arbitrary placeholder string, and — per the Remote-Control caveat in §1.1 — this is *better*
for feature-completeness than explicitly pointing `ANTHROPIC_BASE_URL` at a broker/gateway
host the way `orca-ssh-setup`'s current CLIProxyAPI integration does.

---

## 2. Codex / OpenAI

### 2.1 Inference hostnames and paths — two, depending on auth mode

Codex's model-provider layer explicitly branches base URL by auth mode:

```rust
pub fn to_api_provider(&self, auth_mode: Option<AuthMode>) -> CodexResult<ApiProvider> {
    let default_base_url = if matches!(
        auth_mode,
        Some(
            AuthMode::Chatgpt
                | AuthMode::ChatgptAuthTokens
                | AuthMode::Headers
                | AuthMode::AgentIdentity
                | AuthMode::PersonalAccessToken
        )
    ) {
        CHATGPT_CODEX_BASE_URL
    } else {
        "https://api.openai.com/v1"
    };
    let base_url = self.base_url.clone().unwrap_or_else(|| default_base_url.to_string());
    ...
```
`(codex-rs/model-provider-info/src/lib.rs:245-267)`

```rust
pub const CHATGPT_CODEX_BASE_URL: &str = "https://chatgpt.com/backend-api/codex";
```
`(codex-rs/model-provider-info/src/lib.rs:37)`

The `AuthMode` enum's variant doc comments (`codex-rs/protocol/src/auth.rs:9-29`) name each
mode: `ApiKey` ("OpenAI API key provided by the caller and stored by Codex"), `Chatgpt`
("ChatGPT OAuth managed by Codex"), `ChatgptAuthTokens` ("ChatGPT auth tokens supplied by an
external host application"), `Headers`, `AgentIdentity`, `PersonalAccessToken`. Only `ApiKey`
falls through to the `api.openai.com` branch; every other mode uses the ChatGPT-plan backend.

The actual request path appended to whichever base URL is resolved:

```rust
const RESPONSES_ENDPOINT: &str = "/responses";
```
`(codex-rs/core/src/client.rs:161)`

So: `POST https://api.openai.com/v1/responses` for API-key auth, or
`POST https://chatgpt.com/backend-api/codex/responses` for ChatGPT-plan/OAuth auth. Test
fixtures corroborate the exact production URL shape for the latter, e.g.
`"https://chatgpt.com/backend-api/codex/responses"` and
`"https://chatgpt.com/backend-api/codex/models"`
`(codex-rs/protocol/src/error_tests.rs:533,577,598; codex-rs/response-debug-context/src/lib.rs:120,140)`.

The TUI's own literal default constant independently confirms the API-key-mode host:
```rust
const DEFAULT_OPENAI_BASE_URL: &str = "https://api.openai.com/v1";
```
`(codex-rs/tui/src/chatwidget.rs:494)`

**Not investigated**: precisely which condition puts an interactively-`codex login`'d ChatGPT
session onto `AuthMode::Chatgpt` vs. `ApiKey` at runtime for a given login flow (out of scope —
this document only needed to establish the two possible hostnames and which one an
env-var/placeholder-auth mechanism reaches, answered in §2.2 below: it reaches
`api.openai.com`).

### 2.2 `CODEX_API_KEY`: bypasses `auth.json` entirely, but only in specific entrypoints

Three relevant env vars are defined together:

```rust
pub const OPENAI_API_KEY_ENV_VAR: &str = "OPENAI_API_KEY";
pub const CODEX_API_KEY_ENV_VAR: &str = "CODEX_API_KEY";
pub const CODEX_ACCESS_TOKEN_ENV_VAR: &str = "CODEX_ACCESS_TOKEN";
```
`(codex-rs/login/src/auth/manager.rs:890-892)`

The auth-loading function, which runs on every session start to decide what credential to use:

```rust
async fn load_auth(
    codex_home: &Path,
    enable_codex_api_key_env: bool,
    ...
) -> std::io::Result<Option<CodexAuth>> {
    // API key via env var takes precedence over any other auth method.
    if enable_codex_api_key_env
        && auth_mode_is_allowed(allowed_login_methods, AuthMode::ApiKey)
        && let Some(api_key) = read_codex_api_key_from_env()
    {
        return Ok(Some(CodexAuth::from_api_key(api_key.as_str())));
    }
    // External ChatGPT auth tokens ...
    // (only reached if the CODEX_API_KEY branch above didn't return)
    ...
```
`(codex-rs/login/src/auth/manager.rs:1417-1444, comment at 1429, function signature at
1418-1428)` — **`CODEX_API_KEY` is checked, and can return, before any persisted
`~/.codex/auth.json` is even loaded** (the ephemeral/persisted-storage load happens later in
the same function, `manager.rs:1439-1499`). This is the direct code-level confirmation of "no
credentials file required."

`CodexAuth::from_api_key(...)` produces `AuthMode::ApiKey`
`(codex-rs/login/src/auth/manager.rs:470,482, matching `Self::ApiKey(_) => AuthMode::ApiKey`)`,
which is exactly the mode that resolves to `api.openai.com` in §2.1's `to_api_provider` match.

**Header shape** — the API key is turned into a plain bearer token via the shared
`BearerAuthProvider`:

```rust
pub struct BearerAuthProvider { ... }
impl AuthProvider for BearerAuthProvider {
    ...
    && let Ok(header) = HeaderValue::from_str(&format!("Bearer {token}"))
```
`(codex-rs/model-provider/src/bearer_auth_provider.rs:7,31,34)` — same `Authorization: Bearer
<value>` shape as Claude Code's `ANTHROPIC_AUTH_TOKEN`, i.e. the shape a design that
unconditionally overwrites `Authorization` needs.

**`enable_codex_api_key_env` is not universally on.** Grepping every call site
(`codex-rs/**/*.rs`, non-test) shows it is:
- **`true`** for: `codex exec` (`codex-rs/exec/src/lib.rs:551`, on the actual per-turn
  `AuthManager` used for model requests — `session_source: SessionSource::Exec`,
  `client_name: "codex_exec"`), `codex mcp` (`codex-rs/cli/src/mcp_cmd.rs:634`), `codex plugin`
  (`codex-rs/cli/src/plugin_cmd.rs:603`), `codex doctor` (`codex-rs/cli/src/doctor.rs:376`),
  and two specific codepaths in `codex-rs/cli/src/main.rs` (lines 1957, 2165).
- **`false`** for: the interactive TUI's main session construction
  (`codex-rs/tui/src/lib.rs:578`, `codex-rs/tui/src/startup_orchestration.rs:356`), the MCP
  *server* message processor (`codex-rs/mcp-server/src/message_processor.rs:61`), the
  in-process app-server default (`codex-rs/app-server/src/in_process.rs:835`), and several
  other library-embedding call sites that default to `false` unless the embedder opts in
  (`codex-rs/app-server-client/src/lib.rs`, `codex-rs/thread-manager-sample/src/main.rs:120`,
  etc.) — as well as one intentionally-`false` spot *inside* `codex exec` itself
  (`codex-rs/exec/src/lib.rs:354`), which the surrounding comment identifies as a *different*
  subsystem (fetching workspace-managed cloud config, which "cannot fetch ... even when model
  requests allow CODEX_API_KEY" — i.e. this `false` deliberately does not affect the model-auth
  path at line 551).

**Practical implication**: `CODEX_API_KEY` as a plain env-var bypass is a real, source-confirmed
mechanism, but it is scoped to non-interactive entrypoints — concretely, `codex exec` (the
correct one for a VM/automation harness) and a handful of CLI subcommands, **not** the plain
interactive `codex` TUI session. For a VM-side harness that drives Codex non-interactively
(which is the relevant case for this project's wayfinder design), `codex exec` is exactly the
entrypoint that honors it.

**Lightly documented, not undocumented.** The TypeScript SDK's own README (a first-party doc,
not community-authored) confirms `CODEX_API_KEY` by name as a real, intentional mechanism the
SDK itself relies on:

> "The SDK still injects its required variables (such as `CODEX_API_KEY`) on top of the
> environment you provide. If you set `baseUrl`, the SDK passes it as a
> `--config openai_base_url=...` override."
> `(sdk/typescript/README.md:132-133)`

This second sentence also independently corroborates §2.3 below: base-URL override for the
built-in `openai` provider is a `--config`/`config.toml` key (`openai_base_url`), not an env
var.

The **officially documented, blessed** onboarding path is different and does write a
credentials file — `printenv OPENAI_API_KEY | codex login --with-api-key` (per
`learn.chatgpt.com/docs/auth`, fetched live 2026-08-16, redirect target of
`developers.openai.com/codex/auth`) writes `~/.codex/auth.json`. `OPENAI_API_KEY` alone, without
running `codex login`, is **not** read directly by the core model-request auth path in the
non-test source read here — it surfaces only as a TUI onboarding-form prefill value
(`codex-rs/tui/src/onboarding/auth.rs:783`) and in one unrelated realtime-voice codepath
(`codex-rs/core/src/realtime_conversation.rs:1637`). **`CODEX_API_KEY` (distinct from
`OPENAI_API_KEY`) is the one that behaves as a genuine placeholder-credential bypass for
`codex exec`.**

### 2.3 Base-URL override: a `config.toml`/`--config` key, not an env var

```rust
/// Base URL override for the built-in `openai` model provider.
pub openai_base_url: Option<String>,
```
`(codex-rs/config/src/config_toml.rs:376-377)`, consumed at
`codex-rs/core/src/config/mod.rs:3602-3608` (`cfg.openai_base_url` feeds
`built_in_model_providers(openai_base_url)`, which only overrides `create_openai_provider`'s
`base_url` field when `Some`; `None` leaves it unset, falling through to §2.1's
`api.openai.com`/`chatgpt.com` default-URL branch). There is no `OPENAI_BASE_URL` (or similar)
environment variable read anywhere in this core config-resolution path — the only
`OPENAI_BASE_URL`-named constant found in the whole repo lives in an unrelated subsystem,
`codex-rs/network-proxy/src/credential_broker/providers/openai.rs:13`, which is Codex's
*own* sandboxed-subprocess network-credential-broker feature (injecting credentials into
requests made by tools Codex spawns inside a sandbox) — not the CLI's own outbound request
path, and out of scope here (noted so it isn't mistaken for a real override mechanism).

Official docs corroborate the same shape at the config layer:

> "`model_providers.<id>.base_url`: API base URL for the model provider." /
> "`openai_base_url`: Overrides the default OpenAI endpoint (user-level config only)." /
> "project-scoped `.codex/config.toml` files cannot override `openai_base_url` or provider
> settings — these must remain in user-level configuration for security."
> `(learn.chatgpt.com/docs/config-file/config-reference`, fetched live 2026-08-16, redirect
> target of `developers.openai.com/codex/config-reference`)

### 2.4 Net answer for Codex

Set `CODEX_API_KEY=<any placeholder value>` in the VM's environment, write **no**
`~/.codex/config.toml` `model_providers` override and **no** `openai_base_url`, and invoke
`codex exec ...` (not the interactive `codex` TUI). The CLI:
- resolves `AuthMode::ApiKey` from the env var alone, before ever touching
  `~/.codex/auth.json` (§2.2),
- resolves the built-in `openai` provider's base URL to the hardcoded
  `https://api.openai.com/v1` (§2.1, §2.3), since neither the env var path nor an unset
  `openai_base_url` touches it,
- sends `POST https://api.openai.com/v1/responses` with `Authorization: Bearer <placeholder>`
  (§2.1, §2.2),
- never shows an interactive login prompt (`codex exec` with `CODEX_API_KEY` set never reaches
  the login/onboarding flow at all — confirmed by `load_auth`'s early return in §2.2).

This mirrors Claude Code's mechanism closely, with one important scoping difference: it is
**entrypoint-specific** (`codex exec` and a few CLI subcommands — not the interactive `codex`
TUI), where Claude Code's `ANTHROPIC_AUTH_TOKEN` bypass applies uniformly regardless of
interactive vs. `-p` mode.

---

## 3. Why `orca-ssh-setup` currently overrides the base URL, and whether that's still needed

Re-reading `orca-ssh-setup/SKILL.md` step 3 (host-side broker setup, lines ~82–244) and step 7
(VM-side wiring, lines ~569–634) with the above in hand:

- **Claude Code** (step 7, lines 610–621): writes both `ANTHROPIC_BASE_URL` (set to the
  broker's `http://<mpqemubr0-ip>:8317`, no trailing `/v1` per the skill's own comment) *and*
  `ANTHROPIC_AUTH_TOKEN` (the broker's local API key). This is necessary **only** because the
  broker is a genuinely different host from `api.anthropic.com` — the skill is redirecting the
  CLI's destination, not just its credential. §1.3 shows that if the real host is being kept
  (transparent-MITM design), `ANTHROPIC_BASE_URL` isn't just unnecessary — leaving it unset
  and letting the CLI resolve its own default is *better*, since an explicit non-default
  `ANTHROPIC_BASE_URL` disables Remote Control and MCP tool search by Anthropic's own
  documented design (§1.1).

- **Codex** (step 7, lines 586–608): writes a full custom `[model_providers.hostproxy]` block
  (`base_url`, `wire_api = "responses"`, `env_key = "HOSTPROXY_KEY"`) plus `model_provider =
  "hostproxy"` at the top level, again because the broker is a different host, and because the
  broker's compatibility shape needed `wire_api`/`env_key` spelled out explicitly (the broker
  is not `api.openai.com`, so it can't ride the built-in `openai` provider's defaults at all).
  §2.3–2.4 show that for a transparent-MITM design keeping the real `api.openai.com` host, none
  of this `model_providers` scaffolding is needed — `CODEX_API_KEY` alone, with the built-in
  `openai` provider left as-is, is sufficient, provided the VM-side invocation uses `codex exec`
  (§2.2's entrypoint-scoping caveat).

So: the current skill's explicit overrides are a **provider-redirection** artifact of pointing
at CLIProxyAPI, not a general requirement of using an env-var-based bearer credential. For the
wayfinder design's transparent-MITM model (real hostname kept, credential injected on the
wire), both CLIs' native placeholder-auth env vars work with the base URL left at its
compiled-in default — which is also the simpler and, for Claude Code, strictly more
feature-complete configuration.

---

## Open questions / gaps

- **Claude Code's minified bundle is read by pattern-matching, not disassembly.** Function
  names (`cES`, `kTr`, `HL`, `Mst`, `Pjc`, `V`, `Ua`) are minifier-generated and could
  theoretically be reused/shadowed elsewhere in the 324 MB binary in ways a flat `strings`
  read can't detect (e.g. if the bundler's minifier reuses short identifiers across unrelated
  modules). The snippets quoted were selected because they're internally consistent with each
  other and with Anthropic's documented behavior everywhere cross-checked, but this is
  reverse-engineering a compiled artifact, not reading disclosed source — treat the exact
  mechanism (as opposed to the externally observable behavior, which is docs-corroborated) as
  **corroborated, not contractually guaranteed to remain unchanged** across Claude Code
  releases.
- **Exactly which login flow lands a Codex session on `AuthMode::Chatgpt` vs.
  `ChatgptAuthTokens` vs. others** wasn't traced end-to-end (out of scope — all of them share
  the same `chatgpt.com` inference host per §2.1's `matches!` arm, which was the only thing
  needed here).
- **Whether `codex exec` with only `CODEX_API_KEY` set (no config.toml at all) succeeds
  end-to-end against a live `api.openai.com`**, or whether some other startup check (e.g. a
  first-run terms-acceptance gate, sandbox policy default, or model-catalog fetch) blocks
  before the request is sent, was not verified by actually running the binary — this document
  traces the auth/base-URL *code path* from source but does not include a live smoke test
  (mirroring the caveat already flagged in `research/oauth-refresh-wire-format.md` about not
  independently verifying live-endpoint behavior). Given this feeds a VM harness contract, a
  live `codex exec --help`/dry-run-style smoke test with a throwaway placeholder key against
  the real host (before wiring up the MITM injection) is recommended before relying on this.
- **Claude Code's non-interactive mode flag** is referred to here as `-p`/print mode per
  Anthropic's own docs; this document did not independently verify the exact current flag
  spelling against a live `--help` output, since it wasn't needed to answer the two research
  questions (headless mode already avoids interactive prompts by construction regardless of
  exact flag name, and `ANTHROPIC_AUTH_TOKEN`'s login-screen bypass in §1.2 is unconditional,
  not mode-dependent).
- **`ANTHROPIC_CUSTOM_HEADERS`** (seen alongside `ANTHROPIC_AUTH_TOKEN` in both the binary and
  the docs) can also set an arbitrary `Authorization:` line directly, per `kTr()`'s fallback
  branch in §1.2 — an alternate placeholder mechanism to `ANTHROPIC_AUTH_TOKEN`, not
  investigated further since `ANTHROPIC_AUTH_TOKEN` alone already answers the question cleanly.
