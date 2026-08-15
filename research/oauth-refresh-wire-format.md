# OAuth Token-Refresh Wire Format: Claude Code & Codex CLI

This document records the exact OAuth 2.0 refresh-token wire format that
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) implements for two
unofficial/reverse-engineered CLI OAuth apps: Anthropic's Claude Code CLI and
OpenAI's Codex CLI. Neither app's OAuth flow is documented by its vendor, so
CLIProxyAPI's Go source — a project that has clearly reverse-engineered both
CLIs down to header order and TLS fingerprint — is treated as the primary
source here. It was cloned at commit `78f0c4079e3e6273d65d03b5549cffc898703264`
(2026-08-15) into the scratchpad for this research. All citations below are
`path/to/file.go:line` references into that checkout, rooted at the repo root
(no leading path prefix needed beyond what's shown).

Goal: enough detail to reimplement both refresh flows directly, without
running CLIProxyAPI itself.

---

## Claude Code / Anthropic

### a. Refresh endpoint

Both the authorization-code exchange and the refresh-token exchange POST to
the **same URL**:

```
https://platform.claude.com/v1/oauth/token
```

`(CLIProxyAPI: internal/auth/claude/anthropic_auth.go:27-28)`

Notably this is **not** `api.anthropic.com` or `console.anthropic.com` — a
code comment explains the native client was observed posting the code
exchange to `platform.claude.com`, not `api.anthropic.com`
`(CLIProxyAPI: internal/auth/claude/anthropic_auth.go:25-26)`.

Two more endpoints are used after a refresh completes, to repopulate account
metadata (not required for a token-only refresh, but part of what the real
client does):
- Profile: `https://api.anthropic.com/api/oauth/profile` `(CLIProxyAPI: internal/auth/claude/anthropic_auth.go:29)`
- Roles: `https://api.anthropic.com/api/oauth/claude_cli/roles` `(CLIProxyAPI: internal/auth/claude/anthropic_auth.go:30-32)`

The authorize (browser) endpoint, for completeness, is
`https://claude.ai/oauth/authorize` `(CLIProxyAPI: internal/auth/claude/anthropic_auth.go:24)`.

### b. Client ID / redirect URI / scope

```go
ClientID         = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
RedirectURI      = "http://localhost:54545/callback"
ClaudeOAuthScope = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
```
`(CLIProxyAPI: internal/auth/claude/anthropic_auth.go:33-35)`

`RedirectURI` is only relevant to the authorization-code exchange (PKCE), not
to the refresh call itself, but `ClientID` and `ClaudeOAuthScope` **are** both
sent on every refresh request (see below).

### c. Refresh request shape

- **Method**: `POST`
- **Body encoding**: JSON (not form-urlencoded)
- **Body fields**, built as a `map[string]interface{}` then `json.Marshal`ed:
  ```go
  reqBody := map[string]interface{}{
      "client_id":     ClientID,
      "grant_type":    "refresh_token",
      "refresh_token": refreshToken,
      "scope":         ClaudeOAuthScope,
  }
  ```
  `(CLIProxyAPI: internal/auth/claude/anthropic_auth.go:526-531)`

  A unit test asserts the exact serialized JSON body (confirming field order
  mirrors captured native Claude Code 2.1.220 traffic):
  ```
  {"client_id":"<ClientID>","grant_type":"refresh_token","refresh_token":"<token>","scope":"<ClaudeOAuthScope>"}
  ```
  `(CLIProxyAPI: internal/auth/claude/anthropic_auth_test.go:412-414)`

- **Headers** (applied by `applyClaudeOAuthAxiosHeaders`, shared with the code
  exchange call, deliberately shaped to mimic the real Claude Code CLI's
  Node/Axios HTTP client):
  ```go
  req.Header.Set("Accept", "application/json, text/plain, */*")
  req.Header.Set("Content-Type", "application/json")
  req.Header.Set("User-Agent", "axios/1.15.2")
  req.Header.Set("Accept-Encoding", "gzip, compress, deflate, br")
  req.Header.Set("Connection", "close")
  req.Close = true
  ```
  `(CLIProxyAPI: internal/auth/claude/anthropic_auth.go:211-221, applied to the refresh request at anthropic_auth.go:542)`

  A test also pins these exact header values plus `req.Close == true` as a
  requirement `(CLIProxyAPI: internal/auth/claude/anthropic_auth_test.go:416-430)`.
  There is no `x-api-key` or `anthropic-beta` header on the OAuth refresh
  call — those are inference-API headers, not OAuth-control-plane headers, and
  do not appear anywhere in this refresh path.

  Additionally, the exact **HTTP header ordering on the wire** is controlled
  via a custom ordered-connection wrapper, not just Go's default map-iteration
  order — see gotchas below.

### d. Refresh response shape

```go
type tokenResponse struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
    Organization struct { UUID string `json:"uuid"`; Name string `json:"name"` } `json:"organization"`
    Account      struct { UUID string `json:"uuid"`; EmailAddress string `json:"email_address"` } `json:"account"`
}
```
`(CLIProxyAPI: internal/auth/claude/anthropic_auth.go:126-141)`

**Refresh-token rotation**: the response *can* include a new `refresh_token`,
but the code explicitly tolerates it being absent:

```go
if strings.TrimSpace(tokenResp.RefreshToken) == "" {
    tokenResp.RefreshToken = refreshToken   // fall back to the token that was sent
}
```
`(CLIProxyAPI: internal/auth/claude/anthropic_auth.go:578-581)`

`UpdateTokenStorage` then **unconditionally overwrites** the stored
`RefreshToken` with whatever `RefreshTokens` returned:
```go
storage.RefreshToken = tokenData.RefreshToken
```
`(CLIProxyAPI: internal/auth/claude/anthropic_auth.go:672-673)`

**Practical implication**: the credential file must always be rewritten after
a refresh (access token changed, and possibly the refresh token too), but the
code defensively handles a server that does *not* rotate the refresh token —
it is not assumed to always rotate. A dedicated test
(`TestRefreshTokensUsesNative220ControlPlaneShape`) mocks a refresh response
with **no** `refresh_token` field and asserts the original token is preserved
`(CLIProxyAPI: internal/auth/claude/anthropic_auth_test.go:431-461)`, i.e. as
of the traffic this project captured, Anthropic's endpoint does not appear to
always rotate the refresh token — CLIProxyAPI's code is written to be correct
in either case.

**Access-token TTL**: read from the response's `expires_in` (seconds), with
no hardcoded fallback:
```go
Expire: time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(time.RFC3339)
```
`(CLIProxyAPI: internal/auth/claude/anthropic_auth.go:585)`
The only concrete number in the repo is `3600` (1 hour) used as a mock value
in the unit test's fake server response
`(CLIProxyAPI: internal/auth/claude/anthropic_auth_test.go:433)` — this is a
test fixture, not asserted to be the exact production value, though it is
consistent with the conventional 1-hour OAuth2 access-token lifetime. Treat
"1 hour" as **corroborated, not confirmed**, for this provider (see Open
questions).

### e. Provider-specific gotchas

1. **Custom TLS fingerprint to dodge Cloudflare.** All Claude OAuth
   control-plane calls (code exchange, refresh, profile/roles lookups) go
   through a custom `uTLS`-based `http.Client` built by
   `NewAnthropicHttpClient` / `newUtlsRoundTripper`
   `(CLIProxyAPI: internal/auth/claude/anthropic_auth.go:183-208, internal/auth/claude/utls_transport.go:252-254)`.
   The doc comment on `NewClaudeAuth` claims this uses a "Firefox
   fingerprint" `(CLIProxyAPI: internal/auth/claude/anthropic_auth.go:175-176)`,
   but the actual `ClientHelloSpec` builder's comment says it "reproduces the
   compact **Node/OpenSSL** profile Claude Code 2.1.220 uses for Axios OAuth
   control-plane requests" and explicitly advertises **no ALPN extension**
   (HTTP/1.1 only, no h2 negotiation)
   `(CLIProxyAPI: internal/auth/claude/utls_transport.go:109-113)`. These two
   comments disagree — treat "Node/OpenSSL profile, no ALPN" as the
   authoritative description since it's on the code that actually builds the
   `ClientHelloSpec`; "Firefox fingerprint" in the constructor's doc comment
   looks like stale documentation.

2. **Exact wire-level header ordering is enforced**, not just header
   presence/values. A custom ordered-connection wrapper
   (`httpwire.NewOrderedRequestConn`) pins the header order for the refresh
   request to `Accept, Content-Type, User-Agent, Content-Length,
   Accept-Encoding, Host, Connection`, and a different order for the
   authenticated profile/roles GETs (`...Authorization, Cache-Control...`)
   `(CLIProxyAPI: internal/auth/claude/utls_transport.go:22-40)`. This level
   of mimicry (TLS ClientHello + exact header order + `axios/1.15.2`
   User-Agent + `Connection: close`) strongly suggests Anthropic's OAuth
   control plane does some form of client fingerprinting / bot detection on
   this endpoint, and that naive Go `net/http` defaults were previously
   getting blocked.

3. **429 handling with a client-side cooldown.** On `429 Too Many Requests`,
   the code parses `Retry-After` / `Retry-After-Ms` response headers and
   records a **local, in-memory block** on that specific refresh token so
   further refresh attempts for the same token short-circuit locally (return
   a non-retryable error) until the cooldown expires, rather than hammering
   the endpoint
   `(CLIProxyAPI: internal/auth/claude/anthropic_auth.go:98-116, 493-499, 518-524, 557-563)`.
   5xx responses are marked retryable; all other non-200 statuses (e.g. 400,
   401 invalid_grant) are not retryable
   `(CLIProxyAPI: internal/auth/claude/anthropic_auth.go:564-568)`.

4. **Single-flight de-duplication.** Concurrent refresh calls for the same
   refresh token are coalesced via `golang.org/x/sync/singleflight` so only
   one HTTP request goes out even if multiple callers try to refresh
   simultaneously `(CLIProxyAPI: internal/auth/claude/anthropic_auth.go:44,
   501-506, 517-524)`.

5. **Profile refetch is best-effort.** After a successful refresh, the code
   calls the profile endpoint to repopulate email/account/org fields, but a
   failure there is only logged (`log.Warnf`) and does not fail the refresh —
   the new access/refresh tokens are still returned
   `(CLIProxyAPI: internal/auth/claude/anthropic_auth.go:587-591)`. A minimal
   reimplementation can skip the profile call entirely if it doesn't need
   account metadata.

---

## Codex / OpenAI

### a. Refresh endpoint

Both the authorization-code exchange and the refresh-token exchange POST to:

```
https://auth.openai.com/oauth/token
```
`(CLIProxyAPI: internal/auth/codex/openai_auth.go:26)`

The authorize (browser) endpoint is `https://auth.openai.com/oauth/authorize`
`(CLIProxyAPI: internal/auth/codex/openai_auth.go:25)`. Unlike Claude,
CLIProxyAPI's Codex refresh path never touches `chatgpt.com` — no separate
profile-lookup call was found in `internal/auth/codex/openai_auth.go`.

### b. Client ID / redirect URI / scope

```go
ClientID    = "app_EMoamEEZ73f0CkXaXp7hrann"
RedirectURI = "http://localhost:1455/auth/callback"
```
`(CLIProxyAPI: internal/auth/codex/openai_auth.go:27-28)`

Authorization-URL scope (code-exchange flow, for reference):
`"openid email profile offline_access"` `(CLIProxyAPI: internal/auth/codex/openai_auth.go:76)`.

`RedirectURI` is only used for the code exchange, not for refresh.

### c. Refresh request shape

- **Method**: `POST`
- **Body encoding**: `application/x-www-form-urlencoded` (note: this differs
  from Claude, which is JSON)
- **Body fields**:
  ```go
  data := url.Values{
      "client_id":     {ClientID},
      "grant_type":    {"refresh_token"},
      "refresh_token": {refreshToken},
      "scope":         {"openid profile email"},
  }
  ```
  `(CLIProxyAPI: internal/auth/codex/openai_auth.go:214-219)`

  Note the refresh-time scope (`"openid profile email"`) is a **different
  string** than the authorize-time scope (`"openid email profile
  offline_access"`, includes `offline_access` and different token/word
  order) — both are taken verbatim from the source, this is not a
  normalization on our part.

- **Headers**:
  ```go
  req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
  req.Header.Set("Accept", "application/json")
  ```
  `(CLIProxyAPI: internal/auth/codex/openai_auth.go:226-227)`

  No `User-Agent` override, no `originator` header, no TLS-fingerprint
  transport is applied to this request — the HTTP client is a plain
  `http.Client` with only proxy settings applied via `util.SetProxy`
  `(CLIProxyAPI: internal/auth/codex/openai_auth.go:59-61, internal/util/proxy.go:17-28)`.
  This is a real, confirmed contrast with the Claude path: Codex's refresh
  endpoint apparently does not require client-fingerprint mimicry to avoid
  being rejected (or at least CLIProxyAPI's authors didn't find it
  necessary), whereas Anthropic's does.

### d. Refresh response shape

```go
var tokenResp struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    IDToken      string `json:"id_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
}
```
`(CLIProxyAPI: internal/auth/codex/openai_auth.go:248-254)`

The response also returns a fresh `id_token` (JWT), which is parsed to
extract `account_id` and `email` via `ParseJWTToken` / `claims.GetAccountID()`
/ `claims.Email` `(CLIProxyAPI: internal/auth/codex/openai_auth.go:260-271,
jwt_parser.go)`. This matches the `id_token` field already observed in the
local `~/.codex/auth.json` `tokens` object.

**Refresh-token rotation**: unlike the Claude path, there is **no
empty-string fallback** here — `tokenResp.RefreshToken` from the response is
used directly and unconditionally:
```go
return &CodexTokenData{
    ...
    RefreshToken: tokenResp.RefreshToken,
    ...
}, nil
```
`(CLIProxyAPI: internal/auth/codex/openai_auth.go:273-280)`
and `UpdateTokenStorage` unconditionally overwrites the stored value:
```go
storage.RefreshToken = tokenData.RefreshToken
```
`(CLIProxyAPI: internal/auth/codex/openai_auth.go:344)`

**Strong evidence OpenAI's refresh tokens are rotating (single-use).** The
retry path treats a specific error code, `refresh_token_reused`, as
**non-retryable and fatal** — i.e. reusing an already-consumed refresh token
is a recognized, expected failure mode, not a transient error:
```go
func isNonRetryableRefreshErr(err error) bool {
    ...
    return strings.Contains(raw, "refresh_token_reused")
}
```
`(CLIProxyAPI: internal/auth/codex/openai_auth.go:331-337, wired into
RefreshTokensWithRetry at openai_auth.go:319-322)`. A unit test confirms the
exact server error shape this guards against:
```json
{"error":"invalid_grant","code":"refresh_token_reused"}
```
`(CLIProxyAPI: internal/auth/codex/openai_auth_test.go:78, 90-91)`

**Practical implication**: for Codex, the credential file MUST be rewritten
with the new refresh token after every refresh — reusing a stale
`refresh_token` from a previously-written file will fail with
`refresh_token_reused`. This is a materially stronger/more certain rotation
guarantee than what was found for Claude (where the code merely tolerates
rotation without asserting it always happens).

**Access-token TTL**: same pattern as Claude — read from `expires_in`
(seconds), no hardcoded fallback:
```go
Expire: time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second).Format(time.RFC3339)
```
`(CLIProxyAPI: internal/auth/codex/openai_auth.go:279)`
No concrete TTL value (mocked or otherwise) was found anywhere in
`internal/auth/codex/` — this is an open gap, see below.

### e. Provider-specific gotchas

1. **`refresh_token_reused` is a named, specifically-handled error** — see
   above. Any reimplementation should treat this error code as "the stored
   refresh token is stale; there is nothing to retry, surface an
   auth-required error to the caller" rather than retrying with backoff.

2. **Single-flight de-duplication**, same mechanism as Claude — concurrent
   refresh calls for the same refresh token are coalesced via
   `golang.org/x/sync/singleflight` so only one request goes to
   `auth.openai.com` `(CLIProxyAPI: internal/auth/codex/openai_auth.go:39,
   198-202, 213)`.

3. **Generic retry/backoff.** `RefreshTokensWithRetry` retries up to
   `maxRetries` times with a simple linear backoff (`attempt * 1 second`
   between attempts), aborting early only on `refresh_token_reused`
   `(CLIProxyAPI: internal/auth/codex/openai_auth.go:302-329)`. This is
   noticeably less sophisticated than Claude's 429-aware
   `Retry-After`-driven cooldown — no explicit 429/rate-limit handling was
   found in the Codex refresh path.

4. **No TLS fingerprint / header-order mimicry** for the refresh call itself
   — see (c) above. This is the clearest confirmed asymmetry between the two
   providers in this codebase: Anthropic's OAuth control plane gets the full
   uTLS + ordered-header treatment; OpenAI's does not, in this refresh path.
   (Note: this only describes the **token-refresh** code path audited here;
   it's possible OpenAI-facing *inference* traffic elsewhere in the repo,
   e.g. `internal/client/codex/`, does its own User-Agent mimicry for
   completions/responses calls — that was not investigated, since it's out of
   scope for OAuth refresh.)

---

## Open questions / gaps

- **Exact access-token TTL for Anthropic**: CLIProxyAPI's source never
  hardcodes a TTL; it always trusts the response's `expires_in`. The only
  number in the repo is `3600` (1 hour), and it appears solely as a mock
  value inside a unit test's fake HTTP response
  `(CLIProxyAPI: internal/auth/claude/anthropic_auth_test.go:433)`, not as
  an asserted/documented production constant. **Unconfirmed from
  CLIProxyAPI source** whether real Anthropic OAuth access tokens are
  actually issued with a 1-hour TTL in production; 1 hour is a common OAuth2
  default and plausible, but this doc does not claim it as confirmed.

- **Exact access-token TTL for OpenAI/Codex**: no TTL value, hardcoded or
  mocked, was found anywhere in `internal/auth/codex/`. This is a full gap —
  CLIProxyAPI's source provides no signal at all on the real-world
  `expires_in` value Codex's endpoint returns. Not corroborated from any
  other source in this research pass either.

- **Does Anthropic's endpoint actually rotate refresh tokens in production?**
  CLIProxyAPI's code is written defensively to handle both cases (rotating
  and non-rotating), and its own test mocks a **non-rotating** response
  (server omits `refresh_token`, code falls back to reusing the sent token)
  `(CLIProxyAPI: internal/auth/claude/anthropic_auth_test.go:431-461)`. This
  is weaker evidence than the Codex side, where a specific
  `refresh_token_reused` error is explicitly handled, strongly implying real
  single-use rotation. For Anthropic, treat rotation behavior as **unknown /
  unconfirmed** — a safe implementation should always persist whatever
  `refresh_token` comes back (or the original, if none is returned) after
  every refresh, exactly as CLIProxyAPI does, rather than assuming either
  policy.

- **Whether Anthropic's OAuth control plane truly requires the uTLS/Axios
  mimicry to succeed**, or whether that's defense-in-depth by CLIProxyAPI's
  authors against Cloudflare bot detection that may or may not trigger for
  all callers/IPs. Not something the source code alone can confirm one way
  or the other — the fact that this much effort went into replicating
  `axios/1.15.2`'s exact ClientHello and header order is strong circumstantial
  evidence it was necessary at some point, but the current necessity wasn't
  independently verified here (would require live testing against the
  endpoint, which was out of scope for this source-reading pass).

- **Whether OpenAI's `/oauth/token` endpoint does any client-fingerprint
  enforcement.** CLIProxyAPI's Codex refresh path does none, which is either
  evidence it isn't needed, or evidence CLIProxyAPI simply hasn't hit that
  wall yet for this specific endpoint. No corroborating external source was
  checked for this in this research pass.

- **`internal/client/codex/` inference-time headers** (e.g. the
  `codex_cli_rs/x.y.z` User-Agent strings visible in
  `internal/client/codex/optimize-multi-agent-v2/optimize_multi_agent_v2_test.go`)
  were noticed in passing but not investigated — those apply to Codex
  *chat/completions* traffic, not to the OAuth token-refresh call, and are
  out of scope for this document.
