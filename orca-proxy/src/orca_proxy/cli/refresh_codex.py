"""Codex CLI OAuth refresh — a Credential command (#2's researched wire
format, confirmed from CLIProxyAPI source at commit 78f0c407):

- POST https://auth.openai.com/oauth/token, form-urlencoded
- client_id=app_EMoamEEZ73f0CkXaXp7hrann, grant_type=refresh_token,
  refresh_token=<from ~/.codex/auth.json's tokens.refresh_token>,
  scope="openid profile email"
- Headers: Content-Type: application/x-www-form-urlencoded, Accept:
  application/json — no TLS/header mimicry needed for this endpoint,
  confirmed by the research as a real contrast with Claude's endpoint below.
- Codex's refresh tokens are effectively single-use (CLIProxyAPI treats a
  `refresh_token_reused` error as fatal) — the credential file MUST be
  rewritten after every successful refresh, unconditionally.

Prints the fresh access token to stdout on success (this becomes the
Credential Value, per design ticket #10) and exits nonzero on any failure —
never printing partial output on error, so a failed refresh can't be
mistaken for a valid (truncated) token by the Credential execution engine's
output validation.
"""

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlencode

TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
SCOPE = "openid profile email"


def default_auth_file() -> Path:
    return Path.home() / ".codex" / "auth.json"


def refresh(refresh_token: str, urlopen=urllib.request.urlopen) -> dict:
    body = urlencode(
        {"client_id": CLIENT_ID, "grant_type": "refresh_token", "refresh_token": refresh_token, "scope": SCOPE}
    ).encode()
    request = urllib.request.Request(
        TOKEN_URL,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    with urlopen(request, timeout=15) as response:
        return json.loads(response.read())


def main(auth_file: Path | None = None, urlopen=urllib.request.urlopen) -> int:
    auth_file = auth_file or default_auth_file()
    try:
        auth = json.loads(auth_file.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"could not read {auth_file}: {exc}", file=sys.stderr)
        return 1

    refresh_token = auth.get("tokens", {}).get("refresh_token")
    if not refresh_token:
        print(f"{auth_file}: tokens.refresh_token missing — run `codex login` on this host first", file=sys.stderr)
        return 1

    try:
        token_response = refresh(refresh_token, urlopen=urlopen)
    except urllib.error.HTTPError as exc:
        print(f"refresh failed: HTTP {exc.code} {exc.read().decode(errors='replace')}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"refresh failed: {exc}", file=sys.stderr)
        return 1

    access_token = token_response.get("access_token")
    new_refresh_token = token_response.get("refresh_token")
    if not access_token or not new_refresh_token:
        print("refresh response missing access_token or refresh_token", file=sys.stderr)
        return 1

    # Unconditional rewrite — single-use refresh tokens mean skipping this
    # burns the credential (#2). `tokens.refresh_token` is confirmed (#2's
    # ticket body); `tokens.access_token` as its sibling key is a reasonable
    # but NOT independently confirmed inference (the wire response's
    # `access_token` field is confirmed, the local file's storage key for it
    # was outside #2's researched scope) — flagged here rather than silently
    # assumed. Everything else in the file is preserved as-is.
    auth["tokens"]["refresh_token"] = new_refresh_token
    auth["tokens"]["access_token"] = access_token
    tmp_path = auth_file.with_suffix(".json.tmp")
    # Path.write_text() creates the tmp file at umask-default perms
    # (typically 0o644 — world-readable) and Path.replace() carries that
    # mode straight through to the target, silently downgrading this OAuth
    # credential file from the CLI's own 0o600 on every refresh (every
    # refresh, unconditionally, since Codex refresh tokens are single-use).
    original_mode = auth_file.stat().st_mode  # already confirmed to exist, above
    tmp_path.write_text(json.dumps(auth, indent=2))
    tmp_path.chmod(original_mode)
    tmp_path.replace(auth_file)

    print(access_token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
