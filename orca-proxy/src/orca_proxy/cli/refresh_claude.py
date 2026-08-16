"""Claude Code OAuth refresh — a Credential command (#2's researched wire
format, confirmed from CLIProxyAPI source at commit 78f0c407):

- POST https://platform.claude.com/v1/oauth/token, JSON body — NOT
  api.anthropic.com.
- client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e, grant_type=refresh_token,
  refresh_token=<from ~/.claude/.credentials.json's claudeAiOauth.refreshToken>,
  scope=<the full ClaudeOAuthScope string below>.
- Response may omit `refresh_token` (falls back to reusing the sent one);
  the credential file is always rewritten regardless, since the access
  token always changes.

Known gap, stated plainly rather than silently assumed: the real Claude
Code CLI sends this request through a uTLS-based client mimicking a
Node/Axios TLS fingerprint specifically to dodge Cloudflare bot detection
(per the research). This script only replicates the *application-layer*
headers (User-Agent, Accept, etc.) via Python's stdlib HTTP client — per
design ticket #4's explicit v1 default ("begin with ordinary HTTP...
introduce curl_cffi only if compatibility testing proves it necessary"). If
Cloudflare rejects the plain-TLS handshake in practice, that's the signal
#4 anticipated for pulling in curl_cffi — not yet done here since it hasn't
been live-verified either way.
"""

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

TOKEN_URL = "https://platform.claude.com/v1/oauth/token"
CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
SCOPE = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"


def default_credentials_file() -> Path:
    return Path.home() / ".claude" / ".credentials.json"


# Mimics the real client's headers (research: applyClaudeOAuthAxiosHeaders) —
# the application-layer half of that mimicry; see the module docstring for
# the TLS-fingerprint half this does NOT attempt.
HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/json",
    "User-Agent": "axios/1.15.2",
    "Accept-Encoding": "gzip, compress, deflate, br",
    "Connection": "close",
}


def refresh(refresh_token: str, urlopen=urllib.request.urlopen) -> dict:
    body = json.dumps(
        {"client_id": CLIENT_ID, "grant_type": "refresh_token", "refresh_token": refresh_token, "scope": SCOPE}
    ).encode()
    request = urllib.request.Request(TOKEN_URL, data=body, method="POST", headers=HEADERS)
    with urlopen(request, timeout=15) as response:
        return json.loads(response.read())


def main(credentials_file: Path | None = None, urlopen=urllib.request.urlopen) -> int:
    credentials_file = credentials_file or default_credentials_file()
    try:
        credentials = json.loads(credentials_file.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"could not read {credentials_file}: {exc}", file=sys.stderr)
        return 1

    oauth = credentials.get("claudeAiOauth", {})
    refresh_token = oauth.get("refreshToken")
    if not refresh_token:
        print(
            f"{credentials_file}: claudeAiOauth.refreshToken missing — run `claude` and log in on this host first",
            file=sys.stderr,
        )
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
    if not access_token:
        print("refresh response missing access_token", file=sys.stderr)
        return 1
    # Confirmed by the research: the response CAN omit refresh_token, in
    # which case the original one stays valid — never null it out.
    new_refresh_token = token_response.get("refresh_token") or refresh_token

    credentials["claudeAiOauth"]["refreshToken"] = new_refresh_token
    # `accessToken` as the sibling key is an inference from the established
    # camelCase convention in this same object, not independently confirmed
    # by #2's research (which scoped the wire format, not the full local
    # file shape) — see refresh_codex.py's identical caveat for access_token.
    credentials["claudeAiOauth"]["accessToken"] = access_token
    tmp_path = credentials_file.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(credentials, indent=2))
    tmp_path.replace(credentials_file)

    print(access_token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
