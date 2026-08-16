"""Header redaction for request logs (design ticket #11).

Allowlist, not blocklist: an unknown header defaults to redacted, so the
credential-never-leaks guarantee fails safe against headers nobody thought to
enumerate. Bodies are never logged at all — that decision has no code
counterpart, it's simply that no caller here is ever handed a body to log.
"""

ALLOWLISTED_HEADERS = {
    "user-agent",
    "accept",
    "accept-encoding",
    "accept-language",
    "content-type",
    "content-length",
    "host",
}


def redact_headers(
    headers: list[tuple[str, str]], injected_header_name: str | None, credential_name: str | None
) -> list[dict]:
    """Render raw (name, value) header pairs into the log's redacted shape.

    `injected_header_name`/`credential_name` identify the one header (if any)
    a Credential actually wrote on this request — it gets a distinct
    placeholder naming which Credential injected it, per #11.
    """
    result = []
    for name, value in headers:
        lower = name.lower()
        if injected_header_name is not None and lower == injected_header_name.lower():
            result.append(
                {
                    "name": name,
                    "value": f"[REDACTED · injected by {credential_name}]",
                    "redacted": True,
                    "redaction_reason": "injected",
                }
            )
        elif lower in ALLOWLISTED_HEADERS:
            result.append({"name": name, "value": value, "redacted": False, "redaction_reason": None})
        else:
            result.append(
                {"name": name, "value": "[REDACTED]", "redacted": True, "redaction_reason": "not_allowlisted"}
            )
    return result
