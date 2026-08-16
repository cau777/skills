from orca_proxy.redaction import redact_headers


def test_allowlisted_header_kept_verbatim():
    result = redact_headers([("User-Agent", "curl/8.0")], None, None)
    assert result == [{"name": "User-Agent", "value": "curl/8.0", "redacted": False, "redaction_reason": None}]


def test_unknown_header_redacted():
    result = redact_headers([("Cookie", "secret=1")], None, None)
    assert result == [
        {"name": "Cookie", "value": "[REDACTED]", "redacted": True, "redaction_reason": "not_allowlisted"}
    ]


def test_injected_header_gets_distinct_placeholder():
    result = redact_headers([("Authorization", "Bearer xyz")], "Authorization", "github-host-login")
    assert result == [
        {
            "name": "Authorization",
            "value": "[REDACTED · injected by github-host-login]",
            "redacted": True,
            "redaction_reason": "injected",
        }
    ]


def test_allowlist_check_is_case_insensitive():
    result = redact_headers([("HOST", "api.github.com")], None, None)
    assert result[0]["redacted"] is False


def test_credential_value_never_appears_in_output():
    result = redact_headers([("Authorization", "Bearer super-secret-token")], "Authorization", "gh")
    assert "super-secret-token" not in str(result)
