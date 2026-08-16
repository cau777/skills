import json
import urllib.error

import pytest

from orca_proxy.cli import refresh_claude, refresh_codex


class FakeResponse:
    def __init__(self, body: dict):
        self._body = json.dumps(body).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_urlopen(body: dict, captured: dict):
    def urlopen(request, timeout=None):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse(body)

    return urlopen


def _raising_urlopen(exc):
    def urlopen(request, timeout=None):
        raise exc

    return urlopen


# --- refresh_codex ---

def test_codex_refresh_sends_confirmed_wire_shape():
    captured = {}
    codex_body = {"access_token": "new-access", "refresh_token": "new-refresh"}
    refresh_codex.refresh("old-refresh", urlopen=_fake_urlopen(codex_body, captured))

    request = captured["request"]
    assert request.full_url == "https://auth.openai.com/oauth/token"
    assert request.get_header("Content-type") == "application/x-www-form-urlencoded"
    assert request.get_header("Accept") == "application/json"
    body = request.data.decode()
    assert "client_id=app_EMoamEEZ73f0CkXaXp7hrann" in body
    assert "grant_type=refresh_token" in body
    assert "refresh_token=old-refresh" in body
    assert "scope=openid+profile+email" in body


def test_codex_main_rewrites_auth_file_and_prints_access_token(tmp_path, capsys):
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(json.dumps({"tokens": {"refresh_token": "old-refresh", "account_id": "keep-me"}}))

    codex_body = {"access_token": "new-access", "refresh_token": "new-refresh"}
    exit_code = refresh_codex.main(auth_file, urlopen=_fake_urlopen(codex_body, {}))

    assert exit_code == 0
    assert capsys.readouterr().out.strip() == "new-access"
    rewritten = json.loads(auth_file.read_text())
    assert rewritten["tokens"]["refresh_token"] == "new-refresh"
    assert rewritten["tokens"]["access_token"] == "new-access"
    assert rewritten["tokens"]["account_id"] == "keep-me"  # untouched fields preserved


def test_codex_main_missing_refresh_token_fails_without_network_call(tmp_path, capsys):
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(json.dumps({"tokens": {}}))

    def exploding_urlopen(request, timeout=None):
        raise AssertionError("should never be called")

    exit_code = refresh_codex.main(auth_file, urlopen=exploding_urlopen)
    assert exit_code == 1
    assert "refresh_token missing" in capsys.readouterr().err


def test_codex_main_http_error_prints_no_stdout_and_fails(tmp_path, capsys):
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(json.dumps({"tokens": {"refresh_token": "old"}}))

    class FakeHTTPError(urllib.error.HTTPError):
        def __init__(self):
            super().__init__("url", 400, "Bad Request", {}, None)

        def read(self):
            return b'{"error":"refresh_token_reused"}'

    exit_code = refresh_codex.main(auth_file, urlopen=_raising_urlopen(FakeHTTPError()))
    assert exit_code == 1
    out, err = capsys.readouterr()
    assert out == ""  # never prints partial/garbage output on failure
    assert "refresh_token_reused" in err


def test_codex_main_response_missing_fields_fails(tmp_path, capsys):
    auth_file = tmp_path / "auth.json"
    auth_file.write_text(json.dumps({"tokens": {"refresh_token": "old"}}))
    exit_code = refresh_codex.main(auth_file, urlopen=_fake_urlopen({"access_token": "x"}, {}))
    assert exit_code == 1
    assert "missing access_token or refresh_token" in capsys.readouterr().err


# --- refresh_claude ---

def test_claude_refresh_sends_confirmed_wire_shape():
    captured = {}
    claude_body = {"access_token": "new-access", "refresh_token": "new-refresh"}
    refresh_claude.refresh("old-refresh", urlopen=_fake_urlopen(claude_body, captured))

    request = captured["request"]
    assert request.full_url == "https://platform.claude.com/v1/oauth/token"
    assert request.get_header("Content-type") == "application/json"
    assert request.get_header("User-agent") == "axios/1.15.2"
    body = json.loads(request.data.decode())
    assert body == {
        "client_id": "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
        "grant_type": "refresh_token",
        "refresh_token": "old-refresh",
        "scope": refresh_claude.SCOPE,
    }


def test_claude_main_rewrites_credentials_file(tmp_path, capsys):
    credentials_file = tmp_path / ".credentials.json"
    credentials_file.write_text(
        json.dumps({"claudeAiOauth": {"refreshToken": "old-refresh", "subscriptionType": "keep-me"}})
    )

    claude_body = {"access_token": "new-access", "refresh_token": "new-refresh"}
    exit_code = refresh_claude.main(credentials_file, urlopen=_fake_urlopen(claude_body, {}))

    assert exit_code == 0
    assert capsys.readouterr().out.strip() == "new-access"
    rewritten = json.loads(credentials_file.read_text())
    assert rewritten["claudeAiOauth"]["refreshToken"] == "new-refresh"
    assert rewritten["claudeAiOauth"]["accessToken"] == "new-access"
    assert rewritten["claudeAiOauth"]["subscriptionType"] == "keep-me"


def test_claude_main_preserves_refresh_token_when_response_omits_it(tmp_path):
    # Confirmed by the research: rotation is optional, not guaranteed.
    credentials_file = tmp_path / ".credentials.json"
    credentials_file.write_text(json.dumps({"claudeAiOauth": {"refreshToken": "old-refresh"}}))

    claude_body = {"access_token": "new-access"}  # no refresh_token in the response
    refresh_claude.main(credentials_file, urlopen=_fake_urlopen(claude_body, {}))

    rewritten = json.loads(credentials_file.read_text())
    assert rewritten["claudeAiOauth"]["refreshToken"] == "old-refresh"


def test_claude_main_missing_refresh_token_fails_without_network_call(tmp_path, capsys):
    credentials_file = tmp_path / ".credentials.json"
    credentials_file.write_text(json.dumps({"claudeAiOauth": {}}))

    def exploding_urlopen(request, timeout=None):
        raise AssertionError("should never be called")

    exit_code = refresh_claude.main(credentials_file, urlopen=exploding_urlopen)
    assert exit_code == 1
    assert "refreshToken missing" in capsys.readouterr().err
