"""Tests for authentication system."""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from auth import AuthCredential, resolve_credential


class TestAuthCredential:

    def test_api_key_headers(self):
        cred = AuthCredential(
            token="sk-ant-api03-test", auth_type="api_key",
            source="env", is_subscription=False,
        )
        headers = cred.get_headers()
        assert headers["x-api-key"] == "sk-ant-api03-test"
        assert "authorization" not in headers

    def test_oauth_headers(self):
        cred = AuthCredential(
            token="sk-ant-oat01-test", auth_type="oauth_token",
            source="env", is_subscription=True,
        )
        headers = cred.get_headers()
        assert headers["authorization"] == "Bearer sk-ant-oat01-test"
        assert "x-api-key" not in headers

    def test_billing_mode_api(self):
        cred = AuthCredential(
            token="test", auth_type="api_key",
            source="env", is_subscription=False,
        )
        assert "pay-per-token" in cred.billing_mode

    def test_billing_mode_subscription(self):
        cred = AuthCredential(
            token="test", auth_type="oauth_token",
            source="env", is_subscription=True,
        )
        assert "subscription" in cred.billing_mode


class TestResolveCredential:

    def test_no_credentials(self):
        # Clear all env vars
        env_vars = ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"]
        old_values = {}
        for var in env_vars:
            old_values[var] = os.environ.pop(var, None)

        try:
            # resolve_credential may still find file-based creds,
            # so we just verify it doesn't crash
            resolve_credential()
        finally:
            for var, val in old_values.items():
                if val is not None:
                    os.environ[var] = val

    def test_api_key_from_env(self):
        old = os.environ.get("ANTHROPIC_API_KEY")
        os.environ["ANTHROPIC_API_KEY"] = "sk-ant-api03-test-key"
        try:
            cred = resolve_credential()
            assert cred is not None
            assert cred.auth_type == "api_key"
            assert cred.source == "env"
            assert cred.is_subscription is False
        finally:
            if old:
                os.environ["ANTHROPIC_API_KEY"] = old
            else:
                del os.environ["ANTHROPIC_API_KEY"]
