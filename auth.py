"""Authentication manager for wphunter AI features.

Supports: Anthropic API Key, Claude Code OAuth Token, or interactive connect flow.
"""
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests


@dataclass
class AuthCredential:
    token: str
    auth_type: str          # "api_key", "oauth_token"
    source: str             # "env", "config", "claude_code", "interactive"
    is_subscription: bool   # True = uses subscription quota

    @property
    def header_value(self) -> str:
        """Return the correct Authorization header value."""
        if self.auth_type == "oauth_token":
            return f"Bearer {self.token}"
        return self.token

    @property
    def billing_mode(self) -> str:
        return "subscription (Claude Pro/Max)" if self.is_subscription else "pay-per-token (API)"

    def get_headers(self) -> dict:
        """Return headers dict for Anthropic API requests."""
        headers = {
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        if self.auth_type == "api_key":
            headers["x-api-key"] = self.token
        else:
            headers["authorization"] = f"Bearer {self.token}"
            # OAuth tokens require beta header
            headers["anthropic-beta"] = "oauth-2025-04-20"
        return headers


def resolve_credential() -> Optional[AuthCredential]:
    """Resolve authentication credential in priority order.

    1. ANTHROPIC_API_KEY env var
    2. ANTHROPIC_AUTH_TOKEN env var (OAuth bearer)
    3. CLAUDE_CODE_OAUTH_TOKEN env var
    4. Claude Code credentials file (~/.claude/.credentials.json)
    5. wphunter config file (~/.wphunter/auth.json)
    """
    # 1. Standard API Key
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if api_key and api_key.startswith("sk-ant-api"):
        return AuthCredential(
            token=api_key, auth_type="api_key",
            source="env", is_subscription=False,
        )

    # 2. Auth token (bearer)
    auth_token = os.getenv("ANTHROPIC_AUTH_TOKEN", "")
    if auth_token:
        return AuthCredential(
            token=auth_token, auth_type="oauth_token",
            source="env", is_subscription=auth_token.startswith("sk-ant-oat"),
        )

    # 3. Claude Code OAuth Token
    cc_token = os.getenv("CLAUDE_CODE_OAUTH_TOKEN", "")
    if cc_token:
        try:
            data = json.loads(cc_token)
            access_token = data.get("accessToken", cc_token)
        except (json.JSONDecodeError, TypeError):
            access_token = cc_token
        return AuthCredential(
            token=access_token, auth_type="oauth_token",
            source="env", is_subscription=True,
        )

    # 4. Claude Code credentials file
    cred = _read_claude_code_credentials()
    if cred:
        return cred

    # 5. wphunter saved config
    return _read_wphunter_config()


def _read_claude_code_credentials() -> Optional[AuthCredential]:
    """Read OAuth token from Claude Code credential storage."""
    cred_path = Path.home() / ".claude" / ".credentials.json"
    if not cred_path.exists():
        return None
    try:
        data = json.loads(cred_path.read_text())
        oauth_data = data.get("claudeAiOauth", {})
        access_token = oauth_data.get("accessToken")
        if access_token:
            return AuthCredential(
                token=access_token, auth_type="oauth_token",
                source="claude_code", is_subscription=True,
            )
    except (json.JSONDecodeError, KeyError, PermissionError):
        pass
    return None


def _read_wphunter_config() -> Optional[AuthCredential]:
    """Read saved credential from ~/.wphunter/auth.json."""
    config_path = Path.home() / ".wphunter" / "auth.json"
    if not config_path.exists():
        return None
    try:
        data = json.loads(config_path.read_text())
        return AuthCredential(
            token=data["token"], auth_type=data["auth_type"],
            source="config", is_subscription=data.get("is_subscription", False),
        )
    except (json.JSONDecodeError, KeyError, PermissionError):
        pass
    return None


def save_credential(credential: AuthCredential) -> Path:
    """Save credential to ~/.wphunter/auth.json."""
    config_dir = Path.home() / ".wphunter"
    config_dir.mkdir(exist_ok=True)
    config_path = config_dir / "auth.json"
    config_path.write_text(json.dumps({
        "token": credential.token,
        "auth_type": credential.auth_type,
        "is_subscription": credential.is_subscription,
        "source": "interactive",
    }))
    config_path.chmod(0o600)
    return config_path


def validate_token(credential: AuthCredential) -> bool:
    """Test the token with a minimal API request."""
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers=credential.get_headers(),
            json={
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 10,
                "messages": [{"role": "user", "content": "hi"}],
            },
            timeout=15,
        )
        return resp.status_code == 200
    except requests.RequestException:
        return False


def interactive_connect() -> AuthCredential:
    """Interactive authentication flow for `wphunter connect`."""
    from rich.console import Console
    from rich.panel import Panel

    console = Console()

    console.print(Panel.fit(
        "[bold cyan]wphunter AI Authentication Setup[/]\n\n"
        "Choose how to authenticate with Claude AI:\n\n"
        "[1] [bold]Anthropic API Key[/] (sk-ant-api03-...)\n"
        "    Pay-per-token billing. Get key at: console.anthropic.com\n\n"
        "[2] [bold]Claude Code OAuth Token[/] (sk-ant-oat01-...)\n"
        "    Uses your Claude Pro/Max subscription quota.\n"
        "    Run [cyan]claude setup-token[/] in Claude Code to get this.\n\n"
        "[3] [bold]Auto-detect from Claude Code[/]\n"
        "    Reads token from ~/.claude/.credentials.json\n"
        "    (Requires Claude Code installed and logged in)",
        title="Connect to Claude AI",
        border_style="cyan",
    ))

    choice = input("Select option [1/2/3]: ").strip()

    if choice == "1":
        token = input("Enter your Anthropic API Key: ").strip()
        if not token.startswith("sk-ant-api"):
            console.print("[yellow]Warning: Token doesn't look like an API key (expected sk-ant-api...)[/]")
        credential = AuthCredential(
            token=token, auth_type="api_key",
            source="interactive", is_subscription=False,
        )

    elif choice == "2":
        console.print("\n[dim]Tip: Run 'claude setup-token' in your terminal to get your OAuth token.[/]")
        token = input("Enter your Claude Code OAuth Token: ").strip()
        if not token.startswith("sk-ant-oat"):
            console.print("[yellow]Warning: Token doesn't look like an OAuth token (expected sk-ant-oat...)[/]")
        credential = AuthCredential(
            token=token, auth_type="oauth_token",
            source="interactive", is_subscription=True,
        )

    elif choice == "3":
        credential = _read_claude_code_credentials()
        if not credential:
            console.print("[red]Could not find Claude Code credentials.[/]")
            console.print("Make sure Claude Code is installed and you're logged in.")
            sys.exit(1)
        console.print("[green]Found OAuth token from Claude Code![/]")

    else:
        console.print("[red]Invalid option.[/]")
        sys.exit(1)

    # Validate
    console.print("\n[dim]Validating token...[/]")
    if validate_token(credential):
        path = save_credential(credential)
        console.print("[green]Authentication successful![/]")
        console.print(f"[dim]Credential saved to {path}[/]")
        console.print(f"[dim]Billing mode: {credential.billing_mode}[/]")
        return credential
    else:
        console.print("[red]Authentication failed. Check your token and try again.[/]")
        sys.exit(1)
