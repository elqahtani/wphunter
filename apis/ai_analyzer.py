"""AI-powered analysis of scan results using Claude API.

Supports two backends:
  1. Direct API (requests) — works with API keys and OAuth tokens (haiku only)
  2. Claude Agent SDK — works with Claude Code subscription (sonnet/opus)
     Auto-detected when claude-agent-sdk is installed and user has OAuth auth.
"""
import json
from typing import Optional, List

import requests

from auth import AuthCredential
from apis.token_tracker import TokenTracker
from config import AI_MODEL, AI_MODEL_OAUTH

# Try to import claude-agent-sdk for subscription-based access
_HAS_AGENT_SDK = False
try:
    import asyncio
    from claude_agent_sdk import query as sdk_query, ClaudeAgentOptions
    from claude_agent_sdk import AssistantMessage, TextBlock, ResultMessage
    _HAS_AGENT_SDK = True
except ImportError:
    pass


class AIAnalyzer:
    """Analyze scan findings using Claude API."""

    def __init__(self, credential: AuthCredential, tracker: TokenTracker,
                 model: str = ""):
        self.credential = credential
        self.tracker = tracker
        # Determine backend and model
        self.use_sdk = (
            _HAS_AGENT_SDK
            and credential.auth_type == "oauth_token"
            and not model  # user didn't force a specific model
        )
        if model:
            self.model = model
        elif self.use_sdk:
            self.model = AI_MODEL  # SDK can use sonnet/opus via subscription
        elif credential.auth_type == "oauth_token":
            self.model = AI_MODEL_OAUTH  # direct API: OAuth limited to haiku
        else:
            self.model = AI_MODEL
        self.tracker.is_subscription = credential.is_subscription

    def _call_sdk(self, messages: list, purpose: str,
                  system: str = "") -> Optional[dict]:
        """Call Claude via Agent SDK (subprocess through Claude Code CLI)."""
        user_content = messages[0]["content"] if messages else ""

        options = ClaudeAgentOptions(
            model=self.model,
            system_prompt=system or None,
            max_turns=1,
        )

        collected_text = []
        usage_data = {}

        async def _run():
            async for message in sdk_query(prompt=user_content, options=options):
                if isinstance(message, AssistantMessage):
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            collected_text.append(block.text)
                elif isinstance(message, ResultMessage):
                    if hasattr(message, "usage") and message.usage:
                        usage_data.update(message.usage)

        asyncio.run(_run())

        if not collected_text:
            return None

        full_text = "".join(collected_text)
        result = {
            "content": [{"type": "text", "text": full_text}],
            "usage": usage_data,
        }
        self.tracker.record(
            model=self.model,
            purpose=purpose,
            usage=usage_data,
        )
        return result

    def _call_api(self, messages: list, purpose: str,
                  system: str = "") -> Optional[dict]:
        """Make Claude API call and record token usage."""
        if self.use_sdk:
            return self._call_sdk(messages, purpose, system)

        body = {
            "model": self.model,
            "max_tokens": 4096,
            "messages": messages,
        }
        if system:
            body["system"] = system

        try:
            resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers=self.credential.get_headers(),
                json=body,
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()

            self.tracker.record(
                model=self.model,
                purpose=purpose,
                usage=data.get("usage", {}),
            )
            return data

        except requests.HTTPError as e:
            print(f"    [!] AI API error: {e}")
            if resp is not None:
                try:
                    print(f"    [!] Response: {resp.text[:500]}")
                except Exception:
                    pass
            return None
        except requests.RequestException as e:
            print(f"    [!] AI API error: {e}")
            return None

    def _extract_text(self, response: dict) -> str:
        """Extract text content from API response."""
        content = response.get("content", [])
        return "".join(
            block.get("text", "") for block in content
            if block.get("type") == "text"
        )

    def analyze_judol(self, judol_result) -> Optional[dict]:
        """Analyze judol scan results for deeper insights."""
        print("[*] AI: Analyzing judol findings...")

        findings_json = json.dumps(judol_result.to_dict(), indent=2, ensure_ascii=False)
        # Truncate if too long
        if len(findings_json) > 12000:
            findings_json = findings_json[:12000] + "\n... (truncated)"

        system_prompt = (
            "You are a WordPress security expert specializing in Indonesian gambling "
            "(judol/judi online) spam injection analysis. Analyze the scan findings "
            "and provide a structured assessment. Be specific and actionable."
        )

        user_prompt = f"""Analyze these judol injection scan results:

```json
{findings_json}
```

Provide your analysis in this JSON format:
{{
  "classification": "judol|pharma|seo_spam|clean",
  "severity_assessment": "description of how widespread and deep the infection is",
  "likely_infection_vector": "which vulnerable plugin/theme or method was likely used",
  "cloaking_analysis": "details about the cloaking technique if detected",
  "remediation_steps": ["step 1", "step 2", ...],
  "executive_summary": "2-3 sentence summary for non-technical stakeholders",
  "executive_summary_id": "same summary in Bahasa Indonesia"
}}"""

        response = self._call_api(
            messages=[{"role": "user", "content": user_prompt}],
            purpose="judol_analysis",
            system=system_prompt,
        )

        if not response:
            return None

        text = self._extract_text(response)
        # Try to parse JSON from response
        try:
            # Find JSON block in response
            json_match = text
            if "```json" in text:
                json_match = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                json_match = text.split("```")[1].split("```")[0]
            return json.loads(json_match.strip())
        except (json.JSONDecodeError, IndexError):
            return {"raw_analysis": text}

    def analyze_vulns(self, vulns: list) -> Optional[dict]:
        """Analyze vulnerability findings for risk assessment."""
        if not vulns:
            return None

        print("[*] AI: Analyzing vulnerability findings...")

        vuln_summary = []
        for v in vulns[:30]:  # Limit to top 30
            vuln_summary.append({
                "package": v.package, "version": v.version,
                "cve_id": v.cve_id, "cvss_score": v.cvss_score,
                "severity": v.severity, "summary": v.summary,
                "fix_version": v.fix_version,
            })

        system_prompt = (
            "You are a WordPress security expert. Analyze the vulnerability "
            "scan results and provide risk assessment with prioritized remediation steps."
        )

        user_prompt = f"""Analyze these WordPress vulnerability scan results:

```json
{json.dumps(vuln_summary, indent=2)}
```

Provide your analysis in this JSON format:
{{
  "risk_level": "critical|high|medium|low",
  "risk_summary": "overall risk assessment",
  "top_priorities": ["most urgent action 1", "action 2", ...],
  "remediation_steps": ["step 1", "step 2", ...],
  "executive_summary": "2-3 sentence summary"
}}"""

        response = self._call_api(
            messages=[{"role": "user", "content": user_prompt}],
            purpose="vuln_analysis",
            system=system_prompt,
        )

        if not response:
            return None

        text = self._extract_text(response)
        try:
            json_match = text
            if "```json" in text:
                json_match = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                json_match = text.split("```")[1].split("```")[0]
            return json.loads(json_match.strip())
        except (json.JSONDecodeError, IndexError):
            return {"raw_analysis": text}
