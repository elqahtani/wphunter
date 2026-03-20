"""AI-powered analysis of scan results using Claude API.

Requires authentication via auth.py (API key or OAuth token).
"""
import json
from typing import Optional, List

import requests

from auth import AuthCredential
from apis.token_tracker import TokenTracker
from config import AI_MODEL


class AIAnalyzer:
    """Analyze scan findings using Claude API."""

    def __init__(self, credential: AuthCredential, tracker: TokenTracker,
                 model: str = ""):
        self.credential = credential
        self.tracker = tracker
        self.model = model or AI_MODEL
        self.tracker.is_subscription = credential.is_subscription

    def _call_api(self, messages: list, purpose: str,
                  system: str = "") -> Optional[dict]:
        """Make Claude API call and record token usage."""
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
