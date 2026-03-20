"""Token usage tracker for wphunter AI features.

Tracks input/output tokens across all Claude API calls during a scan session
and provides cost breakdown.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List

# Pricing per million tokens (USD)
MODEL_PRICING = {
    "claude-sonnet-4-6-20250218":  (3.00, 15.00),
    "claude-sonnet-4-20250514":    (3.00, 15.00),
    "claude-haiku-4-5-20251001":   (1.00, 5.00),
    "claude-opus-4-6-20250207":    (5.00, 25.00),
    "claude-sonnet-4-6":           (3.00, 15.00),
    "claude-sonnet-4":             (3.00, 15.00),
    "claude-haiku-4-5":            (1.00, 5.00),
    "claude-opus-4-6":             (5.00, 25.00),
}


@dataclass
class APICallRecord:
    """Single API call record."""
    timestamp: str
    model: str
    purpose: str
    input_tokens: int
    output_tokens: int

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def input_cost(self) -> float:
        rate = MODEL_PRICING.get(self.model, (3.00, 15.00))[0]
        return (self.input_tokens / 1_000_000) * rate

    @property
    def output_cost(self) -> float:
        rate = MODEL_PRICING.get(self.model, (3.00, 15.00))[1]
        return (self.output_tokens / 1_000_000) * rate

    @property
    def total_cost(self) -> float:
        return self.input_cost + self.output_cost


@dataclass
class TokenTracker:
    """Tracks token usage across all API calls in a scan session."""
    calls: List[APICallRecord] = field(default_factory=list)
    is_subscription: bool = False

    def record(self, model: str, purpose: str, usage: dict):
        """Record an API call from the Anthropic API usage dict."""
        self.calls.append(APICallRecord(
            timestamp=datetime.now().isoformat(),
            model=model,
            purpose=purpose,
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
        ))

    @property
    def total_input_tokens(self) -> int:
        return sum(c.input_tokens for c in self.calls)

    @property
    def total_output_tokens(self) -> int:
        return sum(c.output_tokens for c in self.calls)

    @property
    def total_tokens(self) -> int:
        return self.total_input_tokens + self.total_output_tokens

    @property
    def total_cost(self) -> float:
        return sum(c.total_cost for c in self.calls)

    @property
    def total_api_calls(self) -> int:
        return len(self.calls)

    def get_cost_breakdown(self) -> Dict[str, dict]:
        """Group costs by purpose."""
        breakdown = {}
        for call in self.calls:
            if call.purpose not in breakdown:
                breakdown[call.purpose] = {
                    "calls": 0, "input_tokens": 0,
                    "output_tokens": 0, "cost": 0.0,
                }
            b = breakdown[call.purpose]
            b["calls"] += 1
            b["input_tokens"] += call.input_tokens
            b["output_tokens"] += call.output_tokens
            b["cost"] += call.total_cost
        return breakdown

    def to_dict(self) -> dict:
        """Export as JSON-serializable dict."""
        return {
            "total_api_calls": self.total_api_calls,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_tokens": self.total_tokens,
            "total_cost_usd": round(self.total_cost, 6),
            "billing_mode": "subscription" if self.is_subscription else "pay-per-token",
            "breakdown": self.get_cost_breakdown(),
            "calls": [
                {
                    "timestamp": c.timestamp,
                    "model": c.model,
                    "purpose": c.purpose,
                    "input_tokens": c.input_tokens,
                    "output_tokens": c.output_tokens,
                    "cost_usd": round(c.total_cost, 6),
                }
                for c in self.calls
            ],
        }
