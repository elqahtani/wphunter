"""Tests for token usage tracking."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from apis.token_tracker import TokenTracker, APICallRecord


class TestTokenTracker:

    def test_empty_tracker(self):
        tracker = TokenTracker()
        assert tracker.total_api_calls == 0
        assert tracker.total_tokens == 0
        assert tracker.total_cost == 0.0

    def test_record_call(self):
        tracker = TokenTracker()
        tracker.record("claude-sonnet-4-20250514", "test", {
            "input_tokens": 100, "output_tokens": 50,
        })
        assert tracker.total_api_calls == 1
        assert tracker.total_input_tokens == 100
        assert tracker.total_output_tokens == 50
        assert tracker.total_tokens == 150

    def test_cost_calculation(self):
        tracker = TokenTracker()
        tracker.record("claude-sonnet-4-20250514", "test", {
            "input_tokens": 1_000_000, "output_tokens": 0,
        })
        # Sonnet input: $3.00 per MTok
        assert tracker.total_cost == 3.00

    def test_output_cost(self):
        tracker = TokenTracker()
        tracker.record("claude-sonnet-4-20250514", "test", {
            "input_tokens": 0, "output_tokens": 1_000_000,
        })
        # Sonnet output: $15.00 per MTok
        assert tracker.total_cost == 15.00

    def test_haiku_cheaper(self):
        tracker = TokenTracker()
        tracker.record("claude-haiku-4-5-20251001", "test", {
            "input_tokens": 1_000_000, "output_tokens": 0,
        })
        assert tracker.total_cost == 1.00

    def test_multiple_calls(self):
        tracker = TokenTracker()
        tracker.record("claude-sonnet-4-20250514", "analysis", {
            "input_tokens": 500, "output_tokens": 200,
        })
        tracker.record("claude-sonnet-4-20250514", "summary", {
            "input_tokens": 300, "output_tokens": 100,
        })
        assert tracker.total_api_calls == 2
        assert tracker.total_input_tokens == 800
        assert tracker.total_output_tokens == 300

    def test_cost_breakdown(self):
        tracker = TokenTracker()
        tracker.record("claude-sonnet-4-20250514", "analysis", {
            "input_tokens": 500, "output_tokens": 200,
        })
        tracker.record("claude-sonnet-4-20250514", "analysis", {
            "input_tokens": 300, "output_tokens": 100,
        })
        tracker.record("claude-sonnet-4-20250514", "summary", {
            "input_tokens": 100, "output_tokens": 50,
        })
        breakdown = tracker.get_cost_breakdown()
        assert "analysis" in breakdown
        assert "summary" in breakdown
        assert breakdown["analysis"]["calls"] == 2
        assert breakdown["summary"]["calls"] == 1

    def test_to_dict(self):
        tracker = TokenTracker(is_subscription=True)
        tracker.record("claude-sonnet-4-20250514", "test", {
            "input_tokens": 100, "output_tokens": 50,
        })
        d = tracker.to_dict()
        assert d["total_api_calls"] == 1
        assert d["billing_mode"] == "subscription"
        assert len(d["calls"]) == 1


class TestAPICallRecord:

    def test_total_tokens(self):
        record = APICallRecord(
            timestamp="2024-01-01", model="claude-sonnet-4-20250514",
            purpose="test", input_tokens=100, output_tokens=50,
        )
        assert record.total_tokens == 150

    def test_cost(self):
        record = APICallRecord(
            timestamp="2024-01-01", model="claude-sonnet-4-20250514",
            purpose="test", input_tokens=1000, output_tokens=500,
        )
        expected = (1000 / 1_000_000) * 3.00 + (500 / 1_000_000) * 15.00
        assert abs(record.total_cost - expected) < 0.0001
