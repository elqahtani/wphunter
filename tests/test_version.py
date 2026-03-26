"""Tests for version comparison and affected-version logic."""
from apis.wpvulndb import _cmp_ver as wpvulndb_cmp
from apis.wpvulndb import _is_affected as wpvulndb_affected
from apis.wpscan import _cmp_ver as wpscan_cmp
from apis.wpscan import _is_affected as wpscan_affected


class TestCmpVer:
    """Version comparison (both implementations should behave the same)."""

    def test_equal(self):
        assert wpvulndb_cmp("1.2.3", "1.2.3") == 0
        assert wpscan_cmp("1.2.3", "1.2.3") == 0

    def test_less_than(self):
        assert wpvulndb_cmp("1.2.3", "1.2.4") == -1
        assert wpscan_cmp("1.2.3", "1.2.4") == -1

    def test_greater_than(self):
        assert wpvulndb_cmp("1.2.4", "1.2.3") == 1
        assert wpscan_cmp("1.2.4", "1.2.3") == 1

    def test_different_lengths(self):
        assert wpvulndb_cmp("1.2", "1.2.0") == 0
        assert wpscan_cmp("1.2", "1.2.0") == 0

    def test_major_version_diff(self):
        assert wpvulndb_cmp("2.0.0", "1.9.9") == 1
        assert wpscan_cmp("2.0.0", "1.9.9") == 1

    def test_single_segment(self):
        assert wpvulndb_cmp("11", "3") == 1
        assert wpscan_cmp("11", "3") == 1


class TestWpvulndbAffected:
    """WPVulnerability.net operator-based affected check."""

    def test_no_operator(self):
        assert wpvulndb_affected({}, "1.0.0") is True

    def test_lt_affected(self):
        vuln = {"operator": {"max_version": "5.3.2", "max_operator": "lt"}}
        assert wpvulndb_affected(vuln, "5.3.1") is True

    def test_lt_not_affected(self):
        vuln = {"operator": {"max_version": "5.3.2", "max_operator": "lt"}}
        assert wpvulndb_affected(vuln, "5.3.2") is False
        assert wpvulndb_affected(vuln, "5.4.0") is False

    def test_lte_boundary(self):
        vuln = {"operator": {"max_version": "5.3.2", "max_operator": "lte"}}
        assert wpvulndb_affected(vuln, "5.3.2") is True
        assert wpvulndb_affected(vuln, "5.3.3") is False

    def test_min_gte(self):
        vuln = {"operator": {"min_version": "3.0", "min_operator": "gte",
                              "max_version": "5.0", "max_operator": "lt"}}
        assert wpvulndb_affected(vuln, "2.9") is False
        assert wpvulndb_affected(vuln, "3.0") is True
        assert wpvulndb_affected(vuln, "4.0") is True
        assert wpvulndb_affected(vuln, "5.0") is False

    def test_short_operators_ge_le(self):
        """API returns 'ge'/'le' (short form) instead of 'gte'/'lte'."""
        vuln = {"operator": {"min_version": "9.0.0", "min_operator": "ge",
                              "max_version": "9.1.1.1", "max_operator": "le"}}
        assert wpvulndb_affected(vuln, "8.9.9") is False   # below range
        assert wpvulndb_affected(vuln, "9.0.0") is True    # at min boundary
        assert wpvulndb_affected(vuln, "9.1.0") is True    # within range
        assert wpvulndb_affected(vuln, "9.1.1.1") is True  # at max boundary
        assert wpvulndb_affected(vuln, "9.1.2") is False   # above range
        assert wpvulndb_affected(vuln, "9.5.8") is False   # well above range


class TestWpscanAffected:
    """WPScan fixed_in-based affected check."""

    def test_no_fixed_in(self):
        assert wpscan_affected({}, "1.0.0") is True

    def test_affected_below_fix(self):
        assert wpscan_affected({"fixed_in": "3.6.2"}, "3.6.0") is True

    def test_not_affected_at_fix(self):
        assert wpscan_affected({"fixed_in": "3.6.2"}, "3.6.2") is False

    def test_not_affected_above_fix(self):
        assert wpscan_affected({"fixed_in": "3.6.2"}, "4.0.0") is False
