"""Tests for trusted IP allowlist utilities (Ticket 105, ADR-012).

Validates CIDR parsing and IP membership checking.
"""

import pytest

from spark.jobs.utils.trusted_ips import (
    filter_trusted_ips,
    get_trusted_networks_from_env,
    is_trusted_ip,
    parse_trusted_cidrs,
)


class TestParseTrustedCidrs:
    """Tests for CIDR string parsing."""

    def test_parse_single_cidr(self):
        """Single CIDR should parse correctly."""
        networks = parse_trusted_cidrs("192.168.1.0/24")
        assert len(networks) == 1
        assert str(networks[0]) == "192.168.1.0/24"

    def test_parse_multiple_cidrs(self):
        """Multiple CIDRs should parse correctly."""
        networks = parse_trusted_cidrs("192.168.1.0/24,10.0.0.0/8")
        assert len(networks) == 2
        assert str(networks[0]) == "192.168.1.0/24"
        assert str(networks[1]) == "10.0.0.0/8"

    def test_parse_single_ip_becomes_32(self):
        """Single IP without mask should become /32."""
        networks = parse_trusted_cidrs("192.168.1.100")
        assert len(networks) == 1
        assert str(networks[0]) == "192.168.1.100/32"

    def test_parse_ipv6_cidr(self):
        """IPv6 CIDR should parse correctly."""
        networks = parse_trusted_cidrs("2001:db8::/32")
        assert len(networks) == 1
        assert str(networks[0]) == "2001:db8::/32"

    def test_parse_mixed_ipv4_ipv6(self):
        """Mixed IPv4 and IPv6 should parse correctly."""
        networks = parse_trusted_cidrs("192.168.1.0/24,2001:db8::/32")
        assert len(networks) == 2

    def test_parse_with_spaces(self):
        """Spaces around CIDRs should be trimmed."""
        networks = parse_trusted_cidrs(" 192.168.1.0/24 , 10.0.0.0/8 ")
        assert len(networks) == 2

    def test_parse_empty_returns_empty_list(self):
        """Empty string should return empty list."""
        assert parse_trusted_cidrs("") == []
        assert parse_trusted_cidrs("   ") == []

    def test_parse_none_returns_empty_list(self):
        """None should return empty list."""
        assert parse_trusted_cidrs(None) == []

    def test_parse_invalid_cidr_skipped(self):
        """Invalid CIDRs should be skipped, valid ones kept."""
        networks = parse_trusted_cidrs("192.168.1.0/24,not-valid,10.0.0.0/8")
        assert len(networks) == 2

    def test_parse_empty_segments_skipped(self):
        """Empty segments (e.g., double comma) should be skipped."""
        networks = parse_trusted_cidrs("192.168.1.0/24,,10.0.0.0/8")
        assert len(networks) == 2


class TestIsTrustedIp:
    """Tests for IP membership checking."""

    @pytest.fixture
    def sample_networks(self):
        """Sample trusted networks for testing."""
        return parse_trusted_cidrs("192.168.1.0/24,10.0.0.0/8,2001:db8::/32")

    def test_ip_in_trusted_network(self, sample_networks):
        """IP in trusted network should return True."""
        assert is_trusted_ip("192.168.1.50", sample_networks) is True
        assert is_trusted_ip("10.255.255.255", sample_networks) is True

    def test_ip_not_in_trusted_network(self, sample_networks):
        """IP not in any trusted network should return False."""
        assert is_trusted_ip("192.168.2.50", sample_networks) is False
        assert is_trusted_ip("11.0.0.1", sample_networks) is False

    def test_ipv6_in_trusted_network(self, sample_networks):
        """IPv6 in trusted network should return True."""
        assert is_trusted_ip("2001:db8::1", sample_networks) is True

    def test_ipv6_not_in_trusted_network(self, sample_networks):
        """IPv6 not in trusted network should return False."""
        assert is_trusted_ip("2001:db9::1", sample_networks) is False

    def test_empty_networks_returns_false(self):
        """Empty network list should return False for any IP."""
        assert is_trusted_ip("192.168.1.50", []) is False

    def test_invalid_ip_returns_false(self, sample_networks):
        """Invalid IP string should return False."""
        assert is_trusted_ip("not-an-ip", sample_networks) is False
        assert is_trusted_ip("", sample_networks) is False

    def test_exact_network_boundary(self, sample_networks):
        """IPs at network boundaries should work correctly."""
        assert is_trusted_ip("192.168.1.0", sample_networks) is True
        assert is_trusted_ip("192.168.1.255", sample_networks) is True
        assert is_trusted_ip("192.168.0.255", sample_networks) is False


class TestGetTrustedNetworksFromEnv:
    """Tests for environment variable loading."""

    def test_load_from_env(self, monkeypatch):
        """Should load CIDRs from TRUSTED_IP_CIDRS env var."""
        monkeypatch.setenv("TRUSTED_IP_CIDRS", "192.168.1.0/24,10.0.0.0/8")
        networks = get_trusted_networks_from_env()
        assert len(networks) == 2

    def test_missing_env_returns_empty(self, monkeypatch):
        """Missing env var should return empty list."""
        monkeypatch.delenv("TRUSTED_IP_CIDRS", raising=False)
        networks = get_trusted_networks_from_env()
        assert networks == []


class TestFilterTrustedIps:
    """Tests for partitioning IPs into trusted/untrusted."""

    @pytest.fixture
    def sample_networks(self):
        """Sample trusted networks for testing."""
        return parse_trusted_cidrs("192.168.1.0/24")

    def test_partition_ips(self, sample_networks):
        """Should correctly partition IPs."""
        trusted, untrusted = filter_trusted_ips(
            ["192.168.1.50", "10.0.0.1", "192.168.1.100", "203.0.113.50"],
            sample_networks,
        )
        assert trusted == ["192.168.1.50", "192.168.1.100"]
        assert untrusted == ["10.0.0.1", "203.0.113.50"]

    def test_all_trusted(self, sample_networks):
        """All IPs trusted should return empty untrusted list."""
        trusted, untrusted = filter_trusted_ips(
            ["192.168.1.50", "192.168.1.100"],
            sample_networks,
        )
        assert trusted == ["192.168.1.50", "192.168.1.100"]
        assert untrusted == []

    def test_none_trusted(self, sample_networks):
        """No IPs trusted should return empty trusted list."""
        trusted, untrusted = filter_trusted_ips(
            ["10.0.0.1", "203.0.113.50"],
            sample_networks,
        )
        assert trusted == []
        assert untrusted == ["10.0.0.1", "203.0.113.50"]

    def test_empty_input(self, sample_networks):
        """Empty input should return empty lists."""
        trusted, untrusted = filter_trusted_ips([], sample_networks)
        assert trusted == []
        assert untrusted == []
