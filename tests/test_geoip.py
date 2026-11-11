"""Tests for GeoIP enrichment - Seam 3 per SPEC.md.

Tests verify graceful degradation when GeoIP database is unavailable.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import os

from spark.jobs.utils.geoip import GeoIPEnricher, enrich_ip


class TestGeoIPEnricher:
    """Tests for GeoIP enrichment functionality."""

    def test_enrich_ip_returns_unknown_without_database(self):
        """When no GeoIP DB is available, return Unknown for all fields."""
        enricher = GeoIPEnricher(db_path=None)
        result = enricher.enrich("8.8.8.8")

        assert result["country"] == "Unknown"
        assert result["city"] == "Unknown"
        assert result["latitude"] is None
        assert result["longitude"] is None

    def test_enrich_private_ip_returns_private(self):
        """Private/reserved IPs should be marked as such."""
        enricher = GeoIPEnricher(db_path=None)

        for ip in ["192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"]:
            result = enricher.enrich(ip)
            assert result["country"] == "Private/Reserved", f"Failed for {ip}"

    def test_enrich_invalid_ip_returns_unknown(self):
        """Invalid IPs should return Unknown, not raise."""
        enricher = GeoIPEnricher(db_path=None)

        result = enricher.enrich("not-an-ip")
        assert result["country"] == "Unknown"

        result = enricher.enrich("")
        assert result["country"] == "Unknown"

        result = enricher.enrich("999.999.999.999")
        assert result["country"] == "Unknown"

    def test_enrich_ipv6_localhost(self):
        """IPv6 localhost should be marked as Private/Reserved."""
        enricher = GeoIPEnricher(db_path=None)
        result = enricher.enrich("::1")
        assert result["country"] == "Private/Reserved"

    def test_enrich_with_mock_database(self):
        """When GeoIP DB is available (mocked), return actual location data."""
        mock_reader = MagicMock()
        mock_reader.get.return_value = {
            "country": {"names": {"en": "United States"}},
            "city": {"names": {"en": "Mountain View"}},
            "location": {"latitude": 37.386, "longitude": -122.084},
        }

        enricher = GeoIPEnricher(db_path=None)
        enricher._reader = mock_reader
        result = enricher.enrich("8.8.8.8")

        assert result["country"] == "United States"
        assert result["city"] == "Mountain View"
        assert result["latitude"] == 37.386

    def test_enrich_nonexistent_db_path_degrades_gracefully(self):
        """Non-existent DB path should degrade to Unknown, not crash."""
        enricher = GeoIPEnricher(db_path="/nonexistent/path/geoip.mmdb")
        result = enricher.enrich("8.8.8.8")

        assert result["country"] == "Unknown"


class TestEnrichIPFunction:
    """Tests for the convenience function."""

    def test_enrich_ip_function_works_without_db(self):
        """The enrich_ip function should work without configuration."""
        result = enrich_ip("8.8.8.8")
        assert "country" in result
        assert "city" in result

    def test_enrich_ip_function_handles_private_ips(self):
        """The function should recognize private IPs."""
        result = enrich_ip("192.168.1.1")
        assert result["country"] == "Private/Reserved"
