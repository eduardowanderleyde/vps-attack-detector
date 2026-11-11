"""GeoIP enrichment for IP addresses.

Supports DB-IP Lite and MaxMind GeoLite2 databases (.mmdb format).
Degrades gracefully when database is unavailable.
"""

import ipaddress
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

try:
    import maxminddb

    MAXMINDDB_AVAILABLE = True
except ImportError:
    MAXMINDDB_AVAILABLE = False
    logger.warning("maxminddb not installed. GeoIP enrichment will return Unknown.")


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/reserved."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
    except ValueError:
        return False


def is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


class GeoIPEnricher:
    """Enriches IP addresses with geolocation data.

    Uses MaxMind DB format (.mmdb) compatible with both DB-IP Lite
    and MaxMind GeoLite2 databases.

    Degrades gracefully:
    - If no database path provided: returns Unknown
    - If database doesn't exist: returns Unknown
    - If database read fails: returns Unknown
    - If IP is private/reserved: returns Private/Reserved
    """

    def __init__(self, db_path: str | None = None):
        """Initialize the enricher.

        Args:
            db_path: Path to .mmdb database file. If None or doesn't exist,
                    enrichment will return Unknown for all IPs.
        """
        self.db_path = db_path
        self._reader = self._load_database(db_path)

    def _load_database(self, db_path: str | None) -> Any:
        """Load the GeoIP database if available."""
        if not MAXMINDDB_AVAILABLE:
            return None

        if not db_path:
            return None

        if not os.path.exists(db_path):
            logger.warning(f"GeoIP database not found at {db_path}")
            return None

        try:
            return maxminddb.open_database(db_path)
        except Exception as e:
            logger.error(f"Failed to open GeoIP database: {e}")
            return None

    def enrich(self, ip: str) -> dict[str, Any]:
        """Enrich an IP address with geolocation data.

        Args:
            ip: IP address to look up (IPv4 or IPv6)

        Returns:
            Dict with keys: country, city, latitude, longitude
            Values are None or "Unknown" when data unavailable.
        """
        default_result = {
            "country": "Unknown",
            "city": "Unknown",
            "latitude": None,
            "longitude": None,
        }

        if not ip or not ip.strip():
            return default_result

        if not is_valid_ip(ip):
            return default_result

        if is_private_ip(ip):
            return {
                "country": "Private/Reserved",
                "city": "Private/Reserved",
                "latitude": None,
                "longitude": None,
            }

        if not self._reader:
            return default_result

        try:
            data = self._reader.get(ip)
            if not data:
                return default_result

            country = "Unknown"
            city = "Unknown"
            latitude = None
            longitude = None

            if "country" in data and "names" in data["country"]:
                country = data["country"]["names"].get("en", "Unknown")

            if "city" in data and "names" in data["city"]:
                city = data["city"]["names"].get("en", "Unknown")

            if "location" in data:
                latitude = data["location"].get("latitude")
                longitude = data["location"].get("longitude")

            return {
                "country": country,
                "city": city,
                "latitude": latitude,
                "longitude": longitude,
            }

        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")
            return default_result

    def close(self):
        """Close the database reader."""
        if self._reader:
            try:
                self._reader.close()
            except Exception:
                logger.debug("Failed to close GeoIP reader", exc_info=True)


_default_enricher: GeoIPEnricher | None = None


def enrich_ip(ip: str, db_path: str | None = None) -> dict[str, Any]:
    """Convenience function to enrich an IP address.

    Uses a default enricher instance or creates one with the given db_path.

    Args:
        ip: IP address to look up
        db_path: Optional path to GeoIP database

    Returns:
        Dict with geolocation data
    """
    global _default_enricher

    if db_path:
        enricher = GeoIPEnricher(db_path)
        return enricher.enrich(ip)

    if _default_enricher is None:
        env_path = os.getenv("GEOIP_DB_PATH")
        _default_enricher = GeoIPEnricher(env_path)

    return _default_enricher.enrich(ip)
