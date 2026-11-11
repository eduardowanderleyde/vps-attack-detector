"""Trusted IP allowlist utilities (ADR-012).

Provides functions to check if an IP address is in the trusted allowlist,
reducing false positives for legitimate operator access.
"""

import ipaddress
import os
from collections.abc import Sequence


def parse_trusted_cidrs(
    cidrs_str: str | None,
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse a comma-separated string of CIDRs into network objects.

    Args:
        cidrs_str: Comma-separated CIDRs, e.g., "192.168.1.0/24,10.0.0.0/8"
                   Can also be single IPs which become /32 or /128.

    Returns:
        List of IPv4Network or IPv6Network objects.
        Empty list if input is None or empty.

    Examples:
        >>> parse_trusted_cidrs("192.168.1.0/24,10.0.0.0/8")
        [IPv4Network('192.168.1.0/24'), IPv4Network('10.0.0.0/8')]
        >>> parse_trusted_cidrs("192.168.1.100")
        [IPv4Network('192.168.1.100/32')]
        >>> parse_trusted_cidrs(None)
        []
    """
    if not cidrs_str or not cidrs_str.strip():
        return []

    networks = []
    for cidr in cidrs_str.split(","):
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            networks.append(network)
        except ValueError:
            continue

    return networks


def is_trusted_ip(
    ip: str,
    trusted_networks: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    """Check if an IP address is in any of the trusted networks.

    Args:
        ip: IP address string (IPv4 or IPv6)
        trusted_networks: Sequence of network objects from parse_trusted_cidrs()

    Returns:
        True if IP is in any trusted network, False otherwise.
        Returns False for invalid IP addresses.

    Examples:
        >>> networks = parse_trusted_cidrs("192.168.1.0/24")
        >>> is_trusted_ip("192.168.1.50", networks)
        True
        >>> is_trusted_ip("10.0.0.1", networks)
        False
    """
    if not trusted_networks:
        return False

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for network in trusted_networks:
        if ip_obj in network:
            return True

    return False


def get_trusted_networks_from_env() -> list[
    ipaddress.IPv4Network | ipaddress.IPv6Network
]:
    """Load trusted CIDRs from TRUSTED_IP_CIDRS environment variable.

    Returns:
        List of network objects. Empty if env var not set.
    """
    return parse_trusted_cidrs(os.environ.get("TRUSTED_IP_CIDRS"))


def filter_trusted_ips(
    ips: Sequence[str],
    trusted_networks: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> tuple[list[str], list[str]]:
    """Partition IPs into trusted and untrusted.

    Args:
        ips: Sequence of IP address strings
        trusted_networks: Sequence of network objects

    Returns:
        Tuple of (trusted_ips, untrusted_ips)

    Example:
        >>> networks = parse_trusted_cidrs("192.168.1.0/24")
        >>> filter_trusted_ips(["192.168.1.50", "10.0.0.1"], networks)
        (['192.168.1.50'], ['10.0.0.1'])
    """
    trusted = []
    untrusted = []

    for ip in ips:
        if is_trusted_ip(ip, trusted_networks):
            trusted.append(ip)
        else:
            untrusted.append(ip)

    return trusted, untrusted
