"""Tests for attack detection rules - Seam 2 per SPEC.md.

Tests verify that detection functions correctly identify attack patterns
and return properly structured alerts.
"""

from datetime import datetime, timedelta

import pandas as pd
import pytest

from spark.jobs.utils.detectors import (
    detect_credential_stuffing,
    detect_path_scanning,
    detect_rate_spike,
    detect_scanner_ua,
    detect_ssh_brute_force,
    detect_success_after_failure,
)


@pytest.fixture
def ssh_events_brute_force():
    """SSH events that should trigger brute force detection."""
    base_time = datetime(2024, 11, 10, 8, 10, 0)
    events = []

    for i in range(10):
        events.append(
            {
                "timestamp": base_time + timedelta(seconds=i * 5),
                "event_type": "failed_password",
                "source_ip": "203.0.113.50",
                "username": "root",
            }
        )

    events.append(
        {
            "timestamp": base_time + timedelta(minutes=30),
            "event_type": "accepted_password",
            "source_ip": "192.168.1.1",
            "username": "ubuntu",
        }
    )

    return pd.DataFrame(events)


@pytest.fixture
def ssh_events_below_threshold():
    """SSH events below the brute force threshold."""
    base_time = datetime(2024, 11, 10, 8, 10, 0)
    events = []

    for i in range(3):
        events.append(
            {
                "timestamp": base_time + timedelta(seconds=i * 5),
                "event_type": "failed_password",
                "source_ip": "203.0.113.50",
                "username": "root",
            }
        )

    return pd.DataFrame(events)


@pytest.fixture
def http_events_path_scanning():
    """HTTP events that should trigger path scanning detection."""
    base_time = datetime(2024, 11, 10, 8, 10, 0)
    events = []

    suspicious_paths = [
        "/wp-admin",
        "/.env",
        "/phpmyadmin",
        "/admin",
        "/.git/config",
        "/backup.sql",
        "/config.php",
        "/wp-login.php",
        "/shell.php",
        "/test.php",
        "/phpinfo.php",
        "/database.sql",
        "/server-status",
        "/administrator",
        "/.htaccess",
        "/wp-config.php",
        "/info.php",
        "/cmd.php",
        "/c99.php",
        "/r57.php",
        "/.DS_Store",
        "/sitemap.xml",
    ]

    for i, path in enumerate(suspicious_paths):
        events.append(
            {
                "timestamp": base_time + timedelta(seconds=i),
                "source_ip": "203.0.113.100",
                "path": path,
                "status": 404,
                "user_agent": "Mozilla/5.0",
            }
        )

    events.append(
        {
            "timestamp": base_time + timedelta(minutes=1),
            "source_ip": "192.168.1.1",
            "path": "/index.html",
            "status": 200,
            "user_agent": "Mozilla/5.0",
        }
    )

    return pd.DataFrame(events)


@pytest.fixture
def http_events_scanner_ua():
    """HTTP events with scanner user agents."""
    base_time = datetime(2024, 11, 10, 8, 15, 0)
    events = [
        {
            "timestamp": base_time,
            "source_ip": "198.51.100.10",
            "path": "/",
            "status": 200,
            "user_agent": "sqlmap/1.5.2#stable",
        },
        {
            "timestamp": base_time + timedelta(seconds=1),
            "source_ip": "198.51.100.20",
            "path": "/",
            "status": 200,
            "user_agent": "Nikto/2.1.6",
        },
        {
            "timestamp": base_time + timedelta(seconds=2),
            "source_ip": "198.51.100.30",
            "path": "/",
            "status": 200,
            "user_agent": "zgrab/0.x",
        },
        {
            "timestamp": base_time + timedelta(seconds=3),
            "source_ip": "192.168.1.1",
            "path": "/",
            "status": 200,
            "user_agent": "Mozilla/5.0 (Windows NT 10.0)",
        },
    ]
    return pd.DataFrame(events)


@pytest.fixture
def ssh_events_success_after_failure():
    """SSH events showing success after multiple failures (compromise indicator)."""
    base_time = datetime(2024, 11, 10, 8, 10, 0)
    events = []

    for i in range(5):
        events.append(
            {
                "timestamp": base_time + timedelta(seconds=i * 5),
                "event_type": "failed_password",
                "source_ip": "203.0.113.50",
                "username": "ubuntu",
            }
        )

    events.append(
        {
            "timestamp": base_time + timedelta(seconds=30),
            "event_type": "accepted_password",
            "source_ip": "203.0.113.50",
            "username": "ubuntu",
        }
    )

    return pd.DataFrame(events)


class TestSSHBruteForceDetector:
    """Tests for SSH brute force detection."""

    def test_detects_brute_force_above_threshold(self, ssh_events_brute_force):
        """Should detect brute force when failures exceed threshold."""
        alerts = detect_ssh_brute_force(ssh_events_brute_force)

        assert len(alerts) > 0
        alert = alerts[alerts["source_ip"] == "203.0.113.50"].iloc[0]
        assert alert["alert_type"] == "ssh_brute_force"
        assert alert["severity"] in ["high", "critical"]

    def test_no_alert_below_threshold(self, ssh_events_below_threshold):
        """Should not alert when failures are below threshold."""
        alerts = detect_ssh_brute_force(ssh_events_below_threshold)

        brute_force_alerts = alerts[alerts["source_ip"] == "203.0.113.50"]
        assert len(brute_force_alerts) == 0

    def test_returns_dataframe_with_required_columns(self, ssh_events_brute_force):
        """Alert DataFrame should have all required columns."""
        alerts = detect_ssh_brute_force(ssh_events_brute_force)

        required_columns = [
            "alert_type",
            "severity",
            "source_ip",
            "timestamp",
            "evidence",
        ]
        for col in required_columns:
            assert col in alerts.columns


class TestCredentialStuffingDetector:
    """Tests for credential stuffing detection."""

    def test_detects_invalid_user_attempts(self):
        """Should detect multiple invalid user login attempts."""
        events = pd.DataFrame(
            [
                {
                    "timestamp": datetime.now(),
                    "event_type": "invalid_user",
                    "source_ip": "198.51.100.1",
                    "username": "admin",
                },
                {
                    "timestamp": datetime.now(),
                    "event_type": "invalid_user",
                    "source_ip": "198.51.100.1",
                    "username": "test",
                },
                {
                    "timestamp": datetime.now(),
                    "event_type": "invalid_user",
                    "source_ip": "198.51.100.1",
                    "username": "guest",
                },
                {
                    "timestamp": datetime.now(),
                    "event_type": "invalid_user",
                    "source_ip": "198.51.100.1",
                    "username": "oracle",
                },
                {
                    "timestamp": datetime.now(),
                    "event_type": "invalid_user",
                    "source_ip": "198.51.100.1",
                    "username": "postgres",
                },
            ]
        )

        alerts = detect_credential_stuffing(events)

        assert len(alerts) > 0
        assert alerts.iloc[0]["alert_type"] == "credential_stuffing"


class TestPathScanningDetector:
    """Tests for HTTP path scanning detection."""

    def test_detects_path_scanning(self, http_events_path_scanning):
        """Should detect scanning of suspicious paths."""
        alerts = detect_path_scanning(http_events_path_scanning)

        assert len(alerts) > 0
        alert = alerts[alerts["source_ip"] == "203.0.113.100"].iloc[0]
        assert alert["alert_type"] == "path_scanning"

    def test_no_alert_for_normal_404s(self):
        """Normal 404s should not trigger alert."""
        events = pd.DataFrame(
            [
                {
                    "timestamp": datetime.now(),
                    "source_ip": "192.168.1.1",
                    "path": "/typo.html",
                    "status": 404,
                    "user_agent": "Mozilla/5.0",
                },
                {
                    "timestamp": datetime.now(),
                    "source_ip": "192.168.1.1",
                    "path": "/missing.css",
                    "status": 404,
                    "user_agent": "Mozilla/5.0",
                },
            ]
        )

        alerts = detect_path_scanning(events)

        scanner_alerts = alerts[alerts["source_ip"] == "192.168.1.1"]
        assert len(scanner_alerts) == 0


class TestScannerUADetector:
    """Tests for scanner user agent detection."""

    def test_detects_known_scanner_user_agents(self, http_events_scanner_ua):
        """Should detect known scanner user agents."""
        alerts = detect_scanner_ua(http_events_scanner_ua)

        assert len(alerts) >= 3

        scanner_ips = alerts["source_ip"].tolist()
        assert "198.51.100.10" in scanner_ips
        assert "198.51.100.20" in scanner_ips
        assert "198.51.100.30" in scanner_ips

    def test_no_alert_for_normal_user_agents(self):
        """Normal user agents should not trigger alert."""
        events = pd.DataFrame(
            [
                {
                    "timestamp": datetime.now(),
                    "source_ip": "192.168.1.1",
                    "path": "/",
                    "status": 200,
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                },
                {
                    "timestamp": datetime.now(),
                    "source_ip": "192.168.1.2",
                    "path": "/",
                    "status": 200,
                    "user_agent": "curl/7.68.0",
                },
            ]
        )

        alerts = detect_scanner_ua(events)

        assert len(alerts) == 0


class TestRateSpikeDetector:
    """Tests for request rate spike detection."""

    def test_detects_rate_spike(self):
        """Should detect abnormal request rate from single IP."""
        base_time = datetime(2024, 11, 10, 8, 30, 0)
        events = []

        for i in range(150):
            events.append(
                {
                    "timestamp": base_time + timedelta(seconds=i * 0.4),
                    "source_ip": "45.33.32.156",
                    "path": f"/page{i}",
                    "status": 200,
                    "user_agent": "bot",
                }
            )

        df = pd.DataFrame(events)
        alerts = detect_rate_spike(df)

        assert len(alerts) > 0
        assert alerts.iloc[0]["alert_type"] == "rate_spike"


class TestSuccessAfterFailureDetector:
    """Tests for success-after-failure detection (compromise indicator)."""

    def test_detects_success_after_failures(self, ssh_events_success_after_failure):
        """Should detect successful login after multiple failures (critical)."""
        alerts = detect_success_after_failure(ssh_events_success_after_failure)

        assert len(alerts) > 0
        alert = alerts.iloc[0]
        assert alert["alert_type"] == "success_after_failure"
        assert alert["severity"] == "critical"
        assert alert["source_ip"] == "203.0.113.50"

    def test_no_alert_for_normal_success(self):
        """Normal successful logins should not trigger alert."""
        events = pd.DataFrame(
            [
                {
                    "timestamp": datetime.now(),
                    "event_type": "accepted_password",
                    "source_ip": "192.168.1.1",
                    "username": "ubuntu",
                },
            ]
        )

        alerts = detect_success_after_failure(events)

        assert len(alerts) == 0
