"""End-to-end tests for v2 utility wiring.

Tests that verify the new v2 utilities are properly integrated
into the Spark jobs and scripts, not just standalone modules.
"""

import os
import pytest
import tempfile
from datetime import datetime, timedelta
from unittest.mock import patch

import pandas as pd


class TestTrustedIPWiring:
    """Tests for trusted IP integration in detectors."""

    @pytest.fixture
    def ssh_events_with_trusted_ip(self):
        """SSH events where trusted IP has publickey success after failures."""
        now = datetime.now()
        return pd.DataFrame([
            # Failures from attacker
            {"timestamp": now - timedelta(minutes=20), "event_type": "failed_password", 
             "source_ip": "203.0.113.50", "username": "root"},
            {"timestamp": now - timedelta(minutes=19), "event_type": "failed_password", 
             "source_ip": "203.0.113.50", "username": "root"},
            {"timestamp": now - timedelta(minutes=18), "event_type": "failed_password", 
             "source_ip": "203.0.113.50", "username": "root"},
            # Attacker success - should alert
            {"timestamp": now - timedelta(minutes=5), "event_type": "accepted_password", 
             "source_ip": "203.0.113.50", "username": "root"},
            # Failures from trusted IP (operator testing)
            {"timestamp": now - timedelta(minutes=15), "event_type": "failed_password", 
             "source_ip": "192.168.1.100", "username": "admin"},
            {"timestamp": now - timedelta(minutes=14), "event_type": "failed_password", 
             "source_ip": "192.168.1.100", "username": "admin"},
            {"timestamp": now - timedelta(minutes=13), "event_type": "failed_password", 
             "source_ip": "192.168.1.100", "username": "admin"},
            # Trusted IP publickey success - should NOT alert
            {"timestamp": now - timedelta(minutes=2), "event_type": "accepted_publickey", 
             "source_ip": "192.168.1.100", "username": "admin"},
        ])

    def test_success_after_failure_skips_trusted_ip_publickey(self, ssh_events_with_trusted_ip):
        """Trusted IP with publickey auth should not trigger alert."""
        from spark.jobs.utils.detectors import detect_success_after_failure
        
        # With trusted CIDR that includes 192.168.1.100
        alerts = detect_success_after_failure(
            ssh_events_with_trusted_ip,
            trusted_cidrs=["192.168.1.0/24"]
        )
        
        # Should only have alert for the attacker (203.0.113.50), not trusted IP
        assert len(alerts) == 1
        assert alerts.iloc[0]["source_ip"] == "203.0.113.50"

    def test_success_after_failure_without_trusted_ip_alerts_all(self, ssh_events_with_trusted_ip):
        """Without trusted IPs, all success-after-failure should alert."""
        from spark.jobs.utils.detectors import detect_success_after_failure
        
        # Without trusted CIDRs
        alerts = detect_success_after_failure(
            ssh_events_with_trusted_ip,
            trusted_cidrs=None
        )
        
        # Should have alerts for both IPs
        assert len(alerts) == 2
        alerted_ips = set(alerts["source_ip"].tolist())
        assert "203.0.113.50" in alerted_ips
        assert "192.168.1.100" in alerted_ips

    def test_password_auth_from_trusted_ip_still_alerts(self, ssh_events_with_trusted_ip):
        """Password auth from trusted IP should still alert (only publickey is exempt)."""
        from spark.jobs.utils.detectors import detect_success_after_failure
        
        # Modify: change trusted IP success to password instead of publickey
        df = ssh_events_with_trusted_ip.copy()
        df.loc[df["source_ip"] == "192.168.1.100", "event_type"] = df.loc[
            df["source_ip"] == "192.168.1.100", "event_type"
        ].replace("accepted_publickey", "accepted_password")
        
        alerts = detect_success_after_failure(df, trusted_cidrs=["192.168.1.0/24"])
        
        # Both should alert because trusted IP used password
        assert len(alerts) == 2


class TestBlocklistFail2banWiring:
    """Tests for fail2ban integration in blocklist generator."""

    @pytest.fixture
    def sample_alerts_df(self):
        """Sample alerts for blocklist generation."""
        return pd.DataFrame([
            {"alert_id": "a1", "alert_type": "ssh_brute_force", "severity": "high",
             "source_ip": "203.0.113.50", "timestamp": datetime.now(), "evidence": "test"},
            {"alert_id": "a2", "alert_type": "ssh_brute_force", "severity": "high",
             "source_ip": "198.51.100.10", "timestamp": datetime.now(), "evidence": "test"},
            {"alert_id": "a3", "alert_type": "scanner_detected", "severity": "medium",
             "source_ip": "192.0.2.1", "timestamp": datetime.now(), "evidence": "test"},
        ])

    @pytest.fixture
    def mock_fail2ban_log(self):
        """Create a temporary fail2ban.log with some bans."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            # IP 203.0.113.50 is banned
            f.write("2024-11-10 14:30:00,123 fail2ban.actions        [12345]: NOTICE  [sshd] Ban 203.0.113.50\n")
            # IP 192.0.2.1 was banned then unbanned
            f.write("2024-11-10 14:35:00,456 fail2ban.actions        [12345]: NOTICE  [sshd] Ban 192.0.2.1\n")
            f.write("2024-11-10 15:35:00,789 fail2ban.actions        [12345]: NOTICE  [sshd] Unban 192.0.2.1\n")
            f.flush()
            yield f.name
        os.unlink(f.name)

    def test_get_fail2ban_banned_ips(self, mock_fail2ban_log):
        """Should return only currently banned IPs."""
        from scripts.generate_blocklist import get_fail2ban_banned_ips
        
        banned = get_fail2ban_banned_ips(mock_fail2ban_log)
        
        # Only 203.0.113.50 should be banned (192.0.2.1 was unbanned)
        assert "203.0.113.50" in banned
        assert "192.0.2.1" not in banned

    def test_blocklist_skips_fail2ban_banned_ips(self, sample_alerts_df, mock_fail2ban_log):
        """Blocklist should not include IPs already banned by fail2ban."""
        from scripts.generate_blocklist import generate_blocklist
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Write alerts to Parquet
            alerts_path = os.path.join(tmpdir, "alerts")
            sample_alerts_df.to_parquet(alerts_path)
            
            output_path = os.path.join(tmpdir, "blocklist.txt")
            
            count = generate_blocklist(
                alerts_path,
                output_path,
                min_severity="high",
                skip_fail2ban=True,
                fail2ban_log_path=mock_fail2ban_log,
            )
            
            # Read blocklist
            with open(output_path) as f:
                content = f.read()
            
            # 203.0.113.50 is banned by fail2ban, should be skipped
            # 198.51.100.10 is not banned, should be in blocklist
            assert "203.0.113.50" not in content
            assert "198.51.100.10" in content

    def test_blocklist_includes_all_when_skip_disabled(self, sample_alerts_df, mock_fail2ban_log):
        """With skip_fail2ban=False, include all IPs."""
        from scripts.generate_blocklist import generate_blocklist
        
        with tempfile.TemporaryDirectory() as tmpdir:
            alerts_path = os.path.join(tmpdir, "alerts")
            sample_alerts_df.to_parquet(alerts_path)
            
            output_path = os.path.join(tmpdir, "blocklist.txt")
            
            generate_blocklist(
                alerts_path,
                output_path,
                min_severity="high",
                skip_fail2ban=False,
            )
            
            with open(output_path) as f:
                content = f.read()
            
            # Both high-severity IPs should be present
            assert "203.0.113.50" in content
            assert "198.51.100.10" in content
