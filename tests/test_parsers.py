"""Tests for log parsers - Seam 1 per SPEC.md.

Tests verify behavior through the public interface: string in, dict out.
Each parser returns None for unrecognized lines (no exceptions).
"""

import pytest
from datetime import datetime

from spark.jobs.utils.parsers import (
    parse_auth_log,
    parse_nginx_access,
    parse_nginx_error,
    parse_docker_json,
    parse_caddy_json,
    parse_fail2ban_log,
)


class TestAuthLogParser:
    """Tests for SSH/auth.log parser."""

    def test_parse_failed_password_extracts_all_fields(self, sample_auth_log_lines):
        """Failed password attempts should extract IP, user, and event type."""
        result = parse_auth_log(sample_auth_log_lines["failed_password"])

        assert result is not None
        assert result["event_type"] == "failed_password"
        assert result["username"] == "root"
        assert result["source_ip"] == "192.168.1.100"
        assert result["port"] == 54321
        assert result["service"] == "sshd"
        assert result["host"] == "myserver"
        assert isinstance(result["timestamp"], datetime)

    def test_parse_failed_password_invalid_user(self, sample_auth_log_lines):
        """Failed password for invalid user should mark user as invalid."""
        result = parse_auth_log(sample_auth_log_lines["failed_password_invalid_user"])

        assert result is not None
        assert result["event_type"] == "failed_password"
        assert result["username"] == "admin"
        assert result["invalid_user"] is True
        assert result["source_ip"] == "10.0.0.50"

    def test_parse_accepted_password(self, sample_auth_log_lines):
        """Successful password login should be captured."""
        result = parse_auth_log(sample_auth_log_lines["accepted_password"])

        assert result is not None
        assert result["event_type"] == "accepted_password"
        assert result["username"] == "ubuntu"
        assert result["source_ip"] == "192.168.1.1"

    def test_parse_accepted_publickey(self, sample_auth_log_lines):
        """Successful publickey login should be captured."""
        result = parse_auth_log(sample_auth_log_lines["accepted_publickey"])

        assert result is not None
        assert result["event_type"] == "accepted_publickey"
        assert result["username"] == "deploy"
        assert result["source_ip"] == "10.10.10.10"

    def test_parse_invalid_user_attempt(self, sample_auth_log_lines):
        """Invalid user connection attempts should be captured."""
        result = parse_auth_log(sample_auth_log_lines["invalid_user"])

        assert result is not None
        assert result["event_type"] == "invalid_user"
        assert result["username"] == "test"
        assert result["source_ip"] == "203.0.113.50"

    def test_parse_malformed_returns_none(self, sample_auth_log_lines):
        """Malformed lines should return None, not raise."""
        result = parse_auth_log(sample_auth_log_lines["malformed"])
        assert result is None

    def test_parse_empty_string_returns_none(self):
        """Empty string should return None."""
        assert parse_auth_log("") is None

    def test_parse_connection_closed(self, sample_auth_log_lines):
        """Connection closed events should be captured."""
        result = parse_auth_log(sample_auth_log_lines["connection_closed"])

        assert result is not None
        assert result["event_type"] == "connection_closed"
        assert result["source_ip"] == "192.168.1.100"


class TestNginxAccessParser:
    """Tests for nginx access.log parser (combined format)."""

    def test_parse_normal_request(self, sample_nginx_access_lines):
        """Normal 200 response should extract all fields."""
        result = parse_nginx_access(sample_nginx_access_lines["normal_200"])

        assert result is not None
        assert result["source_ip"] == "192.168.1.1"
        assert result["method"] == "GET"
        assert result["path"] == "/index.html"
        assert result["status"] == 200
        assert result["size"] == 1234
        assert "Mozilla" in result["user_agent"]
        assert isinstance(result["timestamp"], datetime)

    def test_parse_404_request(self, sample_nginx_access_lines):
        """404 responses should be captured with path."""
        result = parse_nginx_access(sample_nginx_access_lines["not_found_404"])

        assert result is not None
        assert result["source_ip"] == "203.0.113.50"
        assert result["path"] == "/wp-admin"
        assert result["status"] == 404

    def test_parse_scanner_user_agent(self, sample_nginx_access_lines):
        """Scanner user agents should be captured."""
        result = parse_nginx_access(sample_nginx_access_lines["scanner_ua"])

        assert result is not None
        assert result["path"] == "/.env"
        assert "sqlmap" in result["user_agent"]

    def test_parse_post_request(self, sample_nginx_access_lines):
        """POST requests should capture method and referer."""
        result = parse_nginx_access(sample_nginx_access_lines["post_request"])

        assert result is not None
        assert result["method"] == "POST"
        assert result["path"] == "/api/login"
        assert result["referer"] == "https://example.com"

    def test_parse_ipv6_address(self, sample_nginx_access_lines):
        """IPv6 addresses should be parsed correctly."""
        result = parse_nginx_access(sample_nginx_access_lines["ipv6"])

        assert result is not None
        assert result["source_ip"] == "::1"

    def test_parse_malformed_returns_none(self, sample_nginx_access_lines):
        """Malformed lines should return None."""
        result = parse_nginx_access(sample_nginx_access_lines["malformed"])
        assert result is None

    def test_parse_with_authenticated_user(self, sample_nginx_access_lines):
        """Authenticated requests should capture the user."""
        result = parse_nginx_access(sample_nginx_access_lines["with_user"])

        assert result is not None
        assert result["remote_user"] == "john"


class TestNginxErrorParser:
    """Tests for nginx error.log parser."""

    def test_parse_file_not_found_error(self, sample_nginx_error_lines):
        """File not found errors should extract path and client IP."""
        result = parse_nginx_error(sample_nginx_error_lines["file_not_found"])

        assert result is not None
        assert result["level"] == "error"
        assert result["source_ip"] == "203.0.113.50"
        assert "/.env" in result["message"]
        assert isinstance(result["timestamp"], datetime)

    def test_parse_upstream_timeout(self, sample_nginx_error_lines):
        """Upstream timeout errors should be captured."""
        result = parse_nginx_error(sample_nginx_error_lines["upstream_timeout"])

        assert result is not None
        assert result["level"] == "error"
        assert "timed out" in result["message"]
        assert result["source_ip"] == "192.168.1.1"

    def test_parse_warning_level(self, sample_nginx_error_lines):
        """Warning level messages should be captured."""
        result = parse_nginx_error(sample_nginx_error_lines["warning"])

        assert result is not None
        assert result["level"] == "warn"

    def test_parse_malformed_returns_none(self, sample_nginx_error_lines):
        """Malformed lines should return None."""
        result = parse_nginx_error(sample_nginx_error_lines["malformed"])
        assert result is None


class TestDockerJsonParser:
    """Tests for Docker JSON log parser."""

    def test_parse_stdout_log(self, sample_docker_json_lines):
        """stdout logs should be parsed correctly."""
        result = parse_docker_json(sample_docker_json_lines["stdout"])

        assert result is not None
        assert result["stream"] == "stdout"
        assert "Starting application" in result["message"]
        assert isinstance(result["timestamp"], datetime)

    def test_parse_stderr_log(self, sample_docker_json_lines):
        """stderr logs should be parsed correctly."""
        result = parse_docker_json(sample_docker_json_lines["stderr"])

        assert result is not None
        assert result["stream"] == "stderr"
        assert "Error" in result["message"]

    def test_parse_malformed_json_returns_none(self, sample_docker_json_lines):
        """Invalid JSON should return None."""
        result = parse_docker_json(sample_docker_json_lines["malformed_json"])
        assert result is None

    def test_parse_empty_log_message(self, sample_docker_json_lines):
        """Empty log messages should still be parsed."""
        result = parse_docker_json(sample_docker_json_lines["empty_log"])

        assert result is not None
        assert result["message"] == ""


class TestCaddyJsonParser:
    """Tests for Caddy JSON access log parser (Ticket 103)."""

    def test_parse_normal_200(self, sample_caddy_json_lines):
        """Normal 200 response should extract all fields."""
        result = parse_caddy_json(sample_caddy_json_lines["normal_200"])

        assert result is not None
        assert result["source_ip"] == "192.168.1.1"
        assert result["method"] == "GET"
        assert result["path"] == "/index.html"
        assert result["status"] == 200
        assert result["size"] == 1234
        assert "Mozilla" in result["user_agent"]
        assert isinstance(result["timestamp"], datetime)

    def test_parse_404_request(self, sample_caddy_json_lines):
        """404 responses should be captured with path."""
        result = parse_caddy_json(sample_caddy_json_lines["not_found_404"])

        assert result is not None
        assert result["source_ip"] == "203.0.113.50"
        assert result["path"] == "/wp-admin"
        assert result["status"] == 404

    def test_parse_scanner_user_agent(self, sample_caddy_json_lines):
        """Scanner user agents should be captured."""
        result = parse_caddy_json(sample_caddy_json_lines["scanner_ua"])

        assert result is not None
        assert result["path"] == "/.env"
        assert "sqlmap" in result["user_agent"]

    def test_parse_post_request(self, sample_caddy_json_lines):
        """POST requests should capture method and referer."""
        result = parse_caddy_json(sample_caddy_json_lines["post_request"])

        assert result is not None
        assert result["method"] == "POST"
        assert result["path"] == "/api/login"
        assert result["referer"] == "https://example.com"

    def test_parse_ipv6_address(self, sample_caddy_json_lines):
        """IPv6 addresses should be parsed correctly."""
        result = parse_caddy_json(sample_caddy_json_lines["ipv6"])

        assert result is not None
        assert result["source_ip"] == "::1"

    def test_parse_server_error(self, sample_caddy_json_lines):
        """Server errors should be captured."""
        result = parse_caddy_json(sample_caddy_json_lines["server_error"])

        assert result is not None
        assert result["status"] == 500
        assert result["duration"] > 1.0

    def test_parse_nikto_scan(self, sample_caddy_json_lines):
        """Nikto scanner should be detected."""
        result = parse_caddy_json(sample_caddy_json_lines["nikto_scan"])

        assert result is not None
        assert "Nikto" in result["user_agent"]
        assert result["path"] == "/phpmyadmin"

    def test_parse_malformed_returns_none(self, sample_caddy_json_lines):
        """Malformed JSON should return None."""
        result = parse_caddy_json(sample_caddy_json_lines["malformed_json"])
        assert result is None

    def test_parse_missing_request_returns_none(self, sample_caddy_json_lines):
        """JSON without request object should return None."""
        result = parse_caddy_json(sample_caddy_json_lines["missing_request"])
        assert result is None


class TestFail2banParser:
    """Tests for fail2ban.log parser (Ticket 104)."""

    def test_parse_ban_event(self, sample_fail2ban_lines):
        """Ban events should extract IP and jail."""
        result = parse_fail2ban_log(sample_fail2ban_lines["ban_sshd"])

        assert result is not None
        assert result["action"] == "ban"
        assert result["jail"] == "sshd"
        assert result["source_ip"] == "203.0.113.50"
        assert isinstance(result["timestamp"], datetime)

    def test_parse_unban_event(self, sample_fail2ban_lines):
        """Unban events should extract IP and jail."""
        result = parse_fail2ban_log(sample_fail2ban_lines["unban_sshd"])

        assert result is not None
        assert result["action"] == "unban"
        assert result["jail"] == "sshd"
        assert result["source_ip"] == "203.0.113.50"

    def test_parse_recidive_ban(self, sample_fail2ban_lines):
        """Recidive jail bans should be captured."""
        result = parse_fail2ban_log(sample_fail2ban_lines["ban_recidive"])

        assert result is not None
        assert result["action"] == "ban"
        assert result["jail"] == "recidive"
        assert result["source_ip"] == "198.51.100.10"

    def test_parse_found_event(self, sample_fail2ban_lines):
        """Found events (pre-ban) should be captured."""
        result = parse_fail2ban_log(sample_fail2ban_lines["found"])

        assert result is not None
        assert result["action"] == "found"
        assert result["jail"] == "sshd"
        assert result["source_ip"] == "203.0.113.50"

    def test_parse_already_banned(self, sample_fail2ban_lines):
        """Already banned events should be captured."""
        result = parse_fail2ban_log(sample_fail2ban_lines["already_banned"])

        assert result is not None
        assert result["action"] == "already_banned"
        assert result["source_ip"] == "203.0.113.50"

    def test_parse_restore_ban(self, sample_fail2ban_lines):
        """Restore Ban (on startup) should be captured."""
        result = parse_fail2ban_log(sample_fail2ban_lines["restore_ban"])

        assert result is not None
        assert result["action"] == "restore_ban"
        assert result["source_ip"] == "192.0.2.100"

    def test_parse_malformed_returns_none(self, sample_fail2ban_lines):
        """Malformed lines should return None."""
        result = parse_fail2ban_log(sample_fail2ban_lines["malformed"])
        assert result is None
