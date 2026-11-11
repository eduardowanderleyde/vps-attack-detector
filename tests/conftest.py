"""Pytest configuration and shared fixtures."""

import pytest


@pytest.fixture
def sample_auth_log_lines():
    """Sample auth.log lines for testing parsers."""
    return {
        "failed_password": "Nov 10 14:23:45 myserver sshd[12345]: Failed password for root from 192.168.1.100 port 54321 ssh2",
        "failed_password_invalid_user": "Nov 10 14:23:46 myserver sshd[12346]: Failed password for invalid user admin from 10.0.0.50 port 54322 ssh2",
        "accepted_password": "Nov 10 14:24:00 myserver sshd[12347]: Accepted password for ubuntu from 192.168.1.1 port 54323 ssh2",
        "accepted_publickey": "Nov 10 14:24:01 myserver sshd[12348]: Accepted publickey for deploy from 10.10.10.10 port 54324 ssh2: RSA SHA256:abc123",
        "invalid_user": "Nov 10 14:23:47 myserver sshd[12349]: Invalid user test from 203.0.113.50 port 54325",
        "connection_closed": "Nov 10 14:25:00 myserver sshd[12350]: Connection closed by 192.168.1.100 port 54321 [preauth]",
        "disconnect": "Nov 10 14:25:01 myserver sshd[12351]: Received disconnect from 10.0.0.1 port 54326:11: disconnected by user",
        "malformed": "This is not a valid auth log line",
        "sudo": "Nov 10 15:00:00 myserver sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/ls",
    }


@pytest.fixture
def sample_auth_log_lines_v2():
    """Real-world auth.log formats from production VPS (Ticket 102).

    These are actual formats observed on Ubuntu 22.04 with modern syslog.
    """
    return {
        # ISO timestamp format (systemd-journald / rsyslog modern)
        "iso_failed_login": "2024-11-10T14:23:45.100001+00:00 vps01 sshd[12345]: Failed password for root from 203.0.113.50 port 54321 ssh2",
        "iso_accepted_publickey": "2024-11-10T14:24:01.234567+00:00 vps01 sshd[12348]: Accepted publickey for eduardo from 177.10.20.30 port 54324 ssh2: RSA SHA256:abc123",
        # PAM authentication failure (precedes Failed password)
        "pam_auth_failure": "Nov 10 14:23:44 vps01 sshd[12345]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.50",
        "pam_auth_failure_user": "Nov 10 14:23:44 vps01 sshd[12345]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.50  user=root",
        # Disconnected from authenticating user (brute force disconnect)
        "disconnected_auth_user": "Nov 10 14:23:50 vps01 sshd[12346]: Disconnected from authenticating user root 203.0.113.50 port 54322 [preauth]",
        "disconnected_invalid_user": "Nov 10 14:23:51 vps01 sshd[12347]: Disconnected from invalid user admin 198.51.100.10 port 54323 [preauth]",
        # Connection reset / closed during auth
        "connection_reset": "Nov 10 14:23:52 vps01 sshd[12348]: Connection reset by 192.0.2.1 port 54324 [preauth]",
        "connection_closed_preauth": "Nov 10 14:23:53 vps01 sshd[12349]: Connection closed by authenticating user root 203.0.113.50 port 54325 [preauth]",
        # Key exchange failures (often scanners)
        "no_matching_key_exchange": "Nov 10 14:23:54 vps01 sshd[12350]: Unable to negotiate with 198.51.100.20 port 54326: no matching key exchange method found. Their offer: diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1 [preauth]",
        # Banner exchange (usually scanners)
        "bad_protocol_banner": "Nov 10 14:23:55 vps01 sshd[12351]: Bad protocol version identification 'GET / HTTP/1.1' from 198.51.100.30 port 54327",
        # Maximum auth attempts exceeded
        "max_auth_attempts": "Nov 10 14:23:56 vps01 sshd[12352]: error: maximum authentication attempts exceeded for root from 203.0.113.50 port 54328 ssh2 [preauth]",
        # Too many authentication failures (fail2ban trigger)
        "too_many_failures": "Nov 10 14:23:57 vps01 sshd[12353]: Disconnecting authenticating user root 203.0.113.50 port 54329: Too many authentication failures [preauth]",
        # ISO timestamp with microseconds and timezone offset
        "iso_with_offset": "2024-11-10T11:23:45.100001-03:00 vps01 sshd[12345]: Failed password for invalid user admin from 192.0.2.50 port 54330 ssh2",
    }


@pytest.fixture
def sample_nginx_access_lines():
    """Sample nginx access.log lines (combined format) for testing."""
    return {
        "normal_200": '192.168.1.1 - - [10/Nov/2024:14:30:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"',
        "not_found_404": '203.0.113.50 - - [10/Nov/2024:14:30:01 +0000] "GET /wp-admin HTTP/1.1" 404 162 "-" "Mozilla/5.0"',
        "scanner_ua": '45.33.32.156 - - [10/Nov/2024:14:30:02 +0000] "GET /.env HTTP/1.1" 404 162 "-" "sqlmap/1.5"',
        "post_request": '10.0.0.100 - - [10/Nov/2024:14:30:03 +0000] "POST /api/login HTTP/1.1" 200 89 "https://example.com" "curl/7.68.0"',
        "with_user": '192.168.1.50 - john [10/Nov/2024:14:30:04 +0000] "GET /dashboard HTTP/1.1" 200 5678 "-" "Chrome/90.0"',
        "ipv6": '::1 - - [10/Nov/2024:14:30:05 +0000] "GET /health HTTP/1.1" 200 2 "-" "kube-probe/1.20"',
        "malformed": "This is not a valid nginx log line",
        "nikto_ua": '198.51.100.1 - - [10/Nov/2024:14:30:06 +0000] "GET /phpmyadmin HTTP/1.1" 404 162 "-" "Nikto/2.1.6"',
    }


@pytest.fixture
def sample_nginx_error_lines():
    """Sample nginx error.log lines for testing."""
    return {
        "file_not_found": '2024/11/10 14:30:00 [error] 1234#1234: *5678 open() "/var/www/html/.env" failed (2: No such file or directory), client: 203.0.113.50, server: example.com, request: "GET /.env HTTP/1.1", host: "example.com"',
        "upstream_timeout": '2024/11/10 14:30:01 [error] 1234#1234: *5679 upstream timed out (110: Connection timed out) while connecting to upstream, client: 192.168.1.1, server: example.com, request: "GET /api HTTP/1.1", upstream: "http://127.0.0.1:8000/api"',
        "connection_reset": "2024/11/10 14:30:02 [error] 1234#1234: *5680 recv() failed (104: Connection reset by peer) while reading response header from upstream",
        "warning": '2024/11/10 14:30:03 [warn] 1234#1234: conflicting server name "example.com" on 0.0.0.0:80, ignored',
        "malformed": "Not a valid error log",
    }


@pytest.fixture
def sample_docker_json_lines():
    """Sample Docker JSON log lines for testing."""
    return {
        "stdout": '{"log":"Starting application...\\n","stream":"stdout","time":"2024-11-10T14:30:00.123456789Z"}',
        "stderr": '{"log":"Error: Connection refused\\n","stream":"stderr","time":"2024-11-10T14:30:01.234567890Z"}',
        "multiline": '{"log":"Exception in thread \\"main\\"\\n","stream":"stderr","time":"2024-11-10T14:30:02.345678901Z"}',
        "with_attrs": '{"log":"Request processed\\n","stream":"stdout","time":"2024-11-10T14:30:03.456789012Z","attrs":{"tag":"myapp"}}',
        "malformed_json": "not valid json at all",
        "empty_log": '{"log":"","stream":"stdout","time":"2024-11-10T14:30:04.567890123Z"}',
    }


@pytest.fixture
def sample_caddy_json_lines():
    """Sample Caddy JSON access log lines (Ticket 103).
    
    Caddy produces structured JSON logs with request/response details.
    Format documented at: https://caddyserver.com/docs/caddyfile/directives/log
    """
    return {
        "normal_200": '{"level":"info","ts":1699624200.123456,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"192.168.1.1","remote_port":"54321","proto":"HTTP/2.0","method":"GET","host":"example.com","uri":"/index.html","headers":{"User-Agent":["Mozilla/5.0"]}},"user_id":"","duration":0.001234,"size":1234,"status":200,"resp_headers":{"Content-Type":["text/html"]}}',
        "not_found_404": '{"level":"info","ts":1699624201.234567,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"203.0.113.50","remote_port":"54322","proto":"HTTP/1.1","method":"GET","host":"example.com","uri":"/wp-admin","headers":{"User-Agent":["Mozilla/5.0"]}},"duration":0.000123,"size":162,"status":404}',
        "scanner_ua": '{"level":"info","ts":1699624202.345678,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"45.33.32.156","remote_port":"54323","proto":"HTTP/1.1","method":"GET","host":"example.com","uri":"/.env","headers":{"User-Agent":["sqlmap/1.5"]}},"duration":0.000089,"size":162,"status":404}',
        "post_request": '{"level":"info","ts":1699624203.456789,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"10.0.0.100","remote_port":"54324","proto":"HTTP/1.1","method":"POST","host":"api.example.com","uri":"/api/login","headers":{"User-Agent":["curl/7.68.0"],"Referer":["https://example.com"]}},"duration":0.005678,"size":89,"status":200}',
        "ipv6": '{"level":"info","ts":1699624204.567890,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"::1","remote_port":"54325","proto":"HTTP/1.1","method":"GET","host":"localhost","uri":"/health","headers":{"User-Agent":["kube-probe/1.20"]}},"duration":0.000045,"size":2,"status":200}',
        "server_error": '{"level":"info","ts":1699624205.678901,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"192.168.1.50","remote_port":"54326","proto":"HTTP/1.1","method":"GET","host":"example.com","uri":"/api/data","headers":{"User-Agent":["Chrome/90.0"]}},"duration":1.234567,"size":0,"status":500}',
        "nikto_scan": '{"level":"info","ts":1699624206.789012,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.1","remote_port":"54327","proto":"HTTP/1.1","method":"GET","host":"example.com","uri":"/phpmyadmin","headers":{"User-Agent":["Nikto/2.1.6"]}},"duration":0.000067,"size":162,"status":404}',
        "malformed_json": "not valid json at all",
        "missing_request": '{"level":"info","ts":1699624207.890123,"logger":"http.log.access","msg":"handled request","duration":0.001}',
    }


@pytest.fixture
def sample_fail2ban_lines():
    """Sample fail2ban.log lines (Ticket 104).
    
    fail2ban logs Ban/Unban actions for each jail.
    """
    return {
        "ban_sshd": "2024-11-10 14:30:00,123 fail2ban.actions        [12345]: NOTICE  [sshd] Ban 203.0.113.50",
        "unban_sshd": "2024-11-10 15:30:00,456 fail2ban.actions        [12345]: NOTICE  [sshd] Unban 203.0.113.50",
        "ban_recidive": "2024-11-10 14:35:00,789 fail2ban.actions        [12345]: NOTICE  [recidive] Ban 198.51.100.10",
        "found": "2024-11-10 14:29:50,012 fail2ban.filter          [12345]: INFO    [sshd] Found 203.0.113.50 - 2024-11-10 14:29:50",
        "already_banned": "2024-11-10 14:30:05,345 fail2ban.actions        [12345]: NOTICE  [sshd] 203.0.113.50 already banned",
        "malformed": "Not a valid fail2ban log",
        "restore_ban": "2024-11-10 12:00:00,000 fail2ban.actions        [12345]: NOTICE  [sshd] Restore Ban 192.0.2.100",
    }
