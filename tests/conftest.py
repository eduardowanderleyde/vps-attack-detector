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
