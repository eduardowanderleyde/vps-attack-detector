"""Log parsers for different log formats.

Each parser takes a log line string and returns a structured dict,
or None if the line cannot be parsed.

Supported formats:
- auth.log (Linux authentication logs, traditional and ISO timestamp)
- nginx access.log (combined format)
- nginx error.log
- Docker JSON logs
- fail2ban.log
- Caddy JSON access logs
"""

import json
import re
from datetime import datetime
from typing import Any

# Regex patterns for auth.log - traditional BSD syslog format
AUTH_LOG_BASE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<service>\w+)\[(?P<pid>\d+)\]:\s+(?P<message>.+)$"
)

# ISO 8601 timestamp format (systemd-journald / rsyslog modern)
AUTH_LOG_ISO = re.compile(
    r"^(?P<iso_timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2}|Z))\s+"
    r"(?P<host>\S+)\s+(?P<service>\w+)\[(?P<pid>\d+)\]:\s+(?P<message>.+)$"
)

FAILED_PASSWORD = re.compile(
    r"Failed password for (?P<invalid>invalid user )?(?P<username>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

ACCEPTED_PASSWORD = re.compile(
    r"Accepted password for (?P<username>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

ACCEPTED_PUBLICKEY = re.compile(
    r"Accepted publickey for (?P<username>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

INVALID_USER = re.compile(
    r"Invalid user (?P<username>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

CONNECTION_CLOSED = re.compile(
    r"Connection closed by (?:authenticating user \S+ )?(?P<ip>\S+) port (?P<port>\d+)"
)

DISCONNECT = re.compile(r"Received disconnect from (?P<ip>\S+) port (?P<port>\d+)")

# PAM authentication failure
PAM_AUTH_FAILURE = re.compile(
    r"pam_unix\(sshd:auth\): authentication failure;.*rhost=(?P<ip>\S+)(?:\s+user=(?P<username>\S+))?"
)

# Disconnected from authenticating/invalid user
DISCONNECTED_AUTH = re.compile(
    r"Disconnected from (?P<invalid>invalid user )?(?:authenticating user )?(?P<username>\S+) (?P<ip>\S+) port (?P<port>\d+)"
)

# Disconnecting due to too many failures
DISCONNECTING_TOO_MANY = re.compile(
    r"Disconnecting (?:authenticating )?user (?P<username>\S+) (?P<ip>\S+) port (?P<port>\d+): Too many authentication failures"
)

# Connection reset by
CONNECTION_RESET = re.compile(r"Connection reset by (?P<ip>\S+) port (?P<port>\d+)")

# Unable to negotiate (key exchange failure)
KEY_EXCHANGE_FAILURE = re.compile(
    r"Unable to negotiate with (?P<ip>\S+) port (?P<port>\d+): no matching key exchange"
)

# Bad protocol version (scanner detection)
BAD_PROTOCOL = re.compile(
    r"Bad protocol version identification '.*' from (?P<ip>\S+) port (?P<port>\d+)"
)

# Maximum authentication attempts exceeded
MAX_AUTH_ATTEMPTS = re.compile(
    r"(?:error: )?maximum authentication attempts exceeded for (?:invalid user )?(?P<username>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

# Regex for nginx access.log (combined format)
NGINX_ACCESS = re.compile(
    r"^(?P<ip>\S+)\s+-\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d+)\s+(?P<size>\d+)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

# Regex for nginx error.log
NGINX_ERROR = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\[(?P<level>\w+)\]\s+(?P<pid>\d+)#(?P<tid>\d+):\s+(?P<message>.+)$"
)

NGINX_ERROR_CLIENT = re.compile(r"client:\s*(?P<ip>\S+)")


def parse_auth_log(line: str) -> dict[str, Any] | None:
    """Parse a line from auth.log into structured fields.

    Supports both traditional BSD syslog format and ISO 8601 timestamps.

    Args:
        line: Raw line from auth.log

    Returns:
        Dict with extracted fields or None if line not recognized.
        Fields: timestamp, host, service, pid, message, event_type,
                source_ip, port, username (when applicable)
    """
    if not line or not line.strip():
        return None

    timestamp = None
    host = None
    service = None
    pid = None
    message = None

    iso_match = AUTH_LOG_ISO.match(line)
    if iso_match:
        groups = iso_match.groupdict()
        message = groups["message"]
        host = groups["host"]
        service = groups["service"]
        pid = int(groups["pid"])

        iso_str = groups["iso_timestamp"]
        try:
            if iso_str.endswith("Z"):
                iso_str = iso_str[:-1] + "+00:00"
            timestamp = datetime.fromisoformat(iso_str)
            timestamp = timestamp.replace(tzinfo=None)
        except ValueError:
            return None
    else:
        base_match = AUTH_LOG_BASE.match(line)
        if not base_match:
            return None

        groups = base_match.groupdict()
        message = groups["message"]
        host = groups["host"]
        service = groups["service"]
        pid = int(groups["pid"])

        current_year = datetime.now().year
        timestamp_str = (
            f"{groups['month']} {groups['day']} {groups['time']} {current_year}"
        )
        try:
            timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
        except ValueError:
            return None

    result = {
        "timestamp": timestamp,
        "host": host,
        "service": service,
        "pid": pid,
        "message": message,
        "event_type": "unknown",
        "source_ip": None,
        "port": None,
        "username": None,
        "invalid_user": False,
    }

    if match := FAILED_PASSWORD.search(message):
        result["event_type"] = "failed_password"
        result["username"] = match.group("username")
        result["source_ip"] = match.group("ip")
        result["port"] = int(match.group("port"))
        result["invalid_user"] = match.group("invalid") is not None

    elif match := ACCEPTED_PASSWORD.search(message):
        result["event_type"] = "accepted_password"
        result["username"] = match.group("username")
        result["source_ip"] = match.group("ip")
        result["port"] = int(match.group("port"))

    elif match := ACCEPTED_PUBLICKEY.search(message):
        result["event_type"] = "accepted_publickey"
        result["username"] = match.group("username")
        result["source_ip"] = match.group("ip")
        result["port"] = int(match.group("port"))

    elif match := INVALID_USER.search(message):
        result["event_type"] = "invalid_user"
        result["username"] = match.group("username")
        result["source_ip"] = match.group("ip")
        result["port"] = int(match.group("port"))
        result["invalid_user"] = True

    elif match := MAX_AUTH_ATTEMPTS.search(message):
        result["event_type"] = "max_auth_attempts"
        result["username"] = match.group("username")
        result["source_ip"] = match.group("ip")
        result["port"] = int(match.group("port"))

    elif match := DISCONNECTING_TOO_MANY.search(message):
        result["event_type"] = "too_many_failures"
        result["username"] = match.group("username")
        result["source_ip"] = match.group("ip")
        result["port"] = int(match.group("port"))

    elif match := DISCONNECTED_AUTH.search(message):
        result["event_type"] = "disconnected_authenticating"
        result["username"] = match.group("username")
        result["source_ip"] = match.group("ip")
        result["port"] = int(match.group("port"))
        result["invalid_user"] = match.group("invalid") is not None

    elif match := PAM_AUTH_FAILURE.search(message):
        result["event_type"] = "pam_auth_failure"
        result["source_ip"] = match.group("ip")
        username = match.group("username")
        if username:
            result["username"] = username

    elif match := CONNECTION_RESET.search(message):
        result["event_type"] = "connection_reset"
        result["source_ip"] = match.group("ip")
        result["port"] = int(match.group("port"))

    elif match := CONNECTION_CLOSED.search(message):
        result["event_type"] = "connection_closed"
        result["source_ip"] = match.group("ip")
        result["port"] = int(match.group("port"))

    elif match := KEY_EXCHANGE_FAILURE.search(message):
        result["event_type"] = "key_exchange_failure"
        result["source_ip"] = match.group("ip")
        result["port"] = int(match.group("port"))

    elif match := BAD_PROTOCOL.search(message):
        result["event_type"] = "bad_protocol"
        result["source_ip"] = match.group("ip")
        result["port"] = int(match.group("port"))

    elif match := DISCONNECT.search(message):
        result["event_type"] = "disconnect"
        result["source_ip"] = match.group("ip")
        result["port"] = int(match.group("port"))

    return result


def parse_nginx_access(line: str) -> dict[str, Any] | None:
    """Parse a line from nginx access.log (combined format).

    Args:
        line: Raw line from nginx access.log

    Returns:
        Dict with extracted fields or None if line not recognized.
        Fields: timestamp, source_ip, remote_user, method, path, protocol,
                status, size, referer, user_agent
    """
    if not line or not line.strip():
        return None

    match = NGINX_ACCESS.match(line)
    if not match:
        return None

    groups = match.groupdict()

    try:
        timestamp = datetime.strptime(groups["time"], "%d/%b/%Y:%H:%M:%S %z")
        timestamp = timestamp.replace(tzinfo=None)
    except ValueError:
        try:
            timestamp = datetime.strptime(
                groups["time"].split()[0], "%d/%b/%Y:%H:%M:%S"
            )
        except ValueError:
            return None

    return {
        "timestamp": timestamp,
        "source_ip": groups["ip"],
        "remote_user": groups["user"] if groups["user"] != "-" else None,
        "method": groups["method"],
        "path": groups["path"],
        "protocol": groups["protocol"],
        "status": int(groups["status"]),
        "size": int(groups["size"]),
        "referer": groups["referer"] if groups["referer"] != "-" else None,
        "user_agent": groups["ua"],
    }


def parse_nginx_error(line: str) -> dict[str, Any] | None:
    """Parse a line from nginx error.log.

    Args:
        line: Raw line from nginx error.log

    Returns:
        Dict with extracted fields or None if line not recognized.
        Fields: timestamp, level, pid, tid, message, source_ip (when available)
    """
    if not line or not line.strip():
        return None

    match = NGINX_ERROR.match(line)
    if not match:
        return None

    groups = match.groupdict()

    try:
        timestamp_str = f"{groups['date']} {groups['time']}"
        timestamp = datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return None

    message = groups["message"]
    source_ip = None
    if client_match := NGINX_ERROR_CLIENT.search(message):
        source_ip = client_match.group("ip").rstrip(",")

    return {
        "timestamp": timestamp,
        "level": groups["level"],
        "pid": int(groups["pid"]),
        "tid": int(groups["tid"]),
        "message": message,
        "source_ip": source_ip,
    }


def parse_docker_json(line: str) -> dict[str, Any] | None:
    """Parse a Docker JSON log line.

    Args:
        line: Raw JSON line from Docker logs

    Returns:
        Dict with extracted fields or None if line not recognized.
        Fields: timestamp, stream, message, attrs (if present)
    """
    if not line or not line.strip():
        return None

    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    if "log" not in data or "time" not in data:
        return None

    try:
        timestamp_str = data["time"]
        if "." in timestamp_str:
            timestamp_str = timestamp_str[:26] + "Z"
        timestamp = datetime.fromisoformat(timestamp_str)
        timestamp = timestamp.replace(tzinfo=None)
    except (ValueError, TypeError):
        return None

    return {
        "timestamp": timestamp,
        "stream": data.get("stream", "stdout"),
        "message": data["log"].rstrip("\n"),
        "attrs": data.get("attrs"),
    }


def parse_caddy_json(line: str) -> dict[str, Any] | None:
    """Parse a Caddy JSON access log line.

    Caddy produces structured JSON logs when configured with:
    log {
        output file /var/log/caddy/access.log
        format json
    }

    Args:
        line: Raw JSON line from Caddy access log

    Returns:
        Dict with extracted fields or None if line not recognized.
        Fields: timestamp, source_ip, method, path, protocol, status,
                size, duration, user_agent, referer, host
    """
    if not line or not line.strip():
        return None

    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    if "request" not in data:
        return None

    request = data["request"]
    if "remote_ip" not in request:
        return None

    ts = data.get("ts")
    if ts is None:
        return None

    try:
        timestamp = datetime.fromtimestamp(ts)
    except (ValueError, TypeError, OSError):
        return None

    headers = request.get("headers", {})
    user_agent_list = headers.get("User-Agent", [])
    user_agent = user_agent_list[0] if user_agent_list else None
    referer_list = headers.get("Referer", [])
    referer = referer_list[0] if referer_list else None

    return {
        "timestamp": timestamp,
        "source_ip": request.get("remote_ip"),
        "remote_port": request.get("remote_port"),
        "method": request.get("method"),
        "path": request.get("uri"),
        "protocol": request.get("proto"),
        "host": request.get("host"),
        "status": data.get("status"),
        "size": data.get("size", 0),
        "duration": data.get("duration", 0),
        "user_agent": user_agent,
        "referer": referer,
    }


# Regex patterns for fail2ban.log
FAIL2BAN_BAN = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}),\d+\s+"
    r"fail2ban\.actions\s+\[\d+\]:\s+NOTICE\s+\[(?P<jail>\w+)\]\s+"
    r"(?P<action>Ban|Unban|Restore Ban)\s+(?P<ip>\S+)$"
)

FAIL2BAN_ALREADY_BANNED = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}),\d+\s+"
    r"fail2ban\.actions\s+\[\d+\]:\s+NOTICE\s+\[(?P<jail>\w+)\]\s+"
    r"(?P<ip>\S+)\s+already banned$"
)

FAIL2BAN_FOUND = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}),\d+\s+"
    r"fail2ban\.filter\s+\[\d+\]:\s+INFO\s+\[(?P<jail>\w+)\]\s+"
    r"Found\s+(?P<ip>\S+)"
)


def parse_fail2ban_log(line: str) -> dict[str, Any] | None:
    """Parse a line from fail2ban.log.

    Args:
        line: Raw line from fail2ban.log

    Returns:
        Dict with extracted fields or None if line not recognized.
        Fields: timestamp, action, jail, source_ip
    """
    if not line or not line.strip():
        return None

    if match := FAIL2BAN_BAN.match(line):
        groups = match.groupdict()
        timestamp_str = f"{groups['date']} {groups['time']}"
        try:
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None

        action = groups["action"].lower().replace(" ", "_")
        return {
            "timestamp": timestamp,
            "action": action,
            "jail": groups["jail"],
            "source_ip": groups["ip"],
        }

    if match := FAIL2BAN_ALREADY_BANNED.match(line):
        groups = match.groupdict()
        timestamp_str = f"{groups['date']} {groups['time']}"
        try:
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None

        return {
            "timestamp": timestamp,
            "action": "already_banned",
            "jail": groups["jail"],
            "source_ip": groups["ip"],
        }

    if match := FAIL2BAN_FOUND.match(line):
        groups = match.groupdict()
        timestamp_str = f"{groups['date']} {groups['time']}"
        try:
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None

        return {
            "timestamp": timestamp,
            "action": "found",
            "jail": groups["jail"],
            "source_ip": groups["ip"],
        }

    return None
