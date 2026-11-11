"""Log parsers for different log formats.

Each parser takes a log line string and returns a structured dict,
or None if the line cannot be parsed.

Supported formats:
- auth.log (Linux authentication logs)
- nginx access.log (combined format)
- nginx error.log
- Docker JSON logs
"""

import re
import json
from datetime import datetime
from typing import Any


# Regex patterns for auth.log
AUTH_LOG_BASE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<service>\w+)\[(?P<pid>\d+)\]:\s+(?P<message>.+)$'
)

FAILED_PASSWORD = re.compile(
    r'Failed password for (?P<invalid>invalid user )?(?P<username>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
)

ACCEPTED_PASSWORD = re.compile(
    r'Accepted password for (?P<username>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
)

ACCEPTED_PUBLICKEY = re.compile(
    r'Accepted publickey for (?P<username>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
)

INVALID_USER = re.compile(
    r'Invalid user (?P<username>\S+) from (?P<ip>\S+) port (?P<port>\d+)'
)

CONNECTION_CLOSED = re.compile(
    r'Connection closed by (?P<ip>\S+) port (?P<port>\d+)'
)

DISCONNECT = re.compile(
    r'Received disconnect from (?P<ip>\S+) port (?P<port>\d+)'
)

# Regex for nginx access.log (combined format)
NGINX_ACCESS = re.compile(
    r'^(?P<ip>\S+)\s+-\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d+)\s+(?P<size>\d+)\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)"'
)

# Regex for nginx error.log
NGINX_ERROR = re.compile(
    r'^(?P<date>\d{4}/\d{2}/\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'\[(?P<level>\w+)\]\s+(?P<pid>\d+)#(?P<tid>\d+):\s+(?P<message>.+)$'
)

NGINX_ERROR_CLIENT = re.compile(r'client:\s*(?P<ip>\S+)')


def parse_auth_log(line: str) -> dict[str, Any] | None:
    """Parse a line from auth.log into structured fields.

    Args:
        line: Raw line from auth.log

    Returns:
        Dict with extracted fields or None if line not recognized.
        Fields: timestamp, host, service, pid, message, event_type,
                source_ip, port, username (when applicable)
    """
    if not line or not line.strip():
        return None

    base_match = AUTH_LOG_BASE.match(line)
    if not base_match:
        return None

    groups = base_match.groupdict()
    message = groups["message"]

    current_year = datetime.now().year
    timestamp_str = f"{groups['month']} {groups['day']} {groups['time']} {current_year}"
    try:
        timestamp = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
    except ValueError:
        return None

    result = {
        "timestamp": timestamp,
        "host": groups["host"],
        "service": groups["service"],
        "pid": int(groups["pid"]),
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

    elif match := CONNECTION_CLOSED.search(message):
        result["event_type"] = "connection_closed"
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
            timestamp = datetime.strptime(groups["time"].split()[0], "%d/%b/%Y:%H:%M:%S")
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
        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        timestamp = timestamp.replace(tzinfo=None)
    except (ValueError, TypeError):
        return None

    return {
        "timestamp": timestamp,
        "stream": data.get("stream", "stdout"),
        "message": data["log"].rstrip("\n"),
        "attrs": data.get("attrs"),
    }
