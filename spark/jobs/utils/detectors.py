"""Attack detection rules for security log analysis.

Each detector analyzes a DataFrame of parsed events and returns
a DataFrame of alerts with standardized schema.

Alert schema:
- alert_id: str (unique identifier)
- alert_type: str (type of attack detected)
- severity: str (critical, high, medium, low)
- source_ip: str (attacking IP address)
- timestamp: datetime (when the attack was detected)
- evidence: str (description of what triggered the alert)
"""

import hashlib
import os
from datetime import datetime, timedelta
from typing import Any

import pandas as pd
import yaml

DEFAULT_CONFIG = {
    "ssh_brute_force": {
        "threshold": 5,
        "window_minutes": 10,
        "severity": "high",
    },
    "credential_stuffing": {
        "threshold": 3,
        "window_minutes": 10,
        "severity": "medium",
    },
    "path_scanning": {
        "threshold": 10,
        "window_minutes": 5,
        "severity": "medium",
        "suspicious_paths": [
            "/wp-admin",
            "/wp-login.php",
            "/.env",
            "/.git/config",
            "/phpmyadmin",
            "/phpMyAdmin",
            "/admin",
            "/administrator",
            "/.htaccess",
            "/config.php",
            "/wp-config.php",
            "/backup.sql",
            "/database.sql",
            "/.DS_Store",
            "/server-status",
            "/info.php",
            "/phpinfo.php",
            "/test.php",
            "/shell.php",
            "/cmd.php",
            "/c99.php",
            "/r57.php",
            "/actuator",
            "/graphql",
        ],
    },
    "scanner_user_agents": {
        "severity": "medium",
        "patterns": [
            "sqlmap",
            "nikto",
            "nmap",
            "zgrab",
            "masscan",
            "nessus",
            "wpscan",
            "gobuster",
            "dirbuster",
            "nuclei",
            "shodan",
        ],
    },
    "rate_spike": {
        "threshold_per_minute": 100,
        "window_minutes": 1,
        "severity": "medium",
    },
    "success_after_failure": {
        "failure_threshold": 3,
        "window_minutes": 30,
        "severity": "critical",
    },
}


def load_config(config_path: str | None = None) -> dict[str, Any]:
    """Load detection configuration from YAML file or use defaults."""
    if config_path and os.path.exists(config_path):
        with open(config_path) as f:
            return yaml.safe_load(f)

    env_path = os.getenv("DETECTION_CONFIG_PATH")
    if env_path and os.path.exists(env_path):
        with open(env_path) as f:
            return yaml.safe_load(f)

    return DEFAULT_CONFIG


def generate_alert_id(alert_type: str, source_ip: str, timestamp: datetime) -> str:
    """Generate a unique alert ID."""
    data = f"{alert_type}:{source_ip}:{timestamp.isoformat()}"
    return hashlib.md5(data.encode()).hexdigest()[:16]


def create_alert(
    alert_type: str,
    severity: str,
    source_ip: str,
    timestamp: datetime,
    evidence: str,
) -> dict[str, Any]:
    """Create a standardized alert record."""
    return {
        "alert_id": generate_alert_id(alert_type, source_ip, timestamp),
        "alert_type": alert_type,
        "severity": severity,
        "source_ip": source_ip,
        "timestamp": timestamp,
        "evidence": evidence,
    }


ALERT_COLUMNS = [
    "alert_id",
    "alert_type",
    "severity",
    "source_ip",
    "timestamp",
    "evidence",
]


def empty_alerts_df() -> pd.DataFrame:
    """Return an empty DataFrame with the correct alert schema."""
    return pd.DataFrame(columns=ALERT_COLUMNS)


def detect_ssh_brute_force(
    df: pd.DataFrame,
    config: dict[str, Any] | None = None,
) -> pd.DataFrame:
    """Detect SSH brute force attacks.

    Identifies IPs with multiple failed login attempts within a time window.

    Args:
        df: DataFrame with SSH events (must have: timestamp, event_type, source_ip)
        config: Detection configuration

    Returns:
        DataFrame of alerts
    """
    if config is None:
        config = load_config()

    cfg = config.get("ssh_brute_force", DEFAULT_CONFIG["ssh_brute_force"])
    threshold = cfg.get("threshold", 5)
    window_minutes = cfg.get("window_minutes", 10)
    severity = cfg.get("severity", "high")

    alerts = []

    if df.empty or "event_type" not in df.columns:
        return empty_alerts_df()

    failed = df[df["event_type"] == "failed_password"].copy()
    if failed.empty:
        return empty_alerts_df()

    failed = failed.sort_values("timestamp")

    for ip in failed["source_ip"].unique():
        ip_events = failed[failed["source_ip"] == ip]

        if len(ip_events) < threshold:
            continue

        ip_events = ip_events.sort_values("timestamp")
        timestamps = ip_events["timestamp"].tolist()

        for i in range(len(timestamps) - threshold + 1):
            window_start = timestamps[i]
            window_end = window_start + timedelta(minutes=window_minutes)

            events_in_window = [
                t for t in timestamps if window_start <= t <= window_end
            ]

            if len(events_in_window) >= threshold:
                alerts.append(
                    create_alert(
                        alert_type="ssh_brute_force",
                        severity=severity,
                        source_ip=ip,
                        timestamp=timestamps[i],
                        evidence=f"{len(events_in_window)} failed logins in {window_minutes} minutes",
                    )
                )
                break

    if not alerts:
        return empty_alerts_df()
    return pd.DataFrame(alerts)


def detect_credential_stuffing(
    df: pd.DataFrame,
    config: dict[str, Any] | None = None,
) -> pd.DataFrame:
    """Detect credential stuffing attacks.

    Identifies IPs attempting logins with multiple invalid usernames.

    Args:
        df: DataFrame with SSH events
        config: Detection configuration

    Returns:
        DataFrame of alerts
    """
    if config is None:
        config = load_config()

    cfg = config.get("credential_stuffing", DEFAULT_CONFIG["credential_stuffing"])
    threshold = cfg.get("threshold", 3)
    severity = cfg.get("severity", "medium")

    alerts = []

    if df.empty or "event_type" not in df.columns:
        return empty_alerts_df()

    invalid = df[df["event_type"] == "invalid_user"].copy()
    if invalid.empty:
        return empty_alerts_df()

    for ip in invalid["source_ip"].unique():
        ip_events = invalid[invalid["source_ip"] == ip]
        unique_users = ip_events["username"].nunique()

        if unique_users >= threshold:
            first_event = ip_events.iloc[0]
            usernames = ip_events["username"].unique().tolist()[:5]
            alerts.append(
                create_alert(
                    alert_type="credential_stuffing",
                    severity=severity,
                    source_ip=ip,
                    timestamp=first_event["timestamp"],
                    evidence=f"{unique_users} invalid usernames tried: {', '.join(usernames)}",
                )
            )

    if not alerts:
        return empty_alerts_df()
    return pd.DataFrame(alerts)


def detect_path_scanning(
    df: pd.DataFrame,
    config: dict[str, Any] | None = None,
) -> pd.DataFrame:
    """Detect HTTP path scanning.

    Identifies IPs probing suspicious paths (404s on known vulnerable paths).

    Args:
        df: DataFrame with HTTP events (must have: timestamp, source_ip, path, status)
        config: Detection configuration

    Returns:
        DataFrame of alerts
    """
    if config is None:
        config = load_config()

    cfg = config.get("path_scanning", DEFAULT_CONFIG["path_scanning"])
    threshold = cfg.get("threshold", 10)
    severity = cfg.get("severity", "medium")
    suspicious_paths = cfg.get("suspicious_paths", [])

    alerts = []

    if df.empty or "path" not in df.columns:
        return empty_alerts_df()

    suspicious_lower = [p.lower() for p in suspicious_paths]

    df = df.copy()
    df["path_lower"] = df["path"].str.lower()

    df["is_suspicious"] = df["path_lower"].apply(
        lambda p: any(sus in p for sus in suspicious_lower)
    )

    suspicious_404 = df[(df["status"] == 404) & df["is_suspicious"]]

    for ip in suspicious_404["source_ip"].unique():
        ip_events = suspicious_404[suspicious_404["source_ip"] == ip]

        if len(ip_events) >= threshold:
            first_event = ip_events.iloc[0]
            paths = ip_events["path"].unique().tolist()[:5]
            alerts.append(
                create_alert(
                    alert_type="path_scanning",
                    severity=severity,
                    source_ip=ip,
                    timestamp=first_event["timestamp"],
                    evidence=f"{len(ip_events)} suspicious path probes: {', '.join(paths)}",
                )
            )

    if not alerts:
        return empty_alerts_df()
    return pd.DataFrame(alerts)


def detect_scanner_ua(
    df: pd.DataFrame,
    config: dict[str, Any] | None = None,
) -> pd.DataFrame:
    """Detect requests from known scanner user agents.

    Identifies requests with user agents matching known scanning tools.

    Args:
        df: DataFrame with HTTP events (must have: timestamp, source_ip, user_agent)
        config: Detection configuration

    Returns:
        DataFrame of alerts
    """
    if config is None:
        config = load_config()

    cfg = config.get("scanner_user_agents", DEFAULT_CONFIG["scanner_user_agents"])
    severity = cfg.get("severity", "medium")
    patterns = cfg.get("patterns", [])

    alerts = []

    if df.empty or "user_agent" not in df.columns:
        return empty_alerts_df()

    patterns_lower = [p.lower() for p in patterns]

    def is_scanner(ua: str) -> bool:
        if not ua:
            return False
        ua_lower = ua.lower()
        return any(p in ua_lower for p in patterns_lower)

    df = df.copy()
    df["is_scanner"] = df["user_agent"].apply(is_scanner)

    scanner_requests = df[df["is_scanner"]]

    for ip in scanner_requests["source_ip"].unique():
        ip_events = scanner_requests[scanner_requests["source_ip"] == ip]
        first_event = ip_events.iloc[0]

        alerts.append(
            create_alert(
                alert_type="scanner_detected",
                severity=severity,
                source_ip=ip,
                timestamp=first_event["timestamp"],
                evidence=f"Scanner user agent: {first_event['user_agent'][:100]}",
            )
        )

    if not alerts:
        return empty_alerts_df()
    return pd.DataFrame(alerts)


def detect_rate_spike(
    df: pd.DataFrame,
    config: dict[str, Any] | None = None,
) -> pd.DataFrame:
    """Detect abnormal request rate spikes.

    Identifies IPs making too many requests in a short time window.

    Args:
        df: DataFrame with HTTP events (must have: timestamp, source_ip)
        config: Detection configuration

    Returns:
        DataFrame of alerts
    """
    if config is None:
        config = load_config()

    cfg = config.get("rate_spike", DEFAULT_CONFIG["rate_spike"])
    threshold = cfg.get("threshold_per_minute", 100)
    window_minutes = cfg.get("window_minutes", 1)
    severity = cfg.get("severity", "medium")

    alerts = []

    if df.empty or "source_ip" not in df.columns:
        return empty_alerts_df()

    df = df.sort_values("timestamp")

    for ip in df["source_ip"].unique():
        ip_events = df[df["source_ip"] == ip]

        if len(ip_events) < threshold:
            continue

        timestamps = ip_events["timestamp"].tolist()

        for i in range(len(timestamps)):
            window_start = timestamps[i]
            window_end = window_start + timedelta(minutes=window_minutes)

            events_in_window = [
                t for t in timestamps if window_start <= t <= window_end
            ]

            if len(events_in_window) >= threshold:
                alerts.append(
                    create_alert(
                        alert_type="rate_spike",
                        severity=severity,
                        source_ip=ip,
                        timestamp=window_start,
                        evidence=f"{len(events_in_window)} requests in {window_minutes} minute(s)",
                    )
                )
                break

    if not alerts:
        return empty_alerts_df()
    return pd.DataFrame(alerts)


def detect_success_after_failure(
    df: pd.DataFrame,
    config: dict[str, Any] | None = None,
) -> pd.DataFrame:
    """Detect successful login after multiple failures.

    This is a high-severity indicator of possible credential compromise.

    Args:
        df: DataFrame with SSH events
        config: Detection configuration

    Returns:
        DataFrame of alerts
    """
    if config is None:
        config = load_config()

    cfg = config.get("success_after_failure", DEFAULT_CONFIG["success_after_failure"])
    failure_threshold = cfg.get("failure_threshold", 3)
    window_minutes = cfg.get("window_minutes", 30)
    severity = cfg.get("severity", "critical")

    alerts = []

    if df.empty or "event_type" not in df.columns:
        return empty_alerts_df()

    df = df.sort_values("timestamp")

    success_types = ["accepted_password", "accepted_publickey"]
    successes = df[df["event_type"].isin(success_types)]
    failures = df[df["event_type"] == "failed_password"]

    for _, success in successes.iterrows():
        ip = success["source_ip"]
        success_time = success["timestamp"]
        window_start = success_time - timedelta(minutes=window_minutes)

        prior_failures = failures[
            (failures["source_ip"] == ip)
            & (failures["timestamp"] >= window_start)
            & (failures["timestamp"] < success_time)
        ]

        if len(prior_failures) >= failure_threshold:
            alerts.append(
                create_alert(
                    alert_type="success_after_failure",
                    severity=severity,
                    source_ip=ip,
                    timestamp=success_time,
                    evidence=f"Login success after {len(prior_failures)} failures in {window_minutes} minutes",
                )
            )

    if not alerts:
        return empty_alerts_df()
    return pd.DataFrame(alerts)


def run_all_detectors(
    ssh_events: pd.DataFrame | None = None,
    http_events: pd.DataFrame | None = None,
    config: dict[str, Any] | None = None,
) -> pd.DataFrame:
    """Run all detectors and combine results.

    Args:
        ssh_events: DataFrame with SSH/auth events
        http_events: DataFrame with HTTP events
        config: Detection configuration

    Returns:
        Combined DataFrame of all alerts
    """
    all_alerts = []

    if ssh_events is not None and not ssh_events.empty:
        all_alerts.append(detect_ssh_brute_force(ssh_events, config))
        all_alerts.append(detect_credential_stuffing(ssh_events, config))
        all_alerts.append(detect_success_after_failure(ssh_events, config))

    if http_events is not None and not http_events.empty:
        all_alerts.append(detect_path_scanning(http_events, config))
        all_alerts.append(detect_scanner_ua(http_events, config))
        all_alerts.append(detect_rate_spike(http_events, config))

    if not all_alerts:
        return pd.DataFrame()

    combined = pd.concat(all_alerts, ignore_index=True)
    return combined.drop_duplicates(subset=["alert_id"])
