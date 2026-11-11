#!/usr/bin/env python3
"""Generate blocklist from high-severity alerts.

Produces a text file with IPs to optionally block with fail2ban/ufw.
NEVER applies blocks automatically - for manual review only.
"""

import argparse
import os
import sys
from datetime import datetime

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from spark.jobs.utils.parsers import parse_fail2ban_log


def get_fail2ban_banned_ips(fail2ban_log_path: str | None = None) -> set[str]:
    """Return IPs whose latest fail2ban action is ban or restore_ban."""
    if fail2ban_log_path is None:
        fail2ban_log_path = os.getenv("HOST_FAIL2BAN_LOG", "/var/log/fail2ban.log")
    if not os.path.exists(fail2ban_log_path):
        return set()

    ban_status: dict[str, bool] = {}
    try:
        with open(fail2ban_log_path) as handle:
            for line in handle:
                parsed = parse_fail2ban_log(line.strip())
                if not parsed:
                    continue
                action = parsed.get("action")
                ip = parsed.get("source_ip")
                if not ip:
                    continue
                if action in ("ban", "restore_ban"):
                    ban_status[ip] = True
                elif action == "unban":
                    ban_status[ip] = False
    except OSError:
        return set()
    return {ip for ip, banned in ban_status.items() if banned}


def generate_blocklist(
    alerts_path: str,
    output_path: str,
    min_severity: str = "high",
    min_alerts: int = 1,
    skip_fail2ban: bool = True,
    fail2ban_log_path: str | None = None,
) -> int:
    """Generate blocklist from alerts.

    Args:
        alerts_path: Path to alerts Parquet directory
        output_path: Output file path
        min_severity: Minimum severity to include (critical, high, medium, low)
        min_alerts: Minimum number of alerts per IP to include
        skip_fail2ban: Drop IPs fail2ban has already banned
        fail2ban_log_path: fail2ban log used when skip_fail2ban is set

    Returns:
        Number of IPs in blocklist
    """
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    min_level = severity_order.get(min_severity, 1)

    if not os.path.exists(alerts_path):
        print(f"Alerts path not found: {alerts_path}")
        return 0

    try:
        df = pd.read_parquet(alerts_path)
    except Exception as e:
        print(f"Failed to read alerts: {e}")
        return 0

    if df.empty:
        print("No alerts found")
        return 0

    df["severity_level"] = df["severity"].map(severity_order)
    filtered = df[df["severity_level"] <= min_level]
    if skip_fail2ban:
        already_banned = get_fail2ban_banned_ips(fail2ban_log_path)
        if already_banned:
            print(f"Skipping {len(already_banned)} IPs already banned by fail2ban")
            filtered = filtered[~filtered["source_ip"].isin(already_banned)]

    ip_counts = (
        filtered.groupby("source_ip")
        .agg(
            alert_count=("alert_id", "count"),
            min_severity=("severity_level", "min"),
            alert_types=("alert_type", lambda x: ",".join(x.unique())),
        )
        .reset_index()
    )

    ip_counts = ip_counts[ip_counts["alert_count"] >= min_alerts]
    ip_counts = ip_counts.sort_values("alert_count", ascending=False)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    with open(output_path, "w") as f:
        f.write("# VPS Attack Detector - Blocklist\n")
        f.write(f"# Generated: {datetime.now().isoformat()}\n")
        f.write(f"# Total IPs: {len(ip_counts)}\n")
        f.write(f"# Minimum severity: {min_severity}\n")
        f.write(f"# Minimum alerts per IP: {min_alerts}\n")
        f.write("#\n")
        f.write("# ⚠️  REVIEW BEFORE APPLYING!\n")
        f.write("# This list is for MANUAL review only.\n")
        f.write("# Verify each IP before blocking.\n")
        f.write("#\n")
        f.write("# Usage with fail2ban:\n")
        f.write("#   sudo fail2ban-client set sshd banip <IP>\n")
        f.write("#\n")
        f.write("# Usage with ufw:\n")
        f.write("#   sudo ufw deny from <IP>\n")
        f.write("#\n\n")

        for _, row in ip_counts.iterrows():
            f.write(f"# {row['alert_count']} alerts: {row['alert_types']}\n")
            f.write(f"{row['source_ip']}\n")

    print(f"Generated blocklist with {len(ip_counts)} IPs: {output_path}")
    return len(ip_counts)


def main():
    parser = argparse.ArgumentParser(
        description="Generate blocklist from attack alerts"
    )
    parser.add_argument(
        "--alerts-path",
        default=os.path.join(os.getenv("DATA_PATH", "./data"), "gold", "alerts"),
        help="Path to alerts Parquet directory",
    )
    parser.add_argument(
        "--output-path",
        default=os.path.join(
            os.getenv("DATA_PATH", "./data"), "output", "blocklist.txt"
        ),
        help="Output file path",
    )
    parser.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low"],
        default="high",
        help="Minimum severity to include",
    )
    parser.add_argument(
        "--min-alerts",
        type=int,
        default=1,
        help="Minimum alerts per IP to include",
    )
    parser.add_argument(
        "--no-skip-fail2ban",
        action="store_true",
        help="Include IPs that fail2ban has already banned",
    )
    parser.add_argument(
        "--fail2ban-log",
        default=None,
        help="Path to fail2ban.log",
    )

    args = parser.parse_args()

    count = generate_blocklist(
        args.alerts_path,
        args.output_path,
        args.min_severity,
        args.min_alerts,
        skip_fail2ban=not args.no_skip_fail2ban,
        fail2ban_log_path=args.fail2ban_log,
    )

    sys.exit(0 if count > 0 else 1)


if __name__ == "__main__":
    main()
