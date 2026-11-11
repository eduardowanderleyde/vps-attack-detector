"""Pure helpers for the Streamlit dashboard.

Kept out of app.py so tests can check what the screen will show
without starting a server.
"""

from datetime import date, timedelta

import pandas as pd


def active_ban_ips(events: pd.DataFrame | None) -> set[str]:
    """IPs whose latest fail2ban action is still a ban."""
    if events is None or events.empty or "source_ip" not in events.columns:
        return set()

    if "currently_banned" in events.columns:
        banned = events[events["currently_banned"].fillna(False).astype(bool)]
        return set(banned["source_ip"].dropna().astype(str))

    if "action" not in events.columns:
        return set()

    ordered = events.dropna(subset=["source_ip"]).copy()
    if "event_timestamp" in ordered.columns:
        ordered = ordered.sort_values("event_timestamp")
    status: dict[str, bool] = {}
    for _, row in ordered.iterrows():
        ip = str(row["source_ip"])
        action = row.get("action")
        if action in ("ban", "restore_ban"):
            status[ip] = True
        elif action == "unban":
            status[ip] = False
    return {ip for ip, is_banned in status.items() if is_banned}


def ban_table(events: pd.DataFrame | None) -> pd.DataFrame:
    """One row per IP that fail2ban currently has banned."""
    columns = ["source_ip", "jail", "action", "event_timestamp"]
    banned = active_ban_ips(events)
    if events is None or events.empty or not banned:
        return pd.DataFrame(columns=columns)

    rows = events[events["source_ip"].astype(str).isin(banned)].copy()
    if "event_timestamp" in rows.columns:
        rows = rows.sort_values("event_timestamp")
    latest = rows.groupby(rows["source_ip"].astype(str), as_index=False).tail(1)
    present = [column for column in columns if column in latest.columns]
    return latest[present].sort_values("source_ip").reset_index(drop=True)


def annotate_bans(alerts: pd.DataFrame, banned: set[str]) -> pd.DataFrame:
    """Add a fail2ban column so each alert shows when that IP is already banned."""
    annotated = alerts.copy()
    if "source_ip" not in annotated.columns:
        annotated["fail2ban"] = ""
        return annotated
    annotated["fail2ban"] = [
        "já banido" if str(ip) in banned else "" for ip in annotated["source_ip"]
    ]
    return annotated


def data_date_range(
    timestamps: pd.Series | None,
    today: date,
    window_days: int = 7,
) -> tuple[date, date]:
    """Default the period to every day that has alerts.

    A fixed 'last 7 days' window hides Caddy and fail2ban samples from 2024
    when SSH samples are stamped with the current year.
    """
    fallback_start = today - timedelta(days=window_days)
    if timestamps is None or len(timestamps) == 0:
        return fallback_start, today

    parsed = pd.to_datetime(timestamps, errors="coerce").dropna()
    if parsed.empty:
        return fallback_start, today
    return parsed.min().date(), parsed.max().date()
