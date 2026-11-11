"""What the dashboard shows before Streamlit draws it."""

from datetime import date, datetime

import pandas as pd

from dashboard.view import (
    active_ban_ips,
    annotate_bans,
    ban_table,
    data_date_range,
)


def test_active_bans_follow_the_latest_fail2ban_action():
    events = pd.DataFrame(
        [
            {
                "source_ip": "203.0.113.50",
                "action": "ban",
                "jail": "sshd",
                "event_timestamp": datetime(2024, 11, 10, 8, 12),
                "currently_banned": True,
            },
            {
                "source_ip": "198.51.100.10",
                "action": "unban",
                "jail": "sshd",
                "event_timestamp": datetime(2024, 11, 10, 9, 0),
                "currently_banned": False,
            },
        ]
    )

    assert active_ban_ips(events) == {"203.0.113.50"}
    table = ban_table(events)
    assert list(table["source_ip"]) == ["203.0.113.50"]
    assert list(table["jail"]) == ["sshd"]


def test_alerts_are_marked_when_fail2ban_already_banned_the_ip():
    alerts = pd.DataFrame(
        [
            {"source_ip": "203.0.113.50", "alert_type": "ssh_brute_force"},
            {"source_ip": "203.0.113.75", "alert_type": "ssh_brute_force"},
        ]
    )

    marked = annotate_bans(alerts, {"203.0.113.50"})

    assert list(marked["fail2ban"]) == ["já banido", ""]


def test_default_period_covers_alerts_outside_the_last_week():
    timestamps = pd.Series(
        [datetime(2024, 11, 10, 12, 0), datetime(2026, 11, 10, 8, 0)]
    )

    start, end = data_date_range(timestamps, today=date(2026, 11, 11))

    assert start == date(2024, 11, 10)
    assert end == date(2026, 11, 10)


def test_empty_alerts_fall_back_to_the_last_week():
    start, end = data_date_range(pd.Series(dtype="datetime64[ns]"), date(2026, 11, 11))

    assert start == date(2026, 11, 4)
    assert end == date(2026, 11, 11)
