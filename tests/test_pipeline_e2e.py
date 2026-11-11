"""End-to-end checks for the bronze, silver, and gold pipeline.

Sample logs are ingested with checkpoints, parsed, and detected. Trusted
public-key logins are ignored, and the blocklist drops IPs fail2ban already banned.
"""

import os
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import pytest

SAMPLE_LOGS = Path(__file__).resolve().parents[1] / "data" / "sample_logs"


def test_dag_wires_checkpoints_caddy_fail2ban_and_trusted_ips():
    """The ingest DAG must pass checkpoints, new log types, and the allowlist."""
    dag = (
        Path(__file__).resolve().parents[1]
        / "airflow"
        / "dags"
        / "ingest_and_detect.py"
    ).read_text()
    assert "--checkpoint-path" in dag
    assert "--log-type caddy" in dag
    assert "--log-type fail2ban" in dag
    assert "TRUSTED_IP_CIDRS" in dag


def test_success_after_failure_skips_trusted_publickey_only():
    """ADR-012: trusted public-key success is quiet; trusted password success is not."""
    from spark.jobs.utils.detectors import detect_success_after_failure

    now = datetime(2024, 11, 10, 12, 0, 0)
    rows = []
    for ip, success in (
        ("192.0.2.10", "accepted_publickey"),
        ("192.0.2.11", "accepted_password"),
    ):
        for minute in range(3):
            rows.append(
                {
                    "timestamp": now - timedelta(minutes=10 - minute),
                    "event_type": "failed_password",
                    "source_ip": ip,
                    "username": "root",
                }
            )
        rows.append(
            {
                "timestamp": now,
                "event_type": success,
                "source_ip": ip,
                "username": "root",
            }
        )

    alerts = detect_success_after_failure(
        pd.DataFrame(rows),
        trusted_cidrs=["192.0.2.10/32", "192.0.2.11/32"],
    )
    assert list(alerts["source_ip"]) == ["192.0.2.11"]


def test_blocklist_skips_ips_already_banned_by_fail2ban(tmp_path):
    """The blocklist keeps new threats and drops IPs with an active fail2ban ban."""
    from scripts.generate_blocklist import generate_blocklist

    alerts = pd.DataFrame(
        [
            {
                "alert_id": "a1",
                "alert_type": "ssh_brute_force",
                "severity": "high",
                "source_ip": "203.0.113.50",
            },
            {
                "alert_id": "a2",
                "alert_type": "ssh_brute_force",
                "severity": "high",
                "source_ip": "203.0.113.75",
            },
        ]
    )
    alerts_path = tmp_path / "alerts"
    alerts.to_parquet(alerts_path)
    fail2ban_log = tmp_path / "fail2ban.log"
    fail2ban_log.write_text(
        "2024-11-10 08:12:00,123 fail2ban.actions [3210]: NOTICE [sshd] Ban 203.0.113.50\n"
        "2024-11-10 09:00:00,123 fail2ban.actions [3210]: NOTICE [sshd] Ban 198.51.100.10\n"
        "2024-11-10 09:10:00,123 fail2ban.actions [3210]: NOTICE [sshd] Unban 198.51.100.10\n"
    )
    output = tmp_path / "blocklist.txt"

    count = generate_blocklist(
        str(alerts_path),
        str(output),
        fail2ban_log_path=str(fail2ban_log),
    )

    text = output.read_text()
    assert count == 1
    assert "203.0.113.75" in text
    assert "203.0.113.50\n" not in text


@pytest.fixture(scope="module")
def spark():
    """One local Spark session for the pipeline tests."""
    pytest.importorskip("pyspark")
    from spark.jobs.bronze_ingest import create_spark_session

    session = create_spark_session("pipeline-e2e")
    yield session
    session.stop()


def test_sample_logs_flow_through_bronze_silver_gold(spark, tmp_path, monkeypatch):
    """Sample auth, HTTP, Caddy, and fail2ban logs become silver events and gold alerts."""
    from spark.jobs.bronze_ingest import ingest_logs
    from spark.jobs.gold_detect import run_detection
    from spark.jobs.silver_transform import transform_logs

    monkeypatch.setenv("TRUSTED_IP_CIDRS", "192.168.1.0/24")
    bronze = tmp_path / "bronze"
    silver = tmp_path / "silver"
    gold = tmp_path / "gold"
    sources = {
        "auth": SAMPLE_LOGS / "auth.log",
        "nginx_access": SAMPLE_LOGS / "nginx_access.log",
        "nginx_error": SAMPLE_LOGS / "nginx_error.log",
        "docker": SAMPLE_LOGS / "docker.log",
        "caddy": SAMPLE_LOGS / "caddy.json",
        "fail2ban": SAMPLE_LOGS / "fail2ban.log",
    }
    for log_type, path in sources.items():
        ingested = ingest_logs(
            spark,
            str(path),
            str(bronze),
            log_type,
            "2024-11-10",
            checkpoint_path=str(tmp_path / "checkpoints" / f"{log_type}.json"),
        )
        assert ingested > 0, log_type

    counts = transform_logs(spark, str(bronze), str(silver), "2024-11-10")
    assert counts["auth"] > 0
    assert counts["caddy"] > 0
    assert counts["fail2ban"] > 0
    assert (silver / "http_requests").exists()
    assert (silver / "fail2ban_events").exists()

    alerts = run_detection(spark, str(silver), str(gold), "2024-11-10")
    assert alerts.get("ssh_brute_force", 0) > 0
    assert alerts.get("scanner_detected", 0) > 0

    banned = spark.read.parquet(str(gold / "fail2ban_events")).toPandas()
    still_banned = set(banned.loc[banned["currently_banned"], "source_ip"])
    assert "203.0.113.50" in still_banned
    assert "198.51.100.10" not in still_banned


def test_checkpoint_does_not_replay_lines(spark, tmp_path):
    """A second ingest of an unchanged file writes nothing and keeps the checkpoint."""
    from spark.jobs.bronze_ingest import ingest_logs

    log_path = tmp_path / "auth.log"
    log_path.write_text(
        "Nov 10 08:10:00 vps sshd[1]: Failed password for root from 203.0.113.50 port 22 ssh2\n"
    )
    checkpoint = tmp_path / "auth.json"
    bronze = tmp_path / "bronze"

    first = ingest_logs(
        spark, str(log_path), str(bronze), "auth", "2024-11-10", str(checkpoint)
    )
    second = ingest_logs(
        spark, str(log_path), str(bronze), "auth", "2024-11-10", str(checkpoint)
    )
    log_path.write_text(
        log_path.read_text()
        + "Nov 10 08:10:05 vps sshd[2]: Failed password for root from 203.0.113.50 port 23 ssh2\n"
    )
    third = ingest_logs(
        spark, str(log_path), str(bronze), "auth", "2024-11-10", str(checkpoint)
    )

    assert first == 1
    assert second == 0
    assert third == 1
    assert checkpoint.exists()
    assert os.path.getsize(checkpoint) > 0
