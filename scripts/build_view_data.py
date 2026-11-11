#!/usr/bin/env python3
"""Build ./data gold tables from the sample logs so the dashboard can open.

Does not need Docker or Airflow. Re-running replaces the sample bronze data.
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from spark.jobs.bronze_ingest import create_spark_session, ingest_logs
from spark.jobs.gold_detect import run_detection
from spark.jobs.silver_transform import transform_logs

SAMPLES = ROOT / "data" / "sample_logs"
DATA = ROOT / "data"
SOURCES = {
    "auth": SAMPLES / "auth.log",
    "nginx_access": SAMPLES / "nginx_access.log",
    "nginx_error": SAMPLES / "nginx_error.log",
    "docker": SAMPLES / "docker.log",
    "caddy": SAMPLES / "caddy.json",
    "fail2ban": SAMPLES / "fail2ban.log",
}


def main() -> int:
    missing = [str(path) for path in SOURCES.values() if not path.is_file()]
    if missing:
        print("Missing sample logs:", ", ".join(missing))
        return 1

    spark = create_spark_session("ViewData")
    try:
        for log_type, path in SOURCES.items():
            count = ingest_logs(
                spark,
                str(path),
                str(DATA / "bronze"),
                log_type,
                "2024-11-10",
            )
            print(f"{log_type}: {count} lines")
        transform_logs(
            spark,
            str(DATA / "bronze"),
            str(DATA / "silver"),
            "2024-11-10",
        )
        alerts = run_detection(
            spark,
            str(DATA / "silver"),
            str(DATA / "gold"),
            "2024-11-10",
        )
        print(f"Alerts: {alerts}")
    finally:
        spark.stop()

    print(f"Dashboard data is in {DATA / 'gold'}")
    print("Open it with: DATA_PATH=./data python3 -m streamlit run dashboard/app.py")
    return 0


if __name__ == "__main__":
    os.chdir(ROOT)
    sys.exit(main())
