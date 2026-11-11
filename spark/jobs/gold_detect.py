#!/usr/bin/env python3
"""Gold Layer Detection Job.

Reads Silver layer, applies detection rules, and writes alerts
and aggregations to Gold layer.

Usage:
    python gold_detect.py --silver-path /path/to/silver \
        --gold-path /path/to/gold --detection-date 2024-11-10
"""

import argparse
import os
import sys
from datetime import datetime

import pandas as pd
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, lit, count, countDistinct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from spark.jobs.utils.detectors import (
    detect_ssh_brute_force,
    detect_credential_stuffing,
    detect_success_after_failure,
    detect_path_scanning,
    detect_scanner_ua,
    detect_rate_spike,
    load_config,
)


def create_spark_session(app_name: str = "GoldDetect") -> SparkSession:
    """Create a Spark session configured for local mode."""
    return (
        SparkSession.builder
        .appName(app_name)
        .config("spark.sql.parquet.compression.codec", "snappy")
        .config("spark.sql.sources.partitionOverwriteMode", "dynamic")
        .getOrCreate()
    )


def run_detection(
    spark: SparkSession,
    silver_path: str,
    gold_path: str,
    detection_date: str,
    config_path: str | None = None,
) -> dict[str, int]:
    """Run all detectors and write results to Gold layer.

    Args:
        spark: SparkSession
        silver_path: Path to Silver layer root
        gold_path: Path to Gold layer root
        detection_date: Date for partitioning results
        config_path: Optional path to detection config

    Returns:
        Dict with alert counts by type
    """
    config = load_config(config_path)
    all_alerts = []
    counts = {}

    ssh_path = os.path.join(silver_path, "ssh_events")
    if os.path.exists(ssh_path):
        try:
            ssh_df = spark.read.parquet(ssh_path)
            ssh_pd = ssh_df.toPandas()
            if "event_timestamp" in ssh_pd.columns:
                ssh_pd = ssh_pd.rename(columns={"event_timestamp": "timestamp"})

            for detector, name in [
                (detect_ssh_brute_force, "ssh_brute_force"),
                (detect_credential_stuffing, "credential_stuffing"),
                (detect_success_after_failure, "success_after_failure"),
            ]:
                alerts = detector(ssh_pd, config)
                if not alerts.empty:
                    all_alerts.append(alerts)
                    counts[name] = len(alerts)
                    print(f"Detected {len(alerts)} {name} alerts")
        except Exception as e:
            print(f"Error processing SSH events: {e}")

    http_path = os.path.join(silver_path, "http_requests")
    if os.path.exists(http_path):
        try:
            http_df = spark.read.parquet(http_path)
            http_pd = http_df.toPandas()
            if "event_timestamp" in http_pd.columns:
                http_pd = http_pd.rename(columns={"event_timestamp": "timestamp"})

            for detector, name in [
                (detect_path_scanning, "path_scanning"),
                (detect_scanner_ua, "scanner_detected"),
                (detect_rate_spike, "rate_spike"),
            ]:
                alerts = detector(http_pd, config)
                if not alerts.empty:
                    all_alerts.append(alerts)
                    counts[name] = len(alerts)
                    print(f"Detected {len(alerts)} {name} alerts")
        except Exception as e:
            print(f"Error processing HTTP events: {e}")

    if all_alerts:
        combined = pd.concat(all_alerts, ignore_index=True)
        combined["detection_date"] = detection_date

        combined_spark = spark.createDataFrame(combined)
        alerts_path = os.path.join(gold_path, "alerts")
        combined_spark.write.mode("overwrite").partitionBy("detection_date").parquet(alerts_path)
        print(f"Wrote {len(combined)} alerts to {alerts_path}")

        ip_stats = (
            combined.groupby("source_ip")
            .agg(
                alert_count=("alert_id", "count"),
                alert_types=("alert_type", lambda x: ",".join(x.unique())),
                max_severity=("severity", lambda x: x.iloc[0]),
            )
            .reset_index()
        )
        ip_stats["detection_date"] = detection_date

        ip_stats_spark = spark.createDataFrame(ip_stats)
        ip_path = os.path.join(gold_path, "ip_stats")
        ip_stats_spark.write.mode("overwrite").partitionBy("detection_date").parquet(ip_path)

        summary = (
            combined.groupby(["alert_type", "severity"])
            .size()
            .reset_index(name="count")
        )
        summary["detection_date"] = detection_date

        summary_spark = spark.createDataFrame(summary)
        summary_path = os.path.join(gold_path, "attack_summary")
        summary_spark.write.mode("overwrite").partitionBy("detection_date").parquet(summary_path)

    return counts


def main():
    parser = argparse.ArgumentParser(description="Run detection and write to Gold layer")
    parser.add_argument("--silver-path", required=True, help="Path to Silver layer")
    parser.add_argument("--gold-path", required=True, help="Path to Gold layer")
    parser.add_argument(
        "--detection-date",
        default=datetime.now().strftime("%Y-%m-%d"),
        help="Detection date for partitioning",
    )
    parser.add_argument(
        "--config-path",
        default=os.getenv("DETECTION_CONFIG_PATH"),
        help="Path to detection rules config",
    )

    args = parser.parse_args()

    spark = create_spark_session()

    try:
        counts = run_detection(
            spark,
            args.silver_path,
            args.gold_path,
            args.detection_date,
            args.config_path,
        )
        total = sum(counts.values())
        print(f"Total alerts: {total}")
        sys.exit(0)
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
