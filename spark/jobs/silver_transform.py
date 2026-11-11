#!/usr/bin/env python3
"""Silver Layer Transformation Job.

Reads Bronze layer, parses logs, normalizes timestamps to UTC,
optionally enriches IPs with GeoIP, and writes to Silver layer.

Usage:
    python silver_transform.py --bronze-path /path/to/bronze \
        --silver-path /path/to/silver --event-date 2024-11-10
"""

import argparse
import os
import sys
from datetime import datetime

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.functions import (
    col,
    date_format,
    lit,
    to_timestamp,
    udf,
    when,
)
from pyspark.sql.types import (
    IntegerType,
    MapType,
    StringType,
)

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
from spark.jobs.utils.geoip import GeoIPEnricher
from spark.jobs.utils.parsers import (
    parse_auth_log,
    parse_caddy_json,
    parse_docker_json,
    parse_fail2ban_log,
    parse_nginx_access,
    parse_nginx_error,
)


def create_spark_session(app_name: str = "SilverTransform") -> SparkSession:
    """Create a Spark session configured for local mode."""
    return (
        SparkSession.builder.appName(app_name)
        .config("spark.sql.parquet.compression.codec", "snappy")
        .config("spark.sql.sources.partitionOverwriteMode", "dynamic")
        .getOrCreate()
    )


def create_parser_udf(log_type: str):
    """Create a UDF for parsing log lines based on type."""
    parser_map = {
        "auth": parse_auth_log,
        "nginx_access": parse_nginx_access,
        "nginx_error": parse_nginx_error,
        "docker": parse_docker_json,
        "caddy": parse_caddy_json,
        "fail2ban": parse_fail2ban_log,
    }

    parser = parser_map.get(log_type)
    if not parser:
        raise ValueError(f"Unknown log type: {log_type}")

    @udf(MapType(StringType(), StringType()))
    def parse_line(line: str) -> dict[str, str] | None:
        if not line:
            return None
        result = parser(line)
        if result is None:
            return None
        str_result = {}
        for k, v in result.items():
            if v is None:
                str_result[k] = None
            elif isinstance(v, datetime):
                str_result[k] = v.isoformat()
            elif isinstance(v, bool):
                str_result[k] = str(v).lower()
            else:
                str_result[k] = str(v)
        return str_result

    return parse_line


def create_geoip_udf(geoip_db_path: str | None):
    """Create a UDF for GeoIP enrichment."""
    enricher = GeoIPEnricher(geoip_db_path)

    @udf(MapType(StringType(), StringType()))
    def enrich_ip(ip: str) -> dict[str, str]:
        result = enricher.enrich(ip)
        return {k: str(v) if v is not None else None for k, v in result.items()}

    return enrich_ip


def transform_auth_logs(df: DataFrame, geoip_udf) -> DataFrame:
    """Transform auth log events to Silver schema."""
    return df.select(
        to_timestamp(col("parsed.timestamp")).alias("event_timestamp"),
        col("parsed.host").alias("host"),
        col("parsed.service").alias("service"),
        col("parsed.event_type").alias("event_type"),
        col("parsed.source_ip").alias("source_ip"),
        col("parsed.username").alias("username"),
        col("parsed.port").cast(IntegerType()).alias("port"),
        when(col("parsed.invalid_user") == "true", True)
        .otherwise(False)
        .alias("invalid_user"),
        col("source_file"),
        col("ingestion_timestamp"),
        lit("ssh_events").alias("event_category"),
    )


def transform_http_logs(df: DataFrame, geoip_udf) -> DataFrame:
    """Transform HTTP access log events to Silver schema."""
    return df.select(
        to_timestamp(col("parsed.timestamp")).alias("event_timestamp"),
        col("parsed.source_ip").alias("source_ip"),
        col("parsed.method").alias("method"),
        col("parsed.path").alias("path"),
        col("parsed.status").cast(IntegerType()).alias("status"),
        col("parsed.size").cast(IntegerType()).alias("size"),
        col("parsed.user_agent").alias("user_agent"),
        col("parsed.referer").alias("referer"),
        col("source_file"),
        col("ingestion_timestamp"),
        lit("http_requests").alias("event_category"),
    )


def transform_error_logs(df: DataFrame, geoip_udf) -> DataFrame:
    """Transform nginx error log events to Silver schema."""
    return df.select(
        to_timestamp(col("parsed.timestamp")).alias("event_timestamp"),
        col("parsed.level").alias("level"),
        col("parsed.source_ip").alias("source_ip"),
        col("parsed.message").alias("message"),
        col("source_file"),
        col("ingestion_timestamp"),
        lit("error_logs").alias("event_category"),
    )


def transform_fail2ban_logs(df: DataFrame, geoip_udf) -> DataFrame:
    """Transform fail2ban events to Silver schema."""
    return df.select(
        to_timestamp(col("parsed.timestamp")).alias("event_timestamp"),
        col("parsed.action").alias("action"),
        col("parsed.jail").alias("jail"),
        col("parsed.source_ip").alias("source_ip"),
        col("source_file"),
        col("ingestion_timestamp"),
        lit("fail2ban_events").alias("event_category"),
    )


def transform_container_logs(df: DataFrame, geoip_udf) -> DataFrame:
    """Transform Docker container log events to Silver schema."""
    return df.select(
        to_timestamp(col("parsed.timestamp")).alias("event_timestamp"),
        col("parsed.stream").alias("stream"),
        col("parsed.message").alias("message"),
        col("source_file"),
        col("ingestion_timestamp"),
        lit("container_logs").alias("event_category"),
    )


def transform_logs(
    spark: SparkSession,
    bronze_path: str,
    silver_path: str,
    event_date: str,
    geoip_db_path: str | None = None,
) -> dict[str, int]:
    """Transform Bronze logs to Silver layer.

    Args:
        spark: SparkSession
        bronze_path: Path to Bronze layer root
        silver_path: Path to Silver layer root
        event_date: Date to process (for filtering)
        geoip_db_path: Optional path to GeoIP database

    Returns:
        Dict with counts per log type
    """
    counts = {}
    written_categories: set[str] = set()
    geoip_udf = create_geoip_udf(geoip_db_path)

    log_types = {
        "auth": ("ssh_events", transform_auth_logs),
        "nginx_access": ("http_requests", transform_http_logs),
        "nginx_error": ("error_logs", transform_error_logs),
        "docker": ("container_logs", transform_container_logs),
        "caddy": ("http_requests", transform_http_logs),
        "fail2ban": ("fail2ban_events", transform_fail2ban_logs),
    }

    for log_type, (category, transformer) in log_types.items():
        bronze_dir = os.path.join(bronze_path, log_type)

        if not os.path.exists(bronze_dir):
            print(f"Bronze directory not found: {bronze_dir}")
            counts[log_type] = 0
            continue

        try:
            df = spark.read.parquet(bronze_dir)
        except Exception as e:
            print(f"Failed to read {bronze_dir}: {e}")
            counts[log_type] = 0
            continue

        parse_udf = create_parser_udf(log_type)
        df = df.withColumn("parsed", parse_udf(col("raw_line")))

        df_parsed = df.filter(col("parsed").isNotNull())
        df_errors = df.filter(col("parsed").isNull())

        if df_parsed.count() > 0:
            df_silver = transformer(df_parsed, geoip_udf)

            if "source_ip" in df_silver.columns:
                geo = geoip_udf(col("source_ip"))
                df_silver = df_silver.withColumn("geo", geo)
                df_silver = df_silver.withColumn("country", col("geo.country"))
                df_silver = df_silver.withColumn("city", col("geo.city"))
                df_silver = df_silver.drop("geo")

            df_silver = df_silver.withColumn(
                "event_date", date_format(col("event_timestamp"), "yyyy-MM-dd")
            )

            output_dir = os.path.join(silver_path, category)
            write_mode = "append" if category in written_categories else "overwrite"
            df_silver.write.mode(write_mode).partitionBy("event_date").parquet(
                output_dir
            )
            written_categories.add(category)

            counts[log_type] = df_silver.count()
            print(f"Transformed {counts[log_type]} {log_type} events to {output_dir}")
        else:
            counts[log_type] = 0

        if df_errors.count() > 0:
            error_dir = os.path.join(silver_path, "_errors", log_type)
            df_errors.write.mode("overwrite").parquet(error_dir)
            print(f"Wrote {df_errors.count()} unparseable lines to {error_dir}")

    return counts


def main():
    parser = argparse.ArgumentParser(description="Transform Bronze to Silver layer")
    parser.add_argument("--bronze-path", required=True, help="Path to Bronze layer")
    parser.add_argument("--silver-path", required=True, help="Path to Silver layer")
    parser.add_argument(
        "--event-date",
        default=datetime.now().strftime("%Y-%m-%d"),
        help="Event date to process",
    )
    parser.add_argument(
        "--geoip-db",
        default=os.getenv("GEOIP_DB_PATH"),
        help="Path to GeoIP database",
    )

    args = parser.parse_args()

    spark = create_spark_session()

    try:
        counts = transform_logs(
            spark,
            args.bronze_path,
            args.silver_path,
            args.event_date,
            args.geoip_db,
        )
        total = sum(counts.values())
        print(f"Total transformed: {total} events")
        sys.exit(0 if total > 0 else 1)
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
