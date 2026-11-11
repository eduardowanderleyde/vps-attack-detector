#!/usr/bin/env python3
"""Bronze Layer Ingestion Job.

Reads raw log files and writes to Bronze layer as Parquet,
preserving original content with metadata.

Usage:
    python bronze_ingest.py --input-path /path/to/logs --output-path /path/to/bronze \
        --log-type auth --ingestion-date 2024-11-10
"""

import argparse
import os
import sys
from datetime import datetime

from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    lit,
    input_file_name,
    monotonically_increasing_id,
    current_timestamp,
)
from pyspark.sql.types import StructType, StructField, StringType, LongType, TimestampType


BRONZE_SCHEMA = StructType([
    StructField("raw_line", StringType(), False),
    StructField("source_file", StringType(), False),
    StructField("line_number", LongType(), False),
    StructField("ingestion_timestamp", TimestampType(), False),
    StructField("log_type", StringType(), False),
    StructField("ingestion_date", StringType(), False),
])


def create_spark_session(app_name: str = "BronzeIngest") -> SparkSession:
    """Create a Spark session configured for local mode."""
    return (
        SparkSession.builder
        .appName(app_name)
        .config("spark.sql.parquet.compression.codec", "snappy")
        .config("spark.sql.sources.partitionOverwriteMode", "dynamic")
        .getOrCreate()
    )


def ingest_logs(
    spark: SparkSession,
    input_path: str,
    output_path: str,
    log_type: str,
    ingestion_date: str,
) -> int:
    """Ingest logs from input path to Bronze layer.

    Args:
        spark: SparkSession
        input_path: Path to raw log files (file or directory)
        output_path: Path to Bronze layer root
        log_type: Type of log (auth, nginx_access, nginx_error, docker)
        ingestion_date: Date string for partitioning (YYYY-MM-DD)

    Returns:
        Number of lines ingested
    """
    if not os.path.exists(input_path):
        print(f"Input path does not exist: {input_path}")
        return 0

    if os.path.isfile(input_path):
        files = [input_path]
    else:
        files = [
            os.path.join(input_path, f)
            for f in os.listdir(input_path)
            if os.path.isfile(os.path.join(input_path, f))
            and not f.startswith(".")
        ]

    if not files:
        print(f"No files found in {input_path}")
        return 0

    df = spark.read.text(files)

    df = df.withColumn("source_file", input_file_name())
    df = df.withColumn("line_number", monotonically_increasing_id())
    df = df.withColumn("ingestion_timestamp", current_timestamp())
    df = df.withColumn("log_type", lit(log_type))
    df = df.withColumn("ingestion_date", lit(ingestion_date))

    df = df.select(
        df["value"].alias("raw_line"),
        "source_file",
        "line_number",
        "ingestion_timestamp",
        "log_type",
        "ingestion_date",
    )

    output_dir = os.path.join(output_path, log_type)

    df.write.mode("overwrite").partitionBy("ingestion_date").parquet(output_dir)

    count = df.count()
    print(f"Ingested {count} lines from {len(files)} file(s) to {output_dir}")
    return count


def main():
    parser = argparse.ArgumentParser(description="Ingest logs to Bronze layer")
    parser.add_argument("--input-path", required=True, help="Path to raw log files")
    parser.add_argument("--output-path", required=True, help="Path to Bronze layer")
    parser.add_argument(
        "--log-type",
        required=True,
        choices=["auth", "nginx_access", "nginx_error", "docker"],
        help="Type of log being ingested",
    )
    parser.add_argument(
        "--ingestion-date",
        default=datetime.now().strftime("%Y-%m-%d"),
        help="Ingestion date (default: today)",
    )

    args = parser.parse_args()

    spark = create_spark_session()

    try:
        count = ingest_logs(
            spark,
            args.input_path,
            args.output_path,
            args.log_type,
            args.ingestion_date,
        )
        sys.exit(0 if count > 0 else 1)
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
