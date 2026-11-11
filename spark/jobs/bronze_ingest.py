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
    current_timestamp,
    input_file_name,
    lit,
    monotonically_increasing_id,
)
from pyspark.sql.types import (
    LongType,
    StringType,
    StructField,
    StructType,
    TimestampType,
)

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
from spark.jobs.utils.checkpoints import IncrementalReader

BRONZE_SCHEMA = StructType(
    [
        StructField("raw_line", StringType(), False),
        StructField("source_file", StringType(), False),
        StructField("line_number", LongType(), False),
        StructField("ingestion_timestamp", TimestampType(), False),
        StructField("log_type", StringType(), False),
        StructField("ingestion_date", StringType(), False),
    ]
)


def create_spark_session(app_name: str = "BronzeIngest") -> SparkSession:
    """Create a Spark session configured for local mode."""
    return (
        SparkSession.builder.appName(app_name)
        .config("spark.sql.parquet.compression.codec", "snappy")
        .config("spark.sql.sources.partitionOverwriteMode", "dynamic")
        .getOrCreate()
    )


LOG_TYPES = ["auth", "nginx_access", "nginx_error", "docker", "caddy", "fail2ban"]
_SKIPPED_SUFFIXES = (".gz", ".xz", ".bz2", ".zip")


def list_log_files(input_path: str) -> list[str]:
    """Return readable log files under a file or directory.

    Compressed archives are skipped. A Caddy directory such as
    /var/log/caddy holds access.log plus rotated copies, not one caddy.json.
    """
    if os.path.isfile(input_path):
        return [] if _is_skipped_log(os.path.basename(input_path)) else [input_path]
    if not os.path.isdir(input_path):
        return []

    found = []
    for dirpath, dirnames, filenames in os.walk(input_path):
        dirnames[:] = sorted(name for name in dirnames if not name.startswith("."))
        for name in sorted(filenames):
            if name.startswith(".") or _is_skipped_log(name):
                continue
            found.append(os.path.join(dirpath, name))
    return found


def _is_skipped_log(name: str) -> bool:
    return name.endswith(_SKIPPED_SUFFIXES)


def _write_text_df(
    df,
    source_file: str,
    output_path: str,
    log_type: str,
    ingestion_date: str,
    mode: str,
) -> int:
    """Attach bronze metadata and write Parquet. Returns the row count."""
    df = df.withColumn("source_file", lit(source_file))
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
    df.write.mode(mode).partitionBy("ingestion_date").parquet(output_dir)
    count = df.count()
    print(f"Ingested {count} lines to {output_dir}")
    return count


def _ingest_incremental(
    spark: SparkSession,
    input_path: str,
    output_path: str,
    log_type: str,
    ingestion_date: str,
    checkpoint_path: str,
) -> int:
    """Read only the bytes after the checkpoint and advance it after a successful write."""
    os.makedirs(os.path.dirname(os.path.abspath(checkpoint_path)) or ".", exist_ok=True)
    with IncrementalReader(input_path, checkpoint_path) as reader:
        rows = [(line,) for line, _offset in reader]
        if not rows:
            print(f"No new lines in {input_path}")
            return 0
        df = spark.createDataFrame(rows, ["value"])
        count = _write_text_df(
            df,
            os.path.abspath(input_path),
            output_path,
            log_type,
            ingestion_date,
            mode="append",
        )
        reader.commit()
        return count


def ingest_logs(
    spark: SparkSession,
    input_path: str,
    output_path: str,
    log_type: str,
    ingestion_date: str,
    checkpoint_path: str | None = None,
) -> int:
    """Ingest logs from input path to Bronze layer.

    Args:
        spark: SparkSession
        input_path: Path to raw log files (file or directory)
        output_path: Path to Bronze layer root
        log_type: Type of log (auth, nginx, docker, caddy, fail2ban)
        ingestion_date: Date string for partitioning (YYYY-MM-DD)
        checkpoint_path: When set for a single file, ingest only new bytes
            and advance the checkpoint after the Parquet write succeeds.

    Returns:
        Number of lines ingested
    """
    if not os.path.exists(input_path):
        print(f"Input path does not exist: {input_path}")
        return 0

    files = list_log_files(input_path)
    if checkpoint_path and len(files) == 1:
        return _ingest_incremental(
            spark,
            files[0],
            output_path,
            log_type,
            ingestion_date,
            checkpoint_path,
        )
    if checkpoint_path and len(files) > 1:
        total = 0
        for path in files:
            relative = os.path.relpath(path, input_path).replace(os.sep, "__")
            total += _ingest_incremental(
                spark,
                path,
                output_path,
                log_type,
                ingestion_date,
                os.path.join(checkpoint_path, f"{relative}.json"),
            )
        return total

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
        choices=LOG_TYPES,
        help="Type of log being ingested",
    )
    parser.add_argument(
        "--ingestion-date",
        default=datetime.now().strftime("%Y-%m-%d"),
        help="Ingestion date (default: today)",
    )
    parser.add_argument(
        "--checkpoint-path",
        default=None,
        help=(
            "Checkpoint JSON path for one file, or a directory when "
            "--input-path is a directory of logs (one checkpoint per file)."
        ),
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
            checkpoint_path=args.checkpoint_path,
        )
        if args.checkpoint_path:
            sys.exit(0)
        sys.exit(0 if count > 0 else 1)
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
