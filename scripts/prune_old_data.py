#!/usr/bin/env python3
"""Data retention script - removes old partitions per ADR-009.

Removes Parquet partitions older than configured retention period.
Supports bronze, silver, and gold layers.

Usage:
    python prune_old_data.py --data-path /opt/spark/data --retention-days 30
    python prune_old_data.py --dry-run  # Show what would be deleted
"""

import argparse
import logging
import os
import re
import shutil
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

DATE_PARTITION_PATTERN = re.compile(
    r"(?:ingestion_date|event_date|detection_date)=(\d{4}-\d{2}-\d{2})"
)


def find_date_partitions(base_path: Path) -> Iterator[tuple[Path, datetime]]:
    """Find all date-partitioned directories under base_path.

    Supports partition naming conventions:
    - ingestion_date=YYYY-MM-DD (bronze)
    - event_date=YYYY-MM-DD (silver)
    - detection_date=YYYY-MM-DD (gold)

    Args:
        base_path: Root path to search

    Yields:
        Tuples of (partition_path, partition_date)
    """
    if not base_path.exists():
        return

    for root, dirs, _ in os.walk(base_path):
        for dir_name in dirs:
            match = DATE_PARTITION_PATTERN.match(dir_name)
            if match:
                date_str = match.group(1)
                try:
                    partition_date = datetime.strptime(date_str, "%Y-%m-%d")
                    yield Path(root) / dir_name, partition_date
                except ValueError:
                    continue


def get_partitions_to_prune(
    base_path: Path,
    cutoff_date: datetime,
    layers: list[str] | None = None,
) -> list[tuple[Path, datetime]]:
    """Get list of partitions older than cutoff date.

    Args:
        base_path: Root data path (e.g., /opt/spark/data)
        cutoff_date: Delete partitions older than this
        layers: Layers to prune (default: bronze, silver, gold)

    Returns:
        List of (partition_path, partition_date) to be pruned
    """
    if layers is None:
        layers = ["bronze", "silver", "gold"]

    to_prune = []
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)

    for layer in layers:
        layer_path = base_path / layer
        for partition_path, partition_date in find_date_partitions(layer_path):
            if partition_date.date() == today.date():
                continue

            if partition_date < cutoff_date:
                to_prune.append((partition_path, partition_date))

    to_prune.sort(key=lambda x: (x[1], x[0]))
    return to_prune


def calculate_size(path: Path) -> int:
    """Calculate total size of a directory in bytes."""
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def format_size(size_bytes: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def prune_partitions(
    partitions: list[tuple[Path, datetime]],
    dry_run: bool = False,
    audit_log_path: Path | None = None,
) -> dict:
    """Remove old partitions.

    Args:
        partitions: List of (path, date) tuples to remove
        dry_run: If True, don't actually delete
        audit_log_path: Optional path to write audit log

    Returns:
        Summary dict with counts and sizes
    """
    removed_count = 0
    removed_bytes = 0
    errors = []
    audit_lines = []

    for partition_path, partition_date in partitions:
        size = calculate_size(partition_path)

        if dry_run:
            logger.info(
                f"[DRY-RUN] Would remove: {partition_path} ({format_size(size)})"
            )
        else:
            try:
                shutil.rmtree(partition_path)
                logger.info(f"Removed: {partition_path} ({format_size(size)})")
                removed_count += 1
                removed_bytes += size

                if audit_log_path:
                    audit_lines.append(
                        f"{datetime.now().astimezone().isoformat()} Removed: {partition_path}"
                    )
            except OSError as e:
                logger.error(f"Failed to remove {partition_path}: {e}")
                errors.append(str(partition_path))

    if audit_log_path and audit_lines and not dry_run:
        audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(audit_log_path, "a") as f:
            f.writelines(line + "\n" for line in audit_lines)
            f.write(
                f"{datetime.now().astimezone().isoformat()} Total: {removed_count} partitions, "
                f"{format_size(removed_bytes)} freed\n"
            )

    return {
        "partitions_found": len(partitions),
        "partitions_removed": removed_count,
        "bytes_freed": removed_bytes,
        "errors": errors,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Prune old data partitions per retention policy"
    )
    parser.add_argument(
        "--data-path",
        type=Path,
        default=Path(os.environ.get("DATA_PATH", "/opt/spark/data")),
        help="Root data directory (default: $DATA_PATH or /opt/spark/data)",
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=int(os.environ.get("DATA_RETENTION_DAYS", "30")),
        help="Days to retain data (default: $DATA_RETENTION_DAYS or 30)",
    )
    parser.add_argument(
        "--layers",
        nargs="+",
        default=["bronze", "silver", "gold"],
        help="Layers to prune (default: bronze silver gold)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be deleted without actually deleting",
    )
    parser.add_argument(
        "--audit-log",
        type=Path,
        default=None,
        help="Path to audit log file (default: none)",
    )

    args = parser.parse_args()

    cutoff_date = datetime.now() - timedelta(days=args.retention_days)

    logger.info(f"Data path: {args.data_path}")
    logger.info(f"Retention: {args.retention_days} days")
    logger.info(f"Cutoff date: {cutoff_date.date()}")
    logger.info(f"Layers: {args.layers}")
    if args.dry_run:
        logger.info("Mode: DRY-RUN (no changes will be made)")

    partitions = get_partitions_to_prune(args.data_path, cutoff_date, args.layers)

    if not partitions:
        logger.info("No partitions to prune")
        return

    total_size = sum(calculate_size(p) for p, _ in partitions)
    logger.info(
        f"Found {len(partitions)} partitions to prune ({format_size(total_size)})"
    )

    result = prune_partitions(partitions, args.dry_run, args.audit_log)

    if args.dry_run:
        logger.info(f"[DRY-RUN] Would remove {result['partitions_found']} partitions")
    else:
        logger.info(
            f"Pruned {result['partitions_removed']} partitions, "
            f"freed {format_size(result['bytes_freed'])}"
        )
        if result["errors"]:
            logger.warning(f"Errors on {len(result['errors'])} partitions")


if __name__ == "__main__":
    main()
