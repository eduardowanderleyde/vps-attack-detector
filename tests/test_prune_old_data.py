"""Tests for data retention/pruning script (Ticket 107, ADR-009).

Validates partition discovery, age filtering, and safe deletion.
"""

import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from scripts.prune_old_data import (
    calculate_size,
    find_date_partitions,
    format_size,
    get_partitions_to_prune,
    prune_partitions,
)


@pytest.fixture
def temp_data_dir():
    """Create a temporary data directory with sample partitions."""
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)

        today = datetime.now()
        yesterday = today - timedelta(days=1)
        old_date = today - timedelta(days=40)
        very_old = today - timedelta(days=60)

        for layer in ["bronze", "silver", "gold"]:
            layer_path = base / layer / "events"
            layer_path.mkdir(parents=True)

            partition_key = {
                "bronze": "ingestion_date",
                "silver": "event_date",
                "gold": "detection_date",
            }[layer]

            for date in [today, yesterday, old_date, very_old]:
                part_dir = layer_path / f"{partition_key}={date.strftime('%Y-%m-%d')}"
                part_dir.mkdir()
                (part_dir / "part-00000.parquet").write_text("dummy data")

        yield base


class TestFindDatePartitions:
    """Tests for partition discovery."""

    def test_finds_all_partition_types(self, temp_data_dir):
        """Should find ingestion_date, event_date, and detection_date partitions."""
        partitions = list(find_date_partitions(temp_data_dir))
        assert len(partitions) == 12

    def test_returns_correct_dates(self, temp_data_dir):
        """Should parse dates correctly."""
        partitions = list(find_date_partitions(temp_data_dir))
        for path, date in partitions:
            assert isinstance(date, datetime)
            assert "=" in str(path)

    def test_empty_dir_returns_nothing(self):
        """Should return empty iterator for empty/nonexistent dir."""
        with tempfile.TemporaryDirectory() as tmpdir:
            partitions = list(find_date_partitions(Path(tmpdir)))
            assert partitions == []


class TestGetPartitionsToPrune:
    """Tests for partition filtering."""

    def test_filters_old_partitions(self, temp_data_dir):
        """Should only return partitions older than cutoff."""
        cutoff = datetime.now() - timedelta(days=30)
        partitions = get_partitions_to_prune(temp_data_dir, cutoff)

        for path, date in partitions:
            assert date < cutoff

    def test_excludes_today(self, temp_data_dir):
        """Should never prune today's partition."""
        cutoff = datetime.now() + timedelta(days=1)
        partitions = get_partitions_to_prune(temp_data_dir, cutoff)

        today_str = datetime.now().strftime("%Y-%m-%d")
        for path, _ in partitions:
            assert today_str not in str(path)

    def test_filters_by_layer(self, temp_data_dir):
        """Should only prune specified layers."""
        cutoff = datetime.now() - timedelta(days=30)
        partitions = get_partitions_to_prune(temp_data_dir, cutoff, layers=["bronze"])

        for path, _ in partitions:
            assert "bronze" in str(path)
            assert "silver" not in str(path)
            assert "gold" not in str(path)

    def test_returns_sorted(self, temp_data_dir):
        """Should return partitions sorted by date."""
        cutoff = datetime.now() - timedelta(days=30)
        partitions = get_partitions_to_prune(temp_data_dir, cutoff)

        dates = [date for _, date in partitions]
        assert dates == sorted(dates)


class TestPrunePartitions:
    """Tests for partition deletion."""

    def test_dry_run_deletes_nothing(self, temp_data_dir):
        """Dry run should not delete any files."""
        cutoff = datetime.now() - timedelta(days=30)
        partitions = get_partitions_to_prune(temp_data_dir, cutoff)

        before_count = sum(1 for _ in find_date_partitions(temp_data_dir))

        result = prune_partitions(partitions, dry_run=True)

        after_count = sum(1 for _ in find_date_partitions(temp_data_dir))

        assert before_count == after_count
        assert result["partitions_removed"] == 0

    def test_actual_prune_removes_files(self, temp_data_dir):
        """Actual prune should delete partitions."""
        cutoff = datetime.now() - timedelta(days=30)
        partitions = get_partitions_to_prune(temp_data_dir, cutoff)

        result = prune_partitions(partitions, dry_run=False)

        assert result["partitions_removed"] > 0
        for path, _ in partitions:
            assert not path.exists()

    def test_writes_audit_log(self, temp_data_dir):
        """Should write audit log when path provided."""
        cutoff = datetime.now() - timedelta(days=30)
        partitions = get_partitions_to_prune(temp_data_dir, cutoff)

        audit_path = temp_data_dir / "retention-audit.log"
        prune_partitions(partitions, dry_run=False, audit_log_path=audit_path)

        assert audit_path.exists()
        content = audit_path.read_text()
        assert "Removed:" in content
        assert "Total:" in content


class TestHelperFunctions:
    """Tests for utility functions."""

    def test_calculate_size(self, temp_data_dir):
        """Should calculate directory size."""
        size = calculate_size(temp_data_dir)
        assert size > 0

    def test_format_size_bytes(self):
        """Should format bytes correctly."""
        assert "B" in format_size(500)

    def test_format_size_kb(self):
        """Should format KB correctly."""
        assert "KB" in format_size(5000)

    def test_format_size_mb(self):
        """Should format MB correctly."""
        assert "MB" in format_size(5_000_000)

    def test_format_size_gb(self):
        """Should format GB correctly."""
        assert "GB" in format_size(5_000_000_000)
