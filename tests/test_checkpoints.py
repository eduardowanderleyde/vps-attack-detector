"""Tests for incremental log ingestion checkpoints (Ticket 106).

Validates checkpoint creation, loading, validation, and incremental reading.
"""

import json
import os
import pytest
import tempfile

from spark.jobs.utils.checkpoints import (
    FileCheckpoint,
    get_file_inode,
    load_checkpoint,
    save_checkpoint,
    is_checkpoint_valid,
    read_file_incremental,
    create_checkpoint,
    IncrementalReader,
)


@pytest.fixture
def temp_log_file():
    """Create a temporary log file for testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write("line 1\n")
        f.write("line 2\n")
        f.write("line 3\n")
        f.flush()
        yield f.name
    if os.path.exists(f.name):
        os.unlink(f.name)


@pytest.fixture
def temp_checkpoint_file():
    """Create a temporary checkpoint file path."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        yield f.name
    if os.path.exists(f.name):
        os.unlink(f.name)


class TestGetFileInode:
    """Tests for inode retrieval."""

    def test_get_inode_existing_file(self, temp_log_file):
        """Should return inode for existing file."""
        inode = get_file_inode(temp_log_file)
        assert inode is not None
        assert isinstance(inode, int)

    def test_get_inode_nonexistent_file(self):
        """Should return None for nonexistent file."""
        inode = get_file_inode("/nonexistent/file.log")
        assert inode is None


class TestCreateCheckpoint:
    """Tests for checkpoint creation."""

    def test_create_checkpoint(self, temp_log_file):
        """Should create checkpoint with correct fields."""
        checkpoint = create_checkpoint(temp_log_file, 100, "last line")

        assert checkpoint.file_path == temp_log_file
        assert checkpoint.byte_offset == 100
        assert checkpoint.inode is not None
        assert checkpoint.last_line == "last line"
        assert "T" in checkpoint.updated_at

    def test_create_checkpoint_truncates_long_line(self, temp_log_file):
        """Should truncate long last_line to 100 chars."""
        long_line = "x" * 200
        checkpoint = create_checkpoint(temp_log_file, 100, long_line)

        assert len(checkpoint.last_line) == 100

    def test_create_checkpoint_nonexistent_file(self):
        """Should raise FileNotFoundError for nonexistent file."""
        with pytest.raises(FileNotFoundError):
            create_checkpoint("/nonexistent/file.log", 100)


class TestSaveLoadCheckpoint:
    """Tests for checkpoint persistence."""

    def test_save_and_load_checkpoint(self, temp_log_file, temp_checkpoint_file):
        """Should save and load checkpoint correctly."""
        original = create_checkpoint(temp_log_file, 42, "test line")
        save_checkpoint(temp_checkpoint_file, original)

        loaded = load_checkpoint(temp_checkpoint_file, temp_log_file)

        assert loaded is not None
        assert loaded.file_path == original.file_path
        assert loaded.byte_offset == original.byte_offset
        assert loaded.inode == original.inode

    def test_load_nonexistent_checkpoint(self, temp_log_file, temp_checkpoint_file):
        """Should return None for nonexistent checkpoint file."""
        loaded = load_checkpoint("/nonexistent/checkpoint.json", temp_log_file)
        assert loaded is None

    def test_load_checkpoint_wrong_file(self, temp_log_file, temp_checkpoint_file):
        """Should return None if checkpoint is for different file."""
        checkpoint = create_checkpoint(temp_log_file, 42, "test")
        save_checkpoint(temp_checkpoint_file, checkpoint)

        loaded = load_checkpoint(temp_checkpoint_file, "/other/file.log")
        assert loaded is None

    def test_save_multiple_checkpoints(self, temp_log_file, temp_checkpoint_file):
        """Should save checkpoints for multiple files."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f2:
            f2.write("other file\n")
            f2.flush()
            other_file = f2.name

        try:
            cp1 = create_checkpoint(temp_log_file, 10, "line1")
            cp2 = create_checkpoint(other_file, 20, "line2")

            save_checkpoint(temp_checkpoint_file, cp1)
            save_checkpoint(temp_checkpoint_file, cp2)

            loaded1 = load_checkpoint(temp_checkpoint_file, temp_log_file)
            loaded2 = load_checkpoint(temp_checkpoint_file, other_file)

            assert loaded1.byte_offset == 10
            assert loaded2.byte_offset == 20
        finally:
            os.unlink(other_file)


class TestIsCheckpointValid:
    """Tests for checkpoint validation."""

    def test_valid_checkpoint(self, temp_log_file):
        """Should return True for valid checkpoint."""
        checkpoint = create_checkpoint(temp_log_file, 7, "line 1")
        assert is_checkpoint_valid(checkpoint, temp_log_file) is True

    def test_invalid_checkpoint_file_deleted(self, temp_log_file):
        """Should return False if file was deleted."""
        checkpoint = create_checkpoint(temp_log_file, 7, "line 1")
        os.unlink(temp_log_file)
        assert is_checkpoint_valid(checkpoint, temp_log_file) is False

    def test_invalid_checkpoint_file_rotated(self, temp_log_file):
        """Should return False if file was rotated (different inode)."""
        checkpoint = create_checkpoint(temp_log_file, 7, "line 1")

        os.unlink(temp_log_file)
        with open(temp_log_file, "w") as f:
            f.write("new file content\n")

        assert is_checkpoint_valid(checkpoint, temp_log_file) is False

    def test_invalid_checkpoint_file_truncated(self, temp_log_file):
        """Should return False if file was truncated."""
        with open(temp_log_file, "r") as f:
            f.seek(0, 2)
            end_offset = f.tell()

        checkpoint = create_checkpoint(temp_log_file, end_offset + 100, "line")

        assert is_checkpoint_valid(checkpoint, temp_log_file) is False


class TestReadFileIncremental:
    """Tests for incremental file reading."""

    def test_read_from_start(self, temp_log_file):
        """Should read entire file from start without checkpoint."""
        lines = list(read_file_incremental(temp_log_file))

        assert len(lines) == 3
        assert lines[0][0] == "line 1"
        assert lines[1][0] == "line 2"
        assert lines[2][0] == "line 3"

    def test_read_from_checkpoint(self, temp_log_file):
        """Should read from checkpoint offset."""
        checkpoint = create_checkpoint(temp_log_file, 7, "line 1")

        lines = list(read_file_incremental(temp_log_file, checkpoint))

        assert len(lines) == 2
        assert lines[0][0] == "line 2"
        assert lines[1][0] == "line 3"

    def test_read_empty_after_checkpoint_at_end(self, temp_log_file):
        """Should read nothing if checkpoint is at end of file."""
        with open(temp_log_file, "r") as f:
            f.seek(0, 2)
            end_offset = f.tell()

        checkpoint = create_checkpoint(temp_log_file, end_offset, "line 3")

        lines = list(read_file_incremental(temp_log_file, checkpoint))
        assert len(lines) == 0

    def test_read_ignores_invalid_checkpoint(self, temp_log_file):
        """Should read from start if checkpoint is invalid."""
        checkpoint = FileCheckpoint(
            file_path=temp_log_file,
            byte_offset=7,
            inode=999999,
            last_line="line 1",
            updated_at="2024-01-01T00:00:00Z",
        )

        lines = list(read_file_incremental(temp_log_file, checkpoint))
        assert len(lines) == 3


class TestIncrementalReader:
    """Tests for IncrementalReader context manager."""

    def test_full_read_and_commit(self, temp_log_file, temp_checkpoint_file):
        """Should read file and commit checkpoint."""
        with IncrementalReader(temp_log_file, temp_checkpoint_file) as reader:
            lines = [line for line, _ in reader]
            reader.commit()

        assert len(lines) == 3
        assert lines == ["line 1", "line 2", "line 3"]

        loaded = load_checkpoint(temp_checkpoint_file, os.path.abspath(temp_log_file))
        assert loaded is not None
        assert loaded.byte_offset > 0

    def test_resume_from_checkpoint(self, temp_log_file, temp_checkpoint_file):
        """Should resume from previous checkpoint."""
        with IncrementalReader(temp_log_file, temp_checkpoint_file) as reader:
            lines1 = []
            for line, offset in reader:
                lines1.append(line)
                if len(lines1) == 1:
                    break
            reader.commit()

        with IncrementalReader(temp_log_file, temp_checkpoint_file) as reader:
            lines2 = [line for line, _ in reader]

        assert lines1 == ["line 1"]
        assert lines2 == ["line 2", "line 3"]

    def test_lines_read_count(self, temp_log_file, temp_checkpoint_file):
        """Should track number of lines read."""
        with IncrementalReader(temp_log_file, temp_checkpoint_file) as reader:
            for _ in reader:
                pass
            assert reader.lines_read == 3

    def test_resumed_from_offset(self, temp_log_file, temp_checkpoint_file):
        """Should report offset we resumed from."""
        with IncrementalReader(temp_log_file, temp_checkpoint_file) as reader:
            for line, _ in reader:
                if reader.lines_read == 1:
                    break
            reader.commit()

        with IncrementalReader(temp_log_file, temp_checkpoint_file) as reader:
            assert reader.resumed_from_offset > 0

    def test_no_commit_no_save(self, temp_log_file, temp_checkpoint_file):
        """Should not save checkpoint if commit() not called."""
        with IncrementalReader(temp_log_file, temp_checkpoint_file) as reader:
            for _ in reader:
                pass

        loaded = load_checkpoint(temp_checkpoint_file, os.path.abspath(temp_log_file))
        assert loaded is None

    def test_append_and_continue(self, temp_log_file, temp_checkpoint_file):
        """Should read new lines after append."""
        with IncrementalReader(temp_log_file, temp_checkpoint_file) as reader:
            for _ in reader:
                pass
            reader.commit()

        with open(temp_log_file, "a") as f:
            f.write("line 4\n")
            f.write("line 5\n")

        with IncrementalReader(temp_log_file, temp_checkpoint_file) as reader:
            new_lines = [line for line, _ in reader]

        assert new_lines == ["line 4", "line 5"]
