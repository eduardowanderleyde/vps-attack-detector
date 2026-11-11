"""Checkpoint utilities for incremental log ingestion.

Provides functions to track and resume log file processing using byte offsets,
allowing the pipeline to continue from where it left off after interruptions.
"""

import json
import os
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Self


@dataclass
class FileCheckpoint:
    """Checkpoint state for a single log file.

    Attributes:
        file_path: Absolute path to the log file
        byte_offset: Byte position where we last stopped reading
        inode: Inode number to detect file rotation
        last_line: Last line read (for verification)
        updated_at: Timestamp of last checkpoint update
    """

    file_path: str
    byte_offset: int
    inode: int
    last_line: str | None
    updated_at: str


def get_file_inode(file_path: str) -> int | None:
    """Get the inode number for a file.

    Returns:
        Inode number, or None if file doesn't exist.
    """
    try:
        return os.stat(file_path).st_ino
    except (OSError, FileNotFoundError):
        return None


def load_checkpoint(checkpoint_path: str, file_path: str) -> FileCheckpoint | None:
    """Load checkpoint for a specific file.

    Args:
        checkpoint_path: Path to checkpoint JSON file
        file_path: Path to the log file to get checkpoint for

    Returns:
        FileCheckpoint if found and valid, None otherwise.
    """
    if not os.path.exists(checkpoint_path):
        return None

    try:
        with open(checkpoint_path, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    checkpoints = data.get("checkpoints", {})
    file_data = checkpoints.get(file_path)

    if not file_data:
        return None

    return FileCheckpoint(
        file_path=file_data["file_path"],
        byte_offset=file_data["byte_offset"],
        inode=file_data["inode"],
        last_line=file_data.get("last_line"),
        updated_at=file_data["updated_at"],
    )


def save_checkpoint(checkpoint_path: str, checkpoint: FileCheckpoint) -> None:
    """Save checkpoint for a file.

    Args:
        checkpoint_path: Path to checkpoint JSON file
        checkpoint: FileCheckpoint to save
    """
    data = {"checkpoints": {}}

    if os.path.exists(checkpoint_path):
        try:
            with open(checkpoint_path, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            pass

    if "checkpoints" not in data:
        data["checkpoints"] = {}

    data["checkpoints"][checkpoint.file_path] = asdict(checkpoint)

    os.makedirs(os.path.dirname(checkpoint_path) or ".", exist_ok=True)
    with open(checkpoint_path, "w") as f:
        json.dump(data, f, indent=2)


def is_checkpoint_valid(checkpoint: FileCheckpoint, file_path: str) -> bool:
    """Check if a checkpoint is still valid for a file.

    A checkpoint is invalid if:
    - The file no longer exists
    - The file's inode has changed (file rotation)
    - The file is smaller than the checkpoint offset (truncation)

    Args:
        checkpoint: Checkpoint to validate
        file_path: Path to the log file

    Returns:
        True if checkpoint is valid and can be used.
    """
    current_inode = get_file_inode(file_path)

    if current_inode is None:
        return False

    if current_inode != checkpoint.inode:
        return False

    try:
        file_size = os.path.getsize(file_path)
        if file_size < checkpoint.byte_offset:
            return False
    except OSError:
        return False

    return True


def read_file_incremental(
    file_path: str,
    checkpoint: FileCheckpoint | None = None,
) -> Iterator[tuple[str, int]]:
    """Read a file incrementally from a checkpoint.

    Args:
        file_path: Path to the log file
        checkpoint: Optional checkpoint to resume from

    Yields:
        Tuples of (line, byte_offset_after_line)

    Raises:
        FileNotFoundError: If file doesn't exist
    """
    start_offset = 0

    if checkpoint and is_checkpoint_valid(checkpoint, file_path):
        start_offset = checkpoint.byte_offset

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(start_offset)

        while True:
            line = f.readline()
            if not line:
                break

            current_offset = f.tell()
            yield line.rstrip("\n"), current_offset


def create_checkpoint(
    file_path: str,
    byte_offset: int,
    last_line: str | None = None,
) -> FileCheckpoint:
    """Create a new checkpoint for a file.

    Args:
        file_path: Absolute path to the log file
        byte_offset: Byte position after last processed line
        last_line: Last line processed (for debugging)

    Returns:
        New FileCheckpoint instance
    """
    inode = get_file_inode(file_path)
    if inode is None:
        raise FileNotFoundError(f"File not found: {file_path}")

    return FileCheckpoint(
        file_path=file_path,
        byte_offset=byte_offset,
        inode=inode,
        last_line=last_line[:100] if last_line else None,
        updated_at=datetime.now().astimezone().isoformat(),
    )


class IncrementalReader:
    """Context manager for incremental file reading with checkpoints.

    Usage:
        with IncrementalReader("/var/log/auth.log", "/data/checkpoints/auth.json") as reader:
            for line, offset in reader:
                process(line)
            reader.commit()  # Save checkpoint after successful processing
    """

    def __init__(self, file_path: str, checkpoint_path: str):
        """Initialize incremental reader.

        Args:
            file_path: Path to the log file
            checkpoint_path: Path to checkpoint JSON file
        """
        self.file_path = os.path.abspath(file_path)
        self.checkpoint_path = checkpoint_path
        self.checkpoint = load_checkpoint(checkpoint_path, self.file_path)
        self._last_offset = 0
        self._last_line: str | None = None
        self._lines_read = 0

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def __iter__(self) -> Iterator[tuple[str, int]]:
        """Iterate over new lines in the file."""
        for line, offset in read_file_incremental(self.file_path, self.checkpoint):
            self._last_offset = offset
            self._last_line = line
            self._lines_read += 1
            yield line, offset

    def commit(self) -> None:
        """Save the current position as a checkpoint."""
        if self._last_offset > 0:
            new_checkpoint = create_checkpoint(
                self.file_path,
                self._last_offset,
                self._last_line,
            )
            save_checkpoint(self.checkpoint_path, new_checkpoint)

    @property
    def lines_read(self) -> int:
        """Number of lines read so far."""
        return self._lines_read

    @property
    def resumed_from_offset(self) -> int:
        """Byte offset we resumed from (0 if fresh start)."""
        if self.checkpoint and is_checkpoint_valid(self.checkpoint, self.file_path):
            return self.checkpoint.byte_offset
        return 0
