#!/usr/bin/env python3
"""
file_utils.py — File and path utility functions for Hercules-Hunt.

Provides safe file I/O, JSON handling, globbing, path validation, temporary
file management, and checksum computation. All functions include type hints,
proper error handling, and platform-aware path handling.
"""

from __future__ import annotations

import errno
import hashlib
import json
import logging
import os
import shutil
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Generator, Iterator, List, Optional, Union

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_ENCODING = "utf-8"
_DEFAULT_MAX_SIZE_MB = 10
_DEFAULT_JSON_INDENT = 2
_VALID_CHECKSUM_ALGORITHMS = frozenset({"sha256", "sha512", "sha1", "md5"})
_PATH_TRAVERSAL_MARKERS = {"..", "~", "//"}

# On Windows, reserved device names that should never be treated as file paths
_WINDOWS_DEVICE_NAMES = frozenset({
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
})


# ---------------------------------------------------------------------------
# Path validation
# ---------------------------------------------------------------------------


def validate_path(path: Union[str, Path]) -> Path:
    """Validate that *path* does not contain path-traversal sequences.

    Checks for ``..``, ``~``, double-slash ``//`` patterns, and Windows
    reserved device names.  Raises :class:`ValueError` with a descriptive
    message when the path is unsafe.

    Args:
        path: File or directory path to validate.

    Returns:
        A resolved :class:`Path` object when the path is safe.

    Raises:
        ValueError: If traversal sequences or device names are detected.
        TypeError: If *path* is not a string or :class:`Path`.
    """
    if not isinstance(path, (str, Path)):
        raise TypeError(f"Expected str or Path, got {type(path).__name__}")

    path_obj = Path(path)

    # Check every component for traversal markers
    parts = path_obj.parts
    for part in parts:
        if part in _PATH_TRAVERSAL_MARKERS:
            raise ValueError(
                f"Path traversal detected in component {part!r} of {str(path_obj)!r}"
            )

    # Windows device-name check (os.path.splitdrive keeps drive letter)
    stem = path_obj.stem.upper() if os.name == "nt" else path_obj.stem
    if stem in _WINDOWS_DEVICE_NAMES:
        raise ValueError(
            f"Path contains reserved device name: {stem!r}"
        )

    # Absolute paths with drive letters on Windows are fine; reject bare shares
    if os.name == "nt" and str(path_obj).startswith("\\\\"):
        raise ValueError("UNC paths are not allowed")

    return path_obj


def ensure_dir(path: Union[str, Path]) -> Path:
    """Ensure that a directory exists, creating it (and parents) if needed.

    This is the moral equivalent of ``mkdir -p``.  No error is raised when
    the directory already exists.

    Args:
        path: Directory path to create.

    Returns:
        The :class:`Path` object of the ensured directory.

    Raises:
        OSError: If the directory cannot be created (permissions, read-only
            filesystem, etc.).
        ValueError: If *path* contains traversal sequences.
    """
    validated = validate_path(path)
    try:
        validated.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.error("Failed to create directory %s: %s", validated, exc)
        raise
    return validated


# ---------------------------------------------------------------------------
# Safe file I/O
# ---------------------------------------------------------------------------


def safe_read_file(
    path: Union[str, Path],
    max_size_mb: int = _DEFAULT_MAX_SIZE_MB,
    encoding: str = _DEFAULT_ENCODING,
) -> str:
    """Read a text file with a size limit.

    Raises :class:`ValueError` if the file exceeds *max_size_mb* **before**
    reading it into memory, avoiding accidental OOM on unexpectedly large
    files.

    Args:
        path: Path to the file to read.
        max_size_mb: Maximum allowed size in mebibytes (default 10).
        encoding: File encoding (default ``utf-8``).

    Returns:
        File contents as a string.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file exceeds the size limit or path is unsafe.
        UnicodeDecodeError: If the file cannot be decoded with *encoding*.
    """
    validated = validate_path(path)
    size = get_file_size(validated)
    max_bytes = max_size_mb * 1024 * 1024

    if size > max_bytes:
        raise ValueError(
            f"File {validated} is {size} bytes, which exceeds the "
            f"{max_size_mb} MB limit ({max_bytes} bytes)"
        )

    try:
        with open(str(validated), mode="r", encoding=encoding) as fh:
            return fh.read()
    except FileNotFoundError:
        logger.error("File not found: %s", validated)
        raise
    except UnicodeDecodeError:
        logger.error("Cannot decode %s with encoding %s", validated, encoding)
        raise
    except OSError as exc:
        logger.error("Error reading %s: %s", validated, exc)
        raise


def safe_write_file(
    path: Union[str, Path],
    content: str,
    overwrite: bool = True,
    encoding: str = _DEFAULT_ENCODING,
) -> Path:
    """Write a string to a file after path-validation.

    By default an existing file is **silently overwritten**.  Pass
    ``overwrite=False`` to raise :class:`FileExistsError` when the target
    already exists.

    Args:
        path: Destination path.
        content: String content to write.
        overwrite: Allow overwriting an existing file (default ``True``).
        encoding: File encoding (default ``utf-8``).

    Returns:
        The :class:`Path` of the written file.

    Raises:
        ValueError: If path traversal is detected.
        FileExistsError: If *overwrite* is ``False`` and the file exists.
        OSError: On write failure (permissions, disk full, etc.).
    """
    validated = validate_path(path)
    if not overwrite and validated.exists():
        raise FileExistsError(
            f"File already exists and overwrite=False: {validated}"
        )

    ensure_dir(validated.parent)
    try:
        validated.write_text(content, encoding=encoding)
    except OSError as exc:
        logger.error("Failed to write %s: %s", validated, exc)
        raise

    logger.debug("Wrote %d bytes to %s", len(content.encode(encoding)), validated)
    return validated


# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------


def read_json(path: Union[str, Path]) -> Any:
    """Read and deserialise a JSON file.

    Args:
        path: Path to the JSON file.

    Returns:
        The deserialised Python object (typically ``dict`` or ``list``).

    Raises:
        FileNotFoundError: If the file does not exist.
        json.JSONDecodeError: If the file contains invalid JSON.
        ValueError: If path traversal is detected.
    """
    validated = validate_path(path)
    raw = safe_read_file(validated)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON in %s: %s", validated, exc)
        raise


def write_json(
    path: Union[str, Path],
    data: Any,
    indent: int = _DEFAULT_JSON_INDENT,
    overwrite: bool = True,
    encoding: str = _DEFAULT_ENCODING,
) -> Path:
    """Serialise *data* as JSON and write to *path*.

    Args:
        path: Destination path.
        data: Data to serialise (must be JSON-serialisable).
        indent: Indentation level (default 2).  Pass ``None`` for compact.
        overwrite: Allow overwriting an existing file (default ``True``).
        encoding: File encoding (default ``utf-8``).

    Returns:
        The :class:`Path` of the written file.

    Raises:
        ValueError: If path traversal is detected or data is not serialisable.
        FileExistsError: If *overwrite* is ``False`` and the file exists.
        OSError: On write failure.
    """
    validated = validate_path(path)
    try:
        content = json.dumps(data, indent=indent, ensure_ascii=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Data is not JSON-serialisable: {exc}") from exc

    return safe_write_file(validated, content, overwrite=overwrite, encoding=encoding)


# ---------------------------------------------------------------------------
# Line-based reading
# ---------------------------------------------------------------------------


def read_lines(
    path: Union[str, Path],
    strip: bool = True,
    skip_blank: bool = True,
    encoding: str = _DEFAULT_ENCODING,
) -> List[str]:
    """Read a file and return its non-blank lines.

    Args:
        path: Path to the file.
        strip: Strip leading/trailing whitespace from each line (default
            ``True``).
        skip_blank: Omit lines that are empty after stripping (default
            ``True``).
        encoding: File encoding (default ``utf-8``).

    Returns:
        List of lines.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If path traversal is detected.
    """
    validated = validate_path(path)
    raw = safe_read_file(validated, encoding=encoding)
    lines: List[str] = []
    for line in raw.splitlines():
        candidate = line.strip() if strip else line
        if skip_blank and not candidate:
            continue
        lines.append(candidate)
    return lines


# ---------------------------------------------------------------------------
# Globbing
# ---------------------------------------------------------------------------


def glob_files(directory: Union[str, Path], pattern: str) -> List[Path]:
    """Find files matching a glob pattern under *directory*.

    Only returns **files** (not directories).  Uses :meth:`pathlib.Path.rglob`
    for recursive matching or :meth:`pathlib.Path.glob` when the pattern does
    not start with ``**``.

    Args:
        directory: Root directory to search.
        pattern: Glob pattern (e.g. ``**/*.log`` or ``*.txt``).

    Returns:
        Sorted list of matching :class:`Path` objects.

    Raises:
        NotADirectoryError: If *directory* is not a directory.
        ValueError: If path traversal is detected.
    """
    validated_dir = validate_path(directory)
    if not validated_dir.is_dir():
        raise NotADirectoryError(f"Not a directory: {validated_dir}")

    if pattern.startswith("**"):
        iterator: Iterator[Path] = validated_dir.rglob(pattern)
    else:
        iterator = validated_dir.glob(pattern)

    results = sorted(p for p in iterator if p.is_file())
    logger.debug("glob_files(%s, %s) -> %d results", directory, pattern, len(results))
    return results


# ---------------------------------------------------------------------------
# File metadata
# ---------------------------------------------------------------------------


def get_file_size(path: Union[str, Path]) -> int:
    """Return the size of a file in bytes.

    Args:
        path: Path to the file.

    Returns:
        Size in bytes.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If path traversal is detected.
        IsADirectoryError: If *path* is a directory.
    """
    validated = validate_path(path)
    try:
        stat = validated.stat()
    except FileNotFoundError:
        logger.error("File not found: %s", validated)
        raise

    if not stat.st_size and not validated.is_file():
        # Zero-size could be a valid empty file, but if stat fails check type
        if validated.is_dir():
            raise IsADirectoryError(f"Expected a file, got directory: {validated}")
    return stat.st_size


# ---------------------------------------------------------------------------
# Temporary file context manager
# ---------------------------------------------------------------------------


@contextmanager
def temp_file(
    suffix: str = ".tmp",
    prefix: str = "hunt_",
    directory: Optional[Union[str, Path]] = None,
    content: Optional[str] = None,
    encoding: str = _DEFAULT_ENCODING,
) -> Generator[Path, None, None]:
    """Context manager that creates a temporary file and cleans it up.

    The file is created inside the system temporary directory (or an explicit
    *directory*) and is **deleted** when the context exits — even if an
    exception was raised.

    Args:
        suffix: File suffix (default ``.tmp``).  Include the dot.
        prefix: File prefix (default ``hunt_``).
        directory: Explicit parent directory; if ``None`` the system temp
            dir is used.
        content: Optional initial content written to the file.
        encoding: Encoding used when writing *content*.

    Yields:
        :class:`Path` to the temporary file.

    Example:
        >>> with temp_file(suffix=".json", content='{"a": 1}') as p:
        ...     print(read_json(p))
        {'a': 1}
        >>> # p is now deleted.
    """
    tmp_path: Optional[Path] = None
    try:
        fd, tmp_str = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=directory)
        os.close(fd)
        tmp_path = Path(tmp_str)
        if content is not None:
            tmp_path.write_text(content, encoding=encoding)
        yield tmp_path
    finally:
        if tmp_path is not None and tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError as exc:
                logger.warning("Failed to clean up temp file %s: %s", tmp_path, exc)


# ---------------------------------------------------------------------------
# Checksum
# ---------------------------------------------------------------------------


def file_checksum(path: Union[str, Path], algorithm: str = "sha256") -> str:
    """Compute the checksum of a file using the specified hash algorithm.

    Reads the file in 64 KiB chunks to keep memory usage low regardless of
    file size.

    Args:
        path: Path to the file.
        algorithm: One of ``sha256`` (default), ``sha512``, ``sha1``, ``md5``.

    Returns:
        Hexadecimal digest string.

    Raises:
        ValueError: If *algorithm* is not supported or path is unsafe.
        FileNotFoundError: If the file does not exist.
    """
    if algorithm not in _VALID_CHECKSUM_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm {algorithm!r}. "
            f"Choose from {sorted(_VALID_CHECKSUM_ALGORITHMS)}"
        )

    validated = validate_path(path)
    if not validated.is_file():
        raise FileNotFoundError(f"File not found: {validated}")

    hasher = hashlib.new(algorithm)
    chunk_size = 64 * 1024  # 64 KiB

    try:
        with open(str(validated), mode="rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
    except OSError as exc:
        logger.error("Error reading %s for checksum: %s", validated, exc)
        raise

    digest = hasher.hexdigest()
    logger.debug("Checksum %s(%s) = %s", algorithm, validated, digest)
    return digest


# ---------------------------------------------------------------------------
# High-level helpers
# ---------------------------------------------------------------------------


def copy_file(
    src: Union[str, Path],
    dst: Union[str, Path],
    overwrite: bool = True,
) -> Path:
    """Copy a single file from *src* to *dst*.

    Both paths are validated.  The destination directory is created if it
    does not exist.

    Args:
        src: Source file path.
        dst: Destination path (may be a file or directory).
        overwrite: Allow overwriting destination (default ``True``).

    Returns:
        The destination :class:`Path`.

    Raises:
        FileNotFoundError: If *src* does not exist.
        FileExistsError: If *dst* exists and *overwrite* is ``False``.
        ValueError: If path traversal is detected.
    """
    src_validated = validate_path(src)
    dst_validated = validate_path(dst)

    if not src_validated.is_file():
        raise FileNotFoundError(f"Source file not found: {src_validated}")

    if dst_validated.is_dir():
        dst_validated = dst_validated / src_validated.name

    if not overwrite and dst_validated.exists():
        raise FileExistsError(
            f"Destination exists and overwrite=False: {dst_validated}"
        )

    ensure_dir(dst_validated.parent)
    try:
        shutil.copy2(str(src_validated), str(dst_validated))
    except OSError as exc:
        logger.error("Failed to copy %s -> %s: %s", src_validated, dst_validated, exc)
        raise

    logger.info("Copied %s -> %s", src_validated, dst_validated)
    return dst_validated


def safe_delete(path: Union[str, Path]) -> None:
    """Delete a file safely — no error if it does not exist.

    Args:
        path: Path to the file to delete.

    Raises:
        ValueError: If path traversal is detected.
        OSError: If deletion fails for reasons other than ``ENOENT``.
    """
    validated = validate_path(path)
    try:
        validated.unlink(missing_ok=True)
    except OSError as exc:
        if exc.errno != errno.ENOENT:
            logger.error("Failed to delete %s: %s", validated, exc)
            raise


def list_files(
    directory: Union[str, Path],
    pattern: str = "*",
    recursive: bool = False,
) -> List[Path]:
    """List files in a directory, optionally recursive.

    This is a convenience wrapper around :func:`glob_files` with a simpler
    interface.

    Args:
        directory: Root directory.
        pattern: Glob pattern (default ``*``).
        recursive: If ``True``, use ``**/{pattern}`` (default ``False``).

    Returns:
        Sorted list of matching :class:`Path` objects.
    """
    effective = f"**/{pattern}" if recursive else pattern
    return glob_files(directory, effective)


def atomic_write(
    path: Union[str, Path],
    content: str,
    encoding: str = _DEFAULT_ENCODING,
) -> Path:
    """Atomically write a file via a temporary file + rename.

    The write is considered atomic on most filesystems because the final
    :func:`os.replace` is an atomic operation on the same volume.  This
    prevents readers from seeing a half-written file.

    Args:
        path: Destination path.
        content: String content to write.
        encoding: Encoding (default ``utf-8``).

    Returns:
        The destination :class:`Path`.

    Raises:
        ValueError: If path traversal is detected.
        OSError: On write or rename failure.
    """
    validated = validate_path(path)
    ensure_dir(validated.parent)

    tmp = validated.with_suffix(f"{validated.suffix}.{uuid.uuid4().hex}.tmp")
    try:
        tmp.write_text(content, encoding=encoding)
        os.replace(str(tmp), str(validated))
    except OSError as exc:
        # Attempt cleanup of temp file
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        logger.error("Atomic write failed for %s: %s", validated, exc)
        raise

    return validated
