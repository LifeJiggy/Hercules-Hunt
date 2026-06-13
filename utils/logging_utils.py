#!/usr/bin/env python3
"""
Structured logging and console output utilities for bug bounty and security tooling.

Provides colored console output, ASCII banners, aligned tables, progress bars,
JSON pretty-printing, and a configurable logger with file + stream handlers.
"""

import io
import json
import logging
import os
import sys
import time
from contextlib import contextmanager
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, Union


# ── ANSI Color Codes ──────────────────────────────────────────────────────

class _Colors:
    """ANSI escape sequences for terminal color output."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"

    # Foreground
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright foreground
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Background
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"

    @classmethod
    def supports_color(cls) -> bool:
        """Check if the terminal supports ANSI color codes."""
        if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
            return False
        # NO_COLOR convention
        if os.environ.get("NO_COLOR"):
            return False
        term = os.environ.get("TERM", "")
        if "dumb" in term.lower():
            return False
        return True


_USE_COLOR = _Colors.supports_color()


def _supports_unicode() -> bool:
    """Check if the terminal encoding supports Unicode box-drawing characters."""
    encoding = sys.stdout.encoding or ""
    return "utf" in encoding.lower() or "UTF" in encoding


_USE_UNICODE = _supports_unicode()


def _colorize(text: str, color_code: str) -> str:
    """Wrap text in ANSI color if the terminal supports it.

    Args:
        text: The text to colorize.
        color_code: ANSI escape code for the desired color.

    Returns:
        Colorized string (or plain text if colors are disabled).
    """
    if _USE_COLOR:
        return f"{color_code}{text}{_Colors.RESET}"
    return text


# ── Custom Log Formatter ──────────────────────────────────────────────────


class LogFormatter(logging.Formatter):
    """Custom log formatter with level-based coloring and structured output.

    Formats log messages with timestamps, module names, and severity levels.
    Error and warning messages are colorized for quick visual scanning.

    Format: ``2026-06-13 14:30:00 [INFO]    my_module: Message here``

    Args:
        fmt: Optional format string. Uses a default format if not provided.
        datefmt: Optional date format string.
        style: Format style ('%', '{', or '$').
    """

    # Level-to-color mapping
    _LEVEL_COLORS = {
        logging.DEBUG: _Colors.BRIGHT_BLACK,
        logging.INFO: _Colors.GREEN,
        logging.WARNING: _Colors.YELLOW,
        logging.ERROR: _Colors.RED,
        logging.CRITICAL: _Colors.BG_RED + _Colors.WHITE + _Colors.BOLD,
    }

    # Level name alignment
    _LEVEL_NAMES = {
        logging.DEBUG: "DEBUG",
        logging.INFO: "INFO",
        logging.WARNING: "WARNING",
        logging.ERROR: "ERROR",
        logging.CRITICAL: "CRITICAL",
    }

    def __init__(
        self,
        fmt: Optional[str] = None,
        datefmt: Optional[str] = None,
        style: str = "%",
    ) -> None:
        default_fmt = (
            "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
        )
        super().__init__(
            fmt or default_fmt,
            datefmt or "%Y-%m-%d %H:%M:%S",
            style,
        )

    def format(self, record: logging.LogRecord) -> str:
        """Format a log record with optional color coding.

        Args:
            record: The log record to format.

        Returns:
            Formatted string with ANSI colors for terminal output.
        """
        # Save original state
        orig_levelname = record.levelname
        orig_msg = record.msg

        # Colorize the level name
        color = self._LEVEL_COLORS.get(record.levelno, _Colors.RESET)
        level_name = self._LEVEL_NAMES.get(record.levelno, record.levelname)
        record.levelname = _colorize(level_name, color)

        # Colorize the message based on severity
        if record.levelno >= logging.ERROR:
            record.msg = _colorize(str(record.msg), _Colors.RED)
        elif record.levelno >= logging.WARNING:
            record.msg = _colorize(str(record.msg), _Colors.YELLOW)

        result = super().format(record)

        # Restore original state
        record.levelname = orig_levelname
        record.msg = orig_msg

        return result


# ── Logger Management ─────────────────────────────────────────────────────

_LOG_CACHE: Dict[str, logging.Logger] = {}


def setup_logger(
    name: str,
    level: str = "INFO",
    log_file: Optional[str] = None,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 3,
) -> logging.Logger:
    """Create or reconfigure a named logger with console and optional file handlers.

    Sets up a logger that outputs structured log messages to stderr (with colors)
    and optionally to a rotating file. Existing handlers on the logger are replaced.

    Args:
        name: Logger name (usually __name__).
        level: Log level string ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL').
        log_file: Optional path to a log file. If provided, log output is also
                  written to this file with a detailed format (no colors).
        max_bytes: Maximum size in bytes for the log file before rotation
                   (default 10 MB).
        backup_count: Number of rotated log files to keep (default 3).

    Returns:
        Configured Logger instance.

    Raises:
        ValueError: If level is not a valid logging level name.
        OSError: If the log file directory cannot be created or written to.

    Examples:
        >>> logger = setup_logger("my_tool", "DEBUG", "/tmp/my_tool.log")
        >>> logger.info("Recon started")
        >>> logger.error("Connection failed")
    """
    # Validate and normalize level
    level = level.upper().strip()
    numeric_level = getattr(logging, level, None)
    if not isinstance(numeric_level, int):
        raise ValueError(
            f"Invalid log level: '{level}'. "
            f"Valid: DEBUG, INFO, WARNING, ERROR, CRITICAL"
        )

    logger = logging.getLogger(name)
    logger.setLevel(numeric_level)

    # Remove existing handlers to avoid duplicates on reconfiguration
    logger.handlers.clear()

    # Console handler (stderr) with colorized formatter
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(LogFormatter())
    logger.addHandler(console_handler)

    # File handler with detailed format (no colors)
    if log_file:
        log_dir = os.path.dirname(os.path.abspath(log_file))
        if log_dir and not os.path.exists(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
            except OSError as exc:
                raise OSError(
                    f"Cannot create log directory '{log_dir}': {exc}"
                ) from exc

        file_formatter = logging.Formatter(
            "%(asctime)s [%(levelname)-8s] %(name)s (%(filename)s:%(lineno)d): %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    # Prevent propagation to root logger (avoids duplicate output)
    logger.propagate = False

    _LOG_CACHE[name] = logger
    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a named logger. Creates a default one if not already configured.

    Unlike setup_logger, this will not reconfigure an existing logger.
    If the logger was previously created via setup_logger, that instance
    is returned. Otherwise, a basic logger is created with INFO level
    and console handler.

    Args:
        name: Logger name (typically __name__).

    Returns:
        Logger instance.

    Examples:
        >>> logger = get_logger("recon-agent")
        >>> logger.info("Starting recon...")
    """
    if name in _LOG_CACHE:
        return _LOG_CACHE[name]

    logger = logging.getLogger(name)

    # Only add a default handler if there are none
    if not logger.handlers and not logger.parent.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(LogFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False

    _LOG_CACHE[name] = logger
    return logger


# ── Context Manager: Capture Logs ─────────────────────────────────────────


@contextmanager
def capture_logs_to_string(logger: logging.Logger) -> Iterator[io.StringIO]:
    """Context manager that captures a logger's output to an in-memory string.

    Useful for testing, collecting log output for reports, or redirecting
    logs to a web interface.

    Args:
        logger: The logger to capture output from.

    Yields:
        A StringIO buffer that receives all log messages. Read captured output
        via ``buffer.getvalue()`` after the context exits.

    Examples:
        >>> import logging
        >>> capture_logs_to_string(logging.getLogger())  # doctest: +SKIP
        >>> logger = get_logger("test")
        >>> with capture_logs_to_string(logger) as buf:
        ...     logger.info("Hello")
        >>> "Hello" in buf.getvalue()
        True
    """
    # Create a string stream handler
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(LogFormatter())
    handler.setLevel(logger.level)

    logger.addHandler(handler)
    try:
        yield stream
    finally:
        logger.removeHandler(handler)
        handler.close()


# ── Console Output Helpers ────────────────────────────────────────────────


def print_banner(text: str, width: int = 60, char: str = "#") -> None:
    """Print an ASCII art banner with centered text.

    Creates a visually distinct banner for section headers in terminal output.

    Args:
        text: Banner text to display.
        width: Total width of the banner in characters.
        char: Border character (default '#').

    Examples:
        >>> print_banner("RECON PHASE", 40)
        ########################################
        #             RECON PHASE              #
        ########################################
    """
    if not text:
        return

    border = char * width
    # Center the text with padding
    inner = f"{char}  {text.center(width - 6)}  {char}"

    print("")
    print(_colorize(border, _Colors.CYAN))
    print(_colorize(inner, _Colors.CYAN))
    print(_colorize(border, _Colors.CYAN))
    print("")


def print_success(text: str) -> None:
    """Print a green success/prefixed message.

    Args:
        text: The message to display.
    """
    prefix = _colorize("[+]", _Colors.GREEN)
    message = _colorize(text, _Colors.GREEN)
    print(f"{prefix} {message}")


def print_error(text: str) -> None:
    """Print a red error message to stderr.

    Args:
        text: The error message to display.
    """
    prefix = _colorize("[-]", _Colors.RED)
    message = _colorize(text, _Colors.RED)
    print(f"{prefix} {message}", file=sys.stderr)


def print_warning(text: str) -> None:
    """Print a yellow warning message.

    Args:
        text: The warning message to display.
    """
    prefix = _colorize("[!]", _Colors.YELLOW)
    message = _colorize(text, _Colors.YELLOW)
    print(f"{prefix} {message}")


def print_info(text: str) -> None:
    """Print a blue informational message.

    Args:
        text: The info message to display.
    """
    prefix = _colorize("[*]", _Colors.BLUE)
    message = _colorize(text, _Colors.BLUE)
    print(f"{prefix} {message}")


def print_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    title: Optional[str] = None,
) -> None:
    """Print an aligned text table with headers and rows.

    Columns are auto-sized based on the maximum content width in each column.
    Headers are displayed in bold/cyan.

    Args:
        headers: Column header strings.
        rows: List of rows, where each row is a sequence of cell strings.
              All rows should have the same number of cells as headers.
        title: Optional title printed above the table.

    Raises:
        ValueError: If any row has a different number of columns than headers.

    Examples:
        >>> print_table(
        ...     ["Host", "Status", "Tech"],
        ...     [["example.com", "200", "nginx"], ["test.org", "403", "Apache"]],
        ... )
         Host          Status    Tech
         ───────────────────────────────
         example.com   200       nginx
         test.org      403       Apache
    """
    if title:
        print("")
        print(_colorize(title, _Colors.BOLD + _Colors.CYAN))

    # Validate column counts
    num_cols = len(headers)
    for i, row in enumerate(rows):
        if len(row) != num_cols:
            raise ValueError(
                f"Row {i + 1} has {len(row)} columns, expected {num_cols}"
            )

    # Calculate column widths (headers + content)
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(cell))

    # Build separator line
    sep_char = "─" if _USE_UNICODE else "-"
    separator = "  ".join(sep_char * w for w in col_widths)

    # Print header row
    header_parts = []
    for i, header in enumerate(headers):
        header_parts.append(header.ljust(col_widths[i]))
    header_line = "  ".join(header_parts)
    print(_colorize(header_line, _Colors.BOLD + _Colors.CYAN))
    print(_colorize(separator, _Colors.BRIGHT_BLACK))

    # Print data rows
    for row in rows:
        parts = []
        for i, cell in enumerate(row):
            parts.append(cell.ljust(col_widths[i]))
        print("  ".join(parts))

    if rows:
        print(_colorize(separator, _Colors.BRIGHT_BLACK))
        print(
            _colorize(
                f"({len(rows)} rows)", _Colors.BRIGHT_BLACK + _Colors.ITALIC
            )
        )


def print_progress(
    iteration: int,
    total: int,
    prefix: str = "",
    suffix: str = "",
    bar_length: int = 40,
) -> None:
    """Print a terminal progress bar.

    Overwrites the current line to show an animated progress bar with percentage
    and optional prefix/suffix text. Use this in loops to show task completion
    without flooding the terminal.

    Args:
        iteration: Current iteration (0-indexed).
        total: Total iterations expected.
        prefix: Optional text displayed before the bar.
        suffix: Optional text displayed after the bar.
        bar_length: Width of the progress bar in characters.

    Examples:
        >>> import time
        >>> for i in range(10):
        ...     print_progress(i + 1, 10, "Processing", "files")
        ...     time.sleep(0.05)  # doctest: +SKIP
    """
    if total == 0:
        return

    fraction = iteration / float(total)
    filled_length = int(round(bar_length * fraction))
    fill_char = "█" if _USE_UNICODE else "#"
    empty_char = "░" if _USE_UNICODE else "."
    bar = _colorize(fill_char * filled_length, _Colors.GREEN) + _colorize(
        empty_char * (bar_length - filled_length), _Colors.DIM
    )

    percentage = f"{fraction * 100:.1f}%"

    # Build the full line
    parts = []
    if prefix:
        parts.append(prefix)

    parts.append(f"|{bar}| {percentage}")

    if suffix:
        parts.append(suffix)

    line = " ".join(parts)

    # Carriage return + overwrite
    sys.stdout.write(f"\r{line}")
    sys.stdout.flush()

    # Newline on completion
    if iteration >= total:
        sys.stdout.write("\n")
        sys.stdout.flush()


def print_json(data: Any, indent: int = 2, sort_keys: bool = False) -> None:
    """Pretty-print a Python object as formatted JSON to stdout.

    Handles common serialization edge cases: datetime objects, sets, bytes,
    and custom objects with __dict__.

    Args:
        data: Python object to serialize to JSON.
        indent: Number of spaces for indentation (default 2).
        sort_keys: Whether to sort dictionary keys alphabetically.

    Examples:
        >>> print_json({"name": "test", "count": 3})
        {
          "name": "test",
          "count": 3
        }
    """
    serialized = json.dumps(
        data,
        indent=indent,
        sort_keys=sort_keys,
        default=_json_serialize_fallback,
        ensure_ascii=False,
    )
    print(serialized)


def _json_serialize_fallback(obj: Any) -> str:
    """Fallback serializer for types that json.dumps cannot handle natively.

    Args:
        obj: Object that needs custom serialization.

    Returns:
        A JSON-serializable representation.

    Raises:
        TypeError: If the object cannot be serialized by any known method.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def print_separator(char: str = "-", width: int = 60) -> None:
    """Print a horizontal separator line.

    Args:
        char: Character to repeat for the line (default '-').
        width: Total width of the line in characters (default 60).

    Examples:
        >>> print_separator("=", 40)
        ========================================
    """
    line = char * width
    print(_colorize(line, _Colors.BRIGHT_BLACK))


def print_heading(text: str, width: int = 60) -> None:
    """Print a section heading with underline separator.

    Combines bold text with a separator line for clear section delineation.

    Args:
        text: Heading text.
        width: Total width of the underline.

    Examples:
        >>> print_heading("Results")
        Results
        ────────────────────────────────────────────
    """
    print("")
    print(_colorize(text, _Colors.BOLD + _Colors.CYAN))
    sep_char = "─" if _USE_UNICODE else "-"
    print_separator(sep_char, width)


def print_key_value(key: str, value: str, key_width: int = 24) -> None:
    """Print a colored key-value pair for structured output display.

    Args:
        key: The key/label (displayed in cyan).
        value: The value (displayed in white/bright).
        key_width: Width to pad the key column to for alignment.

    Examples:
        >>> print_key_value("Target", "example.com")
        Target                  : example.com
    """
    padded_key = _colorize(key.ljust(key_width), _Colors.CYAN)
    val_str = _colorize(str(value), _Colors.BRIGHT_WHITE)
    print(f"{padded_key}: {val_str}")


def print_list(items: Sequence[str], bullet: Optional[str] = None) -> None:
    """Print a bulleted list.

    Args:
        items: Sequence of strings to display as a list.
        bullet: Bullet character (default '•').

    Examples:
        >>> print_list(["item1", "item2", "item3"])
        • item1
        • item2
        • item3
    """
    if bullet is None:
        bullet = "•" if _USE_UNICODE else "*"
    for item in items:
        print(f"  {_colorize(bullet, _Colors.CYAN)} {item}")


def print_finding(title: str, severity: str, description: str) -> None:
    """Print a formatted vulnerability finding for reports or console output.

    Args:
        title: Finding title.
        severity: Severity level (Critical/High/Medium/Low/Info). Gets colorized.
        description: Short description of the finding.

    Examples:
        >>> print_finding("IDOR in /api/users", "High", "User IDs are enumerable")
        [High] IDOR in /api/users
               User IDs are enumerable
    """
    severity_colors = {
        "CRITICAL": _Colors.BG_RED + _Colors.WHITE + _Colors.BOLD,
        "HIGH": _Colors.RED + _Colors.BOLD,
        "MEDIUM": _Colors.YELLOW + _Colors.BOLD,
        "LOW": _Colors.BLUE,
        "INFO": _Colors.BRIGHT_BLACK,
    }
    color = severity_colors.get(severity.upper(), _Colors.WHITE)
    sev_tag = _colorize(f"[{severity.upper()}]", color)
    print(f"{sev_tag} {_colorize(title, _Colors.BOLD)}")
    print(f"       {description}")


# ── Timer Utility ─────────────────────────────────────────────────────────


class Timer:
    """Context manager for measuring and logging code execution time.

    Useful for performance profiling of recon steps and hunting operations.

    Args:
        name: Descriptive name for the timed operation.
        logger: Optional logger to report the elapsed time.
        level: Log level for the timing message (default 'INFO').

    Examples:
        >>> with Timer("subdomain scan"):
        ...     time.sleep(0.1)  # doctest: +SKIP
    """

    def __init__(
        self,
        name: str = "",
        logger: Optional[logging.Logger] = None,
        level: str = "INFO",
    ) -> None:
        self.name = name
        self.logger = logger
        self.level = level.upper()
        self.start_time: float = 0.0

    def __enter__(self) -> "Timer":
        self.start_time = time.perf_counter()
        return self

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Optional[object],
    ) -> None:
        elapsed = time.perf_counter() - self.start_time
        msg = f"{self.name} completed in {elapsed:.3f}s"
        if self.logger:
            log_level = getattr(logging, self.level, logging.INFO)
            self.logger.log(log_level, msg)
        else:
            print_info(msg)

    @property
    def elapsed(self) -> float:
        """Return elapsed seconds (only valid after context exits)."""
        return time.perf_counter() - self.start_time


# ── Module Initialization ──────────────────────────────────────────────────

__all__ = [
    "LogFormatter",
    "setup_logger",
    "get_logger",
    "capture_logs_to_string",
    "print_banner",
    "print_success",
    "print_error",
    "print_warning",
    "print_info",
    "print_table",
    "print_progress",
    "print_json",
    "print_separator",
    "print_heading",
    "print_key_value",
    "print_list",
    "print_finding",
    "Timer",
]

if __name__ == "__main__":
    import doctest
    doctest.testmod(verbose=False)
    print("logging_utils.py — all doctests passed.")
