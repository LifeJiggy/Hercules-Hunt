#!/usr/bin/env python3
"""Date and time utility functions.

Provides a comprehensive set of functions for formatting, parsing,
comparing, and manipulating date/time values. All functions include
proper error handling, type hints, and docstrings.

Typical usage:
    >>> from utils.date_utils import now_utc, format_timestamp, time_ago
    >>> now = now_utc()
    >>> print(format_timestamp(now))
    2025-06-13 14:30:00
    >>> print(time_ago(now))
    just now
"""

import calendar
import re
import time
from datetime import datetime, timedelta, date, timezone
from typing import List, Optional, Union


def format_timestamp(
    ts: Optional[Union[datetime, float, int]] = None,
    fmt: str = "%Y-%m-%d %H:%M:%S",
) -> str:
    """Format a timestamp into a string.

    Accepts a datetime object, Unix timestamp (float/int), or None (uses now).

    Args:
        ts: Datetime, Unix timestamp, or None for current UTC time.
        fmt: strftime-compatible format string.

    Returns:
        Formatted timestamp string.

    Raises:
        TypeError: If ts is an unsupported type.
        ValueError: If fmt is invalid or ts is out of range.

    Examples:
        >>> format_timestamp()
        '2025-06-13 14:30:00'
        >>> format_timestamp(1700000000, '%Y-%m-%d')
        '2024-11-14'
    """
    try:
        if ts is None:
            dt = datetime.now(timezone.utc)
        elif isinstance(ts, datetime):
            dt = ts
        elif isinstance(ts, (int, float)):
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        else:
            raise TypeError(
                f"Expected datetime, int, float, or None, got {type(ts).__name__}"
            )
        return dt.strftime(fmt)
    except (ValueError, OSError) as e:
        raise ValueError(f"Failed to format timestamp: {e}") from e


def parse_timestamp(
    s: str, fmt: str = "%Y-%m-%d %H:%M:%S"
) -> datetime:
    """Parse a timestamp string into a datetime object.

    Args:
        s: Timestamp string to parse.
        fmt: strftime-compatible format string matching s.

    Returns:
        Parsed datetime object (naive).

    Raises:
        ValueError: If s cannot be parsed with the given format.
        TypeError: If s is not a string.

    Examples:
        >>> parse_timestamp('2025-06-13 14:30:00')
        datetime.datetime(2025, 6, 13, 14, 30)
    """
    if not isinstance(s, str):
        raise TypeError(f"Expected string, got {type(s).__name__}")
    if not s.strip():
        raise ValueError("Cannot parse empty timestamp string")
    try:
        return datetime.strptime(s, fmt)
    except ValueError as e:
        raise ValueError(
            f"Time data {s!r} does not match format {fmt!r}: {e}"
        ) from e


def parse_iso8601(s: str) -> datetime:
    """Parse an ISO 8601 date/time string into a datetime.

    Supports formats:
        - 2025-06-13T14:30:00
        - 2025-06-13T14:30:00Z
        - 2025-06-13T14:30:00+00:00
        - 2025-06-13T14:30:00.123456
        - 2025-06-13 (date only)

    Args:
        s: ISO 8601 formatted string.

    Returns:
        Timezone-aware datetime if offset present, otherwise naive.

    Raises:
        ValueError: If s cannot be parsed as ISO 8601.
        TypeError: If s is not a string.

    Examples:
        >>> parse_iso8601('2025-06-13T14:30:00Z')
        datetime.datetime(2025, 6, 13, 14, 30, tzinfo=datetime.timezone.utc)
    """
    if not isinstance(s, str):
        raise TypeError(f"Expected string, got {type(s).__name__}")

    s = s.strip()
    if not s:
        raise ValueError("Cannot parse empty ISO 8601 string")

    try:
        return datetime.fromisoformat(s)
    except (ValueError, AttributeError):
        pass

    patterns = [
        (r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d+)Z$", True),
        (r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$", True),
        (r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d+)$", False),
        (r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})$", False),
        (r"^(\d{4})-(\d{2})-(\d{2})$", False),
    ]

    for pattern, is_utc in patterns:
        match = re.match(pattern, s)
        if match:
            parts = [int(x) for x in match.groups() if x is not None]
            if len(parts) == 3:
                dt = datetime(parts[0], parts[1], parts[2])
            elif len(parts) == 6:
                dt = datetime(parts[0], parts[1], parts[2],
                             parts[3], parts[4], parts[5])
            elif len(parts) == 7:
                micro = parts[6]
                micro_str = str(micro).ljust(6, "0")[:6]
                dt = datetime(parts[0], parts[1], parts[2],
                             parts[3], parts[4], parts[5],
                             int(micro_str))
            else:
                continue

            if is_utc:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt

    raise ValueError(f"Could not parse ISO 8601 string: {s!r}")


def format_iso8601(dt: Optional[datetime] = None) -> str:
    """Format a datetime as ISO 8601 string.

    Args:
        dt: Datetime to format. Defaults to current UTC time.

    Returns:
        ISO 8601 formatted string with timezone info.

    Raises:
        TypeError: If dt is not a datetime or None.

    Examples:
        >>> format_iso8601()
        '2025-06-13T14:30:00.123456+00:00'
    """
    if dt is None:
        dt = datetime.now(timezone.utc)
    elif not isinstance(dt, datetime):
        raise TypeError(f"Expected datetime or None, got {type(dt).__name__}")

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.isoformat()


def now_utc() -> datetime:
    """Get the current UTC datetime with timezone info.

    Returns:
        Timezone-aware datetime representing the current UTC time.

    Examples:
        >>> now_utc()
        datetime.datetime(2025, 6, 13, 14, 30, 0, 123456,
                          tzinfo=datetime.timezone.utc)
    """
    return datetime.now(timezone.utc)


def now_local() -> datetime:
    """Get the current local datetime with timezone info.

    Returns:
        Timezone-aware datetime representing the current local time.

    Examples:
        >>> now_local()
        datetime.datetime(2025, 6, 13, 10, 30, 0, 123456,
                          tzinfo=datetime.timezone(datetime.timedelta(-1, 14400), 'EDT'))
    """
    local_tz = datetime.now(timezone.utc).astimezone().tzinfo
    return datetime.now(local_tz)


def seconds_ago(seconds: Union[int, float]) -> datetime:
    """Get a datetime representing N seconds ago from now.

    Args:
        seconds: Number of seconds to go back.

    Returns:
        Timezone-aware UTC datetime N seconds ago.

    Raises:
        TypeError: If seconds is not numeric.
        ValueError: If seconds is negative.

    Examples:
        >>> seconds_ago(30)
        datetime.datetime(2025, 6, 13, 14, 29, 30, tzinfo=datetime.timezone.utc)
    """
    try:
        seconds = float(seconds)
    except (TypeError, ValueError) as e:
        raise TypeError(f"Expected numeric type, got {type(seconds).__name__}") from e

    if seconds < 0:
        raise ValueError(f"seconds must be non-negative, got {seconds}")

    return datetime.now(timezone.utc) - timedelta(seconds=seconds)


def minutes_ago(minutes: Union[int, float]) -> datetime:
    """Get a datetime representing N minutes ago from now.

    Args:
        minutes: Number of minutes to go back.

    Returns:
        Timezone-aware UTC datetime N minutes ago.

    Raises:
        TypeError: If minutes is not numeric.
        ValueError: If minutes is negative.
    """
    try:
        minutes = float(minutes)
    except (TypeError, ValueError) as e:
        raise TypeError(f"Expected numeric type, got {type(minutes).__name__}") from e

    if minutes < 0:
        raise ValueError(f"minutes must be non-negative, got {minutes}")

    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


def hours_ago(hours: Union[int, float]) -> datetime:
    """Get a datetime representing N hours ago from now.

    Args:
        hours: Number of hours to go back.

    Returns:
        Timezone-aware UTC datetime N hours ago.

    Raises:
        TypeError: If hours is not numeric.
        ValueError: If hours is negative.
    """
    try:
        hours = float(hours)
    except (TypeError, ValueError) as e:
        raise TypeError(f"Expected numeric type, got {type(hours).__name__}") from e

    if hours < 0:
        raise ValueError(f"hours must be non-negative, got {hours}")

    return datetime.now(timezone.utc) - timedelta(hours=hours)


def days_ago(days: Union[int, float]) -> datetime:
    """Get a datetime representing N days ago from now.

    Args:
        days: Number of days to go back.

    Returns:
        Timezone-aware UTC datetime N days ago.

    Raises:
        TypeError: If days is not numeric.
        ValueError: If days is negative.
    """
    try:
        days = float(days)
    except (TypeError, ValueError) as e:
        raise TypeError(f"Expected numeric type, got {type(days).__name__}") from e

    if days < 0:
        raise ValueError(f"days must be non-negative, got {days}")

    return datetime.now(timezone.utc) - timedelta(days=days)


def duration_string(seconds: Union[int, float]) -> str:
    """Format a duration in seconds as a human-readable string.

    Args:
        seconds: Duration in seconds.

    Returns:
        Human-readable duration string like "2h 30m 15s".

    Raises:
        TypeError: If seconds is not numeric.
        ValueError: If seconds is negative.

    Examples:
        >>> duration_string(9030)
        '2h 30m 30s'
        >>> duration_string(0)
        '0s'
        >>> duration_string(3661)
        '1h 1m 1s'
    """
    try:
        seconds = float(seconds)
    except (TypeError, ValueError) as e:
        raise TypeError(f"Expected numeric type, got {type(seconds).__name__}") from e

    if seconds < 0:
        raise ValueError(f"seconds must be non-negative, got {seconds}")

    total_seconds = int(seconds)
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)

    parts: List[str] = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        parts.append(f"{secs}s")

    return " ".join(parts)


def time_ago(dt: datetime, now: Optional[datetime] = None) -> str:
    """Return a relative time string comparing dt to now.

    Args:
        dt: The past datetime to compare.
        now: Reference datetime. Defaults to current UTC time.

    Returns:
        Relative time string like "just now", "3 minutes ago",
        "2 hours ago", "5 days ago", "3 weeks ago", "2 months ago",
        "1 year ago".

    Raises:
        TypeError: If dt is not a datetime.
        ValueError: If dt is in the future.

    Examples:
        >>> import datetime
        >>> time_ago(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5))
        '5 minutes ago'
    """
    if not isinstance(dt, datetime):
        raise TypeError(f"Expected datetime, got {type(dt).__name__}")

    if now is None:
        now = datetime.now(timezone.utc)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    if dt > now:
        raise ValueError("dt cannot be in the future")

    diff = now - dt
    total_seconds = int(diff.total_seconds())

    if total_seconds < 10:
        return "just now"
    if total_seconds < 60:
        return f"{total_seconds} seconds ago"
    if total_seconds < 120:
        return "1 minute ago"
    if total_seconds < 3600:
        return f"{total_seconds // 60} minutes ago"
    if total_seconds < 7200:
        return "1 hour ago"
    if total_seconds < 86400:
        return f"{total_seconds // 3600} hours ago"
    if total_seconds < 172800:
        return "1 day ago"
    if total_seconds < 604800:
        return f"{total_seconds // 86400} days ago"
    if total_seconds < 1209600:
        return "1 week ago"
    if total_seconds < 2592000:
        return f"{total_seconds // 604800} weeks ago"
    if total_seconds < 5184000:
        return "1 month ago"
    if total_seconds < 31536000:
        return f"{total_seconds // 2592000} months ago"

    years = total_seconds // 31536000
    return f"{years} year{'s' if years > 1 else ''} ago"


def is_expired(
    timestamp: Union[datetime, float, int],
    max_age_seconds: Union[int, float],
    reference: Optional[datetime] = None,
) -> bool:
    """Check if a timestamp is expired relative to max age.

    Args:
        timestamp: The timestamp to check (datetime, Unix timestamp).
        max_age_seconds: Maximum allowed age in seconds.
        reference: Reference time. Defaults to current UTC time.

    Returns:
        True if the timestamp is older than max_age_seconds, False otherwise.

    Raises:
        TypeError: If types are invalid.
        ValueError: If max_age_seconds is negative.

    Examples:
        >>> is_expired(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2), 3600)
        True
        >>> is_expired(datetime.datetime.now(datetime.timezone.utc), 3600)
        False
    """
    if isinstance(timestamp, (int, float)):
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    elif isinstance(timestamp, datetime):
        dt = timestamp
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    else:
        raise TypeError(
            f"Expected datetime, int, or float, got {type(timestamp).__name__}"
        )

    try:
        max_age_seconds = float(max_age_seconds)
    except (TypeError, ValueError) as e:
        raise TypeError(
            f"Expected numeric max_age_seconds, got {type(max_age_seconds).__name__}"
        ) from e

    if max_age_seconds < 0:
        raise ValueError(
            f"max_age_seconds must be non-negative, got {max_age_seconds}"
        )

    if reference is None:
        reference = datetime.now(timezone.utc)
    elif isinstance(reference, datetime):
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)
    else:
        raise TypeError(
            f"Expected datetime or None for reference, got {type(reference).__name__}"
        )

    return (reference - dt).total_seconds() > max_age_seconds


def date_range(start: Union[date, datetime], end: Union[date, datetime]) -> List[date]:
    """Generate a list of all dates between start and end (inclusive).

    Args:
        start: Start date.
        end: End date (must be >= start).

    Returns:
        List of date objects from start to end inclusive.

    Raises:
        TypeError: If start or end are not date/datetime objects.
        ValueError: If start is after end.

    Examples:
        >>> import datetime
        >>> dr = date_range(datetime.date(2025, 1, 1), datetime.date(2025, 1, 5))
        >>> len(dr)
        5
    """
    for i, (val, name) in enumerate([(start, "start"), (end, "end")]):
        if not isinstance(val, (date, datetime)):
            raise TypeError(
                f"{name} must be a date or datetime, got {type(val).__name__}"
            )

    start_date = start if isinstance(start, date) else start.date()
    end_date = end if isinstance(end, date) else end.date()

    if start_date > end_date:
        raise ValueError(
            f"start ({start_date}) must not be after end ({end_date})"
        )

    delta = end_date - start_date
    return [start_date + timedelta(days=i) for i in range(delta.days + 1)]


_MONTH_ABBR = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def ssl_date_parse(date_string: str) -> datetime:
    """Parse an SSL certificate date format into a datetime.

    Handles formats like:
        "Dec 10 12:00:00 2025 GMT"
        "May  5 00:00:00 2025 GMT"

    Args:
        date_string: SSL certificate date string.

    Returns:
        Timezone-aware UTC datetime.

    Raises:
        ValueError: If the date string cannot be parsed.
        TypeError: If date_string is not a string.

    Examples:
        >>> ssl_date_parse("Dec 10 12:00:00 2025 GMT")
        datetime.datetime(2025, 12, 10, 12, 0, tzinfo=datetime.timezone.utc)
    """
    if not isinstance(date_string, str):
        raise TypeError(f"Expected string, got {type(date_string).__name__}")

    date_string = date_string.strip()
    if not date_string:
        raise ValueError("Cannot parse empty SSL date string")

    pattern = (
        r"^\s*(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
        r"(\d{1,2})\s+"
        r"(\d{2}):(\d{2}):(\d{2})\s+"
        r"(\d{4})\s+"
        r"GMT\s*$"
    )

    match = re.match(pattern, date_string, re.IGNORECASE)
    if not match:
        raise ValueError(
            f"Could not parse SSL date string: {date_string!r}. "
            "Expected format: 'Mon DD HH:MM:SS YYYY GMT'"
        )

    month_abbr = match.group(1).capitalize()
    month = _MONTH_ABBR.get(month_abbr)
    if month is None:
        raise ValueError(f"Unknown month abbreviation: {month_abbr}")

    day = int(match.group(2))
    hour = int(match.group(3))
    minute = int(match.group(4))
    second = int(match.group(5))
    year = int(match.group(6))

    try:
        dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError as e:
        raise ValueError(
            f"Invalid SSL date components: {date_string!r} - {e}"
        ) from e

    return dt


def http_date_parse(date_string: str) -> datetime:
    """Parse an HTTP date header into a datetime.

    Supports RFC 7231 IMF-fixdate and RFC 850 formats:
        "Thu, 13 Jun 2025 14:30:00 GMT"
        "Thursday, 13-Jun-25 14:30:00 GMT"
        "Thu Jun 13 14:30:00 2025"  (ANSI C asctime)

    Args:
        date_string: HTTP date string.

    Returns:
        Timezone-aware UTC datetime.

    Raises:
        ValueError: If the date string cannot be parsed.
        TypeError: If date_string is not a string.

    Examples:
        >>> http_date_parse("Thu, 13 Jun 2025 14:30:00 GMT")
        datetime.datetime(2025, 6, 13, 14, 30, tzinfo=datetime.timezone.utc)
    """
    if not isinstance(date_string, str):
        raise TypeError(f"Expected string, got {type(date_string).__name__}")

    date_string = date_string.strip()
    if not date_string:
        raise ValueError("Cannot parse empty HTTP date string")

    _WEEKDAY = r"(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday)"

    patterns = [
        (
            r"^\s*" + _WEEKDAY + r",\s+"
            r"(\d{2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
            r"(\d{4})\s+"
            r"(\d{2}):(\d{2}):(\d{2})\s+GMT\s*$",
            "imf",
        ),
        (
            r"^\s*" + _WEEKDAY + r",\s+"
            r"(\d{2})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-"
            r"(\d{2})\s+"
            r"(\d{2}):(\d{2}):(\d{2})\s+GMT\s*$",
            "rfc850",
        ),
        (
            r"^\s*" + _WEEKDAY + r"\s+"
            r"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
            r"(\d{1,2})\s+"
            r"(\d{2}):(\d{2}):(\d{2})\s+"
            r"(\d{4})\s*$",
            "asctime",
        ),
    ]

    for pattern, fmt_type in patterns:
        match = re.match(pattern, date_string, re.IGNORECASE)
        if not match:
            continue

        groups = match.groups()

        if fmt_type == "imf":
            day = int(groups[0])
            month_abbr = groups[1].capitalize()
            year = int(groups[2])
            hour = int(groups[3])
            minute = int(groups[4])
            second = int(groups[5])
        elif fmt_type == "rfc850":
            day = int(groups[0])
            month_abbr = groups[1].capitalize()
            year_short = int(groups[2])
            year = 2000 + year_short if year_short < 70 else 1900 + year_short
            hour = int(groups[3])
            minute = int(groups[4])
            second = int(groups[5])
        elif fmt_type == "asctime":
            month_abbr = groups[0].capitalize()
            day = int(groups[1])
            hour = int(groups[2])
            minute = int(groups[3])
            second = int(groups[4])
            year = int(groups[5])
        else:
            continue

        month = _MONTH_ABBR.get(month_abbr)
        if month is None:
            raise ValueError(f"Unknown month abbreviation: {month_abbr}")

        try:
            return datetime(year, month, day, hour, minute, second,
                           tzinfo=timezone.utc)
        except ValueError as e:
            raise ValueError(
                f"Invalid HTTP date components from {date_string!r}: {e}"
            ) from e

    raise ValueError(
        f"Could not parse HTTP date string: {date_string!r}. "
        "Expected RFC 7231 IMF-fixdate, RFC 850, or ANSI C asctime format."
    )


_MAX_FILENAME_LEN = 200


def get_timestamp_filename(
    prefix: str = "", suffix: str = ".txt"
) -> str:
    """Generate a unique filename with a current UTC timestamp.

    Format: {prefix}YYYYMMDD_HHMMSS_{microsec}{suffix}

    Args:
        prefix: Optional filename prefix.
        suffix: File extension suffix (e.g. ".txt", ".log", ".json").

    Returns:
        Unique timestamped filename string.

    Raises:
        TypeError: If prefix or suffix are not strings.
        ValueError: If the resulting filename would exceed platform limits.

    Examples:
        >>> get_timestamp_filename("report_", ".json")
        'report_20250613_143000_123456.json'
        >>> get_timestamp_filename()
        '20250613_143000_123456.txt'
    """
    if not isinstance(prefix, str):
        raise TypeError(f"Expected str for prefix, got {type(prefix).__name__}")
    if not isinstance(suffix, str):
        raise TypeError(f"Expected str for suffix, got {type(suffix).__name__}")

    now = datetime.now(timezone.utc)
    ts_part = now.strftime("%Y%m%d_%H%M%S") + f"_{now.microsecond:06d}"

    filename = f"{prefix}{ts_part}{suffix}"

    if len(filename) > _MAX_FILENAME_LEN:
        raise ValueError(
            f"Generated filename exceeds {_MAX_FILENAME_LEN} characters "
            f"({len(filename)}). Shorten prefix or suffix."
        )

    return filename


if __name__ == "__main__":
    print(f"Current UTC: {format_timestamp()}")
    print(f"Current Local: {format_iso8601(now_local())}")
    print(f"5 minutes ago: {format_timestamp(minutes_ago(5))}")
    print(f"Duration 9030s: {duration_string(9030)}")
    print(f"Time ago (1h ago): {time_ago(hours_ago(1))}")
    print(f"Is expired (2h old, max 1h): {is_expired(hours_ago(2), 3600)}")
    print(f"Date range (3 days): {date_range(date(2025, 1, 1), date(2025, 1, 3))}")
    print(f"SSL date parse: {ssl_date_parse('Jun 13 14:30:00 2025 GMT')}")
    print(f"HTTP date parse: {http_date_parse('Fri, 13 Jun 2025 14:30:00 GMT')}")
    print(f"Timestamp filename: {get_timestamp_filename('scan_', '.json')}")
