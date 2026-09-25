"""
Helpers for GMT scan-hour windows.
"""

import re
from datetime import datetime, timezone

SCANHOURS_PATTERN = re.compile(r"^\s*(\d{1,2})\s*-\s*(\d{1,2})\s*$")


def parse_scanhours(value):
    """
    Parse a HH-HH GMT scan window.
    """
    if value is None:
        return None

    value = str(value).strip()
    if not value:
        return None

    match = SCANHOURS_PATTERN.match(value)
    if not match:
        raise ValueError("scanhours must use HH-HH format, example 14-16")

    start_hour = int(match.group(1))
    end_hour = int(match.group(2))

    if start_hour < 0 or start_hour > 23:
        raise ValueError("scanhours start hour must be between 0 and 23")
    if end_hour < 0 or end_hour > 24:
        raise ValueError("scanhours end hour must be between 0 and 24")
    if start_hour == end_hour:
        raise ValueError("scanhours start and end hours must be different")

    return start_hour, end_hour


def normalize_scanhours(value):
    """
    Return a stable HH-HH representation for config persistence.
    """
    window = parse_scanhours(value)
    if window is None:
        return None

    start_hour, end_hour = window
    return f"{start_hour:02d}-{end_hour:02d}"


def is_scanhours_active(value, now=None):
    """
    Return True when current GMT hour is inside the configured scan window.
    """
    window = parse_scanhours(value)
    if window is None:
        return True

    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    else:
        now = now.astimezone(timezone.utc)

    start_hour, end_hour = window
    current_hour = now.hour

    if start_hour < end_hour:
        return start_hour <= current_hour < end_hour

    return current_hour >= start_hour or current_hour < end_hour
