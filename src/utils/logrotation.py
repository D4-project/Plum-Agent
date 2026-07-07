"""
Helpers for log retention configuration.
"""


def parse_logrotation(value, default=30):
    """
    Parse the number of daily log files to keep.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        raise ValueError("logrotation must be an integer >= 1")

    if isinstance(value, str) and not value.strip():
        return default

    try:
        days = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("logrotation must be an integer >= 1") from error

    if days < 1:
        raise ValueError("logrotation must be an integer >= 1")

    return days
