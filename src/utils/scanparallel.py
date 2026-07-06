"""
Helpers for scan parallelism configuration.
"""


def parse_scanparallel(value, default=1):
    """
    Parse the maximum number of concurrent scan jobs.
    """
    if value is None:
        return default
    if isinstance(value, bool):
        raise ValueError("scanparallel must be an integer >= 0")

    if isinstance(value, str) and not value.strip():
        return default

    try:
        scanparallel = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("scanparallel must be an integer >= 0") from error

    if scanparallel < 0:
        raise ValueError("scanparallel must be an integer >= 0")

    return scanparallel
