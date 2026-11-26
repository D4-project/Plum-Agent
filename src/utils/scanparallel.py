"""
Helpers for scan parallelism configuration.
"""


def parse_scanparallel(value, default=1):
    """
    Parse the maximum number of concurrent scan jobs.
    """
    if value is None:
        return default
    if isinstance(value, (bool, float)):
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


def scanner_parallel_limits(config):
    """Return per-scanner ceilings, falling back to the shared default."""
    default = parse_scanparallel(config.get("scanparallel"))
    limits = {}
    for tool in ("nmap", "masscan"):
        key = f"{tool}_scanparallel"
        limit = parse_scanparallel(config.get(key), default=default)
        if limit < 1 and config.get(key) is not None:
            raise ValueError(
                f"{key} must be an integer >= 1; use {tool}_disabled to disable"
            )
        limits[tool] = limit
    return limits
