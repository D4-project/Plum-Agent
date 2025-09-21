"""
This module hold generic common utils fonction
"""

import subprocess
import shutil
import logging
import threading
from subprocess import CalledProcessError

logger = logging.getLogger("Plum_Agent")


def get_version():
    """
    Retrieves the current version of the code based on git tags or commit hash.

    Attempts to get the latest git tag. If no tag is found or the command fails,
    it falls back to getting the short commit hash of the HEAD. If both attempts
    fail, it returns "unknown".

    Returns:
        str: The git tag, a string in the format "untagged-<short_sha>", or "unknown".
    """
    try:
        tag = (
            subprocess.check_output(
                ["git", "describe", "--tags"], stderr=subprocess.DEVNULL
            )
            .decode()
            .strip()
        )
        return tag
    except CalledProcessError:
        try:
            sha = (
                subprocess.check_output(
                    ["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL
                )
                .decode()
                .strip()
            )
            return f"untagged-{sha}"
        except CalledProcessError:
            return "unknown"


def locate_elf(filename):
    """
    This function find the path of a given executable

    Returns: str: path of the file
    """
    elf_path = shutil.which(filename)
    if elf_path:
        return (True, elf_path)
    else:
        return (False, None)


def run_elf(elfpath, options=None):
    """
    This function execute and wait the end of the process.
    It push log to the console.
    Error as Error, text as Info
    """
    cmd = [elfpath] + (options if options else [])  # squash empty strings.

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )

    def reader(pipe, log_func, prefix=""):
        for line in iter(pipe.readline, ""):
            log_func(f"{prefix}{line.strip()}")
        pipe.close()

    t_out = threading.Thread(target=reader, args=(process.stdout, logger.info))
    t_err = threading.Thread(
        target=reader,
        args=(
            process.stderr,
            logger.error,
        ),
    )

    t_out.start()
    t_err.start()

    process.wait()  # Wait end of Process

    t_out.join()  # Wait end of output
    t_err.join()


class Dict2obj:
    """
    Converts a dict to object...
    Because obj.truc is shorter than obj.get("truc")
    """

    def __init__(self, sub_dict):
        """
        Convert to obj
        """
        for key, value in sub_dict.items():
            if isinstance(value, dict):
                value = Dict2obj(value)
            setattr(self, key, value)

    def __repr__(self):
        return f"{self.__class__.__name__}({self.__dict__})"

    def to_dict(self):
        """
        Back conversion
        """
        result = {}
        for key, value in self.__dict__.items():
            if isinstance(value, Dict2obj):
                value = value.to_dict()
            result[key] = value
        return result
