"""Generic library"""

import subprocess
import shutil
from subprocess import CalledProcessError


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
    """
    elf_path = shutil.which(filename)
    if elf_path:
        return (True, elf_path)
    else:
        return (False, None)
