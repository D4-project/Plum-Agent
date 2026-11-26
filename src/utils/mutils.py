"""
This module hold generic common utils fonction
"""

import html
import logging
import os
import re
import shutil
import signal
import subprocess
import threading
from collections import deque
from subprocess import CalledProcessError

logger = logging.getLogger("Plum_Agent")
scanner_logger = logger.getChild("scanner")
_RUNNING_ELFS = set()
_RUNNING_ELFS_LOCK = threading.Lock()
_ANSI_ESCAPE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|\x1b[PX^_][^\x1b]*\x1b\\"
    r"|(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]"
    r"|\x1b[ -/]*[@-_]"
)
_LOG_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_SCANNER_STATUS = re.compile(
    r"^(?:rate:\s*\S+-kpps,|Starting (?:masscan|Nmap)\b|Initiating .+ Scan\b"
    r"|Scanning \d+ hosts?\b|-- forced options:)",
    re.IGNORECASE,
)
_SCANNER_ERROR = re.compile(
    r"^(?:Quitting!?$|(?:\[-\]\s*)?(?:Error|Fail|Fatal)\s*:)", re.IGNORECASE
)
_SCANNER_WARNING = re.compile(r"^(?:Warning\s*:|Failed to resolve\b)", re.IGNORECASE)


def safe_log_value(value):
    """Escape and bound text from the controller or a scanner for one log record."""
    text = _LOG_CONTROL.sub("", _ANSI_ESCAPE.sub("", str(value)))
    return html.escape(text, quote=False)[:100]


def get_version():
    """
    Return the Git tag or commit hash, and stop clearly when Git is unavailable.

    Returns:
        str: The Git tag or "untagged-<short_sha>".
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
    except OSError as error:
        raise SystemExit(
            "Git is required to run Plum Agent. Install Git and retry."
        ) from error
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
        except OSError as error:
            raise SystemExit(
                "Git is required to run Plum Agent. Install Git and retry."
            ) from error
        except CalledProcessError as error:
            raise SystemExit(
                "Cannot determine Plum Agent version. Run from a Git checkout."
            ) from error


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


def _terminate_process(process, grace_period=5):
    """
    Terminate a process and its process group.
    """
    if process.poll() is not None:
        return

    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except (AttributeError, OSError):
        process.terminate()

    try:
        process.wait(timeout=grace_period)
        return
    except subprocess.TimeoutExpired:
        pass

    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (AttributeError, OSError):
        process.kill()
    process.wait()


def terminate_running_elfs(grace_period=5):
    """
    Terminate all subprocesses started through run_elf.
    """
    with _RUNNING_ELFS_LOCK:
        processes = list(_RUNNING_ELFS)

    for process in processes:
        if process.poll() is None:
            logger.warning("Terminating process pid=%s", process.pid)
            _terminate_process(process, grace_period=grace_period)


def run_elf(elfpath, options=None, show_output=True, *, job_uid=None):
    """Drain scanner output and preserve failure details even in quiet mode."""
    cmd = [elfpath] + (options if options else [])  # squash empty strings.
    source = safe_log_value(os.path.basename(elfpath))
    if job_uid:
        source = f"Job {safe_log_value(job_uid)} {source}"
    diagnostics = deque(maxlen=5)

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        bufsize=1,
        start_new_session=True,
    )
    with _RUNNING_ELFS_LOCK:
        _RUNNING_ELFS.add(process)

    def reader(pipe, stderr=False):
        with pipe:
            for line in pipe:
                message = safe_log_value(line.strip()).strip()
                if not message:
                    continue
                if stderr and _SCANNER_ERROR.match(message):
                    scanner_logger.error("%s: %s", source, message)
                    continue
                if stderr and _SCANNER_WARNING.match(message):
                    scanner_logger.warning("%s: %s", source, message)
                    continue
                if stderr and not _SCANNER_STATUS.match(message):
                    diagnostics.append(message)
                if show_output:
                    scanner_logger.debug("%s", message)

    t_out = threading.Thread(
        target=reader,
        args=(process.stdout,),
        daemon=True,
    )
    t_err = threading.Thread(
        target=reader,
        args=(process.stderr, True),
        daemon=True,
    )

    try:
        t_out.start()
        t_err.start()

        try:
            return_code = process.wait()  # Wait end of Process
        except KeyboardInterrupt:
            _terminate_process(process)
            raise

        t_out.join()  # Wait end of output
        t_err.join()
        if return_code > 0 and diagnostics:
            scanner_logger.error(
                "%s stderr (exit %d): %s", source, return_code, " | ".join(diagnostics)
            )
        return return_code
    finally:
        with _RUNNING_ELFS_LOCK:
            _RUNNING_ELFS.discard(process)


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
