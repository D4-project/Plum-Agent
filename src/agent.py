#!/usr/bin/env python3
# coding=utf-8

"""
Plum Agent Main code
"""

import logging
import os
import argparse
import re
import sys
import shlex
import uuid
import time
import json
import base64
import hashlib
import threading
import ipaddress
import socket
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timedelta
from importlib.metadata import PackageNotFoundError, version
from inspect import signature
import yaml
from packaging.version import InvalidVersion, Version
from rich.logging import RichHandler
from utils.meta import APP_VERSION, print_meta
from utils.mutils import run_elf, safe_log_value, scanner_logger, terminate_running_elfs
from utils.setup import parse_masscan_rate, setup
from utils.scan_stats import masscan_targeted_ports, nmap_targeted_ports
from utils.netutils import robust_request
from utils.logrotation import parse_logrotation
from utils.scanparallel import parse_scanparallel
from utils.scanhours import is_scanhours_active

try:
    from nmap2json import nmap_file_to_json
except ImportError:
    nmap_file_to_json = None

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
MIN_NMAP2JSON_VERSION = "2611.5"
NO_JOB_SLEEP = 30
STANDBY_SLEEP = 60
BACKOFF_START = 5
BACKOFF_MAX = 60
NSE_CACHE_LOCK = threading.Lock()
SHELL_CONTROL_CHARACTERS = frozenset(";&|<>`$()\r\n")
MAX_NMAP_ADDITIONAL_PARAMS_LENGTH = 4096
MAX_INFO_NMAP_COMMAND_LENGTH = 132
DEBUG_MODES = ("none", "info", "debug")
NMAP_DEFAULT_OPTIONS_WITH_VALUES = frozenset(
    {"--host-timeout", "--max-retries", "--min-hostgroup"}
)
NMAP_RESERVED_LONG_OPTIONS = frozenset(
    {
        "--append-output",
        "--exclude-ports",
        "--no-stylesheet",
        "--port-ratio",
        "--resume",
        "--script",
        "--stylesheet",
        "--top-ports",
        "--webxml",
    }
)


class DailyLogFileHandler(logging.FileHandler):
    """
    Write logs to agent-YYMMDD.log and delete logs outside the retention window.
    """

    def __init__(self, directory, keep_days=30):
        self.directory = directory
        self.keep_days = keep_days
        self.current_day = datetime.now().date()
        os.makedirs(self.directory, exist_ok=True)
        super().__init__(self._log_path(self.current_day), mode="a", encoding="utf-8")
        self._cleanup_old_logs()

    def _log_path(self, day):
        return os.path.join(self.directory, f"agent-{day:%y%m%d}.log")

    def _cleanup_old_logs(self):
        cutoff = datetime.now().date() - timedelta(days=self.keep_days - 1)
        for filename in os.listdir(self.directory):
            if not filename.startswith("agent-") or not filename.endswith(".log"):
                continue

            date_part = filename[len("agent-") : -len(".log")]
            try:
                log_day = datetime.strptime(date_part, "%y%m%d").date()
            except ValueError:
                continue

            if log_day < cutoff:
                try:
                    os.remove(os.path.join(self.directory, filename))
                except OSError:
                    continue

    def _rollover_if_needed(self):
        today = datetime.now().date()
        if today == self.current_day:
            return

        self.current_day = today
        if self.stream:
            self.stream.close()
            self.stream = None

        self.baseFilename = os.path.abspath(self._log_path(today))
        self.stream = self._open()
        self._cleanup_old_logs()

    def emit(self, record):
        self._rollover_if_needed()
        super().emit(record)

    def set_keep_days(self, keep_days):
        self.keep_days = keep_days
        self._cleanup_old_logs()


# Initiate loggers.
logger = logging.getLogger("Plum_Agent")
logger.setLevel(logging.ERROR)

# Nice and color full console handder
console_handler = RichHandler()

# File Handler (auto create folder)
log_dir = os.path.join(THIS_DIR, "log")
file_handler = DailyLogFileHandler(log_dir, keep_days=30)
file_formatter = logging.Formatter(
    "%(asctime)s - %(levelname)s - %(message)s", datefmt="[%X]"
)
file_handler.setFormatter(file_formatter)

# Activate log handlers
logger.addHandler(console_handler)
logger.addHandler(file_handler)

# Open Configuration File
try:
    with open(
        os.path.join(THIS_DIR, "config", "config.yaml"), "r", encoding="utf-8"
    ) as f:
        CONFIG = yaml.safe_load(f)
        if not CONFIG:
            CONFIG = {}  # In case of empty file
except FileNotFoundError:
    CONFIG = {}
CONFIG["THIS_DIR"] = THIS_DIR
try:
    file_handler.set_keep_days(parse_logrotation(CONFIG.get("logrotation")))
except ValueError as error:
    logger.error("Invalid logrotation configuration, using default: %s", error)


def _check_nmap2json():
    """Verify the installed converter before registering with Island."""
    try:
        installed = version("nmap2json")
    except PackageNotFoundError as error:
        raise RuntimeError("nmap2json is not installed") from error
    try:
        installed_version = Version(installed)
    except InvalidVersion as error:
        raise RuntimeError(
            f"nmap2json has invalid version metadata: {installed!r}"
        ) from error
    if installed_version < Version(MIN_NMAP2JSON_VERSION):
        raise RuntimeError(f"nmap2json {installed} is too old")
    try:
        signature(nmap_file_to_json).bind(
            "report.xml", True, True, hostname_resolver=None
        )
    except (TypeError, ValueError) as error:
        raise RuntimeError(
            f"nmap2json {installed} does not provide the required hostname conversion API"
        ) from error


def resolve_debug_mode(config_value, cli_verbosity=0):
    """Select the CLI mode when supplied, otherwise parse the YAML setting."""
    if cli_verbosity:
        return "scanner" if cli_verbosity == 1 else "debug"
    if config_value is None or config_value is False:
        return "none"
    if config_value is True:
        return "debug"  # Existing boolean configurations remain valid.
    if isinstance(config_value, str):
        mode = config_value.strip().lower()
        if mode in DEBUG_MODES:
            return mode
    raise ValueError("debug must be one of: none, info, debug")


def configure_log_levels(mode):
    """Expose scanner DEBUG records independently of general agent logs."""
    level = {
        "none": logging.ERROR,
        "info": logging.INFO,
        "scanner": logging.INFO,
        "debug": logging.DEBUG,
    }[mode]
    logger.setLevel(level)
    scanner_logger.setLevel(logging.DEBUG if mode == "scanner" else logging.NOTSET)


def _nse_cache_dir():
    """
    Return the local cache directory for controller-managed NSE scripts.
    """
    cache_dir = os.path.join(CONFIG.get("THIS_DIR"), "nse_cache")
    os.makedirs(cache_dir, exist_ok=True)
    return cache_dir


def _safe_nse_filename(name):
    """
    Restrict cached NSE files to their basename.
    """
    return os.path.basename(str(name or "").strip())


def _sha256_file(path):
    """
    Compute the SHA-256 of a local file.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _collect_nse_hashes():
    """
    Return the local NSE cache hashes keyed by filename.
    """
    with NSE_CACHE_LOCK:
        hashes = {}
        cache_dir = _nse_cache_dir()
        for entry in sorted(os.listdir(cache_dir)):
            if not entry.endswith(".nse"):
                continue
            path = os.path.join(cache_dir, entry)
            if os.path.isfile(path):
                hashes[entry] = _sha256_file(path)
        return hashes


def _resolve_nse_targets(job_message):
    """
    Ensure all requested NSE scripts are present locally and return the paths to use
    for Nmap. If the controller does not yet provide cache-aware payloads, fall back
    to the raw script names for compatibility.
    """
    nse_descriptors = job_message.get("nse_scripts")
    if nse_descriptors is None:
        return job_message.get("nmap_nse") or []

    with NSE_CACHE_LOCK:
        cache_dir = _nse_cache_dir()
        selected_paths = []

        for descriptor in nse_descriptors:
            nse_name = _safe_nse_filename(descriptor.get("name"))
            expected_hash = str(descriptor.get("hash", "")).strip().lower()
            if not nse_name or not expected_hash:
                raise ValueError("Invalid NSE descriptor received from controller")

            nse_path = os.path.join(cache_dir, nse_name)
            current_hash = _sha256_file(nse_path) if os.path.isfile(nse_path) else None

            if current_hash != expected_hash:
                content_b64 = descriptor.get("content_b64")
                if not content_b64:
                    raise ValueError(f"Missing updated NSE payload for {nse_name}")

                file_bytes = base64.b64decode(content_b64)
                file_hash = hashlib.sha256(file_bytes).hexdigest()
                if file_hash != expected_hash:
                    raise ValueError(f"Hash mismatch for {nse_name}")

                tmp_path = f"{nse_path}.{os.getpid()}.{threading.get_ident()}.tmp"
                with open(tmp_path, "wb") as handle:
                    handle.write(file_bytes)
                os.replace(tmp_path, nse_path)
                logger.info("NSE cache refresh: %s", nse_name)
            else:
                logger.info("NSE cache hit: %s", nse_name)

            selected_paths.append(nse_path)

        return selected_paths


def _short_uid(value):
    """
    Return a compact UID for readable logs.
    """
    value = str(value or "")
    if len(value) <= 12:
        return value
    return f"{value[:8]}...{value[-4:]}"


def _nmap_option_name(token):
    """
    Return the option name used for duplicate and reserved-option checks.
    """
    if token.startswith("--"):
        return token.split("=", 1)[0]
    if len(token) == 3 and token.startswith("-T") and token[2].isdigit():
        return "-T"
    return token


def _is_reserved_nmap_option(token):
    """
    Keep job ports, output, and selected NSE scripts under agent control.
    """
    if token in {"-", "--"}:
        return True
    option_name = _nmap_option_name(token)
    if option_name in NMAP_RESERVED_LONG_OPTIONS:
        return True
    if token == "-p" or (token.startswith("-p") and not token.startswith("--")):
        return True
    return token.startswith(("-oA", "-oG", "-oN", "-oS", "-oX"))


def _validate_nmap_param_text(value):
    """
    Reject bounded-string violations and shell-control syntax.
    """
    if len(value) > MAX_NMAP_ADDITIONAL_PARAMS_LENGTH:
        raise ValueError("nmap_additional_params exceeds 4096 characters")
    if any(character in SHELL_CONTROL_CHARACTERS for character in value):
        raise ValueError("nmap_additional_params contains shell-control syntax")
    if any(ord(character) < 32 and character != "\t" for character in value):
        raise ValueError("nmap_additional_params contains control characters")


def _validate_nmap_param_tokens(tokens):
    """
    Reject agent-managed options and malformed default overrides.
    """
    for index, token in enumerate(tokens):
        if _is_reserved_nmap_option(token):
            raise ValueError(f"Nmap option {token!r} is managed by the agent")

        option_name = _nmap_option_name(token)
        if option_name not in NMAP_DEFAULT_OPTIONS_WITH_VALUES:
            continue
        if "=" in token:
            if not token.split("=", 1)[1]:
                raise ValueError(f"Nmap option {option_name!r} requires a value")
            continue
        if index + 1 == len(tokens) or tokens[index + 1].startswith("-"):
            raise ValueError(f"Nmap option {option_name!r} requires a value")


def _parse_nmap_additional_params(value):
    """
    Parse controller-provided Nmap parameters without shell evaluation.
    """
    if value is None:
        return []
    if not isinstance(value, str):
        raise ValueError("nmap_additional_params must be a string or null")
    _validate_nmap_param_text(value)
    if not value.strip():
        return []

    try:
        tokens = shlex.split(value, posix=True)
    except ValueError as error:
        raise ValueError(f"malformed nmap_additional_params: {error}") from error

    _validate_nmap_param_tokens(tokens)
    return tokens


def _merge_nmap_defaults(default_args, additional_args):
    """
    Remove overridden agent defaults, then append profile-level arguments.
    """
    overrides = {_nmap_option_name(token) for token in additional_args}
    merged_args = []
    index = 0
    while index < len(default_args):
        token = default_args[index]
        option_name = _nmap_option_name(token)
        if option_name in overrides:
            index += 2 if option_name in NMAP_DEFAULT_OPTIONS_WITH_VALUES else 1
            continue
        merged_args.append(token)
        if option_name in NMAP_DEFAULT_OPTIONS_WITH_VALUES:
            index += 1
            merged_args.append(default_args[index])
        index += 1

    return merged_args + additional_args


def _build_nmap_args(job_message, output_xml, nmap_ports, nmap_nse_targets):
    """
    Build Nmap argv while keeping agent-managed arguments authoritative.
    """
    profile_present = "nmap_additional_params" in job_message
    profile_value = job_message.get("nmap_additional_params")
    job_uid = _short_uid(job_message.get("job_uid"))
    logger.debug(
        "Job %s agent_version=%s nmap_additional_params present=%s type=%s",
        safe_log_value(job_uid),
        safe_log_value(APP_VERSION),
        profile_present,
        type(profile_value).__name__ if profile_present else "missing",
    )
    additional_args = _parse_nmap_additional_params(profile_value)
    logger.debug(
        "Job %s nmap_additional_params option_names=%s",
        safe_log_value(job_uid),
        safe_log_value(
            [
                _nmap_option_name(token)
                for token in additional_args
                if token.startswith("-")
            ]
        ),
    )
    default_args = [
        "-T3",
        "--host-timeout",
        "40s",
        "--max-retries",
        "2",
        "--min-hostgroup",
        "256",
        "-Pn",
    ]
    run_args = _merge_nmap_defaults(default_args, additional_args)

    debug_mode = CONFIG.get("debug_mode")
    if debug_mode in ("scanner", "debug"):
        run_args.append("-v")
    if debug_mode == "debug":
        run_args.append("-script-trace")

    run_args.extend(["-p", nmap_ports, "-oX", output_xml, "--no-stylesheet"])
    if nmap_nse_targets:
        run_args.extend(["--script", ",".join(nmap_nse_targets)])
    run_args.extend(job_message.get("job", "").split(","))
    return [argument for argument in run_args if argument]


def _resolve_masscan_targets(raw_targets, user_hostnames_by_ip=None):
    """Resolve hostnames locally and return stable, distinct IP/CIDR targets."""
    resolved = []
    seen = set()
    for raw_target in raw_targets.split(","):
        target = raw_target.strip()
        if not target:
            continue
        try:
            network = ipaddress.ip_network(target, strict=False)
            is_hostname = False
            values = (
                [target]
                if network.version == 4 or CONFIG.get("masscan_ipv6", True)
                else []
            )
        except ValueError:
            is_hostname = True
            try:
                values = [
                    item[4][0]
                    for item in socket.getaddrinfo(
                        target, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
                    )
                    if ipaddress.ip_address(item[4][0]).version == 4
                    or CONFIG.get("masscan_ipv6", True)
                ]
            except socket.gaierror as error:
                raise ValueError(
                    f"cannot resolve target {target!r}: {error}"
                ) from error
        for value in values:
            if is_hostname and user_hostnames_by_ip is not None:
                normalized_ip = str(ipaddress.ip_address(value))
                user_hostnames_by_ip.setdefault(normalized_ip, set()).add(target)
            if value not in seen:
                seen.add(value)
                resolved.append(value)
    if not resolved:
        raise ValueError("job has no resolvable target")
    return resolved


def _masscan_hostnames_for_open_ip(address, user_hostnames_by_ip):
    """Attach requested names and PTR only for observed FQDN-derived IPs."""
    try:
        names = user_hostnames_by_ip.get(str(ipaddress.ip_address(address)), set())
    except ValueError:
        return []
    if not names:
        return []
    hostnames = []
    try:
        ptr_name = socket.gethostbyaddr(address)[0]
    except OSError:
        ptr_name = None
    if ptr_name:
        hostnames.append({"name": ptr_name, "type": "PTR"})
    hostnames.extend(
        {"name": name, "type": "user"} for name in sorted(names, key=str.casefold)
    )
    return hostnames


def _masscan_rate():
    """Return a bounded positive packet rate from local configuration."""
    return parse_masscan_rate(CONFIG.get("masscan_rate"))


def _build_masscan_args(job_message, output_xml, ports, user_hostnames_by_ip=None):
    """Build shell-free Masscan argv from an Island job."""
    family = job_message.get("scan_family")
    if family not in ("ipv4", "ipv6"):
        raise ValueError("Masscan job is missing a valid scan_family")
    version = 4 if family == "ipv4" else 6
    arguments = _resolve_masscan_targets(
        job_message.get("job") or "", user_hostnames_by_ip
    )
    arguments = [
        target for target in arguments
        if ipaddress.ip_network(target, strict=False).version == version
    ]
    if not arguments:
        # A hostname may have no addresses in this job's family. Complete this
        # family slice as an empty scan instead of returning it to the queue.
        return []
    if job_message.get("detect_protocol") is True:
        source = CONFIG.get(f"masscan_ip_v{version}")
        if not source:
            raise ValueError(f"Masscan banner detection requires masscan_ip_v{version}")
        if ipaddress.ip_address(source).version != version:
            raise ValueError(f"masscan_ip_v{version} must be IPv{version}")
        arguments.append("--banners")
        arguments.extend(["--source-ip", source])
    arguments.extend(["-p", ports, "--rate", str(_masscan_rate()), "-oX", output_xml])
    return arguments


def _format_command_for_log(executable, arguments):
    """
    Render the exact executable argv as a copy-paste-safe command line.
    """
    return shlex.join([executable, *arguments])


def _truncate_command_for_info_log(command):
    """
    Bound the INFO command preview while reporting the original length.
    """
    if len(command) <= MAX_INFO_NMAP_COMMAND_LENGTH:
        return command

    suffix = f"... [truncated, {len(command)} chars total]"
    prefix_length = MAX_INFO_NMAP_COMMAND_LENGTH - len(suffix)
    return f"{command[:prefix_length]}{suffix}"


def fetch_job():
    """
    Fetch one scan job from the controller.
    """

    job_request = dict(CONFIG.get("botinfo") or {})
    job_request["NSE_HASHES"] = _collect_nse_hashes()
    job = robust_request(
        CONFIG.get("APIPATH").getjob,
        method="POST",
        data=job_request,
        max_retries=1,
    )
    received_at = str(int(time.time()))
    if job is None or "message" not in job:
        raise RuntimeError("Invalid job response from controller")

    job_message = job.get("message") or {}
    if not isinstance(job_message, dict):
        raise RuntimeError("Invalid job message from controller")

    profile_present = "nmap_additional_params" in job_message
    logger.debug(
        "Fetched job %s nmap_additional_params present=%s type=%s",
        safe_log_value(_short_uid(job_message.get("job_uid"))),
        profile_present,
        (
            type(job_message.get("nmap_additional_params")).__name__
            if profile_present
            else "missing"
        ),
    )

    # Validate JOB
    range_toscan = job_message.get("job") or ""
    if len(range_toscan) == 0:
        logger.info("No Job to process")
        return None

    job_message["_received_at"] = received_at
    return job_message


def _release_job(job_uid, attempt_uid=None):
    """Return an interrupted or unusable job to the Island pool."""
    endpoint = getattr(CONFIG.get("APIPATH"), "releasejob", None)
    if not endpoint:
        logger.error(
            "Job %s cannot be released: missing controller endpoint",
            _short_uid(job_uid),
        )
        return False
    data = dict(CONFIG.get("botinfo") or {})
    data["JOB_UID"] = str(job_uid)
    if attempt_uid:
        data["ATTEMPT_UID"] = str(attempt_uid)
    response = robust_request(endpoint, method="POST", data=data, max_retries=3)
    if response is None:
        logger.error("Job %s release failed", _short_uid(job_uid))
        return False
    logger.info("Job %s returned to controller", _short_uid(job_uid))
    return True


def run_scan_job(job_message):
    """
    Run one scan job already fetched from the controller.
    """

    range_toscan = job_message.get("job") or ""

    # Validate the  UID
    range_uid = job_message.get("job_uid")
    attempt_uid = job_message.get("attempt_uid")
    job_uid = _short_uid(range_uid)
    try:
        uuid.UUID(str(range_uid))
    except ValueError:
        logger.error("Job %s invalid UID format", job_uid)
        return False

    scan_tool = str(job_message.get("scan_tool") or "nmap").lower()
    if scan_tool not in {"nmap", "masscan"}:
        logger.error("Job %s has unsupported scan tool %s", job_uid, scan_tool)
        return False
    if scan_tool not in CONFIG.get("capabilities", ["nmap"]):
        logger.error("Job %s requires unavailable scan tool %s", job_uid, scan_tool)
        return False

    received_at = job_message.get("_received_at")
    ports_list = job_message.get("scan_ports") or job_message.get("nmap_ports") or []
    if not ports_list:
        logger.error("Job %s has no port definition", job_uid)
        return False

    ports = ",".join(str(i) for i in ports_list)
    output_xml = os.path.join(CONFIG.get("THIS_DIR"), f"{range_uid}.xml")
    user_hostnames_by_ip = {}
    ports_targeted = None
    try:
        os.remove(output_xml)
    except FileNotFoundError:
        pass
    try:
        if scan_tool == "masscan":
            executable = CONFIG.get("masscan_path")
            run_args = _build_masscan_args(
                job_message, output_xml, ports, user_hostnames_by_ip
            )
            if not run_args:
                ports_targeted = 0
                logger.info("Job %s has no targets in its requested IP family", job_uid)
            elif job_message.get("report_target_count") is True:
                try:
                    ports_targeted = masscan_targeted_ports(run_args, ports)
                except (ValueError, TypeError):
                    ports_targeted = None
        else:
            executable = CONFIG.get("nmap_path")
            nmap_nse_targets = _resolve_nse_targets(job_message)
            run_args = _build_nmap_args(
                job_message, output_xml, ports, nmap_nse_targets
            )
    except ValueError as error:
        logger.error("Job %s cannot prepare scan: %s", job_uid, error)
        _release_job(range_uid, attempt_uid)
        return False

    full_command = _format_command_for_log(executable, run_args) if run_args else ""
    if run_args and CONFIG.get("debug_mode") in ("info", "debug"):
        logger.info(
            "Job %s %s command: %s",
            job_uid,
            scan_tool.capitalize(),
            _truncate_command_for_info_log(full_command),
        )
    if run_args:
        logger.debug(
            "Job %s full %s command: %s", job_uid, scan_tool.capitalize(), full_command
        )
        logger.info("Job %s %s scan started target=%s", job_uid, scan_tool, range_toscan)
        return_code = run_elf(
            executable,
            run_args,
            show_output=CONFIG.get("debug_mode") in ("scanner", "debug"),
            job_uid=job_uid,
        )
    else:
        logger.info("Job %s %s family slice is empty; reporting no results", job_uid, scan_tool)
        return_code = 0
    if return_code and return_code < 0:
        logger.warning("Job %s scan interrupted", job_uid)
        _release_job(range_uid, attempt_uid)
        return False
    if return_code:
        logger.error("Job %s scan process exited with code %s", job_uid, return_code)
        if scan_tool == "masscan":
            try:
                os.remove(output_xml)
            except FileNotFoundError:
                pass
            _release_job(range_uid, attempt_uid)
            return False

    results = [] if scan_tool == "masscan" else {}
    # fetching report.
    if scan_tool == "masscan" and not run_args:
        results = []
    elif os.path.isfile(output_xml):
        try:
            if scan_tool == "nmap" or os.path.getsize(output_xml):
                if scan_tool == "masscan":
                    results = nmap_file_to_json(
                        output_xml,
                        True,
                        True,
                        hostname_resolver=lambda address: _masscan_hostnames_for_open_ip(
                            address, user_hostnames_by_ip
                        ),
                    )
                    if received_at is not None:
                        for host in results:
                            if host.get("starttime") is None:
                                host["starttime"] = received_at
                else:
                    results = nmap_file_to_json(output_xml, True, True)
                    if (
                        job_message.get("report_target_count") is True
                        and return_code == 0
                    ):
                        try:
                            ports_targeted = nmap_targeted_ports(output_xml)
                        except (ValueError, OSError, SyntaxError):
                            ports_targeted = None
        except (OSError, SyntaxError, ValueError) as error:
            logger.error("Job %s invalid scan output: %s", job_uid, error)
            _release_job(range_uid, attempt_uid)
            return False
        finally:
            try:
                os.remove(output_xml)
            except FileNotFoundError:
                pass
    else:
        logger.error("Job %s no scan output file", job_uid)
        _release_job(range_uid, attempt_uid)
        return False

    data = dict(CONFIG.get("botinfo") or {})
    data = data | {"JOB_UID": str(range_uid), "RESULT": json.dumps(results)}
    if ports_targeted is not None and ports_targeted <= 10**12:
        data["PORTS_TARGETED"] = ports_targeted
    if attempt_uid:
        data["ATTEMPT_UID"] = str(attempt_uid)

    result_response = robust_request(
        CONFIG.get("APIPATH").sndjob,
        method="POST",
        data=data,
        max_retries=3,
    )
    if result_response is None:
        logger.error("Job %s result send failed", job_uid)
        return False

    logger.info("Job %s %s scan completed target=%s", job_uid, scan_tool, range_toscan)
    return True


def scan():
    """
    Do one scan job.
    """
    try:
        job_message = fetch_job()
    except RuntimeError as error:
        logger.error("%s", error)
        return False

    if not job_message:
        if CONFIG.get("daemon"):
            logger.info("Sleeping %ss", NO_JOB_SLEEP)
            time.sleep(NO_JOB_SLEEP)
        return False

    return run_scan_job(job_message)


def _scanhours_enabled():
    """
    Return True when agent may request jobs in the configured GMT window.
    """
    try:
        return is_scanhours_active(CONFIG.get("scanhours"))
    except ValueError as error:
        logger.error("Invalid scanhours configuration: %s", error)
        sys.exit(6)


def _scanparallel_value():
    """
    Return configured scan parallelism.
    """
    try:
        return parse_scanparallel(CONFIG.get("scanparallel"))
    except ValueError as error:
        logger.error("Invalid scanparallel configuration: %s", error)
        sys.exit(7)


def _drain_finished_jobs(running, finished=None):
    """
    Remove completed worker futures and log failures.
    """
    if finished is None:
        finished = [future for future in running if future.done()]

    for future in finished:
        job_uid = running.pop(future, "unknown")
        try:
            if not future.result():
                logger.error("Job %s failed", job_uid)
        except Exception:
            logger.exception("Job %s worker failed", job_uid)


def _wait_for_worker_or_sleep(running, delay):
    """
    Sleep until a worker finishes or until delay expires.
    """
    if not running:
        time.sleep(delay)
        return

    finished, _ = wait(set(running), timeout=delay, return_when=FIRST_COMPLETED)
    _drain_finished_jobs(running, finished)


def _run_daemon_loop(scanparallel):
    """
    Run daemon scheduler with bounded scan parallelism.
    """
    backoff_delay = BACKOFF_START
    max_workers = max(scanparallel, 1)

    logger.info("Starting to work endlessly with scanparallel=%s", scanparallel)
    executor = ThreadPoolExecutor(max_workers=max_workers)
    running = {}
    last_scanhours_standby_log = None
    try:
        while True:
            _drain_finished_jobs(running)

            if not _scanhours_enabled():
                now = time.monotonic()
                if (
                    last_scanhours_standby_log is None
                    or now - last_scanhours_standby_log >= 3600
                ):
                    logger.info(
                        "Outside scanhours %s GMT, standby", CONFIG.get("scanhours")
                    )
                    last_scanhours_standby_log = now
                _wait_for_worker_or_sleep(running, STANDBY_SLEEP)
                continue

            if scanparallel == 0:
                logger.info("scanparallel is 0, standby")
                _wait_for_worker_or_sleep(running, STANDBY_SLEEP)
                continue

            if len(running) >= scanparallel:
                _wait_for_worker_or_sleep(running, STANDBY_SLEEP)
                continue

            no_job = False
            controller_error = False

            while len(running) < scanparallel:
                try:
                    job_message = fetch_job()
                    backoff_delay = BACKOFF_START
                except RuntimeError as error:
                    logger.error("%s", error)
                    controller_error = True
                    break

                if not job_message:
                    no_job = True
                    break

                job_uid = _short_uid(job_message.get("job_uid"))
                future = executor.submit(run_scan_job, job_message)
                running[future] = job_uid
                logger.info(
                    "Job %s queued (%s/%s running)",
                    job_uid,
                    len(running),
                    scanparallel,
                )

            if controller_error:
                logger.info("Controller backoff %ss", backoff_delay)
                _wait_for_worker_or_sleep(running, backoff_delay)
                backoff_delay = min(backoff_delay * 2, BACKOFF_MAX)
            elif no_job:
                logger.info("Sleeping %ss", NO_JOB_SLEEP)
                _wait_for_worker_or_sleep(running, NO_JOB_SLEEP)
    except KeyboardInterrupt:
        logger.warning("Stopping running scans")
        terminate_running_elfs()
        raise
    finally:
        if running:
            terminate_running_elfs()
        executor.shutdown(wait=False, cancel_futures=True)


def loop(repeat):
    """
    Main Loop for Agent Execution
    """

    scanparallel = _scanparallel_value()

    if repeat:
        _run_daemon_loop(scanparallel)
        return

    logger.info("Starting to work one time")
    if not _scanhours_enabled():
        logger.info("Outside scanhours %s GMT, standby", CONFIG.get("scanhours"))
        return
    if scanparallel == 0:
        logger.info("scanparallel is 0, standby")
        return
    scan()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plum Discovery Agent")
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("-o", "--once", action="store_true", help="Run Once")
    group.add_argument("-d", "--daemon", action="store_true", help="Run Endlessly")

    group.add_argument(
        "-s", "--setup", action="store_true", help="Setup configuration only"
    )
    parser.add_argument("-island", help="Hostname or IP of the Plum Island controller")
    parser.add_argument("-agentkey", help="Agent Key")
    parser.add_argument("-ipext", help="Force External IP")
    parser.add_argument(
        "--masscan-ip", "-masscan_ip", dest="masscan_ip",
        help="Deprecated: dedicated Masscan source address; use the family-specific option",
    )
    parser.add_argument(
        "--masscan-ip-v4", "-masscan_ip_v4", dest="masscan_ip_v4",
        help="Dedicated IPv4 source IP for Masscan banner detection",
    )
    parser.add_argument(
        "--masscan-ip-v6", "-masscan_ip_v6", dest="masscan_ip_v6",
        help="Dedicated IPv6 source IP for Masscan banner detection",
    )
    parser.add_argument(
        "-scanhours",
        help="GMT scan window in HH-HH format, example 14-16",
    )
    parser.add_argument(
        "-scanparallel",
        help="Maximum scan jobs to run in parallel, 0 for standby",
    )
    parser.add_argument(
        "-logrotation",
        help="Daily log retention in days, default 30",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="-v: scanner output, -vv: full debug (overrides config)",
    )

    args = parser.parse_args()

    try:
        CONFIG["debug_mode"] = resolve_debug_mode(CONFIG.get("debug"), args.verbose)
    except ValueError as error:
        parser.error(str(error))
    configure_log_levels(CONFIG["debug_mode"])
    if CONFIG["debug_mode"] == "debug":
        # Configure urllib3 for debug logging
        urllib3_logger = logging.getLogger("urllib3")
        urllib3_logger.setLevel(logging.DEBUG)
        urllib3_logger.propagate = False  # Add a direct handler
        for h in list(urllib3_logger.handlers):
            urllib3_logger.removeHandler(h)

        # Put handler to our direct handler
        class RedirectHandler(logging.Handler):
            """
            Black magic to put handler to our direct handler
            """

            def emit(self, record):
                logger.handle(record)

        urllib3_logger.addHandler(RedirectHandler())

    # Start of application.
    if CONFIG["debug_mode"] in ("info", "debug"):
        print_meta()
    try:
        _check_nmap2json()
    except RuntimeError as error:
        logger.error(
            "%s. Plum-Agent requires nmap2json >= %s. Install a compatible wheel "
            "in this Python environment and restart Plum-Agent.",
            error,
            MIN_NMAP2JSON_VERSION,
        )
        sys.exit(1)
    logger.debug("Configuration loaded")

    # Config and AutoSetup
    try:
        if args.daemon:
            CONFIG["daemon"] = True
        CONFIG = setup(CONFIG, args)  # Update config
        try:
            file_handler.set_keep_days(parse_logrotation(CONFIG.get("logrotation")))
        except ValueError as error:
            logger.error("Invalid logrotation configuration: %s", error)
            sys.exit(8)

        if args.setup:
            sys.exit(0)  # Setup only
        else:
            # Run mode
            if args.once:
                loop(False)
            elif args.daemon:
                loop(True)

    except KeyboardInterrupt:
        print()  # Flush screen
        logger.warning("Keyboard Interruption, Shutting down")
        terminate_running_elfs()
        sys.exit(0)
