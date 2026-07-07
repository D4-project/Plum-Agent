#!/usr/bin/env python3
# coding=utf-8

"""
Plum Agent Main code
"""

import logging
import os
import argparse
import sys
import uuid
import time
import yaml
import json
import base64
import hashlib
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from rich.logging import RichHandler
from nmap2json import nmap_file_to_json
from utils.meta import print_meta
from utils.mutils import run_elf, terminate_running_elfs
from utils.setup import setup
from utils.netutils import robust_request
from utils.scanparallel import parse_scanparallel
from utils.scanhours import is_scanhours_active

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
NO_JOB_SLEEP = 30
STANDBY_SLEEP = 60
BACKOFF_START = 5
BACKOFF_MAX = 60
NSE_CACHE_LOCK = threading.Lock()

# Initiate loggers.
logger = logging.getLogger("Plum_Agent")
logger.setLevel(logging.DEBUG)  # Niveau global

# Nice and color full console handder
console_handler = RichHandler()
console_handler.setLevel(logging.INFO)

# File Handler (auto create folder)
log_dir = os.path.join(THIS_DIR, "log")
os.makedirs(log_dir, exist_ok=True)
file_handler = logging.FileHandler(os.path.join(log_dir, "agent.log"), mode="a")
file_handler.setLevel(logging.INFO)
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
logger.debug("Loaded config: %s", CONFIG)
CONFIG["THIS_DIR"] = THIS_DIR


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
    if job is None or "message" not in job:
        raise RuntimeError("Invalid job response from controller")

    logger.debug("Message Received: %s", job.get("message"))
    job_message = job.get("message") or {}
    if not isinstance(job_message, dict):
        raise RuntimeError("Invalid job message from controller")

    # Validate JOB
    range_toscan = job_message.get("job") or ""
    if len(range_toscan) == 0:
        logger.info("No Job to process")
        return None

    return job_message


def run_scan_job(job_message):
    """
    Run one scan job already fetched from the controller.
    """

    range_toscan = job_message.get("job") or ""

    # Validate the  UID
    range_uid = job_message.get("job_uid")
    job_uid = _short_uid(range_uid)
    try:
        uuid.UUID(str(range_uid))
    except ValueError:
        logger.error("Job %s invalid UID format", job_uid)
        return False

    nmap_ports_list = job_message.get("nmap_ports") or []
    if not nmap_ports_list:
        logger.error("Job %s has no port definition", job_uid)
        return False

    nmap_ports = ",".join(str(i) for i in nmap_ports_list)
    try:
        nmap_nse_targets = _resolve_nse_targets(job_message)
    except ValueError as error:
        logger.error("Job %s cannot prepare NSE scripts: %s", job_uid, error)
        return False

    logger.info("Job %s received target=%s", job_uid, range_toscan)

    dbg_flag = ""
    trace = ""
    if CONFIG.get("verbose"):
        dbg_flag = "-v"
        trace = "-script-trace"

    output_xml = os.path.join(CONFIG.get("THIS_DIR"), f"{range_uid}.xml")

    run_args = [
        "-T4",
        "--host-timeout",
        "40s",
        "--max-retries",
        "2",
        "--min-hostgroup",
        "256",
        "-Pn",
        "-p",
        nmap_ports,
        "-oX",
        output_xml,
        "--no-stylesheet",
        dbg_flag,
        trace,
    ]
    if nmap_nse_targets:
        run_args.extend(["--script", ",".join(nmap_nse_targets)])

    # Finally  Add the ranges to scan
    for item in range_toscan.split(","):
        run_args.append(item)

    run_args = [arg for arg in run_args if arg]
    logger.debug("Executing %s %s", CONFIG.get("nmap_path"), run_args)
    logger.info("Job %s scan started", job_uid)
    return_code = run_elf(CONFIG.get("nmap_path"), run_args)
    if return_code and return_code < 0:
        logger.warning("Job %s scan interrupted", job_uid)
        return False
    if return_code:
        logger.error("Job %s scan process exited with code %s", job_uid, return_code)

    results = {}
    # fetching report.
    if os.path.isfile(output_xml):
        results = nmap_file_to_json(output_xml, True, True)
        os.remove(output_xml)
    else:
        logger.error("Job %s no scan output file", job_uid)

    data = dict(CONFIG.get("botinfo") or {})
    data = data | {"JOB_UID": str(range_uid), "RESULT": json.dumps(results)}

    result_response = robust_request(
        CONFIG.get("APIPATH").sndjob,
        method="POST",
        data=data,
        max_retries=3,
    )
    if result_response is None:
        logger.error("Job %s result send failed", job_uid)
        return False

    logger.info("Job %s scan completed", job_uid)
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
        "-scanhours",
        help="GMT scan window in HH-HH format, example 14-16",
    )
    parser.add_argument(
        "-scanparallel",
        help="Maximum scan jobs to run in parallel, 0 for standby",
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug output"
    )

    args = parser.parse_args()

    # Set Verbosity if required, including requests
    if args.verbose:
        CONFIG["verbose"] = True
        console_handler.setLevel(logging.DEBUG)
        file_handler.setLevel(logging.DEBUG)

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
    print_meta()
    logger.debug("Loaded config: %s", CONFIG)

    # Config and AutoSetup
    try:
        if args.daemon:
            CONFIG["daemon"] = True
        CONFIG = setup(CONFIG, args)  # Update config

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
