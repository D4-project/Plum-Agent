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
from rich.logging import RichHandler
from nmap2json import nmap_file_to_json
from utils.meta import print_meta
from utils.mutils import run_elf
from utils.setup import setup
from utils.netutils import robust_request

THIS_DIR = os.path.dirname(os.path.abspath(__file__))

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

            tmp_path = f"{nse_path}.tmp"
            with open(tmp_path, "wb") as handle:
                handle.write(file_bytes)
            os.replace(tmp_path, nse_path)
            logger.info("NSE cache refresh: %s", nse_name)
        else:
            logger.info("NSE cache hit: %s", nse_name)

        selected_paths.append(nse_path)

    return selected_paths


def scan():
    """
    Do a Scan Job
    """

    job_request = dict(CONFIG.get("botinfo") or {})
    job_request["NSE_HASHES"] = _collect_nse_hashes()
    job = robust_request(
        CONFIG.get("APIPATH").getjob,
        method="POST",
        data=job_request,
    )
    if not job or "message" not in job:
        logger.error("Invalid job response from controller")
        return False

    logger.debug("Message Received: %s", job.get("message"))
    job_message = job.get("message") or {}

    # Validate JOB
    range_toscan = job_message.get("job", "")
    if len(range_toscan) == 0:
        logger.info("No Job to process")
        if CONFIG.get("daemon"):
            logger.info("Sleeping 30'")
            time.sleep(30)
        return False

    # Validate the  UID
    range_uid = job_message.get("job_uid")
    try:
        uuid.UUID(str(range_uid))
    except ValueError:
        logger.error("Invalid UID format")
        return False

    nmap_ports_list = job_message.get("nmap_ports") or []
    if not nmap_ports_list:
        logger.error("Job UID %s has no port definition", range_uid)
        return False

    nmap_ports = ",".join(str(i) for i in nmap_ports_list)
    try:
        nmap_nse_targets = _resolve_nse_targets(job_message)
    except ValueError as error:
        logger.error("Cannot prepare NSE scripts for job %s: %s", range_uid, error)
        return False

    logger.info("Job UID %s Received, Target is %s", range_toscan, range_uid)

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
    run_elf(CONFIG.get("nmap_path"), run_args)

    results = {}
    # fetching report.
    if os.path.isfile(output_xml):
        results = nmap_file_to_json(output_xml, True, True)
        os.remove(output_xml)
    else:
        logger.error("No Scan output file")

    data = dict(CONFIG.get("botinfo") or {})
    data = data | {"JOB_UID": str(range_uid), "RESULT": json.dumps(results)}

    robust_request(
        CONFIG.get("APIPATH").sndjob,
        method="POST",
        data=data,
    )
    logger.debug("Message Received: %s", job.get("message"))


def loop(repeat):
    """
    Main Loop for Agent Execution
    """

    if repeat:
        logger.info("Starting to work endlessy")
        while True:
            scan()
    else:
        logger.info("Starting to work one time")
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
        sys.exit(0)
