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


def scan():
    """
    Do a Scan Job
    """

    job = robust_request(
        CONFIG.get("APIPATH").getjob,
        method="POST",
        data=CONFIG.get("botinfo"),
    )
    logger.debug("Message Received: %s", job.get("message"))

    # Validate JOB
    range_toscan = job.get("message").get("job")
    if len(range_toscan) == 0:
        logger.info("No Job to process")
        if CONFIG.get("daemon"):
            logger.info("Sleeping 30'")
            time.sleep(30)
        return False

    # Validate the  UID
    range_uid = job.get("message").get("job_uid")
    try:
        uuid.UUID(str(range_uid))
    except ValueError:
        logger.error("Invalid UID format")
        return False

    nmap_ports = ",".join(str(i) for i in job.get("message").get("nmap_ports"))
    nmap_nse = ",".join( job.get("message").get("nmap_nse"))

    logger.info("Job UID %s Received, Target is %s", range_toscan, range_uid)

    dbg_flag = ""
    trace = ""
    if CONFIG.get("verbose"):
        dbg_flag = "-v"
        trace = "-script-trace"

    output_xml = os.path.join(CONFIG.get("THIS_DIR"), f"{range_uid}.xml")

    run_args = [
        "-Pn",
        "-p",
        nmap_ports,
        "-oX",
        output_xml,
        "--no-stylesheet",
        "--script",
        nmap_nse,
        dbg_flag, trace,

        range_toscan,
    ]
    run_args = [arg for arg in run_args if arg]
    logger.debug("Executing %s %s", CONFIG.get("nmap_path"), run_args)
    run_elf(CONFIG.get("nmap_path"), run_args)

    results = {}
    # fetching report.
    if os.path.isfile(output_xml):
        results = nmap_file_to_json(output_xml)
        # with open(output_xml, "r", encoding="utf-8") as file:
        #    results = file.read()
        os.remove(output_xml)
    else:
        logger.error("No Scan output file")

    data = CONFIG.get("botinfo")
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
