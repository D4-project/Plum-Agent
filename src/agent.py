#!/usr/bin/env python3
# coding=utf-8

'''
Plum Agent Main code
'''

import logging
import os
import argparse
import sys
import uuid
import yaml
from rich.logging import RichHandler
from utils.meta import print_meta
from utils.mutils import locate_elf, run_elf
from utils.netutils import getextip

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
file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="[%X]")
file_handler.setFormatter(file_formatter)

# Activate log handlers
logger.addHandler(console_handler)
logger.addHandler(file_handler)

try:
    with open(
        os.path.join(THIS_DIR, "config", "config.yaml"), "r", encoding="utf-8"
    ) as f:
        CONFIG = yaml.safe_load(f)
        if not CONFIG:
            CONFIG = {} # In case of empty file
except FileNotFoundError:
    CONFIG = {}
logger.debug("Loaded config: %s", CONFIG)

def save_config():
    '''
    This function save the globalconfig
    '''
    logger.debug("%s", CONFIG)
    # Neves save Verbose.

    verbose = CONFIG.get("verbose")
    CONFIG["verbose"] = None

    with open(
        os.path.join(THIS_DIR, "config", "config.yaml"), "w", encoding="utf-8") as of:
        yaml.safe_dump(CONFIG, of, default_flow_style=False, allow_unicode=True)

    CONFIG["verbose"] = verbose


def set_config(prompt_args):
    '''
    This function will setup the tool if required by command line.
    It may setup:
        Plum-Island Hostname
        Api-Key
        Fixed External IP
    '''

    flag_setupchanged = False

    if prompt_args.island:
        CONFIG["island"] = prompt_args.island
        logger.info("PluM Island set to %s", prompt_args.island)
        flag_setupchanged = True
    if prompt_args.apikey:
        CONFIG["apikey"] = prompt_args.apikey
        logger.debug("API Key set")
        flag_setupchanged = True

    if flag_setupchanged:
        save_config()

def setup():
    '''
    Agent setup before execution

    The setup will ensure that nmap is reachable,
    A UUID for this agent is generated.
    The host may reach Internet and retrieve the external IP
    TODO: The API Key and Island host is configured
    TODO: The Island is reachable and the API key is valid.
    '''
    flag_setupchanged = False

    logger.info("Initialize Agent system")
    present, nmap_path = locate_elf("nmap")
    if not present:
        logger.error("Nmap binary not found in path, please install it")
        sys.exit(1)
    logger.info("Nmap found in %s", nmap_path)
    CONFIG["nmap_path"] = nmap_path

    # Retrieve or regenerate UUID of the agent
    if not CONFIG.get("uid"):
        uid = uuid.uuid4()
        logger.info("New UUID generated %s", uid)
        CONFIG["uid"] = str(uid)
        flag_setupchanged = True
    else:
        logger.info("Agent UID %s", CONFIG.get("uid"))

    # Check External IP
    CONFIG["extip"] = getextip()
    if not CONFIG.get("extip"):
        logger.error("External IP could not be determined")
        sys.exit(2)

    # Check API Key
    if not CONFIG.get("apikey"):
        logger.error("Missing API Key, configure with -s -apikey")
        sys.exit(3)

    # Check Controller destination
    if not CONFIG.get("island"):
        logger.error("Missing Plum Island controller host, configure with -s -island")
        sys.exit(4)

    # If config changed save it.
    if flag_setupchanged:
        save_config()

def scan():
    '''
    Do a Scan Job
    '''
    dbg_flag = ""
    if CONFIG.get("verbose"):
        dbg_flag = "-v"

    run_args = ["-Pn", "-p", "80,443", "www.circl.lu", "-oX", "output.xml",
                "--no-stylesheet", dbg_flag]
    run_args = [arg for arg in run_args if arg]
    logger.debug("Executing %s %s", CONFIG.get("nmap_path"), run_args)
    run_elf(CONFIG.get("nmap_path"), run_args)

def loop(repeat):
    '''
    Agent Execution
    '''

    if repeat:
        logger.info("Starting to work endlessy")
        while True:
            logger.info("Starting to work endlessy")
            scan()
    else:
        logger.info("Starting to work once")
        scan()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plum Discovery Agent")
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("-o", "--once", action="store_true", help="Run Once")
    group.add_argument("-d", "--daemon", action="store_true", help="Run Endlessly")

    group.add_argument("-s", "--setup", action="store_true", help="Setup configuration and save config")
    parser.add_argument("-island", help="Hostname or IP of the Plum Island controller")
    parser.add_argument("-apikey", help="API Key")

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable debug output"
    )

    args = parser.parse_args()

    if args.verbose:
        CONFIG["verbose"]=True
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
            '''
            Black magic to put handler to our direct handler
            '''
            def emit(self, record):
                logger.handle(record)

        urllib3_logger.addHandler(RedirectHandler())



    print_meta()
    logger.debug("Loaded config: %s", CONFIG)
    if args.setup:
        # Config then AutoSetup
        setup()
        set_config(args)
    else:
        # Run mode
        setup() # Autoconf.
        set_config(args) # Command line Conf.
        if args.once:
            loop(False)
        elif args.daemon:
            loop(True)
