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
from utils.log import LogFilter
from utils.mutils import locate_elf

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler()],
)

logging.getLogger("pyrogram.session.session").addFilter(LogFilter())
logging.getLogger("pyrogram.client").addFilter(LogFilter())
logger = logging.getLogger("media_downloader")

THIS_DIR = os.path.dirname(os.path.abspath(__file__))

try:
    with open(os.path.join(THIS_DIR, "config", "config.yaml"), "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
except FileNotFoundError:
    config = {}


def setup():
    '''
    Agent setup before execution 
    '''
    flag_setupchanged = False

    logger.info("Initialize Agent system")
    present, nmap_path = locate_elf("nmap")
    if not present:
        logger.error("Nmap binary not found in path, please install it")
        sys.exit(1)
    logger.info("Nmap found in %s", nmap_path)
    config["nmap_path"] = nmap_path

    # Retrieve or regenerate UUID of the agent
    if not config.get("uid"):
        uid = uuid.uuid4()
        logger.info("New UUID generated %s", uid)
        config["uid"] = str(uid)
        flag_setupchanged = True
    else:
        logger.info("Agent UID %s", config.get("uid"))


    # If config changed save it.
    if flag_setupchanged:
        with open(os.path.join(THIS_DIR, "config", "config.yaml"), "w", encoding="utf-8") as of:
            yaml.safe_dump(config, of, default_flow_style=False, allow_unicode=True)


def loop(repeat):
    '''
    Agent Execution
    '''
    while repeat:
        logger.info("Starting to work")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Plum Discovery Agent")
    parser = argparse.ArgumentParser(
        description="Plum Discovery Agent"
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        '-o', '--once',
        action='store_true',
        help='Run Once'
    )
    group.add_argument(
        '-d', '--daemon',
        action='store_true',
        help='Run Endlessly'
    )
    args = parser.parse_args()

    print_meta()
    setup()
    if args.once:
        loop(False)
    elif args.daemon:
        loop(True)
