"""
This module, manage the configuration and saved options
"""

import sys
import logging
import os
import uuid
import yaml
from utils.meta import get_bot_info
from utils.mutils import locate_elf, Dict2obj
from utils.netutils import get_ext_ip, robust_request

logger = logging.getLogger("Plum_Agent")


class APIPath:
    """
    Simple class to describe bot API endpoints.
    """

    def __init__(self, host):
        self.host = host.rstrip("/")  # remove trailing slash
        self.register = f"{self.host}/bot_api/beacon"
        self.getjob = f"{self.host}/bot_api/getjob"
        self.sndjob = f"{self.host}/bot_api/sndjob"


def save_config(curr_config):
    """
    This function save the globalconfig
    """
    # Never save some paramaters.
    svg_config = curr_config.copy()
    config_file = os.path.join(svg_config.get("THIS_DIR"), "config", "config.yaml")
    for item in ["verbose", "curr_ip", "THIS_DIR", "APIPATH"]:
        svg_config.pop(item, None)

    with open(config_file, "w", encoding="utf-8") as of:
        yaml.safe_dump(svg_config, of, default_flow_style=False, allow_unicode=True)
    logger.debug("Saved configuration: %s", svg_config)


def setup(cfg, cmd_args):
    """
    Agent setup before execution

    The setup will ensure that nmap is reachable,
    A UUID for this agent is generated.
    The host may reach Internet and retrieve the external IP
    The API Key and Island host is configured
    The Island is reachable and the API key is valid.
    TODO: Override external IP
    """

    flag_setupchanged = False

    if cmd_args.island:
        cfg["island"] = cmd_args.island
        logger.info("PluM Island set to %s", cmd_args.island)
        flag_setupchanged = True
    if cmd_args.agentkey:
        cfg["agent_key"] = cmd_args.agentkey
        logger.debug("API Key set")
        flag_setupchanged = True

    if cmd_args.ipext:
        cfg["ext_ip"] = cmd_args.ipext
        logger.debug("External IP manually set")
        flag_setupchanged = True

    if flag_setupchanged:
        logger.debug("Setup changed, saving it")
        save_config(cfg)

    logger.info("Initialize Agent system")
    present, nmap_path = locate_elf("nmap")
    if not present:
        logger.error("Nmap binary not found in path, please install it")
        sys.exit(1)
    logger.info("Nmap found in %s", nmap_path)
    cfg["nmap_path"] = nmap_path

    # Retrieve or regenerate UUID of the agent
    if not cfg.get("uid"):
        uid = uuid.uuid4()
        logger.info("New UUID generated %s", uid)
        cfg["uid"] = str(uid)
        flag_setupchanged = True
    else:
        logger.info("Agent UID %s", cfg.get("uid"))

    # Check External IP, Do it only if the IP is not hardcoded
    if cfg.get("ext_ip"):
        logger.debug("Static external IP set: %s", cfg.get("ext_ip"))
        cfg["curr_ip"] = cfg.get("ext_ip")
    else:
        cfg["curr_ip"] = get_ext_ip()
        if not cfg.get("curr_ip"):
            logger.error("External IP could not be determined")
            sys.exit(2)

    # Check API Key
    if not cfg.get("agent_key"):
        logger.error("Missing API Key, configure with -s -agentkey")
        sys.exit(3)

    # Check Controller destination
    if not cfg.get("island"):
        logger.error("Missing Plum Island controller host, configure with -s -island")
        sys.exit(4)

    # If config changed save it.
    if flag_setupchanged:
        save_config(cfg)

    # If execution required, we will validate Island availability
    if not cmd_args.setup:
        cfg["botinfo"] = get_bot_info(
            cfg.get("uid"), cfg.get("curr_ip")
        )  # Create BOT report infoblock
        cfg["APIPATH"] = APIPath(cfg.get("island"))  # Setup PATHs
        logger.info("Check if Island reachable")
        logger.debug("Validation address %s", cfg.get("APIPATH").register)

        bot_report = cfg.get("botinfo")
        bot_report["AGENT_KEY"] = cfg.get("agent_key")
        ready_msg = robust_request(
            cfg.get("APIPATH").register, method="POST", data=bot_report, max_retries=3
        )
        if ready_msg:
            ready_msg = Dict2obj(ready_msg)  # convert to obj.
            if not ready_msg.message == "ready":
                logger.error("Island is not ready or bad host configured")
                sys.exit(5)
        else:
            logger.error("Island is not ready or bad host configured")
            sys.exit(5)

        # End of Setup, Island is Reachable
        return cfg
