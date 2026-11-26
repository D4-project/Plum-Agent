"""
This module, manage the configuration and saved options
"""

import sys
import logging
import os
import uuid
import subprocess
import ipaddress
import json
import yaml
from utils.meta import get_bot_info
from utils.mutils import locate_elf, Dict2obj
from utils.netutils import EndpointUnavailable, get_ext_ip, get_ext_ips, robust_request
from utils.logrotation import parse_logrotation
from utils.scanparallel import parse_scanparallel
from utils.scanhours import normalize_scanhours

logger = logging.getLogger("Plum_Agent")


def validate_masscan_ip(value, version=None):
    """Validate the source family and warn about kernel interface assignment."""
    if value in (None, ""):
        return None
    address = ipaddress.ip_address(value)
    if version is not None and address.version != version:
        raise ValueError(f"masscan_ip_v{version} must be IPv{version}")
    if (
        address.is_unspecified
        or address.is_multicast
        or address.is_loopback
        or address.is_link_local
    ):
        raise ValueError("masscan_ip must be a dedicated unicast address")
    result = subprocess.run(
        ["ip", "-j", "address", "show"],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    for interface in json.loads(result.stdout):
        for info in interface.get("addr_info", []):
            if ipaddress.ip_address(info["local"]) == address:
                logger.warning(
                    "Masscan source IP is already assigned to a kernel interface; "
                    "continuing. A dedicated source IP is recommended for banner detection."
                )
                return str(address)
    return str(address)


def parse_masscan_rate(value):
    """Validate the local packets-per-second limit."""
    if value is None:
        return 1000
    if isinstance(value, bool):
        raise ValueError("masscan_rate must be a positive integer")
    try:
        value = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("masscan_rate must be a positive integer") from error
    if value < 1:
        raise ValueError("masscan_rate must be a positive integer")
    return value


def _masscan_has_raw_socket_access(path):
    """Masscan may run as root or with CAP_NET_RAW in its effective set."""
    if os.geteuid() == 0:
        return True
    try:
        output = subprocess.run(
            ["getcap", path],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.lower()
    except (OSError, subprocess.TimeoutExpired):
        return False
    capability_text = output.partition(" ")[2].strip()
    return "cap_net_raw" in capability_text and "e" in capability_text.partition("=")[2]


def _masscan_supports_ipv6(path):
    """Probe IPv6 target parsing without sending packets."""
    try:
        result = subprocess.run(
            [path, "2001:db8::1", "-p80", "--echo"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


class APIPath:
    """
    Simple class to describe bot API endpoints.
    """

    def __init__(self, host):
        self.host = host.rstrip("/")  # remove trailing slash
        self.protocol = f"{self.host}/bot_api/protocol"
        self.register = f"{self.host}/bot_api/beacon"
        self.getjob = f"{self.host}/bot_api/getjob"
        self.sndjob = f"{self.host}/bot_api/sndjob"
        self.releasejob = f"{self.host}/bot_api/releasejob"


def save_config(curr_config):
    """
    This function save the globalconfig
    """
    # Never save some paramaters.
    svg_config = curr_config.copy()
    config_file = os.path.join(svg_config.get("THIS_DIR"), "config", "config.yaml")
    for item in ["verbose", "debug_mode", "curr_ip", "THIS_DIR", "APIPATH"]:
        svg_config.pop(item, None)

    with open(config_file, "w", encoding="utf-8") as of:
        yaml.safe_dump(svg_config, of, default_flow_style=False, allow_unicode=True)
    logger.debug("Configuration saved")


def _supports_tool_inventory(endpoint):
    """Use the legacy protocol only when its optional discovery route is absent."""
    try:
        info = robust_request(endpoint, max_retries=3, optional_endpoint=True)
    except EndpointUnavailable:
        return False
    if not isinstance(info, dict) or info.get("tool_inventory") is not True:
        logger.error("Could not determine the Island agent protocol")
        sys.exit(5)
    return True


def setup(cfg, cmd_args):
    """
    Agent setup before execution

    The setup will ensure that an enabled Nmap is reachable,
    A UUID for this agent is generated.
    The host may reach Internet and retrieve the external IP
    The API Key and Island host is configured
    The Island is reachable and the API key is valid.
    TODO: Override external IP
    """

    disabled = {}
    for tool in ("nmap", "masscan"):
        value = cfg.get(f"{tool}_disabled", False)
        if not isinstance(value, bool):
            logger.error("Invalid %s_disabled setting. Expected true or false.", tool)
            sys.exit(1)
        disabled[tool] = value

    flag_setupchanged = False

    # Migrate old config and CLI settings into their matching family key.
    legacy_source = cfg.pop("masscan_ip", None)
    legacy_argument = getattr(cmd_args, "masscan_ip", None)
    if legacy_argument:
        legacy_source = legacy_argument
        flag_setupchanged = True
    if legacy_source:
        try:
            legacy_family = ipaddress.ip_address(legacy_source).version
        except ValueError:
            logger.error("Invalid legacy masscan_ip")
            sys.exit(1)
        key = f"masscan_ip_v{legacy_family}"
        if legacy_argument:
            cfg[key] = legacy_source
        else:
            cfg.setdefault(key, legacy_source)
        flag_setupchanged = True
    for version in (4, 6):
        key = f"masscan_ip_v{version}"
        argument = getattr(cmd_args, key, None)
        if argument is not None:
            cfg[key] = argument
            flag_setupchanged = True
        try:
            cfg[key] = validate_masscan_ip(cfg.get(key), version)
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            logger.error("Invalid %s: %s", key, error)
            sys.exit(1)

    if getattr(cmd_args, "island", None):
        cfg["island"] = cmd_args.island
        logger.info("PluM Island set to %s", cmd_args.island)
        flag_setupchanged = True
    if getattr(cmd_args, "agentkey", None):
        cfg["agent_key"] = cmd_args.agentkey
        logger.debug("API Key set")
        flag_setupchanged = True

    if getattr(cmd_args, "ipext", None):
        cfg["ext_ip"] = cmd_args.ipext
        logger.debug("External IP manually set")
        flag_setupchanged = True
    if getattr(cmd_args, "scanparallel", None) is not None:
        try:
            cfg["scanparallel"] = parse_scanparallel(cmd_args.scanparallel)
        except ValueError as error:
            logger.error("Invalid scanparallel: %s", error)
            sys.exit(7)
        logger.info("Scan parallel jobs set to %s", cfg.get("scanparallel"))
        flag_setupchanged = True
    if getattr(cmd_args, "logrotation", None) is not None:
        try:
            cfg["logrotation"] = parse_logrotation(cmd_args.logrotation)
        except ValueError as error:
            logger.error("Invalid logrotation: %s", error)
            sys.exit(8)
        logger.info("Log rotation retention set to %s days", cfg.get("logrotation"))
        flag_setupchanged = True
    if getattr(cmd_args, "scanhours", None) is not None:
        try:
            normalized_scanhours = normalize_scanhours(cmd_args.scanhours)
        except ValueError as error:
            logger.error("Invalid scanhours: %s", error)
            sys.exit(6)

        if normalized_scanhours is None:
            cfg.pop("scanhours", None)
            logger.info("Scan hours disabled")
        else:
            cfg["scanhours"] = normalized_scanhours
            logger.info("Scan hours set to %s GMT", normalized_scanhours)
        flag_setupchanged = True

    if cfg.get("scanhours"):
        try:
            cfg["scanhours"] = normalize_scanhours(cfg.get("scanhours"))
        except ValueError as error:
            logger.error("Invalid scanhours: %s", error)
            sys.exit(6)
    if cfg.get("scanparallel") is not None:
        try:
            cfg["scanparallel"] = parse_scanparallel(cfg.get("scanparallel"))
        except ValueError as error:
            logger.error("Invalid scanparallel: %s", error)
            sys.exit(7)
    if cfg.get("logrotation") is not None:
        try:
            cfg["logrotation"] = parse_logrotation(cfg.get("logrotation"))
        except ValueError as error:
            logger.error("Invalid logrotation: %s", error)
            sys.exit(8)

    if flag_setupchanged:
        logger.debug("Setup changed, saving it")
        save_config(cfg)

    if not cfg.get("agent_key"):
        logger.error("Missing API Key, configure with -s -agentkey")
        sys.exit(3)
    if not cfg.get("island"):
        logger.error("Missing Plum Island controller host, configure with -s -island")
        sys.exit(4)

    tools = ("nmap", "masscan")
    tool_inventory = True
    if not cmd_args.setup:
        cfg["APIPATH"] = APIPath(cfg["island"])
        tool_inventory = _supports_tool_inventory(cfg["APIPATH"].protocol)
        if not tool_inventory:
            logger.info(
                "Legacy Island detected. Only Nmap is available for this session."
            )
            tools = ("nmap",)

    logger.info("Initialize Agent system")
    capabilities = []
    for tool in ("nmap", "masscan"):
        cfg.pop(f"{tool}_path", None)
    cfg.pop("masscan_ipv6", None)
    for tool in tools:
        path_key = f"{tool}_path"
        if disabled[tool]:
            logger.info("%s disabled by configuration", tool.capitalize())
            continue
        present, path = locate_elf(tool)
        if not present:
            logger.info("%s not found on PATH", tool.capitalize())
            continue
        path = os.path.realpath(path)
        if (
            tool == "masscan"
            and not cmd_args.setup
            and not _masscan_has_raw_socket_access(path)
        ):
            logger.error(
                "Masscan cannot open raw sockets. Run: sudo setcap cap_net_raw=eip %s",
                path,
            )
            logger.error("Verify with: getcap %s, then restart Plum-Agent", path)
            sys.exit(1)
        cfg[path_key] = path
        capabilities.append(tool)
        logger.info("%s found in %s", tool.capitalize(), path)

    cfg["capabilities"] = capabilities
    if not capabilities and not cmd_args.setup:
        if tool_inventory:
            logger.error(
                "No enabled scan tool available. Install Nmap or Masscan, or check disabled settings."
            )
        else:
            logger.error(
                "Legacy Island requires Nmap. Install and enable Nmap to continue."
            )
        sys.exit(1)
    if "masscan" in capabilities:
        try:
            cfg["masscan_rate"] = parse_masscan_rate(cfg.get("masscan_rate"))
        except ValueError as error:
            logger.error("Invalid masscan_rate: %s", error)
            sys.exit(1)
        cfg["masscan_ipv6_binary"] = _masscan_supports_ipv6(cfg["masscan_path"])
        logger.info(
            "Masscan IPv6 binary support %s",
            "available" if cfg["masscan_ipv6_binary"] else "unavailable",
        )

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

    # Only advertise a Masscan address family when the host has verified
    # external connectivity on that family and the binary supports it.
    external_ips = get_ext_ips() if "masscan" in capabilities else {}
    # `curr_ip` proves reachability only when it was discovered dynamically;
    # a configured identity override is not a connectivity check.
    if not cfg.get("ext_ip"):
        try:
            address = ipaddress.ip_address(cfg.get("curr_ip"))
        except (TypeError, ValueError):
            address = None
        if address is not None and address.is_global:
            external_ips.setdefault(address.version, str(address))
    if "masscan" in capabilities:
        cfg["masscan_ipv4"] = 4 in external_ips
        cfg["masscan_ipv6"] = 6 in external_ips and bool(cfg.get("masscan_ipv6_binary"))
        logger.info(
            "Masscan address families enabled: IPv4=%s IPv6=%s",
            cfg["masscan_ipv4"],
            cfg["masscan_ipv6"],
        )
        if not cfg["masscan_ipv4"] and not cfg["masscan_ipv6"]:
            logger.warning(
                "Masscan found, but no externally reachable IP family was detected"
            )
            if "nmap" not in capabilities and not cmd_args.setup:
                logger.error(
                    "Masscan cannot start without external IPv4 or IPv6 connectivity"
                )
                sys.exit(1)
            capabilities = [tool for tool in capabilities if tool != "masscan"]
            cfg["capabilities"] = capabilities

    # If config changed save it.
    if flag_setupchanged:
        save_config(cfg)

    # If execution required, we will validate Island availability
    if not cmd_args.setup:
        cfg["botinfo"] = get_bot_info(
            cfg.get("uid"), cfg.get("curr_ip")
        )  # Create BOT report infoblock
        cfg["botinfo"]["AGENT_KEY"] = cfg["agent_key"]
        logger.info("Check if Island reachable")
        logger.debug("Validation address %s", cfg.get("APIPATH").register)

        bot_report = dict(cfg["botinfo"])
        if tool_inventory:
            bot_report["capabilities"] = list(capabilities)
            if "masscan" in capabilities:
                bot_report["masscan_families"] = [
                    f"ipv{version}"
                    for version in (4, 6)
                    if cfg.get(f"masscan_ipv{version}", False)
                ]
                for version in (4, 6):
                    source = cfg.get(f"masscan_ip_v{version}")
                    if source:
                        bot_report[f"masscan_ip_v{version}"] = source
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

    return cfg
