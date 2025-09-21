"""
Utility module to manage meta info.
"""

import platform

from rich.console import Console

from . import __copyright__, __license__, __curr_year__
from .mutils import get_version

APP_VERSION = f"{get_version()}"
DEVICE_MODEL = f"{platform.python_implementation()} {platform.python_version()}"
SYSTEM_VERSION = f"{platform.system()} {platform.release()}"
LANG_CODE = "en"


def print_meta():
    """
    Prints meta-data of the script.
    """
    console = Console()
    console.log("[bold]Plum Island Scanning Agent[/bold]")
    console.log(f"Licensed under the terms of the {__license__}")
    console.log(
        f"Another D4 project by CIRCL - 2025-{__curr_year__} - https://d4-project.org"
    )
    console.log(f"Device: {DEVICE_MODEL} - Plum Agent: {APP_VERSION}")
    console.log(f"System: {SYSTEM_VERSION} ({LANG_CODE.upper()})", end="\n\n")


def get_bot_info(uid, ext_ip):
    """
    Generate a dict with all BotInfo
    """
    bot_info = {
        "DEVICE_MODEL": DEVICE_MODEL,
        "AGENT_VERSION": APP_VERSION,
        "SYSTEM_VERSION": SYSTEM_VERSION,
        "UID": uid,
        "EXT_IP": ext_ip,
    }
    return bot_info
