'''
Utility module to manage meta info.
'''
import platform

from rich.console import Console

from . import __copyright__, __license__, __version__, __curr_year__
from .mutils import get_version

APP_VERSION = f"Plum Agent {__version__}"
DEVICE_MODEL = f"{platform.python_implementation()} {platform.python_version()}"
SYSTEM_VERSION = f"{platform.system()} {platform.release()}"
LANG_CODE = "en"


def print_meta():
    """Prints meta-data of the downloader script."""
    console = Console()
    # pylint: disable = C0301
    console.log(
        f"[bold]Plum Island Scanning Agent v{get_version()}[/bold]"
    )
    console.log(f"Licensed under the terms of the {__license__}")
    console.log(f"Circl - 2025-{__curr_year__}")
    console.log(f"Device: {DEVICE_MODEL} - {APP_VERSION}")
    console.log(f"System: {SYSTEM_VERSION} ({LANG_CODE.upper()})", end="\n\n")
