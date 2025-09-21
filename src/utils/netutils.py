'''
Network Related functions
'''

import logging
import random
import ipaddress
import socket
import requests
from requests.exceptions import Timeout, SSLError, RequestException

logger = logging.getLogger("Plum_Agent")


def getextip():
    '''
    Resolve the external (non-RFC1918) IP (v4 or v6) of the host
    using external services.
    '''

    providers = [
        "https://checkip.amazonaws.com",
        "https://ipinfo.io/ip",
        "https://ident.me",
        "https://wtfismyip.com/text",
        "https://api.ipify.org",
        "https://icanhazip.com",
        "http://ifconfig.me/ip",
    ]

    random.shuffle(providers)

    for provider in providers:
        try:
            logger.debug("Using IP external provider %s", provider)

            response = requests.get(provider, timeout=5)
            ip = response.text.strip()
            ip_obj = ipaddress.ip_address(ip)

            if not ip_obj.is_private:
                logger.info("Detected external IP: %s", ip)
                return ip
            else:
                logger.error("Abnormal, RFC1918 IP detected: %s", ip)

        except (Timeout, SSLError, ConnectionError, socket.gaierror, TypeError,
                RequestException) as e:
            logger.warning("Unable to determine external IP with provider %s: %s", provider, e)

    logger.error("No more external IP provider available for discovery")
    return None
