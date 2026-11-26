"""
Network Related functions
"""

import logging
import random
import ipaddress
import socket
import time
import json
import requests
from requests.exceptions import Timeout, SSLError, RequestException

logger = logging.getLogger("Plum_Agent")


class EndpointUnavailable(Exception):
    """The controller does not provide the requested optional endpoint."""


def get_ext_ips():
    """Detect externally visible addresses independently for IPv4 and IPv6."""
    providers = {
        4: "https://api4.ipify.org",
        6: "https://api6.ipify.org",
    }
    detected = {}
    for version, provider in providers.items():
        try:
            response = requests.get(provider, timeout=5)
            response.raise_for_status()
            address = ipaddress.ip_address(response.text.strip())
            if address.version == version and address.is_global:
                detected[version] = str(address)
                logger.info("Detected external IPv%s address", version)
            else:
                logger.info("No external IPv%s address detected", version)
        except (
            Timeout,
            SSLError,
            ConnectionError,
            socket.gaierror,
            TypeError,
            ValueError,
            RequestException,
        ) as error:
            logger.info("External IPv%s connectivity unavailable: %s", version, error)
    return detected


def get_ext_ip():
    """
    Resolve the external (non-RFC1918) IP (v4 or v6) of the host
    using external services.
    """

    providers = [
        "https://checkip.amazonaws.com",
        "https://ipinfo.io/ip",
        "https://ident.me",
        "https://wtfismyip.com/text",
        "https://api.ipify.org",
        "https://icanhazip.com",
        "http://ifconfig.me/ip",
        "https://ip.circl.lu/raw",
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
                # If we got internal IP, we got a severe issue
                logger.error("Abnormal, RFC1918 IP detected: %s", ip)

        except (
            Timeout,
            SSLError,
            ConnectionError,
            socket.gaierror,
            TypeError,
            RequestException,
        ) as e:
            logger.warning(
                "Unable to determine external IP with provider %s: %s", provider, e
            )

    logger.error("No more external IP provider available for discovery")
    return None


def robust_request(
    url,
    method="GET",
    headers=None,
    data=None,
    params=None,
    max_retries=None,
    *,
    optional_endpoint=False,
):
    """
    Perform GET or POST request on API
    Retry on failure with progressive delay
    Automatically parses JSON and returns a Python dict.

    url: API endpoint
    method: "GET" or "POST"
    headers: dict
    data: dict for POST
    params: dict for GET params
    max_retries: optional, None = infinite
    optional_endpoint: raise EndpointUnavailable on HTTP 404 or 405 without retrying

    return dict or None if max retries reached

    TODO Print json error messages in debug.
    """

    delays = [2, 5, 30, 60]  # Retry Schedule
    retry_delay = 300  # Last resort Retry
    attempts = 0
    timeout_wait = 45

    method = method.upper()
    if method not in ("GET", "POST"):
        raise ValueError("method must be 'GET' or 'POST'")

    while True:
        try:
            if method == "GET":
                response = requests.get(
                    url, headers=headers, params=params, timeout=timeout_wait
                )
            else:
                response = requests.post(
                    url,
                    headers=headers,
                    json=json.dumps(data),
                    params=params,
                    timeout=timeout_wait,
                )
                logger.debug("Island responded with HTTP %d", response.status_code)
            if optional_endpoint and response.status_code in (404, 405):
                raise EndpointUnavailable
            if response.status_code != 200:
                logger.error("%s %s -> %s", method, url, response.status_code)
            else:
                try:
                    return response.json()
                except ValueError:
                    logger.error("Invalid JSON response from %s", url)

        except requests.RequestException as e:
            logger.error("Request failed: %s", e)

        # Retry
        delay = delays[attempts] if attempts < len(delays) else retry_delay
        logger.warning("Retrying in %s seconds...", delay)
        time.sleep(delay)
        attempts += 1

        if max_retries is not None and attempts >= max_retries:
            logger.error("Max retries reached. Aborting.")
            return None
