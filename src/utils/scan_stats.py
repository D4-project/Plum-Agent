"""Count intended IP/transport/port pairs without issuing DNS or scan traffic."""

import ipaddress
from nmap2json.report_xml import read_report


def masscan_targeted_ports(arguments, ports):
    """Count the union of already resolved command targets and TCP ports."""
    networks = []
    for value in arguments:
        if value.startswith("-"):
            break
        networks.append(ipaddress.ip_network(value, strict=False))
    hosts = sum(
        net.num_addresses
        for family in (4, 6)
        for net in ipaddress.collapse_addresses(
            n for n in networks if n.version == family
        )
    )
    numbers = set()
    for value in ports.split(","):
        bounds = value.split("-")
        start, end = int(bounds[0]), int(bounds[-1])
        if not 1 <= start <= end <= 65535:
            raise ValueError("Invalid TCP port range")
        numbers.update(range(start, end + 1))
    return hosts * len(numbers)


def nmap_targeted_ports(path):
    """Use scanner-reported hosts and scaninfo, including nonresponding targets."""
    with open(path, "rb") as stream:
        root = read_report(stream)
    hosts = root.find("runstats/hosts")
    scaninfo = root.findall("scaninfo")
    if hosts is None or not scaninfo:
        return None
    count = int(hosts.get("total", "-1"))
    if count < 0:
        return None
    counts = [int(item.get("numservices", "-1")) for item in scaninfo]
    if any(value < 0 for value in counts):
        return None
    return count * sum(counts)
