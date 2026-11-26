"""Agent-side compatibility fixes for Masscan XML reports."""

from io import BytesIO
from ipaddress import IPv6Address
from xml.etree import ElementTree as ET
from xml.parsers import expat


def masscan_report_stream(path):
    """Repair a missing trailing IPv6 colon without changing valid addresses."""
    with open(path, "rb") as source:
        raw = source.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("Masscan report exceeds 1 MiB")

    def reject(*_args):
        raise ValueError("DTD and entities are forbidden in Masscan reports")

    guard = expat.ParserCreate()
    guard.StartDoctypeDeclHandler = reject
    guard.EntityDeclHandler = reject
    guard.ExternalEntityRefHandler = reject
    try:
        guard.Parse(raw, True)
    except expat.ExpatError as error:
        raise ValueError("Malformed Masscan XML") from error
    # ElementTree does not expand XInclude or fetch external resources.
    root = ET.fromstring(raw)
    for address in root.findall("host/address"):
        value = address.get("addr", "")
        if not value.endswith(":"):
            continue
        try:
            IPv6Address(value)
        except ValueError:
            repaired = value + ":0"
            IPv6Address(repaired)
            address.set("addr", repaired)
    return BytesIO(ET.tostring(root, encoding="utf-8"))
