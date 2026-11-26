"""Masscan IPv6 compatibility and XML input checks."""

import sys
import tempfile
import unittest
from pathlib import Path
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from utils.masscan_report import masscan_report_stream
from nmap2json import nmap_file_to_json


class MasscanReportTests(unittest.TestCase):
    def convert(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.xml"
            path.write_bytes(raw)
            result = masscan_report_stream(path)
            self.assertEqual(path.read_bytes(), raw)
            return result

    def test_repair_and_json_conversion(self):
        raw = b'<nmaprun scanner="masscan"><host endtime="100"><address addr="2a00:1169:11b:8d30:" addrtype="ipv6"/><ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/></port></ports></host></nmaprun>'
        stream = self.convert(raw)
        self.assertEqual(
            ET.fromstring(stream.getvalue()).find("host/address").get("addr"),
            "2a00:1169:11b:8d30::0",
        )
        result = nmap_file_to_json(stream, True, True)
        self.assertEqual(result[0]["addr"], "2a00:1169:11b:8d30::")
        self.assertEqual(result[0]["ports"][0]["portid"], "80")

    def test_valid_addresses_unchanged(self):
        for address in ("192.0.2.1", "2001:db8::", "2001:db8::1"):
            raw = (
                f'<nmaprun><host><address addr="{address}"/></host></nmaprun>'.encode()
            )
            root = ET.fromstring(self.convert(raw).getvalue())
            self.assertEqual(root.find("host/address").get("addr"), address)

    def test_reject_unsafe_and_oversized_xml(self):
        for raw in (
            b"<!DOCTYPE nmaprun><nmaprun/>",
            b'<!DOCTYPE nmaprun [<!ENTITY x "test">]><nmaprun>&x;</nmaprun>',
            b"x" * (1024 * 1024 + 1),
            b'<nmaprun><host><address addr="garbage:"/></host></nmaprun>',
        ):
            with self.subTest(prefix=raw[:60]), self.assertRaises(ValueError):
                self.convert(raw)


if __name__ == "__main__":
    unittest.main()
