"""Targeted ports include nonresponders; older controllers receive no new field."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import agent
from utils.scan_stats import masscan_targeted_ports, nmap_targeted_ports


class ScanStatsTest(unittest.TestCase):
    """Regression checks for scan stats test."""

    def test_overlapping_ranges_and_address_families(self):
        """Verify overlapping ranges and address families."""
        args = ["192.0.2.0/30", "192.0.2.1", "2001:db8::/127", "-p", "22,443"]
        self.assertEqual(masscan_targeted_ports(args, "22,22,80-81"), 18)

    def test_nmap_totals_count_down_hosts(self):
        """Verify nmap totals count down hosts."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "scan.xml")
            path.write_text(
                '<nmaprun scanner="nmap"><scaninfo protocol="tcp" numservices="2"/><runstats><hosts up="1" down="255" total="256"/></runstats></nmaprun>'
            )
            self.assertEqual(nmap_targeted_ports(path), 512)
            path.write_text('<nmaprun scanner="nmap"/>')
            self.assertIsNone(nmap_targeted_ports(path))
            path.write_text('<!DOCTYPE nmaprun [<!ENTITY x "bad">]><nmaprun/>')
            with self.assertRaises(ValueError):
                nmap_targeted_ports(path)

    def test_send_counter_only_to_a_controller_that_requests_it(self):
        """Verify send counter only to a controller that requests it."""
        for tool in ("masscan", "nmap"):
            for requested in (False, True):
                with self.subTest(
                    tool=tool, requested=requested
                ), tempfile.TemporaryDirectory() as tmp:
                    sent = {}

                    def run(executable, arguments, **kwargs):
                        """Provide the run test fixture."""
                        output = Path(arguments[arguments.index("-oX") + 1])
                        if tool == "masscan":
                            output.write_text("")
                        else:
                            output.write_text(
                                '<nmaprun scanner="nmap"><scaninfo protocol="tcp" numservices="2"/><runstats><hosts up="0" down="4" total="4"/></runstats></nmaprun>'
                            )
                        return 0

                    def send(url, method, data, **kwargs):
                        """Provide the send test fixture."""
                        sent.update(data)
                        return {"message": "ready"}

                    config = dict(
                        THIS_DIR=tmp,
                        masscan_path="masscan",
                        nmap_path="nmap",
                        capabilities=[tool],
                        debug_mode="none",
                        botinfo={},
                        APIPATH=SimpleNamespace(sndjob="unused"),
                    )
                    with mock.patch.dict(agent.CONFIG, config), mock.patch.object(
                        agent, "run_elf", side_effect=run
                    ), mock.patch.object(
                        agent, "robust_request", side_effect=send
                    ), mock.patch.object(
                        agent, "_resolve_nse_targets", return_value=[]
                    ):
                        self.assertTrue(
                            agent.run_scan_job(
                                dict(
                                    job="192.0.2.0/30",
                                    job_uid="f5813ec7-b36b-4fe7-b662-cca3d281725c",
                                    scan_tool=tool,
                                    scan_ports=[22, 443],
                                    report_target_count=requested,
                                )
                            )
                        )
                    self.assertEqual("PORTS_TARGETED" in sent, requested)
                    if requested:
                        self.assertEqual(sent["PORTS_TARGETED"], 8)
