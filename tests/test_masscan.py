"""Masscan job execution and report compatibility."""

import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, SRC_DIR)

import agent  # pylint: disable=wrong-import-position


class MasscanJobTests(unittest.TestCase):
    """Regression checks for masscan job tests."""

    UID = "f5813ec7-b36b-4fe7-b662-cca3d281725c"
    ATTEMPT_UID = "2bc1f6ba-5453-44cf-908a-a8f6fa7741de"

    def test_arguments_resolve_hostnames_and_enable_banners(self):
        """Verify arguments resolve hostnames and enable banners."""
        job = {
            "job": "192.0.2.0/31,example.test",
            "scan_family": "ipv4",
            "detect_protocol": True,
        }
        address = (None, None, None, None, ("192.0.2.5", 0))
        with (
            mock.patch.dict(agent.CONFIG, {"masscan_ip_v4": "192.0.2.10"}),
            mock.patch.object(
                agent.socket, "getaddrinfo", return_value=[address, address]
            ) as resolve,
        ):
            arguments = agent._build_masscan_args(job, "/tmp/result.xml", "22,443")
        resolve.assert_called_once_with(
            "example.test",
            None,
            family=agent.socket.AF_INET,
            type=agent.socket.SOCK_STREAM,
        )
        self.assertEqual(arguments[:2], ["192.0.2.0/31", "192.0.2.5"])
        self.assertEqual(arguments[arguments.index("--source-ip") + 1], "192.0.2.10")
        self.assertIn("--banners", arguments)
        self.assertEqual(arguments[arguments.index("--rate") + 1], "1000")

    def test_ipv6_resolution_is_skipped_when_binary_probe_failed(self):
        """Skip DNS for an IPv6 job the scanner cannot run."""
        with (
            mock.patch.dict(agent.CONFIG, {"masscan_ipv6": False}, clear=False),
            mock.patch.object(agent.socket, "getaddrinfo") as resolve,
        ):
            self.assertEqual(agent._resolve_masscan_targets("example.test", 6), [])
        resolve.assert_not_called()

    def test_unresolved_hostname_does_not_discard_other_targets(self):
        """A DNS failure leaves direct targets and subsequent DNS results usable."""
        hostnames = {}
        with (
            mock.patch.object(
                agent.socket,
                "getaddrinfo",
                side_effect=[
                    agent.socket.gaierror(-2, "Name or service not known"),
                    [(None, None, None, None, ("192.0.2.5", 0))],
                ],
            ),
            self.assertLogs(agent.logger, level="WARNING") as logs,
        ):
            arguments = agent._build_masscan_args(
                {
                    "job": "missing.test,192.0.2.0/31,example.test",
                    "scan_family": "ipv4",
                },
                "/tmp/result.xml",
                "443",
                hostnames,
            )
        self.assertEqual(arguments[:2], ["192.0.2.0/31", "192.0.2.5"])
        self.assertEqual(hostnames, {"192.0.2.5": {"example.test"}})
        self.assertIn("Skipping unresolved Masscan target missing.test", logs.output[0])

    def test_unresolved_job_submits_empty_result_without_scanning(self):
        """Single or multiple DNS failures complete each IP family with no retry."""
        for family in ("ipv4", "ipv6"):
            for targets in ("missing.test", "missing.test,also-missing.test"):
                with (
                    self.subTest(family=family, targets=targets),
                    tempfile.TemporaryDirectory() as temp,
                    mock.patch.dict(
                        agent.CONFIG,
                        {
                            "THIS_DIR": temp,
                            "capabilities": ["masscan"],
                            "botinfo": {},
                            "APIPATH": SimpleNamespace(
                                sndjob="http://controller/result"
                            ),
                        },
                        clear=True,
                    ),
                    mock.patch.object(
                        agent.socket,
                        "getaddrinfo",
                        side_effect=agent.socket.gaierror(
                            -2, "Name or service not known"
                        ),
                    ),
                    mock.patch.object(agent, "run_elf") as scan,
                    mock.patch.object(agent, "nmap_file_to_json") as parse,
                    mock.patch.object(agent, "_release_job") as release,
                    mock.patch.object(agent, "robust_request", return_value={}) as send,
                    self.assertLogs(agent.logger, level="WARNING"),
                ):
                    self.assertTrue(
                        agent.run_scan_job(
                            {
                                "job": targets,
                                "job_uid": self.UID,
                                "attempt_uid": self.ATTEMPT_UID,
                                "scan_tool": "masscan",
                                "scan_family": family,
                                "scan_ports": [443],
                                "detect_protocol": True,
                                "report_target_count": True,
                            }
                        )
                    )
                    scan.assert_not_called()
                    parse.assert_not_called()
                    release.assert_not_called()
                    send.assert_called_once_with(
                        "http://controller/result",
                        method="POST",
                        data={
                            "JOB_UID": self.UID,
                            "ATTEMPT_UID": self.ATTEMPT_UID,
                            "RESULT": "[]",
                            "PORTS_TARGETED": 0,
                        },
                        max_retries=3,
                    )

    def test_ipv6_job_uses_ipv6_source_and_filters_ipv4(self):
        """Resolve IPv6 only and use an IPv6 source and targets."""
        job = {
            "job": "192.0.2.1,2001:db8::1,example.test",
            "scan_family": "ipv6",
            "detect_protocol": True,
        }
        address = (agent.socket.AF_INET6, None, None, None, ("2001:db8::5", 0, 0, 0))
        hostnames = {}
        with (
            mock.patch.dict(
                agent.CONFIG,
                {
                    "masscan_ipv6": True,
                    "masscan_ip_v4": "192.0.2.10",
                    "masscan_ip_v6": "2001:db8::10",
                },
            ),
            mock.patch.object(
                agent.socket, "getaddrinfo", return_value=[address]
            ) as resolve,
        ):
            arguments = agent._build_masscan_args(
                job, "/tmp/result.xml", "443", hostnames
            )
        resolve.assert_called_once_with(
            "example.test",
            None,
            family=agent.socket.AF_INET6,
            type=agent.socket.SOCK_STREAM,
        )
        self.assertEqual(arguments[:2], ["2001:db8::1", "2001:db8::5"])
        self.assertNotIn("192.0.2.1", arguments)
        self.assertEqual(hostnames, {"2001:db8::5": {"example.test"}})
        self.assertEqual(arguments[arguments.index("--source-ip") + 1], "2001:db8::10")

    def test_family_slice_without_matching_targets_is_empty(self):
        """No scanner arguments are produced when the requested family is absent."""
        self.assertEqual(
            agent._build_masscan_args(
                {"job": "192.0.2.1", "scan_family": "ipv6"}, "/tmp/result.xml", "443"
            ),
            [],
        )

    def test_missing_family_is_rejected(self):
        """Do not mix IPv4/IPv6 targets in a job with no family contract."""
        with self.assertRaisesRegex(ValueError, "scan_family"):
            agent._build_masscan_args({"job": "192.0.2.1"}, "/tmp/result.xml", "443")

    def test_banner_jobs_require_a_matching_dedicated_ip(self):
        """Verify banner jobs require a matching dedicated ip."""
        job = {"job": "192.0.2.1", "scan_family": "ipv4", "detect_protocol": True}
        with mock.patch.dict(agent.CONFIG, {"masscan_ip_v4": None}):
            with self.assertRaises(ValueError):
                agent._build_masscan_args(job, "/tmp/output.xml", "443")
            args = agent._build_masscan_args(
                {**job, "detect_protocol": False}, "/tmp/output.xml", "443"
            )
            self.assertNotIn("--source-ip", args)
        with mock.patch.dict(agent.CONFIG, {"masscan_ip_v4": "2001:db8::2"}):
            with self.assertRaises(ValueError):
                agent._build_masscan_args(job, "/tmp/output.xml", "443")

    def test_fqdn_and_ptr_are_reported_only_for_open_resolved_ip(self):
        """Verify fqdn and ptr are reported only for open resolved ip."""
        document = (
            '<nmaprun scanner="masscan">'
            '<host endtime="100"><address addr="62.16.7.109"/><ports>'
            '<port portid="22" protocol="tcp"><state state="open" reason="syn-ack"/>'
            "</port></ports></host>"
            '<host endtime="100"><address addr="62.16.7.110"/><ports>'
            '<port portid="22" protocol="tcp"><state state="closed" reason="reset"/>'
            "</port></ports></host></nmaprun>"
        )
        addresses = [
            (None, None, None, None, ("62.16.7.109", 0)),
            (None, None, None, None, ("62.16.7.110", 0)),
        ]
        sent = {}
        with tempfile.TemporaryDirectory() as temp:

            def run(_executable, arguments, show_output=False, *, job_uid=None):
                """Provide the run test fixture."""
                del show_output, job_uid
                with open(
                    arguments[arguments.index("-oX") + 1], "w", encoding="utf-8"
                ) as handle:
                    handle.write(document)
                return 0

            def send(_url, method, data, max_retries):
                """Provide the send test fixture."""
                del method, max_retries
                if _url == "http://controller/job":
                    return {
                        "message": {
                            "job": "vlan-luxpost.lu",
                            "job_uid": self.UID,
                            "attempt_uid": self.ATTEMPT_UID,
                            "scan_tool": "masscan",
                            "scan_family": "ipv4",
                            "scan_ports": [22],
                        }
                    }
                sent.update(data)
                return {"message": "received"}

            with (
                mock.patch.dict(
                    agent.CONFIG,
                    {
                        "THIS_DIR": temp,
                        "masscan_path": "/usr/bin/masscan",
                        "capabilities": ["masscan"],
                        "debug_mode": "none",
                        "botinfo": {},
                        "APIPATH": SimpleNamespace(
                            getjob="http://controller/job",
                            sndjob="http://controller/result",
                        ),
                    },
                    clear=False,
                ),
                mock.patch.object(agent.socket, "getaddrinfo", return_value=addresses),
                mock.patch.object(
                    agent.socket,
                    "gethostbyaddr",
                    return_value=("62.16.7.109.rev.sfr.net", [], ["62.16.7.109"]),
                ) as reverse,
                mock.patch.object(agent, "run_elf", side_effect=run),
                mock.patch.object(agent, "robust_request", side_effect=send),
            ):
                with mock.patch.object(agent.time, "time", return_value=90.75):
                    job = agent.fetch_job()
                self.assertTrue(agent.run_scan_job(job))
        reverse.assert_called_once_with("62.16.7.109")
        result = json.loads(sent["RESULT"])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["starttime"], "90")
        self.assertEqual(result[0]["endtime"], "100")
        self.assertEqual(
            result[0]["hostnames"],
            [
                {"name": "62.16.7.109.rev.sfr.net", "type": "PTR"},
                {"name": "vlan-luxpost.lu", "type": "user"},
            ],
        )

    def test_missing_ptr_still_keeps_requested_fqdn(self):
        """Verify missing ptr still keeps requested fqdn."""
        with mock.patch.object(agent.socket, "gethostbyaddr", side_effect=OSError):
            self.assertEqual(
                agent._masscan_hostnames_for_open_ip(
                    "192.0.2.1", {"192.0.2.1": {"example.test"}}
                ),
                [{"name": "example.test", "type": "user"}],
            )

    def test_successful_report_is_sent_through_nmap2json(self):
        """Verify successful report is sent through nmap2json."""
        self.enterContext(
            mock.patch.dict(agent.CONFIG, {"masscan_ip_v4": "192.0.2.10"})
        )
        document = (
            '<nmaprun scanner="masscan"><host starttime="80" endtime="100">'
            '<address addr="192.0.2.1"/><ports><port portid="22" protocol="tcp">'
            '<state state="open" reason="syn-ack"/><service name="ssh" banner="SSH-2.0"/>'
            "</port></ports></host></nmaprun>"
        )
        sent = {}
        with tempfile.TemporaryDirectory() as temp:

            def run(_executable, arguments, show_output=False, *, job_uid=None):
                """Provide the run test fixture."""
                del show_output, job_uid
                output = arguments[arguments.index("-oX") + 1]
                with open(output, "w", encoding="utf-8") as handle:
                    handle.write(document)
                return 0

            def send(_url, method, data, max_retries):
                """Provide the send test fixture."""
                del method, max_retries
                sent.update(data)
                return {"message": "received"}

            with (
                mock.patch.dict(
                    agent.CONFIG,
                    {
                        "THIS_DIR": temp,
                        "masscan_path": "/usr/bin/masscan",
                        "capabilities": ["masscan"],
                        "debug_mode": "none",
                        "botinfo": {},
                        "APIPATH": SimpleNamespace(sndjob="http://controller/result"),
                    },
                    clear=False,
                ),
                mock.patch.object(agent, "run_elf", side_effect=run),
                mock.patch.object(agent, "robust_request", side_effect=send),
            ):
                self.assertTrue(
                    agent.run_scan_job(
                        {
                            "job": "192.0.2.1",
                            "job_uid": self.UID,
                            "attempt_uid": self.ATTEMPT_UID,
                            "scan_tool": "masscan",
                            "scan_family": "ipv4",
                            "scan_ports": [22],
                            "detect_protocol": True,
                            "_received_at": "90",
                        }
                    )
                )
        result = json.loads(sent["RESULT"])
        self.assertEqual(sent["ATTEMPT_UID"], self.ATTEMPT_UID)
        self.assertEqual(result[0]["addr"], "192.0.2.1")
        self.assertEqual(result[0]["starttime"], "80")
        self.assertEqual(result[0]["ports"][0]["scripts"][0]["service"], "ssh")

    def test_empty_success_reports_empty_list(self):
        """Verify empty success reports empty list."""
        sent = {}
        with tempfile.TemporaryDirectory() as temp:

            def run(_executable, arguments, show_output=False, *, job_uid=None):
                """Provide the run test fixture."""
                del show_output, job_uid
                open(arguments[arguments.index("-oX") + 1], "wb").close()
                return 0

            def send(_url, method, data, max_retries):
                """Provide the send test fixture."""
                del method, max_retries
                sent.update(data)
                return {"message": "received"}

            with (
                mock.patch.dict(
                    agent.CONFIG,
                    {
                        "THIS_DIR": temp,
                        "masscan_path": "/usr/bin/masscan",
                        "capabilities": ["masscan"],
                        "debug_mode": "none",
                        "botinfo": {},
                        "APIPATH": SimpleNamespace(sndjob="http://controller/result"),
                    },
                    clear=False,
                ),
                mock.patch.object(agent, "run_elf", side_effect=run),
                mock.patch.object(agent, "robust_request", side_effect=send),
            ):
                self.assertTrue(
                    agent.run_scan_job(
                        {
                            "job": "192.0.2.1",
                            "job_uid": self.UID,
                            "attempt_uid": self.ATTEMPT_UID,
                            "scan_tool": "masscan",
                            "scan_family": "ipv4",
                            "scan_ports": [80],
                        }
                    )
                )
        self.assertEqual(json.loads(sent["RESULT"]), [])

    def test_interrupted_scan_returns_whole_job_to_controller(self):
        """Verify interrupted scan returns whole job to controller."""
        calls = []
        with tempfile.TemporaryDirectory() as temp:

            def request(url, method, data, max_retries):
                """Provide the request test fixture."""
                calls.append((url, method, data, max_retries))
                return {"message": "ready"}

            with (
                mock.patch.dict(
                    agent.CONFIG,
                    {
                        "THIS_DIR": temp,
                        "masscan_path": "/usr/bin/masscan",
                        "capabilities": ["masscan"],
                        "debug_mode": "none",
                        "botinfo": {"UID": "agent"},
                        "APIPATH": SimpleNamespace(
                            sndjob="http://controller/result",
                            releasejob="http://controller/release",
                        ),
                    },
                    clear=False,
                ),
                mock.patch.object(agent, "run_elf", return_value=-15),
                mock.patch.object(agent, "robust_request", side_effect=request),
            ):
                self.assertFalse(
                    agent.run_scan_job(
                        {
                            "job": "192.0.2.1",
                            "job_uid": self.UID,
                            "attempt_uid": self.ATTEMPT_UID,
                            "scan_tool": "masscan",
                            "scan_family": "ipv4",
                            "scan_ports": [80],
                        }
                    )
                )
        self.assertEqual(calls[0][0], "http://controller/release")
        self.assertEqual(calls[0][2]["JOB_UID"], self.UID)
        self.assertEqual(calls[0][2]["ATTEMPT_UID"], self.ATTEMPT_UID)


if __name__ == "__main__":
    unittest.main()
