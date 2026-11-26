"""Verify YAML/CLI mode selection and Nmap output visibility."""

import io
import logging
import os
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, SRC_DIR)

import agent  # pylint: disable=wrong-import-position
from utils import mutils  # pylint: disable=wrong-import-position


class DebugModeTests(unittest.TestCase):
    def setUp(self):
        """Keep Nmap tests independent of the local agent's enabled scanners."""
        self.enterContext(mock.patch.dict(agent.CONFIG, {"capabilities": ["nmap"]}))

    def test_quiet_setup_still_shows_warnings(self):
        """Setup warnings remain visible with default debug:none."""
        self.addCleanup(agent.logger.setLevel, agent.logger.level)
        self.addCleanup(mutils.scanner_logger.setLevel, mutils.scanner_logger.level)
        stream = io.StringIO()
        with mock.patch.object(
            agent.logger, "handlers", [logging.StreamHandler(stream)]
        ):
            agent.configure_log_levels("none", setup_mode=True)
            agent.logger.info("setup info")
            agent.logger.warning("setup warning")
            agent.logger.error("setup error")
        self.assertEqual(
            stream.getvalue().splitlines(),
            ["setup info", "setup warning", "setup error"],
        )

    def test_cli_mode_overrides_yaml(self):
        for yaml_mode, cli_count, expected in (
            (None, 0, "none"),
            ("none", 0, "none"),
            ("info", 0, "info"),
            ("debug", 0, "debug"),
            ("debug", 1, "scanner"),
            ("none", 2, "debug"),
            ("none", 3, "debug"),
            (False, 0, "none"),
            (True, 0, "debug"),
        ):
            with self.subTest(yaml_mode=yaml_mode, cli_count=cli_count):
                self.assertEqual(
                    agent.resolve_debug_mode(yaml_mode, cli_count), expected
                )

        with self.assertRaises(ValueError):
            agent.resolve_debug_mode("verbose")

    def test_runtime_log_levels_separate_scanner_and_agent_output(self):
        self.addCleanup(agent.logger.setLevel, agent.logger.level)
        self.addCleanup(mutils.scanner_logger.setLevel, mutils.scanner_logger.level)
        for mode, expected in (
            ("none", ["agent info", "agent error", "scanner warning", "scanner error"]),
            ("info", ["agent info", "agent error", "scanner warning", "scanner error"]),
            (
                "scanner",
                [
                    "agent info",
                    "agent error",
                    "scanner warning",
                    "scanner error",
                ],
            ),
            (
                "debug",
                [
                    "agent info",
                    "agent debug",
                    "agent error",
                    "scanner debug",
                    "scanner warning",
                    "scanner error",
                ],
            ),
        ):
            with self.subTest(mode=mode):
                stream = io.StringIO()
                handler = logging.StreamHandler(stream)
                with mock.patch.object(agent.logger, "handlers", [handler]):
                    agent.configure_log_levels(mode)
                    agent.logger.info("agent info")
                    agent.logger.debug("agent debug")
                    agent.logger.error("agent error")
                    mutils.scanner_logger.debug("scanner debug")
                    mutils.scanner_logger.warning("scanner warning")
                    mutils.scanner_logger.error("scanner error")
                self.assertEqual(stream.getvalue().splitlines(), expected)

    def test_normal_mode_runs_scanner_with_output_hidden(self):
        job = {
            "job": "example.test",
            "job_uid": "f5813ec7-b36b-4fe7-b662-cca3d281725c",
            "nmap_ports": [80],
        }
        with mock.patch.dict(
            agent.CONFIG,
            {
                "nmap_path": "/usr/bin/nmap",
                "debug_mode": "none",
                "APIPATH": SimpleNamespace(sndjob="http://controller/result"),
            },
        ):
            with mock.patch.object(agent, "run_elf", return_value=0) as runner:
                with mock.patch.object(agent.os.path, "isfile", return_value=True):
                    with mock.patch.object(agent, "nmap_file_to_json", return_value={}):
                        with mock.patch.object(agent.os, "remove"):
                            with mock.patch.object(
                                agent, "robust_request", return_value={}
                            ):
                                self.assertTrue(agent.run_scan_job(job))

        runner.assert_called_once()
        self.assertFalse(runner.call_args.kwargs["show_output"])
        self.assertEqual(runner.call_args.kwargs["job_uid"], "f5813ec7...725c")

    def test_info_shows_command_and_nmap_progress(self):
        job = {
            "job": "example.test",
            "job_uid": "f5813ec7-b36b-4fe7-b662-cca3d281725c",
            "nmap_ports": [80],
        }
        with mock.patch.dict(
            agent.CONFIG, {"nmap_path": "/usr/bin/nmap", "debug_mode": "info"}
        ):
            with mock.patch.object(agent, "run_elf", return_value=-1) as runner:
                with self.assertLogs(agent.logger, level="INFO") as captured:
                    self.assertFalse(agent.run_scan_job(job))

        self.assertIn("Nmap command:", "\n".join(captured.output))
        arguments = runner.call_args.args[1]
        self.assertIn("-v", arguments)
        self.assertNotIn("--script-trace", arguments)
        self.assertTrue(runner.call_args.kwargs["show_output"])

    def test_scanner_mode_streams_nmap_without_script_trace(self):
        job = {
            "job": "example.test",
            "job_uid": "f5813ec7-b36b-4fe7-b662-cca3d281725c",
            "nmap_ports": [80],
        }
        mode = agent.resolve_debug_mode("none", cli_verbosity=1)
        with mock.patch.dict(
            agent.CONFIG, {"nmap_path": "/usr/bin/nmap", "debug_mode": mode}
        ):
            with mock.patch.object(agent, "run_elf", return_value=-1) as runner:
                with mock.patch.object(agent, "_release_job"):
                    self.assertFalse(agent.run_scan_job(job))

        self.assertTrue(runner.call_args.kwargs["show_output"])
        self.assertIn("-v", runner.call_args.args[1])
        self.assertNotIn("--script-trace", runner.call_args.args[1])

    def test_debug_adds_nmap_verbose_flags(self):
        job = {"job": "example.test"}
        with mock.patch.dict(agent.CONFIG, {"debug_mode": "debug"}):
            arguments = agent._build_nmap_args(  # pylint: disable=protected-access
                job, "/tmp/result.xml", "80", []
            )
        self.assertIn("-v", arguments)
        self.assertIn("--script-trace", arguments)
        self.assertIn("-d", arguments)

    def test_masscan_debug_flags_only_in_debug_mode(self):
        for mode in ("none", "info", "scanner", "debug"):
            with self.subTest(mode=mode), mock.patch.dict(
                agent.CONFIG, {"debug_mode": mode}
            ):
                arguments = agent._build_masscan_args(
                    {"job": "192.0.2.1", "scan_family": "ipv4"}, "/tmp/result.xml", "80"
                )
                self.assertEqual("-vv" in arguments, mode == "debug")

    def test_scanner_progress_uses_info_with_single_v(self):
        self.addCleanup(agent.logger.setLevel, agent.logger.level)
        self.addCleanup(mutils.scanner_logger.setLevel, mutils.scanner_logger.level)
        agent.configure_log_levels("scanner")
        with self.assertLogs(mutils.scanner_logger, level="INFO") as captured:
            self.assertEqual(
                mutils.run_elf(sys.executable, ["-c", "print('scan progress')"]), 0
            )
        self.assertEqual(
            [(r.levelname, r.getMessage()) for r in captured.records],
            [("INFO", "scan progress")],
        )

    def test_process_output_is_drained_and_only_logged_when_enabled(self):
        script = (
            "import sys; print('Starting Nmap'); "
            "sys.stderr.write('Starting masscan\\n"
            "rate:  0.00-kpps, 100.00% done, waiting 2-secs, found=1\\r   \\r')"
        )
        with self.assertNoLogs(mutils.logger, level="DEBUG"):
            self.assertEqual(
                mutils.run_elf(sys.executable, ["-c", script], show_output=False), 0
            )

        with self.assertLogs(mutils.logger, level="DEBUG") as captured:
            self.assertEqual(mutils.run_elf(sys.executable, ["-c", script]), 0)
        self.assertCountEqual(
            [(record.levelname, record.getMessage()) for record in captured.records],
            [
                ("DEBUG", "Starting Nmap"),
                ("DEBUG", "Starting masscan"),
                ("DEBUG", "rate:  0.00-kpps, 100.00% done, waiting 2-secs, found=1"),
            ],
        )

    def test_failed_scanner_preserves_stderr_in_quiet_mode(self):
        script = (
            "import sys; "
            "sys.stderr.write('Starting masscan\\n"
            "pcap_open_live: Permission denied\\n"
            "[-] FAIL: adapter could not be opened\\n"
            "rate: 0.00-kpps, 100.00% done, waiting 1-secs, found=0\\r'); "
            "sys.exit(2)"
        )
        with self.assertLogs(mutils.logger, level="INFO") as captured:
            self.assertEqual(
                mutils.run_elf(
                    sys.executable, ["-c", script], show_output=False, job_uid="scan-1"
                ),
                2,
            )
        self.assertEqual(
            [record.levelname for record in captured.records], ["ERROR"] * 2
        )
        messages = [record.getMessage() for record in captured.records]
        self.assertIn("Job scan-1", messages[0])
        self.assertIn("FAIL: adapter could not be opened", messages[0])
        self.assertIn("stderr (exit 2): pcap_open_live: Permission denied", messages[1])

    def test_explicit_scanner_diagnostics_keep_severity_and_escape_output(self):
        stderr = (
            "\x1b[33mWARNING: DNS unavailable\x1b[0m\n"
            "\x1b]0;terminal title\x07ERROR: <target>\u2028" + "x" * 200 + "\n"
        )
        script = f"import sys; sys.stderr.write({stderr!r})"
        with self.assertLogs(mutils.logger, level="INFO") as captured:
            self.assertEqual(
                mutils.run_elf(sys.executable, ["-c", script], show_output=False), 0
            )
        warning, error = captured.records
        self.assertEqual(warning.levelname, "WARNING")
        self.assertTrue(warning.getMessage().endswith("WARNING: DNS unavailable"))
        self.assertEqual(error.levelname, "ERROR")
        message = error.getMessage().split(": ", 1)[1]
        self.assertTrue(message.startswith("ERROR: &lt;target&gt;"))
        self.assertEqual(len(message), 100)
        self.assertNotIn("\u2028", message)


if __name__ == "__main__":
    unittest.main()
