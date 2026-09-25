"""Verify YAML/CLI mode selection and Nmap output visibility."""

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
    def test_cli_mode_overrides_yaml(self):
        for yaml_mode, cli_count, expected in (
            (None, 0, "none"),
            ("none", 0, "none"),
            ("info", 0, "info"),
            ("debug", 0, "debug"),
            ("debug", 1, "info"),
            ("none", 2, "debug"),
            (False, 0, "none"),
            (True, 0, "debug"),
        ):
            with self.subTest(yaml_mode=yaml_mode, cli_count=cli_count):
                self.assertEqual(
                    agent.resolve_debug_mode(yaml_mode, cli_count), expected
                )

        with self.assertRaises(ValueError):
            agent.resolve_debug_mode("verbose")

    def test_normal_mode_logs_scan_start_without_command_or_nmap_output(self):
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
                            with mock.patch.object(agent, "robust_request", return_value={}):
                                with self.assertLogs(agent.logger, level="INFO") as captured:
                                    self.assertTrue(agent.run_scan_job(job))

        output = "\n".join(captured.output)
        self.assertIn("scan started target=example.test", output)
        self.assertIn("scan completed target=example.test", output)
        self.assertNotIn("Nmap command:", output)
        runner.assert_called_once()
        self.assertFalse(runner.call_args.kwargs["show_output"])

    def test_info_shows_command_without_nmap_verbose_flags(self):
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
        self.assertNotIn("-v", arguments)
        self.assertNotIn("-script-trace", arguments)
        self.assertTrue(runner.call_args.kwargs["show_output"])

    def test_debug_adds_nmap_verbose_flags(self):
        job = {"job": "example.test"}
        with mock.patch.dict(agent.CONFIG, {"debug_mode": "debug"}):
            arguments = agent._build_nmap_args(  # pylint: disable=protected-access
                job, "/tmp/result.xml", "80", []
            )
        self.assertIn("-v", arguments)
        self.assertIn("-script-trace", arguments)

    def test_process_output_is_drained_and_only_logged_when_enabled(self):
        script = (
            "import sys; print('stdout marker'); "
            "print('stderr marker', file=sys.stderr)"
        )
        with mock.patch.object(mutils.logger, "info") as info_log:
            with mock.patch.object(mutils.logger, "error") as error_log:
                self.assertEqual(
                    mutils.run_elf(sys.executable, ["-c", script], show_output=False),
                    0,
                )
                info_log.assert_not_called()
                error_log.assert_not_called()

                self.assertEqual(
                    mutils.run_elf(sys.executable, ["-c", script], show_output=True),
                    0,
                )
                info_log.assert_called_once_with("stdout marker")
                error_log.assert_called_once_with("stderr marker")


if __name__ == "__main__":
    unittest.main()
