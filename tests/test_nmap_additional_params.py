"""Tests for profile-level Nmap argument handling."""

import os
import sys
import unittest
from unittest import mock

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, SRC_DIR)

import agent  # pylint: disable=wrong-import-position


class NmapAdditionalParamsTests(unittest.TestCase):
    """Verify safe parsing, defaults, and overrides."""

    def _build_args(self, value=...):
        job_message = {"job": "example.test,192.0.2.1"}
        if value is not ...:
            job_message["nmap_additional_params"] = value
        return agent._build_nmap_args(  # pylint: disable=protected-access
            job_message,
            "/tmp/result.xml",
            "80,443",
            ["tls-alpn.nse"],
        )

    @staticmethod
    def _option_value(arguments, option):
        for index, argument in enumerate(arguments):
            if argument == option:
                return arguments[index + 1]
            if argument.startswith(f"{option}="):
                return argument.split("=", 1)[1]
        return None

    def test_missing_null_and_empty_values_keep_defaults(self):
        """Legacy and empty payloads retain current defaults."""
        for value in (..., None, "", "   "):
            with self.subTest(value=value):
                arguments = self._build_args(value)
                self.assertEqual(self._option_value(arguments, "--host-timeout"), "40s")
                self.assertEqual(
                    self._option_value(arguments, "--min-hostgroup"), "256"
                )

    def test_valid_multi_token_params_are_preserved(self):
        """Quoted values become individual argv items."""
        arguments = self._build_args('--min-rate 100 --script-args "key=value one"')
        self.assertIn("--min-rate", arguments)
        self.assertIn("100", arguments)
        self.assertIn("--script-args", arguments)
        self.assertIn("key=value one", arguments)

    def test_separate_value_options_override_defaults(self):
        """Separate profile values replace duplicate defaults."""
        arguments = self._build_args("--min-hostgroup 32 --host-timeout 5m")
        self.assertEqual(self._option_value(arguments, "--min-hostgroup"), "32")
        self.assertEqual(self._option_value(arguments, "--host-timeout"), "5m")
        self.assertNotIn("256", arguments)
        self.assertNotIn("40s", arguments)

    def test_equals_option_overrides_default(self):
        """Equals-form profile values replace duplicate defaults."""
        arguments = self._build_args("--host-timeout=5m")
        self.assertIn("--host-timeout=5m", arguments)
        self.assertNotIn("40s", arguments)

    def test_agent_managed_arguments_remain_present(self):
        """Extra parameters do not disturb ports, NSE, output, or targets."""
        arguments = self._build_args("-sV")
        self.assertEqual(self._option_value(arguments, "-p"), "80,443")
        self.assertEqual(self._option_value(arguments, "-oX"), "/tmp/result.xml")
        self.assertEqual(self._option_value(arguments, "--script"), "tls-alpn.nse")
        self.assertEqual(arguments[-2:], ["example.test", "192.0.2.1"])

    def test_command_formatter_shell_quotes_exact_argv(self):
        """Logged command is a reversible representation of exact argv."""
        command = agent._format_command_for_log(  # pylint: disable=protected-access
            "/opt/Nmap Tools/nmap",
            ["--script-args", "key=value one", "target name"],
        )
        self.assertEqual(
            command,
            "'/opt/Nmap Tools/nmap' --script-args 'key=value one' 'target name'",
        )

    def test_info_preview_truncates_and_debug_logs_full_command(self):
        """INFO is bounded while DEBUG has exact final argv before execution."""
        long_targets = ",".join(f"host-{index:03d}.example.test" for index in range(40))
        job_message = {
            "job": long_targets,
            "job_uid": "f5813ec7-b36b-4fe7-b662-cca3d281725c",
            "nmap_ports": [80, 443],
            "nmap_nse": ["script path.nse"],
            "nmap_additional_params": '--script-args "key=value one"',
        }
        messages_seen_at_execution = []
        executed_args = []

        with mock.patch.dict(
            agent.CONFIG, {"nmap_path": "/opt/Nmap Tools/nmap"}, clear=False
        ):
            with self.assertLogs(agent.logger, level="DEBUG") as captured:

                def fake_run_elf(executable, arguments):
                    executed_args.extend([executable, *arguments])
                    messages_seen_at_execution.extend(captured.output)
                    return -1

                with mock.patch.object(agent, "run_elf", side_effect=fake_run_elf):
                    self.assertFalse(agent.run_scan_job(job_message))

        full_command = (
            agent._format_command_for_log(  # pylint: disable=protected-access
                executed_args[0], executed_args[1:]
            )
        )
        info_preview = (
            agent._truncate_command_for_info_log(  # pylint: disable=protected-access
                full_command
            )
        )
        self.assertEqual(len(info_preview), agent.MAX_INFO_NMAP_COMMAND_LENGTH)
        self.assertIn("... [truncated,", info_preview)
        self.assertIn(
            f"INFO:Plum_Agent:Job f5813ec7...725c Nmap command: {info_preview}",
            messages_seen_at_execution,
        )
        self.assertIn(
            f"DEBUG:Plum_Agent:Job f5813ec7...725c full Nmap command: {full_command}",
            messages_seen_at_execution,
        )
        self.assertIn("--script-args 'key=value one'", full_command)
        self.assertIn("--script 'script path.nse'", full_command)
        self.assertTrue(full_command.endswith("host-039.example.test"))

    def test_shell_control_syntax_is_rejected(self):
        """Shell metacharacters and control syntax fail before execution."""
        unsafe_values = [
            "-sV; id",
            "-sV && id",
            "-sV | id",
            "-sV > output",
            "-sV `id`",
            "-sV $(id)",
            "-sV\nid",
        ]
        for value in unsafe_values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self._build_args(value)

    @mock.patch.object(agent, "run_elf")
    def test_invalid_params_stop_before_nmap(self, run_elf_mock):
        """Rejected parameters never reach process execution."""
        job_message = {
            "job": "example.test",
            "job_uid": "f5813ec7-b36b-4fe7-b662-cca3d281725c",
            "nmap_ports": [80, 443],
            "nmap_additional_params": "-sV; id",
        }

        self.assertFalse(agent.run_scan_job(job_message))
        run_elf_mock.assert_not_called()

    def test_malformed_and_reserved_params_are_rejected(self):
        """Malformed quoting and agent-managed options fail validation."""
        invalid_values = [
            "--script-args 'unterminated",
            "--host-timeout",
            "--host-timeout=",
            "-p 22",
            "-oX other.xml",
            "--script intrusive.nse",
            "--",
            "x" * 4097,
            ["-sV"],
        ]
        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    self._build_args(value)


if __name__ == "__main__":
    unittest.main()
