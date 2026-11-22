"""Regression test for configuration-only startup."""

import json
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from utils import netutils, setup


class SetupModeTest(unittest.TestCase):
    """Regression checks for setup mode test."""

    def test_dedicated_masscan_ip_rejects_kernel_address(self):
        """Verify dedicated masscan ip rejects kernel address."""
        with patch.object(setup.subprocess, "run") as run:
            run.return_value.stdout = '[{"addr_info":[{"local":"192.0.2.10"}]}]'
            with self.assertRaises(ValueError):
                setup.validate_masscan_ip("192.0.2.10")
            self.assertEqual(setup.validate_masscan_ip("192.0.2.11"), "192.0.2.11")
        for address in ("garbage", "127.0.0.1", "224.0.0.1", "0.0.0.0"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                setup.validate_masscan_ip(address)

    def test_invalid_disabled_flags_stop_before_discovery_or_registration(self):
        """Verify invalid disabled flags stop before discovery or registration."""
        args = Namespace(setup=False, island=None, agentkey=None, ipext=None)
        for value in ("false", 0, None):
            with (
                self.subTest(value=value),
                patch.object(setup, "locate_elf") as locate,
                patch.object(setup, "get_ext_ip") as external_ip,
                patch.object(setup, "robust_request") as request,
            ):
                with (
                    self.assertLogs("Plum_Agent", level="ERROR") as logs,
                    self.assertRaises(SystemExit) as error,
                ):
                    setup.setup(
                        {"nmap_disabled": value, "masscan_disabled": True}, args
                    )
                self.assertEqual(error.exception.code, 1)
                self.assertIn("nmap_disabled", logs.output[0])
                locate.assert_not_called()
                external_ip.assert_not_called()
                request.assert_not_called()

    def test_masscan_only_agent_registers_capability(self):
        """Verify masscan only agent registers capability."""
        args = Namespace(
            setup=False,
            island=None,
            agentkey=None,
            ipext=None,
            scanparallel=None,
            logrotation=None,
            scanhours=None,
        )
        config = {
            "uid": "test-agent",
            "ext_ip": "192.0.2.1",
            "island": "https://example.invalid",
            "agent_key": "test-only",
            "nmap_disabled": True,
        }
        with (
            patch.object(setup, "locate_elf", return_value=(True, "/usr/bin/masscan")),
            patch.object(setup, "_masscan_has_raw_socket_access", return_value=True),
            patch.object(setup, "_masscan_supports_ipv6", return_value=False),
            patch.object(
                setup,
                "robust_request",
                side_effect=({"tool_inventory": True}, {"message": "ready"}),
            ) as request,
        ):
            result = setup.setup(config, args)
        self.assertEqual(result["capabilities"], ["masscan"])
        self.assertEqual(request.call_args.kwargs["data"]["capabilities"], ["masscan"])
        self.assertNotIn("capabilities", result["botinfo"])

    def test_legacy_island_registers_nmap_without_inventory_or_masscan_checks(self):
        """Verify legacy island registers nmap without inventory or masscan checks."""
        args = Namespace(setup=False)
        for missing_status in (404, 405):
            config = {
                "uid": "test-agent",
                "ext_ip": "192.0.2.1",
                "island": "https://example.invalid",
                "agent_key": "test-only",
                "masscan_path": "/previous/masscan",
            }
            with (
                self.subTest(status=missing_status),
                patch.object(netutils.requests, "get") as get,
                patch.object(netutils.requests, "post") as post,
                patch.object(netutils.time, "sleep") as sleep,
                patch.object(
                    setup, "locate_elf", return_value=(True, "/test/nmap")
                ) as locate,
                patch.object(setup, "_masscan_has_raw_socket_access") as raw_access,
            ):
                get.return_value.status_code = missing_status
                post.return_value.status_code = 200
                post.return_value.json.return_value = {"message": "ready"}
                result = setup.setup(config, args)
                get.assert_called_once()
                post.assert_called_once()
                sleep.assert_not_called()
                locate.assert_called_once_with("nmap")
                raw_access.assert_not_called()
                self.assertEqual(result["capabilities"], ["nmap"])
                self.assertNotIn("masscan_path", result)
                payload = json.loads(post.call_args.kwargs["json"])
                self.assertNotIn("capabilities", payload)
                self.assertEqual(payload["UID"], "test-agent")
                self.assertEqual(payload["AGENT_KEY"], "test-only")

    def test_legacy_island_does_not_override_disabled_nmap(self):
        """Verify legacy island does not override disabled nmap."""
        config = {
            "uid": "test-agent",
            "ext_ip": "192.0.2.1",
            "island": "https://example.invalid",
            "agent_key": "test-only",
            "nmap_disabled": True,
        }
        with (
            patch.object(
                setup, "robust_request", side_effect=netutils.EndpointUnavailable
            ) as request,
            patch.object(setup, "locate_elf") as locate,
            self.assertLogs("Plum_Agent", level="ERROR") as logs,
            self.assertRaises(SystemExit) as error,
        ):
            setup.setup(config, Namespace(setup=False))
        self.assertEqual(error.exception.code, 1)
        self.assertIn("Legacy Island requires Nmap", logs.output[0])
        request.assert_called_once()
        locate.assert_not_called()

    def test_protocol_failure_does_not_send_legacy_beacon(self):
        """Verify protocol failure does not send legacy beacon."""
        config = {"island": "https://example.invalid", "agent_key": "test-only"}
        with (
            patch.object(netutils.requests, "get") as get,
            patch.object(netutils.requests, "post") as post,
            patch.object(netutils.time, "sleep"),
            self.assertRaises(SystemExit) as error,
        ):
            get.return_value.status_code = 403
            setup.setup(config, Namespace(setup=False))
        self.assertEqual(error.exception.code, 5)
        post.assert_not_called()

    def test_debug_logs_omit_agent_key(self):
        """Verify debug logs omit agent key."""
        secret = "synthetic-credential-for-logs-test"
        with (
            tempfile.TemporaryDirectory() as temp,
            patch.object(netutils.requests, "post") as post,
            self.assertLogs("Plum_Agent", level="DEBUG") as logs,
        ):
            (Path(temp) / "config").mkdir()
            setup.save_config({"THIS_DIR": temp, "agent_key": secret})
            post.return_value.status_code = 200
            post.return_value.text = secret
            post.return_value.json.return_value = {"message": "ready"}
            reply = netutils.robust_request(
                "https://example.invalid", method="POST", data={"AGENT_KEY": secret}
            )
            self.assertEqual(reply, {"message": "ready"})
        self.assertNotIn(secret, "\n".join(logs.output))

    def test_setup_only_skips_disabled_binary(self):
        """Verify setup only skips disabled binary."""
        args = Namespace(setup=True, island=None, agentkey=None, ipext=None)
        config = {
            "uid": "test-agent",
            "ext_ip": "192.0.2.1",
            "island": "https://example.invalid",
            "agent_key": "test-only",
            "nmap_disabled": True,
            "masscan_disabled": True,
            "nmap_path": "/previous/nmap",
        }
        with (
            patch.object(setup, "locate_elf") as locate,
            patch.object(setup, "robust_request") as request,
        ):
            self.assertIs(setup.setup(config, args), config)
        locate.assert_not_called()
        request.assert_not_called()
        self.assertNotIn("nmap_path", config)

    def test_returns_config_without_registering(self):
        """Verify returns config without registering."""
        args = Namespace(setup=True, island=None, agentkey=None, ipext=None)
        config = {
            "uid": "test-agent",
            "ext_ip": "192.0.2.1",
            "island": "https://example.invalid",
            "agent_key": "test-only",
            "logrotation": "7",
        }
        with (
            patch.object(
                setup,
                "locate_elf",
                side_effect=((True, "/test/nmap"), (False, None)),
            ),
            patch.object(setup, "robust_request") as register,
        ):
            result = setup.setup(config, args)
        register.assert_not_called()
        self.assertIs(result, config)
        self.assertEqual(result["logrotation"], 7)
