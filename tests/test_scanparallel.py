"""Per-scanner concurrency and setup regression checks."""

import sys
import unittest
from argparse import Namespace
from concurrent.futures import Future
from pathlib import Path
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import agent
from utils import setup
from utils.scanparallel import scanner_parallel_limits


class ParallelTests(unittest.TestCase):
    def test_defaults_and_invalid_limits(self):
        self.assertEqual(scanner_parallel_limits({}), {"nmap": 1, "masscan": 1})
        self.assertEqual(
            scanner_parallel_limits({"scanparallel": 1, "masscan_scanparallel": 4}),
            {"nmap": 1, "masscan": 4},
        )
        self.assertEqual(
            scanner_parallel_limits({"scanparallel": 0, "nmap_scanparallel": 3}),
            {"nmap": 3, "masscan": 0},
        )
        self.assertEqual(
            scanner_parallel_limits({"scanparallel": 4}), {"nmap": 4, "masscan": 4}
        )
        for value in (0, -1, True, 1.5, "bad"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                scanner_parallel_limits({"masscan_scanparallel": value})

    def test_setup_cli_overrides_yaml_and_saves(self):
        config = dict(
            uid="test",
            ext_ip="192.0.2.1",
            island="https://example.invalid",
            agent_key="test-only",
            nmap_disabled=True,
            masscan_disabled=True,
            scanparallel=4,
            nmap_scanparallel=4,
            masscan_scanparallel=3,
        )
        with (
            patch.object(setup, "save_config") as save,
            patch.object(setup, "robust_request") as request,
        ):
            result = setup.setup(
                config,
                Namespace(setup=True, nmap_scanparallel="3", masscan_scanparallel="1"),
            )
        self.assertEqual(result["nmap_scanparallel"], 3)
        self.assertEqual(result["masscan_scanparallel"], 1)
        save.assert_called()
        request.assert_not_called()

    def test_specific_limits_exceed_default_and_combine(self):
        jobs = [
            dict(job_uid=str(i), scan_tool=tool)
            for i, tool in enumerate(("nmap", "nmap", "masscan", "masscan", "masscan"))
        ]
        executor = Mock()
        executor.submit.side_effect = lambda *_args: Future()
        with (
            patch.dict(
                agent.CONFIG,
                {"scanparallel": 1, "nmap_scanparallel": 2, "masscan_scanparallel": 3},
            ),
            patch.object(agent, "ThreadPoolExecutor", return_value=executor) as pool,
            patch.object(agent, "_scanhours_enabled", return_value=True),
            patch.object(agent, "fetch_job", side_effect=jobs) as fetch,
            patch.object(
                agent, "_wait_for_worker_or_sleep", side_effect=KeyboardInterrupt
            ),
            patch.object(agent, "terminate_running_elfs"),
            self.assertRaises(KeyboardInterrupt),
        ):
            agent._run_daemon_loop(1)
        pool.assert_called_once_with(max_workers=5)
        self.assertEqual(executor.submit.call_count, 5)
        self.assertEqual(fetch.call_count, 5)

    def test_pending_job_runs_after_a_slot_is_freed(self):
        futures = []

        def submit(_func, job):
            future = Future()
            futures.append((future, job))
            return future

        def finish(running, _delay):
            for future in list(running):
                future.set_result(True)
            agent._drain_finished_jobs(running)

        jobs = [dict(job_uid=str(i), scan_tool="masscan") for i in range(2)]
        executor = Mock()
        executor.submit.side_effect = submit
        with (
            patch.dict(agent.CONFIG, {"scanparallel": 3, "masscan_scanparallel": 1}),
            patch.object(agent, "ThreadPoolExecutor", return_value=executor),
            patch.object(agent, "_scanhours_enabled", return_value=True),
            patch.object(agent, "fetch_job", side_effect=[*jobs, KeyboardInterrupt]),
            patch.object(agent, "_wait_for_worker_or_sleep", side_effect=finish),
            patch.object(agent, "terminate_running_elfs"),
            patch.object(agent, "_release_job") as release,
            self.assertRaises(KeyboardInterrupt),
        ):
            agent._run_daemon_loop(3)
        self.assertEqual([job for _, job in futures], jobs)
        self.assertTrue(futures[0][0].done())
        release.assert_not_called()

    def test_scheduler_enforces_each_limit_and_releases_pending_on_stop(self):
        for limited in ("nmap", "masscan"):
            other = "masscan" if limited == "nmap" else "nmap"
            jobs = [
                dict(job_uid=str(i), attempt_uid="attempt", scan_tool=tool)
                for i, tool in enumerate((limited, other, limited))
            ]
            futures = []

            def submit(_func, job):
                future = Future()
                futures.append((future, job))
                return future

            executor = Mock()
            executor.submit.side_effect = submit
            with (
                self.subTest(limited=limited),
                patch.dict(
                    agent.CONFIG,
                    {
                        "scanparallel": 4,
                        f"{limited}_scanparallel": 1,
                        f"{other}_scanparallel": 2,
                    },
                ),
                patch.object(agent, "ThreadPoolExecutor", return_value=executor),
                patch.object(agent, "_scanhours_enabled", return_value=True),
                patch.object(agent, "fetch_job", side_effect=jobs) as fetch,
                patch.object(
                    agent, "_wait_for_worker_or_sleep", side_effect=KeyboardInterrupt
                ),
                patch.object(agent, "terminate_running_elfs"),
                patch.object(agent, "_release_job") as release,
                self.assertRaises(KeyboardInterrupt),
            ):
                agent._run_daemon_loop(4)
            self.assertEqual([job["scan_tool"] for _, job in futures], [limited, other])
            self.assertEqual(fetch.call_count, 3)
            release.assert_called_once_with("2", "attempt")


if __name__ == "__main__":
    unittest.main()
