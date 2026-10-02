"""Behavioral checks for agent-managed daily log files."""

import logging
import os
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, SRC_DIR)

import agent  # pylint: disable=wrong-import-position
from utils.logrotation import parse_logrotation  # pylint: disable=wrong-import-position


class FixedDatetime(datetime):
    """Clock controlled by each test without sleeping until midnight."""

    current = datetime(2026, 10, 1)

    @classmethod
    def now(cls, tz=None):
        """Return current test date."""
        _ = tz
        return cls.current


class DailyLogRotationTests(unittest.TestCase):
    """Verify rotation and retention without external logrotate."""

    def test_daily_rollover_and_retention(self):
        """Keep two days of logs and leave unrelated files alone."""
        with tempfile.TemporaryDirectory() as directory:
            log_dir = Path(directory)
            (log_dir / "agent-260929.log").write_text("old\n", encoding="utf-8")
            (log_dir / "agent-260930.log").write_text("recent\n", encoding="utf-8")
            (log_dir / "notes.log").write_text("keep\n", encoding="utf-8")

            with mock.patch.object(agent, "datetime", FixedDatetime):
                FixedDatetime.current = datetime(2026, 10, 1)
                handler = agent.DailyLogFileHandler(directory, keep_days=2)
                try:
                    self.assertFalse((log_dir / "agent-260929.log").exists())
                    self.assertTrue((log_dir / "agent-260930.log").exists())

                    handler.emit(
                        logging.LogRecord(
                            "test", logging.INFO, __file__, 1, "day 1", (), None
                        )
                    )
                    FixedDatetime.current = datetime(2026, 10, 2)
                    handler.emit(
                        logging.LogRecord(
                            "test", logging.INFO, __file__, 1, "day 2", (), None
                        )
                    )

                    self.assertFalse((log_dir / "agent-260930.log").exists())
                    self.assertIn(
                        "day 1",
                        (log_dir / "agent-261001.log").read_text(encoding="utf-8"),
                    )
                    self.assertIn(
                        "day 2",
                        (log_dir / "agent-261002.log").read_text(encoding="utf-8"),
                    )
                    self.assertTrue((log_dir / "notes.log").exists())
                finally:
                    handler.close()

    def test_retention_setting(self):
        """Default to 30 days and reject non-positive retention."""
        self.assertEqual(parse_logrotation(None), 30)
        self.assertEqual(parse_logrotation("7"), 7)
        for value in (0, -1, True, "invalid"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_logrotation(value)


if __name__ == "__main__":
    unittest.main()
