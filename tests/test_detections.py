
import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from detections import detect_repeated_failures


class TestDetections(unittest.TestCase):

    def make_events(
        self,
        count,
        event_type="FAILED_LOGIN",
        ip="192.0.2.10",
        interval_seconds=30,
    ):
        start = datetime(2026, 10, 22, 9, 0, 0)

        return [
            {
                "event": event_type,
                "ip": ip,
                "timestamp": (
                    start + timedelta(seconds=i * interval_seconds)
                ).isoformat(sep=" "),
            }
            for i in range(count)
        ]

    def test_detects_repeated_failures(self):
        alerts = detect_repeated_failures(self.make_events(5))

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["count"], 5)

    def test_ignores_below_threshold(self):
        alerts = detect_repeated_failures(self.make_events(4))

        self.assertEqual(alerts, [])

    def test_ignores_successful_logins(self):
        events = self.make_events(10, event_type="SUCCESSFUL_LOGIN")

        self.assertEqual(detect_repeated_failures(events), [])

    def test_ignores_events_without_ip(self):
        events = self.make_events(5)

        for event in events:
            event["ip"] = None

        self.assertEqual(detect_repeated_failures(events), [])

    def test_ignores_failures_outside_window(self):
        events = self.make_events(5, interval_seconds=120)

        alerts = detect_repeated_failures(
            events, threshold=5, window_minutes=5
        )

        self.assertEqual(alerts, [])

    def test_rejects_invalid_threshold(self):
        with self.assertRaises(ValueError):
            detect_repeated_failures([], threshold=0)

    def test_rejects_negative_window(self):
        with self.assertRaises(ValueError):
            detect_repeated_failures([], window_minutes=-1)
    
    def test_reports_highest_count_in_window(self):
        events = self.make_events(
            8,
            interval_seconds=20,
        )

        alerts = detect_repeated_failures(
            events,
            threshold=5,
            window_minutes=5,
        )

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["count"], 8)


if __name__ == "__main__":
    unittest.main()
