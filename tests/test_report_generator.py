
import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from report_generator import save_report


class TestReportGenerator(unittest.TestCase):

    def test_creates_valid_json_report(self):
        events = [
            {"event": "FAILED_LOGIN", "ip": "192.0.2.10"}
        ]
        alerts = [
            {
                "type": "REPEATED_FAILED_LOGINS",
                "ip": "192.0.2.10",
                "count": 5,
                "window_minutes": 5,
                "severity": "MEDIUM",
                "message": "Repeated failed SSH login attempts."
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "report.json"

            result = save_report(
                events, 2, alerts, output_path
            )

            self.assertTrue(result.is_file())

            with result.open("r", encoding="utf-8") as file:
                report = json.load(file)

            self.assertEqual(
                report["summary"]["parsed_events"], 1
            )
            self.assertEqual(
                report["summary"]["rejected_lines"], 2
            )
            self.assertEqual(
                report["summary"]["alerts_generated"], 1
            )
            self.assertEqual(len(report["alerts"]), 1)
            self.assertIn("generated_at", report)


if __name__ == "__main__":
    unittest.main()
