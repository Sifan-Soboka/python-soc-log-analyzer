
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from log_parser import parse_log_line


class TestLogParser(unittest.TestCase):

    def test_failed_password(self):
        line = (
            "Dec 10 06:55:48 LabSZ sshd[24200]: "
            "Failed password for invalid user webmaster "
            "from 173.234.31.186 port 38926 ssh2"
        )

        result = parse_log_line(line)

        self.assertEqual(result["event"], "FAILED_LOGIN")
        self.assertEqual(result["username"], "webmaster")
        self.assertEqual(result["ip"], "173.234.31.186")

    def test_invalid_user(self):
        line = (
            "Dec 10 06:55:46 LabSZ sshd[24200]: "
            "Invalid user webmaster from 173.234.31.186"
        )

        result = parse_log_line(line)

        self.assertEqual(result["event"], "INVALID_USER")
        self.assertEqual(result["username"], "webmaster")

    def test_successful_login(self):
        line = (
            "Dec 10 06:56:00 LabSZ sshd[24200]: "
            "Accepted password for alice from "
            "192.0.2.10 port 40000 ssh2"
        )

        result = parse_log_line(line)

        self.assertEqual(result["event"], "SUCCESSFUL_LOGIN")
        self.assertEqual(result["username"], "alice")

    def test_other_event(self):
        line = (
            "Dec 10 06:55:48 LabSZ sshd[24200]: "
            "Connection closed by 173.234.31.186 [preauth]"
        )

        result = parse_log_line(line)

        self.assertEqual(result["event"], "OTHER")

    def test_invalid_timestamp(self):
        with self.assertRaises(ValueError):
            parse_log_line("not a valid OpenSSH log entry")

    def test_invalid_ip(self):
        line = (
            "Dec 10 06:55:48 LabSZ sshd[24200]: "
            "Failed password for alice from 999.0.0.1 "
            "port 38926 ssh2"
        )

        with self.assertRaises(ValueError):
            parse_log_line(line)


if __name__ == "__main__":
    unittest.main()
