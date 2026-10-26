import tempfile
import unittest
from pathlib import Path

from main import analyze_log


class FailedLoginAnalyzerTests(unittest.TestCase):
    def analyze_text(self, text, threshold=2):
        temp = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False
        )
        try:
            temp.write(text)
            temp.close()
            return analyze_log(Path(temp.name), threshold)
        finally:
            Path(temp.name).unlink(missing_ok=True)

    def test_synthetic_failed_and_successful_logins(self):
        results = self.analyze_text(
            "2026-10-26T09:00:00Z FAILED user=admin ip=192.0.2.10\n"
            "2026-10-26T09:01:00Z SUCCESS user=admin ip=192.0.2.10\n"
        )
        self.assertEqual(results["failed"], 1)
        self.assertEqual(results["successful"], 1)

    def test_threshold_alert(self):
        results = self.analyze_text(
            "2026-10-26T09:00:00Z FAILED user=root ip=192.0.2.5\n"
            "2026-10-26T09:01:00Z FAILED user=root ip=192.0.2.5\n",
            threshold=2,
        )
        self.assertEqual(results["alerts"]["192.0.2.5"], 2)

    def test_openssh_failed_login(self):
        results = self.analyze_text(
            "Dec 10 06:55:48 LabSZ sshd[24200]: "
            "Failed password for invalid user webmaster "
            "from 173.234.31.186 port 38926 ssh2\n"
        )
        self.assertEqual(results["failed"], 1)
        self.assertEqual(results["failed_by_ip"]["173.234.31.186"], 1)
        self.assertEqual(results["failed_by_user"]["webmaster"], 1)

    def test_openssh_successful_login(self):
        results = self.analyze_text(
            "Dec 10 07:20:00 LabSZ sshd[24250]: "
            "Accepted publickey for alice from 192.0.2.9 port 2200 ssh2\n"
        )
        self.assertEqual(results["successful"], 1)
        self.assertEqual(results["successful_by_ip"]["192.0.2.9"], 1)

    def test_invalid_user_is_not_double_counted_as_failed_login(self):
        results = self.analyze_text(
            "Dec 10 06:55:46 LabSZ sshd[24200]: "
            "Invalid user webmaster from 173.234.31.186\n"
        )
        self.assertEqual(results["failed"], 0)
        self.assertEqual(results["invalid_user_events"], 1)


if __name__ == "__main__":
    unittest.main()
