import unittest
from unittest.mock import MagicMock, patch
import json
import io
from disk_investigator.version_checker import parse_semver, check_for_updates, notify_if_update_available


class TestVersionChecker(unittest.TestCase):
    def test_parse_semver(self):
        self.assertEqual(parse_semver("2.0.3"), (2, 0, 3))
        self.assertEqual(parse_semver("v2.1.0"), (2, 1, 0))
        self.assertEqual(parse_semver("3"), (3, 0, 0))
        self.assertEqual(parse_semver("1.2"), (1, 2, 0))
        self.assertTrue(parse_semver("2.0.4") > parse_semver("2.0.3"))
        self.assertTrue(parse_semver("2.1.0") > parse_semver("2.0.9"))
        self.assertFalse(parse_semver("2.0.3") > parse_semver("2.0.3"))

    @patch("urllib.request.urlopen")
    def test_check_for_updates_update_available(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            "tag_name": "v2.0.4",
            "name": "Release v2.0.4",
            "html_url": "https://github.com/codevcn/disk-cleaner/releases/tag/v2.0.4",
            "published_at": "2026-11-01T00:00:00Z"
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        res = check_for_updates(current_version="2.0.3", repo="codevcn/disk-cleaner", force=True)
        self.assertTrue(res["update_available"])
        self.assertEqual(res["latest_version"], "2.0.4")
        self.assertIn("v2.0.4", res["message"])

    @patch("urllib.request.urlopen")
    def test_check_for_updates_already_latest(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            "tag_name": "v2.0.3",
            "name": "Release v2.0.3",
            "html_url": "https://github.com/codevcn/disk-cleaner/releases/tag/v2.0.3",
            "published_at": "2026-10-31T00:00:00Z"
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        res = check_for_updates(current_version="2.0.3", repo="codevcn/disk-cleaner", force=True)
        self.assertFalse(res["update_available"])
        self.assertEqual(res["latest_version"], "2.0.3")

    @patch("urllib.request.urlopen")
    def test_check_for_updates_network_failure(self, mock_urlopen):
        mock_urlopen.side_effect = Exception("Connection refused")
        res = check_for_updates(current_version="2.0.3", repo="codevcn/disk-cleaner", force=True)
        self.assertFalse(res["update_available"])
        self.assertEqual(res["status"], "offline_or_failed")


if __name__ == "__main__":
    unittest.main()
