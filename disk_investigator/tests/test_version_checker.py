import io
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from disk_investigator.version_checker import (
    _get_cache_path,
    _is_valid_cache,
    check_for_updates,
    notify_if_update_available,
    parse_semver,
)


class TestVersionChecker(unittest.TestCase):
    def test_parse_semver(self):
        self.assertEqual(parse_semver("2.0.3"), (2, 0, 3))
        self.assertEqual(parse_semver("v2.1.0"), (2, 1, 0))
        self.assertEqual(parse_semver("3"), (3, 0, 0))
        self.assertEqual(parse_semver("1.2"), (1, 2, 0))
        self.assertTrue(parse_semver("2.0.4") > parse_semver("2.0.3"))
        self.assertTrue(parse_semver("2.1.0") > parse_semver("2.0.9"))
        self.assertFalse(parse_semver("2.0.3") > parse_semver("2.0.3"))

    def test_cache_path_does_not_use_cwd(self):
        cache_path = _get_cache_path()
        cwd = Path.cwd()
        self.assertFalse(
            cache_path.is_relative_to(cwd),
            f"Cache path {cache_path} must not be inside CWD {cwd} to preserve read-only scans",
        )
        self.assertIn("DiskInvestigator", str(cache_path))
        self.assertIn("update_status.json", cache_path.name)

    def test_is_valid_cache(self):
        now = time.time()
        valid = {
            "repo": "codevcn/disk-cleaner",
            "checked_at": now - 100,
            "latest_version": "2.0.4",
        }
        self.assertTrue(_is_valid_cache(valid, "codevcn/disk-cleaner"))

        # Invalid repo
        self.assertFalse(_is_valid_cache(valid, "other/repo"))

        # Future timestamp > 1 hour
        invalid_future = dict(valid, checked_at=now + 5000)
        self.assertFalse(_is_valid_cache(invalid_future, "codevcn/disk-cleaner"))

        # Negative timestamp
        invalid_neg = dict(valid, checked_at=-1)
        self.assertFalse(_is_valid_cache(invalid_neg, "codevcn/disk-cleaner"))

        # Non-dict
        self.assertFalse(_is_valid_cache("not a dict", "codevcn/disk-cleaner"))

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

    @patch("disk_investigator.version_checker._get_cache_path")
    def test_check_for_updates_uses_cache(self, mock_get_cache_path):
        with tempfile.TemporaryDirectory() as tmp_dir:
            cache_file = Path(tmp_dir) / "update_status.json"
            mock_get_cache_path.return_value = cache_file

            now = time.time()
            cached_data = {
                "status": "checked",
                "update_available": True,
                "current_version": "2.0.3",
                "latest_version": "2.1.0",
                "repo": "codevcn/disk-cleaner",
                "checked_at": now - 30,  # 30 seconds ago
                "release_url": "https://github.com/codevcn/disk-cleaner/releases/tag/v2.1.0",
                "message": "Update cached",
            }
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(cached_data, f)

            # Do not force -> should hit cache without network
            with patch("urllib.request.urlopen") as mock_urlopen:
                res = check_for_updates(current_version="2.0.3", repo="codevcn/disk-cleaner", force=False)
                mock_urlopen.assert_not_called()
                self.assertEqual(res["latest_version"], "2.1.0")
                self.assertTrue(res["update_available"])


if __name__ == "__main__":
    unittest.main()
