"""
disk_investigator.updates.release_client
GitHub Releases API client for release discovery and asset downloading.
"""

from __future__ import annotations

import json
import os
import shutil
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, Optional

from .models import ReleaseAsset, ReleaseInfo, parse_semver

DEFAULT_REPO = "codevcn/disk-cleaner"
DEFAULT_USER_AGENT = "disk-investigator-release-client"


class GitHubReleaseClient:
    """Client for discovering releases and fetching release assets from GitHub."""

    def __init__(self, repo: str = DEFAULT_REPO, user_agent: str = DEFAULT_USER_AGENT):
        self.repo = repo
        self.user_agent = user_agent

    def get_latest_release(self, timeout: float = 5.0) -> ReleaseInfo:
        """
        Fetches the latest official release from GitHub Releases API.
        Fails safely on network or HTTP errors.
        """
        api_url = f"https://api.github.com/repos/{self.repo}/releases/latest"
        req = urllib.request.Request(
            api_url,
            headers={
                "User-Agent": self.user_agent,
                "Accept": "application/vnd.github.v3+json",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"GitHub API returned HTTP {resp.status}")
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"GitHub API error HTTP {e.code}: {e.reason}") from e
        except Exception as e:
            raise RuntimeError(f"Failed to query GitHub Releases API: {e}") from e

        tag_name = str(payload.get("tag_name", "")).strip()
        if not tag_name:
            raise ValueError("Release payload missing valid tag_name")

        raw_ver = tag_name.lstrip("vV")
        html_url = str(payload.get("html_url", f"https://github.com/{self.repo}/releases/tag/{tag_name}"))
        release_name = str(payload.get("name", tag_name))
        published_at = str(payload.get("published_at", ""))

        assets: Dict[str, ReleaseAsset] = {}
        for item in payload.get("assets", []):
            name = item.get("name")
            download_url = item.get("browser_download_url")
            if name and download_url:
                assets[name] = ReleaseAsset(
                    name=name,
                    download_url=download_url,
                    size=int(item.get("size", 0)),
                    content_type=str(item.get("content_type", "")),
                )

        return ReleaseInfo(
            tag=tag_name,
            version=raw_ver,
            release_url=html_url,
            published_at=published_at,
            release_name=release_name,
            assets=assets,
        )

    def download_text(self, url: str, timeout: float = 10.0) -> str:
        """Downloads a small text resource (e.g. SHA256SUMS.txt)."""
        req = urllib.request.Request(
            url,
            headers={"User-Agent": self.user_agent},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"Download HTTP {resp.status} for {url}")
                return resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            raise RuntimeError(f"Failed to download text asset from {url}: {e}") from e

    def download_file(
        self,
        url: str,
        destination_path: Path,
        timeout: float = 45.0,
        expected_size: Optional[int] = None,
    ) -> None:
        """
        Downloads a binary resource to a temporary file, verifies non-zero byte size,
        and atomically moves it to destination_path.
        """
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_file = destination_path.with_suffix(f".part_{os.getpid()}")

        req = urllib.request.Request(
            url,
            headers={"User-Agent": self.user_agent},
        )

        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp_file, "wb") as out_f:
                if resp.status != 200:
                    raise RuntimeError(f"Download HTTP {resp.status} for {url}")
                shutil.copyfileobj(resp, out_f)

            if not tmp_file.exists() or tmp_file.stat().st_size == 0:
                raise ValueError(f"Downloaded file from {url} is empty or missing")

            actual_size = tmp_file.stat().st_size
            if expected_size is not None and expected_size > 0:
                if actual_size != expected_size:
                    raise ValueError(
                        f"Downloaded size mismatch: expected {expected_size} bytes, got {actual_size} bytes"
                    )

            os.replace(str(tmp_file), str(destination_path))
        except Exception as e:
            if tmp_file.exists():
                try:
                    tmp_file.unlink()
                except Exception:
                    pass
            raise RuntimeError(f"Failed to download asset from {url}: {e}") from e
