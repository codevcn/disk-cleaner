"""
disk_investigator.updates.checksum
Cryptographic SHA-256 manifest parsing, computation, and fail-closed verification.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Dict, Tuple

SHA256_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
MANIFEST_LINE_PATTERN = re.compile(r"^([0-9a-fA-F]{64})\s+[\* ]?([^\r\n]+)$")


def compute_sha256(filepath: Path) -> str:
    """Computes SHA-256 digest in 64KB blocks."""
    if not filepath.exists() or not filepath.is_file():
        raise FileNotFoundError(f"File not found for SHA-256 computation: {filepath}")
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest().lower()


def parse_sha256sums_manifest(manifest_text: str) -> Dict[str, str]:
    """
    Parses SHA256SUMS.txt format into {filename: sha256_hex_lower}.
    Strictly validates 64-hex format. Ignores empty or malformed lines without crashing.
    """
    results: Dict[str, str] = {}
    if not manifest_text:
        return results

    for raw_line in manifest_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = MANIFEST_LINE_PATTERN.match(line)
        if match:
            digest, filename = match.group(1).lower(), match.group(2).strip()
            # Normalize filename basename
            filename_clean = Path(filename).name
            results[filename_clean] = digest
    return results


def verify_sha256_checksum(filepath: Path, expected_sha: str) -> Tuple[bool, str]:
    """
    Compares computed file hash against expected hash.
    Fails closed: returns (False, actual_hash) on mismatch or invalid input.
    """
    expected_clean = expected_sha.strip().lower()
    if not SHA256_HEX_PATTERN.match(expected_clean):
        return False, ""

    try:
        actual_sha = compute_sha256(filepath)
        return (actual_sha == expected_clean), actual_sha
    except Exception:
        return False, ""
