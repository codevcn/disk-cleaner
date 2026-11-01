#!/usr/bin/env python3
"""
uninstaller.py - Standalone 1-Click Uninstaller CLI for Disk Investigator.
Compiles into disk-investigator-uninstall.exe for independent distribution.

Supports:
- Interactive confirmation and pause on finish.
- Silent unattended mode (--silent / -s).
- Full data purge mode (--purge-data) while safely preserving unknown user files.
- Guaranteed exit codes (0=SUCCESS, 1=FAILED, 2=CANCELLED, 3=PARTIAL, 4=BLOCKED).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Enable UTF-8 output on Windows terminal
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure disk_investigator package can be imported in both dev and bundled mode
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from disk_investigator.lifecycle import (
    APP_NAME,
    APP_DISPLAY_NAME,
    UninstallEngine,
    UninstallResult,
    UninstallStatus,
    get_app_version,
)


def run_uninstaller(
    silent: bool = False,
    purge_data: bool = False,
    no_pause: bool = False,
) -> int:
    """
    Coordinates standalone uninstallation process.
    """
    interactive = not silent

    if interactive:
        print("=======================================================")
        print(f"       GỠ CÀI ĐẶT {APP_DISPLAY_NAME}")
        print("=======================================================")
        print(f"Phiên bản: {get_app_version()}")
        print("=======================================================\n")

        try:
            prompt = f"Bạn có chắc chắn muốn gỡ cài đặt {APP_NAME}? (y/N): "
            response = input(prompt).strip().lower()
            if response not in ("y", "yes"):
                print("\n[*] Đã hủy thao tác gỡ cài đặt theo yêu cầu người dùng.")
                if not no_pause:
                    try:
                        input("\nNhấn Enter để đóng cửa sổ...")
                    except (EOFError, KeyboardInterrupt):
                        pass
                return 2  # CANCELLED
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Thao tác bị gián đoạn.")
            return 2

    # Execute core uninstallation via shared engine
    result = UninstallEngine.execute(
        purge_data=purge_data,
        silent=silent,
    )

    if interactive and not no_pause:
        try:
            input("\nNhấn Enter để đóng cửa sổ...")
        except (EOFError, KeyboardInterrupt):
            pass

    return result.exit_code


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="disk-investigator-uninstall",
        description=f"Standalone Uninstaller for {APP_DISPLAY_NAME}",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"%(prog)s {get_app_version()}",
        help="Show uninstaller version and exit.",
    )
    parser.add_argument(
        "--silent", "-s",
        action="store_true",
        help="Run unattended uninstallation without prompts or closing pause.",
    )
    parser.add_argument(
        "--purge-data",
        action="store_true",
        help="Purge all user cache, logs, and application state while safely preserving unknown user files.",
    )
    parser.add_argument(
        "--no-pause",
        action="store_true",
        help="Skip final pause in interactive mode (useful for script automation).",
    )

    args = parser.parse_args()

    return run_uninstaller(
        silent=args.silent,
        purge_data=args.purge_data,
        no_pause=args.no_pause,
    )


if __name__ == "__main__":
    sys.exit(main())
