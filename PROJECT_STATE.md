# PROJECT STATE: AI-native Disk Investigation System for Windows 11

## 1. Final Architecture (V2.1.0 1-Click All-in-One Distribution & Hardened)
- **Packaging Format**: Google Antigravity Agent Skill (`/disk-cleanup`) powered by the internal Python harness (`disk_investigator`) and distributed via Canonical 1-Click Setup executable (`disk-investigator-setup.exe`).
- **Core Separation**:
  - **Reasoning Layer**: Google Antigravity + Riza conversational investigation principles.
  - **Harness & Policy Layer**: `disk_investigator` (Python 3.12, strict path policy, snapshot session tracking, TOCTOU mitigation & stale-plan defense).
  - **Distribution & Installation Engine**:
    - **Canonical 1-Click All-in-One Installer (`disk-investigator-setup.exe`)**:
      - Single-file, zero-dependency, completely offline self-installer.
      - Deploys binary to `%LOCALAPPDATA%\DiskInvestigator\bin\disk_investigator.exe`.
      - User PATH management safely executed via Windows Registry `HKCU\Environment\Path` using Python `winreg` (never `setx`), followed by `WM_SETTINGCHANGE` broadcast.
      - Deploys Antigravity Agent Skill to `%USERPROFILE%\.gemini\config\skills\disk-cleanup\SKILL.md` with smart backup of user-customized skills (`SKILL.md.user-backup-<timestamp>`).
      - Deploys reference manuals to `%LOCALAPPDATA%\DiskInvestigator\README.md` and `%USERPROFILE%\.gemini\config\skills\disk-cleanup\references\README.md`.
      - Generates auditable `install_manifest.json` tracking SHA-256 hashes.
      - Provides clean `uninstall.cmd` and `--uninstall` flag preserving user customizations.
    - **Standalone Portable Binary (`disk_investigator.exe`)**: Portable single binary for advanced users.
    - **Autonomous Updater (`update_from_github.py` / `update.cmd`)**: Immutable tag checkout in Git mode, or direct canonical setup download and silent upgrade in standalone mode.
    - **Hardened Release Publisher (`publish_release.py` / `publish.cmd`)**: Enforces clean git tree, test quality gate, transactional dual-binary builds, and immutable releases (hard abort if release tag exists).
    - **Transactional Builder (`build_exe.py` / `build_installer.py`)**: Builds to temporary directories, conducts pre-swap quality gate smoke tests, only performs atomic swap (`os.replace`) upon test success, and strictly manages project-owned executables.
    - **Update Cache Migration**: Relocated from CWD to `%LOCALAPPDATA%\DiskInvestigator\updates\update_status.json` with strict schema validation and atomic writes.
  - **Scanner Backends**: `DustBackend` (primary fast radar, `bootandy/dust` v1.2.6 with `-j -o b -p -P`, strictly no `-L`) + `NativeWindowsBackend` (scoped fallback using Python 3.12 `os.scandir` with junction/reparse protection).
  - **Specialized Detectors**: `DeveloperDetector`, `DockerDetector`, `LargeFilesDetector`.
  - **Safety Classifier**: Two-dimensional evaluation: Risk (`LOW`/`MEDIUM`/`HIGH`) vs Policy Disposition (`CLEANABLE`/`REVIEW_REQUIRED`/`BLOCKED`).
  - **Execution Layer**: `PlanGenerator` + `SafeExecutor`:
    - Strict semantics: separates immediate volume reclaim from Recycle Bin deferral.
    - Plan Signature Integrity: HMAC-SHA256 signature binding each plan to session secret key, covering all plan metadata, totals, and item payloads.
    - Schema Validation: Enforces unique item IDs, positive IDs, and item count matching before execution.
    - Pre-flight TOCTOU verification with fail-closed stat error handling (`VERIFY_FAILED`).
    - Ancestor reparse point defense (`has_reparse_point_ancestor`) up to drive root.
    - Windows 8.3 Short-Name Alias Safety (`resolve_windows_aliases` via `GetLongPathNameW` / `os.path.realpath`) applied to OS protection AND cloud sync roots.
    - All-User-Profile Boundary Defense (`C:\Users\*` roots blocked across all accounts).
    - Recycle Bin volume verification (`is_safe_fixed_drive` / Win32 `GetDriveTypeW == DRIVE_FIXED`).
    - Typed action runtime path binding (`npm config get cache`, `pip cache dir`).
    - Multi-volume free space delta tracking (`observed_volume_deltas`).
    - Native Windows Recycle Bin integration (`shell32.SHFileOperationW` with `FOF_ALLOWUNDO`).
    - Mandatory human approval gate (fails closed on empty/missing item selection).

## 2. Completed Milestones
- [x] Initial research & comparison of 7 tools/repos (`dust`, `MangoDisk`, `Czkawka`, `BleachBit`, `Riza`, `Khazix`, `Agentinel`).
- [x] Verification of Windows 11 environment: Python 3.12, Node 22, winget.
- [x] Installation and verification of `bootandy.dust` v1.2.6 via winget.
- [x] Architecture Review Checkpoint 1 with ChatGPT Web (Architect/Reviewer) -> Approved with modifications.
- [x] Phase 1: Scanner Foundation (`models.py`, `path_policy.py`, `capabilities.py`, `backends/`, `services/scan_service.py`, `cli.py`).
- [x] Phase 2: Drilldown Service (`services/drilldown_service.py`, snapshot-linked drilldowns, dominant consumer detection).
- [x] Phase 3 & 4: Specialized Detectors (`DeveloperDetector`, `DockerDetector`, `LargeFilesDetector`).
- [x] Phase 5: Risk & Policy Classifier (`classifiers/risk_classifier.py`).
- [x] Phase 6 & 7: Cleanup Planning & Safe Execution (`cleanup/plan_generator.py`, `cleanup/safe_executor.py` using Windows Recycle Bin).
- [x] Phase 8: Agent Skill Integration (`C:\Users\dell\.gemini\config\skills\disk-cleanup\SKILL.md` and workspace copy).
- [x] Architecture Review Checkpoint 2 with ChatGPT Web -> Architecture Approved (9/10).
- [x] Architecture Review Checkpoint 3 with ChatGPT Web -> Architecture Approved (9.4/10).
- [x] V2.0.4 Remote Publishing Pipeline (`publish_release.py`, `publish.cmd`).
- [x] V2.1.0 1-Click All-in-One Installer & Production Hardening:
  - Created `installer.py` (transactional setup engine, `winreg` PATH manager, skill backup policy, manifest generator, and uninstaller).
  - Created `build_installer.py` (compiles canonical `disk-investigator-setup.exe` embedding binary, skill, and readme).
  - Relocated update cache from CWD to `%LOCALAPPDATA%\DiskInvestigator\updates\update_status.json` with strict schema validation.
  - Implemented transactional build and quality gate self-test in `build_exe.py` and `build_installer.py`.
  - Hardened `publish_release.py` (immutable releases, fail-closed on duplicate tag, upload both setup.exe and portable exe).
  - Enhanced `update_from_github.py` with exact immutable tag checkout and standalone setup.exe auto-download.
  - Comprehensive Test Suite expanded to 59/59 tests passing (100% OK).

## 3. Current Status
- **Status**: Production-Grade V2.1.0 Complete. Canonical 1-Click All-in-One Installer (`disk-investigator-setup.exe`) and Portable CLI Binary (`disk_investigator.exe`) fully compiled, tested, and operational. 59/59 automated tests passing.
