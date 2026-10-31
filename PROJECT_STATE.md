# PROJECT STATE: AI-native Disk Investigation System for Windows 11

## 1. Final Architecture (V2.0.3 Hardened & Verified)
- **Packaging Format**: Google Antigravity Agent Skill (`/disk-cleanup`) powered by the internal Python harness (`disk_investigator`).
- **Core Separation**:
  - **Reasoning Layer**: Google Antigravity + Riza conversational investigation principles.
  - **Harness & Policy Layer**: `disk_investigator` (Python 3.12, strict path policy, snapshot session tracking, TOCTOU mitigation & stale-plan defense).
  - **Scanner Backends**: `DustBackend` (primary fast radar, `bootandy/dust` v1.2.6 with `-j -o b -p -P`, strictly no `-L`) + `NativeWindowsBackend` (scoped fallback using Python 3.12 `os.scandir` with junction/reparse protection).
  - **Specialized Detectors**: `DeveloperDetector`, `DockerDetector`, `LargeFilesDetector`.
  - **Safety Classifier**: Two-dimensional evaluation: Risk (`LOW`/`MEDIUM`/`HIGH`) vs Policy Disposition (`CLEANABLE`/`REVIEW_REQUIRED`/`BLOCKED`).
  - **Execution Layer**: `PlanGenerator` + `SafeExecutor`:
    - Strict semantics: separates immediate volume reclaim from Recycle Bin deferral.
    - Plan Signature Integrity: HMAC-SHA256 signature binding each plan to session secret key, covering all plan metadata, totals, and item payloads.
    - Uniform Cache Signing: Consistent `cache_dir` secret key derivation across `PlanGenerator` and `SafeExecutor`.
    - Plan-time Fingerprint Safety: Fails closed during plan generation if metadata (`mtime`) cannot be established.
    - Schema Validation: Enforces unique item IDs, positive IDs, and item count matching before execution.
    - Pre-flight TOCTOU verification with fail-closed stat error handling (`VERIFY_FAILED`).
    - Ancestor reparse point defense (`has_reparse_point_ancestor`) up to drive root.
    - Windows 8.3 Short-Name Alias Safety (`resolve_windows_aliases` via `GetLongPathNameW` / `os.path.realpath`) applied to OS protection AND cloud sync roots.
    - All-User-Profile Boundary Defense (`C:\Users\*` roots blocked across all accounts).
    - Recycle Bin volume verification (`is_safe_fixed_drive` / Win32 `GetDriveTypeW == DRIVE_FIXED`).
    - Typed action runtime path binding (`npm config get cache`, `pip cache dir`).
    - Multi-volume free space delta tracking (`observed_volume_deltas`).
    - Native Windows Recycle Bin integration (`shell32.SHFileOperationW` with `FOF_ALLOWUNDO`).
    - Typed actions only (`RECYCLE_PATH`, `NPM_CACHE_CLEAN`, `PIP_CACHE_PURGE`, `DOCKER_BUILDER_PRUNE`).
    - Mandatory human approval gate (fails closed on empty/missing item selection).

## 2. Completed Milestones
- [x] Initial research & comparison of 7 tools/repos (`dust`, `MangoDisk`, `Czkawka`, `BleachBit`, `Riza`, `Khazix`, `Agentinel`).
- [x] Verification of Windows 11 environment: Python 3.12, Node 22, winget.
- [x] Installation and verification of `bootandy.dust` v1.2.6 via winget.
- [x] Architecture Review Checkpoint 1 with ChatGPT Web (Architect/Reviewer) via Playwright profile `b6` -> Approved with modifications.
- [x] Phase 1: Scanner Foundation (`models.py`, `path_policy.py`, `capabilities.py`, `backends/`, `services/scan_service.py`, `cli.py`).
- [x] Phase 2: Drilldown Service (`services/drilldown_service.py`, snapshot-linked drilldowns, dominant consumer detection).
- [x] Phase 3 & 4: Specialized Detectors (`DeveloperDetector`, `DockerDetector`, `LargeFilesDetector`).
- [x] Phase 5: Risk & Policy Classifier (`classifiers/risk_classifier.py`).
- [x] Phase 6 & 7: Cleanup Planning & Safe Execution (`cleanup/plan_generator.py`, `cleanup/safe_executor.py` using Windows Recycle Bin).
- [x] Phase 8: Agent Skill Integration (`C:\Users\dell\.gemini\config\skills\disk-cleanup\SKILL.md` and workspace copy).
- [x] Architecture Review Checkpoint 2 with ChatGPT Web -> Architecture Approved (9/10), conditional on V2.0.1 hardening.
- [x] Architecture Review Checkpoint 3 with ChatGPT Web -> Architecture Approved (9.4/10), Production Ready for Investigation & Controlled Use, conditional on V2.0.2 patch.
- [x] V2.0.3 Hardening Implementation:
  - Fixed custom `cache_dir` HMAC secret key derivation consistency between `PlanGenerator` and `SafeExecutor`.
  - Added 8.3 short-name alias resolution to cloud sync path detection (`is_cloud_sync_path` + `preflight_check`).
  - Implemented plan-time fingerprint fail-closed requirement in `PlanGenerator`.
  - Implemented multi-volume free-space delta measurement (`observed_volume_deltas`).
  - Added threat-model documentation alignment for HMAC session boundaries.
- [x] Comprehensive Test Suite: 44/44 tests passing (unit, classifiers, backends, detectors, services, destructive e2e).
- [x] Complete documentation: `README.md`, `ARCHITECTURE.md`, `PROJECT_STATE.md`.

## 3. Standalone Packaging Milestones (V2.0.3 Release)
- [x] Implemented `build_exe.py` PyInstaller automated packager:
  - Enforces strict single-executable invariant in root (`disk_investigator.exe`).
  - Pre-build removal of old executables before compilation.
  - Automatically cleans up PyInstaller temporary directories (`build`, `dist`, `.spec`).
  - Tracks build history with version, ISO timestamp, file size, and SHA-256 digest in `build_history.json`.
  - Self-verifies the compiled binary post-build.
- [x] Implemented `build.cmd` plug-and-play batch script for 1-click execution.
- [x] Verified build cycles: Build #1 and Build #2 tested cleanly; prior executable automatically removed and replaced; `build_history.json` updated.
- [x] Comprehensive, professional `README.md` created with architecture diagrams, safety model, full CLI reference, and skill integration guide.

## 4. Current Status
- **Status**: Production-Grade V2.0.3 Complete & Signed Off. Standalone Portable Executable (`disk_investigator.exe`) available in root alongside Python package. 44/44 tests passing.
