# PROJECT STATE: General-Purpose Windows AI Storage Investigator

## 1. Architecture (V2.2.0 General-Purpose Windows AI Storage Investigator)
- **Role**: AI-native multi-domain storage investigator and optimizer for Windows 11.
- **Core Separation**:
  - **Reasoning Layer**: Google Antigravity Agent Skill (`/disk-cleanup`) + ChatGPT Web Orchestrator.
  - **Ecosystem Discovery Layer**: `CapabilityDiscovery` with hermetic probe abstraction (`RegistryProbe`, `FileSystemProbe`, `ExecutableProbe`) discovering 17 ecosystem capabilities across 8 domains.
  - **Modular Detector Layer**: `DetectorRegistry` managing extensible `Detector` instances across System, Browser, Office, Creator, Streaming, Gaming, Developer, AI/ML, and Medical DICOM.
  - **Correlation & Aggregation Layer**: `ArtifactCorrelator` performing canonical path deduplication, conservative conflict resolution (fail-closed), parent-child containment detection, and net non-overlapping byte accounting.
  - **Policy & Safety Layer**: `ArtifactPolicyEngine` enforcing 3-tier hierarchical security guardrails:
    - Layer 1: Hard Path Policy (OS System32/WinSxS, Cloud Sync roots, User Profile root protection).
    - Layer 2: Semantic Protection Rules (DICOM medical data [BLOCK], Video footage/recordings [BLOCK], Creative projects [BLOCK], Outlook PST [BLOCK], OST [REVIEW_ONLY], AI models [REVIEW_ONLY], Steam games [REVIEW_ONLY], Stale user docs [REVIEW_ONLY]).
    - Layer 3: Domain Policy (cleanable items require LOW user data probability and TYPED_CLEANUP / RECYCLE).
  - **Execution & Action Framework**:
    - `PlanGenerator`: Generates Schema v2 `CleanupPlan` with HMAC-SHA256 signature, eliminating overlapping items and excluding blocked items.
    - `ActionRegistry`: Typed action handlers (`RECYCLE_PATH`, `NPM_CACHE_CLEAN`, `PIP_CACHE_PURGE`, `DOCKER_BUILDER_PRUNE`, `BROWSER_CACHE_PURGE`, `OFFICE_CACHE_PURGE`, `CREATOR_CACHE_PURGE`, `GAMING_CACHE_PURGE`, `STREAMING_LOGS_PURGE`).
    - Process Running Guard: Actively running applications (Chrome, Edge, OBS, Premiere, Teams) are never terminated; active caches are skipped safely.
    - `SafeExecutor`: Enforces `schema_version == 2`, rejects legacy v1 plans with `LEGACY_PLAN_UNSUPPORTED`, verifies HMAC integrity, conducts pre-flight TOCTOU verification, and moves files to Windows Recycle Bin (`SHFileOperationW`).

## 2. Completed Milestones
- [x] Initial research & comparison of 7 storage tools.
- [x] Phase 0: Freeze baseline & verify 62 legacy tests.
- [x] Phase 1: Universal Domain Contracts (`StorageArtifact`, `Capability`, `DetectionContext`, `Evidence` in `models.py`).
- [x] Phase 2: Capability Discovery (`probes.py`, `capability_discovery.py`, 17 application capabilities).
- [x] Phase 3: Detector Registry & Investigation Service (`base.py`, `registry.py`, `artifact_correlator.py`, `investigation_service.py`).
- [x] Phase 4A: System, Browser & Office Detectors (`user_temp.py`, `crash_dump.py`, `chromium.py`, `outlook.py`, `office_cache.py`, `teams.py`, `dicom.py`).
- [x] Phase 4B: Creator, Streaming & Gaming Detectors (`adobe.py`, `davinci.py`, `capcut.py`, `obs.py`, `steam.py`).
- [x] Phase 4C: Developer & AI/ML Detectors (`node`, `python`, `build`, `docker`, `ollama.py`, `huggingface.py`).
- [x] Phase 5: Policy Engine & False-Positive Hardening (`artifact_policy.py`, 13 mandatory false-positive tests in `test_false_positives.py`).
- [x] Phase 6: Typed Action Framework & Plan Schema v2 (`action_types.py`, `action_registry.py`, `schema_version = 2`, HMAC sealing).
- [x] Phase 7: CLI, Skill & Documentation (`discover-capabilities`, `investigate`, upgraded `cleanup-plan`, updated `SKILL.md`).
- [x] Hardening Review Gates (V22-FINAL-01 to V22-FINAL-13):
  - [x] V22-FINAL-01 & 02: Strict allowlist for executable actions in `PlanGenerator` (`KEEP` & `UNINSTALL_VIA_APP` strictly excluded).
  - [x] V22-FINAL-03: `ArtifactCorrelator` conservative precedence: non-cleanup actions strictly override cleanup.
  - [x] V22-FINAL-04 & 05: `PlanItem` semantic provenance & `action_binding` sealed with HMAC-SHA256 across all execution fields.
  - [x] V22-FINAL-06: Target-binding pre-flight verification across Browser, Office, Creator, Gaming, and Streaming caches.
  - [x] V22-FINAL-07: Tri-state process guards (`RUNNING`, `NOT_RUNNING`, `UNKNOWN`) failing closed on any tasklist error/timeout.
  - [x] V22-FINAL-08: Detector fault visibility exposing `detector_runs`, `detector_errors`, and `coverage_status` in report.
  - [x] V22-FINAL-09: Package version set to `2.2.0`.
  - [x] V22-FINAL-10: Documentation consistency across README, Architecture, Skill, and Project State.
  - [x] V22-FINAL-11: Full Windows GitHub CI passing.
  - [x] V22-FINAL-12: CLI smoke tests verified for all V2.2 commands.
  - [x] V22-FINAL-13: Production release V2.2.0 sign-off.

## 3. Completed Milestones (V2.3.0 Standalone Uninstaller & Unified Lifecycle Engine)
- [x] Shared Core Lifecycle Engine:
  - `disk_investigator/lifecycle/models.py`: `UninstallStatus` (SUCCESS, FAILED, CANCELLED, PARTIAL, BLOCKED) and typed `UninstallResult` with exit code mapping (0, 1, 2, 3, 4).
  - `disk_investigator/lifecycle/common.py`: Shared constants, `RELEASE_ASSETS`, Registry User PATH safe management via winreg, SHA-256 computation, authoritative version discovery.
  - `disk_investigator/lifecycle/uninstall_core.py`: `UninstallEngine` with preflight checks, fail-closed process safety (`ProcessState.UNKNOWN`), manifest scope validation, conservative fallback, unknown file preservation.
- [x] Standalone Executable Uninstaller:
  - `uninstaller.py` & `build_uninstaller.py`: Builds standalone `disk-investigator-uninstall.exe`.
  - Interactive mode with user confirmation prompt and closing pause (`Nhấn Enter để đóng...`).
  - Unattended mode with `--silent`.
  - Data purge mode with `--purge-data` safely preserving unknown user files.
- [x] Unified Lifecycle Integration:
  - `installer.py` refactored to delegate uninstall operations directly to `UninstallEngine`.
  - `uninstall.cmd` updated to eliminate raw recursive destructive fallbacks (`rd /s /q`).
  - `build.cmd` updated to compile all 3 executables (`disk_investigator.exe`, `disk-investigator-setup.exe`, `disk-investigator-uninstall.exe`).
  - `publish_release.py` updated to verify and package all 3 executables and `SHA256SUMS.txt`.
  - `.github/workflows/ci.yml` updated to build, smoke test, and release all 3 executables.
  - Full suite of 140 tests passing 100% green.

## 4. Current Status
- **Status**: V2.3.2 Production Hardening Release. Standalone 1-Click Uninstaller with ownership-aware purge semantics, strict Windows NTFS junction escape validation, safe self-preservation, post-delete verification, and unknown-file protection. 149/149 unit and integration tests passing.
