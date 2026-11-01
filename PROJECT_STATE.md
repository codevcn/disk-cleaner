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
- [x] Comprehensive Test Suite: 114/114 tests passing (100% OK).

## 3. Current Status
- **Status**: V2.2.0 Transformation Complete. General-Purpose Windows AI Storage Investigator fully operational. 114/114 automated tests passing.
