# Architecture Specification: General-Purpose Windows AI Storage Investigator

## 1. Architectural Philosophy

The system enforces a strict, layered separation between **Reasoning**, **Ecosystem Discovery**, **Modular Detectors**, **Artifact Correlation**, **Policy Hardening**, and **Typed Action Execution**:

```text
                               +-----------------------------------+
                               |          USER PROMPT              |
                               +-----------------------------------+
                                                 │
                                                 ▼
                               +-----------------------------------+
                               |        GOOGLE ANTIGRAVITY         |
                               |       Skill: /disk-cleanup        |
                               +-----------------------------------+
                                                 │
                                                 ▼ (Subprocess CLI)
                      +───────────────────────────────────────────────────────+
                      |         disk_investigator Investigation Service       |
                      |                                                       |
                      |   [path_policy.py]       [capabilities.py]            |
                      |   - Windows Junctions    - Host diagnostics           |
                      |   - System Blacklist     - Elevation check (non-admin)|
                      |   - Cloud Sync check                                  |
                      +───────────────────────────────────────────────────────+
                                                 │
                                                 ▼
                      +───────────────────────────────────────────────────────+
                      |       Capability Discovery Engine (probes.py)         |
                      |  Non-invasive probes: Registry, FileSystem, Executable |
                      |  17 Ecosystems: Chrome, Edge, Outlook, Teams,         |
                      |  Premiere, AE, DaVinci, CapCut, OBS, Steam, Docker,   |
                      |  VS Code, Node, Python, Ollama, HuggingFace           |
                      +───────────────────────────────────────────────────────+
                                                 │
                                                 ▼
                      +───────────────────────────────────────────────────────+
                      |       Detector Registry (detectors/registry.py)       |
                      |  Error-isolated execution of modular domain detectors |
                      |  - system/ (user_temp, crash_dump)                    |
                      |  - browser/ (chromium: Chrome, Edge)                  |
                      |  - office/ (outlook, office_cache, teams)             |
                      |  - creator/ (adobe, davinci, capcut)                  |
                      |  - streaming/ (obs)                                   |
                      |  - gaming/ (steam)                                    |
                      |  - developer/ (node, python, build, docker)           |
                      |  - ai_ml/ (ollama, huggingface)                       |
                      |  - general/ (large_files, dicom medical)              |
                      +───────────────────────────────────────────────────────+
                                                 │
                                                 ▼
                      +───────────────────────────────────────────────────────+
                      |         Artifact Correlator (services/)               |
                      |  - Canonical path deduplication                       |
                      |  - Conservative conflict resolution (fail-closed)     |
                      |  - Parent/child containment annotation                |
                      |  - Net non-overlapping byte accounting                |
                      +───────────────────────────────────────────────────────+
                                                 │
                                                 ▼
                      +───────────────────────────────────────────────────────+
                      |   Artifact Policy Engine (classifiers/artifact_policy)|
                      |  - Layer 1: Hard Path Policy (OS system/sync roots)   |
                      |  - Layer 2: Semantic Rules (Footage BLOCK, PST BLOCK, |
                      |             DICOM BLOCK, VHDX BLOCK, AI models REVIEW)|
                      |  - Layer 3: Domain Policy (Low user data probability) |
                      +───────────────────────────────────────────────────────+
                                                 │
                                                 ▼
                      +───────────────────────────────────────────────────────+
                      |              Plan Generator (Schema v2)               |
                      |  - Itemized CleanupPlan v2 with HMAC-SHA256 signature |
                      |  - Rejection of overlapping descendant items          |
                      |  - Typed action binding & pre-flight fingerprinting   |
                      +───────────────────────────────────────────────────────+
                                                 │
                                                 ▼
                      =========================================================
                      [        HUMAN APPROVAL GATE - STRICT CONFIRMATION      ]
                      =========================================================
                                                 │ (Explicit Approved item_ids)
                                                 ▼
                      +───────────────────────────────────────────────────────+
                      |     Safe Executor & Action Registry (cleanup/)        |
                      |  - Schema version 2 enforcement (rejects legacy v1)   |
                      |  - HMAC-SHA256 signature verification                 |
                      |  - TOCTOU mtime & size pre-flight check               |
                      |  - Process running check: never kills active apps     |
                      |  - Typed handlers: NPM, PIP, Docker, Caches           |
                      |  - Windows Shell Recycle Bin (SHFileOperationW)       |
                      +───────────────────────────────────────────────────────+
```

---

## 2. Key Component Responsibilities

| Component | Module | Primary Responsibility |
| :--- | :--- | :--- |
| **Domain Contracts** | `models.py` | Universal definitions: `StorageArtifact`, `Capability`, `DetectionContext`, `Evidence`. Strict fail-closed defaults (`Regenerability.NONE`, `UserDataProbability.HIGH`, `RecoveryCost.IMPOSSIBLE`, `RecommendedAction.REVIEW_ONLY`). |
| **Capability Discovery** | `discovery/` | Non-invasive detection of 17 application capabilities across 8 domains via `RegistryProbe`, `FileSystemProbe`, and `ExecutableProbe` protocols. |
| **Detector Registry** | `detectors/registry.py` | Manages extensible `Detector` instances. Enforces fault isolation so one failing detector never crashes the overall scan. |
| **Modular Detectors** | `detectors/` | Subpackages for `system`, `browser`, `office`, `creator`, `streaming`, `gaming`, `developer`, `ai_ml`, and `general`. |
| **Artifact Correlator** | `services/artifact_correlator.py` | Deduplicates artifacts for the same canonical path, resolves conflicting risk/action attributes conservatively, and prevents double-counting nested bytes. |
| **Policy Engine** | `classifiers/artifact_policy.py` | 3-tier security guardrails ensuring user documents, original footage, email archives, medical records, and running app caches are protected from deletion. |
| **Typed Action Framework** | `cleanup/action_registry.py` | Dispatches typed actions (`BROWSER_CACHE_PURGE`, `CREATOR_CACHE_PURGE`, etc.) and enforces process running checks to prevent killing active user apps. |
| **Plan Generator v2** | `cleanup/plan_generator.py` | Prepares auditable `CleanupPlan` (Schema v2) with cryptographic HMAC-SHA256 signature and eliminates overlapping items. |
| **Safe Executor** | `cleanup/safe_executor.py` | Enforces Schema v2, verifies HMAC signature, conducts TOCTOU pre-flight verification, and moves files to Windows Recycle Bin via `SHFileOperationW`. |
| **Agent Skill** | `skills/disk-cleanup/SKILL.md` | Skill definition providing natural conversational workflows for Antigravity AI agents on Windows 11. |
