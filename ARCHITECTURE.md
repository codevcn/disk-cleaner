# Architecture Specification: AI-native Disk Investigation System

## 1. Architectural Philosophy

The system enforces a strict separation between **Reasoning**, **Harness Policy**, **Measurement Engines**, and **Execution Handlers**:

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
                        +─────────────────────────────────────────────────+
                        |             disk_investigator Harness           |
                        |                                                 |
                        |   [path_policy.py]     [capabilities.py]        |
                        |   - Windows Junctions  - Host diagnostics       |
                        |   - System Blacklist   - Elevation check        |
                        |   - Cloud Sync check                            |
                        +─────────────────────────────────────────────────+
                                                 │
                                ┌────────────────┴────────────────┐
                                ▼                                 ▼
                     +─────────────────────+           +─────────────────────+
                     |     DustBackend     |           | NativeWindowsBackend|
                     |  (bootandy/dust -j) |           |  (Python 3.12 walk) |
                     |   - High-speed multithread      |   - Scoped fallback |
                     |   - No link dereferencing       |   - No junction loop|
                     +─────────────────────+           +─────────────────────+
                                │                                 │
                                └────────────────┬────────────────┘
                                                 ▼
                               +───────────────────────────────────+
                               |           ScanSnapshot            |
                               |  - UUID session tracking          |
                               |  - Hierarchical FileSystemNode    |
                               |  - Logical vs Allocated bytes     |
                               +───────────────────────────────────+
                                                 │
                        ┌────────────────────────┼────────────────────────┐
                        ▼                        ▼                        ▼
             +─────────────────────+  +─────────────────────+  +─────────────────────+
             |  DeveloperDetector  |  |   DockerDetector    |  | LargeFilesDetector  |
             |  - node_modules     |  |  - WSL2 ext4.vhdx   |  |  - Extension map    |
             |  - venv / caches    |  |  - Builder cache    |  |  - Age in days      |
             +─────────────────────+  +─────────────────────+  +─────────────────────+
                                                 │
                                                 ▼
                               +───────────────────────────────────+
                               |          RiskClassifier           |
                               |  - Risk: LOW / MEDIUM / HIGH      |
                               |  - Disposition: CLEANABLE /       |
                               |    REVIEW_REQUIRED / BLOCKED      |
                               +───────────────────────────────────+
                                                 │
                                                 ▼
                               +───────────────────────────────────+
                               |           PlanGenerator           |
                               |  - Itemized CleanupPlan (JSON)    |
                               |  - Pre-flight metadata            |
                               +───────────────────────────────────+
                                                 │
                                                 ▼
                               =====================================
                               [ HUMAN APPROVAL GATE - STOP/REVIEW ]
                               =====================================
                                                 │ (Explicit User Confirmation)
                                                 ▼
                               +───────────────────────────────────+
                               |           SafeExecutor            |
                               |  - Pre-flight TOCTOU verification |
                               |  - Windows Recycle Bin handler    |
                               |  - Typed actions only             |
                               +───────────────────────────────────+
```

---

## 2. Key Component Responsibilities

| Component | File | Primary Responsibility |
| :--- | :--- | :--- |
| **Data Models** | `models.py` | Schema definitions (`FileSystemNode`, `DriveOverview`, `ScanSnapshot`). Distinguishes `logical_bytes` from `allocated_bytes` and forbids fabricating `reclaimable_bytes`. |
| **Path Policy** | `path_policy.py` | Path canonicalization, Windows directory junction / symlink detection via `os.path.isjunction`, Cloud sync root identification, OS protected boundary guards. |
| **Capabilities** | `capabilities.py` | Host diagnostics (`doctor`), elevation check (enforces non-admin mode), fixed drive enumeration via `os.listdrives()`. |
| **Dust Backend** | `backends/dust.py` | Adapter for `bootandy/dust` v1.2.6. Invocations strictly use `-j -o b -p -P` and **never** `-L` (no link dereference). Handles path normalization to prevent Windows backslash escaping bugs. |
| **Native Backend** | `backends/native_windows.py` | Resilient scoped fallback scanner using `os.scandir`. Strictly aborts recursion at junction/reparse points. Does not crash on permission-denied subtrees. |
| **Scan Service** | `services/scan_service.py` | Coordinates backends, generates UUID-tracked `ScanSnapshot` objects, persists snapshots in `.investigation_cache/snapshots/`, provides sub-50ms drive overview. |
| **Drilldown Service**| `services/drilldown_service.py`| Target-focused exploration linking child scans to parent snapshots, calculating ratio-of-parent for dominant consumers ($\ge 15\%$). |
| **Specialized Detectors**| `detectors/` | Probes for `node_modules` (stale candidate analysis $>90\text{d}$), Python venvs, global caches, Docker VHDX / build cache, and large files. |
| **Risk Classifier** | `classifiers/risk_classifier.py` | Implements two-dimensional safety evaluation: Intrinsic Risk (`LOW`/`MEDIUM`/`HIGH`) vs Policy Disposition (`CLEANABLE`/`REVIEW_REQUIRED`/`BLOCKED`). |
| **Plan Generator** | `cleanup/plan_generator.py` | Prepares auditable `CleanupPlan` with pre-flight fingerprinting (expected kind, size, mtime) and HMAC-SHA256 signature binding to a session secret key. |
| **Safe Executor** | `cleanup/safe_executor.py` | Pre-flight check (TOCTOU mitigation & stale-plan defense). Cryptographic HMAC signature verification & schema validation. Executes ONLY explicitly selected item IDs. Routes file removals to Windows Recycle Bin via `SHFileOperationW`. |
| **Antigravity Skill**| `skills/disk-cleanup/SKILL.md` | Skill definition providing natural conversational workflows for Antigravity agents. |

---

## 3. Safety Guarantees & Defense-in-Depth

1. **Investigation Is Pure Read-Only**: The CLI `overview`, `scan`, `drilldown`, `detect-*`, and `cleanup-plan` commands do not alter a single byte on disk.
2. **Untrusted Plan Defense & HMAC-SHA256 Plan Signature**:
   - Each `CleanupPlan` is signed using an HMAC-SHA256 digest (`plan_hash`) derived from a machine/session secret key, covering all plan metadata, totals, and item payloads.
   - HMAC protects plans against accidental corruption, tampering, and modification by actors that do not possess the signing secret within the local user session.
   - The executor independently validates the plan schema (no duplicate IDs, matching counts, positive integers) and verifies the HMAC signature using `hmac.compare_digest`.
   - Modifying plan JSON items or recomputing hash without authorization causes immediate execution refusal (`PlanIntegrityError`).
   - All policies (system protection, cloud sync with 8.3 alias resolution, junction refusal, UNC checks) are independently re-evaluated during pre-flight regardless of plan claims.
3. **Critical Boundaries, 8.3 Short-Name Aliases, & Network Share Refusal**:
   - Explicitly rejects whole drive roots (`C:\`, `D:\`), `C:\Users`, all user profile roots under `C:\Users\*` (including Administrator, Default, other users), `C:\ProgramData`, and sensitive identity directories (`.ssh`, `.gnupg`, `Credentials`, `Vault`, `Crypto`, `Protect`, `.aws`).
   - Canonicalizes and resolves Windows 8.3 short-name aliases (e.g. `C:\PROGRA~1` $\rightarrow$ `C:\Program Files`) via `kernel32.GetLongPathNameW` and `os.path.realpath`, preventing alias-based blacklist evasion.
   - Rejects UNC / network share paths (`\\server\share`) and mapped network drives or removable media that do not guarantee local Windows Recycle Bin semantics.
4. **Pre-flight TOCTOU Mitigation & Stale-Plan Defense**: Before moving an item to the Recycle Bin, the executor re-checks:
   - Does the resource still exist?
   - Has its kind changed (e.g. directory replaced by a junction or symlink)?
   - Has its file size changed since plan creation?
   - Has its modification time (`mtime`) drifted by $>5.0$ seconds?
   - Does any ancestor directory contain a reparse point or junction (`has_reparse_point_ancestor`)?
   - In case of any I/O or permission errors during stat verification, the executor strictly fails closed (`VERIFY_FAILED`).
5. **No Wildcard Deletion**: The executor requires an explicit list of integer item IDs from a valid plan. Running with empty or missing item IDs fails closed immediately.
6. **Recycle Bin Fallback Protection**: Deleted files and folders are placed in the Windows Recycle Bin (`SHFileOperationW` with `FOF_ALLOWUNDO`), strictly validated for local `DRIVE_FIXED` volumes (`kernel32.GetDriveTypeW`). The executor never falls back to permanent deletion (`os.remove` / `shutil.rmtree`) if Recycle Bin fails.
7. **Safe Subprocess Execution**: Handlers are strictly typed (`RECYCLE_PATH`, `NPM_CACHE_CLEAN`, `PIP_CACHE_PURGE`, `DOCKER_BUILDER_PRUNE`). Typed cache cleanups dynamically verify paths against active runtime caches (`npm config get cache` / `pip cache dir`). Subprocesses run with `shell=False` and resolved executable paths via `shutil.which()`.
8. **Isolated State Cache & Volume Delta Measurement**: By default, cache and plans are stored in `%LOCALAPPDATA%\DiskInvestigator` (or configurable via `DISK_INVESTIGATOR_CACHE_DIR`). The executor measures actual `observed_volume_free_delta_bytes` before and after execution via `shutil.disk_usage` for transparent reporting.
