# Disk Investigator (Windows 11)

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%2011-0078D6.svg)](https://www.microsoft.com/windows/)
[![Architecture](https://img.shields.io/badge/safety-HMAC--SHA256%20%7C%20RecycleBin-success.svg)](#safety-invariants--threat-model)
[![Tests](https://img.shields.io/badge/tests-44%2F44%20passed%20(100%25)-brightgreen.svg)](#testing--verification)
[![Standalone](https://img.shields.io/badge/executable-single--file%20exe-orange.svg)](#standalone-executable-packaging)

An autonomous filesystem investigation and safe storage cleanup harness designed specifically for **Google Antigravity** AI agents and power users on **Windows 11**.

Instead of a traditional "black-box" disk cleaner that blindly wipes files without context, **Disk Investigator** provides a conversational, forensic, and auditable storage optimization workflow:

$$\text{Fast Overview} \longrightarrow \text{Targeted Drilldown} \longrightarrow \text{Semantic Explanation} \longrightarrow \text{Auditable Plan} \longrightarrow \text{Human Approval Gate} \longrightarrow \text{Safe Execution} \longrightarrow \text{Verification}$$

---

## Table of Contents

1. [Architectural Overview](#architectural-overview)
2. [Safety Invariants & Threat Model](#safety-invariants--threat-model)
3. [Dual Distribution Options](#dual-distribution-options)
4. [Standalone Executable Packaging](#standalone-executable-packaging)
   - [One-Click Build (`build.cmd`)](#one-click-build-buildcmd)
   - [Python Packaging Script (`build_exe.py`)](#python-packaging-script-build_exepy)
   - [Single-Executable Invariant & Build History (`build_history.json`)](#single-executable-invariant--build-history-build_historyjson)
5. [Autonomous GitHub Update Workflow](#autonomous-github-update-workflow)
   - [Automated Version Checking](#automated-version-checking-on-each-run)
   - [One-Click Agent Update (`update_from_github.py` / `update.cmd`)](#one-click-agent-update-update_from_githubpy--updatecmd)
6. [Complete CLI Command Reference](#complete-cli-command-reference)
   - [`doctor`](#1-doctor---environment--runtime-capabilities)
   - [`overview`](#2-overview---high-level-drive-analysis-50ms)
   - [`scan`](#3-scan---recursive-filesystem-scanning)
   - [`drilldown`](#4-drilldown---targeted-forensic-drilldown)
   - [`detect-dev`](#5-detect-dev---developer-artifacts--stale-caches)
   - [`detect-docker`](#6-detect-docker---wsl2-vhdx--docker-storage)
   - [`detect-large`](#7-detect-large---large-files-discovery)
   - [`cleanup-plan`](#8-cleanup-plan---cryptographically-signed-plan-generation)
   - [`execute-plan`](#9-execute-plan---two-phase-safe-execution)
   - [`check-update`](#10-check-update---github-release-inspection)
7. [AI Agent Integration (Google Antigravity Skill)](#ai-agent-integration-google-antigravity-skill)
8. [Testing & Verification](#testing--verification)
9. [Project Structure](#project-structure)

---

## Architectural Overview

```
                      +-----------------------------+
                      |   Google Antigravity Agent  |
                      |   (or Human CLI Operator)   |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |   /disk-cleanup Skill       |
                      |   (Reasoning + Orchestration)
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |  disk_investigator Harness   |
                      |  (CLI / Standalone EXE)     |
                      +--------------+--------------+
                                     |
         +---------------------------+---------------------------+
         |                           |                           |
         v                           v                           v
+------------------+       +-------------------+       +--------------------+
|  Dual Scanner    |       | Semantic Analysis |       | 2-Phase Safety Gate|
|  - Dust (Rust)   |       | - Dev Detector    |       | - HMAC-SHA256 Sign |
|  - Win32 Native  |       | - Docker / WSL2   |       | - TOCTOU Defense   |
|  - Junction Loop |       | - Large Files     |       | - 8.3 Alias Guard  |
+------------------+       +-------------------+       +--------------------+
         |                           |                           |
         +---------------------------+---------------------------+
                                     |
                                     v
                      +-----------------------------+
                      | Windows Shell Recycle Bin   |
                      | (SHFileOperationW Undoable) |
                      +-----------------------------+
```

---

## Safety Invariants & Threat Model

Disk Investigator enforces strict, fail-closed security invariants at both the investigation and execution layers:

### 1. Read-Only by Default
All investigation commands (`doctor`, `overview`, `scan`, `drilldown`, `detect-*`, `cleanup-plan`) are **strictly read-only**. They examine disk usage, inspect metadata, and generate structured reports without altering a single byte on disk.

### 2. Cryptographic Plan Integrity (HMAC-SHA256)
Every generated `CleanupPlan` is sealed with an **HMAC-SHA256** signature using an isolated, ephemeral session secret stored under `.investigation_cache/secret.key`. Any manual tampering with target paths, risk classifications, or plan parameters immediately invalidates the signature and causes the execution engine to fail closed.

### 3. TOCTOU & Stale-Plan Defense
Between the time a plan is generated and the moment the user approves execution, files can be modified, replaced, or swapped. Before any operation:
- **Pre-flight verification** confirms each target's current file size and modification time (`mtime`) against the snapshot taken at planning time.
- If any drift is detected, execution aborts with a `STALE_PLAN` refusal.

### 4. Windows 8.3 Short-Name Alias Defense
Adversarial or malformed paths using legacy 8.3 short-name aliases (e.g. `C:\PROGRA~1` for `C:\Program Files`, or short aliases pointing into Cloud Sync folders) are resolved to their fully canonical, long NTFS forms before any policy validation or boundary checks take place.

### 5. Reparse Point & Junction Loop Prevention
The scanning engine recognizes directory junctions, symlinks, and volume mounts. It refuses to recurse across junctions or treat junctions as disposable folders, preventing infinite loops and catastrophic deletion across volume boundaries.

### 6. Critical Boundary Protections
The system strictly hard-blocks cleanup targeting:
- Operating system roots (`C:\Windows`, `System32`, `WinSxS`).
- Cloud storage synchronization roots (OneDrive, Dropbox, Google Drive, iCloud).
- User profile root directories (`C:\Users\<User>`).
- WSL2 Virtual Hard Disks (`ext4.vhdx`).
- Non-fixed or mapped network drives (UNC paths, WebDAV, SMB shares).

### 7. Non-Destructive Recycle Bin Only
No raw permanent deletion (`rmdir /s /q` or `Remove-Item -Force`) is ever performed. All deletions are executed via the native Windows Shell API (`shell32.SHFileOperationW` with `FO_DELETE` and `FOF_ALLOWUNDO`), placing items safely into the **Windows Recycle Bin** where they can be restored if needed.

---

## Dual Distribution Options

Disk Investigator can be operated interchangeably in two modes:

| Mode | Command Invocation | Dependencies | Use Case |
| :--- | :--- | :--- | :--- |
| **Standalone Portable EXE** | `.\disk_investigator.exe <command>` | None (self-contained Windows binary) | Plug-and-play, portable distributions, air-gapped systems |
| **Python Package** | `python -m disk_investigator <command>` | Python 3.12+ | Development, local debugging, test runner |

Both modes share the exact same JSON schema, command arguments, and security policies.

---

## Standalone Executable Packaging

Disk Investigator includes an automated packaging pipeline that compiles the full application into a single, high-performance `.exe` binary located directly in the project root.

### One-Click Build (`build.cmd`)

For quick, hands-free building on Windows, run `build.cmd` directly from PowerShell, Command Prompt, or by double-clicking in File Explorer:

```cmd
build.cmd
```

`build.cmd` automatically:
1. Detects the Python 3.12+ installation (`D:\Python-3-12\python.exe` or system PATH).
2. Verifies whether `PyInstaller` is available (and installs it via pip if missing).
3. Executes `build_exe.py`.
4. Returns proper exit codes for automated CI/CD and script harnesses.

### Python Packaging Script (`build_exe.py`)

You can also run the packaging script directly via Python:

```bash
# Build standalone binary
python build_exe.py

# Display build history manifest
python build_exe.py --history

# Clean up root executable and temporary files
python build_exe.py --clean-only

# Override version tag
python build_exe.py --version 2.0.4
```

### Single-Executable Invariant & Build History (`build_history.json`)

To prevent repository clutter and confusion across builds, `build_exe.py` enforces three core rules:

1. **Strict Single-Executable Invariant**:
   In the root directory, there is **only ever exactly one** `.exe` file (`disk_investigator.exe`).
2. **Pre-Build Removal of Previous Binaries**:
   From the second build onwards, the script automatically removes the old `disk_investigator.exe` before compilation. If the file is currently locked by a running process, it aborts cleanly with a warning instructing the user to terminate the active instance.
3. **Build History Management (`build_history.json`)**:
   Every successful build is recorded in `build_history.json` with comprehensive audit metadata:
   - `build_number`: Incremental integer (1, 2, 3...)
   - `version`: Application semantic version (e.g. `2.0.3`)
   - `timestamp`: ISO-8601 timestamp with local timezone offset
   - `executable`: Output binary name (`disk_investigator.exe`)
   - `file_size_bytes`: Exact binary size in bytes
   - `file_size_formatted`: Human-readable size (e.g. `8.00 MB`)
   - `sha256`: SHA-256 cryptographic checksum of the resulting binary
   - `build_duration_sec`: Compilation time in seconds
   - `python_version` & `pyinstaller_version`: Environment runtime info
   - `status`: Execution status (`SUCCESS`)

Example `build_history.json`:
```json
{
  "latest": {
    "build_number": 2,
    "version": "2.0.3",
    "timestamp": "2026-10-31T01:17:23.322364+07:00",
    "executable": "disk_investigator.exe",
    "file_size_bytes": 8383666,
    "file_size_formatted": "8.00 MB",
    "sha256": "89d1c241981ee832c03a2f26fbb9d72601fdb05521e7e7ea1b1d22c7e51ffaa7",
    "build_duration_sec": 19.93,
    "python_version": "3.12.0",
    "pyinstaller_version": "6.11.1",
    "platform": "Windows 11 (AMD64)",
    "status": "SUCCESS"
  },
  "history": [ ... ]
}
```

---

## Autonomous GitHub Update Workflow

Disk Investigator includes an end-to-end update system linked to the official repository: **[`codevcn/disk-cleaner`](https://github.com/codevcn/disk-cleaner)**.

### Automated Version Checking on Each Run
- Every time `disk_investigator` runs (e.g. `doctor`, `overview`, `scan`), it checks the local cache (`.investigation_cache/update_status.json`, 1-hour TTL) or queries the GitHub Releases API.
- If a newer version is published on GitHub:
  - An unobtrusive banner is printed to `stderr` (preserving `stdout` JSON integrity for agents).
  - The `doctor` command output includes the full `"update_check"` status.

### One-Click Agent Update (`update_from_github.py` / `update.cmd`)
When an update is detected, the user simply asks the AI Agent:
> *"Có bản cập nhật mới trên GitHub, hãy cập nhật giúp tôi."*

The Agent executes `python update_from_github.py` (or `update.cmd`), which autonomously executes the full lifecycle:
1. **GitHub Pull**: Fetches and pulls latest commits from `origin/main`.
2. **Automated Verification**: Runs all 48 tests (`python -m unittest discover -s disk_investigator/tests`) to ensure 100% test integrity.
3. **Executable Recompilation**: Invokes `build_exe.py` to regenerate the standalone binary `disk_investigator.exe` in the root folder, incrementing `build_history.json`.
4. **Antigravity Skill Sync**: Synchronizes the updated `SKILL.md` to `~/.gemini/config/skills/disk-cleanup/SKILL.md`.
5. **Cache Refresh**: Invalidates update check cache.

```bash
# Check update status manually
python update_from_github.py --check
# or
update.cmd --check

# Execute full autonomous update
python update_from_github.py
# or
update.cmd
```

---

## Complete CLI Command Reference

All CLI commands output structured JSON to standard output (`stdout`), making them immediately parseable by automated agents like Google Antigravity. Use `--compact` for single-line JSON.

### 1. `doctor` - Environment & Runtime Capabilities

Inspects system environment, storage drives, elevation status, and external tool backends (`dust`, `docker`, `czkawka`).

```bash
disk_investigator.exe doctor
# or
python -m disk_investigator doctor
```

**JSON Output Structure:**
```json
{
  "status": "success",
  "doctor": {
    "os": {
      "system": "Windows",
      "release": "11",
      "version": "10.0.26200",
      "platform": "Windows-11-10.0.26200-SP0",
      "is_windows": true
    },
    "python": {
      "version": "3.12.0",
      "has_listdrives": true,
      "has_isjunction": true
    },
    "security": {
      "is_admin": false,
      "execution_mode": "NON-ELEVATED (Standard)",
      "safety_recommendation": "Running non-elevated is safe for standard investigation."
    },
    "storage": {
      "drives_count": 2,
      "drives": ["C:\\", "D:\\"],
      "drive_details": {
        "C:\\": { "total_bytes": 262089469952, "used_bytes": 210982121472, "free_bytes": 51107348480, "percent_used": 80.5 },
        "D:\\": { "total_bytes": 230016675840, "used_bytes": 197537538048, "free_bytes": 32479137792, "percent_used": 85.88 }
      }
    },
    "tools": {
      "dust": { "available": true, "path": "...\\dust.EXE", "version": "Dust 1.2.6" },
      "docker": { "available": true }
    },
    "recommendation": "Ready for high-speed scanning with DustBackend."
  }
}
```

---

### 2. `overview` - High-Level Drive Analysis (< 50ms)

Provides instantaneous drive utilization breakdown and enumerates root-level storage consumers.

```bash
# Overview for all mounted drives
disk_investigator.exe overview

# Overview for a specific drive
disk_investigator.exe overview D:

# Force native Python scanner
disk_investigator.exe overview D: --backend native
```

---

### 3. `scan` - Recursive Filesystem Scanning

Recursively analyzes directory sizes down to a specified depth. Uses the high-speed Rust `dust` backend if present, falling back gracefully to the safe Windows native backend.

```bash
disk_investigator.exe scan "C:\Users\dell" --depth 2 --only-dir --max-entries 25
```

| Option | Shorthand | Default | Description |
| :--- | :--- | :--- | :--- |
| `--depth` | `-d` | `1` | Depth of recursive scanning |
| `--max-entries` | `-n` | `30` | Maximum number of top consumers returned |
| `--only-dir` | `-D` | `false` | Restrict output to directories only |
| `--backend` | | `auto` | Force backend (`dust` or `native`) |

---

### 4. `drilldown` - Targeted Forensic Drilldown

Performs a targeted, deep dive into a specific storage hotspot. Every drilldown operation generates a unique, queryable `snapshot_id` saved under `.investigation_cache/` for audit lineage.

```bash
disk_investigator.exe drilldown "C:\Users\dell\AppData\Local" --depth 2 --max-entries 20
```

---

### 5. `detect-dev` - Developer Artifacts & Stale Caches

Scans paths for developer dependencies, build outputs, package caches, and virtual environments:
- `node_modules` (including stale detection: age > 90 days)
- Python virtual environments (`.venv`, `venv`, `env`)
- Next.js build caches (`.next`)
- Rust Cargo target directories (`target/`)
- Global package caches (`pip cache`, `npm-cache`, `.pnpm-store`)

```bash
# Scan local repository or directory
disk_investigator.exe detect-dev "D:\D-Personal\my-project"

# Include global user caches (AppData, npm, pip)
disk_investigator.exe detect-dev . --include-global
```

---

### 6. `detect-docker` - WSL2 VHDX & Docker Storage

Inspects Docker storage footprint on Windows. Identifies:
- Backing WSL2 `ext4.vhdx` virtual disk locations and actual allocated sizes.
- Docker daemon breakdown (images, containers, build cache) if Docker daemon is running.
- **Safety**: Strictly marks `ext4.vhdx` as `BLOCKED` to prevent accidental corruption of WSL2 distributions.

```bash
disk_investigator.exe detect-docker
```

---

### 7. `detect-large` - Large Files Discovery

Locates individual files exceeding a size threshold (default: 100 MB). Returns an itemized list sorted by size alongside extension-based category breakdowns (Archives, Media, Virtual Disks, Binaries, Documents).

```bash
disk_investigator.exe detect-large "C:\Users\dell\Downloads" --min-size-mb 100 --max-entries 50
```

---

### 8. `cleanup-plan` - Cryptographically Signed Plan Generation

Generates a structured, auditable `CleanupPlan` without deleting any data. Evaluates paths against safety policies, classifies risks (`LOW`, `MEDIUM`, `HIGH`), assigns dispositions (`CLEANABLE`, `REVIEW_REQUIRED`, `BLOCKED`), and seals the plan with an HMAC-SHA256 signature.

```bash
# Generate plan for developer artifacts in a folder
disk_investigator.exe cleanup-plan "D:\D-Personal\old-projects"

# Generate plan including global caches
disk_investigator.exe cleanup-plan . --include-global
```

**Plan Output Sample:**
```json
{
  "status": "success",
  "plan_id": "plan_9f81a7b4",
  "plan_hash": "2f4e8b...",
  "created_at": "2026-10-31T01:20:00+07:00",
  "summary": {
    "total_items": 3,
    "cleanable_items": 2,
    "review_required_items": 1,
    "blocked_items": 0,
    "cleanable_bytes": 1073741824
  },
  "items": [
    {
      "item_id": 1,
      "path": "D:\\old-project\\.next",
      "size_bytes": 524288000,
      "risk": "LOW",
      "disposition": "CLEANABLE",
      "action": "recycle_directory",
      "description": "Next.js build cache",
      "can_auto_recreate": true
    }
  ]
}
```

---

### 9. `execute-plan` - Two-Phase Safe Execution

Executes specific approved items from an existing `CleanupPlan`.

- **Dry-Run by Default**: Without `--apply`, previews actions and runs pre-flight TOCTOU / policy verification without moving any files.
- **Explicit Item Selection Required**: Must pass `--items <id1,id2,...>` to select exact IDs.
- **Windows Recycle Bin**: When `--apply` is specified, items are moved to the Windows Recycle Bin (`FOF_ALLOWUNDO`).

```bash
# 1. Preview execution in Dry-Run mode
disk_investigator.exe execute-plan plan_9f81a7b4 --items 1,2

# 2. Apply execution ONLY after explicit human approval
disk_investigator.exe execute-plan plan_9f81a7b4 --items 1,2 --apply
```

---

### 10. `check-update` - GitHub Release Inspection

Queries GitHub to check if a newer version of the tool is available.

```bash
disk_investigator.exe check-update

# Force query bypassing the 1-hour cache
disk_investigator.exe check-update --force
```

---

## AI Agent Integration (Google Antigravity Skill)

Disk Investigator natively registers as the **`/disk-cleanup`** skill in Google Antigravity:

- **Location**: `C:\Users\dell\.gemini\config\skills\disk-cleanup\SKILL.md`
- **Agent Prompt**: Type `/disk-cleanup` in chat to initiate a guided storage investigation.

### Agent Workflow:
```
User: "Ổ D của tôi sắp đầy, hãy điều tra giúp tôi."
  │
  ├──> Step 1: Agent runs `overview D:` to identify top storage folders.
  ├──> Step 2: Agent runs `drilldown` on the largest hotspots.
  ├──> Step 3: Agent explains the semantic purpose of each directory to the user.
  ├──> Step 4: Agent generates a `cleanup-plan`.
  ├──> Step 5: Agent presents an itemized preview and requests Human Approval.
  ├──> Step 6: User approves specific items (e.g. Items #1, #3).
  ├──> Step 7: Agent executes `execute-plan <plan_id> --items 1,3 --apply`.
  └──> Step 8: Agent verifies reclaimed free space on the drive.
```

---

## Testing & Verification

The test suite includes **44 comprehensive unit and destructive end-to-end tests** covering all safety mechanisms, TOCTOU drift detection, HMAC plan integrity, 8.3 alias defense, and Recycle Bin operations:

```bash
# Run full test suite using Python test runner
python -m unittest discover -s disk_investigator/tests -v
```

### Verified Test Categories:
- **`TestBackends`**: Tests `dust` JSON parsing, native `os.scandir` fallback, partial traversal, and child incomplete flags.
- **`TestClassifiers`**: Verifies `CLEANABLE`, `REVIEW_REQUIRED`, and `BLOCKED` policy enforcement across OS paths, Cloud Sync roots, and Docker VHDX.
- **`TestDetectors`**: Tests `DeveloperDetector` (stale `node_modules`, `.venv`), `DockerDetector`, and `LargeFilesDetector`.
- **`TestPathPolicy`**: Tests NT canonicalization, critical boundary evaluation, and network share detection.
- **`TestServices`**: Tests `ScanService` and `DrilldownService` snapshot lifecycle.
- **`TestDestructiveE2E`**: 15 rigorous safety tests:
  - Recycle Bin sibling preservation
  - TOCTOU size drift and mtime drift refusal
  - Directory junction swap refusal (direct and parent junctions)
  - Windows 8.3 short-name alias bypass refusal
  - HMAC tamper detection and invalid hash refusal
  - Duplicate item ID refusal
  - Non-fixed / mapped drive refusal
  - Cross-volume free space delta measurement

---

## Project Structure

```
d:\D-Personal\disk-cleaner\
├── disk_investigator.exe      # Single-file standalone executable (in root)
├── build.cmd                 # One-click Windows build script
├── build_exe.py              # Packaging script enforcing single .exe & history
├── build_history.json        # Build manifest tracking version, hash, timestamp
├── README.md                 # Project documentation & reference manual
├── ARCHITECTURE.md           # In-depth architectural design specifications
├── PROJECT_STATE.md          # Current project state & audit log
│
├── disk_investigator/        # Core Python package
│   ├── __init__.py           # Package version definition (v2.0.3)
│   ├── __main__.py           # Application entry point
│   ├── cli.py                # Command-line interface & argument parser
│   ├── capabilities.py       # Host environment & tool capability discovery
│   ├── models.py             # Data models & JSON serialization schemas
│   ├── path_policy.py        # Path canonicalization & safety boundaries
│   ├── backends/             # Dust & Native Windows scanners
│   ├── classifiers/          # Semantic classifiers & risk evaluation
│   ├── detectors/            # Specialized detectors (Dev, Docker, Large)
│   ├── cleanup/              # Signed plan generator & safe executor
│   ├── services/             # Scan & drill-down snapshot services
│   └── tests/                # 44 unit & destructive E2E tests
│
└── skills/
    └── disk-cleanup/         # Antigravity AI Agent Skill definition
        └── SKILL.md          # Skill instructions & conversational prompts
```

---

## License

Internal Developer Utility — Safe Storage Optimization for Windows 11 & Google Antigravity Agents.
