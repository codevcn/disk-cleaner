# General-Purpose Windows AI Storage Investigator (Windows 11)

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Windows%2011-0078D6.svg)](https://www.microsoft.com/windows/)
[![Architecture](https://img.shields.io/badge/safety-HMAC--SHA256%20%7C%20RecycleBin%20%7C%20Fail--Closed-success.svg)](#safety-invariants--threat-model)
[![Tests](https://img.shields.io/badge/tests-187%2F187%20passed%20(100%25)-brightgreen.svg)](#testing--verification)
[![Standalone](https://img.shields.io/badge/executable-single--file%20exe-orange.svg)](#standalone-executable-packaging)

An autonomous filesystem investigation and safe storage cleanup harness designed specifically for **Google Antigravity** AI agents and power users on **Windows 11**.

Transformed from a developer-only cleaner into a **General-Purpose Windows AI Storage Investigator**, covering 8 major software ecosystems: **System, Browser, Office, Creator, Streaming, Gaming, Developer, and AI/ML**, with strict healthcare/medical data protections.

Instead of a traditional "black-box" disk cleaner that blindly wipes files without context, **Disk Investigator** provides a conversational, forensic, and auditable storage optimization workflow:

$$\text{Capabilities} \longrightarrow \text{Investigation} \longrightarrow \text{Semantic Explanation} \longrightarrow \text{Auditable Plan v2} \longrightarrow \text{Human Approval Gate} \longrightarrow \text{Safe Execution} \longrightarrow \text{Verification}$$

---

## Table of Contents

1. [Architectural Overview](#architectural-overview)
2. [Multi-Domain Coverage](#multi-domain-coverage)
3. [Safety Invariants & Threat Model](#safety-invariants--threat-model)
4. [Standalone Executable Packaging](#standalone-executable-packaging)
5. [Autonomous In-App Self-Update & Non-Blocking SWR Engine](#autonomous-in-app-self-update--non-blocking-swr-engine)
6. [Complete CLI Command Reference](#complete-cli-command-reference)
   - [`doctor`](#1-doctor---environment--runtime-capabilities)
   - [`overview`](#2-overview---high-level-drive-analysis--50ms)
   - [`scan`](#3-scan---recursive-filesystem-scanning)
   - [`drilldown`](#4-drilldown---targeted-forensic-drilldown)
   - [`detect-dev`](#5-detect-dev---developer-artifacts--stale-caches)
   - [`detect-docker`](#6-detect-docker---wsl2-vhdx--docker-storage)
   - [`detect-large`](#7-detect-large---large-files-discovery)
   - [`cleanup-plan`](#8-cleanup-plan---cryptographically-signed-plan-generation)
   - [`execute-plan`](#9-execute-plan---two-phase-safe-execution)
   - [`check-update`](#10-check-update---github-release-inspection)
   - [`update`](#11-update---autonomous-in-app-self-update)
7. [AI Agent Integration (Google Antigravity Skill)](#ai-agent-integration-google-antigravity-skill)
8. [Testing & Verification](#testing--verification)

---

## Multi-Domain Coverage

| Domain | Cleanable Ephemeral Caches (TYPED_CLEANUP / RECYCLE) | Strictly Protected User Data (BLOCK / REVIEW_ONLY) |
|---|---|---|
| **System** | `%TEMP%` (>24h stale), `%LOCALAPPDATA%\Temp` | `%WINDIR%\System32`, System crash dumps (REVIEW_ONLY) |
| **Browser** | Chrome & Edge `Cache`, `Code Cache`, `GPUCache` | `History`, `Login Data`, `Cookies`, `Bookmarks`, `Sessions` (BLOCK) |
| **Office** | Office File Cache, Teams `Cache` / `blob_storage` | Outlook `.pst` (BLOCK), `.ost` offline mailbox (REVIEW_ONLY) |
| **Creator** | Premiere Media Cache, After Effects Disk Cache, CapCut cache, DaVinci `CacheClip` | Original video footage, `.prproj`, `.aep`, `.resolve` project DBs (BLOCK) |
| **Streaming** | OBS Studio `logs`, `crashes` | OBS stream recordings (`.mkv`, `.mp4`, `.flv`) (BLOCK) |
| **Gaming** | Steam Vulkan/DX `shadercache`, unfinished downloads | Steam installed games (`steamapps\common\*`), saves, mods (REVIEW_ONLY) |
| **Developer** | `node_modules` (with lockfile), `.venv`, cargo `target`, `.next`, `__pycache__` | Source code, uncommitted git trees, Docker `ext4.vhdx` (BLOCK) |
| **AI / ML** | (None silently deleted) | Ollama model weights, HuggingFace model cache (REVIEW_ONLY) |
| **Healthcare** | (None) | DICOM medical scans (`.dcm`, `.dicom`, DICM header) (BLOCK) |

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

### 7. Non-Destructive Recycle Bin & Certified Typed Actions
No raw permanent deletion (`rmdir /s /q` or `Remove-Item -Force`) is ever performed. All filesystem deletions are executed via the native Windows Shell API (`shell32.SHFileOperationW` with `FO_DELETE` and `FOF_ALLOWUNDO`), placing items safely into the **Windows Recycle Bin** where they can be restored if needed. Ephemeral caches for developer and container environments are reclaimed via certified typed CLI handlers (`npm cache clean --force`, `pip cache purge`, `docker builder prune -f`), and all actions enforce fail-closed process guards ensuring running user applications are never terminated or disturbed.

---

## Distribution Options

Disk Investigator provides four tailored distribution assets:

| Distribution | File / Command | Target User / Audience | Setup Experience |
| :--- | :--- | :--- | :--- |
| **1-Click All-in-One Installer (Canonical)** | `disk-investigator-setup.exe` | **End-users & AI Agents** | **Zero dependencies, single file**. Installs binary to `%LOCALAPPDATA%\DiskInvestigator\bin`, configures User `PATH` safely via Registry (`winreg`), installs Antigravity Skill (`SKILL.md`), and provides `uninstall.cmd`. |
| **Standalone 1-Click Uninstaller** | `disk-investigator-uninstall.exe` | **End-users & System Admins** | **Zero dependencies, single file**. 1-Click clean uninstallation of Disk Investigator. Restores User PATH, removes binary and unmodified skill, preserves customized files and user backups. Supports `--purge-data` and `--silent`. |
| **Standalone Portable CLI** | `.\disk_investigator.exe <command>` | **Advanced CLI Users** | Portable single binary. Zero runtime dependencies. Perfect for portable USB drives or air-gapped systems. |
| **Python Developer Package** | `python -m disk_investigator <command>` | **Developers & CI/CD** | Full source code with 140+ automated unit and destructive tests. |

---

## 1-Click All-in-One Installer (`disk-investigator-setup.exe`)

For end-users who just want to download a single file and immediately have full capabilities:

### Installation
1. Download **`disk-investigator-setup.exe`** from [GitHub Releases](https://github.com/codevcn/disk-cleaner/releases/latest).
2. Double-click or run from CMD/PowerShell:
   ```cmd
   disk-investigator-setup.exe
   ```
   *(Or run silently in background: `disk-investigator-setup.exe --silent`)*

### What the Installer Does Automatically:
- **Deploys Standalone Binary**: Installs `disk_investigator.exe` to `%LOCALAPPDATA%\DiskInvestigator\bin\`.
- **Configures User PATH (Registry Safe)**: Safely appends the binary directory to `HKCU\Environment\Path` using Python `winreg` and broadcasts `WM_SETTINGCHANGE`. Never uses `setx`, completely avoiding Windows 1024-character truncation bugs.
- **Deploys Antigravity AI Agent Skill**: Automatically copies `SKILL.md` to `%USERPROFILE%\.gemini\config\skills\disk-cleanup\SKILL.md`. If the user previously customized this skill, it automatically creates a safe backup (`SKILL.md.user-backup-<timestamp>`) before updating.
- **Deploys Reference Documentation**: Places technical documentation at `%LOCALAPPDATA%\DiskInvestigator\README.md` and `%USERPROFILE%\.gemini\config\skills\disk-cleanup\references\README.md` for AI Agent in-depth context.
- **Auditable Manifest**: Generates `%LOCALAPPDATA%\DiskInvestigator\install_manifest.json` with cryptographic SHA-256 hashes of all deployed files.
- **Automated Smoke Test**: Runs `disk_investigator --version` and `doctor` to verify readiness.

---

## Standalone Uninstaller (`disk-investigator-uninstall.exe`)

To cleanly remove Disk Investigator from your system, choose any of these convenient methods:
1. **Dedicated Uninstaller EXE**: Download and run **`disk-investigator-uninstall.exe`** directly from [GitHub Releases](https://github.com/codevcn/disk-cleaner/releases/latest).
2. **Local Shortcut**: Run `%LOCALAPPDATA%\DiskInvestigator\uninstall.cmd`.
3. **Installer CLI Flag**: Run `disk-investigator-setup.exe --uninstall`.

### Uninstaller Features & Safety Invariants:
- **Registry Restoration**: Cleanly removes `%LOCALAPPDATA%\DiskInvestigator\bin` from User PATH and broadcasts `WM_SETTINGCHANGE`.
- **Fail-Closed Process Protection**: Checks if `disk_investigator.exe` is running and aborts before any modifications. If process status is `UNKNOWN`, fails closed. Never terminates user processes.
- **Customization Preservation**: Checks cryptographic SHA-256 hash of `SKILL.md`. If customized by user or if backup files exist, they are 100% preserved.
- **Conservative Purge Mode (`--purge-data`)**: Removes tool-owned directories (`cache`, `logs`, `plans`) but **never deletes unknown user files**.
- **Deterministic Exit Codes**:
  - `0`: SUCCESS
  - `1`: FAILED
  - `2`: CANCELLED
  - `3`: PARTIAL
  - `4`: BLOCKED

---

## Standalone Executable Packaging

Disk Investigator includes an automated packaging pipeline that compiles the full application into standalone Windows executables:

### One-Click Build (`build.cmd`)

For quick, hands-free building on Windows, run `build.cmd`:

```cmd
build.cmd
```

`build.cmd` automatically:
1. Detects Python 3.12+ (`D:\Python-3-12\python.exe` or system PATH).
2. Verifies PyInstaller is installed.
3. Compiles `disk_investigator.exe` via `build_exe.py`.
4. Compiles the canonical 1-Click installer `disk-investigator-setup.exe` via `build_installer.py`.
5. Compiles the standalone uninstaller `disk-investigator-uninstall.exe` via `build_uninstaller.py`.
6. Enforces transactional builds and post-compilation quality gates.

### Packaging Scripts
- **`build_exe.py`**: Compiles standalone CLI binary `disk_investigator.exe` and updates `build_history.json`.
- **`build_installer.py`**: Packages `installer.py` embedding `disk_investigator.exe`, `SKILL.md`, and `README.md` into `disk-investigator-setup.exe`.
- **`build_uninstaller.py`**: Packages `uninstaller.py` embedding `SKILL.md` into standalone `disk-investigator-uninstall.exe`.

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

## Autonomous In-App Self-Update & Non-Blocking SWR Engine

Disk Investigator features a high-performance, resilient update system linked to the official repository: **[`codevcn/disk-cleaner`](https://github.com/codevcn/disk-cleaner)**. It is specifically engineered to operate seamlessly with AI agents and unattended automation.

### 1. Zero-Latency Non-Blocking Version Checking (SWR Engine)
- **Zero Latency on Foreground Commands**: Every routine execution (`doctor`, `overview`, `scan`, `investigate`, `cleanup-plan`, etc.) reads local cache at `%LOCALAPPDATA%\DiskInvestigator\updates\update_check.json` (24-hour TTL) without issuing synchronous network calls (0ms overhead).
- **Background Detached Worker**: If the cache is missing or older than 24 hours, the CLI automatically spawns a detached background child process (`disk_investigator _refresh-update-cache`). The foreground command proceeds instantly while the background process queries GitHub Releases and updates the cache atomically.
- **`stdout` Purity Guarantee**: If a newer version is detected, notice messages are printed **strictly to `stderr`**:
  ```text
  [disk_investigator] Notice: A new version is available: v2.4.4 (current: v2.4.3).
  [disk_investigator] Run 'disk_investigator update --yes' or visit https://github.com/codevcn/disk-cleaner/releases/tag/v2.4.4
  ```
  This preserves 100% JSON structure purity on `stdout`, completely preventing JSON parse crashes in AI agents.
- **Offline-First & Kill-Switch**: If there is no internet connection or GitHub is unreachable, the check silently continues without failing or displaying error messages. To completely disable version checks (e.g. in air-gapped or CI environments), set:
  ```cmd
  set DISK_INVESTIGATOR_NO_UPDATE_CHECK=1
  ```

### 2. Autonomous In-App Self-Update (`disk_investigator update --yes`)
When an update is detected, AI agents or users can perform a complete, transactional binary upgrade with a single command without needing Python, Git, or a web browser:

```bash
# Autonomously upgrade to the latest official release (unattended)
disk_investigator update --yes

# Check status and audit trail of previous updates
disk_investigator update --status
```

**Self-Update Lifecycle & Safety Architecture:**
1. **Official Release Resolution**: Queries GitHub Releases API for the latest immutable tag and asset manifest.
2. **Cryptographic Verification (SHA-256)**: Downloads candidate binary (`disk_investigator.exe` or `disk-investigator-setup.exe`) and `SHA256SUMS.txt` into an isolated staging directory (`%LOCALAPPDATA%\DiskInvestigator\updates\staged\`). Verifies the SHA-256 cryptographic hash before any execution.
3. **Single-Owner PID Concurrency Guard**: Enforces an exclusive file lock (`update.lock`) with cross-process PID inheritance (parent bootloader & child worker) to eliminate update races.
4. **Atomic Handoff & Rollback Defense**: The running binary stages replacement via transactional file swap with automatic `.bak` backup creation. If binary substitution encounters any error, an immediate rollback restores the previous working version.
5. **Environment & Skill Sync**: Updates the User Registry `PATH` (if needed) and synchronizes the Google Antigravity Skill (`%USERPROFILE%\.gemini\config\skills\disk-cleanup\SKILL.md`).
6. **Audit Receipt**: Writes full transaction metadata to `%LOCALAPPDATA%\DiskInvestigator\updates\receipt.json`.

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

Queries GitHub Releases (or inspects the local 24-hour cache) to report version availability.

```bash
# Check update status using local 24-hour cache
disk_investigator.exe check-update

# Force query bypassing the 24-hour cache
disk_investigator.exe check-update --force

# JSON envelope output for AI Agent integration
disk_investigator.exe check-update --force --json
```

**JSON Output Structure:**
```json
{
  "status": "success",
  "update_info": {
    "current_version": "2.4.4",
    "latest_version": "2.4.4",
    "update_available": false,
    "release_url": "https://github.com/codevcn/disk-cleaner/releases/tag/v2.4.4",
    "published_at": "2026-11-05T04:00:00Z",
    "cached": true
  }
}
```

---

### 11. `update` - Autonomous In-App Self-Update

Autonomously downloads, cryptographically verifies, and installs the latest official release directly from GitHub Releases without opening a browser or cloning source code.

- **Non-Interactive Upgrade**: Pass `--yes` (or `-y`) to skip interactive confirmation prompts (ideal for automated AI agents).
- **Audit Receipt**: Pass `--status` to inspect the last update receipt without making changes.
- **Fail-Closed Safety**: Enforces PID-aware file locking, SHA-256 integrity verification, and atomic swap with automatic `.bak` rollback on error.

```bash
# Check status of previous update
disk_investigator.exe update --status

# Autonomously upgrade to the latest official release
disk_investigator.exe update --yes

# Agent JSON envelope
disk_investigator.exe update --yes --json
```

**JSON Output Structure:**
```json
{
  "status": "success",
  "update": {
    "state": "handoff_started",
    "previous_version": "2.4.3",
    "target_version": "2.4.4",
    "asset_name": "disk_investigator.exe",
    "staged_path": "C:\\Users\\dell\\AppData\\Local\\DiskInvestigator\\updates\\staged\\disk_investigator.exe",
    "target_path": "C:\\Users\\dell\\AppData\\Local\\DiskInvestigator\\bin\\disk_investigator.exe",
    "message": "Update staged successfully. Handoff installer started."
  }
}
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

The test suite includes **187 comprehensive unit, integration, lifecycle, and packaged E2E tests (187/187 passed, 100% green)** covering all 8 storage domains, capability discovery, TOCTOU drift detection, HMAC plan integrity, 8.3 alias defense, Recycle Bin operations, typed action registry, non-blocking SWR update cache, and in-app self-update lifecycle:

```bash
# Run full test suite using Python test runner
python -m unittest discover -s disk_investigator/tests -v
```

### Verified Test Categories:
- **`TestCapabilities`**: Probe mocking, registry checks, filesystem & executable detection across 17 applications.
- **`TestMultiDomainDetectors`**: Chromium, Outlook, Office/Teams, Adobe, DaVinci, CapCut, OBS Studio, Steam, Ollama, HuggingFace, DICOM.
- **`TestFalsePositives`**: 13 mandatory boundary vectors (active OBS recordings, Outlook PST/OST, DaVinci project DBs, Premiere source media, Steam game installs, DICOM medical files).
- **`TestActionFramework`**: Action registry, tri-state process guards, Schema v2 validation, HMAC sealing of semantic provenance and action binding.
- **`TestBackends`**: Tests `dust` JSON parsing, native `os.scandir` fallback, partial traversal, and child incomplete flags.
- **`TestClassifiers`**: Verifies `CLEANABLE`, `REVIEW_REQUIRED`, and `BLOCKED` policy enforcement across OS paths, Cloud Sync roots, and Docker VHDX.
- **`TestDetectors`**: Tests `DeveloperDetector` (stale `node_modules`, `.venv`), `DockerDetector`, and `LargeFilesDetector`.
- **`TestPathPolicy`**: Tests NT canonicalization, critical boundary evaluation, and network share detection.
- **`TestServices`**: Tests `ScanService` and `DrilldownService` snapshot lifecycle.
- **`TestUpdateEngine` & `TestInstaller`**: Non-blocking SWR background worker, 24-hour cache TTL, PID concurrency lock, SHA-256 checksum verification, atomic swap & rollback, and packaged binary E2E self-update lifecycle.
- **`TestDestructiveE2E`**: 20 rigorous safety tests:
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
│   ├── __init__.py           # Package version definition (v2.4.4)
│   ├── __main__.py           # Application entry point
│   ├── cli.py                # Command-line interface & argument parser
│   ├── capabilities.py       # Host environment & tool capability discovery
│   ├── models.py             # Data models & JSON serialization schemas
│   ├── path_policy.py        # Path canonicalization & safety boundaries
│   ├── backends/             # Dust & Native Windows scanners
│   ├── classifiers/          # Semantic classifiers & risk evaluation
│   ├── detectors/            # Multi-domain storage detectors (Browser, Office, Creator, etc.)
│   ├── cleanup/              # Signed plan generator & safe executor
│   ├── services/             # Scan & drill-down snapshot services
│   └── tests/                # 187 comprehensive unit, integration, lifecycle & E2E tests
│
└── skills/
    └── disk-cleanup/         # Antigravity AI Agent Skill definition
        └── SKILL.md          # Skill instructions & conversational prompts
```

---

## License

Internal Developer Utility — Safe Storage Optimization for Windows 11 & Google Antigravity Agents.
