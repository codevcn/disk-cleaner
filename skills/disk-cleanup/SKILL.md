---
name: disk-cleanup
description: "AI-native disk investigation and safe storage cleanup for Windows 11. General-purpose Windows AI Storage Investigator across System, Browser, Office, Creator, Streaming, Gaming, Developer, and AI/ML storage domains. Explores hierarchies, explains semantics, and generates auditable cleanup plans with mandatory human approval."
compatibility:
  - Windows 11
  - Google Antigravity Agent
requires:
  - Python 3.12+
  - dust CLI (optional but recommended for high-speed scanning)
keywords:
  - disk-cleanup
  - storage-analyzer
  - windows-cleanup
  - disk-investigation
  - multi-domain
  - creator-cache
  - browser-cache
  - ai-models
  - node_modules
  - docker
---

# Windows AI Storage Investigator Skill (Windows 11)

## 1. Overview & Core Philosophy

This skill turns Antigravity into a **General-Purpose Windows AI Storage Investigator & Safe Storage Optimizer** on Windows 11. It operates across 8 major application ecosystems with rigorous false-positive safety hardening.

### Core Invariants:
1. **READ-ONLY BY DEFAULT**: In the investigation phase, NEVER delete, move, or modify any files or directories.
2. **Investigation First, Clean Second**:
   $$\text{Capabilities} \rightarrow \text{Investigation} \rightarrow \text{Semantic Explanation} \rightarrow \text{Cleanup Plan v2} \rightarrow \text{Human Approval Gate} \rightarrow \text{Typed Execution} \rightarrow \text{Verification}$$
3. **No Raw Destructive Commands**: Never generate or execute arbitrary `Remove-Item -Recurse -Force` or `rmdir /s /q` commands.
4. **Human Approval Gate**: Never delete files without showing an itemized preview and receiving explicit confirmation from the user (`item_ids` required).
5. **Safe Recycle Bin & Process Protection**:
   - Cache file cleanup uses Windows Recycle Bin (`SHFileOperationW`) or certified typed CLI handlers (`npm cache clean`, `pip cache purge`, `docker builder prune`).
   - Running user applications (Chrome, Edge, OBS, Premiere, Teams) are **never terminated**; active app caches are skipped safely.
6. **Strict Semantic Protection**:
   - **Original Video/Footage & Projects**: `.mp4`, `.mov`, `.prproj`, `.aep`, `.resolve` are **permanently BLOCKED** from deletion.
   - **Email Archives**: Outlook `.pst` files are strictly **BLOCKED**; `.ost` files are **REVIEW_ONLY** (never auto-cleaned).
   - **Browser Profiles**: History, Login Data, Cookies, Bookmarks are strictly **BLOCKED**.
   - **Virtual Disks**: Docker `ext4.vhdx` and VM disks are strictly **BLOCKED** from raw deletion.
   - **Medical Records**: DICOM imaging data (`.dcm`, `.dicom`) is strictly **BLOCKED**.
   - **AI Models & Games**: Ollama blobs, HuggingFace hub caches, and Steam installed games require **explicit human review** (never silently wiped).

---

## 2. Multi-Domain Storage Coverage

| Domain | Cleanable Ephemeral Caches (TYPED_CLEANUP / RECYCLE) | Strictly Protected User Data (BLOCK / REVIEW_ONLY) |
|---|---|---|
| **System** | `%TEMP%` (>24h stale), `%LOCALAPPDATA%\Temp` | `%WINDIR%\System32`, System crash dumps (REVIEW_ONLY) |
| **Browser** | Chrome & Edge `Cache`, `Code Cache`, `GPUCache` | `History`, `Login Data`, `Cookies`, `Bookmarks`, `Sessions` |
| **Office** | Office File Cache, Teams `Cache` / `blob_storage` | Outlook `.pst` (BLOCK), `.ost` offline mailbox (REVIEW_ONLY) |
| **Creator** | Premiere Media Cache, After Effects Disk Cache, CapCut cache, DaVinci `CacheClip` | Original video footage, `.prproj`, `.aep`, `.resolve` project DBs |
| **Streaming** | OBS Studio `logs`, `crashes` | OBS stream recordings (`.mkv`, `.mp4`, `.flv`) |
| **Gaming** | Steam Vulkan/DX `shadercache`, unfinished downloads | Steam installed games (`steamapps\common\*`), saves, mods |
| **Developer** | `node_modules` (with lockfile), `.venv`, cargo `target`, `.next`, `__pycache__` | Source code, uncommitted git trees, Docker `ext4.vhdx` |
| **AI / ML** | (None silently deleted) | Ollama model weights, HuggingFace model cache (REVIEW_ONLY) |
| **Healthcare** | (None) | DICOM medical scans (`.dcm`, `.dicom`, DICM header) (BLOCK) |

---

## 3. CLI Command Reference

Execute directly via Python or standalone binary:

```bash
# Using Python module:
python -m disk_investigator <command>

# Or using global executable:
disk_investigator <command>
```

### 1. Capability Discovery
```bash
python -m disk_investigator discover-capabilities
```
Detects installed software ecosystems (browsers, IDEs, creative suites, streaming tools, game launchers, AI runtimes) non-invasively via Registry, FileSystem, and Executable probes.

### 2. Full Multi-Domain Storage Investigation
```bash
python -m disk_investigator investigate [path]
```
Runs capability discovery, applicable modular detectors, and artifact correlation. Reports detected storage by domain, action, and category with fail-closed safety indicators.

### 3. Drive Overview & Fast Scan
```bash
python -m disk_investigator overview [drive]
python -m disk_investigator scan <path> --depth <N>
python -m disk_investigator drilldown <path>
```
High-speed exploration of drive capacity, filesystem trees, and top consumers using Dust backend or native Windows scanner.

### 4. Specialized Legacy Inspection
```bash
python -m disk_investigator detect-dev [path] [--include-global]
python -m disk_investigator detect-docker
python -m disk_investigator detect-large <path> --min-size-mb 100
```

### 5. Generate Auditable Cleanup Plan v2
```bash
python -m disk_investigator cleanup-plan [path] [--include-global]
```
Generates a structured `CleanupPlan` (Schema v2) with cryptographic HMAC-SHA256 signature, eliminating overlapping items and excluding blocked user data.

### 6. Safe Plan Execution
```bash
# Dry run preview (default):
python -m disk_investigator execute-plan <plan_id> --items 1,2,5

# Apply approved cleanup items:
python -m disk_investigator execute-plan <plan_id> --items 1,2,5 --apply
```

---

## 4. Interaction Guide for AI Agents

When assisting a user with disk cleanup or storage investigation:
1. **Always run `discover-capabilities` or `investigate` first** to understand what software ecosystems and cache footprints exist on the machine.
2. **Present a clear domain breakdown** (e.g. System, Creator, AI/ML, Developer, Browser) with exact byte counts.
3. **Never attempt to clean items marked `BLOCK` or `REVIEW_ONLY`**. Explain to the user why items like model weights, games, or PST archives require manual management.
4. **Generate a `cleanup-plan`** and present the proposed items to the user with exact paths, sizes, and risk levels.
5. **Obtain explicit user approval** before running `execute-plan --apply`.
