---
name: disk-cleanup
description: "AI-native disk investigation and safe storage cleanup for Windows 11. Explores filesystem hierarchies top-down, drills down into storage hotspots, explains folder semantics, and generates auditable cleanup plans with mandatory human approval."
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
  - node_modules
  - docker
  - cache-cleaner
---

# Disk Cleanup & Investigation Skill for Windows 11

## 1. Overview & Core Philosophy

This skill turns Antigravity into an **Autonomous Disk Space Investigator & Safe Storage Optimizer** on Windows 11.

### Invariants:
1. **READ-ONLY BY DEFAULT**: In the investigation phase, NEVER delete, move, or modify any files or directories.
2. **Investigation First, Clean Second**:
   $$\text{Overview} \rightarrow \text{Drill-down} \rightarrow \text{Semantic Explanation} \rightarrow \text{Cleanup Plan} \rightarrow \text{Human Approval Gate} \rightarrow \text{Execution} \rightarrow \text{Verification}$$
3. **No Raw Destructive Commands**: Never generate or execute arbitrary `Remove-Item -Recurse -Force` or `rmdir /s /q` commands.
4. **Human Approval Gate**: Never delete files without showing an itemized preview and receiving explicit confirmation from the user.
5. **Safe Recycle Bin**: All file/folder cleanup actions move items to the Windows Recycle Bin (`SHFileOperationW`) so the user can easily restore anything if needed.

---

## 2. CLI Interface

The underlying harness can be executed directly as a global command on Windows 11 after running the 1-Click Setup (`disk-investigator-setup.exe`), or directly via the standalone binary `.\disk_investigator.exe` / Python `python -m disk_investigator`.

```bash
# Global command (Installed via disk-investigator-setup.exe):
disk_investigator <command>

# Or using local standalone executable:
.\disk_investigator.exe <command>

# Or using Python module from repository:
python -m disk_investigator <command>
```

### Command Reference:

#### 1. System Doctor & Capabilities
```bash
python -m disk_investigator doctor
```
Checks installed runtimes, available local drives, Dust backend availability, and execution elevation (always prefers non-elevated for safety).

#### 2. Fast Drive Overview (< 50ms)
```bash
python -m disk_investigator overview [drive]
```
Returns drive capacity (total, used, free, percentage) and top root-level directory entries.

#### 3. Deep Path Scanning
```bash
python -m disk_investigator scan <path> --depth <N> [--only-dir]
```
Recursively measures directory sizes. Uses `dust -j` if available, or native Python scoped fallback. Does not cross junction loops or symlinks.

#### 4. Targeted Drilldown
```bash
python -m disk_investigator drilldown <path> [--depth 2] [--parent-snapshot <ID>]
```
Explores a specific hotspot, links to previous session snapshot ID, and returns `dominant_consumers` (subdirectories taking > 15% of the folder).

#### 5. Developer Waste Detection
```bash
python -m disk_investigator detect-dev [path] [--include-global]
```
Detects `node_modules` (annotating age > 90 days as stale candidate), Python virtual environments (`.venv`), Cargo target directories, Next.js build artifacts (`.next`), and package caches (`npm-cache`, `pip cache`).

#### 6. Docker Storage Breakdown
```bash
python -m disk_investigator detect-docker
```
Inspects WSL2 `ext4.vhdx` virtual hard disks (strictly marked as `BLOCKED` from raw deletion) and daemon caches.

#### 7. Large Files Detection
```bash
python -m disk_investigator detect-large <path> --min-size-mb <N>
```
Finds files larger than N megabytes (default 100MB), categorizing them into `disk_image`, `video`, `installer`, `archive`, `ai_model`, etc.

#### 8. Generate Cleanup Plan (No Deletion)
```bash
python -m disk_investigator cleanup-plan <path> [--include-global]
```
Generates a structured `CleanupPlan` with unique `plan_id`, risk levels (🟢 LOW / 🟡 MEDIUM / 🔴 HIGH), and estimated reclaimable bytes.

#### 9. Execute Plan (Requires Explicit User Approval)
```bash
# Dry-run preview:
python -m disk_investigator execute-plan <plan_id> --items 1,2

# Actual execution after user confirms:
python -m disk_investigator execute-plan <plan_id> --items 1,2 --apply
```
Pre-flights every item (verifies resource still exists, not inside Windows system or cloud sync roots), moves target files to the Windows Recycle Bin or runs typed cache purges.

---

## 3. Conversational Interaction Protocol

When interacting with the user:

### Step 1: Initial Assessment
- Acknowledge the user's request.
- Run `python -m disk_investigator overview C:` (or target drive).
- Present high-level numbers: total, used, free space.
- Highlight the largest candidate areas (e.g. `C:\Users`).

### Step 2: Iterative Drilldown
- Ask or proceed to drill into the dominant directory:
  `python -m disk_investigator drilldown "C:\Users\<user>\AppData"`
- Identify anomalies (e.g. Docker virtual disk, npm cache, IDE cache).

### Step 3: Semantic Explanation
- Answer the user's questions naturally:
  - *What is this folder?* (e.g., "npm-cache contains downloaded JavaScript packages").
  - *Can it be deleted safely?* (e.g., "Yes, npm will re-download packages if needed").
  - *What happens if I delete it?* (Explain clearly).

### Step 4: Proposing a Plan
- Run `python -m disk_investigator cleanup-plan <path>`.
- Present the plan in a clear table:
  | ID | Mục dọn dẹp | Dung lượng | Mức độ an toàn | Hành động |
  | :--- | :--- | :--- | :--- | :--- |
  | 1 | npm-cache | 12.4 GB | 🟢 LOW RISK | Xóa cache npm |
  | 2 | temp files | 6.1 GB | 🟢 LOW RISK | Chuyển vào Recycle Bin |
- **STOP AND WAIT**: Ask the user: *"Bạn có muốn tôi thực hiện dọn dẹp các mục này không? Vui lòng xác nhận các số thứ tự (ví dụ: 1, 2) bạn muốn dọn."*

### Step 5: Safe Execution & Verification
- Only after the user confirms, run:
  `python -m disk_investigator execute-plan <plan_id> --items <approved_ids> --apply`
- Run `python -m disk_investigator overview` to verify and report the observed volume free-space delta along with estimated attributable reclaim!
