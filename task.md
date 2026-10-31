Bây giờ hãy bắt đầu **xây dựng tool dọn dẹp bộ nhớ/ổ đĩa cho Windows 11 bằng AI Agent ngay trong CWD hiện tại**, dựa trên toàn bộ research, repository, tool và architecture đã tìm hiểu ở conversation ChatGPT trước đó.

Bạn được phép và nên sử dụng:

- các repo/tool đã được research trong conversation;
- CLI;
- MCP Server;
- Agent Skill;
- local harness;
- Python / PowerShell / Rust / Node.js nếu phù hợp;
- structured JSON;
- subprocess wrappers;
- filesystem inspection;
- Windows-native APIs;
- hoặc một architecture khác tốt hơn nếu trong quá trình implementation bạn chứng minh được nó hợp lý hơn.

Mục tiêu không phải chỉ tạo một "disk cleaner".

Mục tiêu là tạo một **AI-native disk investigation + cleanup system** để Antigravity có thể trực tiếp sử dụng khi làm việc với tôi.

---

# 1. Làm việc theo mô hình team 2 người

Hãy kết hợp Antigravity hiện tại với ChatGPT bản web thành một team gồm hai vai trò:

```text
Person A — Antigravity
Coder + Executor

Person B — ChatGPT Web
Orchestrator + Architect + Reviewer
```

Bạn có thể sử dụng skill:

[ai-chat-web-interaction](slashCommand;ai-chat-web-interaction)

kết hợp với **Playwright MCP profile `b6`** để tiếp tục làm việc với ChatGPT tại:

https://chatgpt.com/c/6ae41e50-a5c4-83ec-9a78-d802a567447e

Conversation này đã có context và research trước đó về project.

Không mở một conversation ChatGPT mới nếu không cần thiết.

---

# 2. Phân chia trách nhiệm

## ChatGPT Web — Orchestrator & Reviewer

ChatGPT chịu trách nhiệm:

- giữ architectural context;
- review approach;
- đánh giá trade-off;
- review code design;
- review safety;
- phát hiện thiếu sót;
- đề xuất cải tiến;
- review kết quả test;
- quyết định khi nào nên pivot architecture;
- kiểm tra tool có thực sự phù hợp với AI Agent hay chưa.

Khi có một quyết định kỹ thuật quan trọng, có thể hỏi ChatGPT:

```text
Here is the current implementation / problem / test result.

Review it as the project architect.

Identify:
1. architecture problems
2. safety problems
3. unnecessary complexity
4. better alternatives
5. what should be implemented next
```

Không cần hỏi ChatGPT cho mọi dòng code.

Chỉ sử dụng reviewer khi có giá trị.

---

## Antigravity — Coder & Executor

Bạn chịu trách nhiệm:

- inspect CWD;
- thiết kế project structure;
- viết code;
- cài dependency nếu cần;
- integrate repo/tool;
- chạy command;
- tạo wrapper;
- tạo MCP/CLI/harness;
- test;
- debug;
- benchmark;
- sửa lỗi;
- thực hiện các recommendation đã được review;
- hoàn thiện sản phẩm.

Bạn là người trực tiếp thao tác trên môi trường local.

---

# 3. Product goal

Workflow cuối cùng tôi muốn là:

```text
Tôi mở Antigravity
        ↓
Tôi yêu cầu kiểm tra dung lượng máy
        ↓
Antigravity gọi disk investigation tool
        ↓
Tool scan máy
        ↓
Tool trả structured data cho Antigravity
        ↓
Antigravity drill-down vào khu vực đáng chú ý
        ↓
Antigravity hiểu dữ liệu
        ↓
Tôi hỏi đáp tự nhiên với Antigravity
```

Ví dụ:

```text
User:
Ổ C của tôi đang đầy vì cái gì?

Antigravity:
Tôi vừa scan ổ C.

Top consumers:

Users             91 GB
ProgramData       34 GB
Windows           29 GB
Docker            27 GB
AppData           22 GB

Docker đang chiếm bất thường.
Tôi có thể drill-down thêm nếu bạn muốn.
```

Sau đó:

```text
User:
Docker 27 GB là cái gì?

Antigravity:
17.2 GB là unused images
6.4 GB là build cache
3.1 GB là volumes

Trong đó khoảng 21 GB có thể cleanup tương đối an toàn.
```

Và:

```text
User:
node_modules thì sao?

Antigravity:
Tôi tìm thấy 43 thư mục node_modules.

Tổng dung lượng: 18.6 GB.

15 thư mục nằm trong project không được sửa hơn 90 ngày.
Tổng dung lượng nhóm này: 8.2 GB.
```

Đây là trải nghiệm mục tiêu.

---

# 4. Tool phải ưu tiên "investigation", không phải "deletion"

Core capability quan trọng nhất là:

```text
DISCOVER
→ MEASURE
→ DRILL DOWN
→ CLASSIFY
→ EXPLAIN
```

Cleanup chỉ là lớp phía sau.

Tool phải giúp AI Agent trả lời những câu hỏi như:

```text
Cái gì đang chiếm dung lượng?

Folder này chứa gì?

Folder này thuộc app nào?

Có bao nhiêu node_modules?

Docker đang dùng bao nhiêu?

AppData nào lớn bất thường?

Cache nào đang chiếm dung lượng?

File lớn nhất là gì?

Folder nào lâu rồi không dùng?

Có gì có khả năng cleanup?

Nếu xóa thì hậu quả gì?
```

---

# 5. Kiến trúc không bị khóa

Bạn KHÔNG bắt buộc phải implement đúng một architecture cụ thể.

Hãy thử phương án tốt nhất trước.

Có thể là:

```text
Antigravity
    ↓
MCP Server
    ↓
Disk Analysis Engine
```

hoặc:

```text
Antigravity
    ↓
Agent Skill
    ↓
CLI Harness
    ↓
Multiple disk tools
```

hoặc:

```text
Antigravity
    ↓
Local Python Harness
    ↓
Scanner + Classifiers
```

hoặc:

```text
Antigravity
    ↓
Single native binary
    ↓
JSON
```

hoặc hybrid:

```text
Antigravity
          │
          ▼
       Harness
          │
    ┌─────┼─────┐
    ▼     ▼     ▼
 Scanner Cache Docker
        Analyzer
          │
          ▼
      Unified JSON
```

Bạn được quyền thay đổi kiến trúc nếu trong lúc build thấy:

- MCP tạo overhead không cần thiết;
- một repo quá khó integrate;
- CLI parsing không ổn;
- performance kém;
- permission phức tạp;
- tool không còn maintain;
- structured output không đủ tốt;
- implementation quá brittle.

Nhưng trước khi pivot lớn, hãy:

1. ghi lại vấn đề;
2. đưa evidence;
3. hỏi ChatGPT reviewer nếu cần;
4. chọn phương án mới đơn giản hơn.

---

# 6. Ưu tiên integration hơn reinventing

Trước khi tự viết lại chức năng từ đầu, hãy kiểm tra xem các tool/repo đã research trước đó có thể đảm nhiệm phần đó hay không.

Ví dụ:

```text
Existing tool
    ↓
CLI / API
    ↓
Adapter
    ↓
Normalized JSON
    ↓
Antigravity
```

Nếu một repo đã giải quyết tốt:

- disk walking;
- folder-size calculation;
- duplicate detection;
- cache detection;
- large file detection;

thì ưu tiên wrap/integrate nó.

Nhưng nếu integration phức tạp hơn tự implement một lớp nhỏ đáng tin cậy thì có thể tự implement.

Mục tiêu là:

```text
simple
reliable
fast
machine-readable
agent-friendly
```

không phải:

```text
maximum number of dependencies
```

---

# 7. Thiết kế tool cho AI Agent, không phải human UI

Tool không cần GUI ở giai đoạn này.

Ưu tiên interface kiểu:

```text
disk-tool audit C:\
```

```text
disk-tool drilldown "C:\Users"
```

```text
disk-tool largest-files C:\ --limit 100
```

```text
disk-tool detect node_modules
```

```text
disk-tool analyze docker
```

```text
disk-tool cleanup-plan
```

và output:

```json
{
  "path": "C:\\Users",
  "size_bytes": 98234523412,
  "children": [],
  "categories": [],
  "warnings": [],
  "cleanup_candidates": []
}
```

Tên command thực tế có thể khác.

Quan trọng là Antigravity có thể gọi ổn định.

---

# 8. Output phải machine-readable

Ưu tiên JSON hoặc JSONL.

Structured output phải chứa đủ context để AI reasoning.

Ví dụ:

```json
{
  "path": "C:\\Users\\user\\AppData\\Local\\npm-cache",
  "size_bytes": 8217349120,
  "category": "developer_cache",
  "owner_app": "npm",
  "confidence": 0.97,
  "last_modified": "2026-06-12",
  "cleanup": {
    "candidate": true,
    "risk": "low",
    "recoverable": true,
    "estimated_reclaim_bytes": 8217349120
  }
}
```

Không bắt buộc schema đúng như trên.

Nhưng phải đủ rõ để Antigravity hỏi đáp tiếp.

---

# 9. Drill-down phải là first-class feature

Không scan toàn bộ máy cực sâu mỗi lần nếu không cần.

Hỗ trợ workflow:

```text
Level 1
C:\

↓

Level 2
C:\Users
C:\Windows
C:\ProgramData

↓

Level 3
C:\Users\<user>\AppData

↓

Level 4
specific application/cache

↓

Level 5
individual large files
```

AI Agent phải có thể điều tra theo kiểu forensic exploration.

Ưu tiên:

```text
fast overview
→ targeted drill-down
```

thay vì:

```text
scan every file every time
```

---

# 10. Categorization layer

Nếu khả thi, xây layer để phân loại filesystem objects.

Ví dụ:

```text
system
application
user_data
developer_cache
browser_cache
package_cache
temporary
logs
docker
node_modules
python_env
git_repo
downloads
duplicate_candidate
large_file
unknown
```

Không cần hoàn hảo ngay từ version đầu.

Có thể dùng:

```text
path heuristics
+
known directory rules
+
metadata
+
installed application mapping
```

AI có thể reasoning thêm phía trên.

---

# 11. Safety model

Đây là requirement quan trọng nhất.

Default mode:

```text
READ ONLY
```

Trong phase investigation:

Không được tự ý:

- delete file;
- delete folder;
- uninstall application;
- prune Docker;
- clear cache;
- modify registry;
- remove Windows components;
- run destructive PowerShell;
- empty Recycle Bin;
- remove user documents.

Nếu tool có cleanup capability, phải tách rõ:

```text
AUDIT
```

và:

```text
EXECUTION
```

Workflow cleanup:

```text
Audit
→ Cleanup Plan
→ Explain
→ Explicit Approval
→ Execute
→ Verify
```

---

# 12. Cleanup candidate classification

Nếu implement cleanup recommendation, phân loại ít nhất:

```text
LOW RISK
MEDIUM RISK
HIGH RISK
DO NOT TOUCH
UNKNOWN
```

Ví dụ:

```text
LOW RISK
npm cache
pip cache
temporary files

MEDIUM RISK
old node_modules
Docker build cache

HIGH RISK
Docker volume
unknown AppData

DO NOT TOUCH
Windows system component

UNKNOWN
unidentified large folder
```

Không hardcode ví dụ này như truth tuyệt đối.

Hãy xây rule hợp lý.

---

# 13. Performance

Disk scan có thể rất nặng.

Hãy thiết kế để:

- tránh đọc file content khi không cần;
- chỉ lấy metadata;
- tránh hash toàn disk trừ khi duplicate scan được yêu cầu;
- support parallelism nếu an toàn;
- tránh follow symlink/junction loop;
- handle permission denied;
- handle locked files;
- handle Windows junction/reparse points;
- handle long paths;
- handle inaccessible directories.

Nếu scan một subtree lớn, cần có progress/reporting hợp lý nếu implementation hỗ trợ.

---

# 14. Testing strategy

Không chỉ test bằng unit test giả.

Phải chạy tool thật trên máy hiện tại ở phạm vi an toàn.

Bắt đầu với một subtree nhỏ.

Ví dụ:

```text
current project directory
```

sau đó:

```text
Downloads
```

hoặc một directory phù hợp.

Sau đó mới test root drive read-only nếu cần.

Kiểm tra:

```text
correctness
performance
permission handling
path handling
structured output
drill-down
error recovery
```

---

# 15. Iterative build strategy

Không cố build full system một lần.

Làm theo vòng:

```text
Prototype
↓
Run
↓
Inspect output
↓
Review with ChatGPT
↓
Improve
↓
Test again
```

---

# 16. Suggested implementation phases

Bạn có thể thay đổi nếu có lý do tốt.

## Phase 1 — Environment & architecture

- inspect CWD;
- inspect available runtimes;
- inspect research/context;
- chọn architecture;
- tạo project skeleton.

## Phase 2 — Minimal disk audit

Implement:

```text
audit
```

Có khả năng:

- directory size;
- largest children;
- structured JSON.

## Phase 3 — Drill-down

Implement targeted exploration.

Ví dụ:

```text
drilldown <path>
```

## Phase 4 — Detection modules

Thêm các module giá trị cao trước.

Ví dụ:

```text
large files
node_modules
developer caches
Docker
AppData
Downloads
```

Không cần tất cả cùng lúc.

## Phase 5 — Classification

Normalize output thành một unified model.

## Phase 6 — Agent integration

Cho Antigravity gọi tool thuận tiện.

Có thể là:

```text
Skill
MCP
CLI wrapper
Harness
```

Chọn cách có UX tốt nhất.

## Phase 7 — Cleanup planning

Generate cleanup candidates nhưng chưa delete.

## Phase 8 — Optional controlled execution

Chỉ implement nếu safety model đủ chắc.

---

# 17. ChatGPT review checkpoints

Ít nhất nên review ở những checkpoint quan trọng:

```text
Architecture selected
```

```text
First working prototype
```

```text
Agent integration completed
```

```text
Cleanup model designed
```

và khi có vấn đề khó.

Khi gửi review, cung cấp đủ evidence:

- relevant code;
- folder tree;
- command;
- output;
- errors;
- benchmark;
- trade-offs.

Không chỉ hỏi:

```text
"Is this good?"
```

---

# 18. Không bị mắc kẹt vào một approach

Nếu một approach mất quá nhiều công sức mà value thấp:

STOP.

Phân tích nguyên nhân.

Thử phương án khác.

Ví dụ:

```text
MCP too complex
→ use CLI harness

CLI output unreliable
→ wrap library directly

Third-party scanner slow
→ implement filesystem walker

Python performance inadequate
→ delegate scanning to native utility
```

Mục tiêu là hoàn thành tool tốt nhất, không phải bảo vệ quyết định ban đầu.

---

# 19. Documentation

Trong CWD cần có documentation đủ để một AI Agent khác tiếp tục project.

Ít nhất tạo:

```text
README.md
```

với:

- project purpose;
- architecture;
- setup;
- usage;
- available commands;
- JSON schema;
- safety model;
- known limitations.

Nếu kiến trúc đủ phức tạp, thêm:

```text
ARCHITECTURE.md
```

và nếu cần:

```text
AGENT.md
```

hoặc skill instructions phù hợp.

---

# 20. Keep a project state

Trong quá trình build, duy trì một file ngắn như:

```text
PROJECT_STATE.md
```

ghi:

```text
Current architecture
Completed
In progress
Known issues
Decisions
Rejected approaches
Next step
```

Mục đích để không mất context giữa các vòng làm việc.

---

# 21. Khi sử dụng code/tool bên ngoài

Kiểm tra:

- license;
- maintenance status;
- Windows support;
- security implications;
- dependency cost.

Không copy code không rõ license vào project.

Nếu chỉ gọi executable bên ngoài thì document dependency.

---

# 22. Definition of MVP

MVP chưa cần xóa file.

MVP được xem là thành công nếu workflow sau hoạt động:

```text
User
↓
Antigravity
↓
Tool
↓
Scan selected disk/path
↓
Structured result
↓
Antigravity identifies biggest consumers
↓
Antigravity drill-down
↓
Antigravity explains findings
↓
User asks follow-up questions
↓
Antigravity can investigate further using the tool
```

Ví dụ tôi phải có thể hỏi:

```text
"Ổ C đang đầy vì cái gì?"
```

sau đó:

```text
"Drill-down AppData cho tôi."
```

sau đó:

```text
"Trong đó cái nào là cache?"
```

sau đó:

```text
"Bao nhiêu GB có khả năng dọn được?"
```

và Antigravity có dữ liệu thực tế để trả lời.

---

# 23. Definition of Done cho bản hoàn chỉnh

Project được coi là hoàn thành khi:

1. Tool chạy được trên Windows 11.

2. Antigravity gọi được tool trực tiếp.

3. Có fast disk overview.

4. Có targeted drill-down.

5. Có large-file detection.

6. Có category/classification ở mức hữu ích.

7. Có structured machine-readable output.

8. Permission errors không làm crash toàn scan.

9. Windows junction/reparse points được xử lý an toàn.

10. Antigravity có thể hỏi đáp dựa trên dữ liệu scan.

11. Có cleanup candidate model.

12. Investigation mặc định read-only.

13. Cleanup execution nếu tồn tại phải có explicit approval.

14. Có documentation.

15. Tool đã được test thực tế.

16. ChatGPT reviewer đã review architecture và implementation cuối.

---

# 24. Cách làm việc từ bây giờ

Bắt đầu ngay trong CWD hiện tại.

Không chỉ viết plan rồi dừng.

Workflow:

```text
Inspect current environment
↓
Recover project/research context
↓
Consult ChatGPT reviewer nếu cần
↓
Choose architecture
↓
Create first working implementation
↓
Run it
↓
Inspect real output
↓
Fix problems
↓
Review
↓
Iterate
↓
Integrate with Antigravity
↓
Document
↓
Final end-to-end test
```

Trong quá trình làm việc, tự đưa ra quyết định kỹ thuật hợp lý.

Không hỏi tôi các câu nhỏ mà bạn có thể tự quyết định bằng testing hoặc reasoning.

Chỉ cần dừng để hỏi tôi khi:

- hành động có nguy cơ xóa/mất dữ liệu;
- cần quyền Administrator cho hành động destructive;
- có nhiều lựa chọn sản phẩm ảnh hưởng trực tiếp đến UX mà không thể suy ra;
- hoặc cần explicit cleanup approval.

Ngoài các trường hợp đó, tiếp tục chủ động build và iterate.

Mục tiêu cuối cùng:

> Tôi mở Antigravity, hỏi về dung lượng máy tính của mình, và Antigravity có một bộ công cụ đủ tốt để tự điều tra filesystem, drill-down, hiểu dữ liệu, giải thích cho tôi và sau này có thể hỗ trợ cleanup một cách an toàn.