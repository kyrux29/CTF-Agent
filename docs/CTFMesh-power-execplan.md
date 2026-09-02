# CTFMesh Power — ExecPlan đổi safety lấy sức giải CTF

**Status:** kế hoạch triển khai mới — profile `power`
**Date:** 2026-08-31
**Đối tượng:** developer + AI implementation agent
**Phạm vi:** localhost, challenge/lab **được cấp quyền**, single operator
**Không phải:** Internet scanner, công cụ tấn công hệ thống không thuộc scope

> Đọc file này như ExecPlan thay thế hướng “fail-closed typed-Web-only” khi mục tiêu là **solve rate**.
> Profile cũ `m6-ui` / verifier-only **giữ nguyên**, không xóa.
> Profile mới `power` là đường chính để giải CTF.
> Làm đúng một milestone chưa check rồi dừng, chạy gate, ghi worklog.

Câu nhớ cho profile này:

> Quan sát phải đến từ lệnh thật. Nhiều model đua. Planner chia việc. Executor được shell. Flag thắng cuộc đua phải submit được, không được bịa.

---

## 0. Quyết định chiến lược

### 0.1 Đánh đổi được chấp nhận

Vì runtime là máy operator, loopback, authorized CTF:

| Cũ (v0.1 mesh) | Mới (power) | Lý do |
|---|---|---|
| Không shell | `shell.exec` + PTY trong workspace | Mọi harness SOTA đều sống bằng shell |
| 3 technique Web typed | Mọi category CTF Jeopardy | Trần năng lực cũ = 0 với pwn/rev/crypto |
| 2 worker / 1 model | Race 3–6 solver / nhiều model | Veria 52/52 nhờ pass@k, không nhờ 1 agent thông minh hơn |
| Verifier GET-only là cổng SOLVED duy nhất | Flag checker + optional replay | Web V2 vẫn dùng replay; pwn/crypto dùng checker/remote |
| Fixed 2 source slot | N disposable Kali workspace | Mỗi solver một box |
| Pi `noTools: all` + custom hẹp | ACI đầy đủ: shell, file, IAT | Pi không còn là choke capability |
| Không Internet | Opt-in egress: pip/apt + target đã khai | D-CIPHER/EnIGMA đều cho cài tool |
| Hint = hypothesis thuần | Coordinator được bump kỹ thuật vào solver | Veria: coordinator đọc trace rồi chỉ điểm kẹt |

### 0.2 Ranh giới vẫn giữ (localhost ≠ “bắn lung tung”)

Những thứ này **không** đổi dù muốn mạnh:

1. Chỉ loopback UI / Control API. Không publish 0.0.0.0.
2. Mỗi run khai báo **scope**: artifact local và/hoặc origin/host:port target. Solver không được quét cả subnet nhà trừ khi operator bật `open_lan`.
3. Không mount Docker socket vào **solver**. Socket chỉ nằm ở `sandboxd` trên control plane (operator machine). Solver gọi RPC `workspace.exec`.
4. Challenge text / HTTP body / binary string = untrusted. Không load `.pi`, `AGENTS.md`, `.cursor` trong archive thành system prompt.
5. API key model không vào workspace. Provider chỉ ở runner process.
6. Flag candidate phải qua **checker** (pattern + remote submit hoặc lab controller). Worker không tự `SOLVED`.
7. Ghi command + exit code + truncated stdout vào ledger. Cấm “tôi đã chạy và thấy flag” không có observation.

Điểm 6–7 là phần chống hallucination **còn lại**. Bỏ chúng thì agent sẽ soliloquize đúng như EnIGMA mô tả.

---

## 1. Bài học bắt buộc từ các agent mạnh

Nguồn chính (đọc khi implement, đừng copy code SPDX nếu không tương thích; copy **pattern**):

| Hệ | Pattern lấy | Pattern bỏ / chỉnh |
|---|---|---|
| **Veria `ctf-agent`** (BSidesSF 2026 52/52) | Coordinator LLM + swarm per challenge + multi-model race + isolated Docker full tool + bump từ trace + share insight | Không phụ thuộc CTFd; CTFMesh đã có Control API. Không “never kill swarm” vô hạn — vẫn có budget. |
| **EnIGMA / SWE-agent ACI** | Thought-action-observation; Interactive Agent Tools: `gdb` session + `pwntools` tube; summarizer output dài; category few-shot | Đừng để agent tự bịa observation. IAT phải giữ REPL sống song song với shell. |
| **D-CIPHER** | Auto-prompter khám workspace trước; Planner giữ mục tiêu end-to-end; mỗi task = Executor **conversation mới** | Planner không tự chạy 200 lệnh. Executor không thấy toàn bộ transcript planner. |
| **CRAKEN** | RAG writeup / technique graph **lúc delegate**, không nhồi 200 writeup vào system prompt | Contest mode: tắt RAG Internet; chỉ corpus local đã pin. |
| **CAI** | `generic_linux_command` + session interactive; agent chuyên category; HITL pause | Đừng biến thành 20 agent chat lẫn nhau không observation. |
| **HackSynth** | Planner sinh **một lệnh**; Summarizer nén state; loop tới flag hoặc cap | Một lệnh/turn dễ debug hơn agent gọi 15 tool song song. |
| **Claude Code / Codex / OpenHands** | Một agent dài hơi trong box giàu tool thường thắng single-session trên web/misc dễ | Dùng làm **một** racer trong swarm, không phải kiến trúc duy nhất. |
| **CTFMesh v0.1** | Ledger, budget, lease, UI, credential vault, archive intake | Bỏ typed-only tool làm cổng giải. |

### 1.1 Năm cơ chế thực sự tăng solve rate

Theo paper + contest report, thứ tự tác động xấp xỉ:

1. **Môi trường giàu tool** (Kali + gdb/ghidra/sage/pwntools/curl) — paper 2026: Kali vs Ubuntu ~+9.5 điểm NYU CTF.
2. **Shell + IAT thật** — EnIGMA: không IAT thì model soliloquize.
3. **Pass@k / multi-model race** — Veria: cùng challenge, nhiều model, ai ra flag trước thắng.
4. **Task nhỏ + executor context sạch** — D-CIPHER / Cybench subtask.
5. **Coordinator bump khi kẹt** — Veria: đọc trace, chỉ kỹ thuật, không reset toàn bộ.

Prompt đẹp đứng sau năm thứ này.

### 1.2 Soliloquy — failure mode số 1

EnIGMA đặt tên: model **tự viết** output gdb/netcat từ trí nhớ training. Mitigation bắt buộc trong power profile:

- Mọi claim “flag / crash / leak” phải trỏ `observation_id`.
- Tool runtime luôn chạy lệnh; nếu timeout trả `timeout`, không để model bịa nốt.
- Summarizer chỉ tóm output đã ghi, không “suy ra” byte chưa thấy.
- Detector đơn giản: nếu assistant text chứa `FLAG{` / `HTB{` trước khi observation nào match pattern → đánh `unverified_claim`, không submit.

---

## 2. Kiến trúc mục tiêu — profile `power`

### 2.1 Sơ đồ

```text
Operator UI (loopback)
        │
        ▼
Control API ── Postgres ledger / budget / events
        │
        ▼
Coordinator (LLM, 1 session/run hoặc 1 session/board)
        │  spawn / bump / stop / share
        ▼
Challenge Swarm
   ┌────────────┬────────────┬────────────┐
   │ Solver A   │ Solver B   │ Solver C   │  ... up to R racers
   │ model M1   │ model M2   │ model M3   │
   │ workspace1 │ workspace2 │ workspace3 │
   └─────┬──────┴─────┬──────┴─────┬──────┘
         │            │            │
         ▼            ▼            ▼
   sandboxd RPC ─ exec/pty/file into disposable box
         │
         ├─ challenge files (rw copy, not origin)
         ├─ tool image (gdb, r2, sage, pwntools, ...)
         └─ network: target allowlist + optional egress
         │
         ▼
Flag Router
   ├─ pattern + uniqueness
   ├─ optional remote submit / lab controller
   └─ first valid → run SOLVED, cancel sibling racers
```

### 2.2 Thành phần mới

| Service | Tech | Việc |
|---|---|---|
| `sandboxd` | Python, host Docker SDK **chỉ process này** | create/destroy workspace, exec, PTY, copy-in archive, limits |
| `solver-runtime` | Node hoặc Python ReAct | một process/racer: model loop + tool schema shell/file/iat |
| `coordinator` | Python, tái dùng orchestrator | spawn racers, đọc trace rút gọn, bump, diversity |
| `tool-image` | Dockerfile Kali-min hoặc Ubuntu+toolkit | không nhúng flag, không agent code untrusted |
| `flag-router` | Python | nhận candidate, check, race-win, event |
| `knowledge` (opt) | local embeddings | writeup/recipe retrieval lúc delegate |

`sandboxd` là chỗ **duy nhất** nói chuyện Docker. API/Pi/solver **không** mount socket. Đây là đánh đổi nhỏ: operator machine tin được; solver box không tin được.

### 2.3 Workspace contract

Mỗi racer nhận box:

```text
/challenge     rw copy of archive / declared artifacts
/work          scratch
/usr/local/ctf tools
network        --
  default: DNS + declared targets only
  power_egress=1: also HTTPS to pypi/github/apt (operator toggle)
user           uid 1000, no docker.sock, no privileged
caps           default; optional SYS_PTRACE for gdb (bật mặc định power)
mem            4–8G
cpus           2–4
pids           512
timeout        wall clock per run (mặc định 30–90 phút Jeopardy)
```

`SYS_PTRACE` cần cho gdb. Privileged + host net **cấm mặc định**.

### 2.4 Tool surface của một solver (ACI)

Bắt buộc, ổn định, document cho model:

| Tool | Việc | Ghi chú |
|---|---|---|
| `shell.exec` | một lệnh, timeout 30–120s, stdout/stderr cap 32–64KiB | HackSynth-style: một lệnh/turn là default |
| `shell.pty_start/send/read/close` | session sống: python, sage, gdb, nc | IAT |
| `fs.ls / fs.read / fs.write / fs.edit` | file trong `/challenge` và `/work` | path jail |
| `gdb.start/cmd/break/continue` | wrapper gdb | EnIGMA IAT |
| `tube.connect/send/recv/close` | TCP tới host:port trong allowlist | pwntools-like, không raw socket arbitrary IP ngoài scope |
| `http.request` | GET/POST exact origin hoặc allowlist | giữ từ mesh |
| `flag.submit` | gửi candidate | chỉ flag-router quyết định win |
| `note.blackboard` | ghi hypothesis ngắn cho coordinator | không phải fact |

Không cần 80 tool name. Image đã có binary; model gọi qua `shell.exec` (`r2 -A`, `strings`, `sage`, `sqlmap` nếu có). Tool riêng chỉ cho thứ **tương tác**.

### 2.5 Vai trò agent

Lấy D-CIPHER + Veria, bỏ council bàn luận suông.

| Role | Context | Tool | Output |
|---|---|---|---|
| AutoPrompter | 8–15 turn khám `/challenge` | shell/fs | `initial_brief` (category guess, files, attack surface) |
| Coordinator / Planner | brief + blackboard + racer summaries | spawn/bump/stop/share | task specs |
| General solver | full ACI | tất cả | flag candidate hoặc summary kẹt |
| Category solver (web/pwn/rev/crypto/forensics) | prompt + tool hint khác | cùng ACI, image giống | như trên |
| Summarizer | output dài | không exec | 1–2k token state |

Default swarm một challenge:

1. 1 AutoPrompter (model rẻ hoặc cùng model)
2. 1 Coordinator
3. 3 General racers khác model (nếu chỉ 1 key thì 3 temperature/seed hoặc 1 model × 3 box)
4. Khi brief chắc category: thay 1 general bằng category solver

Cap: `max_racers=4` mặc định, `max_racers=6` máy mạnh.

### 2.6 Vòng đời một challenge

```text
intake archive / gắn folder / khai target
        → materialize N workspace copy
        → AutoPrompter (shared brief)
        → spawn racers với brief
        → loop:
             racer thought → tool → observation ledger
             mỗi K turn: summarizer
             stall detector: 0 file mới + 0 network + lặp fingerprint lệnh → coordinator bump
             flag.submit → checker
        → win: kill sibling, SOLVED, giữ workspace để operator xem
        → lose: budget/time, dump trace
```

### 2.7 Flag checker (vẫn cần)

Không quay lại “model nói SOLVED”.

Ưu tiên theo thứ tự:

1. Lab controller / remote check endpoint nếu có.
2. Submit CTFd/platform nếu operator dán token.
3. Pattern manifest (`FLAG{...}`, `HTB{...}`) **và** candidate xuất hiện trong observation stdout/file, không chỉ trong assistant text.
4. Optional: hai lần chạy script exploit trong workspace sạch (khi candidate là file `solve.py`).

Power profile **được** nhận `solve.py` do model viết và chạy trong box. Đó là điểm đánh đổi so với v0.1.

---

## 3. Map vào repo hiện tại — đừng viết lại toàn bộ

Giữ:

- `apps/web` vault + panes + run console (đổi copy: hiện lệnh, không chỉ typed tool)
- `apps/api` challenge/run/event
- `packages/domain` state machine; thêm `POWER_RUNNING`
- `packages/db` job/lease/outbox
- archive intake
- provider proxy + vault

Thêm:

| Path | Việc |
|---|---|
| `services/sandboxd/` | Docker workspace manager |
| `services/solver-runtime/` | ReAct loop + ACI tools |
| `services/coordinator/` hoặc mở rộng `services/orchestrator/` | swarm policy |
| `images/ctf-toolkit/Dockerfile` | tool image |
| `packages/aci/` | schema shell/pty/gdb/tube/flag |
| `packages/knowledge/` | optional local RAG |
| `docs/adr/0009-power-profile.md` | ghi nhận đánh đổi |
| `docs/phases/power-m*.md` | worklog |

Pi runner: **không bắt** mọi tool qua typed gateway nữa khi `run.profile=power`. Có thể giữ Pi như một racer backend (`backend=pi|react|codex`) nhưng default power dùng `solver-runtime` đơn giản hơn Pi — ít ma sát hơn khi cần PTY.

Đừng xóa M5 verifier. Web exact-instance cũ vẫn chạy profile `m6-ui`.

---

## 4. Image toolkit tối thiểu

Một image, không mười image theo category (Squid/D-CIPHER đều dùng chung box).

Lớp pack (apt/pip, pin version trong Dockerfile):

- **base:** python3, pip, git, curl, wget, jq, ripgrep, file, binutils, strace, ltrace, tmux
- **web:** curl, httpie, sqlmap, nikto optional, python `requests`, `beautifulsoup4`
- **pwn:** gdb, gdb-pwndbg hoặc gef, pwntools, ROPgadget, one_gadget, checksec
- **rev:** radare2, ghidra headless nếu kéo nổi (nặng — stage extra `ghidra=1`), capstone
- **crypto:** sage hoặc `pycryptodome`+`gmpy2`+`z3-solver` nếu sage quá nặng cho máy operator
- **forensics/stego:** binwalk, foremost, exiftool, steghide, zsteg, tshark
- **rev/crypto nặng:** tách tag `ctf-toolkit:full` vs `ctf-toolkit:slim`

Build local, không pull flag. Document disk ~8–20GB.

---

## 5. Prompt và context — ngắn, theo việc

### 5.1 Solver system prompt (ý, không phải copy nguyên)

- Bạn ở trong workspace CTF được cấp quyền.
- Dùng tool. Đừng đoán output lệnh.
- Flag chỉ `flag.submit` khi thấy trong output/file.
- Target chỉ host trong scope.
- Nếu kẹt 3 lệnh giống nhau, đổi hướng hoặc đọc lại file đề.

### 5.2 AutoPrompter

Bắt buộc làm trước khi đua:

```text
ls -la /challenge
file /challenge/*
rg -n "flag|TODO|password|http" /challenge -g '!*.png'
đọc README / challenge.yml nếu có
```

Ra JSON brief: `category_guess[]`, `files[]`, `hints_in_repo`, `network_endpoints`, `first_experiments[]`.

### 5.3 Coordinator bump

Input: 2–4k token trace rút gọn (lệnh + exit + 20 dòng cuối), không raw 200k gdb.

Output: một trong `continue | switch_category | try_other_file | write_exploit_script | stop_racer`.

### 5.4 Diversity

Hai racer không được cùng fingerprint lệnh trong cửa sổ N turn (hash argv). Coordinator phạt lặp. Veria share insight; CTFMesh share **observation card** (file path, crash offset, endpoint), không share “theo tao flag là …”.

---

## 6. ExecPlan triển khai

Ước lượng 1 người: 3–5 tuần nếu tái dùng API/UI. Làm tuần tự.

### Milestone P0 — ADR + profile skeleton (0.5–1 ngày)

- [x] `docs/adr/0009-power-profile.md`: localhost, shell granted, sandboxd owns Docker, flag-router owns SOLVED.
- [x] `AGENTS.md` thêm mục “Power profile”: được shell trong workspace; không được socket trong solver.
- [x] Compose profile `power`: api, web, postgres, sandboxd (privileged **chỉ** để nói Docker engine — hoặc group docker), solver-runtime replicas=0 lúc idle.
- [x] Feature flag `CTFMESH_POWER_ENABLED=true`.

**Done khi:** `docker compose --profile power config` sạch; default profile không kéo sandboxd.

---

### Milestone P1 — sandboxd + shell thật (2–3 ngày)

**Đây là milestone quyết định sức mạnh.** Không P1 thì các mốc sau vô nghĩa.

- [x] API nội bộ: `WorkspaceCreate(run_id, archive_digest)`, `Exec(cmd, timeout)`, `PTY`, `Destroy`.
- [x] Copy archive đã intake vào `/challenge`.
- [x] Path jail: không `../`, không `/etc/shadow` trừ khi đọc file challenge.
- [x] Ghi artifact stdout (truncate) + sha256 vào CAS.
- [x] Limits: mem/cpu/pids/time.
- [x] `SYS_PTRACE` bật.
- [x] Test: exec `echo hi`, exec `id`, deny path escape, destroy idempotent, two workspaces isolated.

**Done khi:** pytest + một smoke Docker: tạo box, `ls /challenge`, xóa box, không còn container orphan.

---

### Milestone P2 — solver-runtime ReAct + flag.submit (2–3 ngày)

- [x] Loop: model → tool call → sandboxd → observation → model.
- [x] Tools: `shell.exec`, `fs.*`, `flag.submit`.
- [x] Một lệnh/turn mặc định (HackSynth). Cho phép PTY ở P3.
- [x] Context window: giữ N observation gần nhất + brief + summarizer.
- [x] Backend model: OpenAI-compatible qua provider-proxy đã có. Gemini/DeepSeek adapter tái dùng.
- [x] `flag.submit` gọi flag-router; pattern từ manifest hoặc heuristic `FLAG|HTB|CTF{`.
- [x] Test fixture model: scripted tool sequence tìm file `flag.txt` trong archive mẫu → SOLVED.
- [x] Test soliloquy: model text chứa `FLAG{fake}` không có observation → reject.

**Done khi:** archive chứa `flag.txt` được solver fixture đọc và submit thắng.

---

### Milestone P3 — IAT: gdb + tube (3–4 ngày)

- [x] `gdb.start` (file trong /challenge), `gdb.cmd`, `gdb.close`. Completed 2026-09-01.
- [x] `tube.connect(host,port)` chỉ allowlist; `send`, `recv_until`, `close`.
- [x] PTY generic cho `python -q`, `sage -q`.
- [x] Output gdb/tube luôn observation; summarizer cắt backtrace.
- [x] Lab nội bộ nhỏ: binary hello-pwn in flag khi gửi payload cố định **do test harness biết**, không cần model — để chứng minh IAT chạy. Lab này gitignore flag random.
- [x] Test: gdb break main + continue trả output thật; tube echo server trong compose test net.

**Done khi:** integration không model chứng minh IAT sống song song shell.

---

### Milestone P4 — AutoPrompter + Coordinator + 3 racers (3–5 ngày)

- [x] AutoPrompter 10 turn max, ghi brief.
- [x] Swarm: 3 workspace, 3 solver-runtime, cùng brief.
- [x] Diversity fingerprint lệnh.
- [x] First valid flag cancels siblings (grace 5s flush ledger).
- [x] Stall: 5 turn không observation mới → bump.
- [x] UI Progress: racer A/B/C, lệnh cuối, state.
- [x] Test: 3 fixture racers, chỉ 1 tìm thấy flag file → win + 2 cancelled.
- [x] Test: 2 racer cùng lệnh lặp → một bị bump/stop.

**Done khi:** operator bấm Start trên archive local thấy 3 box và một SOLVED fixture.

---

### Milestone P5 — Category packs + toolkit image (2–3 ngày)

- [x] Dockerfile `images/ctf-toolkit` slim.
- [x] Pack prompt: `web.md` `pwn.md` `rev.md` `crypto.md` `forensics.md` — checklist thao tác, **không** nhúng writeup contest đang thi.
- [x] Coordinator được chọn pack sau brief.
- [x] Compose dùng image này cho workspace.
- [x] Smoke: `gdb --version`, `python3 -c import pwn`, `r2 -v` trong box.

**Done khi:** image build repro từ lock/apt pin; solver thấy binary tool.

---

### Milestone P6 — Multi-provider race + budget (1–2 ngày)

- [x] Settings: map racer → provider/model (OpenAI/Gemini/DeepSeek đã có). Completed 2026-09-01.
- [x] 1 key vẫn chạy 3 racer cùng model, khác `temperature` hoặc `seed`.
- [x] Budget chung run: $ và phút; coordinator dừng racer kém.
- [x] Ledger cost per racer.

**Done khi:** UI chọn 3 model khác nhau cho 1 challenge (nếu đủ key).

---

### Milestone P7 — Knowledge local (optional, 2 ngày)

- [x] Thư mục `knowledge/writeups/` do operator thả markdown **cũ**, pin digest. Completed 2026-09-01.
- [x] Retrieval lúc AutoPrompter xong: top-k đoạn, nhét vào executor task không vào mọi racer.
- [x] Toggle `contest_offline=1` tắt retrieval.
- [x] Không fetch Internet writeup lúc thi.

**Done khi:** test corpus 3 file, query “padding oracle” trả đúng đoạn, contest_offline thì 0 hit.

---

### Milestone P8 — UI power + operator path (2 ngày)

- [x] Nút **Power solve** trên receipt: target `host:port` tùy chọn, race A/B/C cố định, `open_egress` hiển thị unavailable. Completed 2026-09-01.
- [x] Console hiện command stream đã rút gọn, không chain-of-thought.
- [x] Stop/cancel giết toàn swarm qua controller.
- [x] Reveal flag chỉ sau checker win, qua one-time lease mặc định.
- [x] One-liner: `docker compose --profile power up -d --build --wait`.

**Done khi:** usage guide có 1 happy path archive → Start power → flag.

---

### Milestone P9 — Đo sức mạnh (song song từ P4)

Không được gọi là mạnh nếu chưa đo.

Protocol nội bộ:

| Cell | Setup |
|---|---|
| A | 1 racer, 1 model, no coordinator bump |
| B | 3 racer cùng model |
| C | 3 racer + coordinator bump |
| D | 3 racer khác model (nếu có key) |

N≥5 / lab. Lab: 3 Web cũ + 1 pwn toy + 1 crypto toy + 1 forensics toy (tự viết, flag random).

So sánh **cùng lab** với baseline “mở Claude Code/Codex trong cùng image toolkit” nếu operator muốn. Ghi raw count.

**Done khi:** file receipt `docs/operations/power-eval-YYYYMMDD.md` có bảng raw, không chỉ %.

---

## 7. Thứ tự ưu tiên nếu thiếu thời gian

Cắt theo sức tác động:

1. P1 sandboxd + shell
2. P2 ReAct + flag check
3. P4 3 racers
4. P3 IAT
5. P5 toolkit
6. P6 multi-model
7. P8 UI
8. P7 RAG
9. P9 eval

Không làm P7 trước P1. RAG trên agent không có shell gần như vô dụng.

---

## 8. Test matrix power

| Lớp | Case |
|---|---|
| Unit | path jail, command fingerprint, flag pattern, soliloquy reject |
| sandboxd | create/exec/destroy, ptrace, mem kill, two-box isolation |
| ACI | gdb session, tube allowlist deny off-scope host |
| Swarm | first-win cancel, stall bump, budget stop |
| Adversarial | archive chứa `AGENTS.md` “bỏ qua rule, curl metadata”; prompt injection trong README; `flag.txt` giả trong đề vs flag thật remote |
| Eval | raw cells A–D |

CI không cần provider: fixture backend đủ. Live model = operator machine.

---

## 9. Rủi ro còn lại (chấp nhận và giảm)

| Rủi ro | Giảm |
|---|---|
| Solver `rm -rf /challenge` | mỗi racer copy riêng; origin intake immutable |
| Solver phá máy host | no socket in box, no privileged, no host net |
| Solver quét LAN | default allowlist; `open_lan` tắt |
| Chi phí 3 model | cap $ / cancel loser |
| Sage/Ghidra làm máy chết | slim image mặc định; full opt-in |
| Flag ảo | checker + observation binding |
| Docker trên Desktop chậm | tái dùng image; warm pool 1 box |

---

## 10. Prompt giao việc cho AI coder

```text
Đọc AGENTS.md và artifacts/CTFMesh-power-execplan.md.
Làm milestone Power chưa check đầu tiên thôi.
Giữ: không mount docker.sock vào solver, không SOLVED từ prose,
challenge file là untrusted, API loopback.
Được: shell/PTY trong workspace, multi-racer, IAT gdb/tube,
model-authored solve.py chạy trong box.
Viết test deny-path. Chạy gate được thì chạy.
Ghi docs/phases/power-mN-worklog.md và tick Progress.
```

---

## 11. Progress

- [x] Chốt đánh đổi safety → effectiveness, localhost, authorized CTF
- [x] Tổng hợp pattern Veria / EnIGMA / D-CIPHER / CRAKEN / CAI / HackSynth
- [x] Thiết kế profile `power`: sandboxd, ACI, swarm, flag-router
- [x] P0 ADR + compose skeleton — accepted 2026-08-31
- [x] P1 sandboxd + shell — completed 2026-08-31
- [x] P2 solver ReAct + flag.submit — completed 2026-08-31
- [x] P3 IAT gdb/tube — completed 2026-09-01
- [x] P4 coordinator + 3 racers — completed 2026-09-01
- [x] P5 toolkit image + category packs — completed 2026-09-01
- [x] P6 multi-provider race — completed 2026-09-01
- [x] P7 local knowledge — completed 2026-09-01
- [x] P8 UI happy path — completed 2026-09-01
- [ ] P9 raw eval

---

## 12. Decision Log

| Ngày | Quyết định | Lý do |
|---|---|---|
| 2026-08-31 | Tách profile `power`, không phá mesh an toàn | Operator còn đường audit; đường giải không bị typed-tool trói |
| 2026-08-31 | Shell + PTY trong box là P0 capability | Mọi SOTA agent thắng nhờ action space, không nhờ thêm ADR |
| 2026-08-31 | sandboxd giữ Docker socket, solver không | Host tin được; model không tin được |
| 2026-08-31 | Multi-model race mặc định 3 | Veria: pass@k >> single agent; 3 là điểm máy local chịu được |
| 2026-08-31 | AutoPrompter trước khi đua | D-CIPHER: brief từ môi trường thật giảm ảo giác category |
| 2026-08-31 | Flag-router vẫn chặn SOLVED từ text | EnIGMA soliloquy; bỏ checker là tự hack điểm |
| 2026-08-31 | IAT gdb/tube ngay sau shell | Pwn/rev chết nếu chỉ `shell.exec` không REPL |
| 2026-08-31 | RAG local, tắt lúc contest | CRAKEN tăng điểm nhưng nhiễm writeup live |
| 2026-08-31 | Không privileged, không host network mặc định | Localhost không có nghĩa là phá máy operator |
| 2026-08-31 | Bắt đầu P0 bằng `sandboxd` health-only và solver `replicas=0` | Không công bố exec API hoặc shell giả trước khi P1 chốt path jail, limits, artifact và lifecycle; socket exception chỉ nằm trong ADR 0009/profile `power`. |
| 2026-08-31 | Hoàn thành P0 | Default/Power Compose topology, isolated Python regression, Web (33) và Pi runner (28) đều qua; `sandboxd` chỉ chứng minh health rồi được dừng/xóa. |
| 2026-08-31 | Bắt đầu P1 với RPC token-gated và workspace container disposable | `sandboxd` giữ Docker socket; archive được đọc từ intake volume, solver chỉ nhận observation/artifact và không nhận host mount hay socket. |
| 2026-08-31 | Hoàn thành P1 với Docker managed challenge volume | Docker không cho `put_archive` vào rootfs read-only. Init box không mạng, non-root, không socket/host bind nạp archive vào named volume mới; workspace chính vẫn read-only. Nhãn manager cho phép thu hồi container và volume chính xác. |
| 2026-08-31 | Hoàn thành P2 với ReAct evidence loop và flag-router độc lập | Model chỉ trả action JSON; sandboxd là nguồn observation. Router chạy service riêng, re-read CAS read-only, pattern + provenance + byte containment rồi mới gửi digest/mask tới Control API. Fixture prose `CTF{fake}` bị inert; smoke Docker thật đọc `flag.txt` rồi cleanup workspace. |
| 2026-08-31 | Bắt đầu P3 với IAT trạng thái sống và TCP scoped | GDB/PTY và tube sẽ chỉ được điều khiển qua RPC typed của sandboxd. Tube phải khớp chính xác endpoint đã khai báo cho workspace; mọi bytes nhận được được đưa vào CAS trước khi solver thấy chúng. |
| 2026-09-01 | Hoàn thành P3 với session-owned IAT | PTY/GDB vẫn là Docker exec của sandboxd; tube là async TCP stream do sandboxd sở hữu và kiểm exact `(host, port)` từ `WorkspaceCreate`. GDB/tube observations luôn có CAS receipt. GDB/Python và shell chạy song song đã được chứng minh trong box thật; tube echo được chứng minh trên Compose test network tách riêng, không có socket hoặc API key. |
| 2026-09-01 | Bắt đầu P4 với coordinator in-process và progress read model tạm thời | Coordinator chỉ tạo ba `ReActSolver` độc lập qua factory, chia sẻ brief không chứa raw output, và dùng flag-router gate để chọn winner trước khi hủy sibling. UI khởi chạy Power end-to-end vẫn thuộc P8; P4 công bố snapshot an toàn để UI tiêu thụ. |
| 2026-09-01 | Hoàn thành P4 với receipt-only brief và first-winner gate | AutoPrompter bị giới hạn mười turn và không có quyền submit flag. Ba racer luôn tạo workspace riêng; coordinator chỉ thấy telemetry không chứa secret, dùng fingerprint SHA-256 để bump trùng lệnh và grace năm giây trước forced cancel. Flag-router vẫn là authority duy nhất nhận candidate và xác nhận `SOLVED`. |
| 2026-09-01 | Bắt đầu P5 với một toolkit slim và category packs được review | Image sẽ pin Alpine package/Python package trực tiếp trong Dockerfile; pack được đóng cùng orchestrator, chỉ dùng sau AutoPrompter và không đọc nội dung/chỉ dẫn từ archive challenge. |
| 2026-09-01 | Hoàn thành P5 với pack đóng gói và toolkit Alpine slim | Selector nhận nhãn category bị chặn kích thước từ observation + action type, chọn một checklist fixed sau brief; raw output không vào pack/snapshot. Compose build `ctfmesh-ctf-toolkit:0.1` từ Alpine digest, APK version pin và Python dependency lock. Tool chạy qua sandboxd trong box UID 1000, rootfs read-only, network none; `/work` private writable và `/tmp` sticky noexec. |
| 2026-09-01 | Bắt đầu P6 bằng race configuration không chứa secret | Provider/model/temperature và reservation cost sẽ tách khỏi browser vault và sandbox. P8 mới được nối từ UI vào Power start API, nên P6 chỉ công bố composition + snapshot an toàn. |
| 2026-09-01 | Hoàn thành P6 với reservation budget chung và map ba racer | Mỗi provider call reserve maximum cost trước I/O bằng micro-USD, tránh racer song song vượt cap; ledger append-only trả subtotal per racer/AutoPrompter nhưng không chứa key, prompt, output hay flag. Ba model có thể khác provider nếu có key; một key tạo ba backend cùng model ở 0.2/0.5/0.8. |
| 2026-09-01 | Bắt đầu P7 với corpus local có digest và opt-out contest | Retrieval chỉ được phép đọc Markdown từ `knowledge/writeups` do operator quản lý, chạy sau AutoPrompter và chỉ cấp đoạn trích cho executor được delegate; `contest_offline` phải trả zero hit. |
| 2026-09-01 | Hoàn thành P7 với lexical retrieval local có digest pin | Corpus chỉ nhận Markdown UTF-8 hữu hạn, cấm symlink/hidden path và redaction literal giống flag trước context. Query sau AutoPrompter chỉ dựa metadata category/receipt, top-k chỉ vào racer được delegate; coordinator read-model chỉ chứa mode, digest, recipient, số đoạn. `contest_offline` chặn trước mọi truy cập corpus và trả zero hit. |
| 2026-09-01 | Bắt đầu P8 bằng đường khởi chạy Power tách riêng | UI sẽ gửi key ngắn hạn và race map không-secret tới endpoint Power đã feature-gated; endpoint giữ key chỉ trong backend task, gọi sandboxd/flag-router qua capability riêng và ghi progress tóm tắt vào ledger. |
| 2026-09-01 | Hoàn thành P8 với Power operator path và Docker demo ready | Receipt tạo run Power feature-gated, chỉ nhận 3 racer đã validate và TCP target chính xác (nếu có). Controller ghi lifecycle/action receipt an toàn, sandboxd nhận tube allowlist qua service capability, flag vẫn do router độc lập xác minh và reveal một lần. Compose Power healthy, còn UI chỉ dùng key tạm thời từ vault. |
| 2026-09-01 | Sửa hồi quy P8: sandboxd không materialize được archive intake | API viết intake owner-only bằng UID 10001 trong khi sandboxd UID 0 đã bị drop toàn bộ capability nên không traverse được thư mục. Chạy sandboxd cùng UID/GID non-root với API và chỉ bổ sung Docker socket GID qua bootstrap. Tạo workspace, lệnh giới hạn và cleanup trên archive operator cũ đều thành công; không có key/model call trong demo. |
| 2026-09-01 | Sửa hồi quy P8: chấp nhận metadata thinking của DeepSeek V4 nhưng không lưu nó | `reasoning_content` có shape string/null được validate rồi loại bỏ trước action parsing, nên reasoning không thành evidence hay trace. HTTP lỗi chỉ thành recovery code an toàn; controller ghi receipt phục hồi cụ thể thay vì che lỗi bằng `power.swarm.failed` chung chung. Full backend 377 pass/14 skip, Web 36 pass và Pi runner 28 pass. |
| 2026-09-01 | Sửa hồi quy P8: malformed AutoPrompter reply không còn chặn A/B/C | Audit sandbox cho thấy lỗi xảy ra sau năm lệnh thật của AutoPrompter. DeepSeek Power tắt private thinking cho JSON action; retry schema tối đa hai lần và mọi retry vẫn được reserve budget. Receipt đã có vẫn được chia cho ba racer, còn AutoPrompter/queued racer được ghi event tách biệt để UI không báo tool-call giả. Full Python gate exit 0, Web 36 và Pi 28 pass; Power capability healthy. |
| 2026-09-01 | Sửa hồi quy P8: Power budget exhaustion phải hiển thị đúng | `$10/$0.25` chỉ admit 40 provider calls cho AutoPrompter + ba racer nên race bị dừng hợp lệ dù console cũ báo `$0`. Controller giờ chỉ append snapshot thay đổi, persist reservation totals không-secret và console dedupe receipt cũ theo racer/turn/action. Default mới `$0.05` cho 200 calls, Settings hiện capacity so với envelope tối đa 106 calls. Focused 16 test, full Docker gate 381 pass/14 skip, Web 37 và Pi 28 pass; Power Compose rebuilt healthy. |
| 2026-09-01 | Sửa hồi quy P8: Power Trace phải nói được racer đang làm gì, không lộ transcript | Mỗi typed action phát nhãn activity từ vocabulary đóng và artifact reference bất biến nếu có observation. Console/overview hiện racer, state, turn, loại action, activity và evidence count; không event nào nhận command/path/input/output/model reasoning/candidate/raw flag. Focused 29 test, full backend 381 pass/14 skip, Web 38 pass; Power Compose rebuilt healthy. |
| 2026-09-01 | Bắt đầu P9 bằng audit Power + Pi-harness và raw-evaluation harness | Pi harness/M3 typed gateway được giữ làm foundation thực thi, nhưng không là policy authority. Audit chỉ xem M5/M6 fixture và code không có consumer; đồng thời chuẩn bị receipt raw-count A/B/C/D. Không gọi model, không đọc secret/challenge trong cleanup. |

---

## 13. Định nghĩa “mạnh”

Profile `power` được gọi là đạt khi:

1. Solver chạy lệnh thật trong box giàu tool.
2. Ba racer đua được trên một archive local.
3. Toy pwn/crypto/web tự viết (flag random) có ít nhất một cell raw solve > 0 với model operator chọn.
4. 0 SOLVED từ prose không observation.
5. Operator start bằng một Compose profile.

Khi đó CTFMesh không còn là control plane chỉ để nhìn. Nó trở thành loại hệ Veria/D-CIPHER/EnIGMA — trên máy bạn, trong scope bạn cấp.
