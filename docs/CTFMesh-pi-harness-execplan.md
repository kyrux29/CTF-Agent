# CTFMesh — ExecPlan: Power racers chạy trên harness Pi

**Status:** kế hoạch triển khai
**Date:** 2026-09-01
**Đối tượng:** AI coder / developer
**Quyết định gốc:** vòng model **không** tự gọi Chat Completions trong Python. Mọi turn của AutoPrompter và racer đi qua **Pi SDK**. Kéo Pi từ GitHub, pin version, dùng compaction/tool-calling có sẵn.

Câu nhớ:

> sandboxd thực thi. flag-router kết luận. Pi nói chuyện với model. Python không còn là LLM client của Power.

---

## 0. Vì sao đổi

Power P2 hiện dùng `OpenAICompatibleSolverBackend` (`services/solver-runtime/.../model.py`):

- Mỗi turn nhét `action_schema` (~2k token) vào **user** JSON
- Tự giữ 8 observation raw
- Không prompt cache, không compaction, không usage chuẩn của harness
- Trùng việc mà Pi đã làm từ 0.12+ (compaction, tool defs một lần, session JSONL, steer)

Pi (`https://github.com/earendil-works/pi`, package `@earendil-works/pi-coding-agent`) đã là harness CTFMesh chọn từ M2. Docs: [SDK](https://pi.dev/docs/latest/sdk), [Compaction](https://pi.dev/docs/latest/compaction), [Security](https://pi.dev/docs/latest/security).

Việc đúng: **nối Power ACI vào Pi**, không viết thêm LLM loop.

---

## 1. Invariant không đổi

1. Solver workspace **không** mount Docker socket. Chỉ `sandboxd` nói Docker.
2. `noTools: "all"` hoặc `noTools: "builtin"` — Pi không được bash/read/edit **trên host runner**. Mọi quan sát qua custom tool → sandboxd.
3. ResourceLoader **reviewed only**. Không load `AGENTS.md` / `.pi` / `.agents` trong archive.
4. Flag chỉ `flag.submit` → flag-router. Prose trong session không SOLVED.
5. Provider key ở Pi runner process / memory lease, không vào workspace, DB, event raw.
6. API loopback, authorized CTF.
7. Không `pi install git:...` lúc runtime contest. Pin package lúc build.

---

## 2. Kiến trúc sau khi làm xong

```text
UI / Control API / PowerRunController
        │ spawn A/B/C + AutoPrompter
        ▼
services/pi-runner  (Node, Pi SDK)
        │ AgentSession × N
        │ tools: ctfmesh.shell / fs / gdb / tube / flag.submit
        │ compaction + usage từ Pi
        ▼
typed control client  →  sandboxd  →  workspace box
                    ↘  flag-router
```

`ReActSolver` Python **không** gọi model nữa. Có thể giữ như interpreter fixture cho test không mạng, hoặc gói thành “tool executor” phía Python. Production Power: `backend=pi`.

Coordinator Python vẫn: spawn, budget, diversity fingerprint, first-win cancel, brief. Không `post_chat_completions`.

---

## 3. Kéo Pi từ GitHub — quy trình bắt buộc

Repo: `https://github.com/earendil-works/pi`
Package: `@earendil-works/pi-coding-agent` (+ `pi-agent-core`, `pi-ai` theo lock của đúng tag)

Tree hiện pin ~`0.84.3` (M2). Tag mới hơn đã có **0.84.4** (2026-08-28): sửa compaction gửi tool result quá lớn trước khi compact, usage notice, `toolChoice` lúc summarize.

### 3.1 Lệnh (trong `services/pi-runner`)

```bash
# Xác nhận tag, không track main sống
git ls-remote --tags https://github.com/earendil-works/pi.git 'v0.84.*'

# Cài đúng tag đã review — ưu tiên npm registry trùng tag
pnpm add @earendil-works/pi-coding-agent@0.84.4

# Nếu registry lệch source: pack từ GitHub tag
git clone --depth 1 --branch v0.84.4 https://github.com/earendil-works/pi.git /tmp/pi-src
# đọc packages/coding-agent/package.json; chỉ bump nếu build/test Pi upstream xanh
```

Không deep-fork. Không `npm install github:earendil-works/pi` không tag.

### 3.2 `services/pi-runner/UPSTREAM.md` (viết lại khi bump)

Bắt buộc có:

- URL repo
- tag + commit SHA 40 hex
- tên package + version lock
- ngày review
- allowlist API dùng: `createAgentSession`, `defineTool`, `SettingsManager`, `compact`, `steer`, `abort`, `noTools`
- test deny: built-in bash không xuất hiện; cwd challenge không load skill

### 3.3 Gate bump

- [x] `pnpm --filter @ctfmesh/pi-runner check` xanh
- [x] Test: `noTools` ẩn bash/read/edit mặc định
- [x] Test: session_before_compact không đưa custom tool vào compaction call nếu upstream đã fix (0.84.3+)
- [x] Diff breaking SDK 0.84.0 (`ModelsRequestTransforms`, session APIs) đã được code mình theo

Nếu 0.84.4 phá contract M2: giữ 0.84.3, ghi blocker, không nhảy main.

---

## 4. Cấu hình Pi cho CTF (token)

Dùng `SettingsManager.inMemory()` + `applyOverrides`, **không** ghi `~/.pi` trong container.

Đề xuất ban đầu (chỉnh sau khi đo usage event):

```ts
compaction: {
  enabled: true,
},
// tên field theo đúng schema settings của tag đã pin — đọc docs/compaction.md cùng tag
// Mục tiêu hành vi:
//   reserveTokens: 8192   // đủ 1 turn tool+reply; 16384 mặc định quá rộng cho 3 racer
//   keepRecentTokens: 6000 // CTF cần vài lệnh gần, không 20k verbatim
```

Thêm:

- System prompt ngắn, giống role Power hiện tại: một action qua tool, không bịa output.
- `thinkingLevel` thấp/off với DeepSeek/Gemini nếu SDK cho — Power không cần CoT dài.
- Custom tool `execute` trả `content` **đã cắt** (head+tail, max ~2–4k ký tự). Raw 64KiB chỉ nằm CAS sandboxd. Pi compaction không phải chỗ giữ hexdump.

Optional sau P-stable: port ý tưởng [pi-dcp](https://github.com/PSU3D0/pi-dcp) (dedupe tool output giống nhau) **copy pattern vào extension in-tree**, không `pi install` lúc chạy.

---

## 5. Custom tools Pi = ACI Power

Đăng ký bằng `defineTool` + TypeBox. `execute` chỉ gọi control client → sandboxd. Không `child_process` trên runner.

| Pi tool name | Maps sang sandboxd |
|---|---|
| `ctf_shell_exec` | `exec` |
| `ctf_fs_list` / `ctf_fs_read` / `ctf_fs_write` | path jail `/challenge` `/work` |
| `ctf_pty_start` / `send` / `read` / `close` | PTY |
| `ctf_gdb_start` / `cmd` / `close` | gdb IAT |
| `ctf_tube_connect` / `send` / `recv` / `close` | allowlist host:port |
| `ctf_flag_submit` | flag-router; tool result `accepted|rejected` không raw flag |

`tools: [những tên trên]` + `noTools: "all"`.

Turn authority / lease giữ như `services/pi-runner/src/tools.ts` hiện có. Power racer = session role `exploit_builder` (đủ tool) hoặc role hẹp hơn cho AutoPrompter (cấm `ctf_flag_submit`).

Schema tool do Pi gửi provider **một lần** kiểu native function calling — đây là chỗ tiết kiệm token so với `model.py`.

---

## 6. Session layout một Power run

| Session | Role | max wall | Ghi chú |
|---|---|---|---|
| `auto` | AutoPrompter | 6–10 turn | không flag tool |
| `racer-a` | static | budget chung | brief trong prompt đầu |
| `racer-b` | dynamic | | cùng brief, hint khác |
| `racer-c` | exploit | | có flag tool |

- Session JSONL trên volume runner, không mount challenge.
- `prompt(brief)` một lần lúc start; các turn sau chỉ tool result.
- Coordinator bump = `session.steer(...)` hoặc `followUp` khi idle — text operational, không phải evidence.
- Win = flag-router event → `session.abort()` mọi sibling + destroy workspace.
- Persist steer như M2: append JSONL khi idle.

---

## 7. File đụng

| Path | Việc |
|---|---|
| `services/pi-runner/package.json` + lock | pin 0.84.4 (hoặc tag đã review) |
| `services/pi-runner/UPSTREAM.md` | SHA + API allowlist |
| `services/pi-runner/src/session-factory.ts` | Settings compaction, noTools, cwd trống |
| `services/pi-runner/src/tools.ts` | đủ ACI Power, truncate content |
| `services/pi-runner/src/roles.ts` | role Power + pack digest |
| `services/pi-runner/src/task-consumer.ts` | job `power_turn` / `power_session_start` |
| `services/pi-runner/src/resource-loader.ts` | giữ deny challenge discovery |
| `apps/api/.../power_runs.py` | start session qua runner HTTP nội bộ, không mở `OpenAICompatibleSolverBackend` |
| `services/orchestrator/.../power_swarm.py` | backend mặc định `pi`; fixture Python chỉ test |
| `services/solver-runtime/.../model.py` | đánh dấu test-only / xóa khỏi production export |
| `docs/adr/0010-power-on-pi-harness.md` | quyết định này |
| `docs/phases/power-pi-mN-worklog.md` | worklog |

Không xóa sandboxd, flag-router, toolkit image, UI Power.

---

## 8. Milestone

### M-PI-0 — ADR + pin GitHub tag (nửa ngày)

- [x] `docs/adr/0010-power-on-pi-harness.md`: Pi là LLM harness duy nhất của Power; Python không gọi provider vì “đỡ token”.
- [x] Clone/tag review `v0.84.4` (hoặc giữ 0.84.3 nếu gate fail).
- [x] Cập nhật lock + UPSTREAM.md.
- [x] Test package import `createAgentSession` đúng API tag.

**Done khi:** `pnpm --filter @ctfmesh/pi-runner check` xanh trên pin mới; ADR merged trong docs.

---

### M-PI-1 — Power tools trên Pi, không built-in host (1–2 ngày)

- [x] Đăng ký tool bảng §5; execute → sandboxd.
- [x] Cắt tool result ≤ 4000 ký tự (head/tail) + `truncated: true` trong details.
- [x] AutoPrompter session: exclude `ctf_flag_submit`.
- [x] Fixture model / fake transport: session gọi `ctf_fs_list` → observation artifact.

**Done khi:** test Pi không có tool `bash`; test path escape deny; test truncate 64KiB.

---

### M-PI-2 — Power controller nói chuyện với Pi runner (2 ngày)

- [x] Job durable: `power_session_start`, `power_steer`, `power_abort`.
- [x] `PowerRunController` tạo 1+3 session, truyền brief, target allowlist, lease key.
- [x] First accepted flag → abort siblings (giữ grace 5s).
- [x] Python `OpenAICompatibleSolverBackend` không nằm trên path Compose `power`.

**Done khi:** integration không live key: 3 session fixture, 1 flag file → SOLVED + 2 aborted; `model.py` không được import từ `power_runs.py`.

---

### M-PI-3 — Compaction + usage (1 ngày)

- [x] Settings compaction on; `keepRecentTokens` ~6k; `reserveTokens` ~8k (đúng key schema tag).
- [x] Map event Pi usage → budget ledger (không tin model self-report để nới cap).
- [x] Test: nhồi nhiều tool result giả → compact chạy, session còn prompt được.
- [x] Test: compact failure event không SOLVED.

**Done khi:** worklog ghi token trước/sau compact trên fixture dài.

---

### M-PI-4 — Phân vai + brief ngắn (1 ngày)

- [x] Brief structured ≤2k ký tự (files, excerpt, already_tried, category).
- [x] Racer A/B/C system prompt khác nhau (static / dynamic / exploit).
- [x] Fingerprint cả `fs_read` path để bump trùng recon.

**Done khi:** unit coordinator: hai `fs_read` cùng path = duplicate.

---

### M-PI-5 — Đo raw (P9 thật)

- [ ] Một lab file-flag + một lab toy pwn/web với model operator.
- [ ] So sánh (cùng model, cùng cap):
  - A: 1 Pi session
  - B: 3 Pi session
  - X: (tham chiếu lịch sử) Python ReAct cũ nếu còn fixture
- [ ] Ghi `docs/operations/power-pi-eval-YYYYMMDD.md` raw count + usage tokens nếu Pi emit.

**Done khi:** có bảng, không chỉ “cảm giác tiết kiệm”.

---

## 9. Test bắt buộc

| Case | Kỳ vọng |
|---|---|
| Built-in bash/read vắng | session.tools không chứa |
| CWD có `AGENTS.md` độc hại | loader bỏ qua |
| Tool output 64KiB | model thấy ≤ cap cắt |
| flag prose trong assistant text | không SOLVED |
| flag tool + artifact đúng | router accept |
| compact giữa chừng | không mất lease; không double session |
| abort khi sibling win | workspace destroy |
| budget hết | không gọi provider thêm |
| pin sai version | CI `pnpm` lock fail |

---

## 10. Việc cấm trong plan này

- Tự viết thêm Chat Completions client “tối ưu hơn Pi”.
- `tools: ["bash"]` trên runner host.
- `pi install git:github.com/...` trong container lúc solve.
- Load skill từ archive.
- Bật thinking level cao mặc định.
- Tăng 6 racer trước M-PI-5.
- Fork Pi để sửa compaction — dùng settings/extension in-tree trước.

---

## 11. Prompt giao việc

```text
Đọc AGENTS.md, docs/adr/0002-pi-sdk-harness.md, docs/adr/0009-power-profile.md
và docs/CTFMesh-pi-harness-execplan.md.

Làm milestone M-PI chưa check đầu tiên.
Pi là LLM harness duy nhất cho Power. Không gọi provider từ
services/solver-runtime/model.py trên đường production.
Kéo đúng tag GitHub đã ghi trong plan; cập nhật UPSTREAM.md
(tag + commit SHA). noTools ẩn built-in. Tool chỉ sandboxd.
Chạy pnpm --filter @ctfmesh/pi-runner check và pytest power liên quan.
Ghi docs/phases/power-pi-mN-worklog.md.
```

---

## 12. Progress

- [x] Quyết định: Power dùng Pi, không tự gọi LLM
- [x] Chốt nguồn GitHub `earendil-works/pi` + cách pin tag
- [x] Chốt compaction/tool truncate/session map
- [x] M-PI-0 ADR + pin
- [x] M-PI-1 Power tools trên Pi
- [x] M-PI-2 Controller → runner
- [x] M-PI-3 Compaction settings + usage
- [x] M-PI-4 Brief/vai
- [ ] M-PI-5 Raw eval

---

## 13. Decision log

| Ngày | Quyết định | Lý do |
|---|---|---|
| 2026-09-01 | LLM loop Power = Pi SDK | Harness đã có tool calling, compaction, session, steer; Python JSON-schema-mỗi-turn đốt token |
| 2026-09-01 | Pin tag GitHub, không track main | Reproducible; 0.84.4 đáng xét vì fix compaction + large tool result |
| 2026-09-01 | noTools all + custom ACI | Pi không phải sandbox; sandboxd mới được exec |
| 2026-09-01 | Cắt tool content trước khi vào session | Compaction rẻ hơn nếu không nuốt 64KiB strings |
| 2026-09-01 | model.py xuống test-only | Tránh hai đường gọi model lệch protocol |
| 2026-09-01 | Không runtime `pi install` | Contest/offline; extension token chỉ code đã review trong image |
| 2026-09-01 | Bắt đầu M-PI-0 với tag `v0.84.4` tại commit `b79e4cc834970cca69daebffab7df1da7d1e52c4` | Xác minh tag GitHub, npm package, integrity và SDK surface trước khi thay production model path. |
| 2026-09-01 | Hoàn thành M-PI-0; giữ production Power path hiện tại đến M-PI-2 | Pin, ADR, deny-path/API/compaction regression và toàn bộ repository gate đều xanh; M-PI-1 là mốc chưa check kế tiếp. |
| 2026-09-01 | Bắt đầu M-PI-1 với Power custom-tool adapter riêng | Giữ Pi runner không có host shell/target access; adapter chỉ phụ thuộc typed control-runtime seam để M-PI-2 nối durable jobs sau khi tool contracts được kiểm thử. |
| 2026-09-01 | Hoàn thành M-PI-1 với 16 Power custom tools và typed control seam | Bề mặt Pi không có built-in host tool; path/scope/ownership được validate, output vào context bị chặn 4k ký tự và chỉ artifact metadata được lưu trong details. M-PI-2 mới nối durable controller vào seam này. |
| 2026-09-01 | Bắt đầu M-PI-2: durable Power controller → Pi runner | Thay đường production Power gọi Python `OpenAICompatibleSolverBackend` bằng bốn Pi session có lease, workspace và flag-router authority tách biệt. |
| 2026-09-01 | Hoàn thành M-PI-2: 1 AutoPrompter + 3 racer qua durable Pi jobs | Controller cấp workspace/lease trước khi queue; abort có ba slot riêng trong runner và start lease heartbeat. Fixture flag được router đọc lại trước SOLVED, hai sibling racer bị abort. Power Compose không còn service `solver-runtime`. |
| 2026-09-01 | Sửa hồi quy sau M-PI-2 cho egress và Power telemetry | Pi cài cùng Undici proxy dispatcher với SDK trước khi gọi model; `fs_list` tương thích BusyBox; terminal provider error không còn thành `ready`; heartbeat không đua với completion. Mỗi typed Power action thêm receipt metadata-only để UI thấy racer đang hoạt động mà không ghi command/output/prompt/key/flag. M-PI-3 vẫn là mốc chưa check kế tiếp. |
| 2026-09-01 | Bắt đầu M-PI-3: compaction và usage harness | Dùng đúng schema Pi 0.84.4, usage chỉ là telemetry bị validate; budget reservation vẫn là authority. Tham khảo `verialabs/ctf-agent`: giữ ý tưởng race/usage/loop awareness, không sao chép raw message bus, direct Docker control, raw shell, hay key environment. |
| 2026-09-01 | Hoàn thành M-PI-3: compaction + usage telemetry | Power Pi dùng policy in-memory `reserveTokens=8192`, `keepRecentTokens=6000`; session usage chỉ gửi delta counters/cost không transcript và chỉ có thể debit cap. Fixture custom-tool dài giảm context 34,485 → 23,528 tokens rồi tiếp tục prompt được; compact failure không có route SOLVED. Full Python, Pi, Web, static và Compose gates đều xanh. |
| 2026-09-01 | Ưu tiên mục tiêu Power: hiệu năng và năng lực giải | Tối ưu được đo bằng context hữu ích, số tool observation, thời gian tới evidence và solve đã verifier; scope, sandbox, key isolation và independent verification là ranh giới cố định, không phải các tuỳ chọn bị nới để đổi lấy tốc độ. |
| 2026-09-02 | Sửa hồi quy worker/provider sau M-PI-3, không bắt đầu M-PI-4 | Ledger xác nhận queue/lease đúng nhưng DeepSeek từ chối credential với 401; Pi nay chỉ công khai failure code allowlist. Claim loop retry lỗi Control API tạm thời và live runner có restart policy; lỗi protocol khác vẫn fail closed. |
| 2026-09-02 | Chuẩn hóa tên Power tool để tương thích provider, vẫn chưa bắt đầu M-PI-4 | Real DeepSeek turn từ chối dấu chấm trong `function.name`; 16 tool đổi từ `ctf.*` sang `ctf_*` và có regex regression. Theo yêu cầu local-only, key được lưu rõ trong browser local storage nhưng vẫn không vào DB/event/sandbox/container environment. |
| 2026-09-02 | Sửa projection hoạt động live sau M-PI-3, chưa bắt đầu M-PI-4 | Ledger của run thật có hơn 90 Power action nhưng UI hiện 0 vì chỉ nhận vocabulary/counter cũ. Web nay ánh xạ closed action type sang mô tả cố định và đếm receipt append-only; Playwright xác nhận A=24, B=22, C=28 mà không lộ command/output/model text/key. |
| 2026-09-02 | Bắt đầu M-PI-4: brief ngắn, lane riêng và điều hướng racer | Dùng receipt intake đã redaction để tiết kiệm context, tách A/B/C theo static/dynamic/exploit để giảm recon lặp, và cho operator một feed Pi đã review để steer khi turn đang chạy. |
| 2026-09-02 | Hoàn thành M-PI-4: brief/lane/deduplicate và operator feed | Brief ≤2k có category/files/excerpt/already-tried; `ctf_fs_read` cùng path thành fingerprint duplicate và Pi nhận nudge đổi evidence. Browser chỉ hiển thị brief, steer, final text block đã redaction—không CoT/tool args/output/secret—và steer streaming dùng Pi `session.steer`. Python, Pi, Web, static và Compose gates đã qua; worklog ghi rõ điều kiện PATH của full Python gate. |
| 2026-09-02 | Bắt đầu M-PI-5: benchmark Power-on-Pi tái lập được | Đo một session so với ba racer bằng receipt không chứa challenge, prompt, tool output, API key hay flag; benchmark thật sẽ chỉ dùng lab/operator scope đã được ủy quyền. |
| 2026-09-02 | Sửa ràng buộc evidence của `ctf_flag_submit` trước benchmark | Model không còn tự chép artifact ID/SHA. Tool observation cấp handle `obs_N` chỉ sống trong Pi session, submit resolve handle về immutable artifact và handle lạ bị từ chối trước Control API. Điều này giữ flag-router độc lập đồng thời loại một nguyên nhân làm live run không ra flag. |
| 2026-09-02 | Bổ sung terminal live đã redaction cho từng racer trong M-PI-5 | Sau mỗi Power custom tool, Pi gửi command/operation, stdout/stderr cap 6KiB, exit/timeout qua route lease-bound. Runner + API redaction và UI deny-path giữ key/cookie/token/raw flag/candidate ngoài timeline; full output vẫn immutable artifact. Dùng để operator steer nhanh, không thay đổi tiêu chí raw eval hay verifier. |
