# CTFMesh Operator Desk — Hướng dẫn thiết kế giao diện

**Status:** design spec để AI/dev implement
**Date:** 2026-09-01
**Bám source:** `apps/web` snapshot Power (App.tsx, RunConsole, styles.css)
**Sản phẩm:** control plane local, single operator, archive → Power race → evidence → flag reveal

> UI là **bàn điều khiển CTF**, không phải chat GPT, không phải dashboard marketing.
> Người dùng nhìn: challenge nào, 3 racer đang làm gì, budget còn bao nhiêu, flag đã được checker xác nhận chưa.

---

## 0. Nguyên tắc (không đàm phán)

1. **Evidence > transcript.** Không render chain-of-thought, prompt, raw stdout, API key, flag thô — trừ control **Reveal** một lần.
2. **Web không phải agent.** Browser không exec tool. Mọi Start đi Control API → Pi / sandboxd.
3. **Một việc trên một mặt.** Activity bar chỉ mở một panel (History / Progress / Stats / Help). Settings là drawer riêng.
4. **Fail-closed nhìn thấy được.** Thiếu slot, sandboxd, key, origin sai → nút Start disabled + mã lỗi người đọc được, không spinner vô hạn.
5. **Tối trên nền tối.** Ca CTF dài, giảm glare. Không theme sáng bắt buộc ở v1.
6. **Không CDN font/icon.** Asset local, CSP giữ nguyên. Icon = SVG inline 16–20px, không emoji trang trí.
7. **Bàn phím trước.** Mọi control chính có label, focus ring, `Esc` đóng overlay.
8. **Copy tiếng Việt hoặc English thống nhất một locale.** Không trộn “Power solve” / “Bắt đầu giải” lung tung trong cùng view — chọn một glossary (§9).

---

## 1. Tính cách giao diện

| Là | Không là |
|---|---|
| Workbench tối, mật độ cao, giống IDE + lab console | Onboarding SaaS, hero, gradient mesh |
| Số liệu: turn, racer state, $ ước lượng, wall clock | Chart rỗng, “AI thinking…” giả |
| Tem trạng thái: queued / racing / solved / rejected | Badge “99% confidence” |
| Chữ mono cho id, digest, host:port | Comic / display font |

Tham chiếu cảm giác: VS Code activity bar + Linear density + terminal statusline. Accent hiện trong CSS là xanh `#10a37f` (gần ChatGPT). **Đổi accent sang teal-lab** để khỏi giống chat product:

- Primary: `#3ee0b4` trên nền `#101010` — tín hiệu “verified / live”
- Warning: `#f5b74d` — thinking / budget
- Danger: `#ff9b99` — deny / reject
- Info: `#7aa2ff` — network / tube

Giữ scale xám đã có: `#101010` `#171717` `#212121` `#2b2b2b` `#383838`.

---

## 2. Information architecture

```text
┌────┬──────────────────────────────┬─────────────┐
│ 48 │  Main workbench              │  Settings   │
│ px │  (1–3 panes challenge)       │  overlay    │
│    │                              │  chỉ khi mở │
│ IB │  ┌─ Intake / Power launch ─┐ │             │
│    │  └─ Evidence console ──────┘ │             │
│    │     (slide over, không route │             │
│    │      trắng)                  │             │
└────┴──────────────────────────────┴─────────────┘
```

**Activity bar trái (48px, cố định)**

| Icon | View | Nội dung |
|---|---|---|
| đồng hồ | History | Archive + run summary từ API |
| sóng | Progress | Run đang racing / verifying |
| cột | Stats | turn, $ reserved, win/lose — suy từ ledger |
| ? | Help | 1 trang ngắn, không essay |
| bánh răng đáy | Settings | key vault, racer map, budget |

Click lại icon đang mở → thu panel, trả width cho workbench.

**Workbench**

- Trống: dropzone archive lớn, một câu “Chưa có case. Thả ZIP/TAR.”
- Sau inspect: receipt metadata + **Power launch card**
- Khi Start: console evidence **đè workbench** (class hiện có `.run-workspace-window`), không điều hướng trang mới. `?run=` deep-link.

**Không** tách “chat với agent”. Không tab “Prompt playground”.

---

## 3. Design tokens

Implement bằng CSS variables trên `:root` / `.desk`. Không Tailwind CDN.

```css
:root {
  --bg-0: #101010;
  --bg-1: #171717;
  --bg-2: #212121;
  --bg-3: #2b2b2b;
  --bg-4: #383838;
  --line: #3d3d3d;
  --text: #ececec;
  --text-dim: #a4a4a4;
  --text-faint: #737373;
  --ok: #3ee0b4;
  --ok-dim: #1a7a62;
  --warn: #f5b74d;
  --bad: #ff9b99;
  --info: #7aa2ff;
  --mono: ui-monospace, "SF Mono", "Cascadia Code", "JetBrains Mono", Menlo, monospace;
  --sans: "IBM Plex Sans", "Source Sans 3", ui-sans-serif, system-ui, sans-serif;
  /* nếu chưa vendor font: system-ui thôi, đừng Google Fonts */
  --radius: 10px;
  --bar: 48px;
  --pad: 12px;
  --focus: 0 0 0 2px var(--bg-0), 0 0 0 4px var(--ok);
}
```

**Type scale**

| Role | Size / weight |
|---|---|
| Title workbench | 16px / 600 |
| Section | 13px / 600, uppercase 0.04em, color dim |
| Body | 13px / 400, line 1.45 |
| Meta / id | 12px mono |
| Button | 13px / 600 |
| Statusline | 11px mono |

**Spacing:** 4pt grid (4, 8, 12, 16, 24). Bar 48, panel History 280px.

**Elevation:** một overlay = `0 24px 64px rgb(0 0 0 / 0.55)` + border `--line`. Không stack 3 modal.

---

## 4. Màn hình và flow

### 4.1 Cold start

- Nền `--bg-0`, grid rất mờ (opacity ≤ 0.04) — có thể bỏ nếu CSS đã phình.
- Dropzone nét đứt, chiều cao min 180px.
- Dưới: một hàng “Settings ⚙ để dán key trước khi solve”.
- Không carousel, không video.

### 4.2 Receipt

Chỉ hiện field an toàn:

- tên file, format, SHA-256 rút 12 ký tự + copy
- số entry, bytes expanded
- `target network: 0` vs `provider egress: n` tách rõ
- category heuristic = chip “gợi ý”, không “đã giải”

Hành động chính **một** nút primary: **Start Power**.
Triage metadata = secondary / collapsed `<details>`.

### 4.3 Power launch card

Bố cục 3 khối dọc, không form 20 field:

1. **Racer board** — 3 hàng A/B/C: provider · model · temp. Nút “Sửa trong Settings”.
2. **Target** — `<details>` đóng mặc định. Input `host:port` + checkbox “đúng instance được cấp quyền”.
3. **Limits** — một dòng: `60 phút · $10 · 3 racer`. Chi tiết trong Settings.

Primary disabled khi:

- capabilities `power` không ready
- chưa có receipt
- thiếu key cho provider đang chọn
- target malformed

Kèm 1 dòng `missing: sandboxd` đúng mã API.

### 4.4 Settings drawer

Rộng 420px, phải hoặc center dialog hiện có (`.power-settings-dialog`). Thứ tự:

1. Ba ô key OpenAI / Gemini / DeepSeek — `type=password`, không autocomplete
2. Trạng thái lưu local và nút Remove saved keys
3. Racer map A/B/C
4. Wall time, max $, max $/turn
5. Density compact/comfortable
6. Help 1 đoạn: key chỉ ở browser local storage, không vào DB

`Esc` / click backdrop đóng. Theo profile local-only hiện tại, key được lưu
plaintext trong `localStorage` của đúng browser profile; UI phải nói rõ đây
không phải secret vault và luôn có nút **Remove saved keys**.

### 4.5 Evidence console (quan trọng nhất lúc solve)

Header:

```text
RUN  a1b2c3…     RACING      12:04 / 60:00     $1.20 / $10     [Stop]
```

Thân **3 cột racer** (desktop ≥ 1200px), stack dọc khi hẹp:

```text
 A static          B dynamic         C exploit
 running  t=7      bumped t=4        queued
 last: read file   last: gdb cmd     —
```

Mỗi cột:

- state chip (màu §5)
- turn count, observation count
- `last_action_summary` **cố định vocabulary** (đã có trong runner) — không hiện argv
- fingerprint prefix mono 8 ký tự nếu cần debug

Cột phải hoặc đáy: **activity rail** append-only (lifecycle events). Dòng mẫu:

`18:04:12  racer-B  Inspecting the binary in the debugger.`

Không accordion 200 dòng gdb.

Footer khi `solved`: nút **Reveal flag** một lần, input readonly, nút copy, chữ “không lưu lại nếu đóng”.

### 4.6 Progress / History

History: nhóm Archive | Runs. Click mở pane + optional console.
Progress: chỉ run `queued|racing|verifying`. Cancel tại chỗ.
Stats: 4 số — runs, solved, turns, $ reserved. Không pie chart.

---

## 5. Trạng thái và màu

| State | Chip | Ý nghĩa operator |
|---|---|---|
| queued | xám | chưa có session |
| briefing | info | AutoPrompter |
| racing / running | ok nhấp 1s (reduced-motion: tĩnh) | đang tool |
| bumped | warn | coordinator steer |
| verifying | info | flag-router |
| solved | ok đặc | checker thắng |
| rejected / stopped | dim | hết turn / submit sai |
| failed | bad | sandbox/provider |
| cancelled | dim | Stop |
| budget_exhausted | warn | hết $ hoặc phút |

Một run chỉ một màu header. Racer có thể khác nhau.

---

## 6. Motion

- Overlay vào 180–220ms `cubic-bezier(0.2, 0.8, 0.2, 1)` — đã có `run-window-enter`.
- Chip live: opacity pulse 1.2s. `@media (prefers-reduced-motion: reduce)` tắt hết animation.
- Activity rail: dòng mới insert, không flash cả list.
- Không skeleton 8 hàng giả “AI đang nghĩ”. Dùng elapsed timer + state thật (`queued/ready/running`).

---

## 7. Thành phần (component spec)

Giữ file hiện có; đừng tạo design-system package.

| Component | File | Trách nhiệm UI |
|---|---|---|
| Desk shell | `App.tsx` | bar, panes, overlay routing |
| PowerLaunch | đoạn launch trong `App.tsx` (tách file nếu >400 dòng) | dropzone, board, start |
| SettingsDialog | cùng App hoặc `SettingsDialog.tsx` | vault + racer map |
| RunConsole | `RunConsole.tsx` | header metrics, 3 cột, rail, reveal |
| HintDeck | `HintDeck.tsx` | chỉ hiện khi profile mesh/hint; Power mặc định ẩn |
| StatusChip | mới nhỏ | map state → color |
| RacerColumn | mới tách từ console | một racer |

**Button**

- `.power-primary` — ok fill, chữ `#101010`
- `.power-secondary` — ghost border `--line`
- `.power-danger` — Stop / Forget keys

Chiều cao 32px compact, 36px comfortable. Không button 48px marketing.

**Dropzone**

- Drag over: border `--ok`
- File quá 128MiB: error tại chỗ, không upload

**Mono ids:** luôn `title={full}` + copy-on-click.

---

## 8. Layout responsive

| Rộng | Hành vi |
|---|---|
| ≥ 1280 | bar + optional history 280 + workbench; console 3 cột racer |
| 768–1279 | bar + workbench; console 1 cột xếp A rồi B rồi C |
| < 768 | bar đáy hoặc top; Settings full screen; Help/Settings ghim đáy như usage guide |

Không yêu cầu mobile-first CTF — desktop là primary. Mobile chỉ đọc progress + stop.

---

## 9. Glossary UI (dùng một bản)

| Nội bộ | Chữ trên UI (vi) | Không dùng |
|---|---|---|
| Power solve | Chạy Power | “Hack”, “Auto pwn” |
| racer | Racer A/B/C | “Agent bạn”, “Nhân viên AI” |
| observation | Quan sát | “Suy nghĩ” |
| flag-router | Đã kiểm chứng | “AI chắc đây là flag” |
| thinking | Đang chạy | “Đang suy luận…” |
| vault | Khoá provider | “API wallet” |

Nếu locale en: `Power run`, `Racer A`, `Verified`, `Running`.

---

## 10. Accessibility

- Mọi icon button: `aria-label`.
- Dialog: `role="dialog"`, focus trap, restore focus.
- Live region: `aria-live="polite"` cho state run (không mỗi tool line).
- Contrast text-dim trên `#171717` ≥ 4.5:1 — `#a4a4a4` đạt; đừng hạ `#666`.
- Không thông tin chỉ bằng màu: kèm chữ `SOLVED`.
- Tab order: dropzone → start → settings → console stop.

---

## 11. Bảo mật trên UI (thiết kế)

- Key: `input type=password`, không log, không hiện trong History DOM.
- Flag: không để trong `title`, URL, `localStorage`.
- Untrusted receipt field: text node React, không `dangerouslySetInnerHTML`.
- Error API: hiện `code` allowlist (`source_slot_unavailable`), không stack.
- Copy flag: clipboard rồi banner “đã copy — không dán vào chat công khai”.

---

## 12. CSS hygiene (nợ hiện tại)

`styles.css` ~8k dòng, token lặp nhiều cụm. Khi implement spec này:

1. Gom token vào một khối `:root` đầu file.
2. Không thêm theme thứ ba.
3. Component mới dùng biến, không hex rải.
4. Xóa rule dead của blueprint-grid nếu không còn node.
5. Cấm import font URL.

---

## 13. Wireframe chữ (implement đúng thứ tự block)

```text
[⏱][〰][▦][?]          CTFMesh          [⚙]

HISTORY                 WORKBENCH
 Archives               ┌ dropzone ─────────────┐
  dump.zip  18:02       │  Thả archive CTF      │
 Runs                   └───────────────────────┘
  run_ab12  racing        Receipt  dump.zip  tar.gz  a1b2c3d4e5f6
                          Target network 0 · Ready for Power

                          RACERS
                          A DeepSeek v4-pro  t=0.2
                          B DeepSeek v4-pro  t=0.5
                          C DeepSeek v4-pro  t=0.8
                          [Sửa map]

                          ▸ Target host:port (tùy chọn)

                          [ Chạy Power ]   60 phút · $10
```

Console sau Start:

```text
┌ run_ab12  RACING  04:12/60:00  $0.40/$10  [Dừng] ┐
│ A t=8 running   B t=5 bumped   C t=2 running     │
│ Mapping files   gdb inspect    write work file   │
│─────────────────────────────────────────────────│
│ 18:06:01  briefing done                          │
│ 18:06:08  A  Reading one challenge file.         │
│ 18:06:19  B  Starting a debugger…                │
└─────────────────────────────────────────────────┘
```

---

## 14. Việc UI *không* làm

- Chat bubble xen kẽ user/assistant
- Markdown preview source challenge
- Terminal xterm.js raw PTY (lộ payload / flag)
- Chọn `base_url` provider
- Slider “creativity” ngoài temperature đã có trong Settings
- Confetti khi SOLVED
- Dark/light toggle trước khi token gọn
- Trang landing / pricing
- Nhúng Hint Deck 3 technique Web vào mặc định Power

---

## 15. Plan implement cho AI (UI only)

Làm từng PR, không đụng protocol Power/Pi.

### U1 — Token + shell

- [x] Một khối `:root` token §3
- [x] Activity bar 48px + 4 view + settings
- [x] Workbench trống đúng copy cold start

### U2 — Launch card

- [x] Tách `PowerLaunch`
- [x] Primary disabled + missing codes
- [x] Racer board read-only + link Settings

### U3 — Console 3 cột

**Progress (2026-09-02):** COMPLETE — snapshot-only racer strip, reviewed
activity vocabulary, header budgets, and existing Stop/Reveal contracts passed
focused, full-repository, Compose, and Docker browser gates.

**Decision (2026-09-02):** racer roles remain labelled as neutral parallel
lanes until M-PI-4 persists static/dynamic/exploit role metadata. The UI must
not infer an execution role that is absent from the durable snapshot.

- [x] Header metrics
- [x] 3 `RacerColumn` từ snapshot swarm
- [x] Rail vocabulary-only
- [x] Stop / Reveal đúng contract hiện có

### U4 — Polish

**Progress (2026-09-02):** COMPLETE — keyboard containment, one final
reduced-motion safety net, CSS consolidation, and final launch/reveal
regressions passed focused, full-repository, Compose, Docker, and real-browser
gates without changing the Power/Pi protocol.

**Decision (2026-09-02):** Settings owns one modal focus scope and restores the
invoking control on close. Reduced-motion is enforced by one final CSS safety
net so later theme layers cannot accidentally re-enable movement.

- [x] reduced-motion
- [x] focus trap settings
- [x] rút CSS trùng
- [x] Vitest: Start disabled khi capability thiếu; reveal không còn sau click 2

### U5 — History management

**Progress (2026-09-02):** COMPLETE — compact filtering, persistent display
aliases, explicit reversible hiding, and restore passed focused,
full-repository, Compose, Docker, and real-browser gates without mutating
append-only run or evidence records.

**Decision (2026-09-02, terminology superseded by U6):** this reversible
browser-only action is now named Hide. The immutable archive receipt, run
ledger, evidence, and custody records remain server-owned and restorable;
renaming changes only a local display alias.

- [x] Filter archive/run history
- [x] Rename display aliases
- [x] Hide with explicit confirmation
- [x] Restore hidden items
- [x] Vitest: preferences persist; evidence endpoints are never mutated

### U6 — History lifecycle terminology

**Progress (2026-09-02):** COMPLETE — History now uses Hide for reversible
browser state and Remove for confirmed server-side deletion of an unreferenced
archive. Focused, full-repository, Compose, Docker, and browser gates passed.

**Decision (2026-09-02):** Hide never mutates server data. Remove permanently
deletes only an unreferenced archive receipt and its extracted workspace. A
challenge/run reference fails closed; append-only run, event, evidence,
verification, and custody records have no History hard-delete operation.

- [x] Rename reversible local removal to Hide
- [x] Add permanent Remove for unreferenced archives
- [x] Deny Remove when a durable challenge/run references the archive
- [x] Keep run/event/evidence ledgers append-only
- [x] Focused, full-repository, Compose, Docker, and browser gates

**Prompt giao việc**

```text
Đọc docs/CTFMesh-ui-design-guide.md và apps/web/src/App.tsx.
Làm U1 rồi U2. Không thêm chat. Không tải font CDN.
Không hiện raw tool output hay API key.
Giữ endpoint Power hiện có. Chạy pnpm --filter @ctfmesh/web check.
```

---

## 16. Definition of done (UI)

Operator mới mở `http://127.0.0.1:5173` và trong một màn hình:

1. Hiểu phải thả archive.
2. Biết key để ở Settings, không ở form chính.
3. Thấy 3 racer trước khi bấm Start.
4. Sau Start thấy ai đang chạy, không thấy prompt.
5. Stop luôn với một click.
6. Flag chỉ sau verified + Reveal.

Đó là UI tối ưu cho dự án này: ít chữ, nhiều tín hiệu vận hành, không giả chatbot.
