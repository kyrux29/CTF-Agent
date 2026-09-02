# Hướng dẫn vận hành CTFMesh

CTFMesh là control plane local cho CTF được cấp quyền. Profile mặc định khởi
động ở trạng thái trống: không có challenge/target/operator flag được đóng gói
sẵn. Profile M5 opt-in có ba Web lab tổng hợp do dự án sở hữu để regression;
flag của chúng được tạo ngẫu nhiên theo reset và không nằm trong asset Pi nhìn
thấy. Bạn có thể đưa archive CTF của chính mình vào một receipt cục bộ có giới
hạn, rồi tùy chọn gọi một lượt AI triage chỉ với metadata an toàn.

Mục tiêu của luồng hiện tại là buộc scope rõ ràng trước khi ghi nhận evidence:

```text
Archive của bạn → intake an toàn → inventory local → metadata cấu trúc → AI triage tùy chọn
     │                                                                  │
     └→ M6.a exact instance → fixed source slot → Pi workers → independent replay → one-time flag reveal
     └→ Power solve → 3 workspace tách biệt → flag-router độc lập → one-time flag reveal
```

`solved` là trạng thái dành cho verifier độc lập. Không model, UI, hay worker
report nào tự chuyển run sang `solved`.

## Mục lục

- [Giới hạn và điều kiện an toàn](#giới-hạn-và-điều-kiện-an-toàn)
- [Khởi động bằng Docker Compose](#khởi-động-bằng-docker-compose)
- [M2 Pi Runner fixture không target](#m2-pi-runner-fixture-không-target)
- [M5 verifier và local labs](#m5-verifier-và-local-labs)
- [Chuẩn bị challenge của bạn](#chuẩn-bị-challenge-của-bạn)
- [Dùng giao diện archive receipt và Scope Ledger](#dùng-giao-diện-archive-receipt-và-scope-ledger)
- [Power solve: archive đến flag](#power-solve-archive-đến-flag)
- [Chạy challenge hoàn toàn trên giao diện (M6.a)](#chạy-challenge-hoàn-toàn-trên-giao-diện-m6a)
- [Dùng Control API](#dùng-control-api)
- [AI triage qua CLI](#ai-triage-qua-cli)
- [Skill catalog và MCP profiles](#skill-catalog-và-mcp-profiles)
- [MCP cục bộ chỉ đọc](#mcp-cục-bộ-chỉ-đọc)
- [Kiểm tra, dọn dẹp và xử lý lỗi](#kiểm-tra-dọn-dẹp-và-xử-lý-lỗi)

## Giới hạn và điều kiện an toàn

Chỉ đưa vào CTFMesh challenge, target, artifact và credential mà bạn có quyền
kiểm tra. Đây là local single-operator profile, không có authentication hoặc
tenant isolation. Vì vậy:

- Chỉ publish Web ở `127.0.0.1:5173`; không expose Compose ports ra Internet.
- Không cho API key vào manifest, file `.env`, URL, Git, DB hoặc artifact.
  Theo cấu hình local-only hiện tại, key được lưu rõ trong `localStorage` của
  browser để tự nạp lại. Không dùng profile browser này trên máy dùng chung và
  không expose Web ra ngoài loopback.
- Không thêm Docker socket, privileged mode, host network/namespace hoặc shell
  execution vào Compose.
- Chỉ khai báo endpoint chính xác trong manifest. Không dùng wildcard host,
  range không cần thiết hoặc public Internet trong contest mode.
- Treat output của model là dữ liệu chưa tin cậy. Chỉ verifier độc lập mới đủ
  thẩm quyền xác nhận flag/solve.

Khả năng có thật hiện nay:

| Khả năng | Trạng thái |
|---|---|
| Validate/import manifest | Có, qua UI/Control API/CLI |
| Ghi run record, event ledger, `PREPARING` và preflight job | Có |
| Triage OpenAI một lượt trên artifact khai báo | Có, CLI-only, read-only proposal |
| Browser upload archive offline | Có, ZIP/TAR chuẩn với quota và preflight chặt |
| Browser triage sau receipt | Có, chọn đúng một trong OpenAI/Gemini/DeepSeek; một request thành công/receipt, metadata-only proposal |
| Catalog skill + MCP theo category | Có, metadata local đã pin commit/license/digest; không tải hay chạy nội dung upstream |
| M2 Pi SDK control loop | Có qua profile `pi-smoke` fixture; không model key, source, target hay flag |
| M5 independent replay verifier | Có cho đúng ba Web lab local do dự án sở hữu; hai reset sạch, signed proof opaque, không raw flag |
| M6.a archive + public Web instance + model key từ UI | Có, profile `m6-ui`; source-available, assisted Web-only |
| Power archive race | Có, profile `power`; ba racer A/B/C và một TCP host:port tùy chọn |
| Model đọc source/gọi target và đề xuất plan | Có, chỉ qua typed source/HTTP gateway và 3 technique Web đã review |
| Raw flag sau hai remote replay khớp | Có, hiện trên UI qua one-time local reveal; không persist vào DB/event/artifact |
| Raw flag Power sau flag-router xác nhận | Có, hiện trên UI qua one-time local reveal; không persist vào DB/event/artifact |
| Generic solver, shell, Docker socket, public MCP | Không hỗ trợ |
| Xác nhận `solved` generic | Không hỗ trợ; M6.a chỉ nhận manifest do UI xây dựng với 3 Web technique đã review |

## Khởi động bằng Docker Compose

Điều kiện: Docker Engine có Compose plugin.

```bash
mkdir -p challenges
docker compose up -d --build --wait
```

Stack gồm PostgreSQL, local artifact volume, provider proxy, API và Web. Chỉ
Web reverse proxy publish trên loopback; API chỉ ở network nội bộ. Redis/MinIO
không được khởi động vì v0.1 dùng Postgres outbox và local content-addressed
artifact store:

| Thành phần | URL / địa chỉ |
|---|---|
| Scope Ledger | <http://127.0.0.1:5173> |
| API health (qua Web proxy) | <http://127.0.0.1:5173/v1/health> |
| API readiness (qua Web proxy) | <http://127.0.0.1:5173/v1/ready> |
| Web health | <http://127.0.0.1:5173/healthz> |

Kiểm tra sau khi khởi động:

```bash
curl --fail http://127.0.0.1:5173/v1/health
curl --fail http://127.0.0.1:5173/v1/ready
curl --fail http://127.0.0.1:5173/healthz
docker compose ps
```

Thư mục `challenges/` trên máy host bị `.gitignore` và `.dockerignore` loại trừ
để artifact/private challenge không vô tình đi vào Git hay Docker image. Base
API không mount thư mục này. Khi dùng M3, chỉ từng source slot cố định mới bind
đúng `challenges/<challenge-id>/` vào `/challenge` ở chế độ read-only.

Dừng stack nhưng giữ state local:

```bash
docker compose down
```

Không dùng `--remove-orphans` nếu máy đang chạy profile/Compose project CTFMesh
khác mà bạn chưa kiểm tra; Docker sẽ xem chúng là orphan và có thể dừng chúng.

Chỉ reset database/artifact state khi bạn đã export những gì cần giữ:

```bash
docker compose down -v
```

## M2 Pi Runner fixture không target

Default Compose chỉ tạo run/preflight job. Khi muốn kiểm tra riêng Pi SDK,
session lifecycle và steering an toàn, dùng profile M2 target-free. Nó cần một
token nội bộ tối thiểu 16 ký tự nhưng **không** cần hoặc nhận AI API key:

```bash
read -rs "CTFMESH_INTERNAL_RUNNER_TOKEN?M2 runner token (16+ ky tu): "
echo
export CTFMESH_INTERNAL_RUNNER_TOKEN
docker compose --profile pi-smoke up -d --build
```

Profile thêm `preflight-worker` và `pi-runner` ở mode `fixture`. Pi chỉ nhận
context niêm phong qua API nội bộ, không nhận source/challenge mount, URL target,
Docker socket, shell hoặc provider credential. Run fixture vẫn là `running` và
`inconclusive`; nó không thể tạo flag hay `solved`. Hướng dẫn smoke, lifecycle,
steering và kiểm tra isolation đầy đủ nằm tại
[docs/operations/pi-runner-m2-smoke.vi.md](operations/pi-runner-m2-smoke.vi.md).

Không bật `CTFMESH_PI_RUNNER_MODE=live` ở profile M2. M3 đã có provider proxy
và egress policy riêng, nhưng chỉ bật qua profile/tokens đã cấu hình; xem
[hướng dẫn tool gateway M3](operations/m3-tool-gateway.vi.md).

Trước khi cấp API key cho Pi live, dùng profile `m3-source` và operator probe
để kiểm tra challenge database ID, source mount, target alias, cache và deny
path. Probe tạo/cancel run chẩn đoán riêng; run chơi thật phải được tạo sau khi
probe pass. Lệnh đầy đủ và cách attach lab vào hai private slot network nằm ở
[hướng dẫn M3](operations/m3-tool-gateway.vi.md#probe-challenge-đầu-tiên-trước-khi-dùng-api-key).

## M5 verifier và local labs

M5 là profile Docker opt-in để chứng minh authority của verifier trên ba lab
Web tổng hợp: `web-path-traversal`, `web-authz-boundary` và `web-sqli-basic`.
Nó không mở lab port ra host và không phải flow để nhập một flag/URL/plan bất kỳ.
Pi chỉ có thể gửi candidate qua typed `candidate.submit` sau evidence/policy
gate; controller reset flag ngẫu nhiên, verifier replay hai lần bằng cookie jar
mới và chỉ proof Ed25519 opaque mới có thể đưa run tới `SOLVED`.

Chuẩn bị hai service token và cặp Ed25519 private/public key ngoài repository,
rồi làm theo [hướng dẫn M5 đầy đủ](operations/m5-verifier-labs.vi.md). Hướng
dẫn đó có lệnh Compose, health check, lifecycle endpoint, troubleshooting,
teardown và các boundary secret/network. M3 transport E2E và M5 verifier smoke
là hai gate độc lập; không gate nào tự chứng minh model đã solve challenge của
operator.

## Chuẩn bị challenge của bạn

Tạo một thư mục riêng dưới `challenges/`, ví dụ:

```text
challenges/
└── <case>/
    ├── challenge.yaml
    └── ... artifact được manifest khai báo ...
```

Không commit nội dung này mặc định. Nếu muốn version hóa một challenge riêng,
dùng repo private khác hoặc thay đổi `.gitignore` một cách chủ động sau khi đã
review dữ liệu/flag/credential.

### Trường bắt buộc của manifest

Manifest dùng `apiVersion: ctfmesh.io/v1alpha1` và `kind: Challenge`. Các vùng
quan trọng:

| Vùng | Mục đích |
|---|---|
| `metadata.name`, `metadata.category`, `tags` | Nhận diện case và category CTF |
| `spec.mode` | `assisted` hoặc `contest` |
| `spec.target` | `artifact_bundle`, `docker_compose` hoặc `remote` với scope chính xác |
| `spec.artifacts` | Path tương đối và vai trò của mỗi artifact |
| `spec.flag` | Pattern, source policy, replay count |
| `spec.limits` | Time, tool, HTTP, parallelism, cost và artifact byte caps |
| `spec.providers` | Preferred/fallback provider ID đã được bạn phê duyệt |
| `spec.memory` | Namespace, cutoff và public-search policy |
| `tool_profile`, `skill_profile` | Capability được khai báo, không phải quyền ngầm |

Các path artifact phải là POSIX relative path nằm trong case directory; `..`,
absolute path, backslash và symlink không hợp lệ. Với `artifact_bundle`, không
được khai báo endpoint/network fields. Với `contest`, public Internet search và
public target bị từ chối.

### Validate YAML tại máy local

Điều kiện: Python 3.12+, `uv`.

```bash
uv sync --frozen --all-packages --all-groups
uv run --frozen ctfmesh challenge validate challenges/<case>/challenge.yaml
```

Lệnh in JSON có category, target type, allowed endpoints, tool profile và skill
profile. Sửa manifest cho đến khi `valid` là `true`; không bỏ qua lỗi scope.

## Dùng giao diện archive receipt và Scope Ledger

Mở <http://127.0.0.1:5173>. Màn hình đầu tiên phải báo **No saved case yet.**;
đó là trạng thái đúng của repo sạch, không phải lỗi. Khu vực phía
trên là archive receipt; Scope Ledger phía dưới vẫn dành cho manifest có target
scope rõ ràng.

### History và không gian làm tối đa ba challenge

Activity bar sát mé trái tách bốn view giống VS Code: **History** cho session,
**Progress** cho run đang hoạt động, **Statistics** cho số liệu đã suy ra từ
ledger và **? Help** cho hướng dẫn ngắn. Mỗi lần chỉ có một side panel mở; bấm
lại icon đang active để thu panel và trả toàn bộ chiều ngang cho challenge.
Giao diện chính không hiện hướng dẫn dài mặc định. Trên màn hình nhỏ, Help và
Settings vẫn được ghim ở đáy viewport.

Biểu tượng History mở/ẩn thanh **Sessions**. Nhóm **Archive** chứa các
file đã inspect; nhóm **Runs** chứa các tracked run đã tạo từ Scope Ledger.
History lấy từ backend nên vẫn còn sau khi refresh trình duyệt hoặc khởi động
lại container với volume cũ. Mỗi archive hiện thời gian và sáu ký tự cuối của
intake ID để phân biệt các lần upload trùng tên.

- Bấm một session để mở ngay vào pane đang active. Receipt đã mở trong tab hiện
  tại được cache tạm để lần chuyển lại nhanh hơn.
- Bấm **+ New** để làm sạch pane đang active và bắt đầu challenge mới.
- Chọn 1, 2 hoặc 3 pane trong **Settings**. Chọn **Open in A/B/C** ở đầu history,
  rồi chọn hoặc kéo session vào pane đích. Nhãn A/B/C cạnh session cho biết nó
  đang xuất hiện ở đâu.
- Kéo grip ở header để đổi thứ tự pane; kéo divider để đổi chiều rộng. Có thể
  dùng `Alt+←/→` trên grip và phím mũi tên trên divider khi dùng bàn phím. Trên
  màn hình hẹp, các pane tự xếp dọc nhưng vẫn giữ trạng thái riêng.
- Run console nay mở thành evidence panel ngay trên challenge workspace. Bấm
  **Close** để thu panel; URL `?run=<run-id>` được bỏ mà không reload trang.

Mỗi API key nhập trong **Settings** nằm ở một ô provider riêng và được lưu rõ
trong `localStorage` của browser ngay khi bấm **Save**; không có bước unlock hay
passphrase. Bấm **Remove saved keys** để xóa chúng. Mỗi pane giữ provider/model
riêng; tạo session mới lấy default từ Settings. Không secret nào được đưa vào history, DB, event,
artifact hay sessionStorage. API
history chỉ trả summary đã lọc, không trả inventory đầy đủ, possible flag, raw
provider output hoặc secret. Số pane và preference không-secret được lưu local;
thứ tự/kích thước pane chỉ tồn tại trong tab và không phải dữ liệu challenge.

### Luồng archive receipt

1. Chọn hoặc kéo-thả đúng một archive `ZIP`, `TAR`, `TAR.GZ`/`TGZ`,
   `TAR.BZ2`, hoặc `TAR.XZ`/`TXZ` tối đa 128 MiB. Không nén lại archive lồng
   nhau để mong hệ thống tự giải nén nhiều tầng: archive lồng nhau được giữ là
   artifact thường.
2. Bấm **Inspect file**. Server stream body, không tin `Content-Length`, và
   chỉ publish receipt sau khi toàn bộ preflight qua.
3. Receipt hiển thị format, SHA-256, số file, kích thước sau giải nén,
   **Target network: 0 requests** và zero execution. Nếu sau đó dùng AI, nó
   hiển thị riêng **Provider egress: 1 metadata-only request**; provider egress
   không phải target interaction. Các hint category chỉ là heuristic tĩnh,
   không phải quyết định solve.
4. Mục *possible flags* là kết quả dò pattern giới hạn trên input. Nó không
   được coi là flag xác minh. Bấm **Show possible flags**
   mới trả giá trị thô cho tab hiện tại; giá trị này không được ghi vào report,
   event, database hay provider prompt.
5. Mở bánh răng **Settings**, nhập key vào đúng ô OpenAI/Gemini/DeepSeek và bật
   **Allow metadata-only AI requests from this tab** một lần cho tab. Ở mỗi pane,
   chọn provider rồi model preset hoặc exact model ID và bấm **Run AI**.
   Provider đổi trong một pane chỉ reset model của pane đó; key
   provider khác không bị mang theo hoặc xóa. Key được tự nạp từ
   `localStorage` của đúng browser profile; request chỉ gửi key của provider
   đã chọn.
6. Trong lúc provider xử lý, panel **Thinking** hiển thị thời gian đã chờ và 7
   checkpoint: nhận request, nạp receipt, chuẩn bị evidence, gửi provider, nhận
   response, validate output và lưu receipt. Đây là tóm tắt trạng thái thực do
   runtime phát ra, **không phải chain-of-thought**; stream không chứa prompt,
   response thô, API key, archive excerpt hay flag. Có thể bấm **Cancel** bất
   kỳ lúc nào. Khi hoàn tất panel chuyển thành **Done** và hiển thị `7/7`; nếu dừng sớm, checkpoint cuối
   giữ trạng thái dừng cùng mã lỗi an toàn để có thể retry có chủ đích.
7. Không có fallback tự động: một receipt chỉ nhận **một request thành công**
   đến provider đã chọn; nếu provider lỗi trước khi tạo proposal, bạn có thể
   thử lại có chủ đích với key đang kết nối hoặc cập nhật key trong Settings. Egress không chứa path archive, source
   excerpt, printable string hay giá trị candidate; chỉ gồm ID file do service
   tạo, size, SHA-256, media type và structural marker có vocabulary cố định.
   OpenAI dùng strict structured output và `store: false`;
   Gemini/DeepSeek dùng JSON mode rồi validate schema/citation cục bộ. Mọi
   provider đều tắt tools, dùng host HTTPS cố định, không follow redirect và
   không tin proxy từ environment. Không có network đến target, shell, code
   execution, recursive extraction hay tự xác nhận flag. Output là
   category/fact/hypothesis/next action **proposal only**.

Các archive bị từ chối gồm: không phải format hỗ trợ, ZIP encrypted, path
absolute/`..`/backslash/NUL, path duplicate hoặc file-vs-directory prefix
collision, symlink/hardlink/device/FIFO/sparse member, hơn 512 entry, ratio nén
quá cao, file >64 MiB hoặc tổng dữ liệu sau giải nén >512 MiB. Đây là boundary
an toàn, không phải bảo đảm parser không có bug; production-grade extraction
nên chuyển sang sandbox rootless có CPU/RAM/time quota khi runner đã sẵn sàng.

## Power solve: archive đến flag

Power là luồng chính cho archive CTF thuộc mọi category. Nó dùng đúng ba racer
A/B/C với model/provider được chọn trước trong **Settings**. Các racer có
workspace riêng, chỉ dùng typed shell/file/PTY/tube actions, và chỉ flag-router
độc lập được chuyển run sang `solved` sau khi tự đọc lại artifact quan sát.

### Chuẩn bị Power profile

Tạo một lần các capability service trong `.env` private bằng helper sau.
Helper thêm cờ Power, capability sandboxd/flag-router/Pi runner và Docker
socket group; nếu M6 đã có runner token thì giữ nguyên. Nó từ chối ghi đè token
Power đã tồn tại và không đặt API key AI vào file này:

```bash
just power-bootstrap
```

Sau đó chỉ cần một lệnh để build và chờ toàn bộ service Power sẵn sàng:

```bash
docker compose --profile power up -d --build --wait
```

Kiểm tra `GET /v1/runtime/capabilities` qua Web proxy: `power.status` phải là
`ready`. `sandboxd` là service duy nhất được mount Docker socket; API, Web,
flag-router và workspace racer không có socket đó.

### Happy path trên giao diện

1. Mở `http://127.0.0.1:5173`, bấm **Settings**, nhập key OpenAI/Gemini/DeepSeek
   ở đúng provider rồi bấm **Save**. Key được tự nạp lại từ browser local storage
   trong các lần mở sau.
2. Trong Settings, cấu hình map **Racer A/B/C**: provider, model và temperature.
   Đặt Minutes, Race cap và Reserve/call tại đây một lần.
3. Trở lại trang chính, kéo ZIP/TAR vào vùng **Drop ZIP or TAR**. Intake local
   chạy ngay khi file được chọn; không cần chạy triage trước để Power tạo
   workspace.
4. Mở **Target (optional)** rồi để trống host/port cho challenge offline.
   Với pwn/misc service, nhập đúng một host public và port, rồi tick
   **Authorized CTF target**. Power không có open egress: network chỉ là tube
   đến host:port đã khai báo trong manifest.
5. Nếu đề cho prefix riêng, điền **Flag format** trước khi chạy, ví dụ
   `DH{*}`, `picoCTF{*}`, `DUCTF{*}` hoặc `PREFIX_*`. Dấu `*` (và cú pháp cũ
   `...`) là wildcard cho phần thân flag, không phải regex và không phải raw
   flag. Template chấp nhận ký tự Base64 như `+`, `/`, `=` trong thân. Khi đã
   nhập template cho Power, candidate tự động chỉ khớp đúng prefix/template
   (kể cả chữ hoa/thường)
   đó để không dừng race vì một decoy `CTF{...}`; để trống nếu chưa biết
   prefix và muốn dùng fallback `HTB{...}`, `CTF{...}`, `FLAG{...}`.
6. Bấm **Start Power**. Browser mở console ở ngay trang chính. Mỗi racer có
   mục **Terminal**: lệnh argv/operation vừa hoàn tất, stdout/stderr rút gọn,
   exit code và timeout xuất hiện theo event ledger để có thể theo dõi và steer
   đúng hướng. Nội dung được redaction hai lần; API key, cookie/token/bearer và
   raw flag không hiển thị trong log/live output. Output lớn chỉ hiện head/tail
   đã cap, còn artifact quan sát đầy đủ vẫn là bản immutable dùng cho verifier.
7. Khi `stdout` hoặc `stderr` của racer có chuỗi khớp **Flag format** của run,
   run chuyển sang **Paused** và Candidates hiện **Review needed**. Pi kết thúc
   batch hiện tại ở tool boundary; các racer không chạy thêm batch mới trong
   lúc bạn review. Không có scanner background hoặc model prose nào tự chuyển
   trạng thái run sang `solved`.
8. Khi run chuyển sang **Solved**, banner **Verified** hiện ngay dưới header.
   Bấm **Reveal flag** để lấy raw flag trong ô **Raw flag** và copy. Đây là
   luồng UI local one-time; refresh/API restart hoặc reveal lại sẽ không bảo
   toàn giá trị raw.
9. **Candidates** tự hiện các chuỗi khớp từ immutable `stdout`/`stderr` của
   action đã làm pause run, gồm nhãn racer nguồn và cả decoy. Chọn **Confirm**
   để gửi đúng candidate bạn chọn cùng artifact đã quan sát sang flag-router
   độc lập. Nếu router bác candidate, run tự về `running` và các racer tiếp tục
   hướng evidence mới. Chọn **Continue search** để bỏ toàn bộ queue hiện tại và
   resume các racer; chọn **Stop all** để hủy run. Nếu artifact của queue không
   thể đọc, run vẫn giữ `Paused` và giao diện báo lỗi thay vì bỏ qua im lặng.
10. Bấm **Stop all** bất kỳ lúc nào. API hủy controller; coordinator hủy các racer
   và dọn workspace. Khi một flag hợp lệ thắng, các
   racer còn lại cũng bị dừng.

`contest_offline` trong Power tắt hoàn toàn corpus `knowledge/writeups/`; không
file nào được đọc hay gửi model. Khi không bật, corpus cục bộ read-only đó chỉ
được tóm gọn cho racer A sau AutoPrompter, không phải evidence và không có
quyền thay thế quan sát thực.

## Chạy challenge hoàn toàn trên giao diện (M6.a)

M6.a là lane dùng cho **Web CTF có source archive và đúng một instance HTTP(S)
public** mà bạn được phép kiểm tra. Đây là luồng để test challenge đầu tiên; bạn
không cần tự tạo manifest hay gọi API sau khi stack đã được cấu hình. Nó không
hỗ trợ archive-only, IP private/VPN/loopback, Dockerfile trong archive, pwn,
reverse, crypto, browser automation hay arbitrary shell.

### 1. Cấu hình Docker một lần, không đặt AI key vào `.env`

Tạo đúng một lần file `.env` private chứa các **service token local** ngẫu
nhiên. Helper chỉ sinh token giữa các container, các URL nội bộ đã review và
two dynamic slot flags; nó không có trường nhập hay lưu OpenAI/Gemini/DeepSeek
key.

```bash
python3 support/scripts/dev/bootstrap_m6_runtime.py
```

Nếu máy chỉ có Docker, dùng image Python tạm thời thay cho Python host:

```bash
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD:/workspace" -w /workspace python:3.12-alpine \
  python support/scripts/dev/bootstrap_m6_runtime.py
```

Helper từ chối ghi đè `.env` đã tồn tại. File này nằm trong `.gitignore` và
phải có mode `0600`. Nếu muốn tự quản lý bằng secret store thay vì helper, xem
đúng các key M6 trong `.env.example`; để trống cả two challenge-ID fields.

Để trống cả `CTFMESH_SOURCE_SLOT_1_CHALLENGE_ID` và
`CTFMESH_SOURCE_SLOT_2_CHALLENGE_ID`: M6.a gán archive đã được validate vào slot
tự động. Tuyệt đối không thêm `OPENAI_API_KEY`, `GEMINI_API_KEY` hoặc
`DEEPSEEK_API_KEY` vào file này. UI gửi key cho đúng một run qua kênh nội bộ
memory-only, sau đó xóa khỏi form.

Khởi động đầy đủ profile:

```bash
docker compose --profile m6-ui up -d --build --wait
docker compose --profile m6-ui ps
```

Mở `http://127.0.0.1:5173`. Nếu port này đang được một stack local tin cậy dùng,
đổi duy nhất `WEB_PORT` và đồng bộ hai `CTFMESH_CORS_ORIGINS`, sau đó mở port mới.
API, source slot, target connector và verifier không publish port host.

### 2. Settings bánh răng

Bấm biểu tượng **⚙** cuối activity bar bên trái trước khi mở case mới. Drawer này là nơi duy
nhất chứa preference vận hành của giao diện:

- **AI providers:** default provider/model cho pane mới; ba ô key độc lập cho
  OpenAI, Gemini và DeepSeek; một checkbox bật metadata-only request cho tab.
  **Save** lưu key rõ trong browser local storage và tự nạp khi mở lại;
  ledger/DB/artifact/sandbox không nhận key.
- **Run limits:** có preset triage `Quick` (1.536), `Balanced` (2.048) hoặc
  `Deep` (3.072) output token; thời gian chờ AI `Fast` (30 giây), `Patient`
  (2 phút) hoặc **Unlimited** (không có deadline UI, có watchdog khẩn cấp 24 giờ);
  preset instance `Economy` (5 phút,
  40 tool, 24 HTTP, $1), `Balanced` (10 phút, 80 tool, 50 HTTP, $2) hoặc
  `Extended` (15 phút, 120 tool, 80 HTTP, $3). Chọn **Custom** để nhập output
  `512–3.072`, chờ AI `10–86.400` giây, thời gian run `60–900` giây, `1–120`
  tool call, `1–80` HTTP request và `$0,1–3`.
- **Workspace:** comfortable/compact density, 1–3 pane và lựa chọn mở side
  panel mặc định.

Preference chỉ được lưu trong `localStorage` của browser hiện tại; không đi vào
receipt, manifest, event, database hay container. Đổi default sẽ không âm thầm
đổi provider/model của case đang mở. Bấm **New** để tạo pane theo default mới.
Web chỉ là giao diện local: khi bấm **Start run**, Control API mới cấp scope và
giao job cho Pi harness local; Pi gọi typed tools qua gateway/sandbox, còn
verifier độc lập mới có quyền kết luận `SOLVED`.

Mục **Safety locks** chỉ để quan sát: archive tối đa 128 MiB, hai source slot,
origin HTTP(S) public chính xác và hai replay verifier luôn do backend áp đặt.
Không thể vượt hard ceiling, sửa endpoint provider, lưu API key hoặc giảm replay
bằng DevTools/UI. API kiểm tra lại mọi custom value trước materialize slot và
credential lease; HTML input không phải policy authority.

Mỗi pane có dòng **EST**: `input estimate + output max`, và sau khi gửi sẽ cộng
`session estimate`. Đây là heuristic cục bộ dựa trên model family và evidence
đã bound (tối đa 48 file/112 KiB), không phải tokenizer, usage hay hóa đơn do
provider xác nhận.

### 3. Thao tác trong browser

1. Ở **Sessions**, bấm **New**; kéo archive source vào và bấm **Inspect file**.
   Chờ receipt xanh. Bước này vẫn offline và không thực thi file trong archive.
2. Mở **Settings**, paste một hoặc nhiều key vào đúng provider và bật quyền
   metadata cho tab. Bấm Save để giữ key trong browser local storage; quay lại
   từng pane để chọn provider/model riêng. Không cần bấm *Get AI suggestions* trước
   khi solve — đó chỉ là triage metadata tùy chọn.
3. Trong **Run against an instance**, nhập origin gốc như
   `https://challenge.example.org` (không path, query, fragment, username hay
   password). Tick hai xác nhận về target được cấp quyền và cho model làm việc
   trong scope đó; provider egress đã được bật ở Settings.
4. Bấm **Start solve**. Browser nhận run ID và mở evidence panel trong workspace. Key vẫn
   ở vault đã mở để dùng cho pane/run kế tiếp, còn API chỉ cấp lease runtime
   hữu hạn và không ghi key vào DB/event/artifact.
5. Theo dõi rail **Activity**. Nó chỉ cho thấy checkpoint an toàn như worker đã
   nhận việc, typed tool bắt đầu/kết thúc và verification; không hiển thị prompt,
   chain-of-thought, source thô, API key, response thô hoặc flag.
6. Pi master có thể tạo tối đa hai worker đa dạng. `exploit_builder` tự đọc
   source hoặc gửi HTTP quan sát qua capability gateway rồi chỉ được nộp một
   replay plan GET dạng khai báo cho `web.path_traversal`,
   `web.authz_boundary` hoặc `web.sqli_basic`. Không có worker nào tự gọi URL
   tuyệt đối, shell hay endpoint ngoài origin đã khai báo.
7. Nếu plan qua cả hai remote replay độc lập với cookie jar mới và thu được cùng
   flag-shaped value, trạng thái run thành **solved**. Khi đó UI hiện **Reveal
   flag**. Giá trị chỉ đọc được một lần trong API process hiện tại; refresh/restart
   trước khi reveal hoặc bấm lần hai phải chạy lại một verified solve.

Nếu status là `running`/`verifying` lâu, mở **Progress** để xem run active hoặc
**History** để vào lại run, xem rail Activity và dùng **Cancel** nếu muốn giải phóng source slot. Không nhập flag vào
UI để ép kết quả: hệ thống không có API như vậy.

### Điều kiện target và lỗi thường gặp

- Origin phải resolve thành địa chỉ Internet global ở lúc gateway/verifier chạy;
  `localhost`, RFC1918, link-local, multicast, `.local`, `.internal` và redirect
  đều bị từ chối. Đây là lý do instance Docker/VPN không phù hợp với M6.a.
- Target cần ổn định giữa hai replay. Nếu flag đổi theo request/session hoặc
  challenge chỉ cho một lần thử, verifier cố ý để run không solved.
- Hai source slot là giới hạn thực tế. Khi cả hai đang bận, UI trả
  `source_slot_unavailable`; cancel/hoàn tất một run trước.
- API/runner restart làm mất credential lease; API restart cũng làm mất reveal
  lease. Đây là chủ đích để raw secret không bền vững. Launch lại từ archive
  receipt với key mới.

### Luồng manifest và run record

Luồng thao tác:

1. Chuẩn bị bản JSON của manifest. UI chỉ nhận JSON để browser không cần parser
   YAML bên thứ ba; YAML vẫn được CLI validate.
2. Dán JSON vào editor hoặc chọn file `.json` nhỏ hơn 2 MiB.
3. Bấm **Validate manifest**. UI gửi đúng envelope
   `{ "manifest": { ... } }` đến `/v1/challenges/validate`.
4. Nếu scope được chấp nhận, bấm **Import to local ledger**. Server lưu manifest
   idempotent theo digest; import lại nội dung giống hệt sẽ trả record cũ.
5. Bấm **Create tracked run** trên manifest đã import để tạo run `PREPARING`
   với limits đúng theo manifest và một preflight job durable.
6. Run console mở qua `?run=<run-id>`. Bạn có thể bookmark URL này hoặc dùng
   `GET /v1/runs/{id}/console`.

`Create tracked run` ghi `run.created`, `run.state.changed` và
`agent.job.queued` trong cùng transaction/outbox. Nó không gọi model, không đọc
host path tùy ý, không upload artifact, không tương tác target và không thực thi
action. Compose hiện chưa đăng ký worker production để tiêu thụ job; vì vậy
console hiển thị `queued` là đúng ở default profile. `pi-smoke` của M2 thêm
preflight worker và Pi fixture target-free; nó chỉ chứng minh control loop chứ
không gọi model, tool hoặc target. Fake harness vẫn chỉ phục vụ test/dev, không
có endpoint công khai.

Vault API key trên UI chỉ cấp credential cho archive triage hoặc M6.a
exact-instance run do operator bấm chạy với provider/model tương ứng. Nó không
cấp quyền cho manifest run generic, MCP hay target HTTP ngoài capability scope.

## Dùng Control API

### Health và danh sách challenge

```bash
curl --fail http://127.0.0.1:5173/v1/health
curl --fail http://127.0.0.1:5173/v1/ready
curl --fail http://127.0.0.1:5173/v1/challenges
```

### Upload archive và đọc receipt

UI gọi body thô thay vì multipart để server kiểm soát quota ngay lúc stream.
Từ terminal local, thay `<archive>` bằng file bạn được quyền phân tích:

```bash
curl --fail-with-body \
  -H 'content-type: application/octet-stream' \
  -H 'x-archive-name: <archive>.tar.gz' \
  --data-binary @<archive>.tar.gz \
  http://127.0.0.1:5173/v1/archive-intakes
```

Lưu `intake_id` từ response. Receipt chỉ chứa metadata/evidence đã redaction:

```bash
curl --fail http://127.0.0.1:5173/v1/archive-intakes/<intake-id>
```

Chỉ khi bạn chủ động cần xem direct candidate từ input, gọi:

```bash
curl --fail-with-body \
  -H 'content-type: application/json' \
  -X POST \
  --data '{"confirm":true}' \
  http://127.0.0.1:5173/v1/archive-intakes/<intake-id>/candidate-flags/reveal
```

Response này là `unverified_input_candidate`; không bao giờ đổi run thành
`solved`.

Với Power run đang hoặc đã chạy, API sau vẫn có thể quét lại toàn bộ evidence
runtime khi cần chẩn đoán local:

```bash
curl --fail-with-body \
  -H 'content-type: application/json' \
  -X POST \
  --data '{"confirm":true}' \
  http://127.0.0.1:5173/v1/runs/<run-id>/candidate-flags/reveal
```

Response gắn nhãn `unverified_runtime_candidate`, gồm racer nguồn và
`scan_complete`. Trong flow bình thường không cần bấm quét: khi `stdout` hoặc
`stderr` khớp **flag format đã khai báo lúc launch**, run tự vào trạng thái
`paused`, các racer dừng ở tool-boundary an toàn, và bảng **Candidates** tự nạp
toàn bộ giá trị khớp từ output vừa tạo. Candidate chỉ sống trong phản hồi local
`no-store`, không vào event, database hay prompt tiếp theo của model.

Khi hàng chờ đang mở:

- **Confirm** gửi đúng candidate bạn chọn, cùng artifact đã quan sát, sang
  flag-router độc lập. Chỉ router chấp nhận mới chuyển run sang `solved`; nếu
  router bác, các racer tự resume với một steer không chứa candidate.
- **Continue search** không gửi candidate; nó đưa run về `running` và queue
  các racer còn sẵn sàng tìm một hướng evidence khác.
- **Stop all** hủy toàn bộ racer qua control plane. Nếu **Confirm** được
  flag-router chấp nhận, control plane cũng fence/hủy toàn bộ racer còn lại và
  chỉ giữ kết quả verifier đã xác minh.

Candidate không khớp format không làm pause run; nó chỉ có thể xuất hiện trong
lần quét chẩn đoán thủ công nêu trên.

Để gọi triage qua API, chỉ dùng loopback và không lưu command/history có key.
UI là hướng ưu tiên vì key chỉ nằm trong vault RAM của tab và không cần xuất
hiện trong shell history. Xem allowlist
không chứa secret trước:

```bash
curl --fail http://127.0.0.1:5173/v1/archive-triage/providers
```

Endpoint chỉ nhận một trong ba provider ID `openai-responses`,
`gemini-openai-compat`, hoặc `deepseek-chat`; browser không được gửi `base_url`,
header tùy ý hay provider ID khác. Giao diện dùng endpoint NDJSON
`/v1/archive-intakes/<intake-id>/triage/stream`; payload vẫn là:

```json
{
  "provider": "gemini-openai-compat",
  "model": "<exact-approved-model-id>",
  "api_key": "<provider-key>",
  "provider_egress_acknowledged": true,
  "max_output_tokens": 2048,
  "timeout_seconds": 86400
}
```

`provider`, acknowledgement và key đều bắt buộc; key tối đa 8 KiB và request
triage tối đa 16 KiB. `timeout_seconds` là integer `10–86400`, mặc định API cũ là
30 nếu bỏ qua; lựa chọn UI **Unlimited** gửi `86400` như watchdog khẩn cấp 24 giờ,
không dùng `Infinity`/`null`. API chỉ dùng key trong call đó; UI có thể gửi lại cùng key
từ vault RAM cho hành động operator tiếp theo. Response có content type
`application/x-ndjson`, gồm các progress frame tuần tự và đúng một terminal
`result` hoặc `error`; schema hiện tại là `ctfmesh.archive-triage-stream/v1`.
Terminal receipt trả proposal, provider/model và `output_contract`; nó vẫn báo
`execution: none` và `verification: not_attempted`. Endpoint JSON `/triage`
được giữ để tương thích client cũ nhưng không có tiến trình trực tiếp. Không
copy key vào shell history, script, manifest hay file request đã commit.

Nếu UI báo `provider: output budget reached; retry`, provider đã trả response
không hoàn chỉnh và kết quả đó đã bị loại bỏ. Không có action CTF nào được chạy
và intake vẫn dùng lại được: kiểm tra provider/model rồi retry bằng key trong
vault; chỉ cập nhật Settings khi key thực sự sai/hết hạn. Archive triage dùng preset hoặc custom hữu hạn `512–3.072` token cho cả
reasoning lẫn JSON; chọn ở **⚙ Settings** trước khi gửi request. Backend từ chối
cap ngoài khoảng này và không tự lặp request để tránh chi phí bất ngờ.

Khi chạy bằng Docker, API không có Internet egress trực tiếp. Request triage
đi qua `provider-proxy`; proxy này chỉ cho phép CONNECT HTTPS đến ba hostname
provider đã review. Nếu proxy không healthy, API trả lỗi 502/503 thay vì
fallback sang direct connection hay provider khác.

### Validate, import và tạo run

Tạo file request JSON từ manifest mà bạn đã tự review:

```json
{
  "manifest": {
    "apiVersion": "ctfmesh.io/v1alpha1",
    "kind": "Challenge"
  }
}
```

Ví dụ trên chỉ là envelope, chưa phải manifest hợp lệ hoàn chỉnh. Không thay
placeholder bằng target ngoài scope của bạn.

```bash
curl --fail-with-body \
  -H 'content-type: application/json' \
  -X POST http://127.0.0.1:5173/v1/challenges/validate \
  --data @manifest-request.json

curl --fail-with-body \
  -H 'content-type: application/json' \
  -X POST http://127.0.0.1:5173/v1/challenges \
  --data @manifest-request.json
```

Lấy `id` từ response import, rồi tạo run với mode và budget không vượt manifest:

```bash
curl --fail-with-body \
  -H 'content-type: application/json' \
  -H 'Idempotency-Key: <random-safe-retry-key>' \
  -X POST http://127.0.0.1:5173/v1/runs \
  --data '{
    "challenge_id": "<challenge-id>",
    "mode": "assisted",
    "provider": "operator-pending",
    "budget": {
      "wall_time_seconds": 300,
      "max_tool_calls": 30,
      "max_http_requests": 20,
      "max_cost_usd": 1
    }
  }'
```

`Idempotency-Key` là identifier 1–200 ký tự an toàn. Giữ nguyên key này nếu
client timeout và cần retry cùng request; dùng key khác khi bạn chủ động tạo run
mới. API tạo `PREPARING` cùng preflight job, không gọi model/tool/target trong
request.

Đọc state:

```bash
curl --fail http://127.0.0.1:5173/v1/runs/<run-id>
curl --fail http://127.0.0.1:5173/v1/runs/<run-id>/events
curl --fail http://127.0.0.1:5173/v1/runs/<run-id>/blackboard
curl --fail http://127.0.0.1:5173/v1/runs/<run-id>/console
curl --fail http://127.0.0.1:5173/v1/runs/<run-id>/agent-sessions
curl --fail http://127.0.0.1:5173/v1/runs/<run-id>/candidates
curl --fail http://127.0.0.1:5173/v1/runs/<run-id>/verifications
```

Human controls `pause`, `resume`, `cancel`, và `steer` chỉ thay đổi/ghi event
theo contract. Không endpoint nào cho phép set `solved` trực tiếp.

## AI triage qua CLI

Triage hiện có chỉ dùng OpenAI Responses adapter và chỉ tạo **read-only
proposal**. Khi đã chuẩn bị manifest/artifacts của mình:

```bash
export CTFMESH_LIVE_PROVIDERS_ENABLED=true
read -rs OPENAI_API_KEY
export OPENAI_API_KEY

uv run --frozen ctfmesh triage run \
  challenges/<case>/challenge.yaml \
  --challenge-root challenges/<case> \
  --model <operator-approved-model-id> \
  --timeout-seconds 30 \
  --output .artifacts/triage/<case>
```

Quy tắc credential:

- `OPENAI_API_KEY` chỉ tồn tại trong current shell/call stack.
- Không truyền key qua CLI argument, manifest, database, event, artifact, URL
  hay Docker Compose environment file. Archive UI là ngoại lệ có chủ đích: key
  chỉ ở memory của tab/request loopback và bị xóa khỏi form khi call bắt đầu.
- Chỉ bật `CTFMESH_LIVE_PROVIDERS_ENABLED=true` sau khi review manifest scope.
- Model request dùng structured output, `store: false` và `tools: []`.

Pipeline materialize đúng artifact khai báo vào disposable workspace, tạo
fingerprint/redacted evidence, gọi model một lần với timeout, validate result,
và export report an toàn. Nếu result lỗi/malformed, run dừng an toàn. Nó không
thực thi `next_actions`, không contact target, không tạo exploit và không verify
flag.

## Skill catalog và MCP profiles

CTFMesh không chạy `install` script hoặc `SKILL.md` từ GitHub trong runtime.
Thay vào đó, local catalog chứa guidance đã review riêng, còn provenance
upstream được pin theo URL HTTPS, commit SHA 40 ký tự, path, SHA-256 nội dung,
SPDX license và SHA-256 license. Nguồn hiện có:

- `ljagiello/ctf-skills` (MIT): catalog/skill reference cho AI/ML, crypto,
  forensics, misc, OSINT, pwn, reverse và web;
- OWASP WSTG (CC-BY-SA-4.0): reference-only cho web;
- pwn.college Dojo (BSD-2-Clause): reference-only cho pwn/reverse;
- Google CTF (Apache-2.0): reference-only chung.

`reviewed_catalog` nghĩa là metadata nguồn đã được review để định hướng catalog;
`reference_only` nghĩa là chỉ provenance/đọc tham khảo. Cả hai **không** được
fetch, vendored vào prompt, chạy script, hoặc tự thêm tool/network permission.
Xem metadata local bằng API (không có request ra Internet):

```bash
curl --fail http://127.0.0.1:5173/v1/skill-catalog
curl --fail 'http://127.0.0.1:5173/v1/skill-catalog?category=web'
```

Mỗi MCP profile hiện chỉ mô tả facade `ctfmesh.local.readonly` với transport
`local_stdio`, `files_list` và `artifacts_inspect`. Profile không phải cấu hình
MCP remote: `allows_external_connection`, `allows_network` và
`allows_code_execution` đều `false`. Tool vẫn phải qua `ToolRuntime`,
`tool_profile`, capability và policy của manifest; source metadata không cấp
quyền ngầm.

## MCP cục bộ chỉ đọc

MCP dùng cho `artifact_bundle` offline, không dùng cho remote target. Manifest
phải khai báo cả `artifacts.inspect` và `files.list` trong `tool_profile`:

```bash
uv run --frozen ctfmesh mcp serve challenges/<case>/challenge.yaml \
  --challenge-root challenges/<case>
```

MCP transport là stdio. Đừng in banner vào cùng stdout. Không có HTTP server,
network browsing, host shell, code execution hoặc API key trong MCP gateway.

## Kiểm tra, dọn dẹp và xử lý lỗi

### Quality gates

```bash
uv run --frozen ruff format --check .
uv run --frozen ruff check .
uv run --frozen pyright
uv run --frozen pytest -q
pnpm --filter @ctfmesh/web check
pnpm --filter @ctfmesh/pi-runner check
docker compose config --quiet
```

### Dọn output local

```bash
uv run --frozen python support/scripts/dev/clean.py
```

Lệnh này chỉ xóa cache/build output đã định nghĩa. Thêm `--dependencies` khi
muốn xóa `node_modules`; `.venv` và file challenge dưới `challenges/` không bị
script này chạm vào.

### Bảng lỗi nhanh

| Hiện tượng | Nguyên nhân thường gặp | Cách xử lý |
|---|---|---|
| UI báo `Request failed with status 502/503` | API chưa ready hoặc provider proxy chưa healthy | `docker compose ps`, kiểm tra `http://127.0.0.1:5173/v1/ready`, rồi xem `docker compose logs api provider-proxy` |
| Archive bị `422` | format/member/path/size không qua preflight | Xem `detail.code`; không đổi extension để bypass, repack archive bằng regular POSIX paths hoặc tách artifact phù hợp |
| Archive bị `413` | upload/entry/expanded-size/ratio vượt cap | Giảm kích thước archive hoặc chọn artifact cần thiết; không tăng cap qua UI |
| AI triage `502` | key/model/provider response không dùng được | Kiểm tra exact model ID/key ở UI loopback và `docker compose ps provider-proxy`; receipt vẫn còn và không có action nào được chạy |
| AI triage báo `provider deadline reached` | Provider chưa trả structured result trước deadline; import archive vẫn thành công | Mở **Settings → AI wait**, chọn **Unlimited**, lưu rồi retry. Khi đang **Thinking**, có thể bấm **Cancel**; watchdog khẩn cấp tối đa là 24 giờ |
| AI triage báo `provider: output budget reached; retry` | Provider hết budget output trước khi trả JSON hợp lệ | Retry bằng key đang ở vault; nếu lặp lại, tăng bounded output cap hoặc chọn model ít reasoning hơn, không copy provider response/API key vào log |
| Power báo `Provider rejected the saved API key` và A/B/C dừng ngay | Provider trả 401 trước khi racer gọi tool; queue/worker không phải nguyên nhân | Mở **Settings**, thay key đúng provider bằng key còn hiệu lực, lưu lại vault rồi tạo run mới. Key đã bị thu hồi/hết hạn không thể tiếp tục run cũ |
| Power chỉ hiện `queued`, không có activity mới | `pi-runner-live` chưa chạy hoặc Control API chưa healthy | `docker compose --profile power up -d pi-runner-live --wait`, rồi kiểm tra `docker compose ps`. Runner hiện tự retry lỗi kết nối Control API tạm thời |
| UI không import được | JSON invalid hoặc manifest thiếu scope | Validate qua CLI để nhận lỗi YAML/contract rõ hơn |
| `pi-smoke` image không build được khi tải dependency | Docker/registry DNS hoặc network không sẵn sàng | Khôi phục DNS/registry rồi chạy lại với lockfile; không đổi version pin hoặc copy API key vào image |
| `run_mode_must_match_manifest` | `mode` khi tạo run khác manifest | Dùng đúng `spec.mode` |
| `budget_exceeds_manifest` | Budget request lớn hơn `spec.limits` | Hạ các cap trong request hoặc điều chỉnh manifest đã review |
| `idempotency_conflict` | Dùng lại `Idempotency-Key` cho request khác | Giữ body giống hệt để retry, hoặc dùng key mới cho run mới |
| CLI báo live provider disabled | chưa opt-in shell variable | Set `CTFMESH_LIVE_PROVIDERS_ENABLED=true` trong đúng shell |
| CLI báo missing artifact | path/role khai báo không khớp thư mục case | Sửa path relative trong manifest hoặc đặt file đúng vị trí |
| M5 `verifier`/`lab-controller` không healthy | token/key thiếu hoặc Ed25519 key pair không khớp | Xem `docker compose --profile m5 ps`, sửa secret ngoài repo; xem [hướng dẫn M5](operations/m5-verifier-labs.vi.md) |
| M5 run đứng `VERIFYING` | controller/verifier/lab outage hoặc lease chưa retry | Khôi phục service, giữ nguyên state để retry; không set `SOLVED` thủ công |
| Cần xóa mọi state local | chỉ sau khi export dữ liệu cần giữ | `docker compose down -v`, rồi `docker compose up -d --build --wait` |

## Điều chưa nên quảng bá

Không coi run record, manifest validation, hoặc triage proposal là bằng chứng
rằng AI mạnh hơn/nhanh hơn/chính xác hơn người dùng. Muốn đo điều đó cần corpus
đã review, held-out cases, provenance, baseline, cost/latency và verifier độc
lập. Browser triage đã hỗ trợ chọn **một** provider cho mỗi request, nhưng
multi-provider council/routing, dynamic finalizer, secret broker, recursive or
sandboxed artifact execution và verifier generic vẫn là các phase tiếp theo.
M5 hiện đã có verifier thật nhưng chỉ cho ba lab internal đã allowlist; không
được quảng bá như generic CTF solver hoặc proof về chất lượng model.
