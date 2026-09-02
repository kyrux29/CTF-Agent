# M3 tool gateway và fixed slot

**Trạng thái:** M3 hoàn thành ngày 2026-08-31. Contract, policy, database
boundary, Compose topology, provider proxy và authorized source/lab E2E đã
pass. Đây là bằng chứng runtime transport/policy, không phải claim rằng model
đã solve challenge.

**Canonical plan:** [CTFMesh Pi v0.1 ExecPlan](../CTFMesh-Pi-v0.1-ExecPlan.vi.md)

## M3 làm gì

M3 là ranh giới thực thi hẹp giữa worker Pi và material/target CTF. Worker
không có shell, Docker socket, filesystem mount, endpoint URL tuyệt đối hay
provider network. Thay vào đó, một request đi theo luồng sau:

```text
Pi worker → Control API → tool-gateway → fixed source slot → source mount hoặc lab alias
Pi runner live → provider-proxy (CONNECT allowlist) → provider HTTPS
Browser archive triage → Web reverse proxy → Control API → provider-proxy → provider HTTPS
```

`tool-gateway` kiểm tra lease/session, role, manifest, policy, idempotency và
budget trong Postgres trước khi slot làm việc. Kết quả được redact, ghi thành
artifact bất biến và trả về bằng ID/digest; không phải là raw flag hoặc lời tự
khẳng định của model.

Các tool M3 hiện có là:

| Nhóm | Tool | Giới hạn chính |
|---|---|---|
| Source | `source.list`, `source.read`, `source.search`, `source.manifest` | Chỉ source mount read-only, path POSIX relative, không symlink/execution |
| Transform | `transform.apply` | Base64, hex, URL encode/decode và ROT13 với byte quota cố định |
| HTTP | `http.request` | Worker chỉ chọn alias + path relative; slot tạo URL từ manifest đã duyệt |
| Artifact | `artifacts.inspect` | Quan sát artifact đã khai báo, không unpack/run input mới |

M3 không nhận archive upload làm quyền thực thi, không chạy code do model tạo,
không là scanner Internet, và không thể đưa run sang `solved`. Chỉ verifier
độc lập của M5 mới có quyền đó.

## Chuẩn bị source đã được phép

Không có challenge demo trong repository. Đặt source đã được bạn review trong
`challenges/`; thư mục này bị Git ignore và Docker ignore. Source slot không
unpack ZIP/TAR, không chạy `Dockerfile`, dependency install, test suite hoặc
binary. Nếu input của bạn là archive, hãy dùng archive receipt UI/API cho
triage metadata trước; chỉ curate source cần đọc vào slot sau khi bạn đã review
nó.

Source slot được bind vào challenge **database ID**, không phải tên hiển thị.
Điều này ngăn một worker/model chọn host path của chính nó.

1. Khởi động stack mặc định và import manifest bằng UI hoặc `POST /v1/challenges`.
2. Lấy trường `id` trả về, dạng `challenge_<hex>`, bằng `GET /v1/challenges`.
3. Tạo thư mục host `challenges/<challenge-id>/` và đặt source đã duyệt vào đó.
4. Bảo đảm Docker đọc được thư mục; không dùng symlink để trỏ sang dữ liệu ngoài
   scope. Source slot chạy UID/GID `65532` và chỉ mount thư mục đó read-only.

Không set `CTFMESH_SOURCE_SLOT_*_CHALLENGE_ID` theo `metadata.name`. Nó phải
khớp ID mà Control API đã persist, nếu không gateway sẽ từ chối binding.

## Khai báo target alias trong manifest

Đối với lab HTTP local được cấp phép, `target_aliases` phải là origin HTTP(S)
không có path, query, fragment hoặc credential, và phải nằm trong
`allowed_endpoints`. Ví dụ cấu trúc (không phải challenge sẵn dùng):

```json
{
  "target": {
    "type": "docker_compose",
    "compose_file": "lab/docker-compose.yml",
    "service": "lab-target",
    "healthcheck": {"url": "http://lab-target:8080/health", "expected_status": 200},
    "allowed_endpoints": [
      {"host": "lab-target", "ports": [8080], "protocols": ["http"]}
    ],
    "target_aliases": {"lab": "http://lab-target:8080"}
  },
  "tool_profile": ["source.list", "source.read", "source.search", "source.manifest", "transform.apply", "http.request"]
}
```

Worker chỉ có thể gửi như `target_alias: "lab"` và `path: "/health"`. Các
URL tuyệt đối, `//host`, header `Host`/`Authorization`/`Cookie`/proxy, redirect
ra ngoài scope, body quá quota, alias chưa khai báo và endpoint ngoài manifest
đều bị từ chối. Cookie jar do slot giữ riêng theo branch; worker nhận observation
đã redact, không nhận cookie hoặc final target URL.

Lab do operator khởi động độc lập phải chỉ join vào private `slot-1` hoặc
`slot-2` network của Compose, tùy slot đã cấu hình. Không cấp Docker socket cho
CTFMesh để tự tạo/kết nối target container. Kiểm tra tên network thực tế bằng
`docker network ls` trước khi cấu hình lab Compose của bạn với network external
đó. Không attach một target công khai hay không được phép.

## Deploy M3 hoàn toàn bằng Docker

Toàn bộ process sản phẩm và dependency build (API, Web, PostgreSQL, Pi runner,
gateway, source slot và proxy) đều chạy trong container. Máy host chỉ cần
Docker Engine kèm Compose plugin; không cần cài host `uv`, Python, Node hoặc
`pnpm` để deploy. Host vẫn phải giữ thư mục source đã review và inject
token/API key riêng tư — chúng là input của operator, không được bake vào image.

Profile `m3` là entry point triển khai đầy đủ. Nó khởi động default stack (đã
gồm provider proxy cho archive triage) cùng preflight worker, session
initializer, Pi live, gateway và hai source slot. `pi-smoke` fixture bị loại
khỏi profile này vì hai runner không
được tranh cùng durable job queue. Các profile `m3-source` và `m3-provider`
vẫn tồn tại cho diagnostic hẹp.

M3 runtime vẫn giữ hai source slot cố định. Với challenge đầu tiên, chỉ cần set
slot 1: slot 2 mặc định bind read-only cùng challenge database ID/source để giữ
topology và cho phép stable scheduling. Khi chạy hai challenge song song, set
`CTFMESH_SOURCE_SLOT_2_CHALLENGE_ID` riêng. Nếu có lab HTTP cho challenge đầu
tiên, attach lab vào cả hai private network `slot-1` và `slot-2`; không attach
provider/public network.

Trong một shell riêng tư, đặt token nội bộ dài tối thiểu 16 ký tự. Không paste
token/API key vào issue, file `.env` đã commit, manifest hoặc prompt.

```bash
read -rs "CTFMESH_INTERNAL_RUNNER_TOKEN?Runner token (16+ ky tu): "
echo
export CTFMESH_INTERNAL_RUNNER_TOKEN
read -rs "CTFMESH_TOOL_GATEWAY_TOKEN?Gateway token (16+ ky tu): "
echo
export CTFMESH_TOOL_GATEWAY_TOKEN
read -rs "CTFMESH_SOURCE_SLOT_TOKEN?Slot token (16+ ky tu): "
echo
export CTFMESH_SOURCE_SLOT_TOKEN

export CTFMESH_TOOL_GATEWAY_URL=http://tool-gateway:8081
export CTFMESH_SOURCE_SLOT_1_CHALLENGE_ID=challenge_<id-slot-1>
```

Hai slot URL đã có default nội bộ cố định. Chỉ override slot 2 khi chủ động bind
challenge thứ hai; model/request không được chọn các giá trị deployment này.

Sau đó render topology trước khi build:

```bash
docker compose --profile m3 config --quiet
```

Để chạy Pi live, chọn **một** provider/model hợp lệ rồi export key chỉ vào môi
trường process gọi Compose, ví dụ `OPENAI_API_KEY`, `GEMINI_API_KEY` hoặc
`DEEPSEEK_API_KEY`, cùng `CTFMESH_PI_MODEL_PROVIDER` và
`CTFMESH_PI_MODEL_ID`. Profile `m3` đưa key vào `pi-runner-live` duy
nhất; gateway, slot và proxy không nhận key. API cũng không nhận key qua
environment: key của browser archive triage chỉ tồn tại trong đúng request và
API chuyển nó qua CONNECT proxy nội bộ đã review.

```bash
export CTFMESH_PI_MODEL_PROVIDER=openai
export CTFMESH_PI_MODEL_ID=<approved-model-id>
read -rs "OPENAI_API_KEY?OpenAI API key: "
echo
export OPENAI_API_KEY
docker compose --profile m3 up -d --build --wait
```

Provider proxy chỉ chấp nhận `CONNECT <exact-dns-name>:443`. Allowlist mặc định
là `api.openai.com`, `generativelanguage.googleapis.com` và `api.deepseek.com`.
Nếu phải thay đổi, `CTFMESH_PROVIDER_PROXY_ALLOWED_HOSTS` chỉ được chứa DNS host
chính xác, không wildcard/IP/port. `NODE_OPTIONS=--use-env-proxy` buộc Node dùng
proxy; `NO_PROXY` giữ API control-plane nội bộ ngoài proxy.

Browser archive triage có form key một lần riêng, được xử lý không persist. Nó
không cung cấp key cho `pi-runner-live`; M3 live dùng environment injection để
giữ key tách khỏi UI/session/event/database.

## Probe challenge đầu tiên trước khi dùng API key

Sau khi import manifest bằng UI, đặt source ở
`challenges/<challenge-database-id>/`, set token/ID như trên rồi chạy profile
không model:

```bash
docker compose --profile m3-source up -d --build --wait
docker compose --profile m3-source exec -T api \
  python support/scripts/m3_operator_probe.py \
  --challenge-id challenge_<database-id> \
  --source-path path/to/reviewed-source-file \
  --target-alias lab \
  --http-path /health
```

`--source-path` là file POSIX relative trong source mount. `--target-alias` phải
đúng alias manifest; bỏ hai option target để chỉ kiểm tra source. Full M3 proof
cần target lab đang healthy và join cả hai network slot. Probe tạo run riêng,
claim chỉ job của run đó, không gọi provider/model, không in source/response
body, không submit finding/candidate/flag và không thể set `solved`. Thành công
sẽ in source/HTTP artifact digest, HTTP status, deny code của alias ngoài scope,
rồi cancel run và dispose session. Sau khi probe pass, tạo **run mới** trên UI
cho model live; không tái dùng diagnostic run.

## Kiểm tra và dừng an toàn

Các kiểm tra không cần target/model thật:

```bash
docker compose --profile m3 config --quiet
docker compose --profile m3 ps
docker compose --profile m3 ps provider-proxy
```

`provider-proxy` phải là `healthy`. `docker compose ... config` phải cho thấy
chỉ proxy có `provider-public`; API và live runner chỉ có thể nối tới proxy qua
`provider` nội bộ; source slots chỉ có `slot-1`/`slot-2`, và live runner chỉ có
`control` + `provider`. Không dùng `--remove-orphans` nếu máy có container khác
chưa được review.

Để dừng riêng service M3 trong một máy đang chạy stack khác:

```bash
docker compose --profile m3 stop pi-runner-live tool-gateway sandbox-source-1 sandbox-source-2 preflight-worker
```

Không xóa volume/database khi chỉ muốn dừng. Giữ `provider-proxy` chạy nếu vẫn
muốn dùng browser archive triage của default stack. `docker compose down -v` là
thao tác chủ ý xóa state local và chỉ nên dùng sau khi đã export dữ liệu cần giữ.

## Giới hạn đang mở

- M4 đã thêm scheduler/master-worker thực tế, Hint Deck và branch/falsifier.
- M5 đã thêm lab controller, verifier replay hai lần và quyền `solved` cho ba
  local lab đã allowlist; xem [hướng dẫn M5](m5-verifier-labs.vi.md). M5 không
  tạo generic verifier và M3 transport proof không biến M5 thành generic solve.
- Lần build đầu cần registry package có thể truy cập: npm/Corepack cho Web/Pi
  và PyPI cho API/tool-runtime. Đây là egress của Docker build, không phải
  egress runtime của service. Nếu registry, DNS hoặc cache không sẵn, dừng tại
  đó hoặc cấu hình trusted mirror/CI cache của operator; không vendor dependency,
  không nới egress runtime và không thay bằng demo target để tuyên bố E2E pass.

### Khắc phục Docker DNS trước lần build đầu

Nếu host resolve được registry nhưng `docker run ... nslookup registry.npmjs.org`
trả timeout hoặc `EAI_AGAIN`, đây là cấu hình Docker daemon của máy, không phải
lỗi CTFMesh. Việc đổi daemon DNS ảnh hưởng container tạo mới trên toàn máy, nên
operator có quyền quản trị phải review các workload đang chạy trước khi sửa.
Giữ nguyên các field hiện có trong `/etc/docker/daemon.json` và thêm, ví dụ:

```json
"dns": ["1.1.1.1", "1.0.0.1"]
```

Sau khi JSON đã được merge/validate, thử reload daemon rồi kiểm tra DNS trong
container trước khi build:

```bash
sudo dockerd --validate --config-file /etc/docker/daemon.json
sudo systemctl reload docker
docker run --rm busybox:1.36.1 nslookup registry.npmjs.org
docker compose --profile m3 up -d --build --wait
```

Một số Docker daemon (đã quan sát với 26.1.5) nhận HUP nhưng không reload field
`dns`; nếu probe vẫn timeout thì cần `sudo systemctl restart docker`. Restart có
thể dừng workload khi `live-restore=false`, nên chỉ thực hiện sau khi operator đã
điều phối mọi container không thuộc CTFMesh. Nếu policy mạng không cho resolver
công cộng, dùng DNS/trusted package mirror do đơn vị vận hành cung cấp thay vì
hard-code resolver khác. Không sửa Docker daemon từ bất kỳ container CTFMesh nào.
