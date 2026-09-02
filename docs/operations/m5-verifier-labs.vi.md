# M5 — verifier độc lập và local replay labs

**Trạng thái:** hoàn thành cho profile demo/regression local ngày 2026-08-29.
**Phạm vi:** đúng ba Web lab do CTFMesh sở hữu, chạy hoàn toàn trong Docker
network nội bộ. Đây không phải cơ chế chạy exploit tùy ý trên challenge hoặc
instance do operator cung cấp.

M5 khép vòng xác minh cho candidate đã được typed runtime tạo ra. Candidate
không tự là kết quả solve: chỉ khi verifier replay plan hợp lệ ở hai reset độc
lập và nhận proof do lab controller ký thì run mới chuyển sang `SOLVED`.

```text
Pi exploit_builder (candidate.submit, sealed evidence)
                 |
                 v
API: canonical plan artifact + durable verify job ──> VERIFYING
                 |                                      |
                 |                                      v
                 |                         verifier (fresh cookie jar x2)
                 |                                      |
                 |             reset/proof              | GET only
                 +<──── lab-controller <────────────────+──> one fixed lab
                         private key                         private network
                              |
                              v
                  opaque Ed25519 proof, never raw flag
                              |
                              v
                     API validates bindings and records result
```

## Boundary cần biết trước khi chạy

- M5 chỉ allowlist ba `technique_id`: `web.path_traversal`,
  `web.authz_boundary`, và `web.sqli_basic`. Mapping từ technique sang
  lab/origin nằm trong code đã review; plan, manifest, hay model không chọn URL.
- Plan chỉ có HTTP `GET` target-relative, query/header allowlist, một capture
  cuối và reference evidence đã seal. Header name phải lowercase và hiện chỉ
  có `accept`, `content-type`, `x-ctfmesh-user`; URL tuyệt đối, shell/script,
  redirect, biến chưa khai báo, host ngoài scope và raw flag đều bị từ chối.
- Lab controller tạo flag ngẫu nhiên trên mỗi reset vào named volume. Target
  chỉ đọc volume của chính nó; verifier không mount volume flag; controller
  không join target, Pi, provider hay control network.
- Private Ed25519 seed chỉ vào controller. Verifier chỉ nhận public key để
  kiểm proof. Proof immutable giữ đủ `lab_id`, generation, reset ID, hash,
  proof ID, timestamp UTC chính xác đã ký và signature để auditor tái kiểm sau
  này; vẫn không chứa raw flag. Không ghi bất kỳ key/token nào vào
  `.env.example`, Git, event, artifact hay log.
- Không có public API để nộp plan/candidate/raw flag. Candidate phải đi qua
  `candidate.submit` của Pi typed tool sau policy/evidence gate. Điều này tránh
  biến profile demo thành một generic flag checker.

M3 authorized source-slot/lab E2E vẫn là gate riêng. M5 chứng minh verifier và
lab replay; nó không chứng minh một model đã tự tìm được exploit trên challenge
của operator.

## Khởi động profile M5

Cần Docker Engine và Compose plugin. Chuẩn bị bốn secret ngoài repository:

| Biến | Yêu cầu | Được mount vào |
|---|---|---|
| `CTFMESH_INTERNAL_VERIFIER_TOKEN` | service token ngẫu nhiên, 16–512 ký tự | API và verifier |
| `CTFMESH_LAB_CONTROLLER_TOKEN` | service token ngẫu nhiên, 16–512 ký tự | controller và verifier |
| `CTFMESH_LAB_CONTROLLER_PRIVATE_KEY` | Ed25519 private seed, 32 bytes/64 ký tự hex lowercase | controller **chỉ** |
| `CTFMESH_LAB_CONTROLLER_PUBLIC_KEY` | public key 32 bytes/64 ký tự hex tương ứng | verifier **chỉ** |

Provision cặp Ed25519 bằng secret-management workflow đã được phê duyệt; kiểm
tra public key thực sự khớp private seed trước khi deploy. Không dùng test vector
trong test suite làm deployment key. Với shell tương tác, nhập secret mà không
in lại terminal/history:

```bash
read -rs 'CTFMESH_INTERNAL_VERIFIER_TOKEN?Verifier token (16+ ky tu): '
printf '\n'
export CTFMESH_INTERNAL_VERIFIER_TOKEN
read -rs 'CTFMESH_LAB_CONTROLLER_TOKEN?Controller token (16+ ky tu): '
printf '\n'
export CTFMESH_LAB_CONTROLLER_TOKEN
read -rs 'CTFMESH_LAB_CONTROLLER_PRIVATE_KEY?Ed25519 private seed (64 hex): '
printf '\n'
export CTFMESH_LAB_CONTROLLER_PRIVATE_KEY
read -rs 'CTFMESH_LAB_CONTROLLER_PUBLIC_KEY?Ed25519 public key (64 hex): '
printf '\n'
export CTFMESH_LAB_CONTROLLER_PUBLIC_KEY
```

Sau đó kiểm config và chạy. `WEB_PORT` tùy chọn, vẫn luôn bind loopback; đặt
`5174` nếu stack local khác đang dùng `5173`.

```bash
export WEB_PORT=5173
docker compose --profile m5 config --quiet
docker compose --profile m5 up -d --build --wait
curl --fail http://127.0.0.1:${WEB_PORT}/v1/ready
curl --fail http://127.0.0.1:${WEB_PORT}/healthz
docker compose --profile m5 ps
```

Mong đợi `api`, `web`, `postgres`, `provider-proxy`, `lab-controller`, ba
`lab-*` và `verifier` đang chạy. Lab/controller/verifier/API/Postgres không có
published host port; chỉ Web xuất hiện ở `127.0.0.1:${WEB_PORT}`. Đây là điều
kiện isolation, không phải lỗi kết nối.

## Quan sát lifecycle an toàn

Sau khi typed Pi flow đã submit candidate cho một run phù hợp, dùng các endpoint
public chỉ đọc sau. Chúng không trả plan body, candidate raw value, raw flag hay
controller token.

```bash
curl --fail http://127.0.0.1:${WEB_PORT}/v1/runs/<run-id>/console
curl --fail http://127.0.0.1:${WEB_PORT}/v1/runs/<run-id>/candidates
curl --fail http://127.0.0.1:${WEB_PORT}/v1/runs/<run-id>/verifications
curl --fail http://127.0.0.1:${WEB_PORT}/v1/runs/<run-id>/events
```

Diễn giải kết quả:

- `VERIFYING`: candidate và verifier job đã durable nhưng chưa có kết luận.
- `SOLVED`: chỉ có khi đủ hai reset ID khác nhau, replay đều pass, proof binding
  khớp candidate/plan/target profile và proof artifact immutable được lưu.
- Candidate `rejected`/run quay `RUNNING`: plan replay không lấy được candidate
  hợp lệ ở một trong hai reset. Text mà model tự báo là đúng không thay đổi kết
  quả này.
- Verifier/controller/target không sẵn sàng: worker ghi failure code an toàn và
  giữ run ở `VERIFYING`; không tự suy ra `SOLVED` hay `rejected` từ outage.

Các route `/internal/verification-jobs/*`, controller reset/proof routes, named
volumes và token là service-internal. Không gọi chúng từ browser, curl host hay
automation bên ngoài verifier; chúng không phải operator API.

## Demo và regression không lộ flag

Regression M5 đưa cả ba lab qua controller reset + target observation + signed
proof với hai attempt sạch, đồng thời kiểm deny-path schema, tamper proof,
missing controller token, unreviewed target binding và verifier unavailable.
Chạy theo quality gates ở worklog M5 thay vì copy exploit payload từ tài liệu:

```bash
docker build --target test --tag ctfmesh-test-runtime .
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e UV_PROJECT_ENVIRONMENT=/tmp/ctfmesh-venv \
  -e UV_CACHE_DIR=/tmp/ctfmesh-uv-cache \
  -v "$PWD:/app" -w /app \
  ctfmesh-test-runtime \
  sh -ec 'uv sync --frozen --all-packages --all-groups && uv run pytest -q tests/unit/test_m5_replay.py tests/unit/test_m5_lab_controller.py tests/unit/test_m5_labs.py tests/unit/test_m5_worker.py tests/unit/test_m5_candidate_pipeline.py tests/integration/test_m5_api_boundary.py tests/integration/test_compose_m3.py'
```

Không đưa test candidate/flag vào prompt, skill pack hoặc source slot có thể nhìn
thấy bởi Pi. Test vector cryptographic chỉ là fixture public để kiểm chữ ký, không
phải secret deployment.

## Xử lý lỗi và dừng stack

| Hiện tượng | Kiểm tra / xử lý an toàn |
|---|---|
| `lab-controller` hoặc `verifier` exit ngay | Secret token thiếu/ngắn, private/public Ed25519 không đúng độ dài hoặc không khớp. Dừng profile, sửa secret store/shell rồi chạy lại; không paste secret vào log. |
| `lab-flag-init` failed | Kiểm tra Docker named-volume permission và `docker compose --profile m5 ps`; initializer chỉ được phép chỉnh ownership của ba volume lab. Không tháo `read_only` hay thêm privileged mode để “chữa”. |
| `bind: address already in use` ở Web | Đặt `WEB_PORT=5174` (hoặc loopback port trống) rồi chạy lại. Không đổi host IP thành `0.0.0.0`. |
| Candidate giữ `VERIFYING` | Xem trạng thái service bằng `docker compose --profile m5 ps`; verifier outage là non-terminal theo thiết kế. Khôi phục service và để lease/retry xử lý, không set trạng thái bằng tay. |
| `exploit_plan_header_not_allowed` | Header trong declarative plan phải lowercase và thuộc allowlist M5. Không nới allowlist hay chuyển sang arbitrary header chỉ để làm một lab pass. |
| Không kết nối được lab từ host | Đúng theo thiết kế: lab không publish port. Chỉ health Web loopback và test/report an toàn được quan sát từ host. |

Dừng mà giữ Postgres/artifact state:

```bash
docker compose --profile m5 down --remove-orphans
```

Chỉ xóa named-volume state sau khi đã export thông tin cần giữ:

```bash
docker compose --profile m5 down --volumes --remove-orphans
```

Khi cần chạy M5 như smoke song song với stack local khác, dùng tên project tạm
và port loopback khác, rồi chỉ teardown project đó, ví dụ
`docker compose -p ctfmesh-m5-smoke --profile m5 down --volumes --remove-orphans`.
