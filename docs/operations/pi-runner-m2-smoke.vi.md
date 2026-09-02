# M2 Pi Runner fixture smoke

**Trạng thái:** M2 complete — fixture Docker lifecycle đã pass; đây vẫn không
phải live CTF solver.
**Canonical plan:** [CTFMesh Pi v0.1 ExecPlan](../CTFMesh-Pi-v0.1-ExecPlan.vi.md)

## Mục đích và giới hạn

Profile `pi-smoke` chứng minh Pi SDK chạy trong một container tách biệt, nhận
job đã niêm phong từ kernel, ghi event an toàn, mở lại transcript bền vững và
xử lý steering chỉ tại safe boundary. Nó không có source archive, endpoint,
Docker socket, shell, browser, target tool hay provider key.

Vì vậy một run smoke sẽ kết thúc turn ở trạng thái `inconclusive` và vẫn là
`running`; nó không thể tạo flag, gọi verifier, hay chuyển sang `solved`. Đây
là kết quả đúng của M2. M3 hiện đã thêm tool gateway/source slot và provider
proxy theo profile riêng, nhưng chúng không được bật bởi `pi-smoke`; xem
[hướng dẫn M3](m3-tool-gateway.vi.md) để vận hành boundary đó.

## Chuẩn bị

Bạn cần Docker Compose và một token nội bộ cục bộ dài ít nhất 16 ký tự. Token
này chỉ xác thực đường API nội bộ giữa `pi-runner` và `api`; nó không phải AI
API key và không cần ghi vào Git.

```bash
read -rs "CTFMESH_INTERNAL_RUNNER_TOKEN?M2 runner token (16+ ky tu): "
echo
export CTFMESH_INTERNAL_RUNNER_TOKEN
mkdir -p challenges
```

Không đặt Gemini, DeepSeek hoặc OpenAI key vào profile này. `fixture` không
gọi provider và Compose M2 cố ý không truyền AI key cho `pi-runner`.

## Chạy smoke

Khởi động default stack cùng profile M2:

```bash
docker compose --profile pi-smoke up -d --build
docker compose --profile pi-smoke ps
curl --fail http://127.0.0.1:5173/v1/ready
curl --fail http://127.0.0.1:5173/healthz
```

Mở <http://127.0.0.1:5173>, import một manifest CTF được bạn cho phép, rồi
tạo run. Không có challenge nào được đóng gói sẵn trong repository. Bạn cũng
có thể dùng các route `POST /v1/challenges` và `POST /v1/runs` trong
[README](../../README.md#import-through-the-api).

Sau khi run được tạo, hai consumer trong profile làm việc như sau:

1. `preflight-worker` tạo evidence/context niêm phong và job `start_session`.
2. `pi-runner` reserve một session ID/JSONL ổn định trong named volume, mở Pi
   SDK với built-in tools tắt, rồi tạo job `run_turn`.
3. Fixture driver phát event turn có kiểu và hoàn thành với
   `agent:inconclusive`; không có model request, finding, target request hay
   flag.

Kiểm tra lifecycle qua UI event timeline hoặc API. Thay `<run-id>` bằng ID
của run vừa tạo:

```bash
curl --fail http://127.0.0.1:5173/v1/runs/<run-id>/agent-sessions
curl --fail http://127.0.0.1:5173/v1/runs/<run-id>/events
docker compose --profile pi-smoke logs --tail=100 preflight-worker pi-runner
```

Bạn sẽ thấy các event cùng họ `agent.job.*`, `agent.session.*` và
`agent.turn.*`. Event chỉ chứa ID, digest, thống kê hoặc mã lỗi an toàn; nó
không chứa transcript Pi, raw flag hay credential.

## Kiểm thử steering an toàn

Khi session đang idle, gửi steering qua UI hoặc:

```bash
curl --fail-with-body \
  -H 'content-type: application/json' \
  -X POST http://127.0.0.1:5173/v1/runs/<run-id>/steer \
  --data '{"message":"Review the sealed evidence on the next turn."}'
```

API trả về ID/digest thay vì lặp lại câu steering trong public event response.
Nếu một turn đang chạy, request được giữ trong hàng đợi và chỉ xuất hiện thành
job `steer` sau turn đó. Runner mở lại cùng JSONL session khi cần, append
custom message bền vững, rồi kernel mới xác nhận steering và queue turn tiếp
theo. Text có dạng raw flag, bearer token hoặc API key bị từ chối.

## Kiểm tra cô lập container

`docker compose --profile pi-smoke config` phải cho thấy:

- `pi-runner` chỉ ở network nội bộ `control`, không có port publish hay
  challenge/source mount;
- `preflight-worker` chỉ dùng network `control`, artifact volume và không có
  challenge/source mount;
- không service M2 nào mount `./challenges`;
- không service nào có Docker socket, `privileged`, host namespace hoặc
  provider-proxy trong M2;
- `pi-runner`/`preflight-worker` là read-only, `cap_drop: ALL`,
  `no-new-privileges`, `pids_limit` và `tmpfs /tmp`.

## Dừng hoặc reset

Dừng services nhưng giữ database, artifact và Pi session volume:

```bash
docker compose --profile pi-smoke down --remove-orphans
```

Chỉ khi bạn chủ ý xóa toàn bộ state local mới dùng `docker compose down -v`.
Lệnh đó xóa các named volume, gồm cả transcript Pi local, và không thể hoàn
tác bằng CTFMesh.

## Live-model status

Không đặt `CTFMESH_PI_RUNNER_MODE=live` để coi profile này là demo live.
`pi-smoke` vẫn không đưa provider credential vào container và sẽ fail closed
nếu bị cấu hình sai. M3 cung cấp profile live riêng với CONNECT allowlist,
secret injection tối thiểu và kiểm tra egress; nó vẫn chưa thay thế verifier
hay lab E2E độc lập.
