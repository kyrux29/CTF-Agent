# Triển khai CTFMesh trên máy local

**Ngôn ngữ:** [Tiếng Việt](deployment-local-vi.md) · [English](deployment-local.md)

Hướng dẫn này dành cho người đã clone repository CTFMesh và muốn chạy lại
toàn bộ Power workbench trên máy riêng. Mọi service sản phẩm chạy bằng Docker
Compose; không cần cài Python, Node, database hoặc Pi runner lên host để sử
dụng.

CTFMesh chỉ dành cho challenge và instance CTF mà bạn được phép kiểm tra.

## 1. Điều kiện cần

- Docker Engine đang chạy, kèm Docker Compose plugin v2.
- Tài khoản hiện tại có quyền gọi Docker socket.
- `git` để clone/cập nhật mã nguồn.
- Python 3 chỉ để tạo các capability nội bộ của profile Power. Không cần cài
  dependency Python trên host.
- Một API key OpenAI, Gemini hoặc DeepSeek nếu muốn chạy model thật. Key được
  nhập trong trình duyệt sau khi UI khởi động, không đưa vào `.env`.

Kiểm tra nhanh trước khi bắt đầu:

```bash
docker version
docker compose version
docker ps
python3 --version
```

Nếu `docker ps` báo `permission denied`, cấp quyền Docker cho user hiện tại
theo hướng dẫn của Docker rồi đăng xuất/đăng nhập lại. Không chạy CTFMesh bằng
`sudo docker compose`, vì điều đó dễ tạo volume thuộc quyền root cho lần chạy
sau.

## 2. Clone và tạo cấu hình local

Clone repository của bạn, rồi vào thư mục project:

```bash
git clone <URL-REPOSITORY-CUA-BAN> ctfmesh
cd ctfmesh
```

Tạo file cấu hình local bị Git ignore:

```bash
cp .env.example .env
python3 support/scripts/dev/bootstrap_power_runtime.py
```

Script bootstrap tạo các token capability riêng giữa API, Pi runner,
`sandboxd` và flag-router; đồng thời bật `CTFMESH_POWER_ENABLED=true`. File
`.env` được đặt permission chỉ cho user hiện tại. Không thêm API key, cookie,
bearer token hoặc flag vào file này.

Nếu đã cài `just`, lệnh tương đương là:

```bash
just power-bootstrap
```

Chỉ chạy bootstrap một lần cho một file `.env` đã hoàn chỉnh. Script từ chối
ghi đè capability Power đang tồn tại để tránh làm hỏng stack đang dùng.

## 3. Khởi động Power workbench

Kiểm tra Compose trước, sau đó build và khởi động stack:

```bash
docker compose --profile power config --quiet
docker compose --profile power up -d --build --wait
```

Lần build đầu tiên tải base image và tạo image toolkit, nên lâu hơn các lần
sau. Các lần sau khi chỉ cần chạy lại service dùng:

```bash
docker compose --profile power up -d --wait
```

CTFMesh chỉ publish Web ingress ở loopback. Mở:

```text
http://127.0.0.1:5173
```

Không cần, và không nên, publish API, database, Pi runner, `sandboxd` hoặc
flag-router ra Internet.

## 4. Xác nhận deployment thành công

```bash
docker compose --profile power ps
curl --fail --silent --show-error http://127.0.0.1:5173/v1/ready
curl --fail --silent --show-error http://127.0.0.1:5173/v1/runtime/capabilities
```

Kết quả mong đợi:

- `api`, `web`, `provider-proxy`, `sandboxd` và `flag-router` là `healthy`.
- `pi-runner-live` là `running`.
- `/v1/ready` trả `"status":"ready"`.
- `/v1/runtime/capabilities` trả `power.status` là `ready`.

`power.status` xác nhận cấu hình cần thiết đã có; nó không kiểm tra API key
của model. API key chỉ được kiểm tra khi bạn khởi chạy một run từ UI.

## 5. Cấu hình lần đầu trên giao diện

1. Mở biểu tượng **Settings**.
2. Thêm key cho provider bạn dùng và chọn provider/model cho racer A, B, C.
3. Lưu Settings.
4. Tạo workspace, upload ZIP/TAR của challenge và nhập mô tả ngắn nếu có.
5. Nếu đề có instance, khai báo chính xác host:port được cấp quyền và xác
   nhận scope.
6. Nhập flag format nếu ban tổ chức công bố, ví dụ `DH{*}`. `*` là wildcard,
   có phân biệt chữ hoa/thường.
7. Chọn **Power solve** để bắt đầu.

Key provider chỉ sống trong `localStorage` của browser profile hiện tại. Khi
xóa browser data hoặc đổi sang browser profile khác, hãy nhập lại key qua
Settings. Key không được lưu trong database, event, artifact, sandbox hay
container environment.

Khi một output có candidate khớp format, run sẽ pause. Candidate được đưa vào
hàng chờ ngay từ observation đã ghi nhận; bạn chọn **Confirm**, **Continue
search** hoặc **Stop all**. Chỉ flag-router độc lập mới có quyền chuyển run
sang `solved`.

## 6. Chạy control plane không dùng Power

Nếu chỉ muốn mở giao diện intake/triage mà không có racer hay shell workspace:

```bash
docker compose up -d --build --wait
```

Profile mặc định không có challenge, target, provider credential hoặc Power
solver. Muốn chuyển sang Power, thực hiện bootstrap ở bước 2 rồi dùng lệnh
profile `power` ở bước 3.

## 7. Cập nhật mã nguồn và redeploy

Từ thư mục repository:

```bash
git pull --ff-only
docker compose --profile power config --quiet
docker compose --profile power up -d --build --wait
```

Lệnh này giữ PostgreSQL volume và artifact state hiện có. Trước khi update lớn,
nên export dữ liệu vận hành bạn cần giữ và kiểm tra thay đổi migration trong
release notes/ADR liên quan.

## 8. Chẩn đoán lỗi phổ biến

### Không vào được UI

```bash
docker compose --profile power ps
docker compose --profile power logs --tail=200 web api
```

Nếu port `5173` đang bận, chọn port loopback khác trong shell rồi chạy lại:

```bash
WEB_PORT=5174 docker compose --profile power up -d --build --wait
```

Sau đó mở `http://127.0.0.1:5174`.

### UI báo Power unavailable hoặc racers không nhận job

```bash
docker compose --profile power logs --tail=200 api pi-runner-live sandboxd flag-router
curl --fail --silent --show-error http://127.0.0.1:5173/v1/runtime/capabilities
```

Trước hết xác nhận `.env` không bị xóa các capability bootstrap và
`CTFMESH_POWER_ENABLED` có giá trị `true`. Không gửi nội dung `.env` hoặc log
có thể chứa dữ liệu challenge cho người không cần quyền xem.

### Model không gọi được provider

Kiểm tra provider/model đã chọn trong Settings và API key thuộc đúng provider.
Key không nằm trong `.env`, nên việc sửa `.env` sẽ không thay thế được key đã
lưu trong browser. Xem activity của racer và log `pi-runner-live`; không cần
đưa key vào container để debug.

### Stack cũ từ profile khác vẫn còn

Compose giữ các service đã chạy từ profile trước trong cùng project. Dừng
stack hiện tại trước khi đổi profile:

```bash
docker compose down --remove-orphans
docker compose --profile power up -d --build --wait
```

Lệnh này giữ volume/state. Không dùng `-v` nếu bạn muốn giữ database và
artifact hiện tại.

## 9. Dừng, dọn runtime và reset

Dừng service nhưng giữ local state:

```bash
docker compose down --remove-orphans
```

Xem trước cache/build output có thể xóa:

```bash
python3 support/scripts/dev/clean.py --dry-run
```

Xóa cache/build output:

```bash
python3 support/scripts/dev/clean.py
```

Xóa thêm dependency local như `.venv` và `node_modules` (có thể cài lại từ
lockfile):

```bash
python3 support/scripts/dev/clean.py --dependencies
```

Lệnh dưới đây **xóa vĩnh viễn** database, artifact và state Compose local:

```bash
docker compose down -v --remove-orphans
```

Chỉ dùng reset volume khi bạn đã xác nhận không cần giữ run history, intake,
artifact hoặc dữ liệu vận hành trên máy.

## 10. Kiểm tra trước khi đóng góp hoặc push

Nếu có môi trường phát triển đầy đủ, chạy:

```bash
uv sync --all-packages --all-groups
pnpm install --frozen-lockfile
just check
docker compose config --quiet
docker compose --profile power config --quiet
git status --short
```

Xem thêm [README tiếng Việt](../README.vi.md), [hướng dẫn sử dụng UI](usage-guide-vi.md),
[bản đồ tài liệu](README.md) và [CONTRIBUTING.md](../CONTRIBUTING.md).
