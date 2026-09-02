# CTFMesh

**Ngôn ngữ:** [Tiếng Việt](README.vi.md) · [English](README.md)

**Triển khai local:** [Tiếng Việt](docs/deployment-local-vi.md) · [English](docs/deployment-local.md)

CTFMesh là runtime agent chạy cục bộ dành cho các bài CTF và phòng lab **được
ủy quyền**. Profile `power` tùy chọn dùng Pi harness để điều phối một nhóm racer
cô lập trong cùng một workspace có thể kiểm toán. Model chỉ phân tích evidence
và yêu cầu thao tác đã được định kiểu; model không có quyền truy cập khóa nhà
cung cấp, máy chủ, hay Docker socket. Một run chỉ được đánh dấu `solved` sau khi
flag router độc lập xác minh candidate gắn với evidence quan sát được.

Profile Compose mặc định chỉ khởi tạo control plane trống: không có challenge,
target, flag hoặc khóa nhà cung cấp nào được đóng gói sẵn.

## Bắt đầu nhanh

### Yêu cầu

- Docker Engine và Docker Compose plugin.
- `just` hoặc Python 3 để tạo cấu hình nội bộ cho profile Power.
- Ít nhất một khóa API OpenAI, Gemini hoặc DeepSeek để chạy model thật. Khóa
  được nhập trong giao diện Settings, không đặt vào Git hay `.env`.

### Mở workbench cục bộ

Khởi động control plane mặc định:

```bash
docker compose up -d --build --wait
```

Mở [http://127.0.0.1:5173](http://127.0.0.1:5173).

Để dùng Power solver, tạo cấu hình capability nội bộ cục bộ một lần rồi chạy
profile `power`:

```bash
just power-bootstrap
docker compose --profile power up -d --build --wait
curl --fail http://127.0.0.1:5173/v1/runtime/capabilities
```

Phản hồi phải cho thấy `power.status` là `ready`. File bootstrap chỉ chứa
credential giữa các dịch vụ nội bộ và đã được Git bỏ qua.

### Luồng giải challenge trên giao diện

1. Tạo workspace, sau đó tải lên archive ZIP hoặc TAR của challenge được phép
   phân tích.
2. Mở **Settings**, thêm khóa provider một lần trong browser profile cục bộ và
   chọn provider/model cho từng racer.
3. Nhập mô tả ngắn. Nếu challenge có instance, khai báo đúng TCP target được
   cấp quyền; có thể nhập flag format, ví dụ `DH{*}`.
4. Bắt đầu Power race. Console hiển thị trạng thái từng racer, action đã qua
   kiểm soát, output, observation và Pi activity để theo dõi tiến trình.
5. Khi candidate khớp format được quan sát, run tạm dừng để bạn quyết định:
   xác nhận để gửi verifier độc lập, hoặc từ chối để racers tiếp tục tìm kiếm.
   Chỉ kết quả verifier có evidence mới kết thúc run ở trạng thái `solved`.

`*` trong flag format là wildcard. Format có phân biệt chữ hoa/thường, vì vậy
nên dùng prefix chính xác do ban tổ chức cung cấp. Để trống nếu đề không công
bố format; hệ thống sẽ chỉ coi đây là gợi ý chứ không xem model tự khẳng định
flag là bằng chứng.

### Dừng và dọn môi trường

```bash
docker compose down --remove-orphans
```

Lệnh trên dừng service nhưng giữ lại state cục bộ. Dùng lệnh dưới đây chỉ khi
muốn xóa vĩnh viễn volume/state Compose trên máy:

```bash
docker compose down -v
```

## Kiến trúc

```text
Web UI → Control API → Power controller → Pi harness → typed ACI tools
                                                        │
                                                        ▼
                                              sandboxd disposable workspace
                                                        │
observed candidate ───────────────────────→ independent flag router
                                                        │
                                                        ▼
                                                solved / continue search
```

`sandboxd` là service Power duy nhất được tạo disposable Docker workspace.
Racer chỉ thực thi qua service này; racer không nhận Docker socket, host
namespace, provider key, hoặc network target chưa được khai báo. Event là
append-only; output lớn được tham chiếu bằng artifact bất biến.

## Bảo mật và phạm vi

CTFMesh hướng đến một operator đáng tin cậy, chạy local, trên challenge và
target đã được phép. Đây không phải Internet scanner, SaaS dùng chung hay nền
tảng remote execution tổng quát.

- Khóa API chỉ được giữ trong `localStorage` của browser profile cục bộ; không
  đi vào Git, database, event, sandbox hoặc challenge mount.
- Mạng bị từ chối trừ khi target được khai báo và capability hợp lệ cho phép.
- Challenge archive là evidence không tin cậy; instruction nằm trong archive
  không trở thành policy của agent.
- Candidate không tự biến thành flag đã xác minh. Flag router độc lập phải gắn
  quyết định với kết quả command/file/remote đã quan sát.
- Giá trị flag/candidate không được lưu trong transcript, log, event hay
  artifact. Browser cục bộ chỉ cho reveal theo thao tác rõ ràng của operator
  sau đúng điều kiện xác minh.

Chi tiết threat model và quy tắc disclosure ở [SECURITY.md](SECURITY.md).

## Phát triển và kiểm thử

Đọc [CONTRIBUTING.md](CONTRIBUTING.md) và [bản đồ tài liệu](docs/README.md)
trước khi thay đổi mã nguồn. Cài dependency và chạy toàn bộ kiểm tra:

```bash
uv sync --all-packages --all-groups
pnpm install --frozen-lockfile
just check
docker compose config --quiet
docker compose --profile power config --quiet
```

Các lệnh kiểm tra riêng hữu ích:

```bash
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest -q
pnpm --filter @ctfmesh/web check
```

## Cấu trúc repository

| Đường dẫn | Nội dung |
|---|---|
| `apps/` | API, CLI và Web entry point |
| `packages/` | Domain contract và thành phần dùng lại |
| `services/` | Runtime service, Pi harness, verifier và sandbox manager |
| `tests/` | Unit, contract, integration, end-to-end, Web và Pi tests |
| `docs/` | Hướng dẫn, ADR, kế hoạch và worklog lịch sử |
| `support/` | Script bootstrap, cleanup, release chạy trên host và ví dụ |
| `challenges/` | Challenge do operator sở hữu, đã được Git ignore |
| `knowledge/writeups/` | Ghi chú truy hồi cục bộ của operator, đã được Git ignore |

## Tài liệu

- [Hướng dẫn sử dụng tiếng Việt](docs/usage-guide-vi.md)
- [Triển khai lại trên máy local](docs/deployment-local-vi.md)
- [Bản đồ tài liệu](docs/README.md)
- [Kế hoạch Pi harness hiện hành](docs/CTFMesh-pi-harness-execplan.md)
- [Thiết kế UI operator desk](docs/CTFMesh-ui-design-guide.md)
- [Danh sách sẵn sàng phát hành](docs/release-readiness-v0.1.md)
- [Hướng dẫn đóng góp](CONTRIBUTING.md)

Trạng thái hiện tại và các giới hạn đánh giá hiệu năng được theo dõi trong kế
hoạch Pi harness; không nên diễn giải việc có Power profile là cam kết về solve
rate.

## Giấy phép

CTFMesh được phát hành theo [MIT License](LICENSE). Các dependency và tài liệu
tham chiếu bên thứ ba vẫn tuân theo giấy phép riêng của chúng.
