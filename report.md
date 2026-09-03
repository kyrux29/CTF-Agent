# Báo cáo: khôi phục vòng đời Power run và sửa bắt flag

**Nhánh:** `feat/power-capability-gaps` (gồm cả `fix/power-run-lifecycle-and-flag-capture`)
**So với:** `main` @ `7714402`
**Quy mô:** 22 file · +2 123 / −54 dòng · 2 commit
**Ngày:** 02–03/09/2026

---

## 1. Tóm tắt

Trước đợt này, một Power run **kết thúc sau khoảng 48 giây** bất kể ngân sách cấu hình
bao nhiêu, rồi treo vô hạn ở trạng thái `running`. Milestone `M-PI-5` (đo hiệu quả giải
challenge) vì thế **chưa từng chạy được** — không có gì để đo.

Sau đợt này, một run chạy **161 lượt gọi công cụ trong 9 phút**, sống sót qua lỗi mạng
tới nhà cung cấp model, kết thúc bằng một trạng thái có nghĩa, và **để lại sản phẩm lấy
về được** (một `poc.py` tự kiểm chứng, tải xuống qua API).

Đồng thời phát hiện: cơ chế bắt flag **bỏ sót 15 trên 19 định dạng giải thật**, nghĩa là
với phần lớn giải, hệ thống không thể công nhận một flag kể cả khi agent đã tìm ra.

Toàn bộ được kiểm chứng bằng **7 lần chạy thật** trên một challenge pwn (binary Zig
static-PIE đã strip), không phải bằng suy luận trên code.

---

## 2. Tình trạng trước

| Vấn đề | Hệ quả kinh doanh |
|---|---|
| Run dừng sau 48 giây | Không đo được năng lực sản phẩm. `M-PI-5` bế tắc từ đầu |
| Bắt flag sai 15/19 định dạng | Với đa số giải, flag tìm ra cũng **không được công nhận** |
| Run treo `running` vĩnh viễn | Chiếm tài nguyên, phải huỷ tay, UI báo "đang chạy" sai sự thật |
| Cap thời gian không hiệu lực | Cấu hình 25 phút nhưng run chạy 2h33 không ai dừng |
| Lỗi mạng thoáng qua giết racer | Mất cả lượt chạy vì một gói tin |
| Không lấy được kết quả | Agent viết được exploit rồi file biến mất cùng container |

---

## 3. Đã sửa gì

### 3.1 Bắt flag — nghiêm trọng nhất về nghiệp vụ

Luật mặc định là `\b(?:FLAG|HTB|CTF)\{…\}`. Ranh giới từ (`\b`) **không thể nằm giữa
`pico` và `CTF`**, nên mọi tiền tố kết thúc bằng "ctf" đều trượt.

| | Trước | Sau |
|---|---|---|
| Định dạng thật bắt được | **4 / 19** | **19 / 19** |

Ví dụ trượt: `picoCTF{…}` `uiuctf{…}` `DUCTF{…}` `corctf{…}` `csawctf{…}` `justCTF{…}`
`TFCCTF{…}` `SEKAI{…}` `crypto{…}` `b01lers{…}`

Ba lỗi liên quan cùng nhóm:

- **Cắt cụt flag:** `FLAG-YWJjZGVm==` bị bắt thành `FLAG-YWJjZGVm` (mất đệm base64). Giá
  trị cụt đó vẫn qua được mọi lớp kiểm chứng → **run có thể kết luận "đã giải" với flag sai.**
- **Nhập định dạng làm mất mặc định:** gõ sai một chữ hoa thường là run mất sạch luật bắt.
  Nay giữ cả hai.
- **Agent tự kích hoạt nhầm:** hệ thống tự chèn mẫu flag vào kết quả công cụ, nên agent
  nhắc lại là mở cổng duyệt. Đã lọc mẫu rỗng.

**Vì sao lỗi này sống sót:** mọi test cũ đều **tự truyền luật của riêng nó** vào, không
test nào chạy luật mặc định đang ship. Test mới chạy đúng hằng số thật với 19 định dạng.

### 3.2 Vòng đời run

| Sửa | Trước | Sau |
|---|---|---|
| Trần lượt của racer | cứng 4 batch = 40 lượt gọi cả đời (~1% ngân sách) | cấu hình được, mặc định 200 |
| Cap thời gian | khai báo nhưng **không ai trừ** → vô hiệu | trừ theo bucket 5 giây, hết là dừng |
| Đồng hồ trên UI | luôn hiện 0 giây | đo theo thời gian thực |
| Lỗi mạng nhà cung cấp | giết racer vĩnh viễn | thử lại 3 lần, chỉ với lỗi tự khỏi được |
| Run đã nghỉ | im lặng, UI vẫn báo "đang đua" | phát tín hiệu `power.sessions.idle` |

Về **retry**: run thứ 6 chết vì hai lỗi `transport_failed`. Logic thử lại vốn tồn tại
trong nhánh Python cũ nhưng **không được chuyển sang** kiến trúc hiện tại. Run thứ 7 kích
hoạt retry 8 lần và sống sót.

Về **tín hiệu nghỉ**: cố ý **không** đổi trạng thái run. `running` chính là điều kiện để
thao tác *steer* (điều hướng agent) hoạt động — mà steer là cách người vận hành kéo agent
ra khỏi ngõ cụt. Đổi trạng thái sẽ phá đúng cơ chế cứu hộ đó (3 test đã bắt được khi tôi
thử hướng sai).

### 3.3 Trải nghiệm của agent

**Lỗi công cụ không nói cách sửa.** Agent chỉ nhận một câu chung chung và một mã lỗi đục.
Racer B thử lại đúng một lệnh sai **5 lần** rồi bỏ cuộc, ngồi không hết lượt chạy.

| Racer B | Trước | Sau |
|---|---|---|
| Số lượt gọi công cụ | **10** rồi chết | **95** |

**Yêu cầu bất khả thi.** Với challenge chạy ngoại tuyến, flag **không thể** nằm trong gói
tài liệu — nó ở máy chủ của ban tổ chức. Nhưng hướng dẫn vẫn bắt agent "nộp ứng viên đã
quan sát được". Một racer đã thoả mãn yêu cầu đó bằng cách **tự viết một chuỗi giống flag
vào chương trình rồi đọc lại và nộp**. Nay hướng dẫn nêu đúng mục tiêu đạt được: dựng
primitive tái lập được, và cấm tự viết chuỗi hình dạng flag.

### 3.4 Năng lực mới — lấy được sản phẩm

Trước đây agent có thể dựng exploit hoàn chỉnh, chạy thử thành công, rồi **file biến mất**:
thư mục làm việc là bộ nhớ tạm chết theo container, và không có đường tải file ra.

Bốn thay đổi khép kín đường này:

1. `ctf_fs_write` đọc lại file vừa ghi → nội dung thành bằng chứng bất biến
2. Endpoint tải nội dung cho người vận hành (bắt buộc xác nhận, có ghi nhật ký)
3. `ctf_artifact_read` — agent đọc lại phần bị cắt thay vì chạy lại lệnh và trả tiền lần nữa
4. `ctf_gdb_read` + `offset` cho đọc file — gỡ hai nút thắt khi phân tích binary

**Đã kiểm chứng đầu-cuối:** một `poc.py` do agent viết đã được tải về qua API, không đụng
vào ổ đĩa Docker.

---

## 4. Bằng chứng — 7 lần chạy thật

Challenge: binary Zig static-PIE đã strip, ngoại tuyến. 3 agent chạy song song, ngân sách
$2.00 / 25 phút.

| # | Kết thúc | Lượt gọi | Chi phí | Nguyên nhân dừng |
|---|---|---|---|---|
| 1 | treo | 50 | $0.020 | trần 4 batch |
| 2 | lỗi | 54 | $0.023 | xung đột khoá (do tôi gây khi vá, đã sửa) |
| 3 | tạm dừng | 72 | $0.042 | cổng flag bắt nhầm chuỗi thử của chính agent |
| 4 | nghỉ | 132 | $0.097 | agent hết giả thuyết |
| 5 | nghỉ | 152 | $0.092 | agent hết giả thuyết |
| 6 | lỗi | 160 | $0.205 | lỗi mạng, chưa có retry |
| 7 | nghỉ | **161** | $0.123 | agent hết giả thuyết |

**Ngân sách chưa bao giờ là giới hạn:** cao nhất dùng 10% chi phí và 3.6% trần lượt gọi.
Agent dừng vì **hết ý tưởng**, không phải hết hạn mức. Tăng ngân sách sẽ không đổi gì.

### Chất lượng suy luận

Ở run 7, agent làm việc có phương pháp và **báo cáo trung thực khi không tìm ra**:

> *"Sizes 65,536 through 4,294,967,295 were rejected with `ERR bad size`."*
> *"A 200-case protocol fuzz loop completed cleanly: no `Invalid free`, no crash."*
> *"The only established weakness remains the previously known stale-tail information leak.
> No complete candidate was observed or submitted."*

Trước khi sửa hướng dẫn, agent **tự chế flag** để nộp. Sau khi sửa, nó báo âm tính đúng
phạm vi bằng chứng — đây là thay đổi hành vi quan trọng về mặt tin cậy.

### Kết quả giải challenge

**Chưa giải xong.** Đạt được: xác định và chứng minh được lỗ hổng lộ dữ liệu (`PATCH` ngắn
hơn giá trị đã lưu để lại đuôi cũ đọc được), kèm `poc.py` tự kiểm chứng. Chưa nâng lên
thực thi mã từ xa.

Điểm cần nhấn: đây giờ là **giới hạn của model AI**, không còn là giới hạn của hệ thống.
Sáu lần đầu agent chết vì hạ tầng; lần cuối nó chạy đủ lâu, đi đúng hướng được chỉ, và
dừng vì hết ý.

---

## 5. Kiểm định

| | |
|---|---|
| Test Python | **528 passed**, 6 skipped |
| Test agent runtime | **70 passed** |
| Lint · định dạng · kiểu | sạch (ruff, pyright 0 lỗi) |
| Cấu hình triển khai | hợp lệ cả 2 profile |

Bổ sung **4 file test mới** (778 dòng) cho: 19 định dạng flag, vòng đời run, hướng dẫn
chế độ ngoại tuyến, và đường tải sản phẩm. Mỗi test dựng lại đúng kịch bản hỏng đã quan sát.

Nhật ký milestone ghi tại `docs/phases/power-pi-m5-worklog.md` (nối tiếp, không sửa nội
dung cũ).

---

## 6. Còn tồn đọng

### 6.1 Cần quyết định, chưa phải việc kỹ thuật

| Vấn đề | Lựa chọn |
|---|---|
| **Cổng flag hai tầng** | Hiện một chuỗi thử nghiệm của agent làm dừng cả 3 làn (đã xảy ra ở run 3). Nên tách: chỉ khi agent chủ động nộp mới dừng; quét tự động chỉ hiện dấu hiệu |
| **Power không có HTTP** | Nhưng vẫn phát bộ hướng dẫn cho challenge Web. Hoặc bổ sung HTTP, hoặc tuyên bố Power chỉ phục vụ pwn/rev/crypto/forensics |
| **Hai thế hệ kiến trúc** | Nhánh Python cũ (`power_swarm`, bộ hướng dẫn theo loại bài, kho writeup) **không còn chạy** nhưng vẫn nằm trong repo và vẫn được cấu hình triển khai gắn vào. Nên cứu 2 tính năng đáng giữ rồi xoá phần còn lại |

### 6.2 Việc kỹ thuật đã xác định

| Việc | Ước lượng |
|---|---|
| Chạy bộ đo `M-PI-5` (3 điều kiện: 1 agent / 3 agent / model mạnh hơn) | ngày |
| Cập nhật tài liệu mô hình mối đe doạ — hiện **mâu thuẫn với sản phẩm** | ngày |
| Bộ nhớ giả thuyết dùng chung giữa các agent | tuần |
| Kết nối nền tảng CTFd để xác minh flag đúng/sai thật | tuần |
| Tách `app.py` (4 738 dòng, 80 endpoint) | tuần |

### 6.3 Giới hạn kiến trúc — cần biết nếu tính mở rộng

Hệ thống được thiết kế cho **một người vận hành tin cậy trên một máy**. Ba đặc điểm sau là
**đánh đổi có chủ đích**, không phải thiếu sót, nhưng chặn việc dùng nhiều người:

- 45 endpoint công khai **không có xác thực** — an toàn duy nhất là chỉ mở trên localhost
- Dịch vụ sandbox giữ quyền tương đương root trên máy chủ
- Khoá API của nhà cung cấp model lưu dạng văn bản thuần trong trình duyệt

Muốn nhiều người dùng chung là **thiết kế lại tầng tin cậy**, không phải gia cố.

---

## 7. Khuyến nghị

1. **Chạy bộ đo `M-PI-5`** — giờ mới khả thi. Đây là con số đầu tiên chứng minh được năng
   lực sản phẩm, và nó quyết định mọi ưu tiên còn lại.
2. **Chạy thử với model mạnh hơn** — suốt 7 lần chỉ dùng model rẻ nhất. Phép thử này tách
   bạch "giới hạn hệ thống" với "giới hạn model", rất rẻ và rất nhiều thông tin.
3. **Chốt 3 quyết định ở mục 6.1** trước khi xây thêm.
4. **Không tăng ngân sách** — đã đo, không phải nút thắt.

---

## Phụ lục — thay đổi theo file

| Vùng | Nội dung |
|---|---|
| `apps/api` | luật bắt flag, endpoint tải sản phẩm, hướng dẫn theo chế độ, trừ thời gian |
| `packages/db` | trừ thời gian theo bucket, tín hiệu nghỉ |
| `services/flag-router` | luật mặc định đồng bộ |
| `services/orchestrator` | sửa đồng hồ trên UI |
| `services/pi-runner` | trần lượt cấu hình được, retry, 4 công cụ mới, hướng dẫn sửa lỗi |
| `tests` | 4 file mới + cập nhật test cũ vốn che giấu lỗi |
