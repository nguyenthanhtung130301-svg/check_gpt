# Lehaipreshop

Tự động kiểm tra, đổi mật khẩu và xoay TOTP 2FA cho tài khoản ChatGPT qua
giao diện web chạy cục bộ.

> **Runtime:** Python 3.11–3.13 · **UI:** FastAPI + vanilla JS ·
> **DB:** SQLite · **Browser:** Camoufox

## Chạy nhanh trên Windows

### 1. Giải nén source

Sau khi tải ZIP hoặc clone repo, mở thư mục chứa `khoidongoday.bat`:

```text
Lehaipreshop-Change-2FA\
```

### 2. Double-click `khoidongoday.bat`

Không cần chạy file nào khác.

- **Lần đầu:** launcher tự tạo `.venv`, cài dependencies, tải và kiểm tra
  Camoufox. Có thể mất vài phút tùy tốc độ mạng.
- **Những lần sau:** launcher khởi động server ẩn và tự mở dashboard tại
  `http://127.0.0.1:5033`.
- Nếu setup lỗi, cửa sổ sẽ giữ lại thông báo để sửa đúng nguyên nhân rồi chạy lại.

**Yêu cầu:** Python 3.11, 3.12 hoặc 3.13 đã được thêm vào `PATH` và có Internet
ở lần cài đầu tiên.

---

## Tính năng

| Chế độ | Mô tả |
|---|---|
| **Kiểm tra** | Login, kiểm tra live/die và gói Free/Plus. |
| **Đổi 2FA** | Xoay TOTP secret và xác minh đăng nhập bằng secret mới. |
| **Đổi mật khẩu** | Tạo mật khẩu mới và xác minh đăng nhập lại. |
| **Đổi mật khẩu + 2FA** | Đổi cả mật khẩu lẫn TOTP rồi xác minh toàn bộ. |

- Chạy song song 1–10 workers.
- Realtime log và trạng thái qua SSE.
- Auto-retry lỗi transient.
- SQLite Settings Store là nguồn cấu hình runtime duy nhất.
- Camoufox cache cô lập theo folder source.

---

## Sử dụng

1. Mở dashboard do `khoidongoday.bat` tự bật.
2. Paste mỗi tài khoản trên một dòng theo format
   `email|password|totp_secret`.
3. Chọn chế độ cần chạy.
4. Nếu cần proxy, bấm **Proxy** cạnh ô số luồng, nhập mỗi proxy trên một dòng
   rồi lưu. Proxy được gán tuần tự theo tài khoản và tự quay về dòng đầu khi
   đã đi hết danh sách; số luồng quyết định số tài khoản chạy đồng thời.
5. Nhấn **Bắt đầu**.
6. Click một dòng tài khoản để mở/đóng log chi tiết bên phải.
7. Copy hoặc tải kết quả ở panel Output.

Các định dạng proxy được hỗ trợ:

```text
host:port
host:port:user:pass
user:pass@host:port
http://user:pass@host:port
https://host:port
socks5://host:port
```

Nếu danh sách proxy để trống, tool chạy kết nối trực tiếp. Số tài khoản có thể
lớn hơn số proxy vì tool tự xoay vòng lại danh sách proxy.

Khi một job lỗi kỹ thuật, proxy vừa dùng được tạm nghỉ 5 phút. Lần retry sẽ ưu
tiên proxy kế tiếp, đồng thời bỏ qua proxy đang chạy cho tài khoản khác.

Nút **Kiểm tra proxy** lấy IP thoát hiện tại qua Cloudflare, không gọi ChatGPT,
và hiển thị IP, quốc gia, độ trễ, thời điểm kiểm tra hoặc lỗi HTTP.

---

## Cấu trúc release

Toàn bộ chương trình nằm trong **một folder duy nhất**:

```text
Lehaipreshop-Change-2FA/
├── khoidongoday.bat       # Double-click file này
├── setup.bat              # Được launcher tự gọi ở lần đầu
├── server.py
├── jobs.py
├── service.py
├── session_phase.py
├── mfa_phase.py
├── request_phase.py
├── _camoufox_runtime.py
├── camoufox-browser-spec.txt
├── requirements.txt
├── db/
├── scripts/
└── static/
```

Không di chuyển riêng `khoidongoday.bat` ra ngoài folder vì launcher cần các file
đi kèm tại đúng vị trí này.

---

## Dữ liệu local

- SQLite: `%LOCALAPPDATA%\Lehaipreshop\Change2FA\twofa.db`.
- Camoufox cache: `Lehaipreshop-Change-2FA\runtime\camoufox-cache\`.
- `.venv`, runtime, database, cache và dữ liệu tài khoản đều bị loại khỏi Git/ZIP.
- Web server chỉ bind `127.0.0.1:5033`.

---

## Chạy thủ công

Sau khi setup hoàn tất:

```bat
.venv\Scripts\python.exe server.py --host 127.0.0.1 --port 5033
```

Lệnh được chạy từ bên trong folder `Lehaipreshop-Change-2FA`.

---

## License

MIT — xem [LICENSE](LICENSE).
