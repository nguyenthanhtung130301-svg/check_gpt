# Kế hoạch: Hai chế độ chạy proxy cho luồng kiểm tra tài khoản

Ngày lập: 2026-09-20  
Trạng thái: Draft để xác nhận nghiệp vụ trước khi implementation

## 1. Mục tiêu

Cho phép Admin quản lý một pool nhiều proxy và chọn một trong hai cách chạy:

1. `random_per_account` — mỗi worker chọn ngẫu nhiên một proxy khả dụng khi bắt đầu một tài khoản mới.
2. `manual_per_worker` — Admin gán cố định một proxy cho từng worker/luồng; worker đó tiếp tục dùng proxy đã gán cho các tài khoản kế tiếp.

Trong cả hai chế độ, một tài khoản phải giữ nguyên proxy từ đầu đến cuối một lần thực thi. Không được đổi IP giữa login, đọc entitlement, đổi password, đổi 2FA hoặc verify.

Pool rỗng tiếp tục có nghĩa là `DIRECT`; hai chế độ trên chỉ có hiệu lực khi pool có proxy.

## 2. Quy tắc nghiệp vụ đề xuất

### 2.1 Random theo tài khoản

- Chọn proxy tại runtime, ngay trước khi job chuyển sang xử lý tài khoản.
- Chỉ chọn proxy đang enabled, không cooldown và chưa bị job khác sử dụng.
- Nếu còn từ hai ứng viên phù hợp, không chọn lại proxy mà chính worker đó vừa dùng cho tài khoản trước.
- Nếu chỉ còn đúng một proxy khả dụng, cho phép dùng lại và ghi log rõ lý do; không làm job lỗi chỉ vì không thể đổi IP.
- Proxy được ghim vào job cho đến khi job success, error hoặc cancelled.
- Retry do lỗi kỹ thuật phải loại proxy vừa thất bại; nếu không còn proxy thì chờ đến timeout hiện hành rồi trả lỗi rõ ràng.

### 2.2 Thủ công theo worker

- Worker có slot ổn định: `Luồng 1..N`, không phụ thuộc vào thứ tự của `asyncio.Task` trong list.
- Admin gán một proxy pool ID cho mỗi slot đang hoạt động.
- Mỗi slot luôn dùng proxy đã gán cho mọi job mà slot đó nhận.
- Không tự fallback sang proxy khác khi proxy cố định lỗi/cooldown; slot đó tạm nghỉ, các slot khỏe tiếp tục chạy.
- Mapping của slot lớn hơn `max_concurrent` được lưu nhưng đánh dấu inactive, để tăng số luồng trở lại không làm mất cấu hình.
- Mặc định không cho hai slot đang hoạt động dùng cùng một proxy. Nếu sau này có nhu cầu chia sẻ, cần mở thành một policy riêng vì nó thay đổi giới hạn tải và chống trùng IP đồng thời.
- Retry giữ affinity với slot đã chạy lần trước để không âm thầm đổi proxy trong chế độ thủ công.

### 2.3 Thay đổi cấu hình khi đang chạy

- Không cho thay `proxy pool`, `proxy mode`, `worker bindings` hoặc `max_concurrent` khi còn job `queued/running`; API trả `409` kèm thông báo dừng hoặc hoàn tất batch trước.
- Job đang chạy không bao giờ bị đổi proxy do Admin bấm lưu setting.
- Toàn bộ cấu hình proxy được validate trước rồi ghi atomically; không ghi từng key khiến mode, pool và mapping lệch nhau.

## 3. Mô hình dữ liệu/cấu hình

Đề xuất các setting:

```text
twofa.proxy_mode = "random_per_account" | "manual_per_worker"
twofa.proxy_pool = [ProxyEntry]
twofa.worker_proxy_bindings = {"1": "proxy_id", "2": "proxy_id", ...}
```

`ProxyEntry` tối thiểu:

```json
{
  "id": "px_<stable-id>",
  "url": "http://user:pass@host:port",
  "enabled": true,
  "label": "Proxy VN 01"
}
```

Yêu cầu dữ liệu:

- `id` ổn định; mapping không được dùng vị trí dòng vì reorder textarea có thể đổi proxy của worker.
- URL được normalize bằng logic hiện tại và phải unique sau normalize.
- Credential proxy là dữ liệu nhạy cảm: audit log phải redact; collaborator, job snapshot, SSE và log chỉ nhận label đã che credential.
- API bootstrap đầy đủ proxy chỉ trả cho Admin.
- Backward compatibility: loader chấp nhận `twofa.proxy_pool: list[str]` hiện tại, tạo deterministic ID trong bộ nhớ; lần Admin lưu tiếp theo mới nâng sang catalog mới.
- Bản spec `_bmad-output/implementation-artifacts/spec-random-proxy-strategy.md` hiện chỉ bao phủ random. Trước khi code, tạo spec thay thế hoặc cập nhật qua quy trình phê duyệt; không sửa âm thầm phần intent đang frozen.

## 4. Thiết kế runtime

### 4.1 Stable worker slot

- Đổi `_spawn_workers()` để tạo `_worker(slot_id)` với slot từ `1..max_concurrent`.
- Quản lý worker bằng map `slot_id -> task/state` thay vì chỉ là list task.
- `WorkerState` giữ `slot_id`, `last_proxy_id`, `current_job_id`, trạng thái ready/waiting/cooldown.
- Khi resize, retire slot lớn nhất sau khi job hiện tại kết thúc; không hủy job đang chạy.

### 4.2 Proxy allocator

Tách chọn proxy khỏi `TwoFAJobManager` thành một thành phần nhỏ, có thể unit test:

```text
allocate(job, worker_state, settings_snapshot) -> ProxyLease
release(lease, outcome)
```

`ProxyLease` gồm `proxy_id`, URL bí mật dùng nội bộ, masked label, worker slot, mode và thời điểm cấp.

- Random: lọc enabled/cooldown/in-use/last-used rồi `choice()` từ candidate list.
- Manual: resolve binding của slot; nếu binding thiếu, disabled hoặc không còn trong pool thì fail-closed với lỗi cấu hình, không chạy DIRECT.
- Dùng một allocation lock/critical section để hai worker không nhận cùng proxy trong cùng thời điểm.
- Cooldown tiếp tục áp dụng theo lỗi kỹ thuật; lỗi tài khoản die hoặc sai credential không được làm proxy cooldown.
- Job lưu `worker_slot`, `proxy_id`, `proxy_label`, `proxy_mode`; URL đầy đủ chỉ tồn tại nội bộ và trong setting Admin.

### 4.3 Trình tự thực thi

```text
worker nhận job
  -> lấy proxy lease theo mode
  -> persist/broadcast worker slot + masked proxy
  -> chạy toàn bộ flow bằng một proxy
  -> persist kết quả
  -> release lease
  -> cập nhật cooldown/last-used
  -> worker nhận tài khoản tiếp theo
```

Nếu worker manual đang cooldown, worker chờ trước khi claim job mới để tránh giữ một job ở trạng thái running chỉ để đợi proxy.

## 5. API và validation

Mở rộng `SettingsRequest` với:

- `proxy_mode`
- `proxy_pool`
- `worker_proxy_bindings`

Validation server-side:

- Mode thuộc enum hợp lệ.
- Pool tối đa 500 proxy, normalize được, không trùng.
- Manual mode + pool không rỗng: mọi slot `1..max_concurrent` có binding hợp lệ và unique.
- Binding chỉ được trỏ đến proxy enabled trong pool.
- Random mode bỏ qua binding ở runtime nhưng vẫn lưu để Admin quay lại manual không mất cấu hình.
- Không nhận URL proxy từ client thường trong request tạo batch; job dùng snapshot setting của Admin.
- Non-admin không được đọc credential, sửa pool/mode/binding hoặc test proxy.
- Lỗi cấu hình trả `422`; xung đột do đang có job hoạt động trả `409`.

## 6. UX Admin

Trong drawer Proxy/Thiết lập:

1. Giữ textarea nhập nhiều proxy và nút `Kiểm tra proxy`.
2. Thêm segmented control:
   - `Ngẫu nhiên theo tài khoản`
   - `Cố định theo luồng`
3. Khi chọn manual, hiện bảng:
   - Luồng
   - Proxy được gán
   - Trạng thái test gần nhất
   - Trạng thái active/inactive
4. Dropdown chỉ hiện label an toàn như `#03 · HTTP · 203.0.113.x:8080`; không render password.
5. Hiển thị validation inline khi thiếu binding, binding trùng, proxy bị xóa hoặc số proxy ít hơn số luồng.
6. Launch confirmation hiển thị `RANDOM · 10 proxy` hoặc `CỐ ĐỊNH · 5/5 luồng đã gán`.
7. Mỗi job row/log header hiển thị `Luồng #2 · Proxy #3 · RANDOM/MANUAL` nhưng không lộ credential.
8. Khi pool rỗng, hiển thị rõ `DIRECT`; không giả vờ random/manual đang hoạt động.

## 7. Kế hoạch implementation theo pha

### Pha 0 — Chốt spec và baseline

- Xác nhận các quyết định ở mục 10.
- Viết spec thay thế bao phủ cả hai mode và liên kết spec random cũ.
- Chạy baseline test với dependency đầy đủ; ghi riêng test pass, fail và test bị block.

### Pha 1 — Settings và migration tương thích

- Thêm enum/mô hình proxy entry/binding.
- Bổ sung whitelist và type validation ở settings repository.
- Thêm adapter từ pool `list[str]` cũ sang catalog có stable ID.
- Validate toàn bộ payload rồi `bulk_set` atomically.
- Thêm redaction cho mọi key mới có thể chứa proxy secret.

### Pha 2 — Refactor stable workers

- Gắn `slot_id` cố định cho worker.
- Resize không giết job đang chạy.
- Persist/broadcast `worker_slot` trong job state.
- Giữ nguyên fair scheduling giữa các user; bổ sung affinity cho manual retry.

### Pha 3 — Proxy allocator và hai mode

- Implement lease, in-use guard, cooldown và last-used.
- Implement random-per-account với no-immediate-repeat khi có lựa chọn.
- Implement manual-per-worker với fail-closed và worker pause.
- Giữ proxy cố định trong toàn bộ một execution.
- Chuẩn hóa log theo mode và lý do fallback/wait.

### Pha 4 — API/UI Admin

- Mở rộng request/response setting.
- Thêm mode selector và mapping grid.
- Thêm validation client-side nhưng luôn coi server là nguồn quyết định.
- Cập nhật summary, launch confirmation, job row và inline log.
- Chặn save proxy configuration khi có job active.

### Pha 5 — Kiểm thử, tài liệu và rollout

- Hoàn thành các test ở mục 8.
- Cập nhật README với semantics của hai mode, DIRECT, cooldown và retry.
- Test nâng cấp từ database có pool cũ.
- Rollout mặc định bảo toàn hành vi cũ; Admin chủ động chọn mode mới trước khi loại bỏ compatibility path.

## 8. Ma trận kiểm thử bắt buộc

### Unit

- Normalize/dedupe/limit proxy pool.
- Stable ID không đổi khi reorder; URL đổi tạo ID mới và làm binding cũ invalid rõ ràng.
- Reject mode sai, binding thiếu/trùng/không thuộc pool.
- Random không chọn proxy active hoặc cooldown.
- Random không lặp proxy vừa dùng nếu còn lựa chọn khác.
- Random dùng lại proxy duy nhất và log rõ ràng.
- Manual: một worker xử lý nhiều job vẫn giữ đúng proxy.
- Manual: proxy lỗi làm đúng worker pause, không đổi sang proxy khác.
- Retry technical error: random loại proxy lỗi; manual giữ worker affinity.
- Account die/invalid credential không làm proxy cooldown.
- Settings validation fail không tạo partial write.

### Async/concurrency

- N worker chạy đồng thời không cấp trùng một proxy.
- Số proxy ít hơn số worker ở random: worker dư chờ, không chạy DIRECT.
- Resize tăng/giảm worker không đổi slot đang chạy và không mất binding inactive.
- Fair scheduler nhiều user không bị regression.
- Cancel/shutdown luôn release lease.

### API/security

- Admin + CSRF hợp lệ mới được save/test proxy.
- Collaborator bị `403` và không nhìn thấy raw proxy credential trong bootstrap/SSE/log.
- Payload invalid trả `422`; thay config lúc đang chạy trả `409`.
- Audit ghi key/actor nhưng redact URL có credential.

### UI/E2E

- Switch random/manual và reload vẫn giữ setting.
- Manual mapping thay đổi đúng theo số luồng.
- Xóa/reorder proxy không âm thầm đổi binding.
- Launch bị chặn khi manual config chưa đủ.
- Summary và job row thể hiện đúng mode/worker/proxy đã che.

### Regression

- `check_only`, `change_2fa`, `change_password`, `change_password_and_2fa` đều giữ một proxy xuyên suốt job.
- Auto retry, cooldown, stop, stop all, recovery sau restart và output không đổi ngoài metadata mới.
- Pool rỗng vẫn chạy DIRECT như trước.

## 9. Acceptance criteria

- **AC1:** Admin nhập/lưu/test được tối đa 500 proxy; credential không xuất hiện trong audit, log hoặc response cho collaborator.
- **AC2:** Random mode chọn proxy mới ở biên giữa hai tài khoản, không đổi proxy giữa các bước của cùng tài khoản.
- **AC3:** Khi có ít nhất hai proxy khả dụng, cùng một worker không dùng lại ngay proxy vừa dùng.
- **AC4:** Manual mode cho phép Admin gán proxy cho từng slot và mỗi slot dùng đúng proxy đó qua nhiều tài khoản.
- **AC5:** Không có hai job đồng thời dùng cùng proxy; thiếu tài nguyên phải wait/error rõ ràng, không fallback DIRECT.
- **AC6:** Proxy kỹ thuật lỗi đi vào cooldown; lỗi account không làm proxy bị phạt.
- **AC7:** Thay cấu hình không thể làm job đang chạy đổi IP và không thể tạo cấu hình ghi dở.
- **AC8:** Upgrade từ pool `list[str]` hiện tại không làm mất proxy hoặc ngăn DIRECT mode.
- **AC9:** Toàn bộ targeted tests và full suite pass; các test tích hợp bị thiếu dependency phải được chạy lại trong môi trường đầy đủ trước release.

## 10. Quyết định cần Admin xác nhận

1. Random chỉ “cố tránh lặp” và được dùng lại proxy duy nhất, hay phải chờ cho đến khi có proxy khác?
2. Manual mode có bắt buộc mỗi worker dùng proxy unique không? Khuyến nghị: có.
3. Auto-retry ở manual mode giữ đúng worker/proxy cũ hay cho phép worker khác nhận? Khuyến nghị: giữ affinity.
4. Khi nâng cấp, có giữ compatibility `round_robin` tạm thời không? Khuyến nghị: có, chỉ để migration; UI mới chỉ trình bày hai mode mục tiêu.

## 11. Bằng chứng baseline hiện tại

- Backend hiện gán proxy tuần tự lúc tạo job rồi kiểm tra lại proxy khả dụng lúc chạy.
- Worker hiện chưa có slot ID ổn định.
- Spec random cũ và test random đã xuất hiện nhưng setting/backend tương ứng chưa hoàn thiện.
- Trong lần khảo sát này, 6 test `RunnerResilienceTests` chạy pass; suite `test_proxy_rotation` bị block khi import `server.py` do runtime thiếu dependency `certifi`. Đây không phải full-suite gate.
