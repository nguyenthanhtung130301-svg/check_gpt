---
title: 'Hai chế độ định tuyến proxy cho kiểm tra tài khoản'
type: 'feature'
created: '2026-09-20'
status: 'in-progress'
route: 'dispatch'
review_loop_iteration: 0
baseline_commit: '1b5123d0921d5adef4c3459d53056e94ca6333ea'
context: []
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Admin cần quản lý nhiều proxy và chọn proxy ngẫu nhiên sau mỗi tài khoản hoặc gán cố định proxy cho từng luồng, trong khi một lần check phải giữ nguyên IP và không làm thay đổi logic đăng nhập/đổi password/2FA hiện có.

**Approach:** Thêm `random_per_account` và `manual_per_worker`, stable worker slot, stable proxy ID và runtime allocator; random chọn proxy khả dụng ở đầu mỗi execution, manual giữ mapping theo slot. Pool rỗng vẫn là DIRECT và cấu hình cũ được đọc tương thích.

## Boundaries & Constraints

**Always:** Một execution dùng đúng một proxy từ đầu đến cuối; không cấp trùng proxy đồng thời; random tránh proxy vừa dùng khi còn lựa chọn nhưng được dùng lại proxy duy nhất; manual yêu cầu binding unique cho mọi slot active, không fallback và retry giữ affinity; lỗi kỹ thuật mới tạo cooldown; cấu hình liên quan được validate rồi ghi atomically; credential chỉ xuất hiện trong setting Admin và nội bộ runtime.

**Never:** Không sửa logic trong `service.py`, `request_phase.py`, `session_phase.py`, `mfa_phase.py`; không fallback DIRECT khi pool có proxy nhưng đang bận/lỗi; không làm SQL migration, deploy hoặc xóa dữ liệu; không lộ proxy credential qua collaborator bootstrap, snapshot, SSE, log hoặc audit.

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Random bình thường | Pool có ít nhất hai proxy rảnh | Worker chọn ngẫu nhiên, tránh proxy vừa dùng và ghim proxy suốt job | Không đổi proxy giữa các bước |
| Random chỉ còn một proxy | Một proxy duy nhất khả dụng | Dùng lại proxy đó và ghi log lý do | Không fail chỉ vì không đổi được IP |
| Manual | N slot có N binding unique | Mỗi slot luôn dùng proxy đã gán | Binding thiếu/trùng trả 422, không chạy DIRECT |
| Proxy kỹ thuật lỗi | Timeout/kết nối lỗi | Proxy cooldown; random retry chọn proxy khác, manual slot chờ | Hết thời gian chờ trả lỗi rõ ràng |
| Pool rỗng | Không cấu hình proxy | Chạy DIRECT như hiện tại | Không yêu cầu binding |
| Đổi cấu hình đang chạy | Proxy/mode/binding/concurrency đổi khi có job active | Giữ cấu hình và job hiện tại | API trả 409, không partial write |

</frozen-after-approval>

## Code Map

- `jobs.py:110-174,323-360,432-595,596-848,982-994` — thêm metadata job, stable worker slot, allocator/lease, retry affinity, release ở mọi terminal path và atomic settings; giữ fair scheduler cùng giới hạn mỗi user.
- `server.py:130-147,199-220,355-371,470-484` — mở rộng settings contract, map validation thành 422/409, giữ admin+CSRF và chỉ trả raw proxy cho Admin.
- `db/repositories.py:80-116,322-396,3238-3266` — whitelist/type validation key mới; tái dùng `bulk_set()` một transaction và redaction.
- `static/index.html:115-120,232-252,270-275` — mode selector, worker mapping và summary/confirmation.
- `static/app.js:192-255,425-438,566-652,1069-1117` — adapter legacy/catalog, mapping UI, payload bảo toàn đủ setting và display an toàn.
- `static/dashboard.css:1515-1577,2759+` — layout selector/mapping và responsive states.
- `tests/test_proxy_rotation.py`, `tests/test_runner_resilience.py` — thay test `proxy_strategy` dang dở và thêm unit/async regression.
- `README.md:35-81` — mô tả hai mode, DIRECT, cooldown và retry.
- `service.py`, `request_phase.py`, `session_phase.py`, `mfa_phase.py` — chỉ là contract regression; không chỉnh implementation.

## Tasks & Acceptance

**Execution:**
- [ ] `tests/test_proxy_rotation.py`, `tests/test_runner_resilience.py` — viết test đỏ cho validation, random no-repeat/reuse, manual mapping/affinity, lease concurrency/release và bốn flow giữ proxy.
- [ ] `jobs.py` — triển khai catalog adapter, stable workers, allocator và atomic update mà không đổi service contract.
- [ ] `db/repositories.py`, `server.py` — thêm key/schema/API, auth/redaction và conflict handling.
- [ ] `static/index.html`, `static/app.js`, `static/dashboard.css` — triển khai UX Admin cho hai mode và masked metadata.
- [ ] `README.md` — cập nhật hướng dẫn/migration semantics.
- [ ] Toàn bộ file đã đổi — chạy targeted/full tests, syntax checks và rà diff bảo mật.

**Acceptance Criteria:**
- Given random mode và hai proxy rảnh, when cùng worker chạy hai tài khoản liên tiếp, then proxy thứ hai khác proxy thứ nhất và mỗi job giữ một proxy xuyên suốt.
- Given random mode chỉ còn một proxy khả dụng, when job bắt đầu, then proxy đó được dùng lại có log giải thích, không DIRECT/error giả.
- Given manual mode hợp lệ, when mỗi worker xử lý nhiều tài khoản hoặc retry, then worker dùng đúng binding và retry giữ slot.
- Given binding thiếu, trùng hoặc không thuộc pool, when Admin lưu, then API trả 422 và không key nào được ghi.
- Given job queued/running, when Admin đổi cấu hình routing, then API trả 409 và job đang chạy không đổi IP.
- Given lỗi account die/credential, when job thất bại, then proxy không cooldown; given lỗi kỹ thuật, then proxy cooldown.
- Given collaborator hoặc event/log/audit output, when proxy có user/password, then không output nào chứa credential.
- Given pool `list[str]` cũ hoặc pool rỗng, when ứng dụng khởi động, then proxy được đọc tương thích hoặc chạy DIRECT mà không migration DB.

## Implementation Notes

## Spec Change Log

## Review Triage Log

## Design Notes

Settings lưu catalog `{id,url,label,enabled}`; client tạo ID cho dòng mới và giữ ID khi URL không đổi, backend normalize/validate và tạo deterministic ID cho legacy string. Worker được quản lý theo `slot_id -> task/state`; allocator dùng critical section và lease explicit, release trong `finally`. Giảm concurrency retire slot sau execution, không hủy job đang chạy.

## Verification

**Commands:**
- `.\.venv\Scripts\python.exe -m unittest discover -s tests -v` — toàn bộ test pass trong runtime có dependency.
- `.\.venv\Scripts\python.exe -m compileall jobs.py server.py db auth tests` — không lỗi syntax/import compile.
- `git diff --check` — không whitespace error.

**Manual checks (nếu môi trường test thiếu dependency):**
- Ghi rõ dependency/runtime blocker; không báo full gate pass. Kiểm tra UI hai mode, mapping reload, masked credential và một job giữ nguyên proxy bằng môi trường đã cài requirements.
