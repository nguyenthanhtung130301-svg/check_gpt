---
title: 'Thêm chiến lược chọn proxy ngẫu nhiên'
type: 'feature'
created: '2026-09-20'
status: 'in-progress'
route: 'oneshot'
review_loop_iteration: 0
context: []
---

<frozen-after-approval reason="human-owned intent — do not modify unless human renegotiates">

## Intent

**Problem:** Proxy pool hiện chỉ phân bổ tuần tự; người dùng cần tùy chọn phân bổ ngẫu nhiên cho các job đồng thời mà không làm thay đổi hành vi mặc định, retry/cooldown, nhập proxy thủ công hoặc logic `check_only`.

**Approach:** Thêm setting `round_robin|random`, giữ `round_robin` mặc định và nguyên nhánh chọn hiện tại; với `random`, chọn trong tập proxy không bận/không cooldown khi job bắt đầu rồi ghim proxy đó xuyên suốt toàn bộ job. Cập nhật API, hai đường lưu settings trên UI, nhãn hiển thị và test hồi quy riêng cho `check_only`.

</frozen-after-approval>

## Implementation Notes

