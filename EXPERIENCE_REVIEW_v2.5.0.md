# Experience Review v2.5.0

> **Đã bị thay thế:** Các điểm số bên dưới là ước tính trước hậu kiểm. Ca thực tế
> `naplau.com/nap-lau-roblox/index.html` đã tái hiện một false negative nghiêm trọng
> với banner xanh `0/100`. Xem kết luận mới tại
> `EXPERIENCE_REPORT_v2.5.0_POST_QA.md`.

Đây là internal QA sau triển khai, dùng cùng ba vai trò của review v2.4.0. Điểm số là đánh giá kỹ thuật/trải nghiệm nội bộ, không phải khảo sát người dùng độc lập.

| Vai trò | v2.4.0 | v2.5.0 ước tính | Lý do chính |
| --- | ---: | ---: | --- |
| Người test phần mềm | 8,1 | 9,2 | Có regression cho P0 safety/privacy/token guard, telemetry mới, tài liệu residual risk và artifact validation. |
| Người dùng phổ thông | 7,8 | 9,1 | Simple UI mặc định, ba outcome, ít thuật ngữ, domain/context rõ, hành động chính nổi bật, Link Lab rút gọn. |
| Người truy cập nhiều web | 8,0 | 9,0 | SUSPICIOUS yếu không làm phiền on-page ở Simple profile, quét idle/hidden-aware, scan p95, feedback báo nhầm và chuyển Technical nhanh. |

## Điểm đã xử lý

- Focus leak/typing behind modal: đã khóa bằng inert + capture guard + focus trap.
- Bypass quá dễ: typed-domain confirmation và allow-once consume.
- Hai edition gây phân mảnh: hợp nhất profile trong một package.
- URL/token privacy: session storage, history/threat-intel redaction.
- Link Lab có thể tiêu thụ magic/reset link: classifier bỏ probe và khóa preview.
- Thiếu số liệu vận hành: warnings/blocks/bypasses/false positive/scan average/p95.
- Mobile header overflow: phát hiện trong Browser QA và sửa tại breakpoint 320 px.

## Điều kiện để xác nhận điểm production

- Pilot 2–4 tuần với người dùng thật, đo tỷ lệ cảnh báo bị bỏ qua và phản hồi báo nhầm.
- Temporal URL evaluation mới, không chỉ offline split hiện tại.
- E2E trong Chrome/Edge đã cài unpacked extension cho inert/focus/DNR lifecycle.
- Store review, privacy disclosure và kiểm tra CSP/X-Frame-Options trên nhiều website.
