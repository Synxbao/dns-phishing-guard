# Báo cáo hậu kiểm DNS Phishing Guard v2.6.0

Ngày đánh giá: 2026-08-10 (Asia/Saigon)

## Kết luận điều hành

v2.6.0 sửa đúng hai lỗi P0 của v2.5.0:

1. Website giao dịch mã thẻ/nạp game không còn lọt qua chỉ vì URL ML dự đoán `SAFE`.
2. Kết quả thiếu content scan hoặc identity context không còn dùng dấu kiểm xanh gây hiểu nhầm.

Ca `naplau.com` được chuyển sang `SCAM_COMMERCE HIGH 100/100` trong bounded live probe và static regression. Hai hard-negative đại diện cho gift-card chính thức và bài viết cảnh báo đều không bị gắn nhầm. Với `rexawin.com`, extension không thể đọc nội dung do HTTP 403 và browser redirect loop, nên trả `SUSPICIOUS` thay vì khẳng định an toàn.

Phán quyết nội bộ: **PASS cho release candidate/beta**, chưa coi là chứng nhận đạt 9/10 production vì chưa có pilot người dùng độc lập và dynamic sandbox thực sự.

## Ma trận kết quả

| Ca kiểm thử | URL ML | Bằng chứng khác | Verdict v2.6.0 |
| --- | --- | --- | --- |
| Nạp lậu Robux + mã thẻ/seri + khuyến mãi | Có thể `SAFE` | Input giao dịch, keyword ngoài kênh, brand mismatch | `HIGH` |
| Gift-card/redeem chính thức | Có thể `SAFE` | Không có unofficial/promo cluster | Không cảnh báo nội dung |
| Bài viết cảnh báo nạp lậu | Không quan trọng | Không có input giao dịch nhạy cảm | Không cảnh báo nội dung |
| `rexawin.com` | `SAFE` 7,52% | Domain mới, HTTP 403; browser redirect loop | `SUSPICIOUS 20/100` |

## Đánh giá theo vai trò

### Người kiểm thử phần mềm

Điểm mạnh:

- Có positive/negative fixture cho scam-commerce thay vì chỉ source marker.
- Redirect loop dừng sớm và có verdict riêng.
- URL ML metrics được giữ tách biệt, không dùng page-level fix để thổi phồng accuracy.
- `npm run validate` tái lập đầy đủ model integrity, regression và benchmark.

Khoảng trống:

- Corpus page-level vẫn nhỏ; cần thêm fake shop, support scam, investment và marketplace.
- Chưa có E2E tự động trong Chrome/Edge profile đã cài unpacked extension.

### Người dùng phổ thông

Điểm mạnh:

- `CHƯA ĐỦ DỮ LIỆU` diễn đạt trung thực hơn dấu kiểm xanh.
- Cảnh báo giao dịch nói thẳng không gửi mã thẻ, số seri, PIN/voucher hoặc thanh toán trước khi xác minh.
- `rexawin.com` không được greenlight khi Link Lab chỉ nhận HTTP 403.

Khoảng trống:

- Người dùng vẫn cần hiểu `SUSPICIOUS` không đồng nghĩa website chắc chắn lừa đảo.
- Safe Preview không thay thế máy ảo và có thể làm lộ IP tới website.

### Người truy cập nhiều website

Điểm mạnh:

- Hard-negative giữ mức phiền thấp cho nội dung hợp pháp.
- ML-only không tự tạo MEDIUM/HIGH; bằng chứng nội dung/mạng được trình bày riêng.
- Có lịch sử, thống kê, debug export và Link Lab trước khi mở link.

Khoảng trống:

- Threat Intelligence mặc định tắt nên một số domain mới chưa có nội dung đọc được chỉ dừng ở `SUSPICIOUS`.
- Cần pilot theo base rate thật để đo tỷ lệ cảnh báo nhầm và bỏ sót theo từng nhóm hành vi.

## Kiểm thử `rexawin.com`

Phạm vi kiểm thử được giới hạn ở một URL, không đăng nhập, không gửi form, không tải tệp và không giao dịch.

- RDAP cho thấy domain đăng ký ngày 2026-04-12, khoảng 119 ngày.
- URL ML chỉ nhìn cấu trúc URL và dự đoán `SAFE` 7,52%; kết quả này không được dùng như chứng nhận.
- Risk Engine nâng lên `SUSPICIOUS 20/100` vì domain dưới sáu tháng.
- Probe tĩnh nhận HTTP 403 và chỉ đọc được `Forbidden`, vì vậy không có cơ sở phân tích nội dung.
- Browser quan sát được vòng lặp chuyển hướng; không thử bypass.
- Safe Preview bị khóa vì phản hồi HTTP không thành công.

Kết luận đúng: **không xác minh được độ an toàn của website**. Người dùng không nên đăng nhập, nhập OTP/mã thẻ hoặc thanh toán cho tới khi kiểm tra được kênh chính thức và danh tính đơn vị vận hành.

## Việc cần làm tiếp để đạt 9/10 production

1. Xây corpus page-level tối thiểu 100 positive và 200 hard-negative, tách registrable domain và thời gian.
2. Thêm Chrome/Edge E2E cho banner, mutation rescan, focus/inert, Link Lab và DNR lifecycle.
3. Pilot 2-4 tuần với telemetry cục bộ/opt-in để đo false negative, false positive và tỷ lệ bỏ qua.
4. Tích hợp reputation/threat feeds có bảo vệ quyền riêng tư và cơ chế timeout/fallback rõ ràng.
5. Nếu cần xem hành vi động thật, dùng dịch vụ sandbox cô lập chuyên dụng thay vì iframe Safe Preview.
