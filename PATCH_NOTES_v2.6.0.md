# DNS Phishing Guard v2.6.0 - Evidence-Aware Protection

Ngày phát hành: 2026-08-10

## Mục tiêu

v2.6.0 xử lý lỗi nghiêm trọng khi một website có giao dịch mã thẻ/nạp game ngoài kênh chính thức vẫn nhận banner xanh vì URL ngắn, domain lâu năm và không có form mật khẩu. Bản này giữ riêng metrics phishing URL, nhưng bổ sung verdict bảo vệ người dùng ở cấp nội dung và phản hồi mạng.

## Thay đổi chính

- Thêm category `SCAM_COMMERCE` cho mã thẻ, số seri, PIN, voucher, gift card, game currency, nạp game và khuyến mãi khó kiểm chứng.
- Thêm Roblox/Robux và Riot Games vào brand rules; brand commerce mismatch chỉ được kích hoạt khi có hành động hoặc input giao dịch đủ mạnh.
- Không còn hiển thị dấu kiểm xanh cho `SAFE` khi content scan chưa hoàn tất hoặc identity context chưa được nhận diện; thay bằng `CHƯA ĐỦ DỮ LIỆU`.
- Link Lab phân tích HTML tĩnh sau khi loại script/style, không chạy mã website và chỉ đọc tối đa 64 KiB.
- HTTP 403/không thành công và lỗi mạng được coi là chưa xác minh, không phải bằng chứng an toàn.
- Phát hiện vòng lặp/vượt giới hạn redirect, nâng ít nhất `SUSPICIOUS` và khóa Safe Preview.
- Thêm bộ đếm `Giao dịch cần xác minh` trong khu vực thống kê.

## Chống báo nhầm

- Không cảnh báo chỉ vì trang nhắc Roblox, gift card hoặc nạp game.
- Một bài viết cảnh báo về “nạp lậu” có form tìm kiếm/liên kết chính thức nhưng không có input giao dịch nhạy cảm vẫn phải qua hard-negative.
- Trang gift-card chính thức có một ô redeem và không có dấu hiệu ngoài kênh/khuyến mãi bất thường vẫn không bị gắn `SCAM_COMMERCE`.

## Ca hồi quy trọng điểm

- Bounded live probe và fixture tương ứng `naplau.com/nap-lau-roblox/index.html`: HTTP 200, `SCAM_COMMERCE HIGH`, Link Lab verdict `HIGH 100/100`.
- URL ML của cùng kiểu URL có thể vẫn dự đoán `SAFE`; verdict cuối không còn phụ thuộc riêng vào cấu trúc URL.
- `rexawin.com`: URL ML `SAFE` 7,52%, nhưng domain mới khoảng 119 ngày và HTTP 403 khiến verdict cuối là `SUSPICIOUS 20/100`, confidence `32/100`; extension không tuyên bố website an toàn và khóa Safe Preview.

## Giới hạn còn lại

- Không kết luận website vi phạm pháp luật hoặc chắc chắn lừa đảo chỉ từ keyword/HTTP status.
- Link Lab không chạy JavaScript, không đăng nhập, không gửi cookie và không quan sát hành vi sau tương tác.
- Safe Preview là iframe hạn chế, không phải máy ảo hay sandbox hệ điều hành.
- URL ML v5 không được retrain trong bản này; metrics URL giữ nguyên.
