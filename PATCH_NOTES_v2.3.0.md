# DNS Phishing Guard v2.3.0 - Signal Observatory & Link Lab

## Giao diện

- Popup mới ưu tiên Risk, Confidence và các thông số có thể đọc nhanh.
- Tách rõ ML URL thô với điểm ML thực sự được hybrid engine áp dụng.
- Bổ sung telemetry tuổi domain, redirect, RDAP, threat intelligence và phân rã tín hiệu.
- Cảnh báo nổi và trang blacklist dùng cùng hệ màu, typography và motion.
- Responsive đã được kiểm tra ở popup 468 px, chiều ngang 366/316 px và trang desktop/mobile.

## Link Lab

- Người dùng có thể dán một URL và kiểm tra trước khi mở.
- Probe không chạy script, không gửi cookie/referrer và chỉ đọc tối đa 64 KiB trong 8 giây.
- Tối đa 5 redirect, một URL mỗi thao tác; không tự mở rộng sang danh sách mục tiêu.
- Từ chối `javascript:`, `data:`, credential nhúng, localhost, IP nội bộ và địa chỉ dành riêng.
- Nhận diện header tải tệp, MIME/archive/executable, link tải rủi ro, form mật khẩu, iframe và auto-navigation.
- Verdict tổng hợp nâng lên HIGH khi phản hồi là attachment/executable dù lớp phishing riêng vẫn SAFE.
- Safe Preview khóa script, form, popup, download và phần lớn active resource bằng DNR theo tab.

## Giới hạn an toàn

- Probe và Safe Preview vẫn kết nối tới website nên địa chỉ IP có thể bị ghi nhận.
- Safe Preview không phải máy ảo hoặc sandbox hệ điều hành.
- Website có thể từ chối iframe qua X-Frame-Options/CSP.
- Quét giới hạn không quan sát được hành vi chỉ xuất hiện sau tương tác, đăng nhập hoặc tải động theo điều kiện.
- Kết quả SAFE chỉ có nghĩa chưa phát hiện bằng chứng rõ ràng trong phạm vi quét.

## Model

- Không retrain model ở bản UI/Link Lab này.
- Model runtime: `url-logistic-4.2.0`.
- Holdout giữ nguyên: Accuracy 95,98%, Precision 98,40%, Recall 93,43%, F1 95,85%, FPR 1,50%.
