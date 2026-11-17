# Threat Model

## Hai lớp đánh giá độc lập

### Phishing Risk

1. Blacklist/Threat Intelligence xác nhận.
2. URL Logistic Regression chạy cục bộ.
3. RDAP, domain age, PSL, homoglyph và typosquatting.
4. URL heuristics.
5. Redirect behavior.
6. Page behavior và form analysis.

### Content & Cyber Safety

1. Cờ bạc/cá cược và hành động nạp/rút/đặt cược.
2. Nội dung người lớn.
3. Thu thập hoặc chào mua/bán dữ liệu cá nhân.
4. Danh tính giả, giấy tờ giả, tài khoản/SIM/OTP thuê hoặc bán.
5. Crack/keygen/cheat/hack tool kết hợp liên kết tải file.
6. Nội dung quảng bá dịch vụ deepfake/giả giọng/ghép mặt.
7. Cam kết lợi nhuận, đa cấp hoặc tài sản số có dấu hiệu cần xác minh.

## Nguyên tắc quyết định

- Website có thể **không phishing** nhưng vẫn có content warning.
- Content Safety không được cộng trực tiếp vào Phishing Risk Score.
- Một từ khóa đơn lẻ không đủ để tạo cảnh báo cờ bạc hoặc nội dung người lớn.
- Blacklist hoặc Threat Intelligence xác nhận có thể đưa phishing lên HIGH.
- URL ML một mình không tự tạo HIGH.
- Whitelist không vô hiệu hóa page behavior, confirmed threats hoặc content warnings.
- Chỉ báo pháp lý không phải kết luận vi phạm.
- Simple profile không mở on-page panel cho SUSPICIOUS yếu nếu không có blacklist/Threat Intel; trạng thái vẫn hiện trong badge/popup.

## Bảo vệ tương tác cảnh báo

- HIGH và Child Mode coi trang nền là không đáng tin: blur focus, đặt `body.inert`, chặn input/submit capture phase và trap Tab trong extension UI.
- Bypass nguy hiểm yêu cầu typed-domain confirmation; background kiểm tra lại domain và evidence thay vì chỉ tin UI.
- Allow-once chỉ sống tới top-level navigation kế tiếp; tab close luôn dọn DNR/session metadata.

## Link Lab threat boundary

- Preflight không chạy JavaScript, không gửi cookie/referrer và giới hạn redirect/body/time.
- URL có dấu hiệu action token không được probe để tránh tiêu thụ token hoặc kích hoạt GET side effect.
- Literal localhost/private IP bị từ chối, nhưng DNS rebinding sau phân giải vẫn là residual SSRF risk.
- Safe Preview giảm active content bằng iframe sandbox và DNR; không cung cấp isolation tương đương VM/container.

## Có thể phát hiện

- Trang casino/cá cược có nhiều từ khóa và hành động nạp/rút/đăng ký.
- Trang yêu cầu giấy tờ định danh và nhiều dữ liệu nhạy cảm nhưng thiếu chính sách quyền riêng tư.
- Trang quảng bá mua/bán data, tài khoản ngân hàng, SIM/OTP hoặc giấy tờ giả.
- Trang quảng bá crack/keygen và cung cấp tệp thực thi.
- Trang quảng bá dịch vụ deepfake hoặc cam kết lợi nhuận.

## Không thể xác định chắc chắn

- Website cờ bạc có giấy phép hợp lệ hay không.
- Nội dung tài chính có vi phạm pháp luật hay chỉ là bài báo/trích dẫn.
- File tải xuống có thực sự chứa malware nếu chưa phân tích nhị phân.
- Video/ảnh/âm thanh có phải deepfake nếu chỉ nhìn nội dung văn bản.
- Mục đích thực tế khi website thu thập dữ liệu cá nhân.
- Nội dung được render trong canvas, video, ảnh hoặc iframe bị chặn quyền truy cập.
