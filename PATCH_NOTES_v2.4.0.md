# DNS Phishing Guard v2.4.0 - Context-Aware False-Positive Reduction

## Sửa lỗi và thay đổi quyết định

- Sửa parsing `@`: chỉ userinfo trong authority mới là tín hiệu che giấu domain; TikTok `/@handle` không bị phạt.
- Thêm `modules/site-context.js` để phân biệt public web, localhost/loopback và mạng riêng.
- Bỏ RDAP, public threat intel và URL ML public cho local/private; ghi rõ “Không áp dụng” trong kết quả.
- Thêm `identityStatus` và `presentation` vào Risk Engine.
- ML lexical đơn lẻ không còn mở cảnh báo on-page; chỉ badge/popup advisory.
- `mlCorroborated` chỉ kích hoạt khi có evidence độc lập hoặc cụm URL-risk, không chỉ vì điểm URL/HTTP yếu.
- Brand URL mismatch chỉ xét hostname và alias domain chính thức.
- Đổi wording từ “ML URL thô · PHISHING” sang “Độ bất thường URL · chỉ báo cấu trúc”.

## Dữ liệu và model

- Nâng feature version `url-lexical-v3` → `url-lexical-v4` (loại feature `containsAtSymbol` trùng semantics với `hasCredentials`).
- Huấn luyện `url-logistic-5.0.0`, 54 features, clamp standardized ±6.
- Làm giàu 800 benign rows bằng path/query counterfactual thực tế; tăng hard negatives lên 479, weight 2.
- Threshold ổn định chọn `0.59` với ưu tiên precision >= 0.965, FPR <= 0.03 và recall >= 0.80 khi có thể.

## Kiểm chứng

- Independent test: FPR 1,50% → 0,50%; Precision 98,40% → 99,46%; Recall 93,43% giữ nguyên.
- TikTok regression: SAFE, không cảnh báo on-page.
- Localhost regression: local context, không public model/RDAP, risk 0 khi không có tín hiệu hành vi.
- Complex-legit suite 24 ca: 0 ML FP, 0 hybrid FP, 0 on-page warning.
