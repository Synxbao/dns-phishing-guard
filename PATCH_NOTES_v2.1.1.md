# DNS Phishing Guard v2.1.1 — Official Portal False-Positive Patch

Bản vá này xử lý ba cảnh báo nhầm được ghi nhận trên Steam, Facebook Group Call và cổng đăng nhập FEID của FPT.

## Nguyên nhân đã sửa

1. **Số lượng script ngoài bị cộng điểm phishing.** Website lớn thường tải nhiều script từ CDN; số lượng script/iframe giờ chỉ là dữ liệu chẩn đoán, không tự cộng điểm.
2. **URL dài, query và OAuth ReturnUrl bị đánh giá quá mạnh.** Heuristic giờ bỏ tracking parameter, chỉ tính percent-encoding trong đường dẫn; encoding trong query OAuth/SSO không tự bị xem là nguy hiểm.
3. **Ô mật khẩu khuếch đại tín hiệu yếu.** Password chỉ cộng thêm điểm khi đã có bằng chứng độc lập mạnh như IP URL, shortener, typosquat, domain mới, HTTPS downgrade hoặc redirect qua nhiều domain.
4. **“Login with Google/Microsoft” bị hiểu là giả mạo thương hiệu.** Nút đăng nhập liên kết/federated identity không còn tạo `brandMismatch`. Mismatch phải xuất hiện nổi bật trong title, heading, logo hoặc lặp lại như danh tính chính của trang.
5. **URL ML thiếu hard-negative thực tế.** Model v3.1 được thêm các URL chính chủ của Steam Store, Facebook Group Call và FEID FPT, đồng thời thêm biến thể phishing bị bỏ sót.

## Kết quả mô phỏng runtime

| Trường hợp | ML probability | Risk mới | Kết quả |
|---|---:|---:|---|
| `store.steampowered.com` + nhiều script CDN | 57.61% | 8/100 | SAFE |
| Facebook Group Call URL dài | 0.01% | 0/100 | SAFE |
| FEID FPT OAuth/SSO URL + password form nội bộ | 0.01% | 8/100 | SAFE |

## Model URL v3.1

- Model: `url-bagged-logistic-3.1.0`
- Threshold: `0.635`
- Test: TP 134, TN 127, FP 1, FN 24
- Precision: 99.26%
- Recall: 84.81%
- F1: 91.47%
- False Positive Rate: 0.78%
- Regression suite: 18/18 đúng

Các số liệu chỉ áp dụng cho dataset hiện tại; không phải cam kết hiệu quả trên toàn Internet.
