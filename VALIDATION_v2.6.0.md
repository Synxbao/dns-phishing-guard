# Validation v2.6.0

Ngày kiểm tra: 2026-08-10 (Asia/Saigon)

## Lệnh tái lập

```powershell
npm run validate
npm run explain-url -- "https://rexawin.com/"
```

## Release gates

- Manifest/version `2.6.0`: PASS.
- JavaScript source/syntax gates: PASS.
- Model feature order, model integrity và holdout replay: PASS.
- OAuth/SSO, TikTok `/@handle`, localhost/private network, blacklist và URL privacy: PASS.
- Action-token zero-fetch guard, byte cap, redirect handling và download indicators: PASS.
- `SCAM_COMMERCE` positive fixture: PASS (`HIGH`).
- Bounded live probe `naplau.com/nap-lau-roblox/index.html`: HTTP 200, 32.756 byte, `SCAM_COMMERCE HIGH 100/100`, final verdict `HIGH 100/100`.
- Official gift-card hard-negative: PASS (`NONE`).
- Bài viết cảnh báo scam-commerce không có input giao dịch: PASS (`NONE`).
- HTTP 403 preflight: PASS (`SUSPICIOUS`, không greenlight).
- Redirect-loop preflight: PASS; dừng sau khi nhận ra URL lặp, verdict `SUSPICIOUS`, Safe Preview bị khóa.

## Metrics URL ML độc lập

Model runtime không đổi: `url-logistic-5.0.0`.

| Chỉ số | Kết quả |
| --- | ---: |
| TP / TN / FP / FN | 185 / 199 / 1 / 13 |
| Accuracy | 96,48% |
| Precision | 99,46% |
| Recall | 93,43% |
| F1 | 96,35% |
| Specificity | 99,50% |
| False-positive rate | 0,50% |
| False-negative rate | 6,57% |

- Embedded independent test consistency: PASS.
- Holdout replay consistency: PASS.
- Hybrid release regression: 20/20.
- Complex-legit regression: 24 ca, 0 ML false positive, 0 hybrid false positive, 0 on-page warning, 0 context mismatch.
- Runtime benchmark 2.000 predictions: p95 khoảng 0,05 ms trên môi trường kiểm thử hiện tại.

## Kiểm thử `rexawin.com`

Phạm vi: một URL công khai, request chỉ đọc, không cookie/referrer, không đăng nhập, không điền form, không tải tệp và không thực hiện giao dịch.

Quan sát:

- RDAP registration: `2026-04-12T10:38:43Z`, khoảng 119 ngày.
- URL ML: probability `7,52%`, prediction `SAFE` ở ngưỡng `59%`.
- Phishing Risk hybrid: `SUSPICIOUS 20/100`, confidence `32/100`; lý do chính là domain dưới sáu tháng.
- Link Lab: HTTP `403`, `text/plain`, đọc 10 byte; không xác minh được nội dung thực tế.
- Final verdict: `SUSPICIOUS 20/100`, không hiển thị trạng thái xanh.
- Safe Preview: bị khóa vì phản hồi HTTP không thành công.
- Quan sát browser trong cùng đợt QA gặp `net::ERR_TOO_MANY_REDIRECTS`; không thử bypass hoặc mở bề mặt khác để vượt hạn chế.

Kết luận: chưa có đủ bằng chứng để khẳng định `rexawin.com` là phishing/lừa đảo, nhưng cũng không có đủ bằng chứng để gọi nó an toàn. Hành vi đúng của v2.6.0 là yêu cầu người dùng kiểm tra thêm và không nhập dữ liệu/thanh toán.

## Giới hạn

- Holdout cân bằng và regression curated không đại diện trực tiếp cho prevalence production.
- Chưa có pilot người dùng độc lập hoặc temporal holdout mới cho scam-commerce.
- HTTP 403 và redirect loop có thể do cấu hình/anti-bot; chúng là tín hiệu thiếu khả năng xác minh, không phải bằng chứng pháp lý về gian lận.
- Không thực hiện dynamic sandbox ở cấp hệ điều hành.
