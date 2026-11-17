# Validation v2.1.3

Ngày đánh giá lại: 2026-08-10.

## Kết luận

- Release tests: **PASS**.
- Metrics holdout nhúng trong model: **PASS**, phép tính khớp confusion matrix.
- Release regression: **PASS**, hybrid 18/18; URL ML 17/18.
- OAuth/SSO regression: **PASS**, Google OAuth với ML thô 100% vẫn có kết luận hybrid SAFE và network score bằng 0.
- Báo cáo chi tiết được sinh sau bước evaluate tại `evaluation/results/EVALUATION_REPORT.md`.

## Metrics holdout độc lập

Tập test do pipeline huấn luyện ghi nhận có 286 URL: TP 134, TN 127, FP 1, FN 24.

| Metric | Kết quả |
| --- | ---: |
| Accuracy | 91,26% |
| Precision | 99,26% |
| Recall | 84,81% |
| F1 | 91,47% |
| Specificity | 99,22% |
| False Positive Rate | 0,78% |
| False Negative Rate | 15,19% |
| ROC-AUC | 0,9709 |
| Average Precision | 0,9815 |

## Release regression 18 ca

| Bộ đánh giá | TP | TN | FP | FN | Accuracy | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| URL ML | 7 | 10 | 0 | 1 | 94,44% | 93,33% |
| Hybrid Risk Engine | 8 | 10 | 0 | 0 | 100% | 100% |

Bộ này gồm 10 URL safe/OAuth hợp lệ và 8 mẫu phishing rõ ràng. Đây là release gate có chủ đích, không phải ước lượng độc lập về hiệu quả ngoài thực tế.

## Kiểm tra thực hiện

- Manifest JSON và version.
- Model schema, feature order và confusion-matrix integrity.
- JavaScript module imports qua test runtime.
- OAuth/SSO recognition và federated redirect FPT sang Google.
- URL ML inference với model `url-bagged-logistic-3.1.0`.
- Blacklist ưu tiên HIGH.
- Metrics Accuracy, Precision, Recall, F1, Specificity, FPR và FNR.
- Microbenchmark inference p50/p95 trên Node.js.

## Giới hạn còn lại

- Gói runtime không chứa 286 dòng holdout gốc, nên lần chạy này xác minh lại phép tính và metadata nhưng chưa replay từng dự đoán holdout.
- Benign chỉ là benign candidates và có thể còn source bias.
- Chưa có temporal holdout mới hơn thời điểm train.
- Chưa tự động hóa end-to-end trên Chrome/Edge thật cho service worker, DNR, popup, content script và luồng FPT sang Google.
- Quy trình duyệt Chrome Web Store và Microsoft Edge Add-ons có thể thay đổi theo thời điểm.

## Tái lập

```powershell
npm run validate
```

Lệnh trên luôn chạy test và evaluate trước khi tạo lại báo cáo, đúng thứ tự yêu cầu trong note ngày 08/08.
