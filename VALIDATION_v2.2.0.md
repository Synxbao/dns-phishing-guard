# Validation v2.2.0

Ngày đánh giá: 2026-08-10.

## Kết luận

- Dataset gốc: **PASS**, đúng 2.000 benign candidates và 2.000 URL độc hại.
- URL duy nhất: **PASS**, 4.000/4.000.
- Domain leakage giữa train/calibration/threshold/test: **không**.
- Holdout replay: **PASS**, tái lập đủ 398 dự đoán từ model đóng gói.
- Release regression hybrid: **PASS**, 19/19.
- Ca `steamcommunity.asia`: **PASS**, nhận diện brand-suffix mismatch và kết luận HIGH/PHISHING.

## Nguồn dữ liệu

| Nguồn | Số mẫu |
| --- | ---: |
| Danh sách benign của người dùng | 1.000 |
| Tranco benign candidates | 1.000 |
| Danh sách phishing của người dùng | 987 |
| OpenPhish ngày 2026-08-10 | 270 |
| URLhaus malware-download ngày 2026-08-10 | 743 |

13 URL trong danh sách phishing gốc bị loại vì không hợp lệ, trùng lặp hoặc xung đột domain với tập benign. Phần thiếu được bù bằng feed công khai có ngày và SHA-256 trong `training/data/dataset-4000.json`.

Ngoài 4.000 mẫu gốc, 250 hard negatives sạch có path/query/OAuth phức tạp chỉ được dùng trong train với trọng số 3. Chúng không xuất hiện trong holdout.

## Independent test

Test split có 398 URL: TP 185, TN 197, FP 3, FN 13.

| Metric | Kết quả |
| --- | ---: |
| Accuracy | 95,98% |
| Precision | 98,40% |
| Recall | 93,43% |
| F1 | 95,85% |
| Specificity | 98,50% |
| FPR | 1,50% |
| FNR | 6,57% |
| ROC-AUC | 0,9829 |
| Average Precision | 0,9880 |

## Release regression

| Bộ đánh giá | TP | TN | FP | FN | Accuracy |
| --- | ---: | ---: | ---: | ---: | ---: |
| URL ML v4.1 | 8 | 10 | 0 | 1 | 94,74% |
| Hybrid Risk Engine | 9 | 10 | 0 | 0 | 100% |

False negative còn lại của URL ML là mẫu Punycode; lớp homoglyph/Punycode độc lập bắt được nên hybrid vẫn PHISHING/HIGH.

## Cải tiến `steamcommunity.asia`

- Thêm `steamcommunity.com` vào known domains.
- Nhận diện tên thương hiệu được bảo vệ giữ nguyên nhưng đổi suffix domain.
- Thêm Steam vào brand identity của content script.
- Kết hợp brand-suffix mismatch, ML và password/brand mismatch thành cảnh báo HIGH.
- Giới hạn cơ chế suffix protection vào các brand một-suffix đã chọn để tránh báo nhầm domain vùng như `microsoft.co.uk`.

## Giới hạn

- Benign là candidates, không phải chứng nhận an toàn tuyệt đối.
- Feed phishing/malware và Tranco có source bias.
- Holdout cùng đợt thu thập, chưa phải temporal holdout tương lai.
- Chưa chạy end-to-end trên trình duyệt thật với chính URL trong ảnh; tuyệt đối không mở URL độc hại ngoài môi trường cách ly.

## Tái lập

```powershell
npm run pipeline-training
npm run validate
```
