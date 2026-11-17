# Validation v2.2.1

Ngày đánh giá: 2026-08-10.

## False positive được sửa

URL kiểm tra:

`https://hopamchuan.com/song/57692/muon-em-la-cua-rieng-minh/?s=1`

- Domain hoạt động HTTP 200 và được đăng ký từ 2013-05-08.
- Model v4.1 trước sửa: khoảng 93,6%, PHISHING.
- Model v4.2 sau sửa: khoảng 6,1%, SAFE.
- Hybrid: SAFE, không có bằng chứng phishing độc lập.
- Giao diện reputation cap không còn giữ câu “rất giống mẫu phishing”.

Nguyên nhân gốc là tập benign thiên về homepage, khiến `pathTokenCount=8` và `pathDepth=3` bị model xem quá mạnh. Bản sửa bổ sung URL nội dung hợp lệ làm hard negative và kiểm tra contribution trước/sau.

## Independent holdout

398 URL, replay 398/398: TP 185, TN 197, FP 3, FN 13.

| Metric | Kết quả |
| --- | ---: |
| Accuracy | 95,98% |
| Precision | 98,40% |
| Recall | 93,43% |
| F1 | 95,85% |
| Specificity | 98,50% |
| FPR | 1,50% |
| FNR | 6,57% |
| ROC-AUC | 0,9824 |
| Average Precision | 0,9877 |

## Regression

- URL ML: 19/20, không false positive; false negative còn lại là Punycode được lớp homoglyph bắt.
- Hybrid Risk Engine: 20/20.
- OAuth/SSO hợp lệ: PASS.
- Steam brand-suffix lookalike: PASS.
- Hợp Âm Chuẩn content URL: PASS.
- Câu chữ reputation cap: PASS.

## Model và công cụ

- Model: `data/url-model.json` (`url-logistic-4.2.0`).
- Inference: `modules/url-model.js`.
- Feature extraction: `modules/url-ml-features.js`.
- Contribution analysis: `training/explain-prediction.mjs`.

## Giới hạn

- Benign vẫn là candidates và còn source bias.
- Holdout chưa phải temporal holdout tương lai.
- Một URL hợp lệ được thêm vào hard-negative không chứng minh toàn bộ domain luôn an toàn.
- Reputation cap chỉ giảm tín hiệu ML yếu; blacklist, threat intelligence, homoglyph, external password form và hành vi nguy hiểm vẫn có ưu tiên cao.
