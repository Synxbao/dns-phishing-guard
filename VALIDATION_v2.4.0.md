# Validation v2.4.0

Ngày đánh giá: 2026-08-10 (Asia/Saigon)

## Lệnh kiểm tra

```powershell
npm run pipeline-training
npm run validate
```

## Model và dữ liệu

- Model: `url-logistic-5.0.0`.
- Feature version: `url-lexical-v4`, 54 features, standardized clamp ±6.
- Dataset: 4.000 URL (2.000 benign candidates, 1.257 phishing, 743 malware-download).
- Benign counterfactual: 800; hard negative chỉ-train: 479 x weight 2.
- Split: train 2.785, calibration 398, threshold 419, independent test 398.
- Domain leakage: không.
- Threshold: 0,59; Platt slope 1,0116712, intercept 0,0684239.

## Independent holdout

| Chỉ số | Giá trị |
| --- | ---: |
| TP / TN / FP / FN | 185 / 199 / 1 / 13 |
| Accuracy | 96,48% |
| Precision | 99,46% |
| Recall | 93,43% |
| F1 | 96,35% |
| Specificity | 99,50% |
| FPR / FNR | 0,50% / 6,57% |
| ROC-AUC | 0,9911 |
| Average Precision | 0,9929 |
| Brier score | 0,0272 |

Replay split đóng gói khớp confusion matrix: PASS.

## Regression

- Release hybrid: 20/20, 0 FP, 0 FN.
- Release ML-only: 19/20; Punycode là FN của lexical model nhưng lớp Punycode/homoglyph độc lập bắt được và hybrid kết luận HIGH/PHISHING.
- Complex legitimate: 24 ca, gồm TikTok/YouTube `@handle`, social/product/article/OAuth/server-page extension và local/private network.
- Complex legitimate: 0 raw-ML FP, 0 hybrid FP, 0 on-page warning, 0 context mismatch.

## Hai ca báo nhầm ban đầu

- `https://www.tiktok.com/@brainrotdepot1?...`: khoảng 99,9996% ở v2.3.1 → khoảng 0,0081% ở v2.4.0; `SAFE`.
- `http://localhost:20128/dashboard/combos`: v2.3.1 chấm public-model khoảng 94,6%; v2.4.0 phân loại `LOCAL_DEVELOPMENT`, không chạy public URL ML/RDAP và risk 0/100 khi không có hành vi nguy hiểm khác.

## Giới hạn còn lại

- Dữ liệu benign vẫn là candidates, không phải chứng nhận an toàn từng URL.
- 800 path/query counterfactual cải thiện coverage nhưng không phải telemetry production.
- Holdout chưa phải temporal holdout tương lai.
- Link Lab chỉ đọc tối đa 64 KiB và không chạy JavaScript; hành vi sau tương tác có thể chưa quan sát được.
- Chưa chạy quy trình review thực tế của Chrome Web Store/Edge Add-ons.
