# Patch Notes v2.0.0

## Mục tiêu

Giảm false positive trên cổng giáo dục, search URL, SSO, trang tài khoản và URL hợp lệ có path/query phức tạp; đồng thời xây dựng vòng lặp feedback để model cải thiện qua từng lần training.

## Thay đổi

- URL ML v3: 55 features.
- Platt calibration.
- Feedback-weighted training.
- Curated và generated hard negatives.
- Regression suite 15 trường hợp.
- Không coi `.php/.aspx/.jsp/.html` là file tải nguy hiểm.
- Feature education/government và server-page extension.
- ML-only không còn tạo MEDIUM/HIGH.
- Known domain bổ sung Bing và FPT University.
- Thêm `npm run add-feedback` và `npm run evaluate-regression`.

## Kết quả test độc lập

- TP 135, TN 127, FP 1, FN 23.
- Accuracy 91,61%.
- Precision 99,26%.
- Recall 85,44%.
- F1 91,84%.
- False Positive Rate 0,78%.
- ROC-AUC 0,9710.

Đây là trade-off có chủ đích: giảm mạnh cảnh báo nhầm, chấp nhận Recall thấp hơn model v2. Risk Engine hybrid vẫn dùng RDAP, typosquat, threat intelligence, redirect và page behavior để bù cho ML URL.
