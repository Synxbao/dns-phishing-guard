# Báo cáo huấn luyện URL ML v5

- Dataset: **4000 URL** (2000 sạch, 2000 độc hại).
- Model: `url-logistic-5.0.0`, 54 features, Platt calibration.
- Split theo registrable domain: train 2785, calibration 398, chọn ngưỡng 419, test độc lập 398.
- Hard negatives chỉ train: 479; tổng train sau tăng cường: 3743.
- Benign counterfactual nằm trong split theo domain: 800.
- Standardized feature clamp: ±6.
- Domain leakage: **không**.

## Independent test

- TP 185, TN 199, FP 1, FN 13.
- Accuracy 96.48%.
- Precision 99.46%.
- Recall 93.43%.
- F1 96.35%.
- FPR 0.50%; FNR 6.57%.
- ROC-AUC 0.9911; Average Precision 0.9929.

## Giới hạn

- URL sạch là benign candidates ghép từ danh sách người dùng và Tranco, không phải chứng nhận an toàn tuyệt đối.
- Một phần benign dùng path/query counterfactual có ghi nhãn rõ để giảm source bias của URL trang chủ; đây không phải quan sát lưu lượng production.
- Mẫu độc hại kết hợp phishing và malware-download nên tỷ lệ nhóm dữ liệu khác lưu lượng duyệt web bình thường.
- Đặc trưng riêng của từng nguồn và temporal drift có thể làm metrics offline cao hơn thực tế; vẫn cần temporal holdout mới.
- Model URL không thay thế brand mismatch, RDAP, threat intelligence, redirect hoặc phân tích hành vi trang.
