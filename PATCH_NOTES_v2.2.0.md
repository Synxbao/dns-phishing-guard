# DNS Phishing Guard v2.2.0 - Training 4K & Steam Brand-Lookalike

## Thay đổi chính

- Retrain URL ML v4.1 trên 2.000 benign candidates và 2.000 URL phishing/malware.
- Đóng kèm dataset, split, training script, test predictions và báo cáo để tái lập metrics.
- Bổ sung 250 hard negatives sạch có OAuth/path/query phức tạp chỉ trong train.
- Phát hiện brand-suffix mismatch như `steamcommunity.com` bị giả thành `steamcommunity.asia`.
- Bổ sung Steam vào phân tích brand identity trên trang đăng nhập.

## Kết quả

- Independent test: Accuracy 95,98%, Precision 98,40%, Recall 93,43%, F1 95,85%.
- FPR 1,50%, FNR 6,57%, ROC-AUC 0,9829.
- Hybrid release regression: 19/19.

## Lưu ý an toàn

Dataset chứa URL độc hại phục vụ phòng thủ. Không truy cập trực tiếp các URL này. Feed có thể hết hiệu lực hoặc thay đổi trạng thái theo thời gian.
