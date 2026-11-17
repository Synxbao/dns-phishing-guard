# Báo cáo đánh giá - DNS Phishing Guard v2.7.5

Thời điểm tạo: 2026-08-17T11:27:36.070Z

## Kết quả điều hành

- Model: `url-logistic-5.0.0`, ngưỡng xác suất `0.59`.
- Holdout độc lập: 398 URL; replay từng dự đoán: **PASS**.
- Release regression: 22 ca URL và 2 ca content-safety; độ chính xác hybrid URL **100.00%**, recall nội dung **100.00%**, cặp phân biệt **1/1**.
- Complex regression: 34 ca (33 safe + 1 threat control); FP/FN hybrid **0/0**, cặp phân biệt **1/1**.
- Quyết định: **PASS**.

## Metrics holdout độc lập

Các giá trị dưới đây được tính lại từ confusion matrix và replay trực tiếp trên test split đóng kèm. Domain giữa train/calibration/threshold/test không bị trùng.

| Chỉ số | Giá trị |
| --- | ---: |
| TP / TN / FP / FN | 185 / 199 / 1 / 13 |
| Accuracy (độ chính xác tổng thể) | 96.48% |
| Precision | 99.46% |
| Recall | 93.43% |
| F1 | 96.35% |
| Specificity | 99.50% |
| False-positive rate (FPR) | 0.50% |
| False-negative rate (FNR) | 6.57% |
| ROC-AUC (từ pipeline train) | 0.9911 |
| Average precision (từ pipeline train) | 0.9929 |
| Brier score (từ pipeline train) | 0.0272 |

## Metrics release regression

| Bộ đánh giá | Accuracy | Precision | Recall | F1 | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Chỉ URL ML | 90.91% | 90.00% | 90.00% | 90.00% | 8.33% | 10.00% |
| Hybrid Risk Engine | 100.00% | 100.00% | 100.00% | 100.00% | 0.00% | 0.00% |

Release regression đo riêng khả năng bảo vệ các ca OAuth/safe đã biết và các mẫu phishing rõ ràng; không dùng kết quả này thay cho holdout độc lập.

## Recall content-safety sau lọc quảng cáo

| Case | Danh mục kỳ vọng | Mức tối thiểu | Kết quả | Điểm danh mục | Trạng thái |
| --- | --- | --- | --- | ---: | --- |
| content-gambling-first-party | GAMBLING | HIGH | HIGH | 98 | PASS |
| content-sexual-services-first-party | SEXUAL_SERVICES | HIGH | HIGH | 100 | PASS |

Hai fixture này mô phỏng nội dung nhạy cảm là nội dung chính của trang, vì vậy bộ lọc vùng quảng cáo không được làm giảm recall của `GAMBLING` và `SEXUAL_SERVICES`.

## Stress test legitimate thực tế

| Chỉ số | Giá trị |
| --- | ---: |
| Tổng số ca | 34 |
| Ca SAFE / threat control | 33 / 1 |
| Ca public / local-private | 30 / 4 |
| ML raw false positive (public) | 1 |
| Hybrid false positive | 0 |
| Hybrid false negative | 0 |
| Cảnh báo hiển thị on-page | 0 |
| Chỉ còn advisory badge | 0 |
| Context mismatch | 0 |
| Identity tier mismatch | 0 |
| Payment/evidence mismatch | 0 |
| Content expectation mismatch | 0 |
| Cặp official/impostor đạt | 1 / 1 |

Bộ này chứa cả ca hợp pháp phức tạp và threat control ghép cặp. Nó là regression gate để đồng thời chặn báo nhầm và phát hiện việc official/impostor bị trả cùng verdict; không phải ước lượng prevalence ngoài thực tế.

## Hiệu năng inference

| Chỉ số | Giá trị |
| --- | ---: |
| Môi trường | Node v24.18.0 on win32/x64 |
| Số lượt dự đoán | 2200 |
| Trung bình | 0.028 ms/URL |
| p50 | 0.024 ms/URL |
| p95 | 0.047 ms/URL |
| Lớn nhất | 0.612 ms/URL |

Đây là microbenchmark Node.js trên máy chạy báo cáo, không phải latency end-to-end của extension trong Chrome/Edge.

## Ca phân loại sai

Không có ca hybrid phân loại sai trong bộ release regression tuyển chọn.

## Giới hạn

- URL sạch là benign candidates ghép từ danh sách người dùng và Tranco, không phải chứng nhận an toàn tuyệt đối.
- Một phần benign dùng path/query counterfactual có ghi nhãn rõ để giảm source bias của URL trang chủ; đây không phải quan sát lưu lượng production.
- Mẫu độc hại kết hợp phishing và malware-download nên tỷ lệ nhóm dữ liệu khác lưu lượng duyệt web bình thường.
- Đặc trưng riêng của từng nguồn và temporal drift có thể làm metrics offline cao hơn thực tế; vẫn cần temporal holdout mới.
- Model URL không thay thế brand mismatch, RDAP, threat intelligence, redirect hoặc phân tích hành vi trang.
- Holdout được đóng kèm để replay, nhưng vẫn thuộc cùng đợt thu thập dữ liệu và chưa phải temporal holdout tương lai.
- Bộ release regression được tuyển chọn và cố ý giữ nhỏ; kết quả 100% không được trình bày như độ chính xác production.
- Tích hợp cổng thanh toán quan sát được chỉ là coverage evidence; logo/text có thể bị giả nên không thay đổi Risk score hoặc xác thực merchant.
- Đánh giá Node.js này chưa chạy end-to-end trên Chrome/Edge thật hoặc quy trình review của cửa hàng extension.

## Cách tái lập

Chạy `npm run validate` trong thư mục release. Lệnh sẽ chạy test, tính metrics, rồi mới ghi lại báo cáo này.
