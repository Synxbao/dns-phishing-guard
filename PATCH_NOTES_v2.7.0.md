# DNS Phishing Guard v2.7.0 - Coverage-Aware Verdict

Ngày phát hành: 2026-08-10

## Mục tiêu

v2.7.0 sửa cách trình bày khi hệ thống chưa đủ dữ liệu. Risk nội bộ bằng 0 không còn được hiển thị như `0/100` nếu chưa xác minh được phạm vi cốt lõi. Bản này đồng thời bổ sung cảnh báo thận trọng cho marketplace tài khoản/dịch vụ game bên thứ ba mà không tự kết luận website là lừa đảo.

## Thay đổi chính

- Thêm `modules/evidence-coverage.js` và object `evidenceAssessment` cho kết quả live/Link Lab.
- Ba mức coverage: `COMPLETE`, `PARTIAL`, `INSUFFICIENT`.
- Ba trạng thái Risk: `DETERMINED`, `PROVISIONAL`, `UNDETERMINED`.
- Khi Risk là `UNDETERMINED`, popup và cảnh báo trên trang dùng `— / CHƯA XÁC ĐỊNH`; Evidence Score vẫn hiển thị riêng.
- Technical UI có thẻ **Phạm vi bằng chứng**: lớp đã kiểm tra, lớp còn thiếu/tùy chọn, tóm tắt và hành động tiếp theo.
- Simple UI có outcome riêng `GIAO DỊCH CẦN XÁC MINH` và trường `Phạm vi`.

## Giao dịch game bên thứ ba

Category `GAME_COMMERCE` yêu cầu tổ hợp mạnh:

- Ít nhất hai nhóm marketplace/dịch vụ như `acc tự chọn`, `mua/bán/thu acc`, `deadmail`, `dropmail`, `cày thuê/rank`, `chuyển vùng`, `check/kho skin`.
- Có ngữ cảnh nạp tiền, thanh toán, chuyển khoản, trả góp, giao dịch hoặc bảo hành.
- Có hành động giao dịch/dịch vụ trên trang.
- Có liên hệ Zalo/Telegram/Discord/mạng xã hội hoặc brand/domain mismatch.
- Official publisher domain được loại trừ; bài viết cảnh báo và tín hiệu yếu không đạt ngưỡng.

`GAME_COMMERCE` bị giới hạn tối đa `70/100` và mang nhãn “cần xác minh”. Nó không phải kết luận pháp lý hoặc kết luận website chắc chắn lừa đảo.

## Sửa Link Lab

- Asset JavaScript/CSS tải bởi `<link>` không còn bị đếm là liên kết tải xuống.
- Chỉ `<a>`/`<area>` trỏ tới executable/archive mới tăng `riskyDownloadLinkCount`.
- Live probe `shopvanmanh.com` giảm từ 183 liên kết tải giả xuống 0.

## Model và metrics

URL ML không retrain trong bản này vì lỗi nằm ở page context và cách trình bày coverage, không phải nhãn URL.

| Chỉ số | Kết quả |
| --- | ---: |
| Accuracy | 96,48% |
| Precision | 99,46% |
| Recall | 93,43% |
| F1 | 96,35% |
| False-positive rate | 0,50% |
| Hybrid regression | 20/20 |
| Complex-legit regression | 24/24 |

## Giới hạn

- Chưa có pilot người dùng độc lập hoặc E2E trên profile Chrome/Edge đã cài unpacked extension.
- Link Lab không chạy JavaScript nên có thể không thấy nội dung được render động; coverage sẽ giải thích giới hạn này.
- Safe Preview vẫn là iframe hạn chế, không phải máy ảo hoặc sandbox hệ điều hành.

## Adversarial QA bổ sung

- Thêm `npm run probe:adversarial`; chạy hoàn toàn offline với `ageInfo giả lập offline` và không dùng domain phishing thật.
- 26 case mới không trùng regression hiện có: 16 expected pass, 3 hybrid compensated, 5 real gap và 2 structural limitation.
- 7/7 benign hard-negative mới giữ trạng thái an toàn, kể cả một URL có ML raw vượt ngưỡng 0,59.
- Các gap được ghi nhận để phát triển tiếp, chưa tuyên bố đã sửa: action-token ngoài convention, từ lóng SCAM/GAME_COMMERCE và response truncated 64 KiB vẫn có thể bị trình bày quá chắc chắn.
