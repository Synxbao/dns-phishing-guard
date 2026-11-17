# Validation v2.7.1

Ngày kiểm tra: 2026-08-10

## Lệnh tái lập

```powershell
npm run validate
```

`validate` chạy tuần tự release test, đánh giá model/hybrid và adversarial probe offline.

## Kết quả release gate

- Manifest/version `2.7.1`: PASS.
- Content script nạp `modules/page-signal-filter.js` trước `content.js`: PASS.
- Content Safety HIGH dùng chung strict category set, overlay khóa nền và ẩn nút đóng: PASS.
- Content HIGH yêu cầu typed-domain confirmation trước khi cho phép tạm: PASS.
- Label Simple UI tiếng Việt cho URL structure, external reputation source và preview content: PASS.
- Dataset/model integrity: 4.000 URL, 2.000 benign candidates, 2.000 malicious, 54 feature: PASS.
- Holdout replay khớp metadata model: PASS.

## Regression quảng cáo nhúng

Fixture offline gồm nội dung đọc truyện hợp pháp và banner quảng cáo DOM trực tiếp:

- Trước lọc: tổ hợp text/contact/profile từ banner tạo `SEXUAL_SERVICES`, level `HIGH`.
- Sau lọc: main content được giữ, ad text/contact/profile bị loại khỏi content-semantic scan và không còn category false positive.
- Marker được kiểm tra: `ads`, `sponsor`, `banner-ad`, `quang-cao`.
- Ad-unit `300x250` không marker nhưng có creative/tài nguyên bên thứ ba được nhận diện.
- Negative guard: class `address-card` không bị coi là quảng cáo.

## Recall content-safety

`evaluation/release-regression-cases.json` có hai positive first-party mới:

| Case | Danh mục | Kỳ vọng | Kết quả |
| --- | --- | --- | --- |
| `content-gambling-first-party` | `GAMBLING` | HIGH | PASS |
| `content-sexual-services-first-party` | `SEXUAL_SERVICES` | HIGH | PASS |

Content-safety recall gate: **2/2, 100%**.

## Metrics giữ nguyên

URL ML không retrain trong v2.7.1.

| Chỉ số | Kết quả |
| --- | ---: |
| Independent test | 398 URL |
| Accuracy | 96,48% |
| Precision | 99,46% |
| Recall | 93,43% |
| F1 | 96,35% |
| False-positive rate | 0,50% |
| Hybrid URL regression | 20/20 |
| Complex-legit regression | 24/24 |
| Content-safety regression | 2/2 |

## Adversarial probe

- Tổng case: 26; executable: 24; structural: 2.
- Network request thật: 0.
- Benign hard-negative expected pass: 7/7.
- Expected pass: 16; hybrid compensated: 3; real gap: 5; structural limitation: 2.
- Năm gap cũ về action-token, từ lóng thương mại và giới hạn Link Lab 64 KiB vẫn được giữ minh bạch; bản vá này không tuyên bố xử lý các gap đó.

## Giới hạn kỹ thuật

- Heuristic quảng cáo không thể phân biệt hoàn hảo native ad được ngụy trang như nội dung first-party.
- Shadow DOM đóng, canvas hoặc markup không marker/kích thước đặc trưng có thể không bị loại.
- Khối hợp lệ dùng marker quảng cáo hoặc kích thước ad-unit chuẩn kèm tài nguyên bên thứ ba có thể bị loại nhầm khỏi content-semantic scan.
- External form/script/iframe và risky download không bị bộ lọc bỏ qua; đây là trade-off cố ý để không che hành vi nguy hiểm của quảng cáo/widget.
- Chưa thay thế E2E usability test trên Chrome/Edge thật với người dùng độc lập.
