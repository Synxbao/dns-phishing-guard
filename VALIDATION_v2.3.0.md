# Validation v2.3.0

Ngày đánh giá: 2026-08-10.

## Release tests

- Manifest version `2.3.0`: PASS.
- Dataset/model integrity 2.000 benign + 2.000 malicious: PASS.
- URL ML/OAuth/Steam/Hợp Âm Chuẩn/blacklist regressions: PASS.
- Link Lab protocol guard và credential/private-address rejection: PASS.
- HTML signal parser và direct-download classification: PASS.
- Direct-download verdict override SAFE → HIGH: PASS.
- Mock network probe: redirect 1 hop, `credentials: omit`, `no-referrer`, password-form detection và 64 KiB truncation: PASS.

## Metrics model giữ nguyên

398 URL holdout, replay 398/398: TP 185, TN 197, FP 3, FN 13.

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

## Visual QA

- Popup desktop 468 x 720: PASS.
- Popup narrow 366 px và 316 px: PASS.
- Cảnh báo nổi desktop/mobile: PASS; đã sửa lỗi telemetry bar xuống dòng.
- Trang blacklist desktop/mobile: PASS.
- Link Lab desktop/mobile và khu vực Safe Preview: PASS.

## Runtime benchmark

- Node v24.18.0, Windows x64.
- 2.000 predictions.
- Mean 0,030 ms; p50 0,025 ms; p95 0,051 ms; max 1,431 ms.

## Giới hạn đã xác nhận

- Link Lab thực hiện một GET có `Range`, không cookie/referrer; server vẫn thấy kết nối/IP.
- Chỉ đọc 64 KiB đầu và không thực thi JavaScript, do đó không thể khẳng định hành vi runtime đầy đủ.
- DNS rebinding của hostname công khai về IP nội bộ không thể được loại trừ hoàn toàn chỉ bằng URL parser.
- Iframe Safe Preview có thể bị X-Frame-Options/CSP từ chối.
- DNR theo tab và iframe sandbox giảm active content nhưng không thay thế VM hoặc browser profile dùng một lần.
