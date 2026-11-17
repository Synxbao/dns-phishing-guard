# Validation v2.3.1

Ngày đánh giá: 2026-08-10.

## Popup width regression

- Tái hiện bản cũ trong viewport 39 px: document tự co còn 39 px.
- Bản vá trong viewport khởi tạo 39 px: document có mức sàn 320 px.
- Kiểm tra trực quan ở 320 px: PASS.
- Kiểm tra sizing ở 420 px và 468 px: PASS.
- Release test từ chối tái xuất hiện `width: 100vw`: PASS.

## Release tests

- Manifest version `2.3.1`: PASS.
- Dataset/model integrity 2.000 benign + 2.000 malicious: PASS.
- Link Lab URL guards, redirect probe, byte cap và download indicators: PASS.
- OAuth/SSO, URL ML, blacklist và known-safe regressions: PASS.

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

Hybrid release regression: 20/20 PASS.

## Runtime benchmark

- Node v24.18.0, Windows x64; 2.000 predictions.
- Mean 0,040 ms; p50 0,030 ms; p95 0,074 ms; max 2,108 ms.

Không retrain model trong bản vá giao diện này.
