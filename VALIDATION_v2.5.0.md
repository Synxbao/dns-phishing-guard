# Validation v2.5.0

Ngày đánh giá: 2026-08-10 (Asia/Saigon)

## Lệnh đã chạy

```powershell
npm test
npm run evaluate
npm run validate
```

## Release regression

- Syntax check cho background/content/popup/blocked/Link Lab/modules: PASS.
- Manifest JSON và version `2.5.0`: PASS.
- Simple/Technical UI markers, label context và model label: PASS.
- Focus lock, inert restore, capture guard và typed-domain bypass source gate: PASS.
- Allow-once session metadata + consume function: PASS.
- URL privacy redaction và Threat Intel payload minimization: PASS.
- Action-token classifier và zero-fetch probe skip: PASS.
- OAuth/SSO, TikTok `/@handle`, localhost/private context, blacklist và hybrid risk regression: PASS.

## Model độc lập

| Chỉ số | Giá trị |
| --- | ---: |
| TP / TN / FP / FN | 185 / 199 / 1 / 13 |
| Accuracy | 96,48% |
| Precision | 99,46% |
| Recall | 93,43% |
| F1 | 96,35% |
| Specificity | 99,50% |
| FPR / FNR | 0,50% / 6,57% |

- Model: `url-logistic-5.0.0`; feature `url-lexical-v4`; 54 features; threshold 0,59.
- Embedded confusion matrix, holdout replay: nhất quán.
- Release hybrid: 20/20, 0 FP, 0 FN.
- Complex legit: 24 ca, 0 raw-ML FP, 0 hybrid FP, 0 on-page warning, 0 context mismatch.
- Runtime URL inference benchmark: mean 0,0267 ms; p95 0,0432 ms cho 2.000 prediction trên Node v24.18.0/Windows x64.

## Visual QA

- Simple SAFE và HIGH tại popup width 468 px: PASS.
- Simple HIGH tại width 320 px: PASS, `scrollWidth = clientWidth = 320`.
- Technical tại width 320 px: phát hiện overflow 9 px do nút đổi mode; đã ẩn nút này ở breakpoint 320 và xác nhận lại `scrollWidth = clientWidth = 320`.
- `prefers-reduced-motion`, focus-visible và internal vertical scrolling được giữ nguyên.

## Privacy QA

- Query values/fragment không xuất hiện trong history sanitizer hoặc Threat Intel payload test.
- Per-tab result chỉ ghi session storage; local numeric-key migration vẫn chạy khi cài/nâng cấp.
- Báo nhầm không thực hiện network request.

## Giới hạn kiểm chứng

- Chưa có end-to-end automation trực tiếp trong một Chrome profile đã cài unpacked extension; focus/inert và DNR lifecycle được kiểm qua regression/source gate và logic module.
- Chưa thực hiện review Chrome Web Store/Edge Add-ons.
- DNS rebinding và website behavior sau JavaScript/user interaction vẫn là residual risk của preflight.

## Artifact

SHA-256 của ZIP được ghi trong `RELEASE_HASHES_v2.5.0.txt` sau bước đóng gói.
