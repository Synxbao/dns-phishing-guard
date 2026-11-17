# Validation v2.7.5

Ngày kiểm tra: 2026-08-17

## Lệnh và kết quả

```powershell
npm test
npm run evaluate
npm run probe:adversarial
npm run validate
```

| Gate | Kết quả v2.7.5 |
| --- | --- |
| Release tests | PASS |
| Independent holdout | TP/TN/FP/FN `185/199/1/13`; accuracy `96,48%`; precision `99,46%`; recall `93,43%`; FPR `0,50%` |
| Release hybrid | `22/22`, FP `0`, FN `0` |
| Complex hybrid | FP `0`, FN `0`; official/impostor `1/1` |
| Content recall | `2/2` |
| Adversarial probe | `32` total, `30` executable, `0` network request |
| Payment-brand impersonation | `5/5` HIGH, positive payment boost `0` |
| GUI regression | EN/VI, SAFE determined, responsive 320/468/700 px, touch target >=44 px: PASS |

Các chỉ số holdout, recall và false-positive không giảm so với v2.7.4/v2.7.0 baseline. GUI không thay đổi logic risk engine.

## QA session coverage

- 1 phiên GUI: `GUI_SESSION_v2.7.5.md`.
- 2 phiên tính năng + 2 phiên fake-resistance: `FEATURE_FAKE_TEST_SESSIONS_v2.7.5.md`.
- 5 phiên website read-only + 5 phiên usability: `EXTERNAL_USABILITY_TEST_SESSIONS_v2.7.5.md`.
- Báo cáo tổng hợp: `EXPERIENCE_REPORT_v2.7.5_FINAL.md`.

## Giới hạn còn lại

Probe offline không thay thế traffic production; Link Lab vẫn giới hạn 64 KiB và không chạy JavaScript trong bước preflight. RDAP bên ngoài có thể 404/timeout. Bản English dùng bảng dịch local, nên text mới từ nguồn ngoài có thể cần mapping bổ sung.
