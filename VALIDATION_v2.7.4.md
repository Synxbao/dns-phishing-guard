# Validation v2.7.4

Ngày kiểm tra: 2026-08-11

## Lệnh

```powershell
npm run validate
```

Kết quả: **PASS** `npm test`, `npm run evaluate` và `npm run probe:adversarial`. Probe chạy offline, `networkRequestsMade = 0`.

## Trước / sau cặp official-impostor

| Case | Trước bản vá | Sau bản vá v2.7.4 |
| --- | --- | --- |
| Official `napthe.vn` | SUSPICIOUS 10, binary SAFE, content NONE; UI có thể rơi vào thiếu dữ liệu | SAFE 8, binary SAFE, evidence 48/100 `DETERMINED/CONFIDENT`, content NONE, không on-page warning |
| Reserved impostor `napthevn.example` | SUSPICIOUS 30, binary SAFE, content NONE | HIGH 100, binary PHISHING, evidence 100/100, content HIGH (`SCAM_COMMERCE`, `GAME_COMMERCE`), có on-page warning |
| Khoảng cách Hybrid score | 20 điểm, cùng binary SAFE | 92 điểm, verdict phân tách rõ |

Baseline trước sửa được tái dựng offline từ logic cũ; không mở domain giả thật và không gọi RDAP/network thật.

## Kết quả đánh giá

| Hạng mục | Kết quả |
| --- | ---: |
| Manifest | 2.7.4 |
| Holdout TP / TN / FP / FN | 185 / 199 / 1 / 13 |
| Accuracy / Precision / Recall / F1 | 96,48% / 99,46% / 93,43% / 96,35% |
| Holdout FPR | 0,50% |
| Release regression URL | 22/22 hybrid |
| Release content recall | 2/2 |
| Release official/impostor pair | 1/1 |
| Complex regression | 34 case: 33 SAFE + 1 threat control |
| Complex ML raw FP / hybrid FP / hybrid FN | 1 / 0 / 0 |
| Complex content/context/identity/evidence mismatch | 0 / 0 / 0 / 0 |
| Complex official/impostor pair | 1/1 |
| Adversarial probe | 32 tổng, 30 executable, 22 adversarial, 7 benign, 2 structural |
| Request mạng trong probe | 0 |

## Assertion chính

- `content.js` không còn khai báo mảng `BRAND_RULES`; runtime phải chờ `brandRulesReady` trước khi thu page signals.
- `manifest.json` nạp `modules/brand-rules.js` trước `content.js` và khai báo `data/brand-rules.json` trong web-accessible resources.
- Dataset brand có Garena/`napthe.vn`, VNG Games/`vnggames.com`, VTC Game/`vtcgame.vn`, nguồn publisher-owned và `trustAllowlist: false`.
- `known-domains.json` không chứa `napthe.vn`; protected game data chỉ đi vào typo reference pool.
- `findSimilarDomain("napthevn.example", ...)` trả baseline `napthe.vn`.
- Official fixture không tạo official-claim mismatch; impostor fixture tạo `officialClaimMismatch` và `gameCommerceOfficialClaimMismatch`.
- Official fixture chỉ nhận 10 điểm verified-brand evidence khi identity đã nhận diện, Risk SAFE, có input/action nạp game và không có blocker; impostor nhận 0 điểm.
- Biến thể `Gare​na` và `Free-Fire` được chuẩn hóa trước khi so khớp brand; fixture reserved vẫn tạo official-claim mismatch.
- Official page có thêm logo/text MoMo vẫn không bị gán payment-brand mismatch nhờ official publisher-domain match.
- Bài viết Garena không có hành động/input giao dịch không bị cảnh báo nhầm.
- Impostor có claim + brand + ID/mã thẻ đạt Risk HIGH và Content Safety HIGH ngay cả khi không dựa riêng vào typo.
- Domain 420 ngày với URL ML 97% không được hưởng reputation cap 730 ngày: `MODERATELY_ESTABLISHED`, `mlReduction = 0`, score vẫn trên 8.

## QA giao diện

- Browser local QA tại viewport 468×800: `rootScrollWidth = rootClientWidth = 468`, không horizontal overflow.
- Browser local QA tại viewport 320×800: `rootScrollWidth = rootClientWidth = 320`, không có heading/button/metric quan trọng bị cắt.
- Breakpoint 700/620/520/468/420/320 px có assertion CSS cố định trong `tests/release.test.mjs`.
- Menu chuột phải native của hệ điều hành/trình duyệt luôn có thể nằm trên extension; panel không khóa tự thu gọn khi context menu/selection phát sinh, còn overlay HIGH không tự thu gọn.

## Adversarial probe

- Tổng 32 case: 30 executable + 2 structural; 0 request mạng; source manifest khớp 1:1 với executable cases.
- Fixture `napthee.example` đạt `EXPECTED_PASS`: typo detected, Risk `HIGH`, verdict `NGUY_HIỂM`, content `SCAM_COMMERCE` + `GAME_COMMERCE`, payment boost 0.
- 5/5 case giả payment brand cũ vẫn `HIGH/NGUY_HIỂM`, payment evidence boost 0.
- 7/7 benign case đạt expected pass.
- 5 real gap cũ vẫn được báo rõ: action-token semantics, slang trong scam/game-commerce và Link Lab 64 KiB; bản vá này không che hoặc đổi nhãn các gap đó.

## Giới hạn

URL ML thô vẫn dự đoán PHISHING 64,96% cho URL official `napthe.vn`; Hybrid Risk Engine bù đúng xuống SAFE 8 và evidence coverage lên `CONFIDENT 48/100` nhờ context đã xác minh. Điều này chứng minh brand/domain evidence là lớp cần thiết nhưng cũng cho thấy model lexical chưa tự giải quyết false positive này.

Rule brand là dữ liệu snapshot ngày 2026-08-11. Publisher đổi domain/đối tác cần review nguồn và cập nhật dataset. Một website giả không dùng brand/claim rõ ràng hoặc không gần typo baseline vẫn có thể cần Threat Intelligence, RDAP, redirect, form và các tín hiệu hành vi khác để phát hiện.
