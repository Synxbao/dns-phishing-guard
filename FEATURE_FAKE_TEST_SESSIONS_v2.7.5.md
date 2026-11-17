# DNS Phishing Guard - 2 phiên kiểm tra tính năng và 2 phiên chống giả mạo

## Phạm vi

- Thời điểm chạy: `2026-08-17`, múi giờ `Asia/Saigon`.
- Thư mục: `D:\WORK\prj\dns-phishing-guard-v2.7.3-runtime`.
- Snapshot chức năng tại thời điểm kiểm thử có `manifest.json = 2.7.4`; kết quả này là gate cho release GUI `v2.7.5`. Sau khi ghép thay đổi GUI và tăng version, cần chạy lại `npm run validate` một lần cuối.
- Không sửa source code trong bốn phiên này. Các kiểm tra bổ sung chạy bằng script Node truyền qua stdin và không để lại file tạm.
- Mọi ca chống giả mạo dùng fixture offline/reserved (`.example`) hoặc dữ liệu regression có sẵn. `networkRequestsMade = 0`; RDAP không được gọi thật.

## Kết luận nhanh

| Phiên | Mục tiêu | Kết quả |
| --- | --- | --- |
| FEATURE-01 | Regression toàn bộ tính năng release | PASS |
| FEATURE-02 | Đánh giá hybrid, identity tier, search quiet mode và wiring của 5 fix | PASS |
| FAKE-01 | Adversarial probe tổng quát, typosquat/homoglyph/logo giả | PASS có 5 gap đã biết |
| FAKE-02 | Ma trận giả mạo có chủ đích và typed-domain lock hai lớp | PASS |

## FEATURE-01 - Regression chức năng release

### Lệnh

```powershell
npm test
```

### Kết quả thực tế

```text
> node tests/release.test.mjs
release tests: PASS (v2.7.4 verified game-brand rules, official-claim mismatch, paired discrimination)
Exit code: 0
```

### Phạm vi được xác nhận

- Content Safety `HIGH` được tính chung với Risk `HIGH`, dùng overlay, security lock, không có nút đóng ở nhóm nội dung nhạy cảm và yêu cầu gõ domain khi vượt cảnh báo.
- Bộ lọc vùng quảng cáo nhận diện marker `ads`, `sponsor`, `banner-ad`, `quang-cao`, creative bên thứ ba và kích thước ad-unit; regression NetTruyen-style không còn đưa text quảng cáo vào nội dung chính.
- Recall fixture nội dung thật `GAMBLING` và `SEXUAL_SERVICES` vẫn giữ nguyên.
- Identity tier xác nhận biên `364/365/729/730` ngày; `365-729` là `MODERATELY_ESTABLISHED`.
- Payment evidence chỉ được cộng khi đủ ngữ cảnh giao dịch và vẫn có blocker; logo đơn lẻ không phải trust signal.
- Brand rules Garena/VNG/VTC được nạp từ dữ liệu; cặp official/impostor có verdict khác nhau.
- Search-engine quiet mode, setting bật lại, panel góc dưới và breakpoint `700/620/520/468/420/320` đều có assertion.
- Training/model metadata vẫn là `2.000` safe + `2.000` malicious, independent test `398` mẫu.

### Giới hạn phiên

- Đây là Node regression và source assertion, không thay thế kiểm tra tương tác trong Chrome thật.
- Menu chuột phải native của hệ điều hành/trình duyệt luôn có lớp ưu tiên cao hơn extension, nên không thể kết luận về overlap OS chỉ từ phiên này.

## FEATURE-02 - Hybrid evaluation và kiểm tra tính năng mục tiêu

### Lệnh chính

```powershell
npm run evaluate
```

### Kết quả đánh giá

| Nhóm | Kết quả |
| --- | --- |
| Independent holdout | `398` mẫu; TP/TN/FP/FN = `185/199/1/13` |
| Accuracy / Precision / Recall / F1 | `96.4824% / 99.4624% / 93.4343% / 96.3542%` |
| False-positive rate | `0.5%` |
| Release hybrid | `22/22`, FP `0`, FN `0` |
| Official/impostor pair | `1/1` cặp đạt |
| Content Safety recall gate | `2/2`, recall `100%` |
| Complex regression | `34` ca, hybrid FP `0`, hybrid FN `0` |
| Runtime | `2.200` prediction; mean `0.031676 ms`, p95 `0.0561 ms` ở lượt riêng |

### Kiểm tra bổ sung không tạo file

Lệnh thực tế dùng một here-string PowerShell truyền trực tiếp cho Node:

```powershell
@'
// Import buildIdentityStatus, search-engines và các module content wiring.
// Assert biên tuổi 364/365/729/730; 6 search engine; ad marker/size;
// Content HIGH lock, payment wiring, typed-domain backend guard và quiet setting.
'@ | node --input-type=module -
```

Kết quả literal quan trọng:

```text
364 -> UNVERIFIED
365 -> MODERATELY_ESTABLISHED
729 -> MODERATELY_ESTABLISHED
730 -> ESTABLISHED_DOMAIN
google.com, bing.com, duckduckgo.com, search.yahoo.com,
search.brave.com, search.coccoc.com -> isSearchEngineHome=true
google.com.evil.example -> false
sourceChecks: 7/7 true
result: PASS
Exit code: 0
```

### Nhận định

- Hybrid khắc phục được `1` false positive và `1` false negative của ML-only trong release gate mà không tạo FP/FN mới.
- Cặp nạp game chính thức/giả mạo không còn cùng verdict.
- `MODERATELY_ESTABLISHED` chỉ cải thiện coverage danh tính; không được dùng như trust allowlist hoặc reputation cap 730 ngày.

### Giới hạn phiên

- Bộ release/complex là regression có chủ đích, không phải mẫu thống kê đại diện toàn Internet.
- Raw URL ML vẫn có `1` false positive trong complex set; verdict hybrid bù đúng nhưng model nền chưa tự giải quyết ca đó.
- Không gọi RDAP/network thật, vì vậy không đánh giá độ ổn định của dịch vụ ngoài hay latency mạng.

## FAKE-01 - Adversarial probe offline

### Lệnh

```powershell
npm run probe:adversarial
```

### Kết quả tổng

```text
totalCases: 32
executableCases: 30
networkRequestsMade: 0
duplicateCheckPassed: true
EXPECTED_PASS: 22
HYBRID_COMPENSATED: 3
REAL_GAP: 5
EXPECTED_STRUCTURAL_LIMITATION: 2
benignExpectedPassRate: 100%
```

### Các ca giả mạo trọng tâm

| Fixture reserved/offline | Tín hiệu | Verdict |
| --- | --- | --- |
| `paypa1.example` | Typosquat gần `paypal.com` | `HIGH 95` |
| `xn--pple-43d.example` | Homoglyph/punycode Apple | `HIGH 100` |
| `napthee.example` | Gần `napthe.vn` + tự nhận Garena chính thức | `HIGH 100`, `SCAM_COMMERCE + GAME_COMMERCE` |
| `zal0pay.example` | Logo ZaloPay giả + digit substitution | `HIGH 100`, payment boost `0` |
| `vietqrr.example` | Logo VietQR giả + ký tự thừa | `HIGH 80`, payment boost `0` |
| `vietcombank.example` | Brand đúng nhưng sai suffix | `HIGH 100`, payment boost `0` |
| `m0mo.example` | Logo MoMo giả + digit substitution | `HIGH 90`, payment boost `0` |
| `xn--zlopay-3nf.example` | Homoglyph ZaloPay + logo giả | `HIGH 100`, payment boost `0` |

Kết quả bắt buộc cho logo thanh toán giả: `5/5` ca ở mức `HIGH`, `5/5` không được cộng positive payment evidence.

### Các gap còn quan sát được

| Nhóm | Số ca | Ý nghĩa |
| --- | ---: | --- |
| `ACTION_TOKEN` | 2 | Action token/verb mới có thể chưa được lexical rule nhận diện. |
| `SCAM_COMMERCE` | 1 | Slang thương mại lừa đảo mới có thể thiếu tổ hợp tín hiệu. |
| `GAME_COMMERCE` | 1 | Viết tắt/slang game-commerce mới có thể né semantic rule. |
| `LINK_LAB_LIMIT` | 1 | Nội dung nguy hiểm sau giới hạn đọc 64 KiB có thể không được quan sát. |

Các gap này không làm thất bại các ca typosquat, official-claim mismatch hay payment-logo impersonation được yêu cầu, nhưng phải được giữ trong backlog thay vì diễn giải `22/30` expected pass thành bao phủ hoàn toàn.

## FAKE-02 - Ma trận giả mạo và typed-domain lock

### Lệnh

Phiên dùng script Node qua stdin; script import trực tiếp `typosquat.js`, `brand-rules.js`, đọc kết quả adversarial và kiểm tra cả `content.js` lẫn guard phía `background.js`:

```powershell
@'
// 1. findSimilarDomain: napthevn/zal0pay/vietqrr/m0mo trên suffix .example.
// 2. foldText: Gare<zero-width>na và Free-Fire.
// 3. deriveCommerceBrandSignals: official claim trên domain không khớp.
// 4. Assert 5 payment-logo impersonation đều HIGH và boost=0.
// 5. Assert typed-domain lock tại UI và background; thử input đúng/sai.
'@ | node --input-type=module -
```

### Kết quả typosquat

| Input | Baseline gần nhất | Kết quả |
| --- | --- | --- |
| `napthevn.example` | `napthe.vn` | PASS |
| `zal0pay.example` | `zalopay.vn` | PASS |
| `vietqrr.example` | `vietqr.vn` | PASS |
| `m0mo.example` | `momo.vn` | PASS |

### Kết quả obfuscation và claim giả

```text
Gare<zero-width>na -> garena
Free-Fire -> free fire
officialClaimMismatch -> true
officialClaimBrandName -> Garena
Fake game official claim -> HIGH 100
Categories -> SCAM_COMMERCE, GAME_COMMERCE
```

### Kết quả logo thanh toán giả

```text
Ca chạy: 5
HIGH: 5
Ca được cộng positive payment boost: 0
```

### Kết quả typed-domain lock

- Client: Content Safety `HIGH` nằm trong `bypassNeedsTypedDomain`; nút submit khởi tạo ở trạng thái `disabled`; chỉ mở khi input chuẩn hóa bằng đúng `result.domain`.
- Background: `bypassRequiresTypedDomain` kiểm tra lại Content Safety `HIGH`; handler `IGNORE_DOMAIN_TEMP` và `ALLOW_BLOCKED_ONCE` đều so sánh `confirmationDomain` phía service worker. Vì vậy sửa DOM để mở nút client không đủ để vượt guard backend.

| Input cho domain `napthevn.example` | Được chấp nhận |
| --- | --- |
| rỗng | Không |
| `napthevn.example` | Có |
| `www.NAPTHEVN.EXAMPLE` | Có, sau chuẩn hóa |
| `napthevn.example.attacker.example` | Không |
| `napthevn.example.` | Không |

Kết quả phiên: `PASS`, exit code `0`.

### Giới hạn phiên

- Chuẩn hóa zero-width hiện bao phủ nhóm ký tự đã định nghĩa; branding chỉ tồn tại trong ảnh, canvas, video hoặc closed shadow DOM vẫn có thể thiếu text signal.
- Typosquat Levenshtein/homoglyph không bắt mọi alias có khoảng cách xa hoặc tên hoàn toàn khác.
- Typed-domain lock được kiểm tra bằng regression/source guard và ma trận normalize offline; chưa có Chrome MV3 end-to-end automation bấm thật trên overlay.
- Guard vượt cảnh báo làm tăng ma sát và chống bấm nhầm; nó không ngăn người dùng cố tình gõ đúng domain sau khi đã bỏ qua hướng dẫn.

## Gate tích hợp cuối

Sau bốn phiên, chạy thêm gate tích hợp:

```powershell
npm run validate
```

Kết quả: `PASS`, exit code `0`; chuỗi `test -> evaluate -> probe:adversarial` hoàn tất, `networkRequestsMade = 0`.

### Re-run sau khi tăng manifest lên v2.7.5

- `npm test`: PASS (`release tests: PASS (v2.7.5 GUI, game-brand rules, official-claim mismatch, paired discrimination)`).
- `npm run validate`: PASS; holdout `185/199/1/13`, release hybrid `22/22`, complex FP/FN `0/0`, content recall `2/2`, probe `0` request mạng.
- Không có thay đổi verdict của cặp official/impostor hoặc 5 payment-logo impersonation; GUI chỉ đổi presentation và song ngữ.

## Kết luận bàn giao

- Chức năng: đạt regression gate; không ghi nhận suy giảm recall `GAMBLING/SEXUAL_SERVICES`, không có hybrid FP/FN trong release và complex gate.
- Chống giả mạo: các ca typosquat, homoglyph, separator/zero-width brand, logo thanh toán giả và official-claim mismatch mục tiêu đều bị phát hiện; typed-domain lock có kiểm tra ở cả client lẫn background.
- Trạng thái: **PASS có giới hạn kỹ thuật đã ghi rõ**. Gate cuối đã được chạy lại trên manifest `2.7.5` và hoàn tất thành công.
