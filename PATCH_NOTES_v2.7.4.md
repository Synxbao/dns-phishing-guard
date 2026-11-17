# DNS Phishing Guard v2.7.4 - Consolidated Security & UX Patch

Ngày phát hành: 2026-08-11

## Phạm vi

v2.7.4 hợp nhất đầy đủ 5 nhóm lỗi đã được xác nhận qua các lượt review. URL ML vẫn là `url-logistic-5.0.0`, dataset 4.000 URL và threshold 0,59; bản này không retrain model mà sửa security lock, DOM attribution, evidence coverage, brand/domain intelligence và UI consistency.

## Fix 1 - Content Safety HIGH khóa trang đúng mức

- `content.js:8`: dùng chung `STRICT_CONTENT_CATEGORY_IDS` cho Child Mode và content-only UI.
- `content.js:1129`: `bypassNeedsTypedDomain()` coi `contentSafety.level === "HIGH"` là nguồn khóa và yêu cầu gõ đúng domain.
- `content.js:1290`: `showAdvancedSecurityUI()` đặt `isHigh` bằng phishing HIGH hoặc content HIGH.
- `content.js:1443`: `showContentSafetyUI()` chuyển HIGH thuộc nhóm nghiêm ngặt thành overlay; `content.js:1455` tính `isBlockingContent`, bỏ nút `×` và gọi `activateSecurityLock()`.
- `tests/release.test.mjs:107`: assertion cố định kiểm tra OR-condition, overlay, close-button và typed-domain bypass.

Kết quả: không còn trường hợp content layer báo HIGH nhưng nền trang vẫn bấm xuyên hoặc bypass miễn gõ domain. Giới hạn còn lại là classifier nội dung vẫn là heuristic; nếu category HIGH bị false positive, overlay vẫn khóa đúng theo policy và người dùng phải dùng luồng bypass có xác nhận.

## Fix 2 - Loại ad/widget khỏi nội dung chính

- `content.js:295`: `collectPageSignals()` xác định ad regions trước khi tạo `bodyText`, profile, contact và control candidates.
- `content.js:299`: gọi `findLikelyAdRegions()`; `content.js:340` chỉ lấy text ngoài vùng quảng cáo.
- `modules/page-signal-filter.js:2`: danh sách ad-unit size chuẩn; `modules/page-signal-filter.js:62` nhận marker `ads`, `sponsor`, `banner-ad`, `quang-cao`, `adv`, `qc` và thuộc tính quảng cáo.
- `modules/page-signal-filter.js:171`: chỉ loại wrapper yếu khi có kích thước ad chuẩn hoặc creative/tài nguyên bên thứ ba; tránh loại nhầm card nội dung hợp pháp.
- `modules/page-signal-filter.js:218`: thu text bằng cây DOM đã loại ad regions.
- `tests/release.test.mjs:586`: fixture NetTruyen-style gồm main chapter sạch + banner quảng cáo chứa từ khóa `SEXUAL_SERVICES`; dữ liệu thô tái hiện HIGH, dữ liệu lọc loại text/profile/contact quảng cáo.
- `tests/release.test.mjs:732` và `tests/release.test.mjs:757`: nội dung `SEXUAL_SERVICES`/`GAMBLING` first-party thật vẫn HIGH, recall 2/2.

Trade-off: heuristic không thể phân biệt hoàn hảo quảng cáo native được viết giống nội dung chính, nằm chung container, không có marker/kích thước/tài nguyên bên thứ ba. Bản vá giảm mạnh bleed-through phổ biến nhưng không tuyên bố triệt để 100%.

## Fix 3 - Identity/payment evidence không còn quá khắt khe

- `modules/risk-engine.js:213`: thêm `MODERATELY_ESTABLISHED` cho domain 365-729 ngày.
- `modules/risk-engine.js:463`: reputation cap vẫn chỉ kích hoạt từ 730 ngày, nên tier mới không biến domain “nuôi” một năm thành trusted reputation.
- `modules/payment-signals.js:2`: rule VietQR, ZaloPay, MoMo, VNPay, NAPAS, Visa và Mastercard.
- `modules/payment-signals.js:185`: chỉ công nhận integration mạnh trong checkout context có control tương tác, hành động thanh toán và số tiền/đơn vị tiền.
- `modules/evidence-coverage.js:18`: payment evidence tối đa 20 điểm và không đổi `risk.score`/`risk.level`.
- `modules/evidence-coverage.js:43`: logo/text đơn lẻ không đủ; blocker gồm Risk không SAFE, blacklist, threat intel, brand mismatch, external password form, risky download và redirect anomaly.
- `background.js:334`: identity dùng registrable domain; RDAP/result pipeline không coi subdomain là domain đăng ký riêng.
- `tests/release.test.mjs:1343`: sleeper domain 420 ngày + URL ML 97% giữ `MODERATELY_ESTABLISHED`, `mlReduction = 0` và score trên 8.
- Adversarial probe: 5/5 case ZaloPay/VietQR/Vietcombank/MoMo/Punycode chèn logo thật vẫn HIGH, payment boost 0.

Nguồn payment-domain reference được tách ở `data/protected-payment-domains.json` với `trustAllowlist: false`; danh sách chỉ phục vụ typosquat reference, không mở rộng `known-domains.json` theo báo cáo lẻ.

## Fix 4 - Phân biệt cổng nạp game chính thức và giả mạo

- `data/brand-rules.json:138`: Garena/Free Fire/Liên Quân/FC Online/FC Mobile; domain `garena.vn`, `garena.com`, `napthe.vn` tại `data/brand-rules.json:155`.
- `data/brand-rules.json:167`: VNG Games/Zing; `data/brand-rules.json:186`: VTC Game/Vcoin.
- `modules/brand-rules.js:2`: dữ liệu chuyển khỏi hardcode trong `content.js` sang JSON có source refs và verification status.
- `modules/brand-rules.js:13`: chuẩn hóa accent, zero-width và separator; bắt được `Gare​na` và `Free-Fire`.
- `modules/brand-rules.js:99`: nhận diện brand presentation; `modules/brand-rules.js:165` tạo official-claim mismatch khi domain không khớp và có input giao dịch nhạy cảm.
- `modules/risk-engine.js:442`: claim chính thức + brand + ID/mã thẻ trên domain sai tạo page-risk signal 70.
- `modules/content-safety.js:261`: cùng tổ hợp đặt sàn `SCAM_COMMERCE` 78 và `GAME_COMMERCE` 65.
- `data/protected-game-domains.json:39`: thêm `napthe.vn` cùng các domain game đã xác minh vào typosquat baseline, vẫn `trustAllowlist: false`.
- `background.js:337`: hợp nhất protected payment/game domains cho `findSimilarDomain()` nhưng không làm `isKnownDomain` thành true.
- `modules/evidence-coverage.js:19` và `modules/evidence-coverage.js:240`: verified brand/domain alignment chỉ cộng tối đa 10 evidence point khi Risk SAFE, identity đã nhận diện, có action/input nạp game và không có blocker; tổng payment + brand bị khóa trần 20.
- `popup.js:374`: Simple UI ưu tiên ba lý do: địa chỉ gần domain chính thức, claim chính thức không khớp, và yêu cầu ID/serial/PIN.
- Cặp fixture cố định: `evaluation/complex-legit-cases.json:94`/`:138` và `evaluation/release-regression-cases.json:134`/`:177`.

### Nguồn xác minh độc lập

| Nhóm | Domain reference | Nguồn publisher-owned |
| --- | --- | --- |
| Garena | `garena.vn`, `garena.com`, `napthe.vn` | [Garena Việt Nam](https://www.garena.vn/) và [hướng dẫn Garena Delta Force nêu Garena chỉ có duy nhất trang napthe.vn](https://deltaforce.garena.vn/news/huong-dan-chung/huong-dan-nap-the-garena-delta-force) |
| Free Fire | kế thừa domain Garena | [Free Fire chính thức](https://ff.garena.com/en) |
| Liên Quân Mobile | kế thừa domain Garena | [Liên Quân Mobile chính thức](https://lienquan.garena.vn/) |
| FC Online | kế thừa domain Garena | [FC Online Việt Nam](https://fconline.garena.vn/) |
| FC Mobile | kế thừa domain Garena | [FC Mobile Vietnam](https://fcmobile.garena.vn/) |
| VNG Games / Zing | `vnggames.com`, `zing.vn` | [Điều khoản VNGGames Shop](https://shop.vnggames.com/vn/terms-of-service) và [pay.zing.vn](https://pay.zing.vn/) |
| VTC Game / Vcoin | `vtcgame.vn` | [Cổng nạp VTC Game](https://napthe.vtcgame.vn/) |

`napthevn.vn` không được đưa vào trust/blacklist vì chưa có nguồn độc lập đủ mạnh trong phạm vi release; threat fixture dùng `napthevn.example` để kiểm thử offline an toàn.

### Cặp official/impostor

| Case | URL ML thô | Hybrid | Evidence | Content Safety | Positive boost |
| --- | --- | --- | ---: | --- | ---: |
| `napthe.vn` official | PHISHING 64,96% | SAFE 8 | `DETERMINED/CONFIDENT` 48/100 | NONE | verified brand +10 |
| `napthevn.example` impostor | PHISHING 93,14% | HIGH 100 | 100/100 | HIGH: `SCAM_COMMERCE` + `GAME_COMMERCE` | 0 |

URL ML thô vẫn false-positive ở case official; chính Hybrid + evidence context sửa trải nghiệm. Đây không phải tuyên bố model lexical đã tự phân biệt được cặp này.

## Fix 5 - Quiet mode trang tìm kiếm và UI không overlap

- `modules/search-engines.js:4`: Google; `:9` Bing; `:14` DuckDuckGo; `:24` Brave Search; `:29` Cốc Cốc; Yahoo dùng cùng classifier.
- `background.js:76`: `showSearchEnginePageUi` mặc định false; `background.js:368` lưu `isSearchEngineHome` trong kết quả quét.
- `content.js:843`: chỉ ẩn UI khi search-engine page và Risk SAFE; verdict không SAFE vẫn hiện bình thường.
- `popup.html:359`: setting nâng cao “Hiện trạng thái trên trang tìm kiếm phổ biến”.
- `content.js:734`: panel không khóa tự thu gọn khi click ngoài, selection hoặc native context menu; overlay HIGH không dùng hành vi này.
- `content.js:1336` và `content.js:1460`: bar/panel neo góc dưới phải, score không xuống dòng, metric không cắt `100/100`, responsive 700/620/520/468/420/320 px.
- `tests/release.test.mjs:207`: 6 search-engine fixture; assertion SAFE quiet-mode và domain classification.

Browser QA cục bộ:

- 468×800: `rootScrollWidth = rootClientWidth = 468`, không horizontal overflow.
- 320×800: `rootScrollWidth = rootClientWidth = 320`, không heading/button/metric quan trọng bị cắt.
- Menu chuột phải native là lớp OS/browser luôn nằm trên extension và không thể hạ z-index từ content script; bản vá chỉ thu gọn panel không khóa để giảm cảm giác che khuất.

## Validation

Chạy:

```powershell
npm run validate
```

Kết quả:

- Holdout TP/TN/FP/FN: 185/199/1/13.
- Accuracy 96,48%; Precision 99,46%; Recall 93,43%; F1 96,35%; FPR 0,50%.
- Release regression: 22/22 hybrid URL; content recall 2/2; official/impostor pair 1/1.
- Complex regression: 34 case; hybrid FP/FN 0/0; evidence/content/context/identity mismatch 0/0/0/0.
- Adversarial probe: 32 tổng, 30 executable, 0 request mạng; 5/5 fake payment-brand case vẫn HIGH và nhận 0 payment/brand boost.
- So với v2.7.0: holdout metrics không giảm; 24 complex case dùng chung giữ nguyên Hybrid verdict, release regression tăng từ 20 lên 22 URL do thêm cặp official/impostor.

## Giới hạn cần theo dõi

- Ad filtering vẫn là heuristic; native ad không marker và trộn thẳng vào nội dung chính có thể còn bleed-through.
- Domain 365+ ngày có thể là sleeper domain; tier mới chỉ cải thiện identity coverage, không hạ Risk và không hưởng reputation cap trước 730 ngày.
- Brand text trong image/canvas, closed shadow DOM hoặc obfuscation không còn text có thể né rule; zero-width/separator phổ biến đã được xử lý.
- Publisher có thể đổi domain hoặc đối tác; `brand-rules.json` và protected references cần review định kỳ theo nguồn chính thức.
- Browser context menu luôn nằm trên overlay web; đây là hành vi nền tảng, không phải z-index của extension.
- Probe vẫn báo 5 gap cũ ở action-token semantics, slang scam/game-commerce và Link Lab 64 KiB; v2.7.4 không che các gap này.

