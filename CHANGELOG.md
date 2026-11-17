# Changelog

## 2.7.5 - 2026-08-17

- Bản polish GUI cuối: Simple/Technical/Child UI có chuyển ngôn ngữ Việt/Anh tức thời, lưu lựa chọn cục bộ và dịch cả nhãn, placeholder, trạng thái rỗng, aria-label, thời gian và hướng dẫn đọc.
- Giữ đủ Risk, Evidence, Coverage, Link Lab và telemetry trong giao diện gọn hơn; không thay đổi Risk Engine, URL ML, threshold hoặc bộ dữ liệu.
- Chuẩn hóa responsive ở 320/420/468/520/620/700 px, loại horizontal overflow ở Technical shell và nâng control/tab/action chính lên touch target tối thiểu 44 px.
- SAFE + COMPLETE + DETERMINED không còn bị trình bày amber chỉ vì lớp tùy chọn như Threat Intelligence chưa có; lớp còn thiếu vẫn được liệt kê ở Technical UI.
- Bổ sung regression assertion cho locale controls, bản English, trạng thái SAFE đã xác định và kích thước touch target; giữ nguyên các gate content-lock, ad filtering, payment và game-brand của v2.7.4.

## 2.7.4 - 2026-08-11

- Hợp nhất đủ 5 nhóm bản vá đã xác nhận: khóa Content Safety HIGH, chống ad/widget bleed-through, evidence cho domain/payment hợp pháp, bảo vệ hệ sinh thái nạp game Việt Nam và quiet-mode/UI responsive cho trang tìm kiếm.
- Content Safety HIGH thuộc nhóm nghiêm ngặt nay dùng cùng `STRICT_CONTENT_CATEGORY_IDS`, chuyển thành overlay khóa trang, không có nút đóng nhanh và luôn yêu cầu gõ đúng domain nếu người dùng chọn cho phép tạm thời.
- `collectPageSignals()` lọc vùng quảng cáo theo marker, thuộc tính, ad-unit size và creative bên thứ ba trước khi gán body/profile/contact/control cho nội dung chính; fixture NetTruyen-style cố định chứng minh lỗi trước lọc và kết quả sạch sau lọc, trong khi recall `GAMBLING`/`SEXUAL_SERVICES` first-party vẫn 2/2.
- Thêm identity tier `MODERATELY_ESTABLISHED` cho 365-729 ngày nhưng giữ reputation cap ở 730 ngày; regression sleeper-domain 420 ngày xác nhận không được hưởng cap chỉ vì đã “nuôi” hơn một năm.
- Tín hiệu payment integration VietQR/ZaloPay/MoMo/VNPay/NAPAS/Visa/Mastercard chỉ cộng evidence trong checkout context mạnh, bị chặn khi có rủi ro độc lập và không thay đổi Risk score/verdict.
- Chuyển toàn bộ rule nhận diện thương hiệu khỏi mảng hardcode trong `content.js` sang `data/brand-rules.json`, nạp qua `modules/brand-rules.js`; dữ liệu nguồn, trạng thái xác minh và domain được review độc lập nay nằm trong diff riêng, dễ bảo trì.
- Bổ sung hệ sinh thái nạp game đã xác minh: Garena/Free Fire/Liên Quân/FC Online/FC Mobile với `garena.vn`, `garena.com`, `napthe.vn`; VNG Games/Zing với `vnggames.com`, `zing.vn`; VTC Game/Vcoin với `vtcgame.vn`. Các subdomain chính thức được đối chiếu qua registrable domain.
- Không đưa `napthevn.vn` vào trust hoặc blacklist chỉ dựa trên báo cáo người dùng. Dữ liệu ghi rõ trạng thái chưa có nguồn độc lập đủ tin cậy; fixture nguy hiểm dùng domain reserved `.example`.
- Thêm tổ hợp mạnh: trang tự nhận “chính thức/đối tác chính thức”, trình bày thương hiệu game đã biết, chạy trên domain không khớp và yêu cầu ID game/mã thẻ. Tổ hợp này tạo page-risk signal 70 điểm, đặt sàn `SCAM_COMMERCE` 78 và `GAME_COMMERCE` 65 mà không cần chờ thêm nhiều tín hiệu yếu.
- Chuẩn hóa brand text để bắt zero-width và separator phổ biến như `Gare​na`/`Free-Fire`; Simple UI ưu tiên ba lý do dễ hiểu cho official-claim mismatch thay vì lặp thuật ngữ kỹ thuật.
- Thêm `data/protected-game-domains.json` làm nguồn tham chiếu typosquat/homoglyph cho hệ sinh thái nạp game; `trustAllowlist: false`, không làm `isKnownDomain` thành true và không tự chứng nhận website an toàn.
- Thêm evidence positive có điều kiện cho cặp brand/domain game đã xác minh: tối đa 10 điểm, chỉ khi Risk SAFE, identity đã nhận diện, có input/action nạp game thật và không có blocker; tổng payment + brand boost vẫn bị khóa trần 20. Nhờ đó fixture official `napthe.vn` đạt `CONFIDENT 48/100`, còn impostor giữ `HIGH 100` và boost 0.
- SAFE UI trên Google, Bing, DuckDuckGo, Yahoo, Brave Search và Cốc Cốc được ẩn mặc định nhưng vẫn quét ngầm; setting nâng cao cho phép bật lại và mọi verdict không SAFE vẫn hiện cảnh báo.
- Dọn overlap/cắt chữ: panel/bar không khóa neo góc dưới phải, score giữ một dòng, metric cho phép overflow chữ hợp lệ, responsive 700/620/520/468/420/320 px và tự thu gọn khi click/chọn text/context-menu ngoài trang. Menu chuột phải native vẫn là lớp OS/browser luôn nằm trên cùng.
- Thêm cặp official/impostor có nội dung tương đương vào cả `release-regression-cases.json` và `complex-legit-cases.json`; evaluator nay gate cả false positive trên case thật, false negative trên threat control và khoảng cách verdict của cặp.
- Thêm adversarial fixture Garena giả lập trên domain reserved, xác nhận typo + official-claim mismatch vẫn cho `HIGH/NGUY_HIỂM` và không gọi mạng.
- URL ML `url-logistic-5.0.0`, dataset 4.000 URL, calibration và threshold 0,59 không đổi; holdout giữ 185/199/1/13, Accuracy 96,48%, Recall 93,43%, FPR 0,50%. Đây là bản vá rule/evidence/content/UI và regression, không retrain model.

## 2.7.3 - 2026-08-10

- Thêm identity tier `MODERATELY_ESTABLISHED` cho domain 365-729 ngày; tier này được nhận diện trong evidence coverage nhưng không kích hoạt reputation cap của Risk Engine, vốn vẫn yêu cầu ít nhất 730 ngày.
- Xác nhận RDAP luôn tra `registrableDomain` (`shop.vnggames.com` → `vnggames.com`); khi RDAP không trả tuổi, lớp `IDENTITY` vẫn được ghi là thiếu thay vì giả định domain an toàn.
- Thêm `modules/payment-signals.js` để nhận diện VietQR, ZaloPay, MoMo, VNPay, NAPAS, Visa và Mastercard chỉ trong luồng checkout/payment có context, control tương tác và số tiền/hành động thanh toán, đồng thời loại vùng quảng cáo.
- Payment integration chỉ cộng tối đa 20 điểm evidence coverage, không thay đổi `risk.score`, `risk.level`, binary prediction hoặc URL ML; boost bị khóa khi Risk không SAFE, blacklist/threat-intel unsafe, brand mismatch, external password form, risky download hoặc redirect bất thường.
- Khi RDAP là lớp cốt lõi duy nhất còn thiếu nhưng domain/page/URL ML đã được quét sạch và payment integration đủ mạnh, verdict dùng `PROVISIONAL` + `BẰNG CHỨNG HỖ TRỢ TỐT`; identity thiếu vẫn hiển thị và logo không được mô tả như xác thực merchant/giao dịch.
- Tách `data/protected-payment-domains.json` khỏi `known-domains.json`: tập mới chỉ làm reference bắt typosquat/homoglyph, không làm `isKnownDomain` thành true và không phải allowlist. Nguồn/methodology NHNN/NAPAS được ghi trong `data/`.
- Thêm 2 complex-legit checkout fixture: domain 420 ngày và RDAP unavailable; cả hai SAFE, không on-page warning, payment evidence đạt 46/100 và 45/100 theo kỳ vọng.
- Thêm 5 adversarial fixture có logo payment giả trên `zal0pay`, `vietqrr`, `vietcombank` sai suffix, `m0mo` và ZaloPay Punycode; cả 5 vẫn `HIGH/NGUY_HIEM`, payment boost bằng 0.
- URL ML `url-logistic-5.0.0`, dataset 4.000 URL và holdout metrics không thay đổi; đây là bản vá identity/evidence và chống false-positive, không retrain model.

## 2.7.2 - 2026-08-10

- Vá lỗi UI/consistency, không retrain URL ML và không thay đổi điểm, threshold hoặc logic quyết định của Risk Engine.
- Chuyển bar/panel không khóa từ top-center sang góc dưới bên phải, neo panel phía trên bar và bổ sung responsive 320/420/468/520/620/700 px để tránh che ô tìm kiếm/thanh điều hướng.
- Giữ `z-index: 2147483647`, cho label co giãn/ellipsis, giữ score `100/100` không xuống dòng và bỏ `overflow:hidden` khỏi metric value để không cắt chữ ở viewport hẹp hoặc zoom lớn.
- Panel không khóa tự thu gọn khi người dùng click ngoài, chọn văn bản hoặc mở menu chuột phải trên trang gốc; bar vẫn mở lại được bằng chuột/bàn phím. Overlay HIGH/strict không áp dụng hành vi này và vẫn khóa trang.
- Thêm regression NetTruyen-style có main chapter sạch + quảng cáo CSS `300x250` trong wrapper generic; dữ liệu thô tạo `SEXUAL_SERVICES/HIGH`, còn dữ liệu sau lọc phải giữ main content và loại text/contact/profile quảng cáo.
- Gia cố `page-signal-filter` bằng nhóm candidate quảng cáo mạnh/yếu, marker `adv`, `qc`, `adsbygoogle`, data attribute mới và wrapper `banner/promo/widget/slot`; wrapper yếu chỉ bị loại khi có kích thước ad chuẩn hoặc creative bên thứ ba.
- Thêm cờ `isSearchEngineHome` cho Google, Bing, DuckDuckGo, Yahoo, Brave Search và Cốc Cốc; khi Risk SAFE, UI trên trang được ẩn mặc định nhưng quét ngầm/badge/popup vẫn hoạt động, còn Risk khác SAFE vẫn cảnh báo bình thường.
- Thêm setting nâng cao `Hiện trạng thái trên trang tìm kiếm phổ biến`, mặc định tắt; bổ sung `brave.com` và `coccoc.com` vào known domains cùng 6 complex-legit case mới.
- SAFE có evidence dưới 45/100 dùng trạng thái thận trọng màu hổ phách thay vì dấu kiểm xanh; thay đổi chỉ thuộc lớp trình bày, không đổi Risk Engine.

## 2.7.1 - 2026-08-10

- Khóa trang khi `contentSafety.level === HIGH` thuộc nhóm nội dung nghiêm ngặt, kể cả khi phishing Risk riêng chưa ở mức HIGH; overlay không còn nút đóng nhanh.
- Dùng chung `STRICT_CONTENT_CATEGORY_IDS` giữa Child Mode và giao diện content-only; đường cho phép 10 phút vẫn yêu cầu gõ đúng domain khi content-safety là nguồn gây khóa.
- Thêm `modules/page-signal-filter.js` để loại vùng quảng cáo/widget có marker `ads`, `sponsor`, `banner-ad`, `quang-cao`, thuộc tính quảng cáo hoặc kích thước ad-unit chuẩn kèm tài nguyên bên thứ ba trước khi quét nội dung.
- Giữ các tín hiệu bảo mật cấu trúc như external form, script/iframe và risky download ở luồng riêng; chỉ loại quảng cáo khỏi phần gán danh mục nội dung/brand theo trang.
- Thêm fixture DOM offline chứng minh banner quảng cáo có thể kéo trang đọc truyện lên `SEXUAL_SERVICES/HIGH` trước lọc và không còn làm vậy sau lọc.
- Bổ sung release regression cho nội dung `GAMBLING` và `SEXUAL_SERVICES` first-party thật; cả hai vẫn phải đạt `HIGH` sau thay đổi.
- Việt hóa label Simple UI: `Threat Intelligence` thành `Nguồn uy tín bên ngoài`, `Cấu trúc URL & URL ML` thành `Cấu trúc địa chỉ website`; thay label HTML kỹ thuật bằng mô tả nội dung dễ hiểu.
- URL ML/dataset/threshold không thay đổi; đây là bản vá UX, consistency và DOM attribution.

## 2.7.0 - 2026-08-10

- Thêm adversarial QA harness offline `evaluation/adversarial-probe.mjs`, source manifest 24 URL fixture, 2 case structural, JSON/Markdown report và release gate cấm network primitive.
- Probe xác nhận 7/7 benign hard-negative mới không bị cảnh báo nhầm; phát hiện 5 gap cần ưu tiên ở action-token semantics, từ lóng giao dịch Việt Nam và coverage khi HTML bị cắt ở 64 KiB.
- Thêm `evidenceAssessment` với ba mức `COMPLETE`, `PARTIAL`, `INSUFFICIENT`; lưu lớp đã kiểm tra, lớp còn thiếu, dữ kiện xác minh và hành động tiếp theo.
- Khi coverage không đủ và phishing Risk vẫn SAFE, giao diện hiển thị `— / CHƯA XÁC ĐỊNH` thay vì `0/100`.
- Thêm thẻ **Phạm vi bằng chứng** trong Technical UI và trường Phạm vi trong Simple UI.
- Thêm `GAME_COMMERCE` cho tổ hợp mạnh của marketplace tài khoản/dịch vụ game, thanh toán, hành động giao dịch, liên hệ ngoài nền tảng và brand/domain mismatch.
- Thêm hard-negative cho official game domain, bài viết cảnh báo và marketplace chỉ có tín hiệu yếu; cảnh báo không phải kết luận lừa đảo/pháp lý.
- Sửa Link Lab đếm nhầm asset `.js` trong `<link>` là liên kết tải xuống; chỉ `<a>`/`<area>` có đích tệp nguy hiểm mới được tính.
- Live QA `shopvanmanh.com`: trang động có 15 nhóm marketplace, 5 nhóm giao dịch, 4 hành động và nhiều kênh ngoài nền tảng; classifier trả `GAME_COMMERCE WARNING 70/100`, phishing Risk vẫn `CHƯA XÁC ĐỊNH` nếu danh tính domain chưa đủ.
- URL ML không retrain; Accuracy 96,48%, Precision 99,46%, Recall 93,43%, FPR 0,50%; hybrid regression 20/20 và complex-legit 24/24 giữ nguyên.

## 2.6.0 - 2026-08-10

- Thêm trạng thái `CHƯA ĐỦ DỮ LIỆU`; không còn hiện dấu kiểm xanh cho kết quả SAFE thiếu content scan hoặc identity context đáng tin cậy.
- Thêm category `SCAM_COMMERCE` cho mã thẻ/seri/PIN/voucher, gift card, nạp game, khuyến mãi khó kiểm chứng và brand commerce mismatch.
- Bổ sung Roblox/Robux và Riot Games vào brand rules; brand giao dịch được đánh giá độc lập với password phishing.
- Link Lab phân tích HTML tĩnh, nâng scam-commerce mạnh lên HIGH và coi HTTP 403/lỗi mạng là chưa xác minh.
- Phát hiện vòng lặp/vượt giới hạn redirect, nâng ít nhất SUSPICIOUS và khóa Safe Preview cho chuỗi bất thường.
- Thêm regression positive cho trang nạp lậu và hard-negative cho gift-card chính thức/bài viết cảnh báo.
- URL ML v5 và metrics holdout giữ nguyên: Accuracy 96,48%, Precision 99,46%, Recall 93,43%, FPR 0,50%.

## 2.5.0 - 2026-08-10

- Hợp nhất giao diện Dễ dùng/Kỹ thuật; Simple UI trở thành mặc định với ba outcome và Link Lab rút gọn.
- Khóa focus/bàn phím/nền trang cho cảnh báo HIGH và Child Mode; thêm sticky mobile actions.
- Yêu cầu gõ đúng domain khi vượt cảnh báo nguy hiểm/blacklist; allow-once tự thu hồi sau navigation kế tiếp.
- Chuyển per-tab result sang `chrome.storage.session`; che query values/fragment trong history/CSV và payload Threat Intel.
- Link Lab bỏ probe và khóa preview cho link action-token; bổ sung cảnh báo side effect, lộ IP và giới hạn DNS rebinding.
- Thêm feedback báo nhầm cục bộ, warnings/blocks/bypasses counters và scan average/p95.
- Hoãn quét DOM khi tab ẩn, dùng idle scheduling, giảm text cap và giới hạn DOM collections.
- Giữ URL ML `url-logistic-5.0.0`; holdout Accuracy 96,48%, Precision 99,46%, Recall 93,43%, FPR 0,50%; hybrid regression 20/20.

## 2.4.0 - 2026-08-10

- Sửa false positive TikTok `/@handle`: chỉ `@` trong URL authority/userinfo mới là tín hiệu che giấu domain.
- Thêm context classifier cho public web, localhost/loopback và mạng riêng; bỏ public ML/RDAP/threat-intel khi không áp dụng.
- URL ML v5 (`url-logistic-5.0.0`, `url-lexical-v4`, 54 features) với standardized clamp ±6.
- Làm giàu 800 benign counterfactual và 479 hard negatives; independent FPR giảm 1,50% → 0,50%.
- Cảnh báo on-page cần evidence độc lập; ML-only chuyển thành badge/popup advisory.
- Brand mismatch URL chỉ xét hostname và alias chính thức, không xét brand trong path/query.
- Đổi nhãn giao diện thành “Độ bất thường URL” và “Chất lượng bằng chứng”; thêm identity/context status.
- Thêm complex-legit regression 24 ca và test TikTok/localhost/private IPv4/IPv6.

## 2.3.1 - 2026-08-10

- Sửa popup Chrome/Edge có thể co còn khoảng 39 px do `width: 100vw` trong breakpoint tham gia vòng lặp intrinsic sizing.
- Thay breakpoint bằng chiều rộng ổn định 320/420/468 px và đặt mức sàn 320 px.
- Thêm release regression kiểm tra không tái xuất hiện `width: 100vw` trong popup.
- Không thay đổi URL ML, dataset, threshold hoặc logic Link Lab/Safe Preview.

## 2.3.0 - 2026-08-10

- Thiết kế lại popup theo giao diện Signal Observatory với risk dial, telemetry, breakdown và animation có kiểm soát.
- Thiết kế lại cảnh báo nổi, cảnh báo nội dung và trang blacklist theo cùng ngôn ngữ hình ảnh.
- Thêm Link Lab để kiểm tra một URL trước khi mở mà không chạy mã trang hoặc gửi cookie.
- Probe mạng giới hạn 5 redirect, 64 KiB, 8 giây; từ chối protocol nguy hiểm, credential nhúng, localhost và IP nội bộ/dành riêng.
- Thêm nhận diện Content-Disposition, MIME tải tệp, phần mở rộng nguy hiểm, form/password, iframe, script và auto-navigation trong HTML đầu trang.
- Verdict Link Lab nâng lên HIGH khi gặp attachment/executable ngay cả khi lớp phishing riêng đang SAFE.
- Thêm Safe Preview dùng iframe sandbox/credentialless và DNR theo tab để chặn active content.
- Thêm unit/integration test cho URL guard, redirect, response cap và download finding.
- Model URL ML giữ nguyên `url-logistic-4.2.0`; metrics holdout giữ nguyên.

## 2.2.1 - 2026-08-10

- Sửa false positive trên URL bài hát/bài viết hợp lệ có nhiều path token.
- Bổ sung `hopamchuan.com` và 5 URL nội dung thật vào hard-negative regression.
- Thêm công cụ `npm run explain-url` để phân rã contribution từng feature.
- Đổi lý do sau reputation cap, không còn giữ câu “rất giống mẫu phishing” khi hybrid đã xác định SAFE.
- URL Hợp Âm Chuẩn mẫu giảm từ khoảng 93,6% xuống 6,1%.
- Holdout: Accuracy 95,98%, Precision 98,40%, Recall 93,43%, F1 95,85%, FPR 1,50%.
- Hybrid regression: 20/20.

## 2.2.0 - 2026-08-10

- Retrain URL ML v4.1 với 2.000 benign candidates và 2.000 URL độc hại.
- Thêm pipeline training thuần Node.js, dataset provenance, domain-separated splits và holdout replay.
- Thêm 250 hard negatives sạch có OAuth/path/query phức tạp với trọng số train 3.
- Thêm brand-suffix mismatch cho các thương hiệu một-suffix được bảo vệ.
- Thêm Steam content-brand detection và regression `steamcommunity.asia`.
- Independent test: Accuracy 95,98%, Precision 98,40%, Recall 93,43%, F1 95,85%, FPR 1,50%.

## 2.1.3

- Tách ML URL thô khỏi điểm ML áp dụng và kết luận hybrid.
- Hiển thị OAuth/SSO chính thức thay cho chip redirect cảnh báo.
- Xóa cache/kết quả tab cũ khi nâng cấp.
- Thêm gói store-ready và hướng dẫn chia sẻ/phát hành.

## 2.0.0 — Calibrated URL ML v3

- 55 URL/domain features.
- Platt probability calibration.
- Feedback-weighted training và hard-negative mining.
- Regression suite cho Bing, Chess, FPT, Microsoft và các official portals.
- `.php/.aspx/.jsp/.html` không còn là suspicious download extension.
- ML-only chỉ tạo SUSPICIOUS.
- Test ML độc lập: Precision 99,26%, Recall 85,44%, FPR 0,78%, F1 91,84%.

## 1.8.0 — Content & Cyber Safety

- Tách Phishing Risk và Content Safety thành hai lớp độc lập.
- Đổi nhãn SAFE thành “Không phát hiện phishing”.
- Thêm phát hiện cờ bạc/cá cược bằng từ khóa lõi, hành động đặt cược và nạp/rút tiền.
- Thêm phát hiện nội dung người lớn, dữ liệu cá nhân, danh tính giả, malware/crack, deepfake và quảng bá tài chính rủi ro.
- Thêm Content Safety Score, danh mục, lý do, khuyến nghị và disclaimer.
- Thêm badge C/C!, panel nội dung, Child Mode và lịch sử/thống kê nội dung.
- Thêm setting bật/tắt content safety và cảnh báo trên trang.
- Thêm fixture localhost và unit test content safety.
- Tham chiếu Luật An ninh mạng 116/2025/QH15 và Luật Bảo vệ dữ liệu cá nhân 2025; không đưa ra kết luận pháp lý.

## 1.7.1 — False Positive Reduction

- Sửa false positive `chess.com` bị so khớp với `chase.com`.
- Typosquatting chuyển sang so sánh nhãn đăng ký, tỷ lệ khoảng cách và adjacent transposition.
- Không ánh xạ trực tiếp threshold training `0.36` thành cảnh báo trình duyệt.
- ML dưới 90% chỉ là tín hiệu tư vấn; ML từ 90% có thể tạo MEDIUM nhưng không bao giờ tự tạo HIGH.
- Giảm ảnh hưởng ML trên domain trên 2 năm tuổi khi không có tín hiệu khác.
- Whitelist giảm thêm điểm ML nhưng không vô hiệu hóa page/redirect/threat signals.
- Thêm regression tests cho Chess.com, Microsoft.com và các typo thật.

## 1.7.0

- Thêm Logistic Regression URL model thật với 31 lexical features.
- Huấn luyện trên 2.000 URL và group split theo registrable domain.
- Thêm `modules/url-ml-features.js`, `modules/url-model.js` và `data/url-model.json`.
- Tích hợp ML vào Risk Engine, popup và settings.
- Thêm pipeline tái huấn luyện trong `ml/`.
- Thêm model comparison, test predictions và training report.
- Thêm kiểm thử parity Python/JavaScript.
- Đổi binary PHISHING threshold về 30; mức 10–29 chỉ là SUSPICIOUS.

## 1.6.0

- Thêm SUSPICIOUS và threshold calibration trên pilot 100 URL.

## 1.9.0 — Family Safety & URL ML v2

- Thêm category `SEXUAL_SERVICES` và bộ tín hiệu từ khóa, booking, liên hệ và hồ sơ.
- Child Mode v2: strict/standard, require-content-scan, auto-speak và lời nhắc không gửi ảnh/vị trí/chuyển tiền.
- Popup phân biệt chưa quét với đã quét không phát hiện.
- URL feature extractor v2 với tracking-parameter normalization và 35 features.
- Hard-negative training chỉ trên train domains.
- Model mới `url-logistic-2.0.0`.
- Giảm false positive cho URL hợp lệ dài trên domain lâu năm/đã biết.

## 2.1.0

- Tách thành bản Dễ dùng và bản Kỹ thuật.
- Bản Dễ dùng có giao diện 3 mục, câu trả lời trực tiếp và ẩn thông số ML/RDAP mặc định.
- Bản Kỹ thuật giữ dashboard đầy đủ và thêm xuất/sao chép chẩn đoán JSON đã che query.
- Phân biệt rõ chưa quét nội dung với đã quét không phát hiện.
- Nút hành động thay đổi theo mức rủi ro; whitelist yêu cầu xác nhận.
- Các thay đổi nhạy cảm khi Child Mode bật yêu cầu PIN.
- Dùng chung Risk Engine hybrid và URL ML v3; ML đơn lẻ không tạo MEDIUM/HIGH.

## 2.1.1 — Official Portal False-Positive Patch

- External script/iframe counts no longer add phishing risk by themselves.
- OAuth/SSO encoded query values are no longer treated as heavy path encoding.
- Password fields only corroborate strong independent risk.
- Federated “Login with Google/Microsoft” controls no longer trigger brand mismatch.
- Added Steam, Facebook Group Call and FEID FPT hard negatives/feedback.
- Retrained URL model as `url-bagged-logistic-3.1.0`.
