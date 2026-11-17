# Tính năng v2.7.5

## GUI cuối và song ngữ

- Simple/Technical/Child có thể đổi Việt/Anh tức thời; ngôn ngữ được lưu ở local storage.
- Bản English dịch navigation, verdict, Link Lab, coverage, settings, history, content safety, PIN, placeholder và aria-label chuẩn.
- Bố cục giữ đủ thông số nhưng gọn hơn; responsive ở 320/420/468/520/620/700 px và touch target chính >=44 px.
- SAFE đã xác định (`COMPLETE + DETERMINED`) dùng màu xanh nhất quán; `PARTIAL/INSUFFICIENT` vẫn amber.

## Verified game top-up brand protection

- Rule thương hiệu nằm trong `data/brand-rules.json`, không còn hardcode trong `content.js`; loader chuẩn hóa domain, alias, nguồn và trạng thái xác minh trước khi quét trang.
- Phủ Garena/Free Fire/Liên Quân/FC Online/FC Mobile, VNG Games/Zing và VTC Game/Vcoin cùng cổng nạp đã xác minh theo registrable domain.
- Tự nhận chính thức/đối tác, dùng thương hiệu game đã biết trên domain sai và yêu cầu ID game/mã thẻ là tổ hợp cảnh báo mạnh độc lập.
- `data/protected-game-domains.json` chỉ làm typo/homoglyph reference (`trustAllowlist: false`), không tự biến domain thành trusted/known.
- Regression ghép cặp official/impostor dùng nội dung tương đương, gate cả báo nhầm trang thật và bỏ sót trang giả.

## Domain age & payment evidence

- Domain 365-729 ngày dùng tier `MODERATELY_ESTABLISHED`; chỉ domain từ 730 ngày mới được reputation cap của Risk Engine.
- Detector payment yêu cầu checkout context, control tương tác, số tiền/hành động và evidence ZaloPay/VietQR/MoMo/VNPay/NAPAS/Visa/Mastercard ngoài vùng quảng cáo.
- Payment integration chỉ tăng evidence coverage tối đa 20 điểm, không giảm Risk và tự tắt khi có bằng chứng nguy hiểm độc lập.
- Protected payment domains chỉ dùng làm typosquat/homoglyph reference có nguồn, không phải known-domain hay allowlist.
- RDAP fail vẫn để lại identity gap; nếu các lớp khác sạch, kết quả có thể là `PROVISIONAL` với label hỗ trợ thay vì greenlight tuyệt đối.

## UI consistency & search quiet mode

- Bar/panel không khóa neo ở góc dưới bên phải, có responsive 320/420/468/520/620/700 px và tự thu gọn khi click ngoài, chọn văn bản hoặc mở context menu trên trang gốc.
- Label có thể co/ellipsis trong khi score `100/100` giữ một dòng; metric value không còn bị cắt bởi `overflow:hidden`.
- Overlay HIGH/strict vẫn toàn màn hình, không tự thu gọn và giữ security lock/focus trap.
- Google, Bing, DuckDuckGo, Yahoo, Brave Search và Cốc Cốc có cờ `isSearchEngineHome`; SAFE UI được ẩn mặc định nhưng Risk khác SAFE vẫn cảnh báo.
- SAFE evidence dưới 45/100 dùng tone thận trọng thay vì dấu kiểm xanh; Risk Engine và URL ML không thay đổi.
- Regression NetTruyen-style kiểm tra quảng cáo CSS-size trong wrapper generic; bộ lọc dùng marker mạnh/yếu và third-party creative thay vì hardcode domain.

## Content lock & ad-aware attribution

- Content Safety `HIGH` thuộc nhóm nghiêm ngặt dùng overlay khóa nền, không có nút đóng nhanh và bắt buộc xác nhận domain khi cho phép tạm.
- Vùng `ads`, `sponsor`, `banner-ad`, `quang-cao`, data-ad hoặc ad-unit chuẩn kèm tài nguyên bên thứ ba được loại khỏi body text và selector nội dung.
- External form/script/iframe và risky download vẫn được giữ trong lớp bảo mật riêng để việc lọc quảng cáo không che mất hành vi nguy hiểm.
- Regression DOM offline bao gồm false-positive quảng cáo nhúng và positive first-party `GAMBLING`/`SEXUAL_SERVICES`.
- Simple UI dùng nhãn tiếng Việt dễ hiểu cho cấu trúc địa chỉ, nguồn uy tín bên ngoài và nội dung xem trước.

## Coverage-aware protection

- Risk chưa đủ dữ liệu hiển thị `— / CHƯA XÁC ĐỊNH`, không dùng `0/100` như một tín hiệu an toàn giả.
- `evidenceAssessment` phân loại `COMPLETE`, `PARTIAL`, `INSUFFICIENT` và lưu lớp đã kiểm tra, lớp còn thiếu, dữ kiện xác minh, hành động đề xuất.
- Technical UI có thẻ **Phạm vi bằng chứng**; Simple UI hiển thị tóm tắt phạm vi ngay cạnh Risk và Evidence.
- `GAME_COMMERCE` nhận diện tổ hợp mạnh của marketplace tài khoản/dịch vụ game, hành động giao dịch, thanh toán, liên hệ ngoài nền tảng và thương hiệu trên domain bên thứ ba.
- `SCAM_COMMERCE` nhận diện tổ hợp mã thẻ/seri/PIN/voucher, nạp game, thương hiệu ngoài domain chính thức, hành động giao dịch và cam kết khuyến mãi.
- Official game domain, bài viết/wiki/cảnh báo và marketplace chỉ có tín hiệu yếu được giữ làm hard-negative.
- Child Mode coi giao dịch game bên thứ ba và scam-commerce là nhóm cần người lớn xác minh.
- Thống kê cục bộ tách `Mã trả trước cần xác minh` và `Giao dịch game bên thứ ba`.

## Unified consumer experience

- Một package duy nhất với giao diện `simple` mặc định và giao diện `technical` theo yêu cầu.
- Simple UI hiển thị rõ **TRANG ĐANG MỞ**, ba outcome, tối đa ba lý do, hành động an toàn chính và Link Lab rút gọn.
- Technical UI giữ Risk Score, evidence quality, RDAP, redirect, ML contribution, lịch sử, telemetry, audit và xuất chẩn đoán.
- Chuyển profile ngay trong popup; hai profile dùng chung một kết quả hybrid, không có model riêng.
- Responsive 320/420/468 px; đã kiểm tra không horizontal overflow ở 320 px.

## Interaction safety

- Cảnh báo HIGH/Child Mode dùng `inert`, focus trap và capture guard cho keydown/beforeinput/input/submit.
- Nút quay lại là focus mặc định; action footer sticky trên màn hình nhỏ.
- HIGH, blacklist, Threat Intel unsafe và Content HIGH yêu cầu gõ đúng domain trước khi bỏ qua.
- Allow-once dùng DNR session rule có metadata và tự consume ở top-level `webNavigation.onCommitted` kế tiếp.
- Phản hồi **Báo nhầm** được lưu cục bộ theo domain/reasons, không có remote telemetry mặc định.

## Context-aware scanning

- Phân loại URL thành `PUBLIC_WEB`, `LOCAL_DEVELOPMENT` hoặc `PRIVATE_NETWORK`.
- localhost, loopback, IP riêng và hostname nội bộ không bị phạt vì HTTP/IP/port khác chuẩn.
- RDAP, public threat intelligence và URL ML công cộng được bỏ qua trong ngữ cảnh local/private.
- Blacklist, redirect, external password form, brand mismatch, urgency và risky download vẫn hoạt động.

## Phishing detection

- Hybrid Risk Engine tách threat intel, domain, URL, network, page behavior và URL ML.
- URL ML v5 chạy cục bộ, 54 features, Platt calibration và standardized clamp ±6.
- `@` chỉ được coi là che giấu đích khi URL parser thấy username/password; `/@handle` là path bình thường.
- Brand token mismatch chỉ xét hostname và danh sách alias domain chính thức.
- ML đơn lẻ chỉ tạo `BADGE_ADVISORY`; panel on-page cần tín hiệu độc lập hoặc cụm lexical rõ ràng.
- Identity status: local development, private network, known/popular, official suffix, established, new hoặc unverified.
- Public Suffix List, RDAP cache, typosquatting, brand-suffix mismatch, homoglyph/Punycode, blacklist/whitelist và DNR blocking.
- Redirect server/client, cross-domain chain, HTTPS downgrade, external password form và executable/archive download link.

## Dữ liệu và evaluation

- 2.000 benign candidates + 2.000 phishing/malware.
- 800 benign counterfactual path/query trong split độc lập theo domain.
- 479 hard negatives chỉ-train, trọng số 2.
- Independent holdout: Accuracy 96,48%, Precision 99,46%, Recall 93,43%, F1 96,35%, FPR 0,50%.
- 34 complex regression (33 SAFE + 1 threat control): URL ML thô còn 1 FP trên case official, Hybrid Risk Engine đạt 0 FP/FN, 0 on-page warning trên case SAFE và cặp official/impostor đạt 1/1.
- Regression riêng cho TikTok `/@handle`, OAuth/SSO, long path/query, `.php/.aspx/.jsp`, localhost và mạng riêng.

## Signal Observatory UI

- Risk dial, **Chất lượng bằng chứng**, tuổi domain, redirect, identity/context và phân rã từng lớp.
- Risk dial hiển thị `CHƯA XÁC ĐỊNH` khi coverage không đủ; không suy diễn score nội bộ bằng 0 thành kết luận an toàn.
- “Độ bất thường URL” thay cho nhãn ML thô có thể bị hiểu như kết luận.
- Badge `i` màu xanh cho advisory không đủ bằng chứng; `?`, `!`, `!!` dành cho mức tăng dần.
- Responsive 320/420/468 px, motion có `prefers-reduced-motion`.

## Link Lab & Safe Preview

- Ô nhập URL để quét trước khi mở.
- Probe tối đa 5 redirect, 64 KiB, 8 giây; không cookie/referrer và không chạy code trang.
- Từ chối protocol không phải HTTP(S), credential nhúng, localhost và IP nội bộ/dành riêng.
- Phát hiện content-disposition, MIME tải tệp, executable/archive extension, form/password, script, iframe và auto-navigation.
- Phân tích phần HTML tĩnh để nhận diện scam-commerce và cờ bạc mà không chạy mã trang.
- Chỉ coi `<a>`/`<area>` trỏ tới executable/archive là liên kết tải; asset `.js` trong `<link>` không tạo cảnh báo tải giả.
- HTTP không thành công, lỗi mạng, vòng lặp hoặc chuỗi chuyển hướng quá dài không được trình bày như xác nhận an toàn.
- Khóa Safe Preview khi phát hiện action-token hoặc bất thường chuyển hướng.
- Safe Preview dùng iframe sandbox/credentialless và DNR theo tab để chặn active content.
- Phiên tạm lưu trong `chrome.storage.session`, không ghi URL đầy đủ vào lịch sử Link Lab.
- Nhận diện reset/verify/confirm/magic-login/unsubscribe/invite/action token; bỏ network probe và khóa preview/open để tránh tiêu thụ token.
- Ghi rõ probe có thể lộ IP, GET có thể có tác động phía máy chủ và literal-host filtering chưa loại trừ hoàn toàn DNS rebinding.

## Privacy & performance

- Kết quả phân tích theo tab chỉ tồn tại trong `chrome.storage.session`; migration xóa numeric keys cũ khỏi local storage.
- History/CSV che toàn bộ query value và bỏ fragment; Threat Intel nhận payload tối thiểu đã redacted.
- Quét DOM dừng/reschedule khi tab ẩn, ưu tiên `requestIdleCallback`, giảm text cap còn 120 KiB và giới hạn số node mỗi nhóm.
- Thống kê cục bộ bổ sung warnings, blocks, bypasses, false-positive feedback, scan average và scan p95.

## Content & Family Safety

- Giao dịch mã trả trước cần xác minh: thẻ cào, mã/seri/PIN, voucher, gift card và nạp tiền/vật phẩm game ngoài kênh chính thức.
- Giao dịch game bên thứ ba cần xác minh: acc tự chọn, mua/bán/thu acc, deadmail/dropmail, cày thuê/rank, chuyển vùng/check skin, thanh toán và liên hệ ngoài nền tảng.
- Cờ bạc/cá cược; nội dung người lớn; dịch vụ tình dục/môi giới nhạy cảm.
- Thu thập dữ liệu cá nhân; danh tính giả; SIM/OTP/tài khoản rác; giấy tờ giả.
- Crack/keygen/cheat/APK mod; malware; deepfake; quảng bá tài chính rủi ro.
- Child Mode với PIN PBKDF2-SHA-256, hai mức bảo vệ và cảnh báo toàn màn hình khi có bằng chứng phù hợp.

