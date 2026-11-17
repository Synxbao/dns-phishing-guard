# Báo cáo trải nghiệm DNS Phishing Guard v2.7.4

Ngày đánh giá: 2026-08-11

## Phương pháp

Đánh giá dùng đúng fixture đã thêm cho 5 fix, không mở domain phishing thật và không gọi RDAP/network thật trong adversarial probe. Các nguồn bằng chứng gồm `npm run validate`, cặp official/impostor Garena, fixture payment chính thống, fixture NetTruyen-style ad bleed-through, content-safety HIGH, 6 search-engine case và Browser QA popup tại 468×800/320×800.

Đây là QA offline + browser layout preview, chưa phải thử nghiệm end-to-end bằng extension đã cài trên Chrome/Edge production.

## Persona 1 - Pentester

### Fix 1: Content Safety HIGH

- Thử đường phishing Risk SAFE nhưng content category nghiêm ngặt HIGH: overlay vẫn khóa vì điều kiện OR đã bao gồm content layer.
- Không có nút `×`; nền trang bị inert/capture guard, focus nằm trong cảnh báo và bypass 10 phút yêu cầu gõ đúng domain.
- Đánh giá: sửa đúng cơ chế gốc của policy enforcement, không chỉ đổi màu hoặc label.

Điểm: **9,3/10**. Rủi ro còn lại nằm ở độ chính xác của classifier category; lock thực thi đúng nhưng classifier false positive vẫn có thể gây friction.

### Fix 2: Ad bleed-through

- Fixture main chapter sạch + banner `300x250` chứa profile/contact nhạy cảm tái hiện `SEXUAL_SERVICES/HIGH` trước lọc.
- Sau lọc, text/profile/contact trong ad region bị loại; main content được giữ.
- First-party `SEXUAL_SERVICES` và `GAMBLING` vẫn HIGH 2/2.
- Cách né còn lại: native ad không marker, không kích thước chuẩn, dùng cùng origin và trộn trực tiếp vào article/container chính.

Điểm: **8,5/10**. Sửa đúng điểm attribution trước classifier nhưng bản chất vẫn là heuristic DOM.

### Fix 3: Moderate age/payment evidence

- Domain 420 ngày + ML 97% vẫn `MODERATELY_ESTABLISHED`, `mlReduction = 0`, score trên 8: sleeper domain không hưởng cap >=730 ngày.
- 5 case giả ZaloPay/VietQR/Vietcombank/MoMo/Punycode chèn logo thật vẫn HIGH, payment boost 0.
- Payment signal chỉ tăng coverage, không giảm Risk và không xác thực merchant.
- Cách lợi dụng còn lại: sleeper domain có lịch sử sạch, checkout rất giống thật và chưa có threat/brand mismatch vẫn có thể đạt evidence tốt hơn; các lớp khác phải tiếp tục giám sát.

Điểm: **8,7/10**. Cơ chế có guard tốt, nhưng tuổi domain và logo/payment context không bao giờ là bằng chứng tuyệt đối.

### Fix 4: Brand game Việt Nam

- `Gare​na` có zero-width và `Free-Fire` có separator vẫn được chuẩn hóa, official-claim mismatch vẫn kích hoạt.
- Official `napthe.vn`: SAFE 8, content NONE, evidence CONFIDENT 48.
- Reserved impostor: HIGH 100, `SCAM_COMMERCE + GAME_COMMERCE`, positive boost 0.
- Official-claim + brand + ID/serial/PIN trên domain sai tự đủ mạnh, không phụ thuộc hoàn toàn vào typo.
- Cách né còn lại: logo chỉ nằm trong ảnh/canvas, closed shadow DOM, brand viết biến thể ngữ nghĩa chưa có trong dataset, hoặc trang không claim “official” và chọn domain không gần baseline.

Điểm: **8,9/10**. Đã giải quyết nguyên nhân gốc là thiếu dữ liệu/rule runtime; coverage brand vẫn cần bảo trì liên tục.

### Fix 5: Search/UI

- Search-engine SAFE bị ẩn trên trang nhưng vẫn quét ngầm; verdict không SAFE không được miễn cảnh báo.
- Popup 468/320 px không horizontal overflow và không cắt text quan trọng.
- Native context menu vẫn có thể nằm trên extension; panel không khóa tự thu gọn, overlay HIGH không thu gọn.
- Cách né/giới hạn: trang gốc có fixed widget ở góc dưới phải vẫn có thể cạnh tranh không gian; content script không thể dự đoán mọi layout hoặc đặt UI lên trên menu OS.

Điểm: **8,8/10**. Polish tốt và có regression, nhưng overlap với mọi website không thể bảo đảm tuyệt đối.

## Persona 2 - Người dùng phổ thông

- `napthe.vn`: không còn amber “CHƯA ĐỦ DỮ LIỆU”; kết quả là SAFE, evidence `CONFIDENT 48/100`, không hiện cảnh báo trên trang.
- `napthevn.example`: cảnh báo HIGH rõ, khóa trang và nêu đúng việc địa chỉ gần domain chính thức nhưng claim/domain không khớp.
- Bing/Google và các search engine đã khai báo: không còn bar xanh/amber khi Risk SAFE mặc định.
- Trang đọc truyện với banner nhúng: nội dung quảng cáo không còn bị quy cho website trong fixture cố định.
- Popup ở 320 px vẫn đọc và thao tác được; navigation, card Risk và Link Lab không tràn ngang.

Điểm trải nghiệm tổng: **9,2/10**. Điểm trừ chính là cảnh báo heuristic vẫn cần một đường “báo nhầm” rõ và dữ liệu brand cần cập nhật khi nhà phát hành đổi đối tác.

## Persona 3 - Người không rành kỹ thuật

Ba lý do đầu cho impostor được ưu tiên như sau:

1. “Địa chỉ website này rất giống `napthe.vn`, một địa chỉ chính thức đã được xác minh.”
2. “Trang tự nhận là chính thức hoặc đối tác của Garena, nhưng địa chỉ hiện tại không khớp hệ thống chính thức.”
3. “Trang yêu cầu ID game hoặc mã thẻ (số serial/PIN); nhập vào có thể làm mất tiền hoặc tài khoản.”

Các lý do này diễn đạt hậu quả và hành động, không yêu cầu người dùng hiểu ML, RDAP, typosquat hay evidence layer.

Với content-safety HIGH, overlay không có nút đóng, có nút quay lại nổi bật, không bấm xuyên nền và bypass buộc gõ đúng domain. Trải nghiệm đủ nghiêm túc nhưng vẫn có lời giải thích và lựa chọn có chủ đích, không chỉ hiển thị màn đỏ gây hoảng.

Điểm: **9,3/10**. Giới hạn còn lại là người dùng vẫn có thể cố tình gõ domain để bypass; đây là quyền chủ động có ma sát, không phải khóa tuyệt đối.

## Tổng hợp

| Fix | Trạng thái | Điểm Pentester | Điểm User thường | Điểm User phổ thông |
| --- | --- | ---: | ---: | ---: |
| 1. Content HIGH security lock | Đã sửa, có test tự động | 9,3 | 9,3 | 9,4 |
| 2. Ad/widget bleed-through | Sửa cơ chế chính, còn giới hạn heuristic | 8,5 | 9,0 | 8,9 |
| 3. Moderate age + payment evidence | Đã sửa có guard; còn rủi ro sleeper/payment imitation | 8,7 | 9,0 | 8,8 |
| 4. Game top-up brand discrimination | Đã sửa và có cặp đối chứng; còn coverage/ảnh-only | 8,9 | 9,5 | 9,4 |
| 5. Search quiet mode + UI overlap | Đã sửa phần kiểm soát được; context menu OS là giới hạn nền tảng | 8,8 | 9,3 | 9,2 |

## Kết luận

v2.7.4 đạt mục tiêu sử dụng chính: cổng nạp chính thức không còn bị amber do thiếu evidence, cổng giả lập gần giống bị tách lên HIGH rõ rệt, content HIGH thực sự khóa trang, ad bleed-through có regression cố định và search page an toàn không còn bị bar che khuất.

Không nên tuyên bố “triệt để” cho Fix 2, 3, 4 và 5. Bản sau nên ưu tiên image/canvas brand OCR có kiểm soát, telemetry false-positive cho ad attribution, temporal/sleeper-domain evidence và browser E2E trên Chrome/Edge đã cài extension.

