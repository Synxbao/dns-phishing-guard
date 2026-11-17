# Báo cáo hậu kiểm trải nghiệm DNS Phishing Guard v2.5.0

Ngày đánh giá: 2026-08-10 (Asia/Saigon)

## Kết luận điều hành

Điểm 9,2 / 9,1 / 9,0 trong review trước là ước tính nội bộ và không còn hợp lệ.
Ca thực tế do người dùng cung cấp đã tái hiện một false negative nghiêm trọng:

- URL: `https://www.naplau.com/nap-lau-roblox/index.html`
- Extension hiển thị banner xanh `KHÔNG PHÁT HIỆN PHISHING`.
- Risk score: `0/100`; chất lượng bằng chứng: `26/100`.
- Trang công khai quảng bá "nạp lậu Robux", yêu cầu ID game, thẻ cào, số seri và mã thẻ.
- URL ML v5 dự đoán `SAFE` với xác suất bất thường `45,70%`, dưới ngưỡng `59%`.

Không có đủ bằng chứng trong lần kiểm tra này để đưa ra kết luận pháp lý rằng website
chắc chắn là phishing hoặc lừa đảo. Tuy nhiên, có đủ bằng chứng để kết luận rằng một
banner xanh kèm dấu kiểm và điểm `0/100` là không phù hợp với mục tiêu bảo vệ người
dùng trước website có giao dịch không chính thức, thu giá trị thẻ cào và dùng thương
hiệu game trên domain không chính thức.

Phán quyết phát hành:

- Bộ hồi quy kỹ thuật hiện tại: **PASS**.
- Beta nội bộ cho người hiểu giới hạn: **PASS có điều kiện**.
- Phát hành rộng như công cụ bảo vệ người dùng phổ thông khỏi lừa đảo: **HOLD**.

## Phạm vi và phương pháp

### Bằng chứng quan sát trực tiếp

1. Ảnh chụp runtime từ Edge/Chromium cho thấy banner xanh trên trang đang mở, với
   risk `0/100` và bằng chứng `26/100`.
2. Tải tĩnh tối đa một phản hồi HTML bằng request không cookie, không đăng nhập,
   không nhập dữ liệu và không chạy JavaScript của website.
3. Phản hồi trả HTTP `200`, khoảng 32 KiB HTML, không có CSP hoặc X-Frame-Options
   trong phản hồi quan sát được.
4. Nội dung tĩnh có 17 lần nhắc `Roblox`, 14 lần nhắc `nạp lậu`, 4 lần nhắc
   `thẻ cào`, cùng các cụm `mã thẻ`, `số seri`, `x2` và `cam kết 100%`.
5. RDAP cho thấy `naplau.com` đăng ký ngày 2021-09-01, khoảng 1.803 ngày tại thời
   điểm kiểm tra. Domain lâu năm không chứng minh website an toàn.

### Kiểm chứng cục bộ

- `npm run validate`: PASS.
- Independent URL holdout: TP/TN/FP/FN = `185/199/1/13`.
- Accuracy `96,48%`; precision `99,46%`; recall `93,43%`; FPR `0,50%`; FNR `6,57%`.
- Hybrid release regression: `20/20`.
- Complex-legit regression: 24 ca, không có false positive.
- `npm run explain-url -- <naplau URL>`: probability `0,456959`, prediction `SAFE`.
- Danh sách 13 false negative trong holdout có nhiều URL ngắn, sạch về hình thức;
  ví dụ `timtv.biz`, `pubgm.games` và `uni-stake.com`. Đây là giới hạn tự nhiên của
  mô hình lexical chỉ nhìn cấu trúc URL.

### Giới hạn đánh giá

- Không gửi ID game, mã seri, mã thẻ, tiền hoặc dữ liệu cá nhân.
- Không kích hoạt luồng giao dịch và không chạy JavaScript của website trong môi
  trường phân tích.
- Không dùng kết quả này để kết luận pháp lý về chủ website.
- Chưa chạy E2E tự động trong profile Chrome/Edge do nhóm kiểm thử kiểm soát và đã
  cài unpacked extension; ảnh runtime do người dùng cung cấp là bằng chứng thực tế
  cho ca false negative này.
- Điểm số dưới đây vẫn là đánh giá nội bộ, chưa thay thế pilot người dùng độc lập.

## Ma trận kết quả chính

| Luồng | Kỳ vọng theo mục tiêu sản phẩm | Kết quả | Đánh giá |
| --- | --- | --- | --- |
| Website hợp pháp có URL phức tạp | Không cảnh báo nhầm | 24/24 complex-legit không cảnh báo | PASS |
| OAuth/SSO, TikTok `/@handle`, localhost | Hiểu đúng ngữ cảnh | Bộ hồi quy PASS | PASS |
| Cảnh báo HIGH và bypass | Khóa tương tác, xác nhận domain | Source/module regression PASS | PASS có giới hạn E2E |
| Quyền riêng tư URL/token | Không lưu hoặc gửi query nhạy cảm | Regression PASS | PASS |
| Website giao dịch "nạp lậu" bằng thẻ cào | Ít nhất phải cảnh báo cần xác minh | Banner xanh, risk `0/100` | **FAIL nghiêm trọng** |
| Độ trung thực của banner SAFE | Không tạo cảm giác được bảo đảm khi bằng chứng thấp | Dấu kiểm xanh dù evidence `26/100` | **FAIL** |

## Đánh giá theo ba vai trò

### 1. Người kiểm thử phần mềm — 6,3/10

Điểm tốt:

- Pipeline model, holdout replay, release regression và benchmark có thể tái lập.
- Bộ test false-positive cho URL hợp pháp phức tạp tốt và giải quyết đúng vấn đề
  cảnh báo nhầm trước đây.
- Các chốt focus, bypass, URL privacy và action-token được kiểm tra bằng regression.
- Metrics không che giấu FNR `6,57%` của URL model.

Điểm làm giảm mạnh:

- Release gate `20/20` quá nhỏ và không có nhóm scam-commerce, gift-card abuse,
  game top-up giả, brand abuse không dùng password hoặc giao dịch thẻ cào.
- Ca thực tế vượt qua URL ML, page behavior, content safety và lớp trình bày cùng lúc.
- Không có E2E browser tự động để xác minh quyết định cuối trên các trang thật đại diện.
- Review cũ nâng điểm dựa trên hoàn thành checklist, chưa thử đủ các failure mode sát
  mục tiêu kinh doanh của sản phẩm.

Nhận định: nền tảng kiểm thử tốt cho hồi quy đã biết, nhưng coverage chưa đại diện cho
"bảo vệ người dùng khỏi website lừa đảo". Một P0 lọt qua khiến release chưa đạt 9.

### 2. Người dùng phổ thông — 4,8/10

Điểm tốt:

- Banner dễ nhìn, tiếng Việt rõ và trạng thái màu sắc dễ hiểu.
- Khi hệ thống phát hiện HIGH, hành động quay lại và hướng dẫn không nhập OTP/mật khẩu
  được thiết kế tốt.
- Popup Simple giảm đáng kể thuật ngữ kỹ thuật so với v2.4.0.

Điểm nguy hiểm trong trải nghiệm thật:

- Người dùng phổ thông thường hiểu dấu kiểm xanh là "website an toàn", dù câu chữ chỉ
  nói "không phát hiện phishing".
- Risk `0/100` củng cố niềm tin sai trong khi evidence chỉ `26/100`.
- Trang đang yêu cầu tài sản có giá trị tương đương tiền là mã thẻ cào; một false
  negative ở đây có thể dẫn trực tiếp tới mất tiền.
- Người dùng không có lý do để mở Technical mode sau khi extension đã chủ động xác
  nhận bằng màu xanh.

Nhận định: giao diện đẹp nhưng kết luận sai ở đúng thời điểm người dùng cần bảo vệ nhất
làm trải nghiệm consumer chưa an toàn.

### 3. Người thường xuyên truy cập nhiều website — 5,4/10

Điểm tốt:

- Ít cảnh báo nhầm, không để raw ML đơn lẻ chặn trang và hiểu URL hợp pháp phức tạp.
- Có lịch sử, thống kê, p95 scan, feedback báo nhầm và Technical mode.
- Quét URL cục bộ rất nhanh; overhead lexical gần như không đáng kể.

Điểm còn thiếu:

- Tối ưu giảm false positive đã tạo khoảng trống false negative đối với domain lâu năm
  và URL ngắn, sạch về hình thức.
- Người duyệt nhiều trang sẽ gặp nhiều website thương mại ngách; chỉ dựa vào cấu trúc
  URL và password form không đủ để đánh giá rủi ro giao dịch.
- Không có nhóm cảnh báo riêng cho gift card, mã nạp, game currency, giao dịch ngoài
  kênh chính thức hoặc cam kết khuyến mãi bất thường.
- Một lần greenlight sai có thể làm mất niềm tin vào mọi kết quả sau đó.

Nhận định: extension ít gây phiền, nhưng độ bao phủ hành vi thực tế chưa đủ cho người
dùng duyệt web cường độ cao.

## Findings ưu tiên

### P0 — Banner xanh cho website giao dịch rủi ro khi bằng chứng thấp

Quan sát: extension hiển thị dấu kiểm xanh, `0/100`, evidence `26/100` trên trang thu
ID game và giá trị thẻ cào để đổi lấy Robux ngoài domain chính thức.

Tác động: người dùng có thể coi extension như xác nhận uy tín và gửi mã thẻ có giá trị.
Đây là failure trực tiếp của mục tiêu bảo vệ người dùng, bất kể website có đáp ứng định
nghĩa hẹp của credential phishing hay không.

Khuyến nghị:

- Không hiển thị trạng thái xanh khi confidence/evidence dưới ngưỡng tối thiểu, ví dụ
  `< 55/100`; dùng trạng thái xám/vàng `Chưa đủ dữ liệu để đánh giá`.
- Đổi `0/100` thành `Không ghi nhận tín hiệu trong phạm vi đã quét` khi coverage thấp.
- Dấu kiểm xanh chỉ xuất hiện khi content scan hoàn tất và không có lớp nào chưa áp dụng.

### P0 — Thiếu lớp phát hiện scam-commerce và thẻ nạp trả trước

Page scanner hiện nhận dạng password, form password khác origin, urgency, brand mismatch
và file thực thi, nhưng không coi `mã thẻ`, `số seri`, `thẻ cào`, `gift card`, `voucher`,
`game top-up` hoặc lời hứa nhân đôi là tài sản nhạy cảm.

Khuyến nghị:

- Thêm category `SCAM_COMMERCE` hoặc `PREPAID_VALUE_ABUSE` tách khỏi phishing pháp lý.
- Thu thập tín hiệu input cho mã thẻ, seri, voucher, gift card, PIN nạp tiền và game ID.
- Kết hợp ít nhất hai lớp: thu mã trả trước + thương hiệu/domain không khớp; hoặc thu mã
  trả trước + khuyến mãi/cam kết bất thường; hoặc giao dịch ngoài kênh chính thức.
- Cảnh báo `CẦN XÁC MINH` mặc định; nâng HIGH khi có thêm blacklist, threat intel,
  brand impersonation rõ hoặc form gửi sang origin khác.

### P1 — Brand mismatch bị khóa sau điều kiện có password

`content.js:264` chỉ chạy toàn bộ brand analysis khi trang có input password. Trang này
nhắc Roblox nổi bật nhưng không hỏi password, nên brand mismatch không thể được tạo.
Ngoài ra, `BRAND_RULES` tại `content.js:15` chưa có Roblox hoặc các nhà phát hành/game
phổ biến tại Việt Nam.

Khuyến nghị:

- Tách brand identity khỏi password detection.
- Chỉ cảnh báo khi brand xuất hiện nổi bật và có hành động nhạy cảm như đăng nhập,
  thanh toán, nạp tiền, gửi mã thẻ hoặc tải tệp.
- Dùng danh sách brand/domain có phiên bản và test cả positive lẫn negative để tránh
  biến mọi bài báo nhắc Roblox thành cảnh báo.

### P1 — Bộ đánh giá chưa đại diện cho mục tiêu sản phẩm

Dataset 4.000 URL và holdout đo khả năng phân loại lexical, không đo nội dung giao dịch
sau khi trang tải. Bộ hybrid 20 case chủ yếu là hồi quy đã biết. Vì vậy accuracy `96,48%`
không trả lời câu hỏi: "extension có bảo vệ người dùng khỏi website lừa đảo thương mại
ngách hay không?"

Khuyến nghị:

- Tạo corpus page-level có nhãn cho game top-up, gift card, marketplace, tech support,
  fake shop, investment, romance/Telegram và brand abuse không có password.
- Bổ sung ít nhất 100 positive và 200 hard-negative trước release tiếp theo.
- Chia train/test theo registrable domain và theo thời gian; không đưa domain cùng họ
  vào cả hai phía.
- Đo false-negative rate theo từng nhóm hành vi, không chỉ một FNR tổng.

### P1 — Phạm vi tên sản phẩm và thông điệp chưa đồng nhất

Risk engine đang tối ưu cho phishing kỹ thuật, trong khi mục tiêu người dùng là phát hiện
phishing **và lừa đảo**. Một website có thể không ăn cắp mật khẩu nhưng vẫn lấy tiền/mã
thẻ bằng giao dịch gian dối hoặc không được xác minh.

Khuyến nghị:

- Giữ `Phishing Risk` riêng để tránh làm sai metrics.
- Thêm `User Protection Verdict` tổng hợp phishing, scam-commerce, content safety,
  download và threat intelligence.
- Trên banner, ưu tiên verdict bảo vệ người dùng thay vì chỉ verdict phishing.

## Nguyên nhân gốc trong mã

- `content.js:15`: danh sách brand giới hạn, chưa có Roblox.
- `content.js:100` và `content.js:105`: financial/sensitive fields không bao phủ mã
  thẻ cào, seri, voucher hoặc gift card.
- `content.js:264`: brand mismatch chỉ được tính khi có password input.
- `modules/risk-engine.js:430`: risk engine chỉ nhận brand mismatch đã được content
  script tạo; không có fallback cho brand + giao dịch.
- `modules/content-safety.js`: chưa có category cho scam-commerce hoặc prepaid value.
- `content.js:566`: SAFE dùng dấu kiểm xanh và nhãn mạnh.
- `content.js:975`: khi người dùng bật safe banner, SAFE được hiển thị mà không có
  minimum confidence gate.
- `modules/risk-engine.js:586`: score `0` chỉ giới hạn confidence tối đa 45, nhưng UI
  vẫn trình bày màu xanh thay vì trạng thái chưa đủ dữ liệu.

## Điều kiện để đạt 9/10 thực sự

1. Ca `naplau.com/nap-lau-roblox/index.html` phải trả ít nhất `CẦN XÁC MINH`, không
   được xanh, mà không hardcode riêng domain.
2. Thêm regression cho các biến thể nội dung tương tự và hard-negative là shop game
   hợp pháp, bài báo, wiki và trang cộng đồng có nhắc Roblox.
3. Banner SAFE phải confidence-aware và không dùng dấu kiểm khi evidence thấp.
4. Có browser E2E trên Chrome và Edge đã cài unpacked extension cho verdict, content
   rescan, mutation, focus/inert và DNR lifecycle.
5. Có pilot 2-4 tuần, đo false negative do người dùng báo, tỷ lệ bỏ qua, thiệt hại tiềm
   năng và độ tin cậy của quyết định, không chỉ đo số cảnh báo.
6. Có temporal evaluation mới và báo cáo metrics riêng cho phishing, scam-commerce,
   malware download và legit commerce.

## Kết luận cuối

v2.5.0 đã tiến bộ rõ về giao diện, quyền riêng tư, an toàn bypass và giảm cảnh báo nhầm.
Tuy nhiên, ảnh runtime và phép thử URL thực tế chứng minh rằng extension vẫn có thể
greenlight một website giao dịch rủi ro bằng thẻ cào chỉ vì URL sạch, domain lâu năm và
không có password form.

Vì vậy, điểm hiện tại chưa đạt 9 ở bất kỳ vai trò nào. Ưu tiên tiếp theo không phải làm
giao diện đẹp hơn, mà là bổ sung verdict bảo vệ người dùng ở cấp hành vi và làm cho trạng
thái SAFE trung thực với độ bao phủ/bằng chứng thực tế.
