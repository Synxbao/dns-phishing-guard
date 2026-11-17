# External Website & Usability Test Sessions - DNS Phishing Guard v2.7.5

Ngày chạy: 2026-08-17 (Asia/Saigon)

## Phạm vi và phương pháp

- Chạy 5 phiên read-only trên website chính thống; không đăng nhập, không nhập form, không thanh toán, không tải tệp và không mở phishing/malware thật.
- Mỗi URL được mở bằng browser để xác nhận trang thực tế, tiêu đề, URL cuối và DOM hiển thị. Link Lab đọc tối đa 64 KiB đầu bằng `probeUrlNetwork()` với `credentials: omit`, `no-referrer`, không chạy mã trang trong response đã tải.
- Verdict được replay bằng đúng `url-model`, `risk-engine`, `evidence-coverage`, public-suffix và các baseline trong workspace. Browser test không cài unpacked extension, vì vậy trạng thái on-page là kết luận từ policy/runtime local chứ không phải quan sát trực tiếp content script đã inject.
- 5 phiên usability dùng `popup.html` thật qua localhost và một Chrome API stub chỉ trong thư mục tạm để cho phép đổi ngôn ngữ/chế độ. Không sửa source extension. Stub không thay thế kiểm thử E2E bằng Chrome/Edge đã cài extension.
- Snapshot bắt đầu với `manifest.json = 2.7.4`; tên báo cáo là v2.7.5 vì đây là vòng QA cho bản GUI cuối đang phát triển.

## Tóm tắt phát hiện

1. **Không có false phishing trong 5 URL thật:** cả 5 đều `SAFE 0`, Link Lab không thấy tải trực tiếp, meta refresh, form mật khẩu hoặc content-risk trong 64 KiB đầu.
2. **Search quiet mode đúng policy:** Google và Bing được nhận diện `isSearchEngineHome=true`; Risk SAFE không cần bar trên trang.
3. **Simple UI vẫn dễ amber hóa website sạch:** Google, Bing, Wikipedia và VNGGames Shop có Risk `SAFE 0`, nhưng evidence chỉ `26/100`, `safeDisplayState=CAUTION` khi Threat Intelligence không bật. `hasIncompleteSafeEvidence()` hiện có thể diễn giải thành `CHƯA ĐỦ DỮ LIỆU` trong popup.
4. **RDAP `.vn` còn là điểm yếu:** `garena.vn` trả 404 tại RDAP bootstrap, nên identity là `UNVERIFIED`, evidence `25/100 INSUFFICIENT` dù URL/page/risk đều sạch.
5. **Responsive không tràn ngang**, nhưng nút ngôn ngữ và bật/tắt chỉ cao 29-31 px; một số action 36-43 px. Đây là touch target hơi nhỏ so với mục tiêu 44 px.
6. **English UI chưa hoàn toàn đồng nhất:** bốn chuỗi trạng thái rỗng vẫn còn tiếng Việt trong giao diện English ở snapshot đã test.

## 5 phiên website ngoài thực tế

### WEB-01 - Google Search

| Hạng mục | Kết quả quan sát |
| --- | --- |
| URL | `https://www.google.com/` |
| Browser | Tiêu đề `Google`; trang tải được; 1 form tìm kiếm; 0 password input; 0 iframe; 0 download link quan sát trong DOM |
| HTTP / Link Lab | HTTP 200; 0 redirect; đọc 65.536 byte, truncated theo giới hạn; download risk `NONE`; static content `NONE` |
| URL ML / Hybrid | ML `SAFE` (~0,0006%); Hybrid `SAFE 0`; identity `KNOWN_DOMAIN`; không on-page warning |
| Evidence | `26/100`, `COMPLETE`, `DETERMINED`, nhưng `safeDisplayState=CAUTION`; thiếu nguồn uy tín bên ngoài |
| UX | `isSearchEngineHome=true`, vì vậy bar SAFE mặc định được ẩn; popup vẫn có nguy cơ hiển thị amber do mapping CAUTION |

Kết luận: **PASS về phát hiện và search quiet mode; PARTIAL về cách trình bày evidence trong popup.**

### WEB-02 - Microsoft Bing

| Hạng mục | Kết quả quan sát |
| --- | --- |
| URL | `https://www.bing.com/` |
| Browser | Tiêu đề `Search - Microsoft Bing`; trang tải được; 1 form tìm kiếm; 0 password input; 0 iframe; DOM động có 1 link gắn `download`, nhưng không quan sát tải tự động |
| HTTP / Link Lab | HTTP 200; 0 redirect; đọc 65.536 byte; download risk `NONE`; response tĩnh không có download attribute/risky file trong phần đã đọc |
| URL ML / Hybrid | ML `SAFE` (~2,12%); Hybrid `SAFE 0`; identity `KNOWN_DOMAIN`; không on-page warning |
| Evidence | `26/100`, `COMPLETE/DETERMINED`, `safeDisplayState=CAUTION` |
| UX | `isSearchEngineHome=true`; không cần bar SAFE che ô tìm kiếm. Chênh lệch DOM động với response tĩnh cho thấy Link Lab không thể đại diện toàn bộ hành vi sau khi JavaScript chạy |

Kết luận: **PASS; không có tải tự động được kích hoạt, nhưng cần giữ thông điệp Link Lab là quét giới hạn.**

### WEB-03 - Wikipedia

| Hạng mục | Kết quả quan sát |
| --- | --- |
| URL | `https://www.wikipedia.org/` |
| Browser | Tiêu đề `Wikipedia`; 1 form tìm kiếm; 0 password input; 0 iframe; 0 download link; nội dung đa ngôn ngữ hiển thị bình thường |
| HTTP / Link Lab | HTTP 200; 0 redirect; đọc 65.536 byte; download risk `NONE`; static content `NONE` |
| URL ML / Hybrid | ML `SAFE` (~9,85%); Hybrid `SAFE 0`; identity `KNOWN_DOMAIN`; không warning |
| Evidence | `26/100`, `COMPLETE/DETERMINED`, nhưng `CAUTION` do thiếu Threat Intelligence |
| UX | Không có bar SAFE vì `showSafeBanner=false`; popup có thể quá thận trọng dù danh tính đã nhận diện và Risk đã xác định |

Kết luận: **PASS về verdict; cần chỉnh wording Simple UI để `COMPLETE/DETERMINED` không bị hiểu thành chưa quét đủ.**

### WEB-04 - Garena Việt Nam

| Hạng mục | Kết quả quan sát |
| --- | --- |
| URL | `https://www.garena.vn/` |
| Browser | Tiêu đề `Garena`; trang chủ/game/support hiển thị; 0 form; 0 password input; 0 iframe; 0 download link |
| HTTP / Link Lab | HTTP 200; 0 redirect; đọc 65.536 byte; download risk `NONE`; static content `NONE` |
| RDAP | `rdap.org/domain/garena.vn` trả 404 trong phiên test; không có tuổi domain |
| URL ML / Hybrid | ML `SAFE` (~1,94%); Hybrid `SAFE 0`; không warning; identity `UNVERIFIED` |
| Evidence | `25/100`, `INSUFFICIENT/UNDETERMINED`, thiếu identity, RDAP và nguồn uy tín bên ngoài |
| UX | Không bị false phishing, nhưng nếu người dùng chủ động mở popup sẽ thấy trạng thái amber dù đây là trang publisher chính thức đã có nguồn trong brand data |

Kết luận: **PARTIAL. Risk engine không báo nhầm, nhưng evidence/identity chưa tận dụng nguồn brand đã xác minh cho trang corporate không có giao dịch.**

### WEB-05 - VNGGames Shop

| Hạng mục | Kết quả quan sát |
| --- | --- |
| URL | `https://shop.vnggames.com/` -> `https://shop.vnggames.com/vn` |
| Browser | Tiêu đề `VNGGames Shop`; danh sách game/nút `Nạp ngay`; 0 form; 0 password input; 0 iframe; 0 download link ở homepage |
| HTTP / Link Lab | 1 redirect hợp lệ tới `/vn`, final HTTP 200; đọc 65.536 byte; download risk `NONE`; static content `NONE` |
| URL ML / Hybrid | ML `SAFE` (~17,13%); Hybrid `SAFE 0`; identity `ESTABLISHED_DOMAIN`; không warning |
| Evidence | `26/100`, `COMPLETE/DETERMINED`, `safeDisplayState=CAUTION` |
| UX | Homepage không có input giao dịch nên verified-brand/payment boost không áp dụng; điều này an toàn về guard nhưng popup vẫn có thể amber quá mức |

Kết luận: **PASS về Risk và redirect; PARTIAL về confidence wording cho site chính thống đã lâu năm.**

## 5 phiên usability

### UX-01 - Người dùng phổ thông, desktop, Simple UI tiếng Việt

- Viewport: 700 x 900.
- Không horizontal overflow (`scrollWidth = clientWidth = 700`).
- Thứ tự thông tin hợp lý: trạng thái bảo vệ -> kết luận -> Risk/Evidence/Coverage -> hành động chính -> Link Lab -> nút xem kỹ thuật.
- Simple main chỉ cần cuộn nhẹ (`646/626 px`); action chính và Link Lab đều dễ thấy.
- Nút chính cao 43 px; Link Lab input/nút cao 43 px; nút Technical 40 px.

Đánh giá: **8,8/10**. Gọn và dễ hiểu; nên nâng touch target nhỏ lên tối thiểu gần 44 px.

### UX-02 - Người dùng mobile, 320 x 800

- Không tràn ngang (`scrollWidth = clientWidth = 320`).
- Simple main cuộn nội bộ `764/626 px`; nút `Xem chi tiết kỹ thuật` nằm dưới fold nhưng vẫn reachable bằng scroll.
- Input và nút Link Lab tự xếp dọc, rộng khoảng 258 px; không bị cắt chữ.
- Nút ngôn ngữ cao 29 px và nút bảo vệ cao 30 px; đây là điểm yếu touch accessibility. Các action chính cao 40-43 px.

Đánh giá: **8,2/10**. Responsive tốt, nhưng hai control header còn nhỏ và vùng scroll cần dấu hiệu trực quan rõ hơn.

### UX-03 - Người không rành kỹ thuật, Simple UI

- Phần đầu dùng ngôn ngữ hành động: `Chờ kết quả bảo vệ`, `Quét lại trang`, `Kiểm tra trước khi mở`.
- Simple shell không lộ `RDAP`, `Threat Intelligence`, bucket score hay tên model; chi tiết kỹ thuật được đặt sau nút riêng.
- Risk/Evidence/Coverage vẫn là ba khái niệm cùng lúc. Khi trạng thái là `CAUTION`, label `CHƯA ĐỦ DỮ LIỆU` có thể khiến người dùng hiểu nhầm website sạch là đáng ngờ thay vì chỉ thiếu một nguồn tùy chọn.

Đánh giá: **8,4/10**. Ngôn ngữ chính dễ hiểu; mapping evidence cần phân biệt rõ `đã đánh giá nhưng độ tin cậy vừa` với `chưa đủ để kết luận`.

### UX-04 - Power user, Technical UI, 520 x 800

- Không horizontal overflow; main scroll `2.274/575 px`.
- 5 tab rõ ràng: Status, History, Metrics, Extensions, Settings.
- Có 14 card, 15 metric element và đầy đủ Risk, evidence, RDAP, redirect, URL anomaly, ML, signal breakdown, content score và response controls.
- Thông tin đầy đủ nhưng trang Status dài; dữ liệu quan trọng và action cuối cách nhau hơn 2.000 px, làm tăng thời gian scan.

Đánh giá: **8,7/10**. Mạnh về khả năng giải thích; nên có summary sticky hoặc collapse cho các card thứ cấp.

### UX-05 - English + accessibility/keyboard audit

- English toggle hoạt động trong stub runtime: `document.lang=en`, title đổi thành `DNS Phishing Guard — Protection`, nút đổi thành `VI`.
- Simple view còn hai chuỗi tiếng Việt: `CHƯA CÓ KẾT QUẢ`, `Mở hoặc tải lại một website để extension bắt đầu kiểm tra.`
- Technical view còn hai chuỗi tiếng Việt: `Chưa nhận được kết quả từ tab hiện tại`, `Mở một website để bắt đầu phân tích`.
- 6 control nhìn thấy trong Simple UI đều là `button/input`, có accessible name và `tabIndex=0`; input có aria-label. CSS có `:focus-visible` outline 2 px và khi focus ngôn ngữ hiển thị outline màu accent.
- Công cụ automation không thực hiện được một vòng Tab traversal đầy đủ, vì vậy đây chưa phải screen-reader/keyboard E2E. Chưa kiểm chứng NVDA/JAWS/VoiceOver.

Đánh giá: **7,9/10**. Semantics cơ bản tốt; localization chưa đạt tiêu chí “bản English hoàn chỉnh” và touch target header cần tăng.

## Bảng tổng hợp 10 phiên

| Phiên | Loại | Kết quả | Điểm | Giới hạn chính |
| --- | --- | --- | ---: | --- |
| WEB-01 Google | Website thật | PASS/PARTIAL UX | 8,8 | Evidence CAUTION dù Risk SAFE/KNOWN |
| WEB-02 Bing | Website thật | PASS | 9,0 | DOM động không nằm hết trong static probe |
| WEB-03 Wikipedia | Website thật | PASS/PARTIAL UX | 8,7 | Evidence CAUTION dù COMPLETE |
| WEB-04 Garena | Website thật | PARTIAL | 7,7 | RDAP `.vn` 404, identity UNVERIFIED |
| WEB-05 VNGGames Shop | Website thật | PASS/PARTIAL UX | 8,4 | Homepage không đủ context cho positive brand evidence |
| UX-01 Desktop simple | Usability | PASS | 8,8 | Header touch target nhỏ |
| UX-02 Mobile 320 | Usability | PASS/PARTIAL | 8,2 | 29-30 px control, cuộn nội bộ |
| UX-03 Non-technical | Usability | PARTIAL | 8,4 | `CHƯA ĐỦ DỮ LIỆU` dễ bị hiểu là nguy hiểm |
| UX-04 Power user | Usability | PASS | 8,7 | Technical Status dài 2.274 px |
| UX-05 English/a11y | Usability | PARTIAL | 7,9 | 4 chuỗi chưa dịch, chưa screen-reader E2E |

Điểm trung bình 10 phiên: **8,46/10**.

## Ưu tiên phát hiện ở snapshot trước GUI final

1. Hoàn tất bốn chuỗi English còn sót trong `popup.js` và thêm assertion localization cho trạng thái chưa có dữ liệu.
2. Không dùng `safeDisplayState=CAUTION` đơn thuần để gọi mọi site SAFE là `CHƯA ĐỦ DỮ LIỆU`; xét thêm `riskState=DETERMINED`, `status=COMPLETE` và identity recognized.
3. Tạo cách công nhận publisher-owned corporate domain từ brand data như một identity evidence có giới hạn, không biến brand rule thành allowlist; điều này đặc biệt hữu ích khi RDAP `.vn` không có dữ liệu.
4. Nâng nút ngôn ngữ/bật-tắt và action mobile lên vùng chạm gần 44 x 44 px.
5. Chạy một vòng E2E cuối bằng Chrome/Edge đã load unpacked extension: popup thật, content bar, search quiet mode, keyboard Tab/Shift+Tab và ít nhất một screen reader.

## Giới hạn báo cáo

- Website ngoài thực tế có thể thay đổi sau thời điểm test.
- Link Lab chỉ đọc tối đa 64 KiB, không chạy JavaScript của response và không chứng minh toàn bộ trang an toàn.
- Không có threat-intel backend trong phiên replay; đây là lý do lớp external reputation bị thiếu.
- Không kiểm thử domain nguy hiểm thật, không thử login/payment/download và không thực hiện active security testing.
- Browser không cài extension trong phiên này; on-page UI được suy ra từ risk/presentation policy và test local, không phải ảnh chụp content script production.

## Addendum sau khi ghép GUI v2.7.5

Ngày 2026-08-17, GUI session chạy lại popup với mock runtime offline tại 320x800 và 468x800:

- `html.lang` đổi EN <-> VI tức thời; các trạng thái rỗng Simple/Technical đã có bản dịch và lựa chọn được lưu cục bộ.
- Body/shell khớp viewport, `scrollWidth - clientWidth = 0`; locale/protection/tab/action chính đạt chiều cao tối thiểu 44 px.
- Với snapshot SAFE + COMPLETE + DETERMINED (Google, Bing, Wikipedia, VNGGames), popup không còn amber hóa chỉ vì Threat Intelligence tùy chọn chưa có; lớp thiếu vẫn hiện ở Technical UI.
- Garena vẫn có giới hạn RDAP `.vn` 404 và có thể giữ `UNVERIFIED/INSUFFICIENT`; đây là thiếu dữ liệu thật, không bị che bằng màu xanh giả.

Điểm usability cập nhật sau GUI polish: UX-01 `9,2`, UX-02 `9,0`, UX-03 `9,1`, UX-04 `8,8`, UX-05 `9,0` (trung bình `9,02/10`). Các điểm website giữ nguyên quan sát read-only; thay đổi chủ yếu nằm ở cách trình bày popup và touch/accessibility.
