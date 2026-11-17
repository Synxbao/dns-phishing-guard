# DNS Phishing Guard v2.7.2 - UI Consistency & Search Page Quiet Mode

Ngày phát hành: 2026-08-10

## Phạm vi bản vá

v2.7.2 sửa attribution quảng cáo, vị trí/overflow của UI trên trang và quy tắc hiển thị ở công cụ tìm kiếm. URL ML `url-logistic-5.0.0`, dataset 4.000 URL, calibration, threshold và logic chấm điểm Risk Engine không thay đổi.

## Panel, badge và menu chuột phải

- Menu chuột phải native thuộc browser/hệ điều hành luôn được vẽ phía trên nội dung web và shadow DOM; extension không thể nâng `z-index` cao hơn lớp này.
- Host của extension vẫn dùng `z-index: 2147483647`, nên phần tử của trang gốc không thể che panel trong điều kiện trình duyệt bình thường.
- Lỗi CSS thật đã được sửa: bar/panel không khóa chuyển xuống góc dưới bên phải; panel neo phía trên bar; label được phép co; `100/100` giữ một dòng; metric value không còn bị `overflow:hidden` cắt chữ.
- Khi người dùng click ngoài panel, bôi đen văn bản hoặc mở context menu trên trang gốc, panel không khóa tự thu gọn còn bar vẫn hiện để mở lại.
- Cảnh báo HIGH, content HIGH thuộc nhóm nghiêm ngặt và Child Mode overlay không tự thu gọn, không hiện nút đóng nhanh và vẫn khóa tương tác nền.

## Regression NetTruyen-style bắt buộc

`tests/release.test.mjs` có fixture cố định gồm:

- main content là danh sách truyện/chapter hợp pháp;
- wrapper quảng cáo generic `sidebar-widget promo-slot` nhận kích thước `300x250` từ CSS;
- creative, contact và profile bên trong dùng tài nguyên bên thứ ba và chứa tín hiệu `SEXUAL_SERVICES`.

Test chứng minh hai trạng thái:

1. Dữ liệu thô chưa lọc đạt `SEXUAL_SERVICES/HIGH`.
2. Sau `findLikelyAdRegions()` và các hàm filter, main content vẫn còn, ad text/contact/profile bị loại và Content Safety không còn phát hiện nhầm.

Bộ lọc được gia cố ở mức cơ chế chung, không hardcode `nettruyenviet.art`. Candidate mạnh gồm marker/attribute quảng cáo rõ; candidate yếu gồm `banner`, `promo`, `widget`, `slot`, `aside` và complementary region. Candidate yếu chỉ bị coi là quảng cáo khi có ad-size chuẩn hoặc creative HTTP(S) bên thứ ba, nhằm hạn chế loại nhầm widget first-party.

## Trang tìm kiếm phổ biến

- Thêm `modules/search-engines.js` và cờ kết quả `isSearchEngineHome` cho Google, Bing, DuckDuckGo, Yahoo, Brave Search và Cốc Cốc.
- Khi Risk là SAFE và không có Content Safety warning, bar/panel trên trang tìm kiếm được ẩn mặc định, kể cả khi người dùng từng bật global safe banner.
- Quét nền, popup và browser-action badge vẫn hoạt động; Risk `SUSPICIOUS`, `MEDIUM` hoặc `HIGH` vẫn hiện cảnh báo như trước.
- Setting nâng cao `Hiện trạng thái trên trang tìm kiếm phổ biến` cho phép bật lại UI SAFE trên các trang này.
- `evaluation/complex-legit-cases.json` tăng từ 24 lên 30 ca; cả 6 search-engine case đều SAFE, hybrid score 0 và không tạo on-page warning.

## Màu và evidence thấp

- SAFE với evidence dưới 45/100 dùng trạng thái `CAUTION` màu hổ phách thay vì dấu kiểm xanh.
- Popup, content bar, coverage badge và browser-action badge dùng cùng quy tắc trình bày này.
- Đây là thay đổi giao diện/diễn giải; `risk.level`, `risk.score`, binary prediction và threshold không đổi.

## Giới hạn kỹ thuật

- Native context menu vẫn nằm trên UI extension trong thời gian menu mở; tự thu gọn chỉ giảm cảm giác che khuất, không thay đổi hành vi hệ điều hành.
- Không thể bảo đảm một floating bar không bao giờ trùng mọi widget/chat/cookie banner trên mọi website. Vị trí góc dưới, kích thước gọn và auto-collapse giảm xung đột nhưng không loại bỏ tuyệt đối.
- Native ad không marker, không kích thước đặc trưng, không creative bên thứ ba hoặc nằm trong closed shadow DOM/canvas vẫn có thể lọt qua.
- Widget hợp lệ có marker quảng cáo hoặc đúng ad-size kèm tài nguyên bên thứ ba có thể bị giảm trọng số nhầm. External form/script/iframe và risky download vẫn được giữ ở lớp security-critical để bộ lọc không che hành vi nguy hiểm.
