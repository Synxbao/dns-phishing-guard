# DNS Phishing Guard v2.7.1 - Content Lock & Ad-Aware Scanning

Ngày phát hành: 2026-08-10

## Mục tiêu

v2.7.1 là bản vá UX/consistency cho lớp Content Safety. Bản này không retrain URL ML và không thay đổi dataset 4.000 URL, feature, calibration hoặc threshold.

## Content Safety HIGH khóa trang nhất quán

- `showAdvancedSecurityUI()` coi kết quả là HIGH khi phishing Risk hoặc Content Safety ở mức `HIGH`.
- `showContentSafetyUI()` chuyển sang overlay toàn màn hình khi `HIGH` đi kèm danh mục nghiêm ngặt dùng chung với Child Mode.
- Overlay HIGH ẩn nút `×`, khóa tương tác nền bằng `inert`/focus trap và đặt **Quay lại** làm focus ban đầu.
- Nút **Tôi hiểu rủi ro · cho phép 10 phút** gọi hộp xác nhận gõ đúng domain khi Content Safety HIGH là nguồn gây khóa.
- Danh sách danh mục nghiêm ngặt chỉ còn một nguồn `STRICT_CONTENT_CATEGORY_IDS`, tránh Child Mode và adult UI lệch nhau.

## Giảm gán nhầm quảng cáo nhúng cho website

- Thêm `modules/page-signal-filter.js`, được nạp trước `content.js`.
- Nhận diện vùng quảng cáo bằng marker class/id/ARIA/data attribute như `ads`, `sponsor`, `banner-ad`, `quang-cao` và biến thể tương đương.
- Nhận diện thêm ad-unit kích thước chuẩn khi phần tử là iframe/`ins` hoặc chứa creative/tài nguyên HTTP(S) bên thứ ba.
- Loại text, nút liên hệ, hồ sơ/card, input thương mại và các selector content-semantic nằm trong vùng quảng cáo trước khi tính danh mục Content Safety.
- Không loại external password form, external script/iframe hoặc risky download khỏi lớp bảo mật cấu trúc; quảng cáo nguy hiểm vẫn có thể tạo cảnh báo hành vi/tải tệp.
- Ghi thêm `excludedAdRegionCount` và `excludedAdTextLength` trong page signals để chẩn đoán.

## Regression offline

- Fixture trang đọc truyện hợp pháp + banner quảng cáo nhúng: dữ liệu thô tạo `SEXUAL_SERVICES/HIGH`; sau lọc, nội dung chính không còn bị phát hiện nhầm.
- Positive first-party `SEXUAL_SERVICES` vẫn đạt `HIGH`.
- Positive first-party `GAMBLING` vẫn đạt `HIGH`.
- Hai positive này được thêm vào `evaluation/release-regression-cases.json` và gate `npm run evaluate`.
- Test source bảo vệ overlay HIGH, nút đóng bị ẩn, security lock và typed-domain bypass.

## Nhãn Simple UI

- `Cấu trúc URL & URL ML` → `Cấu trúc địa chỉ website`.
- `Threat Intelligence` → `Nguồn uy tín bên ngoài`.
- `HTML giới hạn`/`HTML thực tế` → `Nội dung xem trước giới hạn`/`Nội dung thực tế của trang`.
- Detail kỹ thuật vẫn giữ URL ML, RDAP, DOM và Threat Intelligence trong Technical UI khi cần điều tra.

## Giới hạn và trade-off

- Heuristic không thể biết chắc mọi widget có phải quảng cáo hay không khi publisher bỏ toàn bộ marker, dùng shadow DOM đóng hoặc render bằng canvas.
- Một khối first-party hợp lệ có class quảng cáo hoặc đúng kích thước ad-unit kèm liên kết/tài nguyên bên thứ ba có thể bị giảm trọng số nhầm.
- Ngược lại, native ad cố tình ngụy trang như nội dung chính, không có marker/kích thước đặc trưng, vẫn có thể lọt vào content scan.
- Bộ lọc ưu tiên giảm false positive gán danh mục cho toàn site nhưng giữ các tín hiệu security-critical riêng; vì vậy quảng cáo có form ngoài domain hoặc tải executable vẫn có thể làm tăng phishing/page risk.
