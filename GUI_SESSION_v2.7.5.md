# GUI Session v2.7.5

Ngày kiểm tra: 2026-08-17  
Phạm vi: popup Simple/Technical/Child, song ngữ Việt-Anh, responsive và presentation consistency. Không thay đổi risk engine, model hoặc evaluation fixtures.

## Thay đổi giao diện

- `popup.html:11`, `popup.html:35`, `popup.html:97`: thêm nút chuyển `VI/EN` ở Child, Simple và Technical UI.
- `popup.html:378`: thêm lựa chọn ngôn ngữ trong Settings. Ngôn ngữ được lưu bằng `chrome.storage.local`, không thay đổi dữ liệu hoặc verdict.
- `popup.css:122`: gom nút ngôn ngữ và trạng thái bảo vệ thành cụm điều khiển gọn; giữ theme tối/cyan/xanh/amber/đỏ hiện tại.
- `popup.css:160`: giảm padding, bán kính và khoảng cách dư của Simple UI; tăng độ rõ của verdict, reason và metric mà vẫn giữ đủ Risk/Evidence/Coverage.
- `popup.css:89`: bỏ min-content overflow của Technical shell ở viewport 320 px.
- `popup.css:129`, `popup.css:392`, `popup.css:1390`: các nút ngôn ngữ, tab, protection toggle và action chính có touch target cao tối thiểu 44 px.
- `popup.css:569`: giữ đường glow trong card, không tạo horizontal overflow.

## Bản tiếng Anh

- `popup.js:35`: thêm bảng dịch cho toàn bộ nhãn điều hướng, verdict Simple, Link Lab, telemetry, coverage, content safety, history, metrics, extension audit, settings, family mode và PIN modal.
- `popup.js:498`: bộ dịch xử lý cả text node, placeholder, `aria-label`, `title` và chuỗi động có domain/số liệu.
- `popup.js:603`: chuyển ngôn ngữ tức thời, lưu lựa chọn, render lại dữ liệu hiện có; không cần reload extension.
- `popup.js:705`: thời gian và tuổi domain dùng locale Anh/Việt tương ứng.
- `popup.js:724`: hướng dẫn đọc bằng `en-US` hoặc `vi-VN` theo giao diện.
- Mutation observer chỉ cập nhật khi nội dung thay đổi; nút locale kiểm tra giá trị trước khi ghi DOM để tránh vòng lặp render.

## Sửa consistency SAFE

- `popup.js:668`: `SAFE + COMPLETE + DETERMINED` không còn bị đổi sang amber chỉ vì thiếu lớp tùy chọn như Threat Intelligence.
- `popup.js:1160`: Technical coverage dùng màu xanh/đã xác định cho cùng trường hợp; lớp tùy chọn còn thiếu vẫn xuất hiện trong danh sách coverage, không bị che giấu.
- Các trạng thái `PARTIAL`, `INSUFFICIENT`, `UNDETERMINED` và `PROVISIONAL` vẫn giữ amber.

## Kiểm tra responsive và usability

Playwright + Microsoft Edge 151, dữ liệu popup mock offline, không gọi website bên ngoài:

| Chế độ | Viewport | Body/shell | Horizontal overflow | Điều khiển chính |
|---|---:|---:|---:|---|
| Simple EN | 320x800 | 320/320 px | 0 px | Locale 44x44; Protection >=44x44; actions >=44 px cao |
| Simple EN | 468x800 | 468/468 px | 0 px | Locale/Protection/actions >=44 px cao |
| Technical EN | 320x800 | 320/320 px | 0 px | Locale 44x44; Protection 72x44; tabs 59x44 |
| Technical EN | 468x800 | 468/468 px | 0 px | Locale/Protection/tabs/actions >=44 px cao |

- Đã kiểm tra trực quan Simple và Technical ở 320/468 px: không cắt verdict, domain, score strip, tab hoặc header.
- Đã bấm chuyển EN -> VI trong browser test: `html.lang` đổi `en` -> `vi`, nút đổi thành `EN`, verdict trở lại tiếng Việt mà không mất kết quả quét.
- Chuỗi fallback tiếng Anh đã kiểm tra gồm `NO RESULT YET`, hướng dẫn mở/reload website và trạng thái Technical chưa nhận dữ liệu.
- Ảnh QA tạm được lưu ngoài runtime tại `D:\WORK\prj\gui-qa-temp\*-final.png`; không đưa vào extension package.

## Regression gates

- `node --check popup.js`: PASS.
- `npm test`: PASS.
- `npm run validate`: PASS.
- Holdout không đổi: accuracy `96.48%`, precision `99.46%`, recall `93.43%`, FPR `0.50%`.
- Hybrid release: `22/22`; complex hybrid FP/FN: `0/0`; content recall: `2/2`.
- Adversarial probe: 30 executable cases, 0 network requests, 5/5 payment-brand threats vẫn nguy hiểm và không nhận positive boost.
- `tests/release.test.mjs:89`: thêm assertions cho locale controls, i18n source, COMPLETE/DETERMINED SAFE presentation và touch target 44 px.
- Sau khi ghép release, manifest/cache/footer/debug export được đồng bộ lên `2.7.5`; `npm run validate` chạy lại và tiếp tục PASS.

## Giới hạn còn lại

- Các reason/detail do module hoặc backend bên ngoài cung cấp với câu mới chưa có trong bảng dịch có thể giữ nguyên ngôn ngữ nguồn; verdict, action, navigation và các reason chuẩn hiện tại đã có tiếng Anh.
- Popup vẫn cần cuộn dọc để xem toàn bộ Technical telemetry trên màn hình thấp; đây là chủ đích để không thu nhỏ chữ hoặc ẩn dữ liệu.
- Không thêm font/CDN/network dependency; giao diện tiếp tục hoạt động offline theo CSP của extension.
