# DNS Phishing Guard v2.7.5 - GUI Polish & Bilingual Release

Ngày phát hành: 2026-08-17

## Phạm vi

v2.7.5 là bản chỉnh giao diện và trải nghiệm cuối trên nền v2.7.4. Không retrain URL ML, không đổi threshold, không đổi điểm Risk Engine và không nới lỏng các guard chống giả mạo.

## Thay đổi chính

1. **GUI gọn và đầy đủ thông tin**
   - `popup.html:11,35,97,379`: thêm control Việt/Anh cho Child, Simple, Technical và lựa chọn ngôn ngữ trong Settings.
   - `popup.css:89,122,160,392,569,1390`: sửa min-content overflow, giảm khoảng cách thừa, giữ theme tối/cyan/amber/đỏ, responsive 320-700 px và touch target tối thiểu 44 px.
   - Các thẻ Risk, Evidence, Coverage, Link Lab, content safety và Technical telemetry vẫn giữ nguyên; chỉ tổ chức lại bố cục và khoảng cách.

2. **Bản tiếng Anh hoàn chỉnh hơn**
   - `popup.js:35-480`: bảng dịch cho navigation, verdict, Link Lab, coverage, content safety, history, metrics, settings, family mode và PIN.
   - `popup.js:498-620`: dịch text node, placeholder, aria-label/title, trạng thái sinh động; lựa chọn được lưu ở `chrome.storage.local`.
   - `popup.js:705,724`: locale thời gian/tuổi domain và speech locale đổi theo EN/VI.

3. **Consistency của SAFE**
   - `popup.js:668-675,1160-1164`: `SAFE + COMPLETE + DETERMINED` không bị amber hóa chỉ vì thiếu lớp tùy chọn; trạng thái `PARTIAL/INSUFFICIENT/UNDETERMINED/PROVISIONAL` vẫn thận trọng.

4. **Regression và đóng gói**
   - `tests/release.test.mjs:75,89-103,1414`: kiểm tra version 2.7.5, locale, English, SAFE presentation, touch targets và các gate security trước đó.
   - `manifest.json:4`, `popup.html:7,85,414`, `blocked.html:67`, `popup.js:1404`, `modules/model-config.js:1`: đồng bộ version 2.7.5.

## Giới hạn kỹ thuật

- Chuỗi lý do mới do backend/module ngoài bảng dịch có thể giữ nguyên ngôn ngữ nguồn cho tới khi bổ sung mapping.
- Popup Technical vẫn cần cuộn dọc ở màn hình thấp để giữ đủ telemetry; không thu nhỏ chữ hoặc ẩn dữ liệu.
- Menu chuột phải native của trình duyệt có thể nằm trên extension theo thứ tự lớp của OS; panel không khóa tự thu gọn khi người dùng chọn text/click ngoài trang, còn overlay HIGH vẫn khóa.
- Các giới hạn model/probe đã ghi trong v2.7.4 vẫn giữ nguyên và không được diễn giải là đã được giải quyết bởi bản GUI.
