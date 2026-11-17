# DNS Phishing Guard v2.7.5 — Một extension, hai giao diện

Giao diện Đơn giản và Kỹ thuật nằm trong cùng package, dùng chung URL ML v5, context classifier, Risk Engine hybrid, RDAP, typosquatting, homoglyph, redirect, phân tích form/DOM, Content Safety và Child Mode. Giao diện Đơn giản là mặc định; có thể chuyển profile trong popup hoặc Cài đặt.

## Bản Dễ dùng

Dành cho người dùng phổ thông và gia đình.

- Một màn hình chính tập trung vào **Trang đang mở**, hành động an toàn và **Link bạn đang kiểm tra**.
- Không hiển thị xác suất ML, RDAP, entropy hoặc phân rã điểm ở màn hình chính.
- Dùng câu trả lời trực tiếp: Chưa phát hiện phishing / Cần kiểm tra / Nguy cơ cao.
- Tách rõ nội dung: Chưa quét được / Đã quét chưa phát hiện / Đã phát hiện nội dung cần lưu ý.
- Risk chưa xác định dùng `—/100`; khu vực Phạm vi giải thích vì sao dữ liệu chưa đủ.
- Marketplace game bên thứ ba có outcome riêng `GIAO DỊCH CẦN XÁC MINH` thay vì bị gom vào trạng thái chung.
- Nút chính thay đổi theo tình huống.
- Chỉ hiện chi tiết kỹ thuật khi người dùng chủ động mở.
- Thêm whitelist phải xác nhận lại.
- Các thay đổi quan trọng khi Child Mode đang bật cần PIN phụ huynh.
- Không hiện banner xanh trên mọi website.

## Bản Kỹ thuật

Dành cho người phát triển, kiểm thử, giảng viên hoặc người quản trị.

- Hiển thị Risk Score, chất lượng bằng chứng, độ bất thường URL, model version và threshold.
- Hiển thị thẻ Evidence Coverage với Risk state, lớp đã kiểm tra, lớp còn thiếu và hành động tiếp theo.
- Hiển thị RDAP, public suffix, redirect chain, blacklist/whitelist và Strict Mode.
- Phân rã điểm theo Threat Intel, domain, URL, redirect, ML và page behavior.
- Lịch sử, thống kê, CSV, cache, extension permission audit.
- Quản lý whitelist/blacklist và Threat Intelligence endpoint.
- Sao chép hoặc xuất báo cáo chẩn đoán JSON; giá trị query và fragment được che.
- Link Lab quét URL trước khi mở, nhận diện redirect/tải tệp và mở Safe Preview bị khóa tương tác.

## Các sửa đổi chung

- Simple và Technical UI dùng chung brand-rule dataset đã xác minh cho Garena, VNG Games/Zing và VTC Game; cặp official/impostor không có model riêng theo giao diện.
- Content Safety `HIGH` trong nhóm nghiêm ngặt khóa tương tác nền ở cả luồng phishing kết hợp và content-only.
- Tín hiệu từ vùng quảng cáo/widget nghi ngờ được tách khỏi phần gán danh mục nội dung cho website; hành vi tải tệp/form/chuyển hướng nguy hiểm vẫn được kiểm tra riêng.
- Label lớp bằng chứng trong Simple UI dùng tiếng Việt phổ thông; detail kỹ thuật vẫn còn trong Technical UI.
- ML URL đơn lẻ không mở cảnh báo on-page; cần tín hiệu độc lập xác nhận.
- localhost/loopback/mạng riêng không dùng RDAP hoặc URL ML công cộng.
- Domain đã biết, lâu năm hoặc thuộc suffix chính thức được giới hạn ảnh hưởng của tín hiệu lexical yếu.
- RDAP không có dữ liệu được coi là UNKNOWN, không phải domain mới.
- `.aspx`, `.php`, `.jsp`, `.html` không bị xem là file thực thi nguy hiểm.
- Phân biệt rõ “chưa quét nội dung” với “đã quét nhưng chưa phát hiện”.
- Whitelist chỉ giảm tín hiệu uy tín; không bỏ qua blacklist, form mật khẩu gửi domain lạ, redirect nguy hiểm hoặc Content Safety.
- Child Mode tiếp tục che nội dung người lớn, dịch vụ tình dục, cờ bạc, mã độc, lạm dụng danh tính và thu thập dữ liệu nhạy cảm.

## Chuyển đổi giao diện

- Từ Simple UI, chọn **Xem chi tiết kỹ thuật**.
- Từ Technical UI, chọn **Chế độ đơn giản** hoặc đổi mục **Giao diện mặc định** trong Cài đặt.
- Việc chuyển giao diện không thay đổi điểm, model, blacklist, lịch sử hoặc cấu hình bảo vệ.

