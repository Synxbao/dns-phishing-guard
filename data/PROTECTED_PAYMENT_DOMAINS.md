# Protected payment domains

`protected-payment-domains.json` chỉ là tập tham chiếu chống typosquat/homoglyph cho các thương
hiệu thanh toán thường bị giả mạo. Tệp này **không phải allowlist**, không làm `isKnownDomain`
thành `true`, không giảm Risk score và không xác nhận một merchant hay giao dịch là hợp pháp.

Nguồn tham chiếu được ghi ngay trong JSON. Khi cập nhật theo danh sách NHNN/NAPAS, bản phát hành
phải lưu ngày snapshot, URL nguồn, checksum của tài liệu đầu vào và review thay đổi domain. Không
nhập một danh sách ngành không có nguồn hoặc tự động biến thành danh sách tin cậy.

Quy trình đề xuất:

1. Tải snapshot công khai từ NHNN/NAPAS bằng một quy trình riêng có kiểm duyệt.
2. Lưu tài liệu nguồn, ngày tải và SHA-256 trong hồ sơ release.
3. Trích domain chính thức, review thủ công từng thay đổi và chỉ đưa vào typo-reference.
4. Chạy toàn bộ test typosquat/homoglyph và false-positive trước khi đóng gói.
