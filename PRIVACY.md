# Privacy

- URL Machine Learning chạy hoàn toàn trên thiết bị bằng model JSON đi kèm extension.
- Model không gửi URL, feature vector hoặc prediction tới máy chủ.
- Content Safety chạy cục bộ và chỉ phân tích:
  - số lượng trường input/form;
  - tên/placeholder/label của trường;
  - từ khóa trong title, meta description và phần văn bản hiển thị;
  - liên kết iframe/script/download;
  - sự hiện diện của liên kết chính sách quyền riêng tư.
- Extension **không đọc giá trị** người dùng nhập trong password, OTP, số thẻ, CCCD hoặc các trường biểu mẫu khác.
- Extension không chụp ảnh màn hình, không ghi âm và không tải ảnh/video lên máy chủ để nhận diện deepfake.
- RDAP có thể gửi registrable domain tới RDAP providers để tra tuổi domain.
- Threat Intelligence backend tắt mặc định; khi bật, endpoint chỉ nhận URL đã che query value/bỏ fragment cùng hostname và path. Token, mã xác nhận và query value không được gửi theo mặc định.
- Kết quả chi tiết theo tab chỉ lưu trong `chrome.storage.session` và bị xóa khi tab đóng hoặc phiên trình duyệt kết thúc.
- Lịch sử/CSV chỉ lưu URL đã che giá trị query và bỏ fragment. Phản hồi báo nhầm chỉ lưu domain, điểm, mức và tối đa bốn lý do cục bộ.
- Extension lưu cài đặt, cache danh tiếng không chứa URL rõ, lịch sử đã redacted và thống kê tổng hợp trong local Chrome storage.
- Link Lab bình thường vẫn tạo kết nối tới website nên có thể lộ IP. URL có dấu hiệu token xác nhận/reset/magic-login được phân tích tĩnh nhưng không probe mạng.
- Quyền `management` chỉ được yêu cầu khi người dùng chủ động quét quyền extension khác.
