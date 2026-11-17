# Child Mode v2

## Nguyên tắc

Trẻ chỉ cần biết nên tiếp tục, quay lại hay gọi người lớn. Giao diện không dùng thuật ngữ RDAP, Punycode hoặc xác suất mô hình.

## Mức bảo vệ

- **Nghiêm ngặt:** cảnh báo từ mức `NOTICE` và luôn chặn các danh mục nhạy cảm chính.
- **Tiêu chuẩn:** cảnh báo từ `WARNING`, nhưng dịch vụ tình dục, nội dung người lớn, cờ bạc, malware, danh tính giả và thu thập dữ liệu nhạy cảm vẫn yêu cầu người lớn xác nhận.

## Trạng thái quét

- `ĐANG KIỂM TRA`: content script chưa gửi page signals; không hiển thị màu xanh.
- `ĐÃ KIỂM TRA`: chưa thấy cảnh báo rõ ràng.
- `KHOAN ĐÃ`: có tín hiệu cần người lớn kiểm tra.
- `DỪNG LẠI`: phishing hoặc content risk cao.

## Lời nhắc dành cho trẻ

- Không nhập mật khẩu hoặc OTP.
- Không gửi ảnh riêng tư hoặc vị trí.
- Không liên hệ Zalo/Telegram/điện thoại với người lạ từ trang nhạy cảm.
- Không đặt lịch hoặc chuyển tiền.
- Không tải file lạ.
- Gọi bố mẹ, người chăm sóc hoặc thầy cô.

## Giới hạn

PIN giao diện không ngăn trẻ gỡ extension tại `chrome://extensions`. Nên kết hợp tài khoản trẻ em, quyền hệ điều hành và chính sách quản trị trình duyệt.
