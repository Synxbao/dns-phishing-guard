# Bản nháp nội dung Store Listing — v2.7.5 Bilingual Protection

## Tên

DNS Phishing Guard — Cảnh báo phishing, link và giao dịch đáng ngờ

## Mô tả ngắn

Cảnh báo phishing, link khó xác minh, giao dịch game/mã trả trước và nội dung rủi ro bằng tiếng Việt; giải thích rõ dữ liệu đã kiểm tra và còn thiếu.

## Mục đích duy nhất

Giúp người dùng nhận biết dấu hiệu phishing, giao dịch đáng ngờ và nội dung trực tuyến có rủi ro trước khi nhập mật khẩu, OTP, mã thẻ, thông tin thanh toán hoặc tải file.

## Mô tả chi tiết

DNS Phishing Guard phân tích URL, domain, tuổi domain qua RDAP, typosquatting, homoglyph, Punycode, chuyển hướng, form đăng nhập và các tín hiệu nội dung trang. Extension sử dụng Risk Engine hybrid kết hợp mô hình URL Machine Learning chạy cục bộ với các tín hiệu độc lập; ML không tự quyết định cảnh báo nghiêm trọng.

Các tính năng chính:

- Cảnh báo phishing bằng ngôn ngữ dễ hiểu.
- Giao diện Đơn giản mặc định và giao diện Kỹ thuật khi cần xem toàn bộ bằng chứng.
- Link Lab kiểm tra link trước khi mở; tự tránh probe link có token reset/xác nhận/magic login.
- Link Lab không gọi kết quả là an toàn khi gặp HTTP 403, lỗi mạng hoặc vòng lặp chuyển hướng.
- Risk hiển thị `Chưa xác định` thay vì `0/100` khi bằng chứng không đủ.
- Khu vực Phạm vi bằng chứng cho biết lớp nào đã kiểm tra, lớp nào còn thiếu và hành động tiếp theo.
- Nhận diện có điều kiện luồng VietQR/ZaloPay/MoMo/VNPay/NAPAS/thẻ; logo không được dùng như xác thực website hay giao dịch.
- Tách payment-brand typo reference khỏi allowlist để vẫn cảnh báo domain giả mạo ví/ngân hàng.
- Cảnh báo nội dung rủi ro cao khóa trang và yêu cầu xác nhận domain trước khi cho phép tạm.
- Giảm gán nhầm nội dung quảng cáo/widget nhúng cho website chính bằng bộ lọc vùng quảng cáo không hardcode domain.
- Nhận diện luồng đăng nhập OAuth/SSO chính thức như Google và Microsoft.
- Phân tích form mật khẩu gửi sang domain khác.
- Nhận diện giao dịch mã thẻ, seri, PIN, voucher, gift card và nạp game ngoài kênh chính thức bằng tổ hợp tín hiệu.
- Đối chiếu Garena/Free Fire/Liên Quân/FC Online/FC Mobile, VNG Games/Zing và VTC Game/Vcoin với domain/cổng nạp đã xác minh; dữ liệu này không phải allowlist.
- Cảnh báo mạnh khi trang tự nhận chính thức/đối tác của thương hiệu game nhưng chạy trên domain không khớp và yêu cầu ID game hoặc mã thẻ.
- Nhận diện ngữ cảnh mua bán tài khoản/dịch vụ game qua domain và kênh liên hệ bên thứ ba mà không tự kết luận website lừa đảo.
- Nhận diện cờ bạc, nội dung người lớn, dịch vụ tình dục, mã độc và yêu cầu dữ liệu nhạy cảm.
- Child Mode có PIN phụ huynh.
- Whitelist/blacklist và chặn domain đã xác nhận.
- Không đọc nội dung người dùng nhập vào ô mật khẩu hoặc OTP.
- Mặc định xử lý dữ liệu trên thiết bị; không bán dữ liệu người dùng.
- Lịch sử che giá trị query/fragment; kết quả tab chỉ tồn tại trong session storage.

Kết quả chỉ là chỉ báo kỹ thuật, không bảo đảm website an toàn tuyệt đối và không phải kết luận pháp lý.

## Gợi ý ảnh chụp

1. Popup phân biệt `Có thể tiếp tục thận trọng` và `Chưa đủ dữ liệu`.
2. Cảnh báo phishing mô phỏng có lý do rõ ràng.
3. Child Mode che trang nội dung hạn chế.
4. Nhận diện OAuth/SSO Google chính thức.
5. Màn hình cài đặt quyền riêng tư và lịch sử.

