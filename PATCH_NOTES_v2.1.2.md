# DNS Phishing Guard v2.1.2 — OAuth/SSO False-Positive Patch

## Vấn đề được sửa

Trang đăng nhập chính thức `accounts.google.com` có thể bị đánh HIGH sau khi người dùng chọn “Đăng nhập bằng Google” từ cổng FPT. Nguyên nhân là Risk Engine xem chuyển hướng `fpt.edu.vn → google.com` như một redirect khác domain đáng ngờ. Điểm mạng này làm mất cơ chế giới hạn ML trên domain Google đã biết và lâu năm.

## Thay đổi

- Nhận diện endpoint đăng nhập chính thức của Google, Microsoft và Apple.
- Nhận diện tham số OAuth/OIDC như `client_id`, `redirect_uri`, `response_type`, `scope`, `continue`.
- Chuyển domain đến nhà cung cấp danh tính chính thức không tự cộng điểm `cross-domain-redirect`.
- ML và heuristic URL trên trang nhà cung cấp danh tính được giới hạn khi không có tín hiệu độc lập mạnh.
- Vẫn giữ cảnh báo với HTTPS downgrade, blacklist, typosquat, homoglyph, form mật khẩu gửi origin lạ và threat intelligence.
- Giao diện kỹ thuật hiển thị `OAuth/SSO Google → fpt.edu.vn` thay vì coi đó là redirect đáng ngờ.
- Bổ sung các URL OAuth FPT/Google/Microsoft vào feedback, regression và hard-negative data cho lần tái huấn luyện tiếp theo.

## Kỳ vọng với trường hợp trong ảnh

- Domain hiện tại: `accounts.google.com`
- Nhà cung cấp danh tính: Google
- Relying party: `fpt.edu.vn`
- Redirect network score: `0`
- ML raw probability vẫn được giữ trong bản kỹ thuật, nhưng không được tự kết luận phishing.
- Kết quả hybrid: SAFE hoặc tối đa cảnh báo nhẹ nếu xuất hiện tín hiệu khác.

Kết quả này không xác nhận ứng dụng bên thứ ba là đáng tin tuyệt đối. Người dùng vẫn cần kiểm tra dòng “Tiếp tục tới …” trên trang Google trước khi chọn tài khoản.
