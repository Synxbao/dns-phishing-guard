# Hướng dẫn chia sẻ DNS Phishing Guard v2.7.5

## Chọn gói phát hành

- **Gói runtime đầy đủ:** `dns-phishing-guard-v2.7.5-runtime.zip` gồm extension, model, dữ liệu huấn luyện 4.000 URL, test, evaluation và tài liệu. Dùng cho phát triển, kiểm thử và đánh giá.
- **Gói Store:** `dns-phishing-guard-v2.7.5-store.zip` chỉ gồm runtime production, có `manifest.json` ở root. Dùng để tải lên Chrome Web Store/Edge Add-ons hoặc chia sẻ bản cài gọn.
- SHA-256 được ghi trong `D:\WORK\prj\RELEASE_HASHES_v2.7.5.txt`.

Không cài đồng thời nhiều bản DNS Phishing Guard trên cùng trình duyệt vì các content script có thể cùng chèn cảnh báo vào một trang.

## Cài bản unpacked

1. Giải nén gói runtime vào một thư mục cố định.
2. Mở `edge://extensions` hoặc `chrome://extensions`.
3. Bật **Chế độ nhà phát triển**.
4. Chọn **Tải tiện ích đã giải nén / Load unpacked**.
5. Chọn thư mục có file `manifest.json` ở cấp cao nhất.
6. Ghim biểu tượng extension và tải lại các tab đang mở.

## Kiểm tra URL an toàn hơn

1. Mở popup, dán URL vào ô **Kiểm tra trước khi mở/Link Lab** rồi bấm **Kiểm tra link** hoặc **Quét trước**.
2. Đọc verdict, HTTP status, chuỗi redirect, dấu hiệu form/password và tải tệp.
3. Nếu cần xem giao diện, chọn **Mở Safe Preview**. Preview khóa script/form/download bằng iframe sandbox và luật DNR theo tab.
4. Chỉ mở tab thường khi nhận ra đúng domain và không cần nhập thông tin nhạy cảm.

Safe Preview không phải máy ảo hay sandbox hệ điều hành: website vẫn nhận kết nối/IP, có thể từ chối iframe bằng CSP/X-Frame-Options, và hành vi sau đăng nhập/tương tác có thể chưa được quan sát.

Link reset mật khẩu, xác nhận email, magic login, unsubscribe hoặc URL có action token sẽ không được probe và không thể mở Safe Preview. Đây là biện pháp tránh tiêu thụ token hoặc kích hoạt hành động phía máy chủ.

## Phát hành Store

1. Tải lên `dns-phishing-guard-v2.7.5-store.zip`.
2. Điền listing, quyền truy cập, ảnh giao diện và Privacy Policy.
3. Nêu rõ Link Lab chỉ thực hiện preflight giới hạn; không gửi cookie/referrer và không chạy JavaScript trong bước quét.
4. Nên phát hành Private/Unlisted cho nhóm thử nghiệm trước khi Public.

## Lưu ý bảo mật

- Chỉ chia sẻ ZIP do bạn tự đóng gói và kèm SHA-256.
- Không mở trực tiếp URL độc hại trong dataset; dùng fixture/mock server đi kèm test.
- Không đưa API key, cookie, bearer token hoặc dữ liệu cá nhân vào source/log.
- Nhãn SAFE chỉ nghĩa là chưa thấy bằng chứng rõ trong phạm vi quét, không phải chứng nhận an toàn tuyệt đối.

## Xác minh bản phát hành

```powershell
npm run validate
Get-FileHash .\dns-phishing-guard-v2.7.5-runtime.zip -Algorithm SHA256
Get-FileHash .\dns-phishing-guard-v2.7.5-store.zip -Algorithm SHA256
```

Báo cáo QA cuối: `EXPERIENCE_REPORT_v2.7.5_FINAL.md`; validation: `VALIDATION_v2.7.5.md`.

