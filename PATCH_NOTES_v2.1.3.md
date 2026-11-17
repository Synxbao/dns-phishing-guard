# DNS Phishing Guard v2.1.3 — OAuth/SSO Display & Distribution Patch

## Mục tiêu

Bản vá này sửa phần hiển thị gây hiểu nhầm khi URL Machine Learning đánh giá cao một URL đăng nhập OAuth/SSO chính thức, ví dụ `accounts.google.com` được mở từ cổng FPT.

## Thay đổi chính

1. **Tách ML thô khỏi kết luận cuối**
   - Bản kỹ thuật đổi nhãn thành `ML URL thô (tham khảo)`.
   - Hiển thị riêng `Điểm ML áp dụng` sau khi Risk Engine giảm trọng số theo ngữ cảnh.
   - Hiển thị kết luận hybrid `SAFE/PHISHING` thay vì để nhãn ML thô trông như kết luận cuối.

2. **Hiển thị đúng OAuth/SSO**
   - Luồng FPT → Google/Microsoft/Apple được hiển thị là `OAuth/SSO chính thức`.
   - Không còn gắn chip đỏ `Đổi domain khi redirect` cho luồng đăng nhập liên kết đã nhận diện.

3. **Xóa cache phân tích cũ khi nâng cấp**
   - Đổi schema cache sang `v213`.
   - Xóa kết quả phân tích theo tab và cache phiên bản cũ trong lần cài/nâng cấp.

4. **Chuẩn bị chia sẻ**
   - Có gói runtime cho cài thử thủ công.
   - Có gói store-ready với `manifest.json` ở thư mục gốc của ZIP.
   - Có hướng dẫn chia sẻ nội bộ và phát hành qua Chrome Web Store/Microsoft Edge Add-ons.

## Điều không thay đổi

- Mô hình URL vẫn là `url-bagged-logistic-3.1.0`.
- Xác suất ML thô có thể vẫn cao trên URL OAuth phức tạp; nó chỉ là một tín hiệu và không tự quyết định mức cảnh báo cuối.
- Blacklist, threat intelligence, homoglyph, typosquat đáng tin, form mật khẩu gửi domain ngoài và HTTPS downgrade vẫn có ưu tiên cao.
