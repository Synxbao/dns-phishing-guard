# DNS Phishing Guard v2.7.3 - Domain Age & Conditional Payment Evidence

Ngày phát hành: 2026-08-10

## Mục tiêu

Giảm trạng thái amber `CHƯA ĐỦ DỮ LIỆU` trên checkout chính thức khi các lớp kỹ thuật sạch,
nhưng không biến logo ví/ngân hàng thành allowlist và không nới lỏng phát hiện giả mạo thương hiệu.
URL ML `url-logistic-5.0.0`, dataset 4.000 URL, calibration và threshold 0,59 không đổi.

## Ngưỡng tuổi domain mới

- `>= 730 ngày`: `ESTABLISHED_DOMAIN` như trước; vẫn là ngưỡng duy nhất được dùng cho reputation cap của Risk Engine.
- `365-729 ngày`: `MODERATELY_ESTABLISHED`; được xem là identity context đã nhận diện, với label nêu rõ độ tin cậy thấp hơn domain lâu năm.
- `180-364 ngày`: vẫn `UNVERIFIED`.
- `< 180 ngày`: vẫn `NEW_DOMAIN` và tiếp tục là tín hiệu rủi ro; dưới 30 ngày giữ trọng số cao nhất.

Mốc 365 ngày được chọn vì một năm hoạt động là ranh giới dễ giải thích và đủ để tách domain mới/vừa
khỏi domain hoàn toàn chưa có lịch sử. Mốc 730 ngày vẫn giữ cho reputation cap để tránh nới lỏng URL ML
trên domain chỉ mới một năm tuổi.

## Tín hiệu tích hợp thanh toán

`modules/payment-signals.js` tìm VietQR, ZaloPay, MoMo, VNPay, NAPAS, Visa và Mastercard trong một
container checkout/payment thực sự. Một logo hoặc chuỗi chữ đứng riêng không đủ điều kiện. Detector yêu cầu:

- ngữ cảnh thanh toán/checkout/đơn hàng;
- control tương tác như button, radio, select hoặc link hành động;
- số tiền/đơn vị tiền tệ và hành động thanh toán;
- provider evidence từ text/logo/resource domain;
- phần tử không nằm trong vùng quảng cáo do `page-signal-filter` nhận diện.

Tín hiệu đủ mạnh cộng tối đa 20 điểm **evidence coverage**, không cộng hoặc trừ Risk score. Với trang
SAFE đã hoàn tất các lớp domain-list, URL ML và page content, coverage có floor 25/100; payment evidence
có thể đưa kết quả lên ngưỡng trình bày 45/100. Label luôn ghi rõ đây là tích hợp quan sát được, không
phải xác thực website, đơn vị bán hàng hoặc giao dịch thật.

Boost tự động về 0 khi có một trong các điều kiện: Risk khác SAFE, blacklist, Threat Intelligence unsafe,
brand mismatch, commerce/game brand mismatch, form mật khẩu gửi ra ngoài origin, risky download,
HTTPS downgrade hoặc redirect qua nhiều domain bất thường.

## RDAP và identity

`background.js` đã dùng đúng `registrableDomain` cho lookup RDAP: subdomain như `shop.vnggames.com`
tra `vnggames.com`, không tra riêng subdomain. Khi RDAP fail hoàn toàn, hệ thống không giả định identity
đã xác minh. Nếu payment evidence đủ mạnh và các lớp còn lại sạch, trạng thái chuyển từ `UNDETERMINED`
sang `PROVISIONAL`; lớp `IDENTITY` vẫn nằm trong danh sách thiếu để người dùng thấy giới hạn.

Fixture RDAP unavailable sau sửa: Risk `SAFE 0`, raw evidence 14, floor lớp kỹ thuật 25, payment +20,
evidence cuối 45/100, label `BẰNG CHỨNG HỖ TRỢ TỐT`.

Mô phỏng offline riêng cho `https://shop.vnggames.com/` (không mở website, không gọi RDAP):

- registrable domain được tính là `vnggames.com`;
- age giả lập 420 ngày: URL ML 17,13%, Risk `SAFE 0`, identity `MODERATELY_ESTABLISHED`, evidence 46/100;
- RDAP giả lập unavailable: Risk vẫn `SAFE 0`, identity `UNVERIFIED` vẫn hiển thị thiếu, evidence 45/100 và `PROVISIONAL/CONFIDENT`.

## Protected payment brands, không phải allowlist

`data/protected-payment-domains.json` chứa reference cho ZaloPay, MoMo, VNPay, VNPayment, NAPAS và
VietQR. Tệp có `trustAllowlist: false`; các domain này chỉ được trộn vào pool typosquat/homoglyph.
`isKnownDomain` vẫn chỉ đọc `known-domains.json`.

Nguồn/methodology nằm trong `data/protected-payment-domains.json` và
`data/PROTECTED_PAYMENT_DOMAINS.md`. Quy trình mở rộng đề xuất dùng snapshot có ngày/checksum từ danh
sách trung gian thanh toán được NHNN cấp phép và hệ sinh thái/thành viên NAPAS, sau đó review thủ công;
không nhập một allowlist ngành không nguồn gốc.

## Adversarial logo giả

Probe offline thêm 5 case reserved-domain:

| Case | Kết quả | Payment boost |
| --- | --- | ---: |
| `zal0pay.example` | HIGH / NGUY HIỂM | 0 |
| `vietqrr.example` | HIGH / NGUY HIỂM | 0 |
| `vietcombank.example` | HIGH / NGUY HIỂM | 0 |
| `m0mo.example` | HIGH / NGUY HIỂM | 0 |
| ZaloPay Punycode `xn--zlopay-3nf.example` | HIGH / NGUY HIỂM | 0 |

Logo giả không làm tăng Risk; detector payment cũng không làm giảm Risk. Protected-brand typo pool và
homoglyph/Punycode layer vẫn quyết định cảnh báo.

## Giới hạn

- DOM heuristic không thể chứng minh SDK/cổng thanh toán phía sau thật sự xử lý giao dịch; phishing page có thể sao chép toàn bộ logo và layout.
- Checkout dựng bằng canvas, closed shadow DOM hoặc nội dung tải sau scan có thể chưa được nhận diện.
- Cổng white-label/redirect ngoài danh sách provider có thể không nhận được evidence boost dù hợp pháp.
- RDAP privacy/failure vẫn để lại identity gap; trạng thái xanh chỉ có nghĩa chưa thấy phishing rõ ràng trong phạm vi đã quét.
