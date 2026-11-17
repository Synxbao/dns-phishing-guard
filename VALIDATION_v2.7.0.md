# Validation v2.7.0

Ngày kiểm tra: 2026-08-10 (Asia/Saigon)

## Lệnh tái lập

```powershell
npm run validate
```

## Release gates

- Manifest/version `2.7.0`: PASS.
- JavaScript syntax cho background, content, popup và modules thay đổi: PASS.
- Coverage assessment `COMPLETE/PARTIAL/INSUFFICIENT`: PASS.
- Risk `UNDETERMINED` được mask thành `—/100` trong Simple UI, Technical UI, on-page content panel và Link Lab: PASS.
- `GAME_COMMERCE` positive fixture kiểu marketplace tài khoản game: PASS (`WARNING 70/100`).
- Official Riot domain negative: PASS (`GAME_COMMERCE` không kích hoạt).
- Bài viết cảnh báo game-account negative: PASS.
- Official gift-card và scam-commerce article negative cũ: PASS.
- Asset-only `.js`/`.css` trong `<link>` không bị tính là risky download: PASS.
- Redirect loop, HTTP không thành công, action-token convention hiện có, byte cap và Safe Preview lock: PASS.
- Byte cap thực thi đúng, nhưng adversarial clean-prefix cho thấy `truncated=true` chưa hạ evidence coverage hoặc ngăn verdict xanh: GAP cần sửa.
- URL privacy, OAuth/SSO, localhost/private context, blacklist và model integrity: PASS.

## Adversarial probe offline

- Source manifest: `evaluation/sourced-test-urls.json`, 24 URL fixture; thêm 2 case structural.
- Chính sách: 0 request mạng, không gọi RDAP/Threat Intelligence thật, threat-shaped URL chỉ dùng `.example`; `ageInfo` được ghi rõ là giả lập offline.
- Không trùng 20 release-regression hoặc 24 complex-legit hiện có.
- 16 case adversarial thực thi: 5 real gap (31,25%), 3 hybrid compensated (18,75%).
- 24 case thực thi: 16 expected pass; 7/7 benign hard-negative đạt kỳ vọng.
- Gap chính: action-token lệch convention (2), từ lóng SCAM/GAME_COMMERCE (2), coverage 64 KiB (1).
- Structural limitation: optional-permission audit phản ánh active grants; `document_idle` có thể bỏ DOM trang trung gian dù `webNavigation` vẫn theo dõi redirect.
- Báo cáo đầy đủ và đánh giá ba persona: `evaluation/results/ADVERSARIAL_PROBE_REPORT.md`.

## Metrics URL ML độc lập

Model runtime không đổi: `url-logistic-5.0.0`.

| Chỉ số | Kết quả |
| --- | ---: |
| TP / TN / FP / FN | 185 / 199 / 1 / 13 |
| Accuracy | 96,48% |
| Precision | 99,46% |
| Recall | 93,43% |
| F1 | 96,35% |
| Specificity | 99,50% |
| False-positive rate | 0,50% |
| False-negative rate | 6,57% |

- Embedded independent test consistency: PASS.
- Holdout replay consistency: PASS.
- Hybrid release regression: 20/20.
- Complex-legit regression: 24 ca, 0 ML false positive, 0 hybrid false positive, 0 on-page warning, 0 context mismatch.
- Runtime benchmark 2.000 predictions: p95 khoảng 0,05 ms.

## Bounded QA `shopvanmanh.com`

Phạm vi: website công khai, chỉ đọc; không đăng nhập, không gửi form, không nhắn tin, không tải tệp và không giao dịch.

Quan sát DOM đã render:

- 15 nhóm marketplace/dịch vụ game, gồm `acc tự chọn`, `mua/bán acc`, `deadmail`, `dropmail`, `cày thuê/rank`, `check/kho skin`.
- 5 nhóm giao dịch/thanh toán/bảo hành.
- 4 action controls liên quan nạp tiền hoặc dịch vụ game.
- Nhiều kênh ngoài nền tảng: Zalo, Discord và Facebook.
- Brand Riot Games/Valorant xuất hiện nổi bật trên domain không thuộc nhà phát hành.

Replay classifier với tín hiệu quan sát:

- Content category: `GAME_COMMERCE`.
- Content level/score: `WARNING 70/100`.
- Phishing Risk vẫn tách riêng; nếu identity chưa được xác minh thì hiển thị `CHƯA XÁC ĐỊNH`, không hiển thị `0/100`.
- Evidence assessment mẫu: `PARTIAL`, `riskState=UNDETERMINED`, hành động đề xuất là xác minh domain chính thức, chủ thể vận hành, chính sách và thanh toán.

Live Link Lab probe:

- HTTP 200, 49.552 byte, 11 script, 0 form.
- 0 risky download link sau khi sửa asset false positive.
- HTML tĩnh không chứa đủ nội dung marketplace vì phần lớn nội dung được render động; đây là giới hạn được thể hiện trong coverage, không phải xác nhận an toàn.

## Browser UI QA

- Technical popup tải tại chiều rộng mặc định: không horizontal overflow.
- Thẻ **Phạm vi bằng chứng** hiển thị đúng cấu trúc.
- Viewport 360 px tạo body 320 px; coverage grid và metrics chuyển thành một cột; không horizontal overflow.
- Lỗi `chrome.runtime` khi mở popup như website localhost là giới hạn của harness tĩnh, không phải lỗi trong context extension.

## Regression `rexawin.com`

- URL ML vẫn dự đoán `SAFE` với xác suất `7,52%`; đây chỉ là tín hiệu cấu trúc URL.
- Live Link Lab probe trả HTTP `403`, đọc 10 byte và không thấy chỉ báo tải tự động.
- Vì nội dung thực tế chưa được xác minh, verdict vẫn ở nhóm `SUSPICIOUS/PARTIAL`, không chuyển sang trạng thái xanh.
- v2.7.0 trình bày rõ lớp HTML còn thiếu và giữ Safe Preview bị khóa cho phản hồi HTTP không thành công.

## Giới hạn

- Chưa chạy E2E trên Chrome/Edge profile đã load unpacked extension.
- Chưa có pilot production hoặc temporal holdout riêng cho marketplace game.
- Keyword/context classifier là bộ lọc sàng lọc; không dùng để kết luận pháp lý hoặc uy tín tuyệt đối.
- Adversarial corpus là fixture tuyển chọn offline, không phải ước lượng prevalence ngoài production và không chứa feed phishing/malware thật.
