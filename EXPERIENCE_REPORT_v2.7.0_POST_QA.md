# Báo cáo trải nghiệm DNS Phishing Guard v2.7.0 sau cải tiến

Ngày đánh giá: 2026-08-10 (Asia/Saigon)

## Kết luận

v2.7.0 giải quyết đúng mâu thuẫn lớn nhất của v2.6.0: trạng thái chưa đủ dữ liệu không còn đi kèm `RISK 0/100`. Người dùng nhìn thấy Risk `CHƯA XÁC ĐỊNH`, Evidence Score riêng, các lớp đã kiểm tra/còn thiếu và hành động tiếp theo. Marketplace tài khoản game được nhận diện như ngữ cảnh cần xác minh, không bị gán nhãn lừa đảo.

## Đánh giá theo vai trò

| Vai trò | v2.6.0 trước sửa | v2.7.0 sau QA |
| --- | ---: | ---: |
| Người kiểm thử phần mềm | 7,8/10 | **8,8/10** |
| Người dùng phổ thông | 7,1/10 | **8,9/10** |
| Người truy cập nhiều website | 7,4/10 | **8,7/10** |
| Trung bình | 7,4/10 | **8,8/10** |

## Người kiểm thử phần mềm — 8,8/10

Điểm tăng:

- Coverage là object thuần, có release test độc lập.
- Positive/negative fixture bảo vệ cả khả năng phát hiện và false-positive rate.
- Risk state và evidence score không còn bị trộn.
- Link Lab asset false positive đã có regression.
- `npm run validate` pass đầy đủ; metrics ML và complex-legit giữ nguyên.

Chưa đạt 9 hoàn toàn vì chưa có E2E Chrome/Edge profile cài extension và chưa có temporal page-level corpus lớn.

## Người dùng phổ thông — 8,9/10

Điểm tăng:

- Không còn con số 0 gây cảm giác an toàn giả.
- Outcome “Giao dịch cần xác minh” đúng với ngữ cảnh mua bán tài khoản game.
- Hành động tiếp theo cụ thể: kiểm tra domain nhà phát hành, chủ thể vận hành, chính sách và kênh thanh toán.
- Câu chữ nhấn mạnh đây không phải kết luận lừa đảo.

Khoảng trống còn lại là thẻ coverage kỹ thuật có nhiều chữ; cần pilot để đo người dùng có đọc và hiểu đúng hay không.

## Người truy cập nhiều website — 8,7/10

Điểm tăng:

- Phân biệt được thiếu danh tính, thiếu nội dung và lớp tùy chọn.
- Cảnh báo marketplace có ngữ cảnh riêng, giảm tình trạng mọi domain lạ đều trông giống nhau.
- Official domain/article/weak-text negative giúp hạn chế cảnh báo lan rộng.
- Thống kê tách marketplace game và mã trả trước.

Chưa đạt 9 vì chưa có base-rate pilot theo hàng nghìn lượt duyệt web thật và threat intelligence mặc định vẫn chưa cấu hình.

## Phán quyết phát hành

**PASS cho release candidate/beta v2.7.0.** Có thể dùng thử với nhóm người dùng nhỏ. Chưa nên tuyên bố đạt 9/10 production cho tới khi hoàn tất E2E trình duyệt và pilot có đo false positive/false negative theo thời gian.
