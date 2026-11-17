# Báo cáo trải nghiệm DNS Phishing Guard v2.6.0 trước cải tiến v2.7.0

Ngày đánh giá: 2026-08-10 (Asia/Saigon)

## Phạm vi và phương pháp

Bản được đánh giá là `v2.6.0`. Báo cáo này được hoàn thành trước khi sửa mã cho `v2.7.0`, dựa trên bốn nguồn bằng chứng:

1. Trải nghiệm trực tiếp website công khai `https://shopvanmanh.com/` ở chế độ chỉ đọc.
2. Ảnh chụp extension đang hoạt động trên chính website này do người dùng cung cấp.
3. Chạy lại toàn bộ release gate bằng `npm run validate`.
4. Đọc luồng tính điểm, phân tích nội dung và cách popup trình bày trạng thái thiếu dữ liệu.

Không đăng nhập, không điền hoặc gửi form, không nhắn tin, không tải tệp và không thực hiện giao dịch. Báo cáo chỉ đánh giá tín hiệu kỹ thuật và trải nghiệm người dùng; không kết luận website là lừa đảo hay vi phạm pháp luật.

## Kết quả kiểm tra hiện tại

`npm run validate` của v2.6.0: **PASS**.

- Accuracy URL ML: `96,48%`.
- Precision: `99,46%`.
- Recall: `93,43%`.
- False-positive rate: `0,50%`.
- Hybrid release regression: `20/20`.
- Complex-legit regression: `24` ca, không có hybrid false positive.

Quan sát trực tiếp `shopvanmanh.com`:

- Trang tự mô tả là nền tảng mua bán tài khoản và dịch vụ Valorant.
- Có khu vực `Nạp tiền`, `ACC TỰ CHỌN`, `DEADMAIL`, `DROPMAIL`, `Cày rank` và hỗ trợ khôi phục tài khoản.
- Có nhiều kênh liên hệ/giao dịch ngoài website như Zalo, Discord và Facebook.
- Không thấy form mật khẩu, thuộc tính tải xuống hay meta refresh ở trang đầu trong lần quan sát.
- Ảnh chụp extension trả `CHƯA ĐỦ DỮ LIỆU`, `RISK 0/100`, chất lượng bằng chứng `26/100`.

Trạng thái màu hổ phách là an toàn hơn dấu kiểm xanh, nhưng con số `0/100` mâu thuẫn với chính kết luận “chưa đủ dữ liệu”.

## Phát hiện ưu tiên

### P1 — `0/100` có thể bị hiểu thành “không có rủi ro”

Khi hệ thống chưa đủ dữ liệu, điểm rủi ro thực tế chưa được xác định. Hiển thị `0/100` khiến người dùng phổ thông dễ coi đây là giấy chứng nhận an toàn, dù phần chữ đang cảnh báo điều ngược lại. Đây là lỗi truyền đạt có thể tác động trực tiếp đến quyết định đăng nhập hoặc thanh toán.

Yêu cầu sửa: dùng `—/100` hoặc `CHƯA XÁC ĐỊNH` cho risk khi coverage không đủ; giữ `26/100` dưới nhãn riêng `Chất lượng bằng chứng`.

### P1 — Không nói rõ đã kiểm tra gì và còn thiếu gì

Popup chỉ đưa ra một trạng thái chung. Người dùng không biết URL ML, RDAP, blacklist, nội dung trang, chuyển hướng hay Threat Intelligence đã chạy thành công hay chưa. Nút “Quét lại” cũng không giải thích quét lại sẽ bổ sung được lớp bằng chứng nào.

Yêu cầu sửa: tạo assessment coverage có ba mức `COMPLETE`, `PARTIAL`, `INSUFFICIENT`, kèm các lớp đã kiểm tra, lớp còn thiếu, dữ kiện đã xác minh và hành động tiếp theo.

### P1 — Thiếu ngữ cảnh giao dịch tài khoản game bên thứ ba

Luật `SCAM_COMMERCE` hiện tập trung mạnh vào mã thẻ, voucher, “nạp lậu”, khuyến mãi và trường nhập mã/ID game. Một marketplace tài khoản game có các cụm `acc tự chọn`, `mua/bán/thu acc`, `deadmail`, `dropmail`, `cày thuê`, `chuyển vùng`, liên hệ Zalo/Telegram/Discord và hành động nạp/thanh toán có thể không đạt ngưỡng, dù đây là ngữ cảnh người dùng cần thận trọng và xác minh chủ thể giao dịch.

Yêu cầu sửa: thêm chỉ báo ngữ cảnh “Giao dịch game bên thứ ba cần xác minh”. Chỉ kích hoạt khi có tổ hợp mạnh; không gọi website là scam chỉ từ vài từ khóa.

### P2 — Trạng thái thiếu dữ liệu chưa phân hóa theo mức độ

Một trang blog mới, một website bị HTTP 403 và một marketplace có nhiều dấu hiệu giao dịch đều có thể bị gom vào cùng một nhãn hổ phách. Người truy cập nhiều website sẽ nhanh chóng bỏ qua cảnh báo nếu mọi ca chưa xác minh đều trông giống nhau.

Yêu cầu sửa: cho biết loại bất định, ví dụ `thiếu dữ liệu danh tính`, `không đọc được nội dung`, `đã thấy giao dịch bên thứ ba nhưng chưa xác minh uy tín`.

### P2 — Hành động tiếp theo còn chung chung

“Quét lại trang” không đủ cho tình huống liên quan giao dịch. Người dùng cần hướng dẫn cụ thể như kiểm tra domain chính thức của nhà phát hành, chính sách hoàn tiền/bảo hành, danh tính đơn vị vận hành, tránh gửi OTP/mã thẻ và tránh thanh toán qua kênh cá nhân trước khi xác minh.

## Đánh giá theo ba vai trò

### 1. Người kiểm thử phần mềm — 7,8/10

Điểm tốt:

- Release gate tái lập nhanh và toàn bộ kiểm thử hiện có đều pass.
- Metrics URL ML được tách khỏi hybrid verdict, tránh thổi phồng độ chính xác.
- Có hard-negative cho website chính thức và bài viết cảnh báo, giúp giữ false positive thấp.
- Luồng quyền riêng tư, URL token, redirect loop và giới hạn Link Lab được kiểm soát tương đối rõ.

Điểm trừ:

- Chưa có schema coverage có thể kiểm thử độc lập.
- Chưa có fixture đại diện marketplace tài khoản game bên thứ ba.
- Chưa có E2E Chrome/Edge cho cách popup hiện điểm khi risk chưa xác định.
- Corpus page-level vẫn nhỏ hơn nhiều so với corpus URL ML.

### 2. Người dùng phổ thông — 7,1/10

Điểm tốt:

- Giao diện bắt mắt, trạng thái màu và câu chữ dễ nhận biết.
- Không còn dấu kiểm xanh khi thiếu nội dung hoặc danh tính website.
- Có lời nhắc không nhập dữ liệu/thanh toán khi chưa xác minh.

Điểm trừ:

- `RISK 0/100` lấn át phần chữ và tạo cảm giác an toàn giả.
- Không hiểu `26/100` là độ tin cậy, phạm vi quét hay mức nguy hiểm.
- Không biết hệ thống đã nhìn thấy hoạt động mua bán tài khoản game hay chưa.
- Hành động duy nhất chủ yếu là quét lại, chưa hỗ trợ quyết định thực tế.

### 3. Người truy cập nhiều website — 7,4/10

Điểm tốt:

- Tốc độ phân tích nhanh; giao diện kỹ thuật có breakdown, lịch sử và Link Lab.
- ML-only không tự đẩy website lên cảnh báo nặng nếu thiếu bằng chứng độc lập.
- Mức false positive trên tập kiểm thử hiện tại thấp.

Điểm trừ:

- Nhãn thiếu dữ liệu quá tổng quát, dễ gây mệt mỏi cảnh báo trên nhiều domain mới/lạ.
- Không có “bản đồ bằng chứng” để xem nhanh lớp nào thất bại.
- Chưa phân biệt rõ website ít dữ liệu nhưng không có hành vi nhạy cảm với website có giao dịch bên thứ ba.
- Chưa có pilot theo base rate duyệt web thực tế để đo tỷ lệ bỏ qua cảnh báo.

## Điểm tổng hợp trước cải tiến

| Vai trò | Điểm |
| --- | ---: |
| Người kiểm thử phần mềm | 7,8/10 |
| Người dùng phổ thông | 7,1/10 |
| Người truy cập nhiều website | 7,4/10 |
| Trung bình | **7,4/10** |

## Tiêu chí chấp nhận cho v2.7.0

1. Risk chưa xác định không được hiển thị là `0/100`.
2. Có coverage assessment ổn định và kiểm thử được: trạng thái, lớp đã kiểm tra, lớp còn thiếu, dữ kiện xác minh, hành động tiếp theo.
3. Nhận diện tổ hợp mạnh của marketplace/game-account commerce và chỉ đưa ra cảnh báo xác minh, không kết luận pháp lý.
4. Có positive fixture giống ngữ cảnh `shopvanmanh.com` và hard-negative cho domain chính thức, bài viết/wiki/chính sách, marketplace chỉ có tín hiệu yếu.
5. Release regression và complex-legit regression không giảm; URL ML metrics không bị thay đổi giả tạo bởi luật page-level.
6. Popup và banner giải thích nhất quán giữa `Risk chưa xác định` và `Chất lượng bằng chứng`.

## Kết luận trước cải tiến

v2.6.0 đã có nền tảng phòng thủ tốt và thận trọng hơn các bản trước, nhưng chưa đạt mục tiêu bảo vệ người dùng phổ thông trong tình huống dữ liệu không đầy đủ. Lỗi cần sửa trước tiên không phải là ép hệ thống kết luận website nguy hiểm, mà là trình bày đúng sự bất định và nêu rõ ngữ cảnh giao dịch cần xác minh. Đây là hướng cải tiến giữ được độ an toàn mà không đánh đổi false-positive rate.
