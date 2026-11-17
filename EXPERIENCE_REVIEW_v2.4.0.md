# Báo cáo trải nghiệm DNS Phishing Guard v2.4.0

Ngày đánh giá: 2026-08-10 (Asia/Saigon)

## Kết luận điều hành

DNS Phishing Guard v2.4.0 đã cải thiện đúng vấn đề báo nhầm quan trọng nhất: URL ML không còn được dùng như phán quyết phishing và chỉ báo ML đơn lẻ không còn che trang. TikTok `/@handle`, URL dài, OAuth/SSO và localhost đều vượt qua bộ hồi quy mà không tạo cảnh báo trên trang.

Phần lõi phát hiện đủ tốt cho **bản beta kỹ thuật**. Tuy nhiên, tôi chưa khuyến nghị phát hành rộng cho người dùng phổ thông trước khi sửa các vấn đề an toàn tương tác sau:

1. Cảnh báo đỏ không khóa focus của trang phía sau; ô mật khẩu đang được focus vẫn nhận ký tự dù overlay đã xuất hiện.
2. Nút `Cho phép 10 phút` và `Người lớn: cho phép một lần` cho phép vượt cảnh báo quá dễ trong chế độ thường.
3. Ở chiều rộng 320 px, nút `Quay lại` của cảnh báo đỏ nằm sâu dưới vùng cuộn thay vì luôn xuất hiện.
4. Cấu hình `uiProfile`/`simpleWarningsOnly` chưa tạo ra giao diện đơn giản thực sự; bản hiện tại vẫn là giao diện kỹ thuật.

Phán quyết phát hành:

- Lõi phát hiện và hồi quy: **PASS**.
- Beta nội bộ/kỹ thuật: **PASS có điều kiện**.
- Phát hành Store cho người dùng phổ thông: **HOLD** cho đến khi sửa các mục ưu tiên P0/P1.

## Phạm vi trải nghiệm

### Quan sát trực tiếp

- Trải nghiệm popup ở các trạng thái `SAFE`, `SUSPICIOUS`, `HIGH` và `LOCAL_DEVELOPMENT`.
- Trải nghiệm Link Lab với URL lành tính, địa chỉ nội bộ bị từ chối và fixture tải tệp `.exe` cục bộ.
- Trải nghiệm trang Safe Preview, trang blacklist block và cảnh báo trực tiếp trên website.
- Kiểm tra responsive ở 320 px; không có tràn ngang.
- Kiểm tra focus bàn phím khi cảnh báo đỏ xuất hiện trên một form đăng nhập fixture cục bộ.
- Không truy cập URL phishing/malware thật và không gửi dữ liệu nhạy cảm ra ngoài.

Giao diện được chạy bằng chính HTML/CSS/JS của extension với phản hồi service worker được mô phỏng cục bộ. Fixture đã được xóa sau khi thử. Môi trường hiện tại không có Chrome/Edge bên ngoài được kết nối để tải unpacked extension, vì vậy latency RDAP, quyền trình duyệt và hành vi Store build trên Chrome/Edge thật chưa được quan sát end-to-end.

### Kiểm chứng tự động

- `npm run validate`: PASS.
- Syntax check: PASS cho 29 tệp JavaScript/MJS.
- Independent holdout: 398 URL, TP/TN/FP/FN = 185/199/1/13.
- Accuracy 96,48%; Precision 99,46%; Recall 93,43%; F1 96,35%.
- FPR 0,50%; FNR 6,57%.
- Hybrid release regression: 20/20.
- Complex-legit regression: 24 ca, 0 ML FP, 0 hybrid FP, 0 cảnh báo on-page.
- Inference benchmark: trung bình 0,0275 ms, p95 0,0445 ms/URL trong Node.js.

## Đánh giá theo ba vai trò

### 1. Người test phần mềm — 8,2/10

Điểm tốt:

- Dự án có dataset, split, model, test, replay prediction và báo cáo tái lập được.
- Split theo registrable domain loại bỏ domain leakage giữa các tập.
- Logic context-aware và warning gate được kiểm tra rõ cho TikTok, OAuth, localhost và typosquat.
- Cách trình bày `Độ bất thường URL` đúng hơn nhiều so với nhãn `ML = phishing` trước đây.
- Link Lab có giới hạn redirect, byte, timeout, không cookie/referrer và kiểm tra loại tệp.

Điểm chưa đạt:

- Chưa có E2E test thật cho MV3 service worker, DNR, focus trap, keyboard, Safe Preview và quyền trình duyệt.
- Benchmark hiện chỉ đo URL inference, chưa đo toàn bộ content scan, RDAP, storage, badge và render cảnh báo.
- Chưa có temporal holdout tương lai hoặc dữ liệu production được gắn nhãn qua thời gian.
- Một số cấu hình tồn tại nhưng chưa tạo khác biệt giao diện thực tế.

Nhận định: cấu trúc kiểm thử tốt hơn nhiều extension cá nhân thông thường, nhưng cần bổ sung E2E browser tests trước khi coi đây là release consumer-grade.

### 2. Người dùng phổ thông — 6,6/10

Điểm tốt:

- Màu xanh/đỏ, risk dial và câu `Dừng lại và rời khỏi trang` rất dễ hiểu.
- Nhãn xanh dùng `Chưa thấy bằng chứng phishing rõ ràng`, không hứa website an toàn tuyệt đối.
- Cảnh báo đỏ che trang, không có nút đóng nhỏ và nêu rõ không nhập mật khẩu/OTP.
- Trang Safe Preview nói rõ giới hạn và việc vẫn có thể lộ IP.
- Giao diện tiếng Việt, có đọc hướng dẫn và Child Mode.

Điểm gây khó:

- Popup chứa nhiều thuật ngữ như RDAP, DNR, hybrid, public suffix, ML raw và breakdown.
- Người dùng phải cuộn dài mới tới lý do, hành động và phần an toàn nội dung.
- Khi quét một link nguy hiểm trong Link Lab, phần đầu popup vẫn có thể đang xanh vì đó là trạng thái tab hiện tại. Hai đối tượng đánh giá nằm chung một màn hình nên dễ bị hiểu nhầm.
- Nút bỏ qua cảnh báo quá dễ bấm và không yêu cầu xác nhận trong chế độ thường.
- Trên màn hình 320 px, hành động an toàn chính không luôn nằm trong vùng nhìn thấy.

Nhận định: giao diện đẹp và tạo cảm giác sản phẩm hoàn thiện, nhưng hiện phù hợp với người hiểu kỹ thuật hơn người dùng đại chúng.

### 3. Người truy cập nhiều website — 7,7/10

Điểm tốt:

- ML đơn lẻ không làm gián đoạn trang, giảm mệt mỏi vì cảnh báo.
- Localhost/mạng riêng không bị phạt theo tiêu chí web công cộng.
- Popup có lịch sử, thống kê, cache hit, RDAP rate và dynamic scan count.
- Whitelist không vô hiệu hóa hành vi trang nguy hiểm; đây là thiết kế đúng.
- Link Lab hữu ích khi nhận link từ chat/email và chưa muốn mở trực tiếp.

Điểm còn thiếu:

- Chưa đo CPU/battery của content scan trên SPA, mạng xã hội và trang có DOM lớn.
- Lịch sử chưa có tìm kiếm, lọc theo mức độ/domain/thời gian hoặc nút đánh dấu báo nhầm.
- Thống kê chưa có p50/p95 latency, số lần chặn thật, số lần người dùng bỏ qua, tỷ lệ báo nhầm do người dùng xác nhận và phiên bản model/list đang vận hành.
- URL đầy đủ có thể được lưu trong lịch sử cảnh báo, gây rủi ro riêng tư với query token hoặc nội dung tìm kiếm.

Nhận định: trải nghiệm hàng ngày đã ít gây phiền hơn v2.3.1, nhưng cần telemetry riêng tư và benchmark thực tế trước khi khẳng định không ảnh hưởng người dùng duyệt web cường độ cao.

## Các phát hiện ưu tiên

### P0 — Cảnh báo đỏ không khóa tương tác bàn phím phía sau

Quan sát trực tiếp: khi ô mật khẩu đang được focus và cảnh báo `HIGH` xuất hiện, `document.activeElement` vẫn là ô mật khẩu. Dữ liệu giả tiếp tục được nhập vào ô phía sau overlay.

Tác động:

- Người dùng có thể tiếp tục gõ thông tin nhạy cảm dù không nhìn thấy form.
- Trang có listener bàn phím hoặc submit tùy chỉnh vẫn có thể phản ứng.
- `aria-modal` hiện tại không đủ nếu không quản lý focus và không làm phần nền inert.

Khuyến nghị:

- Khi mở cảnh báo đỏ: blur active element, đặt `document.body.inert = true`, focus nút `Quay lại` và trap `Tab` trong alert.
- Chặn `keydown`, `beforeinput` và `submit` ở capture phase trong thời gian cảnh báo `HIGH` hoạt động.
- Khôi phục focus/inert chỉ sau một hành động bỏ qua đã được xác nhận rõ ràng.

### P1 — Các đường vượt cảnh báo quá dễ sử dụng

Quan sát:

- Cảnh báo đỏ có nút `Cho phép 10 phút` gọi bỏ qua ngay, không có confirm trong chế độ thường.
- Trang blacklist có nút `Người lớn: cho phép một lần`; PIN chỉ bắt buộc khi Child Mode đang bật.
- DNR `allowDomainOnce` tồn tại đến khi tab bị dọn, nên tên `cho phép một lần` không phản ánh chính xác vòng đời thực tế.

Tác động: một cú bấm nhầm có thể vô hiệu hóa lớp bảo vệ đúng lúc rủi ro cao nhất.

Khuyến nghị:

- Không cho bỏ qua một-click đối với blacklist, threat-intel confirmed hoặc `HIGH` có nhiều bằng chứng.
- Yêu cầu confirm hai bước, hiển thị domain rõ ràng và cân nhắc PIN/admin confirmation cho mọi bypass đỏ.
- Đổi DNR allow rule thành một navigation thật sự hoặc TTL ngắn; tự xóa sau lần commit đầu tiên.
- Đổi cách trình bày bypass thành hành động phụ, không đặt ngang hàng với `Quay lại`.

### P1 — Hành động an toàn không luôn hiện trên mobile

Ở 320 px, phần chi tiết chiếm gần toàn bộ panel và nút `Quay lại` nằm dưới vùng cuộn. Cảnh báo vẫn dễ nhận biết nhưng đường thoát an toàn không tức thời.

Khuyến nghị:

- Đặt action footer sticky ở đáy panel.
- Luôn hiển thị `Quay lại` trước các metric kỹ thuật.
- Thu gọn domain/model/breakdown vào mục `Xem chi tiết` trên màn hình nhỏ.

### P1 — Chưa có giao diện consumer thực sự

`uiProfile: technical` và `simpleWarningsOnly` được lưu/truyền nhưng chưa được dùng để thay đổi popup hoặc cảnh báo. Store listing nói về bản dễ dùng trong khi gói hiện tại vẫn hiển thị `TECHNICAL` và nhiều dữ liệu chuyên sâu.

Khuyến nghị:

- Mặc định Store build dùng ba trạng thái đơn giản: `Chưa thấy nguy cơ`, `Cần kiểm tra`, `Dừng lại`.
- Chỉ hiển thị domain, lý do chính và một hành động an toàn; đưa RDAP/ML/breakdown vào `Chi tiết kỹ thuật`.
- Giữ technical profile cho developer, tester và người dùng nâng cao.

### P2 — Link Lab có thể tạo request có tác dụng phụ

Probe hiện dùng `GET`. Dù không gửi cookie, một URL magic-login, reset mật khẩu, xác nhận email, unsubscribe hoặc action token vẫn có thể bị tiêu thụ hoặc kích hoạt ở phía máy chủ.

Khuyến nghị:

- Thử `HEAD` trước; chỉ dùng `GET` khi cần đọc nội dung và sau khi đánh giá URL không giống action/token một lần.
- Cảnh báo riêng khi URL chứa token/code/key dài hoặc path như `confirm`, `reset`, `unsubscribe`, `magic-login`.
- Nêu rõ Link Lab có thể kích hoạt hành vi server-side, không chỉ làm lộ IP.

### P2 — Chặn mạng nội bộ mới dựa vào hostname/IP dạng literal

`isBlockedLiteralHost` chặn localhost, IP riêng và suffix nội bộ trực tiếp. Chưa có bằng chứng rằng extension xác minh IP sau DNS resolution ở mỗi redirect. Domain công khai trỏ hoặc rebind tới IP riêng là rủi ro còn lại cần test trên Chrome/Edge thật.

Khuyến nghị:

- Thêm test DNS rebinding/public-domain-to-private-IP.
- Nếu trình duyệt không cung cấp cách kiểm tra địa chỉ đã resolve, chuyển probe mạng sang backend cô lập có egress policy và IP validation cho từng hop.
- Không mô tả Link Lab là chống SSRF hoàn chỉnh khi chưa có lớp kiểm tra này.

### P2 — URL đầy đủ có thể lưu hoặc gửi query nhạy cảm

- Lịch sử lưu `entry.url` đầy đủ và CSV xuất lại URL đó.
- Threat Intelligence tùy chọn gửi toàn bộ `{ url }` tới endpoint cấu hình.
- Query OAuth, reset token, mã mời hoặc từ khóa tìm kiếm có thể chứa dữ liệu riêng tư.

Khuyến nghị:

- Lịch sử mặc định chỉ lưu scheme + hostname + pathname đã chuẩn hóa; bỏ query/fragment.
- Export CSV dùng URL đã redacted như debug export.
- Threat Intel gửi hostname/path hoặc hash/features theo mặc định; nếu cần full URL phải có opt-in và cảnh báo rõ ngay tại setting.

### P2 — Chưa có benchmark end-to-end cho người dùng duyệt nhiều

Content script đọc tối đa 160.000 ký tự và quét nhiều nhóm DOM sau mutation debounce. Đây là thiết kế có thể hoạt động tốt, nhưng benchmark 0,0275 ms hiện chỉ đo URL ML và không phản ánh chi phí này.

Khuyến nghị:

- Đo p50/p95/p99 của `collectPageSignals` trên trang 1k/5k/20k node và SPA thay đổi liên tục.
- Dùng `requestIdleCallback`, ngân sách thời gian, giới hạn node và incremental scan.
- Bỏ qua scan khi tab ẩn hoặc khi mutation không liên quan đến form/link/nội dung nhận diện.

### P3 — Nhãn phiên bản model chưa đồng nhất

Settings ghi `Mô hình Machine Learning URL v4`, trong khi model runtime là `url-logistic-5.0.0`; v4 là phiên bản feature. Nên đổi thành `URL ML v5 · feature v4` hoặc chỉ hiển thị model version lấy từ JSON.

## Diễn giải metrics và nguy cơ báo nhầm

FPR 0,50% của raw URL model là cải thiện rõ so với 1,50%, nhưng tập test cân bằng 50/50 không giống lưu lượng thật. Với Recall 93,43% và FPR 0,50%, nếu phishing chỉ chiếm:

| Tỷ lệ phishing giả định | Xác suất cảnh báo raw ML là phishing thật |
| --- | ---: |
| 0,1% | 15,76% |
| 0,5% | 48,43% |
| 1,0% | 65,37% |
| 5,0% | 90,77% |

Đây không phải metrics của hybrid engine và không dự đoán trực tiếp production. Nó cho thấy quyết định v2.4.0 không cho raw ML tự chặn trang là đúng. Để tiếp tục giảm báo nhầm, nên đo theo base rate thật, thời gian thật và nhóm website thật thay vì chỉ tăng accuracy trên dataset cân bằng.

## Đề xuất dashboard thông số tiếp theo

Khu vực `Thông số` hiện đã có nền tảng tốt. Nên bổ sung:

- Số trang đã chặn trước tải và số cảnh báo on-page.
- Số lần `Cho phép 10 phút`, whitelist và báo nhầm.
- p50/p95 thời gian static scan, content scan và RDAP.
- Tỷ lệ kết quả theo domain mới/domain phổ biến/local/private.
- Model version, feature version, threshold và thời điểm cập nhật blacklist/model.
- Biểu đồ 7/30 ngày và bộ lọc domain/mức cảnh báo.
- Nút `Báo nhầm` có lý do chọn sẵn, mặc định chỉ lưu cục bộ; chỉ gửi telemetry khi người dùng opt-in.

## Thứ tự cải tiến khuyến nghị

1. Khóa focus và tương tác nền khi cảnh báo `HIGH`.
2. Làm cứng mọi bypass đỏ và sửa `allow once` thành đúng một lần.
3. Giữ nút `Quay lại` sticky trên mobile.
4. Tách consumer profile khỏi technical profile.
5. Redact URL trong history/CSV/Threat Intel.
6. Làm rõ và gia cố Link Lab đối với GET side effect và DNS rebinding.
7. Thêm browser E2E, performance benchmark và temporal holdout.
8. Sau đó mới phát hành Store rộng và thu thập feedback báo nhầm theo cơ chế opt-in.

## Điểm tra cứu mã nguồn

- Focus/overlay và action cảnh báo: `content.js:407`, `content.js:712`, `content.js:744`, `content.js:813`, `content.js:889`.
- Bypass và parent gate: `background.js:653`, `background.js:859`, `background.js:912`, `modules/blocking.js:75`, `blocked.js:32`.
- Consumer profile chưa được áp dụng: `popup.js:25`, `background.js:84`, `background.js:605`.
- Link Lab literal-host check và GET probe: `modules/link-lab.js:35`, `modules/link-lab.js:249`.
- Lưu/gửi URL đầy đủ: `modules/history.js:53`, `modules/history.js:172`, `modules/threat-intel.js:63`.
- Nhãn model chưa đồng nhất: `popup.html:274`.

## Kết luận cuối

v2.4.0 đã đi đúng hướng về độ chính xác: giảm false positive, hiểu localhost, không phạt `@handle` và không để ML đơn lẻ làm gián đoạn người dùng. Điểm yếu hiện tại không còn chủ yếu nằm ở model mà nằm ở **an toàn tương tác, giao diện consumer, quyền riêng tư URL và kiểm thử end-to-end**.

Nếu sửa bốn mục P0/P1 đầu tiên, extension có thể chuyển từ beta kỹ thuật sang release candidate dành cho người dùng phổ thông.
