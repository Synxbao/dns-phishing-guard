# DNS Phishing Guard v2.5.0 - Unified Safety Release

## Mục tiêu

Phát hành này xử lý các điểm còn thiếu trong review trải nghiệm v2.4.0 để extension dễ dùng hơn cho người phổ thông, an toàn hơn khi cảnh báo và hữu ích hơn cho người duyệt nhiều website. URL ML và threshold được giữ nguyên vì metrics/false-positive regression đã đạt yêu cầu; thay đổi tập trung vào warning gate, interaction safety, privacy, Link Lab và quan sát vận hành.

## Giao diện

- Một package duy nhất thay cho hai edition riêng.
- `uiProfile: simple` và `simpleWarningsOnly: true` là mặc định.
- Simple UI có ba kết luận, 1–3 lý do, domain hiện tại, hành động an toàn chính, Link Lab rút gọn và nút mở chi tiết kỹ thuật.
- Technical UI giữ toàn bộ Risk, confidence, RDAP, redirect, breakdown, history, stats, extension audit và JSON diagnostics.
- Nhãn model thống nhất: `URL ML v5 · Feature v4`.
- Link Lab tự cuộn/focus tới kết quả; popup đã kiểm tra 468 px và 320 px, không horizontal overflow.

## Cảnh báo và bypass

- HIGH/Child Mode blur active element, đặt `document.body.inert = true`, `aria-hidden`, focus nút quay lại và trap Tab.
- Capture guard chặn `keydown`, `beforeinput`, `input` và `submit` của trang nền; trạng thái inert/ARIA được phục hồi khi đóng UI.
- HIGH, blacklist, Threat Intel unsafe và Content HIGH yêu cầu gõ đúng domain trước khi cho phép 10 phút.
- Trang blacklist cũng yêu cầu typed-domain confirmation.
- DNR allow-once có metadata trong session storage và bị consume ngay sau top-level navigation kế tiếp.
- Thêm phản hồi **Báo nhầm** lưu cục bộ, không gửi telemetry từ xa.

## Privacy

- Per-tab result chuyển sang `chrome.storage.session`; numeric keys cũ được xóa khi nâng cấp.
- History/CSV che query value và bỏ fragment.
- Threat Intelligence nhận URL redacted, hostname và path; token/query value không được gửi mặc định.
- False-positive feedback chỉ lưu domain, điểm, mức và lý do; tối đa 100 mục cục bộ.

## Link Lab

- Nhận diện URL reset/verify/confirm/activation/magic-login/passwordless/unsubscribe/invite và query action token.
- Không gửi GET cho URL nhạy cảm; verdict tối thiểu là SUSPICIOUS vì network coverage bị chủ động bỏ qua.
- Safe Preview và open action bị khóa cho URL nhạy cảm.
- Bổ sung giới hạn rõ ràng về IP exposure, server-side effect, 64 KiB cap và DNS rebinding sau phân giải.

## Hiệu năng và số liệu

- Không quét DOM khi tab ẩn; reschedule khi tab hiện lại.
- Ưu tiên `requestIdleCallback`, giảm body text cap từ 160 KiB xuống 120 KiB và giới hạn số node mỗi selector.
- Ghi `scanDurationMs`; thống kê local có average/p95, warnings, blocks, bypasses và false-positive reports.

## Không thay đổi model

- Model: `url-logistic-5.0.0`.
- Feature version: `url-lexical-v4`, 54 features.
- Dataset: 4.000 URL, 2.000 benign candidates và 2.000 phishing/malware.
- Holdout và complex-legit regression giữ nguyên kết quả v2.4.0.

## Giới hạn còn lại

- Safe Preview là iframe + DNR restrictions, không phải máy ảo hoặc sandbox hệ điều hành.
- Link Lab bình thường vẫn tạo kết nối và có thể lộ IP; GET có thể có side effect nếu URL không được classifier nhận diện.
- Literal private-host filter không đảm bảo chặn mọi DNS rebinding sau phân giải.
- Review điểm trải nghiệm là internal QA, chưa thay thế nghiên cứu người dùng hoặc review Chrome Web Store thực tế.
