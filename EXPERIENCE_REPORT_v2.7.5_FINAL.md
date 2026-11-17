# Báo cáo tổng hợp trải nghiệm DNS Phishing Guard v2.7.5

Ngày: 2026-08-17 (Asia/Saigon)

## Phạm vi đã thực hiện

| Nhóm phiên | Số phiên | Bằng chứng |
| --- | ---: | --- |
| Chỉnh GUI + song ngữ | 1 | `GUI_SESSION_v2.7.5.md` |
| Kiểm tra tính năng | 2 | `FEATURE_FAKE_TEST_SESSIONS_v2.7.5.md` |
| Kiểm tra website ngoài thực tế | 5 | `EXTERNAL_USABILITY_TEST_SESSIONS_v2.7.5.md` |
| Kiểm tra khả năng sử dụng | 5 | `EXTERNAL_USABILITY_TEST_SESSIONS_v2.7.5.md` |
| Kiểm tra chống fake | 2 | `FEATURE_FAKE_TEST_SESSIONS_v2.7.5.md` |
| Báo cáo tổng | 1 | Tài liệu này |

Tổng cộng: **16 phiên kiểm thử/đánh giá**, trong đó 10 phiên website/usability, 4 phiên feature/fake và 1 phiên GUI; phiên cuối là tổng hợp phát hành.

## Kết quả kỹ thuật sau khi đóng v2.7.5

- `npm run validate`: PASS; holdout giữ `185/199/1/13`, accuracy `96,48%`, precision `99,46%`, recall `93,43%`, FPR `0,50%`.
- Release hybrid `22/22`, complex FP/FN `0/0`, content recall `2/2`.
- Adversarial probe `32` case, `30` executable, `0` network request; 5/5 payment-logo impersonation vẫn HIGH và không nhận positive payment boost.
- Typed-domain lock được kiểm tra ở content và background; typo/zero-width/separator brand variants và official-claim mismatch vẫn bị bắt.
- GUI English/Việt đổi tức thời, lưu local, không horizontal overflow ở 320/468 px; control/tab/action chính đạt tối thiểu 44 px.

## Đánh giá ba vai trò

| Vai trò | Quan sát | Điểm |
| --- | --- | ---: |
| Pentester | Cơ chế gốc được cải thiện ở brand data, claim mismatch, ad attribution và lock; còn khoảng trống với slang mới, ảnh-only brand, action-token và sleeper domain lâu năm. | 8,8/10 |
| Người dùng phổ thông | Site chính thống không còn bị amber chỉ vì thiếu Threat Intelligence khi Risk đã `SAFE + COMPLETE + DETERMINED`; trang tìm kiếm phổ biến được quiet-mode khi SAFE; cảnh báo fake có domain/lý do rõ. | 9,0/10 |
| Người dùng không rành kỹ thuật | Simple UI ưu tiên câu hành động, 3 lý do dễ hiểu và nút quay lại; Content Safety HIGH khóa thật, không có nút đóng nhanh và bypass cần gõ đúng domain. | 8,8/10 |

Điểm trung bình vòng trải nghiệm: **8,87/10**. Điểm này phản ánh các regression offline và GUI QA; không phải chứng nhận an toàn tuyệt đối cho mọi website.

## Bảng trạng thái 5 nhóm fix nền

| Fix | Trạng thái | Pentester | User thường | User không rành kỹ thuật |
| --- | --- | ---: | ---: | ---: |
| Content Safety HIGH lock | Đã sửa, có regression | 9,0 | 9,0 | 9,2 |
| Ad/widget attribution | Đã sửa, có DOM regression; heuristic còn giới hạn | 8,5 | 8,8 | 8,5 |
| Identity/payment evidence | Đã sửa, không biến logo thành trust | 8,7 | 8,9 | 8,6 |
| Game brand true/fake separation | Đã sửa, có cặp official/impostor | 9,0 | 9,1 | 8,9 |
| Search quiet mode + GUI polish | Đã sửa, có responsive/i18n assertions | 8,8 | 9,0 | 8,8 |

## Giới hạn cần theo dõi bản sau

1. Brand xuất hiện chỉ trong ảnh/canvas/closed shadow DOM hoặc alias hoàn toàn mới có thể không tạo text signal.
2. Domain được nuôi đủ 365 ngày vẫn có thể là sleeper; `MODERATELY_ESTABLISHED` chỉ tăng coverage, không cấp reputation cap.
3. Heuristic ad-region không thể phân biệt 100% widget first-party với quảng cáo nhúng; recall first-party GAMBLING/SEXUAL_SERVICES hiện vẫn `2/2`.
4. Link Lab giới hạn 64 KiB và không quan sát hành vi JavaScript sau response; RDAP/threat-intel phụ thuộc dịch vụ ngoài.
5. Bảng dịch English cần bổ sung nếu module/backend sinh reason mới ngoài mapping.

## Kết luận

v2.7.5 là bản GUI polish trên nền security fixes v2.7.4. Các gate tự động đều PASS, chỉ số model không giảm, và toàn bộ số phiên người dùng yêu cầu đã có báo cáo kèm kết quả. Bản phát hành không tuyên bố giải quyết triệt để các giới hạn kỹ thuật nêu trên.
