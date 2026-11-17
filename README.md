# DNS Phishing Guard v2.7.5 - Bilingual GUI & Verified Protection

Chrome/Edge Manifest V3 extension hỗ trợ người dùng nhận biết website có dấu hiệu phishing/lừa đảo trước khi nhập mật khẩu, OTP, thông tin thanh toán hoặc tải tệp.

Nhãn xanh chỉ có nghĩa **chưa phát hiện bằng chứng phishing rõ ràng trong phạm vi đã quét**. Nó không phải chứng nhận website uy tín, hợp pháp hoặc an toàn tuyệt đối.

## Thay đổi chính v2.7.5

- Bản GUI cuối có nút chuyển Việt/Anh tức thời ở Simple, Technical, Child và Settings; lựa chọn được lưu cục bộ và không làm thay đổi verdict.
- Responsive 320-700 px, không horizontal overflow, touch target control chính tối thiểu 44 px; vẫn giữ đầy đủ Risk, Evidence, Coverage, Link Lab và telemetry.
- SAFE + COMPLETE + DETERMINED không bị amber hóa chỉ vì lớp tùy chọn chưa có; trạng thái thiếu bằng chứng thật vẫn giữ cảnh báo thận trọng.

## Nền tảng bảo vệ security fixes trước GUI v2.7.5

- Rule thương hiệu được tách khỏi `content.js` sang `data/brand-rules.json`, có nguồn xác minh, trạng thái review và loader runtime riêng.
- Bổ sung Garena/Free Fire/Liên Quân/FC Online/FC Mobile, VNG Games/Zing và VTC Game/Vcoin cùng các registrable domain/cổng nạp đã xác minh.
- `napthe.vn` được bảo vệ như baseline typosquat nhưng không được biến thành allowlist. `napthevn.vn` không được tin cậy hoặc blacklist chỉ dựa trên báo cáo; test dùng `napthevn.example`.
- Tổ hợp “tự nhận chính thức/đối tác + thương hiệu game đã biết + domain sai + form ID game/mã thẻ” đủ tạo cảnh báo mạnh độc lập: page signal 70, `SCAM_COMMERCE` tối thiểu 78 và `GAME_COMMERCE` tối thiểu 65.
- Regression thêm cặp official/impostor có nội dung gần như giống nhau và gate khoảng cách verdict, thay vì chỉ test riêng một trang giả.
- URL ML `url-logistic-5.0.0`, dataset 4.000 URL, domain-age tier và payment evidence của v2.7.3 được giữ nguyên; bản này không retrain model.

## Nền tảng từ v2.7.0

- Khi bằng chứng chưa đủ, Risk hiển thị `— / CHƯA XÁC ĐỊNH` thay vì `0/100`; điểm chất lượng bằng chứng vẫn được giữ riêng.
- Thêm `evidenceAssessment` với ba mức `COMPLETE`, `PARTIAL`, `INSUFFICIENT`, danh sách lớp đã kiểm tra, lớp còn thiếu, dữ kiện xác minh và hành động tiếp theo.
- Thêm category `GAME_COMMERCE` cho tổ hợp mạnh của marketplace tài khoản/dịch vụ game, thanh toán, hành động giao dịch, liên hệ Zalo/Telegram/Discord/mạng xã hội và brand/domain mismatch. Category này là cảnh báo xác minh, không phải kết luận lừa đảo.
- Thêm lớp `SCAM_COMMERCE` cho giao dịch mã thẻ, số seri, PIN, voucher, gift card, nạp game và khuyến mãi khó kiểm chứng ngoài kênh chính thức.
- Tách brand mismatch thương mại khỏi brand mismatch đăng nhập; hỗ trợ Roblox/Robux và Riot Games mà không biến mọi bài viết nhắc thương hiệu thành cảnh báo.
- Link Lab đọc tĩnh tối đa 64 KiB để nhận diện cụm scam-commerce/cờ bạc, HTTP không thành công và vòng lặp/vượt giới hạn chuyển hướng mà không chạy JavaScript trang.
- Safe Preview bị khóa với link action-token và chuỗi chuyển hướng bất thường.
- Ca hồi quy `naplau.com/nap-lau-roblox/index.html` được nâng từ URL ML `SAFE` thành verdict Link Lab `HIGH` nhờ bằng chứng nội dung, không hardcode domain.
- Bổ sung hard-negative cho trang gift-card chính thức và bài viết cảnh báo để giảm false positive.
- Link Lab không còn coi file JavaScript/CSS asset trong `<link>` là liên kết tải xuống; chỉ đếm liên kết người dùng có thể bấm như `<a>`/`<area>`.
- Fixture marketplace kiểu `shopvanmanh.com`, official game-domain negative, article negative và weak-signal negative được đưa vào release gate.
- Giữ nguyên URL ML `url-logistic-5.0.0`; ML cấu trúc URL vẫn chỉ là một lớp tín hiệu, không phải chứng nhận website an toàn.

## Dữ liệu và model

- Dataset gốc: **4.000 URL** gồm 2.000 benign candidates và 2.000 phishing/malware.
- 800/2.000 benign candidates có path/query counterfactual được ghi nhãn rõ: profile, bài viết, sản phẩm, dashboard, OAuth, UUID, tracking và server-page extension.
- 479 hard negatives chỉ dùng cho train, trọng số 2.
- Split theo `registrableDomain`: train 2.785, calibration 398, threshold 419, independent test 398; không domain leakage.
- Model runtime: `url-logistic-5.0.0`, feature version `url-lexical-v4`, 54 features, Platt calibration, threshold 0,59.

Independent test:

| Chỉ số | Kết quả |
| --- | ---: |
| TP / TN / FP / FN | 185 / 199 / 1 / 13 |
| Accuracy | 96,48% |
| Precision | 99,46% |
| Recall | 93,43% |
| F1 | 96,35% |
| False-positive rate | 0,50% |
| ROC-AUC | 0,9911 |

So với v2.3.1, holdout FPR giảm từ 1,50% xuống 0,50%. Bộ complex regression hiện gồm 34 ca (33 SAFE + 1 threat control): URL ML thô còn 1 false positive trên case official `napthe.vn`, nhưng Hybrid Risk Engine bù đúng để đạt 0 hybrid false positive, 0 hybrid false negative, 0 cảnh báo on-page trên case SAFE và cặp official/impostor đạt 1/1. Đây vẫn là dữ liệu offline/curated, không phải ước lượng production theo thời gian thực.

## Các lớp kết quả

- **Phishing Risk:** blacklist, threat intelligence tùy chọn, RDAP, Public Suffix List, typosquatting, brand-suffix mismatch, homoglyph, cấu trúc URL, redirect, URL ML và hành vi trang.
- **Content & Transaction Safety:** scam-commerce/mã trả trước, cờ bạc, nội dung người lớn, dịch vụ nhạy cảm, dữ liệu cá nhân, danh tính giả, malware, deepfake và quảng bá tài chính rủi ro.
- **User Protection Verdict:** tổng hợp phishing, nội dung giao dịch, phản hồi mạng và tải tệp để tránh greenlight khi bằng chứng còn thiếu.
- **Evidence Coverage:** tách trạng thái risk khỏi độ đầy đủ dữ liệu, giải thích rõ lớp nào đã chạy, lớp nào còn thiếu và vì sao chưa thể xác nhận website.

## Link Lab và Safe Preview

1. Dán URL vào ô **Link Lab** trong popup.
2. Bấm **Kiểm tra link/Quét trước** để probe không cookie/referrer, không chạy JavaScript, tối đa 5 redirect, 64 KiB và 8 giây.
3. Đọc verdict tổng hợp, chất lượng bằng chứng, HTTP, redirect, nội dung tĩnh, form/password và cảnh báo tải tệp.
4. Nếu cần xem giao diện, mở **Safe Preview** bị khóa script, form, popup và download.

Link Lab từ chối localhost/IP nội bộ và không kết nối tới URL có dấu hiệu action token. HTTP 403, lỗi mạng hoặc vòng lặp chuyển hướng được trình bày là **không xác minh được**, không phải `SAFE`, và Safe Preview bị khóa. Khi được phép dùng, Safe Preview vẫn kết nối tới website và có thể lộ IP; đây không phải máy ảo hay sandbox hệ điều hành. DNS rebinding sau phân giải vẫn là giới hạn cần lưu ý.

## Vị trí model và logic

- Trọng số model: `data/url-model.json`.
- Inference và clamp: `modules/url-model.js`.
- 54 đặc trưng URL: `modules/url-ml-features.js`.
- Phân loại public/local/private: `modules/site-context.js`.
- Hybrid score và warning gate: `modules/risk-engine.js`.
- Phạm vi bằng chứng và trạng thái Risk chưa xác định: `modules/evidence-coverage.js`.
- Nhận diện luồng thanh toán có điều kiện: `modules/payment-signals.js`.
- Reference chống giả mạo payment brand: `data/protected-payment-domains.json`.
- Rule thương hiệu runtime: `data/brand-rules.json` và `modules/brand-rules.js`.
- Reference typosquat hệ sinh thái nạp game: `data/protected-game-domains.json`.
- Dataset, split, train script và báo cáo: `training/`.
- Regression và metrics: `evaluation/`.

Giải thích contribution:

```powershell
npm run explain-url -- "https://example.com/path"
```

## Cài đặt

1. Giải nén gói runtime.
2. Mở `edge://extensions` hoặc `chrome://extensions`.
3. Bật **Chế độ nhà phát triển**.
4. Chọn **Tải tiện ích đã giải nén** và trỏ tới thư mục có `manifest.json`.
5. Tải lại các tab đã mở trước khi cài extension.

## Huấn luyện và kiểm tra lại

```powershell
npm run pipeline-training
npm run probe:adversarial
npm run validate
```

`probe:adversarial` chạy 29 URL fixture từ `evaluation/sourced-test-urls.json` cùng 2 case structural, dùng `ageInfo giả lập offline` và không gọi mạng. Không mở trực tiếp URL độc hại trong dataset. Báo cáo mới nhất nằm tại `training/reports/` và `evaluation/results/`.

