# Adversarial Probe Report - DNS Phishing Guard v2.7.5

Thời điểm tạo: 2026-08-17T11:27:36.400Z

## Kết luận điều hành

- Probe chạy **hoàn toàn offline**, số request mạng: **0**; RDAP dùng **ageInfo giả lập offline** cho từng case public.
- 32 case mới đã được đối chiếu; **không trùng URL hoặc ID** với 24 release-regression và 34 complex-legit hiện có.
- Gap rate trên 22 case adversarial thực thi: **22.73%**.
- Hybrid compensation rate trên cùng tập adversarial: **13.64%**.
- Expected-pass rate trên 30 case thực thi: **73.33%**; benign hard-negative: **100.00%**.
- Logo giả payment: **5/5** vẫn ra NGUY HIỂM; số threat case được cộng payment evidence: **0**.
- Kết luận: kiến trúc multi-layer bù tốt cho ML URL bị bỏ sót, nhưng action-token semantics, từ lóng giao dịch Việt Nam và coverage khi HTML bị cắt ở 64 KiB cần ưu tiên sửa.

## Phạm vi an toàn

| Chỉ số | Giá trị |
| --- | ---: |
| Request mạng thực | 0 |
| RDAP | ageInfo giả lập offline |
| Threat Intelligence ngoài | Không gọi |
| Domain dạng threat | Chỉ .example/.invalid dành riêng |
| Payload khai thác / thu credential | Không có |
| Source manifest offline | evaluation/sourced-test-urls.json · 30 URL |

Giai đoạn thu thập feed thật trong đặc tả mới **không được thực hiện** vì chỉ thị đang có yêu cầu toàn bộ case ở mức pattern/kịch bản, không gọi network và không sinh hoặc sử dụng domain phishing thật. File sourced dùng case reserved cùng URL benign đã biết từ dữ liệu cục bộ.

## Tóm tắt kiến trúc đã nạp

- Hybrid verdict đi qua threat intelligence, domain/RDAP/PSL, URL heuristics, redirect/network, page behavior, URL ML, content safety và evidence coverage.
- URL ML: `url-logistic-5.0.0`, 54 feature, Platt calibration, ngưỡng xác suất **0.59**. Ngưỡng hybrid: suspicious 10, medium/binary 30, high 70.
- 24 release-regression hiện đã cover OAuth chính thức, các mẫu phishing rõ, IP/userinfo/Punycode và một số domain legit; 34 complex-legit cover social profile, bài viết/sản phẩm, tracking query, OAuth, checkout payment, localhost và private network.
- Probe này chỉ thêm pattern chưa có: lexical sát ngưỡng mới, OAuth-shaped host lạ, public host chứa internal/local/dev, semantic action-token mới, typosquat suffix reserved, 5 ca logo payment giả, từ lóng giao dịch Việt Nam và clean-prefix 64 KiB.

## Đối chiếu bộ đánh giá hiện có

| Chỉ số | Baseline | Adversarial probe mới |
| --- | ---: | ---: |
| Release regression | 24 | Không sửa |
| Complex legit | 34 | Không sửa |
| Case mới | 0 | 32 |
| Case trùng URL/ID | - | 0 |
| Hybrid accuracy baseline | 100.00% | Không dùng làm prevalence estimate |

Các case sau đây **KHÔNG trùng** với `release-regression-cases.json` hoặc `complex-legit-cases.json` hiện có:

- `benign-threshold-below-new-pattern`
- `benign-threshold-above-new-pattern`
- `benign-mdn-authentication-guide`
- `benign-dropbox-account-security`
- `benign-spotify-password-help`
- `benign-cloudflare-sso-guide`
- `benign-fpt-student-return-url`
- `fake-oauth-untrusted-host`
- `fake-service-login-safe-shape`
- `public-host-internal-label`
- `public-host-local-label`
- `public-host-dev-label`
- `hybrid-compensates-ml-safe-brand-page`
- `hybrid-compensates-ml-safe-redirect`
- `action-token-known-convention-control`
- `action-token-resume-session-gap`
- `action-token-finalize-change-gap`
- `typosquat-steam-reserved-suffix`
- `typosquat-paypal-digit-reserved-suffix`
- `homoglyph-apple-reserved-suffix`
- `fake-game-topup-garena-official-claim`
- `fake-payment-logo-zalopay-digit`
- `fake-payment-logo-vietqr-extra-letter`
- `fake-payment-logo-vietcombank-wrong-suffix`
- `fake-payment-logo-momo-digit`
- `fake-payment-logo-zalopay-homoglyph`
- `scam-commerce-vn-synonyms-established-gap`
- `scam-commerce-vn-synonyms-new-domain-compensated`
- `game-commerce-vn-abbreviations-established-gap`
- `link-lab-clean-prefix-64k-gap`
- `optional-permission-weighting-structural`
- `document-idle-client-redirect-race`

## Tổng hợp kết quả

| Chỉ số | Giá trị |
| --- | ---: |
| Tổng case | 32 |
| Case thực thi / structural | 30 / 2 |
| Expected pass | 22 |
| Hybrid compensated | 3 |
| Real gap | 5 |
| Expected structural limitation | 2 |
| Gap rate (adversarial) | 22.73% |
| Hybrid compensation rate (adversarial) | 13.64% |
| Expected-pass rate (executable) | 73.33% |
| Benign expected-pass rate | 100.00% |
| CHƯA ĐỦ DỮ LIỆU (ba trạng thái) | 1 / 30 · 3.33% |

| Case | Nhóm | Phân loại | UI verdict | Risk score / level | ML probability / prediction |
| --- | --- | --- | --- | ---: | ---: |
| `benign-threshold-below-new-pattern` | BENIGN_LEXICAL | EXPECTED_PASS | AN_TOAN | 8 / SAFE | 0.57803 / SAFE |
| `benign-threshold-above-new-pattern` | BENIGN_LEXICAL | EXPECTED_PASS | AN_TOAN | 8 / SAFE | 0.613051 / PHISHING |
| `benign-mdn-authentication-guide` | BENIGN_COMPLEX_PATH | EXPECTED_PASS | AN_TOAN | 8 / SAFE | 0.001217 / SAFE |
| `benign-dropbox-account-security` | BENIGN_COMPLEX_PATH | EXPECTED_PASS | AN_TOAN | 8 / SAFE | 0 / SAFE |
| `benign-spotify-password-help` | BENIGN_COMPLEX_PATH | EXPECTED_PASS | AN_TOAN | 8 / SAFE | 0 / SAFE |
| `benign-cloudflare-sso-guide` | BENIGN_COMPLEX_PATH | EXPECTED_PASS | AN_TOAN | 0 / SAFE | 0.010477 / SAFE |
| `benign-fpt-student-return-url` | BENIGN_COMPLEX_PATH | EXPECTED_PASS | AN_TOAN | 0 / SAFE | 0.007544 / SAFE |
| `fake-oauth-untrusted-host` | AUTH_FLOW | EXPECTED_PASS | NGUY_HIEM | 100 / HIGH | 0.972048 / PHISHING |
| `fake-service-login-safe-shape` | AUTH_FLOW | EXPECTED_PASS | AN_TOAN | 8 / SAFE | 0.778429 / PHISHING |
| `public-host-internal-label` | SITE_CONTEXT | EXPECTED_PASS | AN_TOAN | 0 / SAFE | 0.099797 / SAFE |
| `public-host-local-label` | SITE_CONTEXT | EXPECTED_PASS | AN_TOAN | 0 / SAFE | 0.051629 / SAFE |
| `public-host-dev-label` | SITE_CONTEXT | EXPECTED_PASS | AN_TOAN | 0 / SAFE | 0.045333 / SAFE |
| `hybrid-compensates-ml-safe-brand-page` | HYBRID_COMPENSATION | HYBRID_COMPENSATED | NGUY_HIEM | 100 / HIGH | 0.369033 / SAFE |
| `hybrid-compensates-ml-safe-redirect` | HYBRID_COMPENSATION | HYBRID_COMPENSATED | CAN_KIEM_TRA | 32 / MEDIUM | 0.005464 / SAFE |
| `action-token-known-convention-control` | ACTION_TOKEN | EXPECTED_PASS | AN_TOAN | 0 / SAFE | 0.323126 / SAFE |
| `action-token-resume-session-gap` | ACTION_TOKEN | REAL_GAP | AN_TOAN | 0 / SAFE | 0.487801 / SAFE |
| `action-token-finalize-change-gap` | ACTION_TOKEN | REAL_GAP | AN_TOAN | 0 / SAFE | 0.389777 / SAFE |
| `typosquat-steam-reserved-suffix` | TYPOSQUAT_HOMOGLYPH | EXPECTED_PASS | NGUY_HIEM | 100 / HIGH | 0.994028 / PHISHING |
| `typosquat-paypal-digit-reserved-suffix` | TYPOSQUAT_HOMOGLYPH | EXPECTED_PASS | NGUY_HIEM | 95 / HIGH | 0.007829 / SAFE |
| `homoglyph-apple-reserved-suffix` | TYPOSQUAT_HOMOGLYPH | EXPECTED_PASS | NGUY_HIEM | 100 / HIGH | 0.005178 / SAFE |
| `fake-game-topup-garena-official-claim` | GAME_TOPUP_BRAND_IMPERSONATION | EXPECTED_PASS | NGUY_HIEM | 100 / HIGH | 0.89189 / PHISHING |
| `fake-payment-logo-zalopay-digit` | PAYMENT_BRAND_IMPERSONATION | EXPECTED_PASS | NGUY_HIEM | 100 / HIGH | 0.750601 / PHISHING |
| `fake-payment-logo-vietqr-extra-letter` | PAYMENT_BRAND_IMPERSONATION | EXPECTED_PASS | NGUY_HIEM | 80 / HIGH | 0.514714 / SAFE |
| `fake-payment-logo-vietcombank-wrong-suffix` | PAYMENT_BRAND_IMPERSONATION | EXPECTED_PASS | NGUY_HIEM | 100 / HIGH | 0.838312 / PHISHING |
| `fake-payment-logo-momo-digit` | PAYMENT_BRAND_IMPERSONATION | EXPECTED_PASS | NGUY_HIEM | 90 / HIGH | 0.584882 / SAFE |
| `fake-payment-logo-zalopay-homoglyph` | PAYMENT_BRAND_IMPERSONATION | EXPECTED_PASS | NGUY_HIEM | 100 / HIGH | 0.724729 / PHISHING |
| `scam-commerce-vn-synonyms-established-gap` | SCAM_COMMERCE | REAL_GAP | AN_TOAN | 8 / SAFE | 0.819918 / PHISHING |
| `scam-commerce-vn-synonyms-new-domain-compensated` | SCAM_COMMERCE | HYBRID_COMPENSATED | NGUY_HIEM | 80 / HIGH | 0.969178 / PHISHING |
| `game-commerce-vn-abbreviations-established-gap` | GAME_COMMERCE | REAL_GAP | AN_TOAN | 8 / SAFE | 0.909613 / PHISHING |
| `link-lab-clean-prefix-64k-gap` | LINK_LAB_LIMIT | REAL_GAP | AN_TOAN | 8 / SAFE | 0.930151 / PHISHING |

## Case lộ gap thật

- `action-token-resume-session-gap`: Kịch bản link đăng nhập một lần dùng tên resume-session/grant_ref chưa nằm trong regex hiện tại. Điểm chưa đạt: Semantics một lần nên được chặn probe. Không được kết nối tới URL có thể tiêu thụ quyền truy cập một lần. Verdict ba trạng thái phải khớp sourced-test-urls.json.
- `action-token-finalize-change-gap`: Kịch bản xác nhận thay đổi thông tin dùng finalize/proof_ref, không trùng keyword hiện có. Điểm chưa đạt: Link có tác động một lần cần được nhận diện theo semantics. Không probe URL có khả năng hoàn tất thay đổi tài khoản. Verdict ba trạng thái phải khớp sourced-test-urls.json.
- `scam-commerce-vn-synonyms-established-gap`: Từ lóng bơm Rbx/code cào/S-R/IB ad/CK TK cá nhân chưa có trong static keyword set. Điểm chưa đạt: SCAM_COMMERCE nên nhận ra biến thể Việt hóa. Không được trả trạng thái xanh khi pattern giao dịch trả trước bị bỏ sót. Verdict ba trạng thái phải khớp sourced-test-urls.json.
- `game-commerce-vn-abbreviations-established-gap`: Acc clone/nick full đồ/cọc/ib ad/ck cá nhân/chốt đơn là cụm phổ biến nhưng chưa có trong rules. Điểm chưa đạt: Static content layer nên gắn cảnh báo giao dịch game. Không greenlight giao dịch bên thứ ba khi semantic rõ. Verdict ba trạng thái phải khớp sourced-test-urls.json.
- `link-lab-clean-prefix-64k-gap`: 64 KiB đầu sạch, form mật khẩu/download/JS navigation chỉ xuất hiện sau giới hạn đọc. Điểm chưa đạt: Kết quả truncated không nên được coi đủ phạm vi cốt lõi. Không greenlight khi nội dung chỉ được đọc một phần. Verdict ba trạng thái phải khớp sourced-test-urls.json.

## Case Hybrid Risk Engine đã tự bù đắp qua layer khác

- `hybrid-compensates-ml-safe-brand-page`: URL ML có thể cho SAFE, nhưng brand mismatch và form mật khẩu ngoài origin phải bù lại. Điểm chưa đạt: Kỳ vọng lý tưởng của lớp URL-only đối với pattern giả danh.
- `hybrid-compensates-ml-safe-redirect`: URL cuối có lexical yếu nhưng chuỗi nhiều domain phải tạo cảnh báo độc lập. Điểm chưa đạt: Kỳ vọng lý tưởng của URL ML trên chuỗi chuyển hướng bất thường.
- `scam-commerce-vn-synonyms-new-domain-compensated`: Cùng semantic gap nhưng domain mới phải tạo lớp cảnh báo bù tối thiểu. Điểm chưa đạt: Keyword layer lý tưởng phải phát hiện nội dung.

## Expected structural limitations

- `optional-permission-weighting-structural`: So sánh cùng quyền management khi đang active và khi chỉ khai báo optional_permissions. chrome.management cung cấp quyền đang có hiệu lực; manifest intent của extension khác không phải lúc nào cũng có trong ExtensionInfo.
- `document-idle-client-redirect-race`: Trang chuyển hướng bằng JavaScript trước lịch quét 900 ms có thể không để lại page signals của trang trung gian. webNavigation vẫn ghi nhận client redirect và final URL, nhưng DOM/hành vi trang trung gian không được bảo đảm quan sát.

Layer yếu nhất theo kết quả thực thi là **Link Lab/content semantics**: hai gap action-token, hai gap từ lóng giao dịch Việt Nam và một gap coverage 64 KiB. Domain/site-context/auth allowlist/typosquat không lộ gap trong các fixture mới.

## QA/UX theo ba persona

Đây là trải nghiệm headless dựa trên logic thật, source UI và fixture offline; không thay thế usability test với người tham gia độc lập.

| Tiêu chí | Pentester | User thường | User không rành kỹ thuật | Mức nghiêm trọng |
| --- | ---: | ---: | ---: | --- |
| Kháng bypass / logic | 3.6 | 5 | 4 | CAO |
| Minh bạch verdict | 4 | 4 | 4 | CAO |
| Link Lab / Safe Preview | 3 | 4 | 3 | CAO |
| Cảnh báo giao dịch Việt Nam | 3 | 3 | 3 | CAO |
| Khả năng sử dụng hằng ngày | 4 | 4 | 3.6 | TRUNG BÌNH |

### Pentester / security researcher

Hành vi mô phỏng: Mở Signal Observatory, so ML raw với từng bucket, thử Link Lab bằng fixture reserved và kiểm tra lớp nào tạo hoặc triệt tiêu verdict.

| Tiêu chí | Điểm /5 | Mức nghiêm trọng | Nhận xét |
| --- | ---: | --- | --- |
| Kháng bypass nhiều lớp | 3 | CAO | Auth allowlist, site context và typosquat hoạt động; vẫn còn semantic gap ở action-token/content. |
| An toàn Link Lab | 3 | CAO | Không chạy JS/cookie/form, nhưng truncated 64 KiB chưa hạ coverage. |
| Minh bạch bằng chứng | 4 | TRUNG BÌNH | Có bucket, ML contribution, evidence coverage và reason riêng. |
| Extension Audit | 3 | TRUNG BÌNH | Chấm active grants tốt hơn manifest intent; optional declaration là giới hạn dữ liệu. |
| Khả năng tái lập | 5 | THẤP | Probe offline, deterministic, JSON + Markdown và không gọi mạng. |

Điểm trung bình: **3.6/5**.

### Người dùng phổ thông có hiểu biết CNTT cơ bản

Hành vi mô phỏng: Dán link vào Link Lab, đọc verdict đơn giản trước, rồi mở chi tiết khi cần biết vì sao ML và domain-age khác nhau.

| Tiêu chí | Điểm /5 | Mức nghiêm trọng | Nhận xét |
| --- | ---: | --- | --- |
| Tránh cảnh báo nhầm | 5 | CAO | 7/7 hard-negative mới đạt kỳ vọng. |
| Hiểu CHƯA ĐỦ DỮ LIỆU | 4 | CAO | 3.33% case thực thi quy về trạng thái chưa đủ dữ liệu; RiskState tách UNDETERMINED khỏi score xanh. |
| Quy trình check nhanh | 4 | TRUNG BÌNH | Một ô dán link, verdict và hành động chính; phần kỹ thuật nằm sau. |
| Ma sát khi bỏ qua cảnh báo | 4 | CAO | HIGH yêu cầu gõ đúng domain, giảm bấm nhầm. |
| Ngữ cảnh lừa đảo Việt Nam | 3 | CAO | Cảnh báo hiện có tốt với từ khóa chuẩn nhưng còn thiếu từ lóng/viết tắt. |

Điểm trung bình: **4/5**.

### Người không rành kỹ thuật / phụ huynh

Hành vi mô phỏng: Chỉ nhìn Simple UI hoặc Child Mode, nghe hướng dẫn, quay lại trang an toàn và nhờ người lớn thay vì tự đọc bucket kỹ thuật.

| Tiêu chí | Điểm /5 | Mức nghiêm trọng | Nhận xét |
| --- | ---: | --- | --- |
| Ngôn ngữ đời thường | 4 | CAO | Simple UI tránh RDAP/entropy; lý do được rút gọn. |
| Child Mode và focus lock | 4 | CAO | Có inert, focus trap, PIN và hành động quay lại rõ ràng. |
| Không hiểu nhầm màu amber | 4 | CAO | CHƯA ĐỦ DỮ LIỆU ghi rõ không nên coi là an toàn. |
| Giải thích scam-commerce | 3 | CAO | Thông điệp hành động rõ, nhưng coverage từ lóng chưa đủ. |
| Kỳ vọng Safe Preview | 3 | TRUNG BÌNH | Có disclaimer về IP/sandbox, nhưng tên gọi vẫn dễ bị hiểu là an toàn tuyệt đối. |

Điểm trung bình: **3.6/5**.

## Case đề xuất merge vào regression chính thức

Các case URL-only phù hợp với schema hiện tại:

`evaluation/release-regression-cases.json`

```json
[
  {
    "id": "probe-fake-oauth-untrusted-host",
    "label": "PHISHING",
    "url": "https://accounts-login.example/o/oauth2/v2/auth?client_id=sample&response_type=code",
    "ageDays": 3
  },
  {
    "id": "probe-paypal-digit-typosquat",
    "label": "PHISHING",
    "url": "https://paypa1.example/account/verify",
    "ageDays": 5
  },
  {
    "id": "probe-apple-homoglyph-reserved",
    "label": "PHISHING",
    "url": "https://xn--pple-43d.example/account/verify",
    "ageDays": 5
  }
]
```

`evaluation/complex-legit-cases.json`

```json
[
  {
    "id": "probe-benign-ml-above-threshold",
    "url": "https://client-support.example/signin/support?confirm=profile&alert=notice",
    "knownDomain": false,
    "ageDays": 1200,
    "context": "PUBLIC_WEB"
  },
  {
    "id": "probe-benign-mdn-auth-guide",
    "url": "https://developer.mozilla.org/en-US/docs/Web/Security/Authentication/login-account-verify-password?redirect_uri=%2Fdocs&token=placeholder",
    "knownDomain": true,
    "ageDays": 9000,
    "context": "PUBLIC_WEB"
  },
  {
    "id": "probe-public-internal-label",
    "url": "https://api.internal-tools.example/v1/account/health?view=security",
    "knownDomain": false,
    "ageDays": 1200,
    "context": "PUBLIC_WEB"
  }
]
```

Các case action-token, content semantics và 64 KiB cần merge vào `tests/release.test.mjs` hoặc một schema Link Lab riêng vì hai JSON URL-only hiện tại không mang page/network fixture: `action-token-resume-session-gap`, `action-token-finalize-change-gap`, `scam-commerce-vn-synonyms-established-gap`, `game-commerce-vn-abbreviations-established-gap`, `link-lab-clean-prefix-64k-gap`.

## Ưu tiên cải tiến

1. Khi `network.truncated === true`, hạ evidence coverage xuống PARTIAL/INSUFFICIENT, không hiển thị xanh và cân nhắc khóa Safe Preview cho tới khi có lớp xác minh khác.
2. Mở rộng action-token classifier bằng semantic path/parameter mới như resume/finalize/complete/grant/proof, nhưng thêm negative fixtures cho bài viết trợ giúp để tránh false positive.
3. Bổ sung từ lóng Việt Nam theo cụm hành vi, không chỉ keyword đơn: bơm Rbx, code cào, S/R, ib ad, ck TK cá nhân, cọc trước, chốt đơn, acc clone/nick full đồ.
4. Extension Audit nên ghi rõ đang chấm **quyền active**, không phải toàn bộ optional intent; nếu có manifest metadata đáng tin cậy thì hiển thị riêng, không cộng lẫn.
5. Giữ `webNavigation` làm lớp bù cho redirect race và cân nhắc thu tín hiệu tối thiểu sớm hơn; không coi page behavior của trang trung gian là đã được quan sát nếu redirect xảy ra trước content scan.

## Kết luận ưu tiên

Ba lỗ hổng logic cần sửa trước:

1. Link Lab vẫn có thể trả coverage COMPLETE/AN TOÀN khi response bị cắt ở 64 KiB và tín hiệu rủi ro nằm phía sau.
2. Action-token classifier phụ thuộc convention hữu hạn, bỏ sót resume/finalize/grant/proof semantics.
3. SCAM_COMMERCE/GAME_COMMERCE bỏ sót cụm từ lóng Việt Nam; domain-age đôi lúc bù được nhưng domain lâu năm có thể được greenlight.

Ba vấn đề UX cần ưu tiên:

1. Trạng thái xanh sau nội dung truncated tạo cảm giác chắc chắn hơn phạm vi quan sát thật.
2. Tên Safe Preview có thể bị hiểu như máy ảo an toàn tuyệt đối dù vẫn kết nối thật và có thể lộ IP.
3. Amber/CHƯA ĐỦ DỮ LIỆU đã diễn đạt tốt hơn v2.6, nhưng vẫn cần usability test để chắc người dùng lớn tuổi không đọc nó như “gần như an toàn”.

## Giới hạn

- Probe không load Chrome/Edge thật, không kiểm thử focus/inert bằng accessibility tree và không chạy review của cửa hàng extension.
- Case RDAP dùng tuổi domain giả lập offline; không dùng kết quả này để kết luận uy tín domain thật.
- Fixture HTML chỉ mô tả pattern; không có form thu credential hoạt động, exploit hoặc domain phishing thật.
- Tỷ lệ gap/compensation phản ánh bộ adversarial tuyển chọn, không phải tỷ lệ lỗi ngoài production.
- Safe Preview vẫn là kết nối thật khi người dùng chủ động mở trong extension; có thể lộ IP và không phải máy ảo hệ điều hành.

## Cách tái lập

Chạy `npm run probe:adversarial` trong thư mục release. Lệnh chỉ đọc dữ liệu cục bộ, dùng ageInfo giả lập offline, rồi ghi JSON và Markdown vào `evaluation/results/`.
