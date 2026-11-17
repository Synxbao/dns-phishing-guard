# Validation v2.7.2

Ngày kiểm tra: 2026-08-10

## Lệnh và kết quả

Đã chạy trong thư mục bản phát hành `dns-phishing-guard-v2.7.2-runtime`:

```powershell
npm run validate
```

Kết quả: **PASS** cả ba bước `npm test`, `npm run evaluate` và `npm run probe:adversarial`.

## Trước / sau

| Hạng mục | v2.7.1 trước bản vá | v2.7.2 sau bản vá |
| --- | ---: | ---: |
| Manifest | 2.7.1 | 2.7.2 |
| Release test | PASS (chưa có fixture generic CSS ad) | PASS, có fixture NetTruyen-style cố định |
| URL hybrid regression | 20/20 | 20/20 |
| Content regression | 2/2 | 2/2 (recall 100%) |
| Complex-legit | 24/24 | 30/30, 0 ML FP, 0 hybrid FP, 0 on-page warning |
| Holdout accuracy | 96,48% | 96,48% |
| Holdout precision | 99,46% | 99,46% |
| Holdout recall | 93,43% | 93,43% |
| Holdout FPR | 0,50% | 0,50% |
| Adversarial probe | 26 ca, 0 request mạng | 26 ca, 0 request mạng |

## NetTruyen-style regression bắt buộc

Test cố định nằm trong `tests/release.test.mjs` và chạy trong CI/`npm run validate`:

- Fixture có main chapter/list sạch và wrapper generic `sidebar-widget promo-slot` với kích thước runtime `300x250`.
- Creative, profile và contact trong wrapper dùng tài nguyên bên thứ ba và chứa từ khóa dịch vụ nhạy cảm.
- **Trước sửa:** `findLikelyAdRegions()` trả `[]`; dữ liệu raw tạo `SEXUAL_SERVICES/HIGH` và không thể loại ad bleed-through.
- **Sau sửa:** wrapper được nhận diện; main text được giữ; ad text/contact/profile bị loại trước content-semantic scan; filtered result không còn `SEXUAL_SERVICES`.
- Positive first-party `SEXUAL_SERVICES` và `GAMBLING` vẫn đạt `HIGH`, nên recall không giảm.

## Search engine quiet mode

`modules/search-engines.js` nhận diện host chính xác cho Google, Bing, DuckDuckGo, Yahoo, Brave Search và Cốc Cốc; không nhận diện `docs.google.com`, `accounts.google.com` hoặc lookalike `google.com.evil.example`.

Các case search engine trong `evaluation/complex-legit-cases.json` đều trả:

- `SAFE`;
- hybrid score `0`;
- không cảnh báo on-page;
- vẫn tiếp tục được quét ngầm.

Setting `showSearchEnginePageUi` mặc định `false`; khi Risk không phải SAFE, suppression không áp dụng và cảnh báo bình thường vẫn được giữ.

## UI regression

- Bar/panel không khóa dùng bottom-right, panel neo phía trên bar.
- Score giữ `white-space: nowrap`; label có thể co/ellipsis; metric value không còn bị cắt.
- Auto-collapse chỉ gắn cho UI không khóa; `HIGH` strict/content overlay vẫn dùng `inert`, focus trap và không có nút đóng nhanh.
- Source assertions bao phủ breakpoint 320/420/468/520/620/700 px và popup setting text-wrap.
- Native browser context menu vẫn có thể nằm trên extension UI trong lúc mở; đây là giới hạn OS/browser, không phải lỗi z-index của extension.

## Adversarial probe

- Tổng: 26; executable: 24; structural: 2.
- Request mạng thật: 0; RDAP: `ageInfo giả lập offline`.
- Benign expected pass: 7/7.
- Real gaps còn lại: 5 (action-token, scam-commerce/game-commerce semantics và giới hạn Link Lab 64 KiB), giữ nguyên từ baseline.

## Giới hạn heuristic quảng cáo

Bộ lọc không thể phân biệt hoàn hảo native ad không marker, closed shadow DOM/canvas hoặc widget first-party có ad-size/creative bên thứ ba. Có trade-off loại nhầm một số vùng hợp lệ để giảm false positive; external form/script/iframe và risky download vẫn không bị loại khỏi lớp security-critical.
