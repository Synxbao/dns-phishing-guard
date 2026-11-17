# Validation v2.7.3

Ngày kiểm tra: 2026-08-10

## Lệnh

```powershell
npm run validate
```

Kết quả: **PASS** `npm test`, `npm run evaluate` và `npm run probe:adversarial`; toàn bộ probe chạy
offline, `networkRequestsMade = 0`.

## Trước / sau

| Hạng mục | v2.7.2 trước sửa | v2.7.3 sau sửa |
| --- | ---: | ---: |
| Manifest | 2.7.2 | 2.7.3 |
| Domain 420 ngày | `UNVERIFIED` | `MODERATELY_ESTABLISHED` |
| Checkout 420 ngày + payment | amber/thiếu identity | SAFE, evidence 46/100, CONFIDENT |
| RDAP unavailable + payment | `UNDETERMINED`, evidence thấp | `PROVISIONAL`, identity vẫn thiếu, evidence 45/100 |
| Complex-legit | 30/30 | 32/32 |
| ML false positive / hybrid FP / on-page warning | 0 / 0 / 0 | 0 / 0 / 0 |
| Identity/evidence mismatch | chưa có gate riêng | 0 / 0 |
| Adversarial probe | 26 tổng, 24 executable | 31 tổng, 29 executable |
| Fake payment-brand case | 0 | 5/5 HIGH, boost 0 |
| Request mạng trong probe | 0 | 0 |

## Metrics giữ nguyên

| Chỉ số | Kết quả |
| --- | ---: |
| Holdout TP / TN / FP / FN | 185 / 199 / 1 / 13 |
| Accuracy | 96,48% |
| Precision | 99,46% |
| Recall | 93,43% |
| F1 | 96,35% |
| FPR | 0,50% |
| Hybrid release regression | 20/20 |
| Content regression | 2/2, recall 100% |

## Assertion chính

- `buildIdentityStatus()` trả `UNVERIFIED` ở 364 ngày, `MODERATELY_ESTABLISHED` ở 365 và 729 ngày,
  `ESTABLISHED_DOMAIN` ở 730 ngày.
- Trusted-reputation cap trong Risk Engine vẫn dùng `ageDays >= 730`; tier mới không hạ score URL ML.
- RDAP lookup dùng `domainInfo.registrableDomain || hostname` và gọi `checkDomainAge(identityDomain)`.
- Logo payment đứng riêng và payment block nằm trong ad region đều không qualify.
- Luồng checkout có context + control + amount/action + provider evidence qualify `STRONG`.
- Payment evidence không thay đổi Risk score/binary prediction trên typosquat fixture.
- 5 ca fake ZaloPay/VietQR/Vietcombank/MoMo/Punycode đều `HIGH/NGUY_HIEM`, payment boost 0.

## Adversarial probe

- Tổng 31 case: 29 executable + 2 structural.
- 21 adversarial executable; 5 payment-brand case mới đều `EXPECTED_PASS`.
- 7/7 benign expected pass; 0 request mạng; source manifest 29 URL fixture khớp 1:1.
- 5 real gap cũ còn nguyên: action-token semantics, scam/game-commerce từ lóng và giới hạn Link Lab 64 KiB.

## Mô phỏng case shop.vnggames.com

Test chỉ dùng URL structure + `ageInfo`/page signals giả lập offline, không tải trang và không gọi RDAP:

| Kịch bản | Risk | Identity | Evidence | Presentation |
| --- | --- | --- | ---: | --- |
| Tuổi 420 ngày | SAFE 0 | MODERATELY_ESTABLISHED | 46/100 | DETERMINED / CONFIDENT |
| RDAP unavailable | SAFE 0 | UNVERIFIED (vẫn thiếu) | 45/100 | PROVISIONAL / CONFIDENT |

`identityDomain` trong cả hai lượt là `vnggames.com`, xác nhận subdomain `shop.` không bị gửi riêng cho RDAP.

## Giới hạn

Payment integration là heuristic DOM, không phải kiểm chứng giao dịch hay pháp nhân. Một trang giả mạo
có thể sao chép logo/layout; vì vậy boost chỉ áp dụng sau khi Risk đã SAFE và tự tắt khi có bằng chứng
độc lập. RDAP fail vẫn được hiển thị là lớp identity thiếu dù presentation có thể đạt mức CONFIDENT nhờ
các lớp sạch hội tụ.
