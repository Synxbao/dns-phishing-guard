# Validation - DNS Phishing Guard v2.7.5

Kết quả hiện hành được ghi tại `VALIDATION_v2.7.5.md` và tái lập bằng:

```powershell
npm run validate
```

Tóm tắt:

- Dataset 2.000 benign + 2.000 độc hại; 800 benign counterfactual: PASS.
- Domain-separated holdout replay 398/398: PASS.
- TP/TN/FP/FN: 185/199/1/13.
- Accuracy 96,48%; Precision 99,46%; Recall 93,43%; F1 96,35%; FPR 0,50%.
- Hybrid release regression 22/22 URL + content recall 2/2: PASS.
- Complex regression 34/34: 33 SAFE + 1 threat control, 1 ML raw FP trên case official, 0 hybrid FP/FN, cặp official/impostor đạt 1/1.
- Cặp nạp game: official `napthe.vn` SAFE 8, evidence `CONFIDENT 48/100`; reserved impostor HIGH 100, content HIGH, verified-brand boost 0.
- TikTok `/@brainrotdepot1`: ML khoảng 0,008%, hybrid SAFE, không cảnh báo on-page.
- localhost dashboard: `LOCAL_DEVELOPMENT`, ML/RDAP không áp dụng, risk 0/100.
- URL userinfo `paypal.com@...`: vẫn nhận diện và cảnh báo.
- Link Lab guards, redirect probe, redirect-loop stop, byte cap, static scam-commerce và download indicators: PASS.
- Adversarial probe offline: 32 case (30 executable + 2 structural), 0 request mạng, 0 case trùng; 7/7 benign hard-negative đạt kỳ vọng.
- 5/5 ca ZaloPay/VietQR/Vietcombank/MoMo/Punycode có logo payment giả vẫn HIGH/NGUY HIỂM; payment evidence boost bằng 0.
- Domain 365-729 ngày dùng `MODERATELY_ESTABLISHED`; reputation cap của Risk Engine vẫn yêu cầu 730 ngày.
- Sleeper-domain regression 420 ngày + URL ML 97% giữ `mlReduction = 0`, không được hưởng cap của domain >=730 ngày.
- Checkout RDAP unavailable giữ lớp identity thiếu nhưng có thể đạt `PROVISIONAL/CONFIDENT` khi core scan sạch + payment evidence đủ mạnh.
- Kết quả adversarial: 5 real gap, 3 case được hybrid layer bù, 2 structural limitation; xem `evaluation/results/ADVERSARIAL_PROBE_REPORT.md`.
- Giới hạn 64 KiB được thực thi đúng, nhưng verdict/coverage chưa tự hạ khi response bị truncate; đây là gap cần sửa, không phải release gate đã đóng.
- Asset `.js`/`.css` không còn bị đếm như liên kết tải xuống; live probe `shopvanmanh.com` trả 0 risky download link: PASS.
- Action-token Link Lab zero-fetch guard và Safe Preview lock: PASS.
- Coverage-aware Risk `—`, `evidenceAssessment`, `SCAM_COMMERCE`, `GAME_COMMERCE`, official domain/article hard-negative và HTTP 403 uncertainty: PASS.
- Focus/inert/capture guard, typed-domain bypass và allow-once consume gate: PASS.
- History/Threat Intel URL redaction và per-tab session storage: PASS.
- Technical UI Browser QA tại 468 px và viewport 360 px/body 320 px, thẻ Phạm vi bằng chứng hiển thị đúng và không horizontal overflow: PASS.
- Browser QA v2.7.5 tại 468×800 và 320×800: không horizontal overflow, không cắt heading/button/metric quan trọng.
- JavaScript syntax/check runtime cho background/content/popup/modules/training/tools: PASS.

Kiểm thử `rexawin.com`: URL ML `SAFE` 7,52%, domain khoảng 119 ngày, HTTP 403; final verdict `SUSPICIOUS 20/100`, confidence `32/100`. Không đủ bằng chứng để kết luận độc hại hoặc an toàn.

Giới hạn: holdout cùng đợt thu thập, counterfactual/curated cases không thay thế temporal holdout hoặc thử nghiệm end-to-end trên lưu lượng production. Adversarial sourcing giữ offline/pattern-only nên không thu OpenPhish/URLhaus/ThreatFox hoặc domain typosquat thật.

