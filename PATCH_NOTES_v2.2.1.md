# DNS Phishing Guard v2.2.1 - Legit Content URL False-Positive Patch

## Vấn đề

URL bài hát hợp lệ trên `hopamchuan.com` bị URL ML đánh giá khoảng 94% vì path sâu và nhiều token, dù hybrid đã giảm điểm xuống SAFE.

## Sửa đổi

- Thêm các URL nội dung thật của Hợp Âm Chuẩn vào hard-negative train-only.
- Thêm `hopamchuan.com` vào known domains sau khi xác minh domain lâu năm.
- Giữ holdout độc lập không chứa hard negatives.
- Thêm công cụ giải thích contribution của từng feature.
- Thay câu cảnh báo ML bằng giải thích trung tính khi reputation cap được áp dụng.

## Kết quả

- URL mẫu: khoảng 93,6% xuống 6,1%.
- Holdout F1 giữ ở 95,85%, FPR 1,50%.
- Hybrid regression 20/20.
