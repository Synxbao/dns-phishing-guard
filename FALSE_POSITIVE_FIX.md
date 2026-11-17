# False Positive Fix — v1.7.1

## Vấn đề đã sửa

- `chess.com` từng bị nhận nhầm là typosquat của `chase.com` do Levenshtein distance bằng 2.
- URL hợp lệ có path sâu như Chess.com có thể nhận xác suất ML rất cao vì source bias trong dataset.
- `microsoft.com` từng bị cảnh báo chỉ vì xác suất 39% vượt threshold training 36%.

## Quy tắc mới

1. Typosquatting dùng nhãn domain và tỷ lệ khoảng cách. Hai chỉnh sửa chỉ được chấp nhận với nhãn dài hoặc hoán đổi ký tự liền kề.
2. Threshold training 0.36 không còn là threshold cảnh báo UI.
3. ML 55–74% cộng 10 điểm, 75–89% cộng 20 điểm, từ 90% cộng 30 điểm.
4. ML đơn lẻ chỉ có thể tạo MEDIUM khi xác suất từ 90%; không bao giờ tự tạo HIGH.
5. Domain đã biết hoặc từ 2 năm tuổi, không có tín hiệu độc lập, được giảm tối đa 25 điểm ML.
6. Blacklist, threat intelligence, form mật khẩu ngoài origin và redirect nguy hiểm không bị giảm.

## Kỳ vọng regression

- Microsoft.com: SAFE ngay cả khi model lexical cho xác suất cao, nếu domain đã biết/lâu năm và không có tín hiệu độc lập.
- Chess.com lâu năm với ML 99%, không có tín hiệu khác: SAFE, score 5.
- Domain mới dưới 30 ngày + ML 92%: MEDIUM.
- Homoglyph, blacklist hoặc form mật khẩu gửi ngoài domain: vẫn HIGH.

Model Logistic Regression không được retrain trong bản vá này; v1.7.1 sửa cách tích hợp model vào Risk Engine.
