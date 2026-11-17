# Validation v2.1.0

Đã chạy trong môi trường xây dựng:

- JavaScript/MJS syntax: PASS
- manifest.json và known-domains.json: PASS
- Popup ID references: PASS
- risk-engine tests: PASS
- typosquat tests: PASS
- content-safety tests: PASS
- parent-control tests: PASS
- public-suffix tests: PASS
- Python/JavaScript URL model parity: PASS

Các điểm chưa được xác nhận tự động:

- Giao diện trực tiếp trên mọi phiên bản Chrome/Edge.
- Service worker lifecycle sau khi trình duyệt ngủ hoặc cập nhật.
- DNR và Strict Mode trên các website phức tạp.
- Speech synthesis tiếng Việt trên từng hệ điều hành.
- Tất cả website thực tế ngoài tập regression hiện có.
