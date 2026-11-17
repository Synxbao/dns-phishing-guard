# Bundled training source snapshot

Các tệp trong thư mục này là snapshot offline dùng để tái lập dataset v2.4.0.

- `benign_urls_1000.txt`: danh sách benign candidates do người dùng cung cấp.
- `phishing_urls_1000.txt`: danh sách phishing do người dùng cung cấp.
- `tranco-top-5000.csv`: 5.000 dòng đầu của snapshot Tranco cục bộ; pipeline chỉ lấy đủ 1.000 benign candidates bổ sung.
- `openphish-feed-2026-08-10.txt`: snapshot OpenPhish được dùng cho defensive training.
- `urlhaus-recent-2026-08-10.csv`: snapshot URLhaus malware-download được dùng cho defensive training.

Không mở trực tiếp URL độc hại. `training/build-dataset.mjs` chỉ parse chuỗi và trích xuất feature offline. Hash nguồn được ghi trong `training/data/dataset-4000.json`.
