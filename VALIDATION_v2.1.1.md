# Validation — v2.1.1

Ngày kiểm tra: 2026-07-19

## Tự động

- JavaScript syntax: PASS
- Manifest/JSON parsing: PASS
- Risk Engine tests: PASS
- Typosquat tests: PASS
- Content Safety tests: PASS
- Parent Control tests: PASS
- Public Suffix tests: PASS
- Python/JavaScript URL-model parity: PASS
- ML regression suite: PASS — 18/18
- Domain leakage: false

## Regression mới

- Steam Store với ML 56–58% và nhiều external scripts: SAFE, tối đa 8 điểm.
- Facebook Group Call với URL dài/query và nhiều external scripts: SAFE, 0 điểm trong mẫu.
- FEID FPT với encoded OAuth ReturnUrl, `Account/Login`, password input nội bộ và nút federated login: SAFE, tối đa 8 điểm khi `brandMismatch=false`.

## Chưa tự động xác minh trong trình duyệt thật

- DOM cụ thể của trang FEID có được nhận đúng là federated-login control hay không.
- Service worker/content-script lifecycle sau khi nâng cấp mà không reload tab.
- DNR, speech synthesis và overlay trên mọi website.

Sau khi cài bản mới cần refresh tab bằng `Ctrl + Shift + R` để content script v2.1.1 được inject.
