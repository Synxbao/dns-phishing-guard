# DNS Phishing Guard v2.3.1 - Popup Width Hotfix

## Lỗi đã sửa

Trong một số cửa sổ Chrome/Edge hẹp, popup có thể khởi tạo với viewport khoảng 39 px. Breakpoint cũ dùng `width: 100vw`, khiến document tiếp tục nhận chính chiều rộng cực nhỏ đó và bị khóa thành một dải dọc.

## Thay đổi

- Loại bỏ `width: 100vw` khỏi popup.
- Đặt chiều rộng ổn định 468 px mặc định, 420 px ở breakpoint trung gian và 320 px ở breakpoint hẹp.
- Đặt `min-width: 320px` để popup không tự co về kích thước không sử dụng được.
- Thêm regression test cho CSS sizing.

Không thay đổi model URL ML, dataset 4.000 URL, threshold, logic hybrid, Link Lab hoặc Safe Preview.
