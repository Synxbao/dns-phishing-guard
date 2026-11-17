import { getHistory, clearHistory, historyToCSV } from "./modules/history.js";
import {
  requestManagementPermission,
  getExtensionAudit,
  setExtensionEnabled
} from "./modules/extension-audit.js";
import {
  getEvidenceAssessment,
  isRiskUndetermined
} from "./modules/evidence-coverage.js";

const DEFAULT_SETTINGS = {
  enabled: true,
  analyzePage: true,
  saveHistory: true,
  showSafeBanner: false,
  showSearchEnginePageUi: false,
  childMode: false,
  childSafeBanner: true,
  childProtectionLevel: "strict",
  childRequireContentScan: true,
  childAutoSpeak: false,
  redirectAnalysis: true,
  autoBlockConfirmed: true,
  urlModelEnabled: true,
  contentSafetyEnabled: true,
  showContentSafetyWarnings: true,
  threatIntelEnabled: false,
  threatIntelEndpoint: "",
  uiProfile: "simple",
  uiLanguage: "vi",
  simpleWarningsOnly: true
};

const ENGLISH_UI_TEXT = new Map(Object.entries({
  "Bảo vệ đang hoạt động": "Protection active",
  "Bật hoặc tắt bảo vệ": "Turn protection on or off",
  "Đang BẬT": "ON",
  "Đang TẮT": "OFF",
  "KHIÊN NHỎ · BẢO VỆ CHỦ ĐỘNG": "LITTLE SHIELD · ACTIVE PROTECTION",
  "ĐANG KIỂM TRA…": "CHECKING…",
  "Khiên Nhỏ đang kiểm tra trang.": "Little Shield is checking this page.",
  "Con hãy chờ một chút.": "Please wait a moment.",
  "← QUAY LẠI NƠI AN TOÀN": "← RETURN TO SAFETY",
  "🔊 Nghe hướng dẫn": "🔊 Hear guidance",
  "Quét lại trang": "Scan again",
  "Dành cho người lớn 🔒": "For adults 🔒",
  "TRANG ĐANG MỞ": "CURRENT PAGE",
  "ĐANG KIỂM TRA": "CHECKING",
  "ĐANG PHÂN TÍCH": "ANALYZING",
  "Chờ kết quả bảo vệ": "Waiting for protection result",
  "Chưa có dữ liệu": "No data yet",
  "Mở một website để extension bắt đầu kiểm tra.": "Open a website to begin the safety check.",
  "Chưa có tín hiệu để hiển thị.": "No signals to display yet.",
  "Rủi ro": "Risk",
  "Bằng chứng": "Evidence",
  "Phạm vi": "Coverage",
  "Kết quả này có vẻ báo nhầm": "This result may be a false alarm",
  "LINK BẠN ĐANG KIỂM TRA": "LINK CHECK",
  "Kiểm tra trước khi mở": "Check before opening",
  "Dán link để kiểm tra cấu trúc, chuyển hướng và phản hồi giới hạn mà không chạy mã trang hay gửi cookie.": "Paste a link to inspect its structure, redirects, and a limited response without running page code or sending cookies.",
  "Link bạn đang kiểm tra": "Link to check",
  "Kiểm tra link": "Check link",
  "Chưa kết nối tới URL nào.": "No URL has been contacted.",
  "Mở Safe Preview": "Open Safe Preview",
  "Xem chi tiết kỹ thuật →": "View technical details →",
  "Dữ liệu phân tích lưu cục bộ": "Analysis stays on this device",
  "Chế độ đơn giản": "Simple mode",
  "Điều hướng chính": "Main navigation",
  "Trạng thái": "Status",
  "Lịch sử": "History",
  "Thông số": "Metrics",
  "Tiện ích": "Extensions",
  "Cài đặt": "Settings",
  "Đang chờ dữ liệu quét": "Waiting for scan data",
  "KẾT LUẬN HYBRID": "HYBRID VERDICT",
  "Đang tổng hợp tín hiệu": "Combining signals",
  "Điểm cuối kết hợp uy tín domain, cấu trúc URL, ML, chuyển hướng và hành vi trên trang.": "The final score combines domain reputation, URL structure, ML, redirects, and on-page behavior.",
  "Chất lượng bằng chứng": "Evidence quality",
  "Dán link để quét URL, RDAP, ML, redirect và tối đa 64 KiB đầu mà không chạy mã trang hay gửi cookie. Probe vẫn kết nối tới website nên có thể làm lộ IP.": "Paste a link to scan URL, RDAP, ML, redirects, and up to the first 64 KiB without running page code or sending cookies. The probe still connects to the site and may expose your IP.",
  "URL cần kiểm tra": "URL to check",
  "Quét trước": "Pre-scan",
  "Chưa có kết nối tới URL nào.": "No URL has been contacted.",
  "KẾT QUẢ PREFLIGHT": "PREFLIGHT RESULT",
  "Tải tệp / tự điều hướng": "Downloads / auto-navigation",
  "Safe Preview khóa JavaScript, form, popup và download; đây không phải máy ảo hay sandbox hệ điều hành.": "Safe Preview blocks JavaScript, forms, popups, and downloads; it is not a virtual machine or an operating-system sandbox.",
  "Thông số lần quét": "Scan snapshot",
  "Tuổi domain": "Domain age",
  "Dữ liệu đăng ký": "Registration data",
  "Chuyển hướng": "Redirects",
  "Chuỗi điều hướng": "Navigation chain",
  "Độ bất thường URL": "URL anomaly",
  "Chỉ dùng tham khảo": "Reference only",
  "ML áp dụng": "Applied ML",
  "Sau hiệu chỉnh hybrid": "After hybrid calibration",
  "Danh tính kỹ thuật": "Technical identity",
  "Ngữ cảnh & nhận diện": "Context & identity",
  "Domain đăng ký": "Registrable domain",
  "Danh sách": "Lists",
  "Hạn chế": "Restricted mode",
  "Phạm vi bằng chứng": "Evidence coverage",
  "Đang tổng hợp các lớp đã kiểm tra.": "Summarizing checked evidence layers.",
  "✓ Đã kiểm tra": "✓ Checked",
  "△ Còn thiếu / tùy chọn": "△ Missing / optional",
  "HÀNH ĐỘNG TIẾP THEO": "NEXT ACTION",
  "Mô hình phân tích": "Analysis models",
  "Ngưỡng hybrid": "Hybrid threshold",
  "Phân rã điểm": "Score breakdown",
  "Tín hiệu quan sát": "Observed signals",
  "Hành động đề xuất": "Recommended actions",
  "Thao tác bảo vệ": "Protection controls",
  "↻ Quét lại": "↻ Scan again",
  "Chế độ hạn chế": "Restricted mode",
  "Tin tưởng": "Trust",
  "Báo cáo xấu": "Mark as unsafe",
  "Báo nhầm (cục bộ)": "False alarm (local)",
  "Sao chép chẩn đoán": "Copy diagnostics",
  "Xuất JSON": "Export JSON",
  "An toàn nội dung & chỉ báo pháp lý": "Content safety & policy indicators",
  "Trạng thái phân tích": "Analysis status",
  "Danh mục phát hiện": "Detected categories",
  "Tín hiệu nội dung": "Content signals",
  "Khuyến nghị": "Recommendations",
  "Chỉ báo kỹ thuật, không phải kết luận pháp lý.": "Technical indicators only, not a legal conclusion.",
  "Lịch sử cảnh báo": "Alert history",
  "Tối đa 100 sự kiện gần nhất được lưu cục bộ trên thiết bị.": "Up to 100 recent events are stored locally on this device.",
  "Xuất CSV": "Export CSV",
  "Xóa lịch sử": "Clear history",
  "Thông số bảo vệ": "Protection metrics",
  "Số liệu vận hành được tổng hợp cục bộ, không gửi ra ngoài.": "Operational metrics are aggregated locally and are not sent anywhere.",
  "Hiệu suất phân tích": "Analysis performance",
  "RDAP có dữ liệu": "RDAP available",
  "RDAP cache hit": "RDAP cache hit",
  "Kết quả cache hit": "Result cache hit",
  "Quét do trang đổi": "Dynamic rescans",
  "Thời gian quét trung bình": "Average scan time",
  "Thời gian quét p95": "p95 scan time",
  "Lần quét cuối": "Last scan",
  "Xóa cache": "Clear cache",
  "Xóa thống kê": "Clear metrics",
  "Kiểm tra tiện ích": "Extension audit",
  "Phân tích mức quyền của các tiện ích khác; không tự kết luận malware.": "Reviews permissions used by other extensions; it does not automatically label them as malware.",
  "Quét quyền nhạy cảm": "Scan sensitive permissions",
  "Quyền management chỉ được xin khi bạn chủ động bắt đầu quét.": "The management permission is requested only when you start an audit.",
  "Quét tiện ích đã cài": "Scan installed extensions",
  "Mở trang quản lý": "Open extension manager",
  "Chưa quét.": "Not scanned yet.",
  "Cài đặt bảo vệ": "Protection settings",
  "Tùy chỉnh lớp phân tích, quyền riêng tư và chế độ gia đình.": "Configure analysis layers, privacy, and family protection.",
  "Lớp phát hiện": "Detection layers",
  "Phân tích hành vi trang": "Analyze page behavior",
  "Theo dõi form, iframe, script và nội dung chèn muộn.": "Monitor forms, iframes, scripts, and late-injected content.",
  "Theo dõi chuyển hướng": "Analyze redirects",
  "Ghi nhận server/client redirect và đổi domain.": "Track server/client redirects and domain changes.",
  "Chặn blacklist trước khi tải": "Block confirmed blacklist entries before load",
  "Dùng DNR cho domain đã được xác nhận.": "Use declarative network rules for confirmed domains.",
  "Mô hình URL ML": "URL ML model",
  "Phân tích an toàn nội dung": "Analyze content safety",
  "Nhận diện cờ bạc, nội dung người lớn, malware và dữ liệu nhạy cảm.": "Detect gambling, adult content, malware, and sensitive-data collection.",
  "Hiện cảnh báo nội dung trên trang": "Show content warnings on the page",
  "Tách riêng khỏi điểm phishing và không tự kết luận pháp lý.": "Kept separate from the phishing score and never treated as a legal conclusion.",
  "Lưu lịch sử cảnh báo": "Save alert history",
  "Chỉ lưu website mức vàng và đỏ.": "Only amber and red websites are stored.",
  "Hiện banner xanh": "Show safe banner",
  "Trang an toàn mặc định chỉ hiện badge.": "Safe pages show only a badge by default.",
  "Hiện trạng thái trên trang tìm kiếm phổ biến": "Show status on popular search pages",
  "Mặc định ẩn khi an toàn; cảnh báo rủi ro vẫn luôn hiện.": "Hidden by default when safe; risk alerts always remain visible.",
  "Gọi endpoint HTTPS do bạn quản lý. Mặc định tắt.": "Call an HTTPS endpoint you control. Disabled by default.",
  "Lưu endpoint": "Save endpoint",
  "Giao diện mặc định": "Default interface",
  "Đơn giản — dành cho người dùng phổ thông": "Simple — for everyday users",
  "Kỹ thuật — hiển thị toàn bộ tín hiệu": "Technical — show every signal",
  "Cả hai giao diện dùng chung một kết quả phân tích; chế độ đơn giản chỉ lược bớt thuật ngữ.": "Both interfaces use the same analysis result; Simple mode only reduces technical terminology.",
  "Ngôn ngữ giao diện / Interface language": "Interface language",
  "Tiếng Việt": "Vietnamese",
  "Đổi ngôn ngữ chỉ thay đổi cách hiển thị; dữ liệu quét và mức cảnh báo được giữ nguyên.": "Changing language only affects presentation; scan data and risk levels remain unchanged.",
  "Gia đình": "Family",
  "Chế độ trẻ em": "Child mode",
  "Chặn toàn màn hình với nội dung nhạy cảm và khóa thao tác bằng PIN.": "Use a full-screen block for sensitive content and protect controls with a PIN.",
  "Phải quét nội dung trước khi báo an toàn": "Require content scan before showing safe",
  "Không hiển thị màu xanh khi content script chưa gửi dữ liệu.": "Do not show a green state before the content script reports.",
  "Tự đọc cảnh báo": "Read alerts aloud",
  "Đọc hướng dẫn bằng tiếng Việt khi trang bị chặn.": "Read guidance aloud when a page is blocked.",
  "Hiện banner đã kiểm tra": "Show checked banner",
  "Hiển thị thông báo xanh sau khi đã quét trang.": "Show a green notice after the page is scanned.",
  "Mức bảo vệ trẻ em": "Child protection level",
  "Nghiêm ngặt — chặn từ mức cần lưu ý": "Strict — block from notice level",
  "Tiêu chuẩn — chặn cảnh báo/vượt ngưỡng": "Standard — block warning/high levels",
  "Dịch vụ tình dục, nội dung người lớn, cờ bạc, malware, danh tính giả và thu thập dữ liệu nhạy cảm luôn yêu cầu người lớn xác nhận.": "Sexual services, adult content, gambling, malware, identity abuse, and sensitive-data collection always require an adult.",
  "Tạo/đổi PIN": "Create/change PIN",
  "Khóa ngay": "Lock now",
  "Xóa PIN": "Remove PIN",
  "Whitelist tùy chỉnh": "Custom allowlist",
  "Thêm": "Add",
  "Blacklist tùy chỉnh": "Custom blocklist",
  "Phân tích cục bộ": "Local analysis",
  "Dành cho người lớn": "Adult access",
  "Nhập PIN.": "Enter PIN.",
  "Nhập lại PIN": "Re-enter PIN",
  "Hủy": "Cancel",
  "Xác nhận": "Confirm",
  "KHÔNG PHÁT HIỆN PHISHING": "NO PHISHING DETECTED",
  "NGUY HIỂM": "DANGEROUS",
  "CẢNH BÁO": "WARNING",
  "CẦN KIỂM TRA": "CHECK REQUIRED",
  "RỦI RO NỘI DUNG CAO": "HIGH CONTENT RISK",
  "CẢNH BÁO NỘI DUNG": "CONTENT WARNING",
  "NỘI DUNG CẦN LƯU Ý": "CONTENT NOTICE",
  "KHÔNG PHÁT HIỆN NỘI DUNG HẠN CHẾ": "NO RESTRICTED CONTENT DETECTED",
  "Không xác định": "Unknown",
  "Không áp dụng": "Not applicable",
  "Không có dữ liệu": "No data",
  "Không đáng kể": "No significant redirects",
  "Đang bật": "On",
  "Đang tắt": "Off",
  "Đã quét": "Scanned",
  "Chưa quét được": "Scan unavailable",
  "Mặc định": "Default",
  "Chưa chạy": "Not run",
  "Không khả dụng": "Unavailable",
  "Không có": "None",
  "Blacklist": "Blocklist",
  "Whitelist": "Allowlist",
  "CHƯA ĐỦ DỮ LIỆU": "INSUFFICIENT DATA",
  "DỮ LIỆU MỘT PHẦN": "PARTIAL DATA",
  "ĐỦ PHẠM VI CỐT LÕI": "CORE COVERAGE COMPLETE",
  "BẰNG CHỨNG HỖ TRỢ TỐT": "GOOD SUPPORTING EVIDENCE",
  "BẰNG CHỨNG CÒN YẾU": "WEAK EVIDENCE",
  "CHƯA XÁC ĐỊNH": "UNDETERMINED",
  "TẠM THỜI": "PROVISIONAL",
  "ĐÃ XÁC ĐỊNH": "DETERMINED",
  "Tên miền & danh sách cục bộ": "Domain & local lists",
  "Ngữ cảnh danh tính": "Identity context",
  "Danh tính/chủ thể website": "Website identity/operator",
  "Dữ liệu đăng ký domain": "Domain registration data",
  "Cấu trúc địa chỉ website": "Website address structure",
  "Nội dung trang": "Page content",
  "Nội dung thực tế của trang": "Actual page content",
  "Nội dung xem trước giới hạn": "Limited preview content",
  "Chuỗi chuyển hướng": "Redirect chain",
  "Nguồn uy tín bên ngoài": "External reputation source",
  "Tích hợp thanh toán được quan sát": "Observed payment integration",
  "Khớp thương hiệu và địa chỉ chính thức": "Verified brand/domain alignment",
  "Chưa ghi nhận lớp kiểm tra nào.": "No checked layers recorded.",
  "Không thiếu lớp bằng chứng cốt lõi.": "No core evidence layers are missing.",
  "Không phát hiện dấu hiệu rủi ro rõ ràng.": "No clear risk signals detected.",
  "Tiếp tục thận trọng.": "Continue with care.",
  "Chưa có cảnh báo nào.": "No alerts yet.",
  "Chưa được cấp quyền management.": "Management permission has not been granted.",
  "Không tìm thấy tiện ích khác.": "No other extensions found.",
  "Không có quyền nhạy cảm nổi bật": "No notable sensitive permissions",
  "Chưa có domain nào": "No domains yet"
}));

const ENGLISH_DYNAMIC_TEXT = [
  [/^Cập nhật (.+)$/u, (_, value) => `Updated ${value}`],
  [/^(\d+) ngày$/u, (_, value) => `${value} days`],
  [/^(\d+) tháng$/u, (_, value) => `${value} months`],
  [/^([\d.]+) năm$/u, (_, value) => `${value} years`],
  [/^(\d+) lần · (\d+) domain$/u, (_, hops, domains) => `${hops} redirects · ${domains} domains`],
  [/^(\d+) lần$/u, (_, value) => `${value} redirects`],
  [/^Đã xóa (\d+) mục$/u, (_, value) => `Cleared ${value} items`],
  [/^Chất lượng bằng chứng (.+)$/u, (_, value) => `Evidence quality ${value}`],
  [/^Nội dung: (.+)$/u, (_, value) => `Content: ${value}`],
  [/^Mức quyền: (.+) · Đang bật$/u, (_, value) => `Permission level: ${value} · Enabled`],
  [/^Mức quyền: (.+) · Đang tắt$/u, (_, value) => `Permission level: ${value} · Disabled`],
  [/^Đã phân tích domain (.+)\.$/u, (_, value) => `Analyzed domain ${value}.`],
  [/^Tuổi domain quan sát được: (\d+) ngày\.$/u, (_, value) => `Observed domain age: ${value} days.`],
  [/^Ngữ cảnh domain: (.+)\.$/u, (_, value) => `Domain context: ${value}.`],
  [/^Còn thiếu: (.+)\.$/u, (_, value) => `Missing: ${value}.`],
  [/^Nội dung cần lưu ý: (.+)\.$/u, (_, value) => `Content notice: ${value}.`],
  [/^Trang tự nhận là chính thức hoặc đối tác của (.+), nhưng địa chỉ hiện tại không khớp hệ thống chính thức\.$/u, (_, value) => `The page claims to be an official channel or partner of ${value}, but this address does not match the verified official system.`],
  [/^Địa chỉ website này rất giống (.+), một địa chỉ chính thức đã được xác minh\.$/u, (_, value) => `This website address closely resembles ${value}, a verified official address.`],
  [/^Đã quan sát luồng thanh toán với (.+); đây không phải xác thực giao dịch thật\.$/u, (_, value) => `Observed a payment flow using ${value}; this does not authenticate the transaction.`],
  [/^Địa chỉ hiện tại khớp hệ thống chính thức đã xác minh của (.+); đây vẫn không phải bảo đảm tuyệt đối cho giao dịch\.$/u, (_, value) => `The current address matches the verified official system for ${value}; this is still not an absolute transaction guarantee.`],
  [/^(.+): NGUY HIỂM$/u, (_, value) => `${value}: UNSAFE`],
  [/^Có dữ liệu · cache$/u, () => "Available · cache"],
  [/^Có dữ liệu$/u, () => "Available"],
  [/^Không áp dụng cho mạng cục bộ$/u, () => "Not applicable to local networks"],
  [/^Không có dữ liệu$/u, () => "Unavailable"],
  [/^Đã quét xong · đọc (.+) KiB · không gửi cookie hoặc thông tin đăng nhập\.$/u, (_, value) => `Scan complete · read ${value} KiB · no cookies or credentials sent.`]
];

[
  ["Dừng lại và rời khỏi trang", "Stop and leave this page"],
  ["CHƯA CÓ KẾT QUẢ", "NO RESULT YET"],
  ["Mở hoặc tải lại một website để extension bắt đầu kiểm tra.", "Open or reload a website to start the safety check."],
  ["Chưa nhận được kết quả từ tab hiện tại", "No result has been received from the current tab"],
  ["Mở một website để bắt đầu phân tích", "Open a website to begin analysis"],
  ["Cần xác minh trước khi tiếp tục", "Verify before continuing"],
  ["Có tín hiệu cần kiểm tra thêm", "Signals need another check"],
  ["Chưa thấy bằng chứng phishing rõ ràng", "No clear phishing evidence found"],
  ["KHÔNG NÊN TRUY CẬP", "DO NOT VISIT"],
  ["RỦI RO CAO", "HIGH RISK"],
  ["Dừng lại và rời khỏi trang", "Stop and leave this page"],
  ["Đừng nhập mật khẩu, OTP, thông tin thanh toán hoặc tải tệp từ trang này.", "Do not enter passwords, OTPs, payment details, or download files from this page."],
  ["GIAO DỊCH CẦN XÁC MINH", "TRANSACTION NEEDS VERIFICATION"],
  ["UY TÍN WEBSITE CHƯA ĐƯỢC XÁC MINH", "WEBSITE REPUTATION NOT VERIFIED"],
  ["GIAO DỊCH GAME BÊN THỨ BA", "THIRD-PARTY GAME TRANSACTION"],
  ["Đã thấy giao dịch tài khoản hoặc dịch vụ game", "A game account or service transaction was detected"],
  ["CHƯA ĐỦ BẰNG CHỨNG", "INSUFFICIENT EVIDENCE"],
  ["Xác minh trước khi tiếp tục", "Verify before continuing"],
  ["Chất lượng bằng chứng hoặc phạm vi quét chưa đủ để xác nhận trạng thái xanh.", "Evidence quality or scan coverage is not enough to confirm a green state."],
  ["CÓ THỂ TIẾP TỤC THẬN TRỌNG", "CAUTIOUSLY OK TO CONTINUE"],
  ["CHƯA THẤY PHISHING RÕ RÀNG", "NO CLEAR PHISHING FOUND"],
  ["Trang hiện tại có vẻ ổn", "This page currently looks okay"],
  ["Kết quả an toàn không phải bảo đảm tuyệt đối. Vẫn kiểm tra domain trước khi nhập mật khẩu hoặc thanh toán.", "A safe result is not an absolute guarantee. Check the domain before entering a password or paying."],
  ["← Quay lại nơi an toàn", "← Return to safety"],
  ["↻ Quét lại trang", "↻ Scan again"],
  ["↻ Quét lại & kiểm tra lớp thiếu", "↻ Rescan and check missing layers"],
  ["← Quay lại để kiểm tra", "← Go back and verify"],
  ["Chưa có dữ liệu từ tab hiện tại.", "No data from the current tab."],
  ["Domain được nhận diện trong tập website phổ biến.", "The domain is recognized in the popular-website dataset."],
  ["Domain đã hoạt động hơn một năm.", "The domain has been active for more than one year."],
  ["Domain nằm trong blacklist đã được xác nhận.", "The domain is on a confirmed blocklist."],
  ["Nguồn Threat Intelligence báo URL có nguy cơ.", "The threat-intelligence source reports risk for this URL."],
  ["Tên miền có ký tự lạ hoặc gần giống một thương hiệu khác.", "The domain uses unusual characters or resembles another brand."],
  ["Tên thương hiệu trên trang không khớp địa chỉ website.", "The brand shown on the page does not match the website address."],
  ["Trang dùng thương hiệu cho giao dịch trên domain không chính thức.", "The page uses a brand for transactions on an unofficial domain."],
  ["Trang dùng thương hiệu game trên domain không thuộc nhà phát hành.", "The page uses a game brand on a domain not operated by the publisher."],
  ["Form mật khẩu có thể gửi dữ liệu sang một địa chỉ khác.", "A password form may send data to another address."],
  ["Trang đang yêu cầu nhập mật khẩu.", "The page is asking for a password."],
  ["Trang có liên kết tới loại tệp cần thận trọng.", "The page links to a file type that needs care."],
  ["Domain mới được đăng ký gần đây.", "The domain was registered recently."],
  ["Điều hướng đã đi qua nhiều domain khác nhau.", "Navigation crossed multiple domains."],
  ["Chưa thấy blacklist, giả mạo tên miền hoặc hành vi lấy dữ liệu rõ ràng.", "No clear blocklist hit, domain impersonation, or data-collection behavior was found."],
  ["Cấu trúc URL có điểm bất thường; đây chỉ là tín hiệu tham khảo, không phải kết luận phishing.", "The URL structure is unusual; this is a reference signal, not a phishing conclusion."],
  ["Chờ một chút hoặc bấm Kiểm tra lại.", "Wait a moment or press Check again."],
  ["Trang này có thể không an toàn.", "This page may be unsafe."],
  ["Trang này hơi lạ.", "This page looks unusual."],
  ["Trang này có vài dấu hiệu cần kiểm tra.", "This page has a few signals that need checking."],
  ["Khiên Nhỏ chưa thể nói trang này an toàn.", "Little Shield cannot confirm that this page is safe."],
  ["Khiên Nhỏ chưa thấy cảnh báo rõ ràng trên trang này.", "Little Shield found no clear warning on this page."],
  ["Chưa đủ dữ liệu nhận diện domain", "Not enough data to identify the domain"],
  ["Chưa xác minh", "Unverified"],
  ["Domain khá mới, dưới 6 tháng tuổi", "Relatively new domain, under six months old"],
  ["Domain đã hoạt động hơn một năm", "Domain active for more than one year"],
  ["Domain đã hoạt động hơn một năm", "Domain active for more than one year"],
  ["Domain lâu năm", "Established domain"],
  ["Domain mới", "New domain"],
  ["Được người dùng tin cậy", "User trusted"],
  ["Domain đã biết / phổ biến", "Known / popular domain"],
  ["Tên miền tổ chức công", "Public-sector domain"],
  ["Mạng riêng / nội bộ", "Private / internal network"],
  ["Môi trường phát triển cục bộ", "Local development environment"],
  ["Có trong blacklist", "On the blocklist"],
  ["Đang bật", "Enabled"],
  ["Đang tắt", "Disabled"],
  ["Đã xóa", "Cleared"],
  ["Đã lưu", "Saved"],
  ["Đã sao chép", "Copied"],
  ["Không thể sao chép", "Copy failed"],
  ["Không thể ghi nhận", "Could not record"],
  ["Đã ghi nhận cục bộ", "Recorded locally"],
  ["Đã ghi nhận báo nhầm", "False alarm recorded"],
  ["Thử ghi nhận lại", "Try recording again"],
  ["Không thể thực hiện.", "Action could not be completed."],
  ["Endpoint không hợp lệ", "Invalid endpoint"],
  ["Hãy nhập một URL cần kiểm tra.", "Enter a URL to check."],
  ["Đang quét…", "Scanning…"],
  ["Đang mở…", "Opening…"],
  ["Không thể kiểm tra URL.", "Could not check the URL."],
  ["Đang quét tĩnh và đọc phản hồi giới hạn; không chạy mã trang…", "Running a static scan and reading a limited response; page code is not executed…"],
  ["Đang kiểm tra mà không chạy mã trang…", "Checking without running page code…"],
  ["Không thể mở Safe Preview.", "Could not open Safe Preview."],
  ["Safe Preview bị khóa cho link nhạy cảm", "Safe Preview is locked for sensitive links"],
  ["Không kết nối", "Not connected"],
  ["Chưa xác định", "Unknown"],
  ["vòng lặp", "loop"],
  ["vượt giới hạn", "limit exceeded"],
  ["script", "script"],
  ["form", "form"],
  ["password", "password"],
  ["link tải", "download link"],
  ["Đã quét — chưa phát hiện danh mục hạn chế rõ ràng", "Scanned — no clear restricted category detected"],
  ["Chưa thu thập được tín hiệu nội dung trang", "Page-content signals were not collected"],
  ["Không phát hiện tín hiệu nội dung đáng chú ý.", "No notable content signals detected."],
  ["Chưa quét được nội dung trang; hãy tải lại tab và bấm Quét lại.", "Page content was not scanned; reload the tab and press Scan again."],
  ["Tiếp tục thận trọng khi cung cấp dữ liệu hoặc thanh toán.", "Continue with care when sharing data or making payments."],
  ["Không có chỉ báo đặc biệt", "No special indicators"],
  ["Không phát hiện dấu hiệu rủi ro rõ ràng.", "No clear risk indicators detected."],
  ["Không thiếu lớp bằng chứng cốt lõi.", "No core evidence layers are missing."],
  ["Tiếp tục thận trọng.", "Continue with care."],
  ["Chưa có cảnh báo nào.", "No alerts yet."],
  ["Bạn chưa cấp quyền management.", "You have not granted management permission."],
  ["Chưa có tiện ích nào", "No extensions yet"],
  ["Threat Intel", "External reputation"],
  ["Whitelist giảm", "Allowlist reduction"],
  ["Hành vi trang", "Page behavior"],
  ["Đổi domain khi redirect", "Domain changed during redirect"],
  ["HTTPS → HTTP", "HTTPS → HTTP"],
  ["Tích hợp thanh toán quan sát được · không phải xác thực", "Observed payment integration · not authentication"],
  ["Không có chỉ báo đặc biệt", "No special indicators"],
  ["Cờ bạc / cá cược", "Gambling / betting"],
  ["Nội dung người lớn", "Adult content"],
  ["Dịch vụ tình dục / môi giới nhạy cảm", "Sexual services / sensitive brokerage"],
  ["Thu thập / mua bán dữ liệu cá nhân", "Personal-data collection / trading"],
  ["Danh tính giả / tài khoản rác", "Identity abuse / throwaway accounts"],
  ["Phần mềm độc hại / công cụ bẻ khóa", "Malware / cracking tools"],
  ["Dịch vụ giả mạo bằng AI / deepfake", "AI impersonation / deepfake services"],
  ["Quảng bá tài chính rủi ro", "Risky financial promotion"],
  ["Giao dịch hoặc mã trả trước cần xác minh", "Transaction or prepaid code needs verification"],
  ["Giao dịch game bên thứ ba cần xác minh", "Third-party game transaction needs verification"],
  ["Bảo vệ dữ liệu cá nhân và minh bạch khi thu thập dữ liệu", "Personal-data protection and collection transparency"],
  ["Dịch vụ tình dục / môi giới nhạy cảm", "Sexual services / sensitive brokerage"]
].forEach(([vi, en]) => ENGLISH_UI_TEXT.set(vi, en));

[
  ["Đã phân tích host, public suffix, blacklist, whitelist và domain phổ biến.", "Host, public suffix, blocklist, allowlist, and popular-domain data were analyzed."],
  ["Domain có ngữ cảnh nhận diện đủ mạnh.", "The domain has sufficiently strong identity context."],
  ["Chưa nhận diện được domain chính thức, domain phổ biến, domain đã hoạt động đủ lâu hoặc domain do người dùng tin cậy.", "No official, popular, sufficiently established, or user-trusted domain identity was recognized."],
  ["Không áp dụng cho localhost hoặc mạng riêng.", "Not applicable to localhost or private networks."],
  ["Đã nhận được dữ liệu RDAP về tuổi và trạng thái domain.", "RDAP domain-age and status data was received."],
  ["RDAP không trả dữ liệu trong lần quét này.", "RDAP returned no data for this scan."],
  ["Đã kiểm tra đặc trưng URL; kết quả ML chỉ là tín hiệu tham khảo.", "URL features were checked; the ML result is a reference signal only."],
  ["Không áp dụng cho ngữ cảnh mạng cục bộ.", "Not applicable to a local-network context."],
  ["URL ML đang tắt.", "URL ML is disabled."],
  ["URL ML chưa trả kết quả.", "URL ML has not returned a result."],
  ["Đã đọc phần HTML giới hạn mà không chạy JavaScript, form hoặc download.", "A limited HTML response was read without running JavaScript, forms, or downloads."],
  ["Đã thu thập tín hiệu nội dung và hành vi DOM trên trang.", "Page-content and DOM-behavior signals were collected."],
  ["Lớp nội dung chưa phát hiện danh mục cảnh báo theo các luật hiện có.", "The content layer found no alert category under the current rules."],
  ["Link Lab chưa đọc được phản hồi HTML thành công.", "Link Lab could not read a successful HTML response."],
  ["Phân tích nội dung đang tắt.", "Content analysis is disabled."],
  ["Content script chưa trả đủ tín hiệu trang.", "The content script has not returned enough page signals."],
  ["Đã theo dõi chuyển hướng trong phạm vi trình duyệt hoặc Link Lab.", "Redirects were tracked within the browser or Link Lab scope."],
  ["Phân tích chuyển hướng đang tắt.", "Redirect analysis is disabled."],
  ["Đã đối chiếu nguồn Threat Intelligence được cấu hình.", "The configured threat-intelligence source was checked."],
  ["Threat Intelligence có kết quả khớp nguy hiểm.", "Threat intelligence returned an unsafe match."],
  ["Threat Intelligence được cấu hình không trả kết quả khớp trong lần quét này.", "The configured threat-intelligence source returned no match for this scan."],
  ["Chưa cấu hình hoặc chưa kiểm tra nguồn uy tín bên ngoài.", "No external reputation source was configured or checked."],
  ["Có logo/cấu trúc cổng thanh toán nhưng không dùng làm bằng chứng tích cực vì trang vẫn có tín hiệu rủi ro độc lập.", "Payment logos or structure were found, but they are not counted as positive evidence because independent risk signals remain."],
  ["Các lớp kỹ thuật đã chạy một phần nhưng chưa xác minh được chủ thể đứng sau website.", "Technical layers ran partially, but the website operator could not be verified."],
  ["Chưa đọc đủ nội dung thực tế nên chưa thể xác nhận mức rủi ro đầy đủ.", "Not enough real page content was read to confirm the full risk level."],
  ["Chưa thấy phishing rõ ràng, nhưng chất lượng bằng chứng còn thấp nên không nên hiển thị như một xác nhận an toàn.", "No clear phishing was found, but evidence quality is too low to present this as a safety confirmation."],
  ["Có tín hiệu rủi ro cần xác minh trước khi tiếp tục.", "Risk signals need verification before continuing."],
  ["Đã hoàn tất các lớp bằng chứng cốt lõi; chưa thấy bằng chứng phishing rõ ràng trong lần quét này.", "Core evidence layers completed; no clear phishing evidence was found in this scan."],
  ["Đã thấy giao dịch game bên thứ ba, nhưng uy tín và danh tính website chưa được xác minh đầy đủ.", "A third-party game transaction was detected, but website reputation and identity are not fully verified."],
  ["Đã thấy ngữ cảnh giao dịch game bên thứ ba cần kiểm tra độc lập.", "A third-party game transaction context was found and needs independent verification."],
  ["Có bằng chứng rủi ro cao dù một số lớp dữ liệu có thể còn thiếu.", "High-risk evidence exists even though some data layers may be missing."],
  ["Rời khỏi trang, không nhập dữ liệu, không thanh toán và không tải tệp.", "Leave the page; do not enter data, pay, or download files."],
  ["Không mở trực tiếp nếu link yêu cầu đăng nhập hoặc thanh toán; thử lại Link Lab sau hoặc xác minh domain qua kênh chính thức.", "Do not open it directly if the link asks for login or payment; retry Link Lab later or verify the domain through an official channel."],
  ["Tải lại rồi quét lại trang; nếu vẫn thiếu dữ liệu, dùng Link Lab và xác minh domain qua nguồn chính thức.", "Reload and rescan; if data is still missing, use Link Lab and verify the domain through an official source."],
  ["Kiểm tra tên pháp nhân, thông tin liên hệ, domain chính thức và chính sách giao dịch trước khi nhập dữ liệu hoặc thanh toán.", "Check the legal entity, contact information, official domain, and transaction policy before entering data or paying."],
  ["Tiếp tục thận trọng, kiểm tra đúng domain chính thức và quét lại trước khi đăng nhập hoặc thanh toán.", "Proceed carefully, verify the official domain, and rescan before logging in or paying."],
  ["Không nhập dữ liệu nhạy cảm cho tới khi kiểm tra được domain và lý do cảnh báo.", "Do not enter sensitive data until the domain and alert reasons are verified."],
  ["Có thể tiếp tục thận trọng và luôn kiểm tra domain trước khi đăng nhập hoặc thanh toán.", "You may proceed carefully; always verify the domain before logging in or paying."],
  ["Không phát hiện dấu hiệu rủi ro rõ ràng, nhưng vẫn cần thận trọng với thông tin nhạy cảm.", "No clear risk signals were found, but sensitive information still requires care."],
  ["Kiểm tra kỹ domain thật trước khi tiếp tục.", "Carefully verify the real domain before continuing."],
  ["Không nhập mật khẩu, OTP hoặc thông tin thanh toán khi chưa xác minh domain.", "Do not enter passwords, OTPs, or payment data until the domain is verified."],
  ["Không nhập mật khẩu, OTP, số thẻ hoặc thông tin cá nhân.", "Do not enter passwords, OTPs, card numbers, or personal information."],
  ["Không tải hoặc mở file từ trang này.", "Do not download or open files from this page."],
  ["HTTPS và điểm thấp không phải là bảo đảm an toàn tuyệt đối.", "HTTPS and a low score are not an absolute safety guarantee."],
  ["Đóng trang và tự gõ địa chỉ chính thức của dịch vụ.", "Close the page and type the service's official address yourself."],
  ["Ưu tiên truy cập dịch vụ từ bookmark hoặc ứng dụng chính thức.", "Prefer a bookmark or the official app when accessing the service."],
  ["Nếu đã nhập mật khẩu, hãy đổi mật khẩu và bật xác thực đa yếu tố.", "If you entered a password, change it and enable multi-factor authentication."],
  ["Trang đang yêu cầu mật khẩu; hãy kiểm tra domain thật trước khi nhập.", "The page asks for a password; verify the real domain before entering it."],
  ["Trang đang yêu cầu mật khẩu; chỉ nhập khi bạn chắc chắn domain là chính xác.", "The page asks for a password; enter it only when you are sure the domain is correct."],
  ["Trang đã chuyển hướng; hãy kiểm tra domain cuối cùng.", "The page redirected; check the final domain."],
  ["Trang đã chuyển hướng nhiều lần; hãy kiểm tra domain cuối cùng.", "The page redirected multiple times; check the final domain."],
  ["Nguồn threat intelligence đã xác nhận URL nguy hiểm; nên quay lại ngay.", "Threat intelligence confirmed the URL as unsafe; go back now."],
  ["Bạn đã bị chuyển qua domain khác; hãy kiểm tra địa chỉ cuối cùng thật kỹ.", "You were redirected to another domain; carefully inspect the final address."]
].forEach(([vi, en]) => ENGLISH_UI_TEXT.set(vi, en));

[
  ["Có dấu hiệu quảng bá, môi giới hoặc giao dịch dịch vụ tình dục; đây chỉ là chỉ báo kỹ thuật, không phải kết luận pháp lý.", "Signals of sexual-service promotion, brokerage, or transactions were found; this is a technical indicator, not a legal conclusion."],
  ["Có dấu hiệu thu mã thẻ, voucher hoặc giá trị trả trước trong giao dịch ngoài kênh chính thức; cần xác minh độc lập trước khi thanh toán.", "Signals of card-code, voucher, or prepaid-value collection outside an official channel were found; verify independently before paying."],
  ["Có lời kêu gọi đăng ký, chơi hoặc đặt cược", "Calls to register, play, or place bets were found"],
  ["Có nội dung nạp tiền, rút tiền, thưởng hoặc khuyến mãi", "Top-up, withdrawal, reward, or promotion content was found"],
  ["Có nội dung nạp tiền/vật phẩm hoặc tiền tệ trong game", "Game top-up, item, or currency content was found"],
  ["Có nội dung quảng bá crack, keygen, cheat, hack tool hoặc phần mềm can thiệp", "Content promoting cracks, keygens, cheats, hacking tools, or intrusive software was found"],
  ["Có thể liên quan hành vi phát tán phần mềm độc hại hoặc xâm phạm an ninh thông tin.", "This may involve malware distribution or information-security abuse."],
  ["Có nội dung liên quan mua bán/cho thuê tài khoản, SIM, OTP hoặc giấy tờ giả", "Content about trading or renting accounts, SIMs, OTPs, or fake documents was found"],
  ["Có nội dung chào mua, bán hoặc trao đổi dữ liệu cá nhân", "Content offering to buy, sell, or exchange personal data was found"],
  ["Có nội dung cam kết lợi nhuận, đa cấp, tài sản số hoặc đầu tư rủi ro cần xác minh", "Profit promises, multi-level marketing, digital assets, or risky-investment content needs verification"],
  ["Có nội dung quảng bá tạo hoặc cung cấp dịch vụ giả mặt, giả giọng hay deepfake", "Content promoting face, voice, or deepfake impersonation services was found"],
  ["Có nội dung cam kết lợi nhuận, đa cấp, tài sản số hoặc đầu tư rủi ro cần xác minh", "Profit promises, multi-level marketing, digital assets, or risky-investment content needs verification"],
  ["Các tín hiệu chỉ hỗ trợ sàng lọc; hãy kiểm tra nguồn chính thức trước khi kết luận hoặc báo cáo website.", "These signals only support screening; check an official source before concluding or reporting a website."],
  ["Đây là chỉ báo kỹ thuật về nội dung và hành vi quan sát được, không phải kết luận website vi phạm pháp luật.", "These are technical indicators of observed content and behavior, not a legal conclusion about the website."],
  ["Nội dung có thể không phù hợp với trẻ em hoặc môi trường công cộng.", "This content may be unsuitable for children or public environments."],
  ["Nội dung hạn chế và rủi ro tài chính; tính hợp pháp phụ thuộc giấy phép và quy định áp dụng.", "Restricted content and financial risk; legality depends on applicable licensing and rules."]
].forEach(([vi, en]) => ENGLISH_UI_TEXT.set(vi, en));

let uiLanguage = "vi";
let languageObserver = null;
let languageFrame = 0;
const localizedAttributeSources = new WeakMap();

let currentTab = null;
let currentResult = null;
let parentState = { configured: false, unlocked: false, unlockedUntil: 0 };
let pinMode = "unlock";
let pinSuccessAction = null;
let linkLabSessionId = "";

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = String(value ?? "");
  return div.innerHTML;
}

function translateTextToEnglish(value) {
  const text = String(value ?? "");
  const match = text.match(/^(\s*)([\s\S]*?)(\s*)$/u);
  const leading = match?.[1] || "";
  const core = match?.[2] || "";
  const trailing = match?.[3] || "";
  if (!core) return text;
  const direct = ENGLISH_UI_TEXT.get(core);
  if (direct) return `${leading}${direct}${trailing}`;
  for (const [pattern, replacement] of ENGLISH_DYNAMIC_TEXT) {
    if (pattern.test(core)) return `${leading}${core.replace(pattern, replacement)}${trailing}`;
  }
  return text;
}

function localizeTextNode(node) {
  if (!node?.parentElement || node.parentElement.closest("[data-no-translate], script, style")) return;
  const current = node.nodeValue || "";
  if (!current.trim()) return;
  if (node.__dpgVietnameseText === undefined) node.__dpgVietnameseText = current;
  const source = node.__dpgVietnameseText;
  const translated = translateTextToEnglish(source);
  if (uiLanguage === "en" && current !== source && current !== translated) {
    node.__dpgVietnameseText = current;
  } else if (uiLanguage === "vi" && current !== source && current !== translated) {
    node.__dpgVietnameseText = current;
  }
  const nextSource = node.__dpgVietnameseText;
  const next = uiLanguage === "en" ? translateTextToEnglish(nextSource) : nextSource;
  if (node.nodeValue !== next) node.nodeValue = next;
}

function localizeAttribute(element, attribute) {
  if (!element.hasAttribute(attribute) || element.matches("[data-no-translate]")) return;
  const current = element.getAttribute(attribute) || "";
  let sources = localizedAttributeSources.get(element);
  if (!sources) {
    sources = {};
    localizedAttributeSources.set(element, sources);
  }
  if (sources[attribute] === undefined) sources[attribute] = current;
  const source = sources[attribute];
  const translated = translateTextToEnglish(source);
  if (current !== source && current !== translated) sources[attribute] = current;
  const nextSource = sources[attribute];
  const next = uiLanguage === "en" ? translateTextToEnglish(nextSource) : nextSource;
  if (current !== next) element.setAttribute(attribute, next);
}

function updateLanguageControls() {
  const targetLanguage = uiLanguage === "en" ? "vi" : "en";
  const buttonText = targetLanguage.toUpperCase();
  const label = targetLanguage === "en" ? "Switch interface to English" : "Chuyển giao diện sang tiếng Việt";
  ["childLanguageBtn", "simpleLanguageBtn", "technicalLanguageBtn"].forEach(id => {
    const button = document.getElementById(id);
    if (!button) return;
    if (button.textContent !== buttonText) button.textContent = buttonText;
    if (button.getAttribute("aria-label") !== label) button.setAttribute("aria-label", label);
    if (button.title !== label) button.title = label;
  });
  const select = document.getElementById("uiLanguageSelect");
  if (select && select.value !== uiLanguage) select.value = uiLanguage;
}

function applyLanguageToDom(root = document.body) {
  if (!root) return;
  document.documentElement.lang = uiLanguage;
  document.body.dataset.language = uiLanguage;
  document.title = uiLanguage === "en" ? "DNS Phishing Guard — Protection" : "DNS Phishing Guard — Bảo vệ";
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  let node = walker.nextNode();
  while (node) {
    localizeTextNode(node);
    node = walker.nextNode();
  }
  root.querySelectorAll?.("[placeholder], [aria-label], [title]").forEach(element => {
    ["placeholder", "aria-label", "title"].forEach(attribute => localizeAttribute(element, attribute));
  });
  updateLanguageControls();
}

function scheduleLanguageRefresh() {
  if (languageFrame) return;
  languageFrame = requestAnimationFrame(() => {
    languageFrame = 0;
    applyLanguageToDom();
  });
}

async function refreshLocalizedViews() {
  renderChildStatus();
  renderSimpleStatus();
  await renderToggle();
  if (currentTab?.id) await loadStatus();
  const activeView = document.querySelector(".tab.active")?.dataset.view;
  if (activeView === "history") await renderHistory();
  if (activeView === "stats") await renderStats();
  if (activeView === "audit") await renderAudit();
  if (activeView === "settings") await renderSettings();
  applyLanguageToDom();
}

async function setUiLanguage(language, persist = true) {
  uiLanguage = language === "en" ? "en" : "vi";
  if (persist) await chrome.storage.local.set({ uiLanguage });
  await refreshLocalizedViews();
}

async function setupLanguage() {
  const stored = await chrome.storage.local.get("uiLanguage");
  uiLanguage = stored.uiLanguage === "en" ? "en" : "vi";
  ["childLanguageBtn", "simpleLanguageBtn", "technicalLanguageBtn"].forEach(id => {
    document.getElementById(id)?.addEventListener("click", () => {
      setUiLanguage(uiLanguage === "en" ? "vi" : "en").catch(error => console.error("Language switch error:", error));
    });
  });
  document.getElementById("uiLanguageSelect")?.addEventListener("change", event => {
    setUiLanguage(event.target.value).catch(error => console.error("Language switch error:", error));
  });
  languageObserver = new MutationObserver(scheduleLanguageRefresh);
  languageObserver.observe(document.body, {
    subtree: true,
    childList: true,
    characterData: true,
    attributes: true,
    attributeFilter: ["placeholder", "aria-label", "title"]
  });
  applyLanguageToDom();
}

function normalizeInputDomain(raw) {
  return String(raw || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/\/.*$/, "");
}

function riskClass(level) {
  if (level === "HIGH") return "high";
  if (level === "MEDIUM") return "medium";
  if (level === "SUSPICIOUS") return "suspicious";
  return "safe";
}

function riskLabel(level) {
  if (level === "HIGH") return "NGUY HIỂM";
  if (level === "MEDIUM") return "CẢNH BÁO";
  if (level === "SUSPICIOUS") return "CẦN KIỂM TRA";
  return "KHÔNG PHÁT HIỆN PHISHING";
}

function riskSummary(level) {
  if (level === "HIGH") return "Dừng lại và rời khỏi trang";
  if (level === "MEDIUM") return "Cần xác minh trước khi tiếp tục";
  if (level === "SUSPICIOUS") return "Có tín hiệu cần kiểm tra thêm";
  return "Chưa thấy bằng chứng phishing rõ ràng";
}

function riskColor(level) {
  if (level === "HIGH") return "var(--high)";
  if (level === "MEDIUM") return "var(--medium)";
  if (level === "SUSPICIOUS") return "var(--suspicious)";
  return "var(--safe)";
}

function hasIncompleteSafeEvidence(result) {
  const assessment = getEvidenceAssessment(result);
  const determinedSafe = result?.risk?.level === "SAFE" &&
    assessment.status === "COMPLETE" &&
    assessment.riskState === "DETERMINED";
  // Optional layers (for example threat intelligence) should not turn a
  // complete, determined SAFE result into an amber verdict in the user UI.
  return !determinedSafe && (isRiskUndetermined(result) || assessment.safeDisplayState === "CAUTION");
}

function gameCommerceCategory(result) {
  return (result?.contentSafety?.categories || []).find(item => item?.id === "GAME_COMMERCE") || null;
}

function contentClass(level) {
  if (level === "HIGH") return "high";
  if (level === "WARNING") return "medium";
  if (level === "NOTICE") return "suspicious";
  return "safe";
}

function contentLabel(level) {
  if (level === "HIGH") return "RỦI RO NỘI DUNG CAO";
  if (level === "WARNING") return "CẢNH BÁO NỘI DUNG";
  if (level === "NOTICE") return "NỘI DUNG CẦN LƯU Ý";
  return "KHÔNG PHÁT HIỆN NỘI DUNG HẠN CHẾ";
}

function contentColor(level) {
  if (level === "HIGH") return "#7C3AED";
  if (level === "WARNING") return "#A855F7";
  if (level === "NOTICE") return "#F97316";
  return "var(--safe)";
}

function formatTime(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(uiLanguage === "en" ? "en-GB" : "vi-VN", { hour12: false });
}

function formatDomainAge(ageInfo) {
  const days = Number(ageInfo?.ageDays);
  if (!Number.isFinite(days) || days < 0) return uiLanguage === "en" ? "Unknown" : "Không xác định";
  if (days < 60) return uiLanguage === "en" ? `${Math.round(days)} days` : `${Math.round(days)} ngày`;
  if (days < 730) return uiLanguage === "en" ? `${Math.round(days / 30)} months` : `${Math.round(days / 30)} tháng`;
  return uiLanguage === "en" ? `${(days / 365.25).toFixed(1)} years` : `${(days / 365.25).toFixed(1)} năm`;
}

function percent(numerator, denominator) {
  if (!denominator) return "0%";
  return `${Math.round((numerator / denominator) * 100)}%`;
}

function speak(text) {
  try {
    window.speechSynthesis.cancel();
    const utterance = new SpeechSynthesisUtterance(uiLanguage === "en" ? translateTextToEnglish(text) : text);
    utterance.lang = uiLanguage === "en" ? "en-US" : "vi-VN";
    utterance.rate = 0.88;
    window.speechSynthesis.speak(utterance);
  } catch {
    // Optional browser capability.
  }
}

async function getSettings() {
  return { ...DEFAULT_SETTINGS, ...(await chrome.storage.local.get(Object.keys(DEFAULT_SETTINGS))) };
}

async function fetchParentState() {
  const response = await chrome.runtime.sendMessage({ type: "GET_PARENT_STATE" }).catch(() => null);
  parentState = response?.done
    ? {
        configured: Boolean(response.configured),
        unlocked: Boolean(response.unlocked),
        unlockedUntil: Number(response.unlockedUntil) || 0
      }
    : { configured: false, unlocked: false, unlockedUntil: 0 };
  return parentState;
}

function setupTabs() {
  document.querySelectorAll(".tab").forEach(button => {
    button.addEventListener("click", async () => {
      document.querySelectorAll(".tab").forEach(item => item.classList.remove("active"));
      document.querySelectorAll(".view").forEach(item => item.classList.remove("active"));
      button.classList.add("active");
      document.getElementById(`view-${button.dataset.view}`).classList.add("active");
      if (button.dataset.view === "history") await renderHistory();
      if (button.dataset.view === "stats") await renderStats();
      if (button.dataset.view === "settings") await renderSettings();
    });
  });
}

async function renderToggle() {
  const settings = await getSettings();
  ["toggleBtn", "simpleToggleBtn"].forEach(id => {
    const button = document.getElementById(id);
    if (!button) return;
    button.textContent = settings.enabled ? "Đang BẬT" : "Đang TẮT";
    button.classList.toggle("off", !settings.enabled);
  });
  const dot = document.getElementById("statusDot");
  dot.style.background = settings.enabled ? "var(--safe)" : "var(--dim)";
  dot.classList.toggle("inactive", !settings.enabled);
  const simpleDot = document.getElementById("simpleStatusDot");
  if (simpleDot) {
    simpleDot.style.background = settings.enabled ? "var(--safe)" : "var(--dim)";
    simpleDot.style.boxShadow = settings.enabled ? "0 0 10px var(--safe)" : "none";
  }
}

async function setupToggle() {
  const toggleProtection = async () => {
    const settings = await getSettings();
    if (settings.childMode && !parentState.unlocked && settings.enabled) {
      openPinModal("unlock", async () => {
        await chrome.storage.local.set({ enabled: false });
        await renderToggle();
      });
      return;
    }
    await chrome.storage.local.set({ enabled: !settings.enabled });
    await renderToggle();
  };
  ["toggleBtn", "simpleToggleBtn"].forEach(id => {
    document.getElementById(id)?.addEventListener("click", toggleProtection);
  });
}

function childSummary(result) {
  if (!result) return {
    level: "SAFE",
    label: "ĐANG KIỂM TRA…",
    message: "Khiên Nhỏ chưa có kết quả cho trang này.",
    advice: "Con hãy chờ một chút hoặc bấm Kiểm tra lại.",
    speech: "Khiên Nhỏ đang kiểm tra trang này. Con hãy chờ một chút."
  };
  if (result.settings?.childRequireContentScan !== false && result.contentSafety?.available === false) return {
    level: "SUSPICIOUS",
    label: "🔄 ĐANG KIỂM TRA…",
    message: "Khiên Nhỏ chưa đọc xong nội dung trang này.",
    advice: "Con hãy chờ hoặc bấm Kiểm tra lại trước khi nhập thông tin.",
    speech: "Khiên Nhỏ chưa kiểm tra xong nội dung trang này. Con hãy chờ một chút."
  };
  const childCategories = result.contentSafety?.categories || [];
  const strictCategoryIds = new Set(["SEXUAL_SERVICES", "ADULT", "GAMBLING", "MALWARE", "IDENTITY_ABUSE", "PERSONAL_DATA", "SCAM_COMMERCE", "GAME_COMMERCE"]);
  const childContentWarning = result.contentSafety?.detected && (
    childCategories.some(item => strictCategoryIds.has(item.id)) ||
    ["HIGH", "WARNING"].includes(result.contentSafety.level) ||
    (result.settings?.childProtectionLevel === "strict" && result.contentSafety.level === "NOTICE")
  );
  if (childContentWarning) return {
    level: result.contentSafety.level === "HIGH" ? "HIGH" : "MEDIUM",
    label: "🛡️ NỘI DUNG CẦN TRÁNH",
    message: childCategories.some(item => item.id === "SEXUAL_SERVICES")
      ? "Trang này có dấu hiệu dịch vụ nhạy cảm chỉ dành cho người lớn."
      : childCategories.some(item => item.id === "GAMBLING")
        ? "Trang này có dấu hiệu cờ bạc hoặc cá cược."
        : childCategories.some(item => item.id === "SCAM_COMMERCE")
          ? "Trang này có dấu hiệu yêu cầu mã thẻ hoặc giao dịch cần người lớn xác minh."
        : childCategories.some(item => item.id === "GAME_COMMERCE")
          ? "Trang này có mua bán tài khoản hoặc dịch vụ game qua kênh bên thứ ba; cần người lớn xác minh."
        : childCategories.some(item => item.id === "ADULT")
          ? "Trang này có nội dung không phù hợp với trẻ em."
          : "Trang này có nội dung hoặc yêu cầu thông tin cần người lớn kiểm tra.",
    advice: "Con đừng liên hệ, gửi ảnh riêng tư, chia sẻ vị trí, chuyển tiền hoặc tiếp tục một mình. Hãy gọi người lớn.",
    speech: "Dừng lại. Trang này có nội dung chỉ dành cho người lớn hoặc cần người lớn kiểm tra. Con đừng liên hệ, gửi ảnh, chia sẻ vị trí hoặc chuyển tiền."
  };
  const phishingPageWarning = result.risk.level !== "SAFE" && result.risk.presentation?.shouldWarnOnPage !== false;
  if (phishingPageWarning && result.risk.level === "HIGH") return {
    level: "HIGH",
    label: "🛑 DỪNG LẠI!",
    message: "Trang này có thể không an toàn.",
    advice: "Đừng nhập mật khẩu, mã OTP, số điện thoại và đừng tải tệp. Hãy quay lại và gọi người lớn.",
    speech: "Dừng lại. Trang này có thể không an toàn. Con đừng nhập mật khẩu, mã O T P, số điện thoại và đừng tải tệp. Hãy quay lại và gọi người lớn."
  };
  if (phishingPageWarning && result.risk.level === "SUSPICIOUS") return {
    level: "SUSPICIOUS",
    label: "🔎 KHOAN ĐÃ!",
    message: "Trang này có vài dấu hiệu cần kiểm tra.",
    advice: "Con đừng tự nhập thông tin. Hãy nhờ người lớn kiểm tra trước.",
    speech: "Khoan đã. Trang này có vài dấu hiệu cần kiểm tra. Con đừng nhập mật khẩu hoặc thông tin của gia đình. Hãy gọi người lớn kiểm tra."
  };
  if (phishingPageWarning && result.risk.level === "MEDIUM") return {
    level: "MEDIUM",
    label: "⚠️ KHOAN ĐÃ!",
    message: "Trang này hơi lạ.",
    advice: "Con đừng tự nhập thông tin. Hãy quay lại hoặc nhờ người lớn kiểm tra.",
    speech: "Khoan đã. Trang này hơi lạ. Con đừng nhập mật khẩu hoặc thông tin của gia đình. Hãy quay lại hoặc gọi người lớn kiểm tra."
  };
  if (hasIncompleteSafeEvidence(result)) return {
    level: "SUSPICIOUS",
    label: "🔎 CHƯA ĐỦ DỮ LIỆU",
    message: "Khiên Nhỏ chưa thể nói trang này an toàn.",
    advice: "Con đừng nhập thông tin hoặc thanh toán. Hãy nhờ người lớn kiểm tra domain trước.",
    speech: "Khiên Nhỏ chưa có đủ dữ liệu để nói trang này an toàn. Con đừng nhập thông tin hoặc thanh toán. Hãy gọi người lớn kiểm tra."
  };
  return {
    level: "SAFE",
    label: "✅ ĐÃ KIỂM TRA",
    message: "Khiên Nhỏ chưa thấy cảnh báo rõ ràng trên trang này.",
    advice: "Con vẫn không nên đưa mật khẩu, ảnh riêng tư hoặc thông tin của gia đình cho người lạ nhé.",
    speech: "Trang này có vẻ ổn. Nhưng con vẫn không nên đưa mật khẩu hoặc thông tin của gia đình cho người lạ."
  };
}

function renderChildStatus() {
  const summary = childSummary(currentResult);
  const card = document.getElementById("childCard");
  card.classList.toggle("medium-border", summary.level === "MEDIUM" || summary.level === "SUSPICIOUS");
  card.classList.toggle("high-border", summary.level === "HIGH");
  document.getElementById("childLabel").textContent = summary.label;
  document.getElementById("childMessage").textContent = summary.message;
  document.getElementById("childAdvice").textContent = summary.advice;
  document.getElementById("childDomain").textContent = currentResult?.domain || "Chưa có dữ liệu";
  document.getElementById("childBackBtn").classList.toggle("hidden", summary.level === "SAFE");
  document.getElementById("childSpeakBtn").dataset.speech = summary.speech;
}

function simpleOutcome(result) {
  if (!result) return {
    tone: "check",
    badge: "ĐANG KIỂM TRA",
    icon: "⌁",
    kicker: "CHƯA CÓ KẾT QUẢ",
    title: "Chờ kết quả bảo vệ",
    advice: "Mở hoặc tải lại một website để extension bắt đầu kiểm tra.",
    action: "recheck",
    actionLabel: "Quét lại trang"
  };

  const contentLevel = result.contentSafety?.level || "NONE";
  const danger = result.risk.level === "HIGH" || contentLevel === "HIGH";
  const incompleteSafeEvidence = hasIncompleteSafeEvidence(result);
  const gameCommerce = gameCommerceCategory(result);
  const assessment = getEvidenceAssessment(result);
  const check = !danger && (
    result.risk.level === "MEDIUM" ||
    result.risk.level === "SUSPICIOUS" ||
    ["WARNING", "NOTICE"].includes(contentLevel)
  );
  if (danger) return {
    tone: "danger",
    badge: "KHÔNG NÊN TRUY CẬP",
    icon: "!",
    kicker: "RỦI RO CAO",
    title: "Dừng lại và rời khỏi trang",
    advice: "Đừng nhập mật khẩu, OTP, thông tin thanh toán hoặc tải tệp từ trang này.",
    action: "back",
    actionLabel: "← Quay lại nơi an toàn"
  };
  if (gameCommerce && result.risk.level === "SAFE") return {
    tone: "check",
    badge: "GIAO DỊCH CẦN XÁC MINH",
    icon: "G?",
    kicker: incompleteSafeEvidence ? "UY TÍN WEBSITE CHƯA ĐƯỢC XÁC MINH" : "GIAO DỊCH GAME BÊN THỨ BA",
    title: "Đã thấy giao dịch tài khoản hoặc dịch vụ game",
    advice: assessment.recommendedAction,
    action: "recheck",
    actionLabel: "↻ Quét lại & kiểm tra lớp thiếu"
  };
  if (incompleteSafeEvidence) return {
    tone: "check",
    badge: "CHƯA ĐỦ DỮ LIỆU",
    icon: "?",
    kicker: "KHÔNG NÊN COI LÀ XÁC NHẬN AN TOÀN",
    title: "Chưa thể đánh giá đầy đủ",
    advice: "Kết quả hiện có quá ít bằng chứng. Hãy quét lại và không nhập dữ liệu hoặc thanh toán cho tới khi xác minh domain.",
    action: "recheck",
    actionLabel: "↻ Quét lại trang"
  };
  if (check) return {
    tone: "check",
    badge: "CẦN KIỂM TRA",
    icon: "?",
    kicker: "CHƯA ĐỦ BẰNG CHỨNG",
    title: "Xác minh trước khi tiếp tục",
    advice: "Kiểm tra đúng domain chính thức và tránh nhập dữ liệu nhạy cảm cho tới khi xác minh xong.",
    action: "back",
    actionLabel: "← Quay lại để kiểm tra"
  };
  return {
    tone: "safe",
    badge: "CÓ THỂ TIẾP TỤC THẬN TRỌNG",
    icon: "✓",
    kicker: "CHƯA THẤY PHISHING RÕ RÀNG",
    title: "Trang hiện tại có vẻ ổn",
    advice: "Kết quả an toàn không phải bảo đảm tuyệt đối. Vẫn kiểm tra domain trước khi nhập mật khẩu hoặc thanh toán.",
    action: "recheck",
    actionLabel: "↻ Quét lại trang"
  };
}

function simpleReasonItems(result, outcome) {
  if (!result) return ["Chưa có dữ liệu từ tab hiện tại."];
  const reasons = [];
  const page = result.pageSignals || {};
  const officialClaimMismatch = Boolean(page.officialClaimMismatch || page.gameCommerceOfficialClaimMismatch);
  if (result.listStatus?.blacklisted) reasons.push("Domain nằm trong blacklist đã được xác nhận.");
  if (result.threatInfo?.isUnsafe) reasons.push("Nguồn Threat Intelligence báo URL có nguy cơ.");
  if (officialClaimMismatch) {
    const closestOfficialDomain = result.typoMatch?.closest;
    reasons.push(closestOfficialDomain
      ? `Địa chỉ website này rất giống ${closestOfficialDomain}, một địa chỉ chính thức đã được xác minh.`
      : "Địa chỉ website này không nằm trong hệ thống địa chỉ chính thức đã được xác minh của thương hiệu.");
    reasons.push(`Trang tự nhận là chính thức hoặc đối tác của ${page.officialClaimBrandName || page.gameCommerceBrandName || "một thương hiệu game"}, nhưng địa chỉ hiện tại không khớp hệ thống chính thức.`);
    if (Number(page.gameAccountInputCount || 0) > 0 || Number(page.prepaidCodeInputCount || 0) > 0) {
      reasons.push("Trang yêu cầu ID game hoặc mã thẻ (số serial/PIN); nhập vào có thể làm mất tiền hoặc tài khoản.");
    }
  }
  if (!officialClaimMismatch && (result.homoglyphInfo?.hasHomoglyph || result.homoglyphInfo?.isPunycode || result.typoMatch)) {
    reasons.push("Tên miền có ký tự lạ hoặc gần giống một thương hiệu khác.");
  }
  if (page.brandMismatch) reasons.push("Tên thương hiệu trên trang không khớp địa chỉ website.");
  if (!officialClaimMismatch && page.commerceBrandMismatch) reasons.push("Trang dùng thương hiệu cho giao dịch trên domain không chính thức.");
  if (!officialClaimMismatch && page.gameCommerceBrandMismatch) reasons.push("Trang dùng thương hiệu game trên domain không thuộc nhà phát hành.");
  if (page.externalPasswordFormCount > 0) reasons.push("Form mật khẩu có thể gửi dữ liệu sang một địa chỉ khác.");
  else if (page.passwordInputCount > 0 && outcome.tone !== "safe") reasons.push("Trang đang yêu cầu nhập mật khẩu.");
  if (page.riskyDownloadLinkCount > 0) reasons.push("Trang có liên kết tới loại tệp cần thận trọng.");
  if (Number(result.ageInfo?.ageDays) < 30) reasons.push("Domain mới được đăng ký gần đây.");
  if (result.redirectInfo?.crossDomainCount > 0 && !result.redirectInfo?.isFederatedAuthFlow) {
    reasons.push("Điều hướng đã đi qua nhiều domain khác nhau.");
  }
  const contentLabels = (result.contentSafety?.categories || []).map(item => item.label).filter(Boolean);
  if (contentLabels.length) reasons.push(`Nội dung cần lưu ý: ${contentLabels.slice(0, 2).join(", ")}.`);

  const assessment = getEvidenceAssessment(result);
  if (assessment.riskState === "UNDETERMINED" && assessment.missingLayers?.length) {
    reasons.push(`Còn thiếu: ${assessment.missingLayers.slice(0, 2).map(item => item.label).join(", ")}.`);
  }
  if (assessment.paymentEvidenceEligible) {
    const providers = (page.paymentIntegration?.providers || []).map(item => item.label).filter(Boolean).slice(0, 3);
    reasons.push(`Đã quan sát luồng thanh toán với ${providers.join(", ") || "cổng phổ biến"}; đây không phải xác thực giao dịch thật.`);
  }
  if (assessment.verifiedBrandEvidenceEligible) {
    reasons.push(`Địa chỉ hiện tại khớp hệ thống chính thức đã xác minh của ${page.gameCommerceBrandName || "thương hiệu game"}; đây vẫn không phải bảo đảm tuyệt đối cho giao dịch.`);
  }

  if (!reasons.length && result.risk.level === "SAFE" && outcome.tone === "check") {
    reasons.push("Chất lượng bằng chứng hoặc phạm vi quét chưa đủ để xác nhận trạng thái xanh.");
  }

  if (!reasons.length && outcome.tone === "safe") {
    if (result.listStatus?.knownDomain) reasons.push("Domain được nhận diện trong tập website phổ biến.");
    if (Number(result.ageInfo?.ageDays) >= 365) reasons.push("Domain đã hoạt động hơn một năm.");
    reasons.push("Chưa thấy blacklist, giả mạo tên miền hoặc hành vi lấy dữ liệu rõ ràng.");
  }
  if (!reasons.length) {
    const mlProbability = Number(result.mlInfo?.probability);
    if (Number.isFinite(mlProbability) && mlProbability >= 0.55) {
      reasons.push("Cấu trúc URL có điểm bất thường; đây chỉ là tín hiệu tham khảo, không phải kết luận phishing.");
    }
  }
  return [...new Set([...reasons, ...(result.risk?.reasons || [])])].slice(0, 3);
}

function renderSimpleStatus() {
  const outcome = simpleOutcome(currentResult);
  const card = document.getElementById("simpleVerdictCard");
  card.className = `simple-verdict ${outcome.tone}`;
  document.getElementById("simpleRiskBadge").textContent = outcome.badge;
  document.getElementById("simpleOutcomeIcon").textContent = outcome.icon;
  document.getElementById("simpleOutcomeKicker").textContent = outcome.kicker;
  document.getElementById("simpleOutcomeTitle").textContent = outcome.title;
  document.getElementById("simpleDomain").textContent = currentResult?.domain || "Chưa có dữ liệu";
  document.getElementById("simpleAdvice").textContent = outcome.advice;
  renderList("simpleReasons", simpleReasonItems(currentResult, outcome), "Chưa có tín hiệu để hiển thị.");
  const assessment = currentResult ? getEvidenceAssessment(currentResult) : null;
  document.getElementById("simpleScore").textContent = currentResult
    ? (assessment.riskState === "UNDETERMINED" ? "— /100" : `${currentResult.risk?.score ?? 0}/100`)
    : "—";
  document.getElementById("simpleConfidence").textContent = assessment ? `${assessment.evidenceScore}/100` : "—";
  document.getElementById("simpleCoverage").textContent = assessment?.label || "—";
  const primary = document.getElementById("simplePrimaryBtn");
  primary.dataset.action = outcome.action;
  primary.textContent = outcome.actionLabel;
  const hideFeedback = !currentResult || outcome.tone === "safe";
  document.getElementById("simpleFeedbackBtn").classList.toggle("hidden", hideFeedback);
  primary.parentElement.classList.toggle("solo", hideFeedback);
}

async function renderShellMode() {
  const settings = await getSettings();
  await fetchParentState();
  const lockedChild = settings.childMode && !parentState.unlocked;
  const simpleMode = !lockedChild && settings.uiProfile !== "technical";
  const technicalMode = !lockedChild && !simpleMode;
  document.getElementById("childShell").classList.toggle("hidden", !lockedChild);
  document.getElementById("simpleShell").classList.toggle("hidden", !simpleMode);
  document.getElementById("advancedShell").classList.toggle("hidden", !technicalMode);
  if (lockedChild) renderChildStatus();
  else {
    renderSimpleStatus();
    await renderToggle();
  }
}

function setupShellModeActions() {
  document.getElementById("technicalModeBtn").addEventListener("click", async () => {
    await chrome.storage.local.set({ uiProfile: "technical" });
    await renderShellMode();
  });
  document.getElementById("simpleModeBtn").addEventListener("click", async () => {
    await chrome.storage.local.set({ uiProfile: "simple" });
    await renderShellMode();
  });
}

function setupChildActions() {
  document.getElementById("childBackBtn").addEventListener("click", async () => {
    if (currentTab?.id) await chrome.tabs.goBack(currentTab.id).catch(() => {});
    window.close();
  });
  document.getElementById("childSpeakBtn").addEventListener("click", event => speak(event.currentTarget.dataset.speech || "Hãy gọi người lớn."));
  document.getElementById("childRecheckBtn").addEventListener("click", async () => {
    if (!currentTab?.id || !currentTab.url) return;
    await chrome.runtime.sendMessage({ type: "RECHECK_TAB", tabId: currentTab.id, url: currentTab.url });
    await loadStatus();
  });
  document.getElementById("parentUnlockBtn").addEventListener("click", async () => {
    await fetchParentState();
    openPinModal(parentState.configured ? "unlock" : "setup", async () => {
      await loadStatus();
      await renderShellMode();
    });
  });
}

function setupSimpleActions() {
  document.getElementById("simplePrimaryBtn").addEventListener("click", async event => {
    if (!currentTab?.id) return;
    if (event.currentTarget.dataset.action === "back") {
      await chrome.tabs.goBack(currentTab.id).catch(() => chrome.tabs.update(currentTab.id, { url: "about:blank" }));
      window.close();
      return;
    }
    if (!currentTab.url) return;
    event.currentTarget.disabled = true;
    event.currentTarget.textContent = "Đang quét…";
    await chrome.runtime.sendMessage({ type: "RECHECK_TAB", tabId: currentTab.id, url: currentTab.url }).catch(() => null);
    await loadStatus();
    event.currentTarget.disabled = false;
    renderSimpleStatus();
  });

  document.getElementById("simpleFeedbackBtn").addEventListener("click", async event => {
    if (!currentTab?.id || !currentResult?.domain) return;
    const status = document.getElementById("simpleFeedbackStatus");
    event.currentTarget.disabled = true;
    const response = await chrome.runtime.sendMessage({
      type: "REPORT_FALSE_POSITIVE",
      tabId: currentTab.id,
      domain: currentResult.domain
    }).catch(() => null);
    status.textContent = response?.done
      ? "Đã ghi nhận cục bộ để bạn xem lại; không gửi dữ liệu ra ngoài."
      : response?.error || "Chưa thể lưu phản hồi.";
    event.currentTarget.textContent = response?.done ? "Đã ghi nhận báo nhầm" : "Thử ghi nhận lại";
    event.currentTarget.disabled = Boolean(response?.done);
  });
}

function renderBreakdown(result) {
  const labels = {
    threatIntel: "Threat Intel",
    domain: "Domain",
    url: "URL",
    network: "Chuyển hướng",
    ml: "URL ML",
    page: "Hành vi trang"
  };
  const breakdown = result?.risk?.breakdown || {};
  document.getElementById("breakdown").innerHTML = Object.entries(labels).map(([key, label]) => {
    const value = Math.min(100, Number(breakdown[key]) || 0);
    const color = value >= 70
      ? "var(--high)"
      : value >= 30
        ? "var(--medium)"
        : value >= 10
          ? "var(--suspicious)"
          : "var(--safe)";
    return `<div class="break-row"><span>${label}</span><div class="track"><div class="fill" style="width:${value}%;background:${color}"></div></div><b>${value}</b></div>`;
  }).join("") + (breakdown.whitelistReduction
    ? `<div class="break-row"><span>Whitelist giảm</span><div class="track"><div class="fill" style="width:${breakdown.whitelistReduction}%;background:var(--accent)"></div></div><b>-${breakdown.whitelistReduction}</b></div>`
    : "");
}

function renderEvidenceCoverage(result) {
  const assessment = getEvidenceAssessment(result);
  const badge = document.getElementById("coverageBadge");
  const determinedSafe = result.risk?.level === "SAFE" &&
    assessment.status === "COMPLETE" &&
    assessment.riskState === "DETERMINED";
  const caution = !determinedSafe && assessment.safeDisplayState === "CAUTION";
  const supportedSafe = determinedSafe || (result.risk?.level === "SAFE" && assessment.safeDisplayState === "CONFIDENT");
  const tone = supportedSafe ? "safe" : "suspicious";
  badge.textContent = caution ? "BẰNG CHỨNG CÒN YẾU" : assessment.label;
  badge.className = `pill ${tone}`;
  document.getElementById("coverageSummary").textContent = assessment.summary;
  document.getElementById("coverageRiskState").textContent = assessment.riskState === "UNDETERMINED"
    ? "CHƯA XÁC ĐỊNH"
    : assessment.riskState === "PROVISIONAL"
      ? "TẠM THỜI"
      : "ĐÃ XÁC ĐỊNH";
  document.getElementById("coverageEvidenceScore").textContent = `${assessment.evidenceScore}/100`;
  renderList(
    "coverageChecked",
    assessment.checkedLayers.map(item => `${item.label}: ${item.detail}`),
    "Chưa ghi nhận lớp kiểm tra nào."
  );
  renderList(
    "coverageMissing",
    assessment.missingLayers.map(item => `${item.label}: ${item.detail}`),
    "Không thiếu lớp bằng chứng cốt lõi."
  );
  document.getElementById("coverageAction").textContent = assessment.recommendedAction;
}

function renderList(elementId, items, fallback) {
  const element = document.getElementById(elementId);
  element.innerHTML = "";
  if (!items?.length) {
    const li = document.createElement("li");
    li.textContent = fallback;
    element.appendChild(li);
    return;
  }
  items.forEach(item => {
    const li = document.createElement("li");
    li.textContent = item;
    element.appendChild(li);
  });
}

async function loadStatus() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTab = tab || null;
  if (!tab?.id) {
    currentResult = null;
    renderChildStatus();
    renderSimpleStatus();
    return;
  }

  const data = await chrome.storage.session.get(String(tab.id));
  currentResult = data[String(tab.id)] || null;
  renderChildStatus();
  renderSimpleStatus();
  if (!currentResult) {
    document.getElementById("domain").textContent = "Chưa có dữ liệu";
    document.getElementById("riskSummary").textContent = "Mở một website để bắt đầu phân tích";
    document.getElementById("scanFreshness").textContent = "Chưa nhận được kết quả từ tab hiện tại";
    return;
  }

  const result = currentResult;
  const level = result.risk.level;
  const scoreValue = Math.max(0, Math.min(100, Number(result.risk.score) || 0));
  const incompleteSafeEvidence = hasIncompleteSafeEvidence(result);
  const assessment = getEvidenceAssessment(result);
  const gameCommerce = gameCommerceCategory(result);
  const gameCommercePrimary = Boolean(gameCommerce && level === "SAFE");
  const visualLevel = incompleteSafeEvidence ? "SUSPICIOUS" : level;
  const riskTone = riskColor(visualLevel);
  const shell = document.getElementById("advancedShell");
  shell.style.setProperty("--risk-color", riskTone);
  shell.dataset.risk = riskClass(visualLevel);
  document.getElementById("domain").textContent = result.domain;
  document.getElementById("riskSummary").textContent = gameCommercePrimary
    ? assessment.summary
    : incompleteSafeEvidence
      ? assessment.summary
    : riskSummary(level);
  document.getElementById("scanFreshness").textContent = result.checkedAt
    ? `Cập nhật ${formatTime(result.checkedAt)}`
    : "Kết quả mới nhất của tab hiện tại";
  const badge = document.getElementById("riskBadge");
  badge.textContent = gameCommercePrimary
    ? "GIAO DỊCH CẦN XÁC MINH"
    : incompleteSafeEvidence ? "CHƯA ĐỦ DỮ LIỆU" : riskLabel(level);
  badge.className = `pill ${riskClass(visualLevel)}`;
  document.getElementById("score").textContent = incompleteSafeEvidence ? "—" : scoreValue;
  document.getElementById("scoreUnit").textContent = incompleteSafeEvidence ? "CHƯA XÁC ĐỊNH" : "/ 100";
  document.getElementById("scoreFill").style.cssText = `width:${incompleteSafeEvidence ? 0 : scoreValue}%;background:${riskTone}`;
  const riskDial = document.getElementById("riskDial");
  riskDial.style.setProperty("--score-angle", `${(incompleteSafeEvidence ? 0 : scoreValue) * 3.6}deg`);
  riskDial.style.setProperty("--risk-color", riskTone);
  riskDial.setAttribute("aria-label", incompleteSafeEvidence ? "Điểm rủi ro chưa xác định" : `Điểm rủi ro ${scoreValue} trên 100`);
  document.getElementById("confidence").textContent = `${assessment.evidenceScore}/100`;
  document.getElementById("confidenceFill").style.cssText = `width:${assessment.evidenceScore}%;background:var(--accent)`;
  document.getElementById("registrableDomain").textContent = result.registrableDomain || result.domain;
  document.getElementById("identityStatus").textContent = result.risk.identityStatus?.label || "Chưa xác minh";
  document.getElementById("identityStatus").title = result.risk.identityStatus?.detail || "";
  document.getElementById("publicSuffix").textContent = result.domainInfo?.publicSuffix || "—";
  const ageElement = document.getElementById("age");
  ageElement.textContent = result.rdapMeta?.skipped ? "Không áp dụng" : formatDomainAge(result.ageInfo);
  ageElement.title = result.rdapMeta?.skipped
    ? "RDAP không áp dụng cho localhost hoặc mạng riêng"
    : result.ageInfo ? `${result.ageInfo.ageDays} ngày` : "Không xác định";
  document.getElementById("rdapStatus").textContent = result.rdapMeta?.skipped
    ? "Không áp dụng cho mạng cục bộ"
    : result.rdapMeta?.available
      ? (result.rdapMeta.cacheHit ? "Có dữ liệu · cache" : "Có dữ liệu")
      : "Không có dữ liệu";
  const redirects = result.redirectInfo;
  document.getElementById("redirectStatus").textContent = redirects?.isFederatedAuthFlow
    ? `OAuth/SSO ${redirects.providerName || "chính thức"}${redirects.relyingPartyDomain ? ` → ${redirects.relyingPartyDomain}` : ""}`
    : redirects?.hopCount > 1
      ? `${redirects.hopCount - 1} lần · ${redirects.uniqueDomainCount} domain`
      : "Không đáng kể";
  document.getElementById("threatStatus").textContent = result.threatInfo?.isUnsafe
    ? `${result.threatInfo.source}: NGUY HIỂM`
    : result.threatInfo?.skipped
      ? "Không áp dụng cho mạng cục bộ"
      : result.threatInfo?.checked ? `${result.threatInfo.source}: không khớp` : "Chưa cấu hình/không kiểm tra";
  document.getElementById("listStatus").textContent = result.listStatus?.blacklisted ? "Blacklist" : result.listStatus?.whitelisted ? "Whitelist" : "Không có";
  document.getElementById("strictStatus").textContent = result.strictMode ? "Đang bật" : "Đang tắt";
  document.getElementById("modelVersion").textContent = result.risk.model?.version || "Mặc định";
  document.getElementById("modelThreshold").textContent = result.risk.model?.thresholds?.binaryPhishing ?? "—";
  const ml = result.mlInfo || result.risk.model?.urlModel;
  document.getElementById("mlStatus").textContent = ml?.available === false
    ? (ml.skipped ? "Không áp dụng cho mạng cục bộ" : ml.disabled ? "Đang tắt" : "Không khả dụng")
    : (ml?.modelVersion || ml?.version || "Chưa chạy");
  const probability = Number(ml?.probability);
  const rawPercent = Number.isFinite(probability)
    ? Math.round(probability * 1000) / 10
    : null;
  const mlApplied = Number(result.risk?.breakdown?.ml || 0);
  const mlRawPoints = Number(result.risk?.breakdown?.mlRaw || 0);
  const mlReduction = Number(result.risk?.breakdown?.mlReduction || 0);
  const anomalyBand = rawPercent === null
    ? ""
    : rawPercent >= 90
      ? "rất cao"
      : rawPercent >= 75
        ? "cao"
        : rawPercent >= 55
          ? "cần theo dõi"
          : "thấp";
  document.getElementById("mlProbability").textContent = ml?.skipped
    ? "Không áp dụng"
    : rawPercent !== null
      ? `${rawPercent}% · ${anomalyBand}`
      : "—";
  document.getElementById("mlApplied").textContent = ml?.skipped
    ? "0/100 · chỉ kiểm tra hành vi trang"
    : rawPercent !== null
      ? `${mlApplied}/100${mlReduction > 0 ? ` · giảm ${mlReduction} từ ${mlRawPoints}` : ""} · ${result.risk.binaryPrediction === "PHISHING" ? "có bằng chứng nguy hiểm" : "chưa đủ bằng chứng"}`
      : "—";

  const content = result.contentSafety || { available: false, detected: false, score: 0, level: "NONE", categories: [], reasons: [], recommendations: [] };
  const contentBadge = document.getElementById("contentSafetyBadge");
  const gameCommerceOnly = (content.categories || []).length > 0 && (content.categories || []).every(item => item.id === "GAME_COMMERCE");
  contentBadge.textContent = content.disabled
    ? "ĐANG TẮT"
    : content.available ? (gameCommerceOnly ? "GIAO DỊCH GAME CẦN XÁC MINH" : contentLabel(content.level)) : "CHƯA QUÉT ĐƯỢC";
  contentBadge.className = `pill ${content.available ? (gameCommerceOnly ? "suspicious" : contentClass(content.level)) : "suspicious"}`;
  document.getElementById("contentSafetyScore").textContent = `${content.score || 0}/100`;
  document.getElementById("contentSafetyFill").style.cssText = `width:${content.score || 0}%;background:${gameCommerceOnly ? "#F59E0B" : contentColor(content.level)}`;
  document.getElementById("contentSafetyAvailability").textContent = content.disabled
    ? "Đang tắt"
    : content.available ? "Đã quét" : "Chưa quét được";
  document.getElementById("contentCategoryChips").innerHTML = !content.available
    ? '<span class="chip warn">Chưa thu thập được tín hiệu nội dung trang</span>'
    : (content.categories || []).length
      ? content.categories.map(item => `<span class="chip content">${escapeHtml(item.icon || "⚑")} ${escapeHtml(item.label)} · ${item.score}</span>`).join("")
      : '<span class="chip">Đã quét — chưa phát hiện danh mục hạn chế rõ ràng</span>';
  renderList("contentSafetyReasons", content.reasons, content.available ? "Không phát hiện tín hiệu nội dung đáng chú ý." : "Chưa quét được nội dung trang; hãy tải lại tab và bấm Quét lại.");
  renderList("contentSafetyRecommendations", content.recommendations, "Tiếp tục thận trọng khi cung cấp dữ liệu hoặc thanh toán.");
  document.getElementById("contentSafetyDisclaimer").textContent = content.disclaimer || "Chỉ báo kỹ thuật, không phải kết luận pháp lý.";

  document.getElementById("strictBtn").textContent = result.strictMode ? "Tắt hạn chế" : "Chế độ hạn chế";

  const flags = [];
  const identityCode = result.risk.identityStatus?.code;
  if (["LOCAL_DEVELOPMENT", "PRIVATE_NETWORK", "KNOWN_DOMAIN", "OFFICIAL_SUFFIX", "ESTABLISHED_DOMAIN", "MODERATELY_ESTABLISHED"].includes(identityCode)) {
    flags.push({ text: result.risk.identityStatus.label, kind: "safe" });
  } else if (["BLACKLISTED", "NEW_DOMAIN"].includes(identityCode)) {
    flags.push({ text: result.risk.identityStatus.label, kind: "warn" });
  }
  if (result.homoglyphInfo?.isPunycode) flags.push({ text: "Punycode/IDN", kind: "warn" });
  if (result.homoglyphInfo?.hasHomoglyph) flags.push({ text: "Homoglyph", kind: "warn" });
  if (result.typoMatch) flags.push({ text: `Typosquat: ${result.typoMatch.closest}`, kind: "warn" });
  if (redirects?.isFederatedAuthFlow) {
    flags.push({
      text: `OAuth/SSO ${redirects.providerName || "chính thức"}${redirects.relyingPartyDomain ? ` → ${redirects.relyingPartyDomain}` : ""}`,
      kind: "safe"
    });
  } else if (redirects?.crossDomainCount > 0) {
    flags.push({ text: "Đổi domain khi redirect", kind: "warn" });
  }
  if (redirects?.httpsDowngrade) flags.push({ text: "HTTPS → HTTP", kind: "warn" });
  if (assessment.paymentEvidenceEligible) {
    flags.push({ text: "Tích hợp thanh toán quan sát được · không phải xác thực", kind: "safe" });
  }
  document.getElementById("flagRow").innerHTML = flags.map(item => {
    const value = typeof item === "string" ? { text: item, kind: "warn" } : item;
    return `<span class="chip ${value.kind === "safe" ? "safe" : "warn"}">${escapeHtml(value.text)}</span>`;
  }).join("") || '<span class="chip">Không có chỉ báo đặc biệt</span>';
  renderEvidenceCoverage(result);
  renderBreakdown(result);
  renderList("reasons", result.risk.reasons, "Không phát hiện dấu hiệu rủi ro rõ ràng.");
  renderList(
    "recommendations",
    [...new Set([assessment.recommendedAction, ...(result.risk.recommendations || [])])],
    "Tiếp tục thận trọng."
  );
}


function redactUrl(rawUrl) {
  try {
    const url = new URL(rawUrl);
    for (const key of [...url.searchParams.keys()]) url.searchParams.set(key, "<redacted>");
    url.hash = url.hash ? "#<redacted>" : "";
    return url.href;
  } catch {
    return String(rawUrl || "");
  }
}

function buildDebugReport() {
  if (!currentResult) return null;
  const clone = structuredClone(currentResult);
  clone.url = redactUrl(clone.url);
  if (clone.redirectInfo) {
    clone.redirectInfo.initialUrl = redactUrl(clone.redirectInfo.initialUrl);
    clone.redirectInfo.finalUrl = redactUrl(clone.redirectInfo.finalUrl);
    clone.redirectInfo.urls = (clone.redirectInfo.urls || []).map(redactUrl);
  }
  if (clone.pageSignals?.pageUrl) clone.pageSignals.pageUrl = redactUrl(clone.pageSignals.pageUrl);
  return {
    exportedAt: new Date().toISOString(),
    extension: "DNS Phishing Guard",
    extensionVersion: "2.7.5",
    privacyNote: "Giá trị query và fragment đã được che trước khi xuất.",
    result: clone
  };
}

function downloadJson(filename, value) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

function setupStatusActions() {
  document.getElementById("recheckBtn").addEventListener("click", async () => {
    if (!currentTab?.id || !currentTab.url) return;
    const response = await chrome.runtime.sendMessage({ type: "RECHECK_TAB", tabId: currentTab.id, url: currentTab.url });
    if (response?.done) await loadStatus();
  });

  document.getElementById("trustBtn").addEventListener("click", async () => {
    if (!currentResult) return;
    const confirmed = window.confirm(`Chỉ thêm ${currentResult.registrableDomain || currentResult.domain} vào whitelist khi địa chỉ này được tổ chức chính thức cung cấp. Tiếp tục?`);
    if (!confirmed) return;
    const response = await chrome.runtime.sendMessage({ type: "ADD_WHITELIST", domain: currentResult.registrableDomain || currentResult.domain, tabId: currentTab?.id });
    if (response?.requiresParent) openPinModal("unlock", () => document.getElementById("trustBtn").click());
    else await loadStatus();
  });

  document.getElementById("reportBtn").addEventListener("click", async () => {
    if (!currentResult) return;
    await chrome.runtime.sendMessage({ type: "ADD_BLACKLIST", domain: currentResult.domain, tabId: currentTab?.id });
    await loadStatus();
  });

  document.getElementById("falsePositiveBtn")?.addEventListener("click", async event => {
    if (!currentTab?.id || !currentResult?.domain) return;
    const response = await chrome.runtime.sendMessage({
      type: "REPORT_FALSE_POSITIVE",
      tabId: currentTab.id,
      domain: currentResult.domain
    }).catch(() => null);
    event.currentTarget.textContent = response?.done ? "Đã ghi nhận cục bộ" : "Không thể ghi nhận";
    if (response?.done) event.currentTarget.disabled = true;
  });

  document.getElementById("strictBtn").addEventListener("click", async () => {
    if (!currentTab?.id || !currentResult) return;
    const type = currentResult.strictMode ? "DISABLE_STRICT_MODE" : "ENABLE_STRICT_MODE";
    const response = await chrome.runtime.sendMessage({ type, tabId: currentTab.id });
    if (response?.requiresParent) openPinModal("unlock", () => document.getElementById("strictBtn").click());
    else window.close();
  });

  document.getElementById("copyDebugBtn")?.addEventListener("click", async () => {
    const report = buildDebugReport();
    if (!report) return;
    const button = document.getElementById("copyDebugBtn");
    try {
      await navigator.clipboard.writeText(JSON.stringify(report, null, 2));
      button.textContent = "Đã sao chép";
    } catch {
      button.textContent = "Không thể sao chép";
    }
    setTimeout(() => { button.textContent = "Sao chép chẩn đoán"; }, 1400);
  });

  document.getElementById("exportDebugBtn")?.addEventListener("click", () => {
    const report = buildDebugReport();
    if (!report) return;
    const domain = String(currentResult?.domain || "unknown").replace(/[^a-z0-9.-]/gi, "_");
    downloadJson(`dns-phishing-guard-${domain}-${Date.now()}.json`, report);
  });
}

function setLinkLabStatus(message, state = "") {
  const element = document.getElementById("linkLabStatus");
  element.textContent = message;
  element.className = `link-lab-status${state ? ` ${state}` : ""}`;
}

function setSimpleLinkLabStatus(message, state = "") {
  const element = document.getElementById("simpleLinkLabStatus");
  element.textContent = message;
  element.className = `simple-link-status${state ? ` ${state}` : ""}`;
}

function renderSimpleLinkLabResult(result) {
  const verdict = result.verdict || result.risk || {};
  const network = result.network || {};
  const reasons = [
    ...(verdict.reasons || []),
    ...(result.risk?.reasons || []),
    ...(network.downloadRisk?.reasons || [])
  ].slice(0, 3);
  document.getElementById("simpleLinkLabBadge").textContent = riskLabel(verdict.level || "SAFE");
  const preflightAssessment = getEvidenceAssessment(result);
  document.getElementById("simpleLinkLabScore").textContent = preflightAssessment.riskState === "UNDETERMINED"
    ? "—/100"
    : `${verdict.score ?? 0}/100`;
  document.getElementById("simpleLinkLabTitle").textContent = verdict.label || riskSummary(verdict.level || "SAFE");
  document.getElementById("simpleLinkLabTarget").textContent = result.displayFinalUrl || result.domain || "—";
  renderList("simpleLinkLabReasons", reasons, "Chưa thấy tín hiệu rủi ro rõ ràng trong phạm vi quét trước.");
  const preview = document.getElementById("simpleLinkLabPreviewBtn");
  preview.disabled = result.previewAllowed === false;
  preview.textContent = result.previewAllowed === false ? "Safe Preview bị khóa cho link nhạy cảm" : "Mở Safe Preview";
  const container = document.getElementById("simpleLinkLabResult");
  container.classList.remove("hidden");
  requestAnimationFrame(() => {
    container.scrollIntoView({ behavior: "smooth", block: "nearest" });
    container.focus({ preventScroll: true });
  });
}

function renderLinkLabResult(result) {
  const network = result.network || {};
  const signals = network.htmlSignals || {};
  const verdict = result.verdict || result.risk || {};
  const level = verdict.level || "SAFE";
  const badge = document.getElementById("linkLabRiskBadge");
  badge.textContent = riskLabel(level);
  badge.className = `pill ${riskClass(level)}`;
  document.getElementById("linkLabFinalUrl").textContent = result.displayFinalUrl || result.domain || "—";
  document.getElementById("linkLabFinalUrl").title = result.displayFinalUrl || "";
  const preflightAssessment = getEvidenceAssessment(result);
  document.getElementById("linkLabRiskScore").textContent = preflightAssessment.riskState === "UNDETERMINED"
    ? "—/100"
    : `${verdict.score ?? 0}/100`;
  document.getElementById("linkLabConfidence").textContent = `${preflightAssessment.evidenceScore ?? verdict.confidenceScore ?? 0}/100`;
  document.getElementById("linkLabHttp").textContent = network.reachable ? `${network.status || "—"}` : "Không kết nối";
  const redirectSuffix = network.redirectAnomaly?.type === "LOOP"
    ? " · vòng lặp"
    : network.redirectAnomaly?.type === "LIMIT"
      ? " · vượt giới hạn"
      : "";
  document.getElementById("linkLabRedirects").textContent = `${network.redirectCount || 0} lần${redirectSuffix}`;
  document.getElementById("linkLabDownload").textContent = network.downloadRisk?.label || "Chưa xác định";
  document.getElementById("linkLabSignals").textContent = [
    `script ${signals.scriptCount || 0}`,
    `form ${signals.formCount || 0}`,
    `password ${signals.passwordInputCount || 0}`,
    `link tải ${signals.riskyDownloadLinkCount || 0}`
  ].join(" · ");

  const reasons = [
    ...(network.error ? [`Probe mạng: ${network.error}`] : []),
    ...(verdict.reasons || []),
    ...(result.risk?.reasons || []),
    ...(network.downloadRisk?.reasons || [])
  ].slice(0, 5);
  renderList("linkLabReasons", reasons, "Chưa thấy tín hiệu rủi ro rõ ràng trong phạm vi quét trước.");
  const resultElement = document.getElementById("linkLabResult");
  resultElement.classList.remove("hidden");
  resultElement.tabIndex = -1;
  const preview = document.getElementById("linkLabPreviewBtn");
  preview.disabled = result.previewAllowed === false;
  preview.textContent = result.previewAllowed === false ? "Safe Preview bị khóa cho link nhạy cảm" : "Mở Safe Preview";
  renderSimpleLinkLabResult(result);
  requestAnimationFrame(() => {
    resultElement.scrollIntoView({ behavior: "smooth", block: "nearest" });
    resultElement.focus({ preventScroll: true });
  });
}

async function scanLinkLab(value, scanButton, idleLabel) {
  if (!value) {
    setLinkLabStatus("Hãy nhập một URL cần kiểm tra.", "error");
    setSimpleLinkLabStatus("Hãy nhập một URL cần kiểm tra.", "error");
    return;
  }

  linkLabSessionId = "";
  scanButton.disabled = true;
  scanButton.textContent = "Đang quét…";
  ["linkLabPreviewBtn", "simpleLinkLabPreviewBtn"].forEach(id => {
    document.getElementById(id).disabled = true;
  });
  document.getElementById("linkLabResult").classList.add("hidden");
  document.getElementById("simpleLinkLabResult").classList.add("hidden");
  setLinkLabStatus("Đang quét tĩnh và đọc phản hồi giới hạn; không chạy mã trang…", "scanning");
  setSimpleLinkLabStatus("Đang kiểm tra mà không chạy mã trang…", "scanning");

  try {
    const response = await chrome.runtime.sendMessage({ type: "ANALYZE_URL_PREFLIGHT", url: value });
    if (!response?.done || !response.result) throw new Error(response?.error || "Không thể kiểm tra URL.");
    linkLabSessionId = response.sessionId || "";
    renderLinkLabResult(response.result);
    const network = response.result.network || {};
    const message = network.probeSkipped
      ? "Đã phân tích URL nhưng không kết nối vì link có thể chứa token hoặc hành động dùng một lần."
      : `Đã quét xong · đọc ${Math.round((network.bytesInspected || 0) / 1024)} KiB · không gửi cookie hoặc thông tin đăng nhập.`;
    setLinkLabStatus(message);
    setSimpleLinkLabStatus(message);
  } catch (error) {
    const message = error.message || "Không thể kiểm tra URL.";
    setLinkLabStatus(message, "error");
    setSimpleLinkLabStatus(message, "error");
  } finally {
    scanButton.disabled = false;
    scanButton.textContent = idleLabel;
  }
}

async function openLinkLabPreview(button) {
  if (!linkLabSessionId) return;
  button.disabled = true;
  button.textContent = "Đang mở…";
  const response = await chrome.runtime.sendMessage({
    type: "OPEN_SAFE_PREVIEW",
    sessionId: linkLabSessionId
  }).catch(() => null);
  if (response?.done) window.close();
  else {
    button.disabled = false;
    button.textContent = "Mở Safe Preview";
    const message = response?.error || "Không thể mở Safe Preview.";
    setLinkLabStatus(message, "error");
    setSimpleLinkLabStatus(message, "error");
  }
}

function setupLinkLab() {
  document.getElementById("linkLabForm").addEventListener("submit", event => {
    event.preventDefault();
    scanLinkLab(document.getElementById("linkLabInput").value.trim(), document.getElementById("linkLabScanBtn"), "Quét trước");
  });
  document.getElementById("simpleLinkLabForm").addEventListener("submit", event => {
    event.preventDefault();
    scanLinkLab(document.getElementById("simpleLinkLabInput").value.trim(), document.getElementById("simpleLinkLabScanBtn"), "Kiểm tra link");
  });
  document.getElementById("linkLabPreviewBtn").addEventListener("click", event => openLinkLabPreview(event.currentTarget));
  document.getElementById("simpleLinkLabPreviewBtn").addEventListener("click", event => openLinkLabPreview(event.currentTarget));
}

async function renderHistory() {
  const history = await getHistory();
  const element = document.getElementById("historyList");
  if (!history.length) {
    element.innerHTML = '<div class="empty">Chưa có cảnh báo nào.</div>';
    return;
  }
  element.innerHTML = history.slice(0, 100).map(item => `
    <div class="history-item">
      <div class="head"><b>${escapeHtml(item.domain)}</b><span class="pill ${riskClass(item.level)}">${item.score}</span></div>
      <div class="small">Chất lượng bằng chứng ${item.confidenceScore ?? "—"}/100 · ${escapeHtml(item.confidenceLevel || "")}</div>
      ${(item.contentCategories || []).length ? `<div class="small">Nội dung: ${escapeHtml(item.contentCategories.join(", "))} · ${item.contentSafetyScore || 0}/100</div>` : ""}
      <div class="time">${formatTime(item.checkedAt)}</div>
    </div>`).join("");
}

function setupHistoryActions() {
  document.getElementById("clearHistoryBtn").addEventListener("click", async () => {
    await clearHistory();
    await renderHistory();
  });
  document.getElementById("exportCsvBtn").addEventListener("click", async () => {
    const csv = historyToCSV(await getHistory());
    const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `dns-phishing-guard-history-${Date.now()}.csv`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  });
}

async function renderStats() {
  const data = await chrome.storage.local.get("scan_stats");
  const stats = data.scan_stats || {};
  const total = stats.totalScans || 0;
  document.getElementById("statsGrid").innerHTML = [
    ["Tổng lượt quét", total, ""],
    ["Không phát hiện phishing", stats.safe || 0, "safe"],
    ["Cần kiểm tra", stats.suspicious || 0, "suspicious"],
    ["Cảnh báo", stats.medium || 0, "medium"],
    ["Nguy hiểm", stats.high || 0, "high"],
    ["Cảnh báo nội dung", stats.contentWarnings || 0, "suspicious"],
    ["Mã trả trước cần xác minh", stats.scamCommerceWarnings || 0, "medium"],
    ["Giao dịch game bên thứ ba", stats.gameCommerceWarnings || 0, "suspicious"],
    ["Cờ bạc/cá cược", stats.gamblingWarnings || 0, "suspicious"],
    ["Dữ liệu cá nhân", stats.personalDataWarnings || 0, "medium"],
    ["Cảnh báo đã hiển thị", stats.warningsShown || 0, "medium"],
    ["Lượt chặn blacklist", stats.blocks || 0, "high"],
    ["Lượt vượt cảnh báo", stats.bypasses || 0, "suspicious"],
    ["Phản hồi báo nhầm", stats.falsePositiveReports || 0, ""]
  ].map(([label, value, cls]) => `<div class="stat"><span>${label}</span><b class="${cls}">${value}</b></div>`).join("");
  const rdapTotal = (stats.rdapAvailable || 0) + (stats.rdapUnavailable || 0);
  document.getElementById("rdapRate").textContent = percent(stats.rdapAvailable || 0, rdapTotal);
  document.getElementById("rdapCacheRate").textContent = percent(stats.rdapCacheHits || 0, total);
  document.getElementById("resultCacheRate").textContent = percent(stats.resultCacheHits || 0, total);
  document.getElementById("dynamicScans").textContent = stats.dynamicRescans || 0;
  document.getElementById("scanAverage").textContent = `${Math.round(stats.scanAverageMs || 0)} ms`;
  document.getElementById("scanP95").textContent = `${Math.round(stats.scanP95Ms || 0)} ms`;
  document.getElementById("lastScan").textContent = formatTime(stats.lastScanAt);
}

function setupStatsActions() {
  document.getElementById("clearCacheBtn").addEventListener("click", async () => {
    const response = await chrome.runtime.sendMessage({ type: "CLEAR_ANALYSIS_CACHE" });
    const button = document.getElementById("clearCacheBtn");
    button.textContent = `Đã xóa ${response?.removed || 0} mục`;
    setTimeout(() => { button.textContent = "Xóa cache"; }, 1500);
  });
  document.getElementById("clearStatsBtn").addEventListener("click", async () => {
    await chrome.storage.local.set({ scan_stats: {} });
    await renderStats();
  });
}

function auditLevelClass(level) {
  if (level === "CAO") return "high";
  if (level === "TRUNG BÌNH") return "medium";
  return "safe";
}

async function renderAudit() {
  const result = await getExtensionAudit();
  const list = document.getElementById("auditList");
  if (!result.granted) {
    list.innerHTML = '<div class="empty">Chưa được cấp quyền management.</div>';
    return;
  }
  if (!result.items.length) {
    list.innerHTML = '<div class="empty">Không tìm thấy tiện ích khác.</div>';
    return;
  }
  list.innerHTML = result.items.map(item => `
    <div class="audit-item">
      <div class="head"><b>${escapeHtml(item.name)}</b><span class="pill ${auditLevelClass(item.level)}">${item.score}/100</span></div>
      <div class="small">Mức quyền: ${item.level} · ${item.enabled ? "Đang bật" : "Đang tắt"}</div>
      <ul class="audit-reasons">${(item.reasons.length ? item.reasons : ["Không có quyền nhạy cảm nổi bật"]).slice(0, 5).map(reason => `<li>${escapeHtml(reason)}</li>`).join("")}</ul>
      <div class="actions"><button class="action audit-toggle" data-id="${item.id}" data-enabled="${item.enabled}">${item.enabled ? "Tắt tiện ích" : "Bật tiện ích"}</button></div>
    </div>`).join("");
  list.querySelectorAll(".audit-toggle").forEach(button => {
    button.addEventListener("click", async () => {
      try {
        await setExtensionEnabled(button.dataset.id, button.dataset.enabled !== "true");
        await renderAudit();
      } catch (error) {
        button.textContent = `Không thể: ${error.message}`;
      }
    });
  });
}

function setupAudit() {
  document.getElementById("auditBtn").addEventListener("click", async () => {
    const granted = await requestManagementPermission().catch(() => false);
    if (granted) await renderAudit();
    else document.getElementById("auditList").innerHTML = '<div class="empty">Bạn chưa cấp quyền management.</div>';
  });
  document.getElementById("openExtensionsBtn").addEventListener("click", async () => {
    await chrome.tabs.create({ url: "chrome://extensions/" }).catch(() => {});
  });
}

function renderListChips(elementId, items, storageKey) {
  const element = document.getElementById(elementId);
  element.innerHTML = items.length
    ? items.map(domain => `<span class="list-chip">${escapeHtml(domain)}<button data-domain="${escapeHtml(domain)}" data-key="${storageKey}">✕</button></span>`).join("")
    : '<span class="small">Chưa có domain nào</span>';
  element.querySelectorAll("button[data-domain]").forEach(button => {
    button.addEventListener("click", async () => {
      const data = await chrome.storage.local.get(button.dataset.key);
      const next = (data[button.dataset.key] || []).filter(item => item !== button.dataset.domain);
      await chrome.storage.local.set({ [button.dataset.key]: next });
      await renderSettings();
    });
  });
}

async function renderSettings() {
  const settings = await getSettings();
  await fetchParentState();
  document.querySelectorAll(".switch[data-setting]").forEach(button => {
    button.classList.toggle("on", Boolean(settings[button.dataset.setting]));
  });
  document.getElementById("childModeSwitch").classList.toggle("on", settings.childMode);
  const protectionSelect = document.getElementById("childProtectionLevel");
  if (protectionSelect) protectionSelect.value = settings.childProtectionLevel || "strict";
  const uiProfileSelect = document.getElementById("uiProfileSelect");
  if (uiProfileSelect) uiProfileSelect.value = settings.uiProfile === "technical" ? "technical" : "simple";
  const uiLanguageSelect = document.getElementById("uiLanguageSelect");
  if (uiLanguageSelect) uiLanguageSelect.value = uiLanguage;
  document.getElementById("threatIntelEndpoint").value = settings.threatIntelEndpoint || "";
  let text = parentState.configured ? "PIN đã được thiết lập." : "Chưa có PIN phụ huynh.";
  if (parentState.unlocked) text += ` Đang mở khóa đến ${new Date(parentState.unlockedUntil).toLocaleTimeString("vi-VN", { hour: "2-digit", minute: "2-digit" })}.`;
  else if (parentState.configured) text += " Hiện đang khóa.";
  document.getElementById("parentStateText").textContent = text;
  document.getElementById("lockParentBtn").disabled = !parentState.unlocked;
  document.getElementById("removePinBtn").disabled = !parentState.configured;
  const stored = await chrome.storage.local.get(["customWhitelist", "customBlacklist"]);
  renderListChips("whitelistChips", stored.customWhitelist || [], "customWhitelist");
  renderListChips("blacklistChips", stored.customBlacklist || [], "customBlacklist");
}

function openPinModal(mode, successAction = null) {
  pinMode = mode;
  pinSuccessAction = successAction;
  const modal = document.getElementById("pinModal");
  const confirm = document.getElementById("pinConfirmInput");
  document.getElementById("pinInput").value = "";
  confirm.value = "";
  document.getElementById("pinError").textContent = "";
  confirm.classList.toggle("hidden", mode === "unlock");
  document.getElementById("pinTitle").textContent = mode === "unlock" ? "Dành cho người lớn" : mode === "change" ? "Đổi PIN phụ huynh" : "Tạo PIN phụ huynh";
  document.getElementById("pinDescription").textContent = mode === "unlock" ? "Nhập PIN để mở phần nâng cao trong 10 phút." : "Tạo mã gồm 4–8 chữ số.";
  modal.classList.remove("hidden");
  setTimeout(() => document.getElementById("pinInput").focus(), 20);
}

function closePinModal() {
  document.getElementById("pinModal").classList.add("hidden");
  pinSuccessAction = null;
}

async function submitPin() {
  const pin = document.getElementById("pinInput").value;
  const confirmPin = document.getElementById("pinConfirmInput").value;
  const error = document.getElementById("pinError");
  if (!/^\d{4,8}$/.test(pin)) {
    error.textContent = "PIN phải gồm 4–8 chữ số.";
    return;
  }
  if (pinMode !== "unlock" && pin !== confirmPin) {
    error.textContent = "Hai lần nhập PIN chưa giống nhau.";
    return;
  }
  const response = pinMode === "unlock"
    ? await chrome.runtime.sendMessage({ type: "VERIFY_PARENT_PIN", pin, minutes: 10 })
    : await chrome.runtime.sendMessage({ type: "SET_PARENT_PIN", pin, enableChildMode: pinMode === "setup" });
  if (!response?.done) {
    error.textContent = response?.error || "Không thể thực hiện.";
    return;
  }
  const action = pinSuccessAction;
  closePinModal();
  await fetchParentState();
  if (action) await action();
  await renderShellMode();
  await renderSettings();
}

function setupPinModal() {
  document.getElementById("pinCancelBtn").addEventListener("click", closePinModal);
  document.getElementById("pinSubmitBtn").addEventListener("click", submitPin);
  ["pinInput", "pinConfirmInput"].forEach(id => document.getElementById(id).addEventListener("keydown", event => {
    if (event.key === "Enter") submitPin();
  }));
}

function setupSettings() {
  document.querySelectorAll(".switch[data-setting]").forEach(button => {
    button.addEventListener("click", async () => {
      const key = button.dataset.setting;
      const settings = await getSettings();
      await chrome.storage.local.set({ [key]: !settings[key] });
      await renderSettings();
    });
  });

  document.getElementById("saveThreatEndpointBtn").addEventListener("click", async () => {
    const value = document.getElementById("threatIntelEndpoint").value.trim();
    if (value) {
      try {
        const url = new URL(value);
        if (url.protocol !== "https:" && url.hostname !== "localhost") throw new Error();
      } catch {
        document.getElementById("saveThreatEndpointBtn").textContent = "Endpoint không hợp lệ";
        setTimeout(() => { document.getElementById("saveThreatEndpointBtn").textContent = "Lưu endpoint"; }, 1600);
        return;
      }
    }
    await chrome.storage.local.set({ threatIntelEndpoint: value });
    document.getElementById("saveThreatEndpointBtn").textContent = "Đã lưu";
    setTimeout(() => { document.getElementById("saveThreatEndpointBtn").textContent = "Lưu endpoint"; }, 1200);
  });

  document.getElementById("childProtectionLevel")?.addEventListener("change", async event => {
    await chrome.storage.local.set({ childProtectionLevel: event.target.value });
    await renderSettings();
  });

  document.getElementById("uiProfileSelect")?.addEventListener("change", async event => {
    await chrome.storage.local.set({ uiProfile: event.target.value === "technical" ? "technical" : "simple" });
    await renderShellMode();
  });

  document.getElementById("childModeSwitch").addEventListener("click", async () => {
    const settings = await getSettings();
    await fetchParentState();
    if (!settings.childMode && !parentState.configured) {
      openPinModal("setup", loadStatus);
      return;
    }
    if (settings.childMode && !parentState.unlocked) {
      openPinModal("unlock", async () => {
        await chrome.runtime.sendMessage({ type: "SET_CHILD_MODE", enabled: false });
      });
      return;
    }
    await chrome.runtime.sendMessage({ type: "SET_CHILD_MODE", enabled: !settings.childMode });
    await renderSettings();
    await renderShellMode();
  });

  document.getElementById("changePinBtn").addEventListener("click", async () => {
    await fetchParentState();
    if (parentState.configured && !parentState.unlocked) openPinModal("unlock", () => openPinModal("change"));
    else openPinModal(parentState.configured ? "change" : "setup");
  });
  document.getElementById("lockParentBtn").addEventListener("click", async () => {
    await chrome.runtime.sendMessage({ type: "LOCK_PARENT" });
    await renderSettings();
    await renderShellMode();
  });
  document.getElementById("removePinBtn").addEventListener("click", async () => {
    await fetchParentState();
    if (!parentState.unlocked) {
      openPinModal("unlock", () => document.getElementById("removePinBtn").click());
      return;
    }
    await chrome.runtime.sendMessage({ type: "CLEAR_PARENT_PIN" });
    await renderSettings();
    await renderShellMode();
  });

  async function addDomain(inputId, type) {
    const input = document.getElementById(inputId);
    const domain = normalizeInputDomain(input.value);
    if (!domain) return;
    const response = await chrome.runtime.sendMessage({ type, domain, tabId: currentTab?.id });
    if (response?.requiresParent) {
      openPinModal("unlock", () => addDomain(inputId, type));
      return;
    }
    input.value = "";
    await renderSettings();
  }
  document.getElementById("whitelistAddBtn").addEventListener("click", () => addDomain("whitelistInput", "ADD_WHITELIST"));
  document.getElementById("blacklistAddBtn").addEventListener("click", () => addDomain("blacklistInput", "ADD_BLACKLIST"));
}

async function init() {
  await setupLanguage();
  setupTabs();
  await setupToggle();
  setupShellModeActions();
  setupChildActions();
  setupSimpleActions();
  setupStatusActions();
  setupLinkLab();
  setupHistoryActions();
  setupStatsActions();
  setupAudit();
  setupSettings();
  setupPinModal();
  await fetchParentState();
  await loadStatus();
  await renderShellMode();
}

init().catch(error => console.error("Popup init error:", error));
