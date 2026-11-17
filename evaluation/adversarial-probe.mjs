import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeFederatedAuthRedirect, isTrustedIdentityProviderUrl } from "../modules/auth-flow.js";
import { analyzeContentSafety, CATEGORY_META } from "../modules/content-safety.js";
import { buildEvidenceAssessment } from "../modules/evidence-coverage.js";
import { auditExtension, PERMISSION_WEIGHTS } from "../modules/extension-audit.js";
import { analyzeHomoglyph } from "../modules/homoglyph.js";
import {
  MAX_RESPONSE_BYTES,
  buildPreflightVerdict,
  classifyDownloadRisk,
  classifySensitiveActionUrl,
  isBlockedLiteralHost,
  summarizeHtml
} from "../modules/link-lab.js";
import { getDomainParts, initializeFromText } from "../modules/public-suffix.js";
import { calculateRisk } from "../modules/risk-engine.js";
import { classifySiteContext } from "../modules/site-context.js";
import { findSimilarDomain } from "../modules/typosquat.js";
import { extractUrlMlFeatures } from "../modules/url-ml-features.js";
import { predictWithModel } from "../modules/url-model.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const reportDir = path.join(root, "evaluation", "results");
const generatedAt = new Date().toISOString();
const OFFLINE_RDAP_NOTE = "ageInfo giả lập offline";
const FIXTURE_SCAN_TIME = "2026-08-10T00:00:00.000Z";

const OUTCOMES = Object.freeze({
  SAFE: "AN_TOAN",
  INSUFFICIENT: "CHUA_DU_DU_LIEU",
  CHECK: "CAN_KIEM_TRA",
  DANGER: "NGUY_HIEM"
});

const CLASSIFICATIONS = Object.freeze({
  PASS: "EXPECTED_PASS",
  COMPENSATED: "HYBRID_COMPENSATED",
  GAP: "REAL_GAP",
  STRUCTURAL: "EXPECTED_STRUCTURAL_LIMITATION"
});

const RISK_RANK = Object.freeze({ SAFE: 0, SUSPICIOUS: 1, MEDIUM: 2, HIGH: 3 });

function cleanPageSignals(overrides = {}) {
  return {
    scannedAt: FIXTURE_SCAN_TIME,
    contentSamples: {},
    ...overrides
  };
}

function fakePaymentIntegration(providers) {
  return {
    detected: true,
    confidence: "STRONG",
    score: 100,
    providers: providers.map(label => ({
      id: label.toUpperCase().replace(/[^A-Z0-9]+/g, "_"),
      label,
      evidence: ["logo-or-text", "provider-resource-domain"]
    })),
    context: {
      paymentContext: true,
      interactiveControlCount: 5,
      hasPaymentAction: true,
      hasAmountOrCurrency: true
    },
    disclaimer: "Fixture logo giả trong luồng thanh toán giả lập."
  };
}

const scamSynonymHtml = `
  <!doctype html>
  <title>Dịch vụ cộng Rbx siêu tốc</title>
  <h1>Bơm xu theo gói, xử lý qua chat</h1>
  <form>
    <input name="chuoi-s-r" placeholder="Chuỗi S/R">
    <input name="code-cao" placeholder="Code cào">
    <button>Chốt đơn với ad</button>
  </form>
  <p>IB ad để nhận hướng dẫn, CK vào TK cá nhân rồi hệ thống cộng xu.</p>
`;

const gameCommerceAbbreviationHtml = `
  <!doctype html>
  <title>Kho nick FPS full đồ</title>
  <h1>Acc clone và nick xịn theo ngân sách</h1>
  <p>Cọc trước, ib ad, ck cá nhân; có hỗ trợ đổi pass sau khi chốt.</p>
  <button>Chốt đơn</button>
`;

const cleanPrefixHtml = "<!doctype html><html><body>" + "A".repeat(MAX_RESPONSE_BYTES + 512);
const hiddenTailHtml = `
  <form action="https://collector.example/submit"><input type="password"></form>
  <a download href="https://files.example/setup.exe">Tải bộ cài</a>
  <script>location.replace("https://next.example/")</script>
  </body></html>
`;

const CASES = [
  {
    id: "benign-threshold-below-new-pattern",
    category: "BENIGN_LEXICAL",
    metricScope: "BENIGN",
    sourceClass: "reserved-benign-pattern",
    url: "https://account-services.example/news/customer-service-alert?return_to=%2Fdashboard",
    ageDays: 1200,
    rationale: "Bài viết hỗ trợ hợp lệ có nhiều token account/service/alert và xác suất ML sát ngưỡng nhưng không có bằng chứng độc lập.",
    expected: {
      security: [
        { field: "uiVerdict", op: "equals", value: OUTCOMES.SAFE, note: "Không được cảnh báo nhầm URL benign sát ngưỡng." },
        { field: "shouldWarnOnPage", op: "equals", value: false, note: "Không hiện cảnh báo on-page chỉ vì lexical ML." }
      ]
    }
  },
  {
    id: "benign-threshold-above-new-pattern",
    category: "BENIGN_LEXICAL",
    metricScope: "BENIGN",
    sourceClass: "reserved-benign-pattern",
    url: "https://client-support.example/signin/support?confirm=profile&alert=notice",
    ageDays: 1200,
    rationale: "URL hỗ trợ giả lập có ML vượt ngưỡng 0.59 nhưng domain lâu năm giả lập và trang sạch phải kích hoạt weak-signal cap.",
    expected: {
      security: [
        { field: "uiVerdict", op: "equals", value: OUTCOMES.SAFE, note: "ML đơn lẻ không được biến thành kết luận phishing." },
        { field: "riskBinaryPrediction", op: "equals", value: "SAFE", note: "Hybrid binary verdict phải giữ SAFE." }
      ]
    }
  },
  {
    id: "benign-mdn-authentication-guide",
    category: "BENIGN_COMPLEX_PATH",
    metricScope: "BENIGN",
    sourceClass: "known-benign-shape",
    url: "https://developer.mozilla.org/en-US/docs/Web/Security/Authentication/login-account-verify-password?redirect_uri=%2Fdocs&token=placeholder&security=guide",
    ageDays: 9000,
    rationale: "Tài liệu kỹ thuật hợp lệ chứa nhiều từ khóa phishing trong path/query.",
    expected: { security: [{ field: "uiVerdict", op: "equals", value: OUTCOMES.SAFE, note: "Tài liệu bảo mật không bị false positive." }] }
  },
  {
    id: "benign-dropbox-account-security",
    category: "BENIGN_COMPLEX_PATH",
    metricScope: "BENIGN",
    sourceClass: "known-benign-shape",
    url: "https://www.dropbox.com/account/security/login?return_to=%2Faccount%2Fbilling&verify=email&token=placeholder",
    ageDays: 9000,
    rationale: "Trang cài đặt tài khoản chính thức với return path và token placeholder.",
    expected: { security: [{ field: "uiVerdict", op: "equals", value: OUTCOMES.SAFE, note: "Domain chính thức phải được bảo vệ khỏi ML lexical over-trigger." }] }
  },
  {
    id: "benign-spotify-password-help",
    category: "BENIGN_COMPLEX_PATH",
    metricScope: "BENIGN",
    sourceClass: "known-benign-shape",
    url: "https://support.spotify.com/us/account_payment_help/account_help/change-or-reset-password/?ref=help&confirm=account",
    ageDays: 6000,
    rationale: "Bài trợ giúp password/payment hợp lệ với path dài chưa có trong complex-legit.",
    expected: { security: [{ field: "uiVerdict", op: "equals", value: OUTCOMES.SAFE, note: "Nội dung trợ giúp chính thức không bị cảnh báo nhầm." }] }
  },
  {
    id: "benign-cloudflare-sso-guide",
    category: "BENIGN_COMPLEX_PATH",
    metricScope: "BENIGN",
    sourceClass: "known-benign-shape",
    url: "https://www.cloudflare.com/learning/access-management/what-is-sso/?utm_source=security-guide&return_to=%2Flearning",
    ageDays: 5000,
    rationale: "Bài viết SSO hợp lệ với tracking/return parameter mới.",
    expected: { security: [{ field: "uiVerdict", op: "equals", value: OUTCOMES.SAFE, note: "Bài viết SSO chính thức phải giữ SAFE." }] }
  },
  {
    id: "benign-fpt-student-return-url",
    category: "BENIGN_COMPLEX_PATH",
    metricScope: "BENIGN",
    sourceClass: "known-benign-shape",
    url: "https://fap.fpt.edu.vn/Default.aspx?tab=account&returnUrl=%2FStudent.aspx%3Fview%3Dsecurity%26confirm%3Dprofile",
    ageDays: 3000,
    rationale: "Cổng giáo dục hợp lệ dùng ASPX và returnUrl lồng nhau.",
    expected: { security: [{ field: "uiVerdict", op: "equals", value: OUTCOMES.SAFE, note: "Official suffix và domain lâu năm phải tránh false positive." }] }
  },
  {
    id: "fake-oauth-untrusted-host",
    category: "AUTH_FLOW",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-threat-pattern",
    url: "https://accounts-login.example/o/oauth2/v2/auth?client_id=sample&redirect_uri=https%3A%2F%2Fclient.example%2Fcallback&response_type=code&scope=openid",
    ageDays: 3,
    pageSignals: cleanPageSignals({
      externalPasswordFormCount: 1,
      passwordInputCount: 1,
      brandMismatch: true,
      brandName: "Google"
    }),
    rationale: "Path OAuth giống Google nhưng host không thuộc allowlist; page behavior cung cấp bằng chứng độc lập.",
    expected: {
      target: [
        { field: "authTrusted", op: "equals", value: false, note: "Không whitelist OAuth chỉ dựa vào path." },
        { field: "federatedAuthFlow", op: "equals", value: false, note: "Không đánh dấu expected auth flow trên host lạ." }
      ],
      security: [{ field: "uiVerdict", op: "equals", value: OUTCOMES.DANGER, note: "Brand mismatch và external password form phải tạo cảnh báo cao." }]
    }
  },
  {
    id: "fake-service-login-safe-shape",
    category: "AUTH_FLOW",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-benign-pattern",
    url: "https://identity-bridge.example/ServiceLogin?continue=%2Fdashboard&scope=profile",
    ageDays: 1200,
    rationale: "Host không phải IdP nhưng path ServiceLogin; chỉ kiểm tra allowlist, không gán độc hại khi thiếu bằng chứng.",
    expected: {
      target: [{ field: "authTrusted", op: "equals", value: false, note: "Host lạ không được nhận là IdP chính thức." }],
      security: [{ field: "uiVerdict", op: "equals", value: OUTCOMES.SAFE, note: "Không biến path OAuth đơn lẻ thành false positive." }]
    }
  },
  {
    id: "public-host-internal-label",
    category: "SITE_CONTEXT",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-benign-pattern",
    url: "https://api.internal-tools.example/v1/account/health?view=security",
    ageDays: 1200,
    rationale: "Hostname công khai chứa internal nhưng không kết thúc bằng suffix nội bộ.",
    expected: {
      target: [
        { field: "siteContext", op: "equals", value: "PUBLIC_WEB", note: "Chuỗi internal trong label không được né public reputation." },
        { field: "mlAvailable", op: "equals", value: true, note: "URL ML vẫn phải chạy cho public host." }
      ],
      security: [{ field: "uiVerdict", op: "equals", value: OUTCOMES.SAFE, note: "Public classification đúng nhưng không cảnh báo nhầm trang sạch." }]
    }
  },
  {
    id: "public-host-local-label",
    category: "SITE_CONTEXT",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-benign-pattern",
    url: "https://local-preview.example/docs/login-flow?ref=developer",
    ageDays: 1200,
    rationale: "Hostname chứa local nhưng TLD không phải .local.",
    expected: {
      target: [{ field: "siteContext", op: "equals", value: "PUBLIC_WEB", note: "Không nhầm public host với localhost/.local." }],
      security: [{ field: "uiVerdict", op: "equals", value: OUTCOMES.SAFE, note: "Giữ SAFE khi trang sạch và domain lâu năm giả lập." }]
    }
  },
  {
    id: "public-host-dev-label",
    category: "SITE_CONTEXT",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-benign-pattern",
    url: "https://dev-portal.example/internal/dashboard?account=demo",
    ageDays: 1200,
    rationale: "Hostname công khai có dev và path internal nhưng vẫn thuộc PUBLIC_WEB.",
    expected: {
      target: [{ field: "siteContext", op: "equals", value: "PUBLIC_WEB", note: "dev trong hostname không làm tắt RDAP/ML." }],
      security: [{ field: "mlAvailable", op: "equals", value: true, note: "Lớp public model vẫn hoạt động." }]
    }
  },
  {
    id: "hybrid-compensates-ml-safe-brand-page",
    category: "HYBRID_COMPENSATION",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-threat-pattern",
    url: "https://customer-help.example/news/customer-service-alert?return_to=%2Fdashboard",
    ageDays: 400,
    pageSignals: cleanPageSignals({
      externalPasswordFormCount: 1,
      passwordInputCount: 1,
      brandMismatch: true,
      brandName: "PayPal",
      hasUrgencyText: true
    }),
    rationale: "URL ML có thể cho SAFE, nhưng brand mismatch và form mật khẩu ngoài origin phải bù lại.",
    expected: {
      target: [{ field: "mlPrediction", op: "equals", value: "PHISHING", note: "Kỳ vọng lý tưởng của lớp URL-only đối với pattern giả danh." }],
      security: [{ field: "uiVerdict", op: "equals", value: OUTCOMES.DANGER, note: "Hybrid phải bắt qua page behavior dù ML bỏ sót." }]
    }
  },
  {
    id: "hybrid-compensates-ml-safe-redirect",
    category: "HYBRID_COMPENSATION",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-threat-pattern",
    url: "https://portal.example/help/article?ref=mail",
    ageDays: 400,
    redirect: {
      initialUrl: "https://start.example/notice",
      intermediateUrls: ["https://notice.example/continue", "https://handoff.example/landing"],
      hasServerRedirect: true,
      hasClientRedirect: true
    },
    rationale: "URL cuối có lexical yếu nhưng chuỗi nhiều domain phải tạo cảnh báo độc lập.",
    expected: {
      target: [{ field: "mlPrediction", op: "equals", value: "PHISHING", note: "Kỳ vọng lý tưởng của URL ML trên chuỗi chuyển hướng bất thường." }],
      security: [{ field: "riskLevel", op: "rankAtLeast", value: "MEDIUM", note: "Network layer phải bù khi ML không phát hiện." }]
    }
  },
  {
    id: "action-token-known-convention-control",
    category: "ACTION_TOKEN",
    metricScope: "CONTROL",
    sourceClass: "reserved-benign-pattern",
    url: "https://service.example/reset-password?token=PLACEHOLDER123",
    ageDays: 1200,
    rationale: "Positive control cho convention reset-password/token đã được liệt kê.",
    expected: {
      target: [{ field: "sensitiveAction", op: "equals", value: true, note: "Classifier phải nhận action token chuẩn." }],
      security: [{ field: "probeWouldSkip", op: "equals", value: true, note: "Link Lab sẽ không gửi request cho action-token URL." }]
    }
  },
  {
    id: "action-token-resume-session-gap",
    category: "ACTION_TOKEN",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-threat-pattern",
    url: "https://service.example/resume-session?grant_ref=PLACEHOLDER123",
    ageDays: 1200,
    rationale: "Kịch bản link đăng nhập một lần dùng tên resume-session/grant_ref chưa nằm trong regex hiện tại.",
    expected: {
      target: [{ field: "sensitiveAction", op: "equals", value: true, note: "Semantics một lần nên được chặn probe." }],
      security: [{ field: "probeWouldSkip", op: "equals", value: true, note: "Không được kết nối tới URL có thể tiêu thụ quyền truy cập một lần." }]
    }
  },
  {
    id: "action-token-finalize-change-gap",
    category: "ACTION_TOKEN",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-threat-pattern",
    url: "https://service.example/finalize-contact-change?proof_ref=PLACEHOLDER123",
    ageDays: 1200,
    rationale: "Kịch bản xác nhận thay đổi thông tin dùng finalize/proof_ref, không trùng keyword hiện có.",
    expected: {
      target: [{ field: "sensitiveAction", op: "equals", value: true, note: "Link có tác động một lần cần được nhận diện theo semantics." }],
      security: [{ field: "probeWouldSkip", op: "equals", value: true, note: "Không probe URL có khả năng hoàn tất thay đổi tài khoản." }]
    }
  },
  {
    id: "typosquat-steam-reserved-suffix",
    category: "TYPOSQUAT_HOMOGLYPH",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-threat-pattern",
    url: "https://steamcommunity.example/community/login",
    ageDays: 5,
    rationale: "Nhãn brand chính xác nhưng đổi sang suffix hiếm không thuộc RISKY_TLDS.",
    expected: {
      target: [{ field: "typoDetected", op: "equals", value: true, note: "findSimilarDomain phải bắt brand-suffix mismatch." }],
      security: [{ field: "riskLevel", op: "rankAtLeast", value: "MEDIUM", note: "Typosquat và tuổi domain phải tạo cảnh báo." }]
    }
  },
  {
    id: "typosquat-paypal-digit-reserved-suffix",
    category: "TYPOSQUAT_HOMOGLYPH",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-threat-pattern",
    url: "https://paypa1.example/account/verify",
    ageDays: 5,
    rationale: "Một ký tự số thay chữ trên suffix không rủi ro; typosquat phải hoạt động độc lập với TLD list.",
    expected: {
      target: [{ field: "typoDetected", op: "equals", value: true, note: "Khoảng cách một ký tự phải được phát hiện." }],
      security: [{ field: "riskLevel", op: "rankAtLeast", value: "MEDIUM", note: "Hybrid phải cảnh báo pattern gần PayPal." }]
    }
  },
  {
    id: "homoglyph-apple-reserved-suffix",
    category: "TYPOSQUAT_HOMOGLYPH",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-threat-pattern",
    url: "https://xn--pple-43d.example/account/verify",
    ageDays: 5,
    rationale: "Punycode giải mã thành ký tự giống Latin trên suffix reserved.",
    expected: {
      target: [
        { field: "punycodeDetected", op: "equals", value: true, note: "Nhận diện xn--." },
        { field: "homoglyphDetected", op: "equals", value: true, note: "Nhận diện ký tự Unicode giống Latin." }
      ],
      security: [{ field: "riskLevel", op: "rankAtLeast", value: "MEDIUM", note: "Punycode/homoglyph phải cảnh báo độc lập với TLD." }]
    }
  },
  {
    id: "fake-game-topup-garena-official-claim",
    category: "GAME_TOPUP_BRAND_IMPERSONATION",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-threat-pattern",
    url: "https://napthee.example/app/32837/buy/0",
    ageDays: 5,
    pageSignals: cleanPageSignals({
      prepaidValueHitCount: 3,
      gameTopupHitCount: 4,
      commerceActionCount: 2,
      prepaidCodeInputCount: 2,
      gameAccountInputCount: 1,
      commerceBrandMismatch: true,
      commerceBrandName: "Garena",
      officialClaim: true,
      officialClaimHitCount: 1,
      officialClaimMismatch: true,
      officialClaimBrandName: "Garena",
      gameTransactionHitCount: 2,
      gameCommerceActionCount: 2,
      gameCommerceBrandMismatch: true,
      gameCommerceOfficialBrand: false,
      gameCommerceOfficialClaimMismatch: true,
      gameCommerceBrandName: "Garena",
      contentSamples: {
        scamCommerce: ["ma the", "so seri", "nap game", "id game"],
        gameCommerce: ["nap tien", "thanh toan"]
      }
    }),
    rationale: "Domain reserved thêm một ký tự vào napthe.vn, tự nhận là đối tác chính thức Garena và thu ID game cùng mã thẻ.",
    expected: {
      target: [
        { field: "typoDetected", op: "equals", value: true, note: "Protected game typo pool phải bắt biến thể napthevn." },
        { field: "contentCategoryIds", op: "includes", value: "SCAM_COMMERCE", note: "Official-claim mismatch với trường mã thẻ phải kích hoạt content safety." }
      ],
      security: [
        { field: "riskLevel", op: "equals", value: "HIGH", note: "Brand claim mismatch nhạy cảm phải đủ mạnh ngay cả khi bỏ qua logo giả." },
        { field: "uiVerdict", op: "equals", value: OUTCOMES.DANGER, note: "Không được trả về trạng thái chưa đủ dữ liệu." }
      ]
    }
  },
  {
    id: "fake-payment-logo-zalopay-digit",
    category: "PAYMENT_BRAND_IMPERSONATION",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-threat-pattern",
    url: "https://zal0pay.example/checkout",
    ageDays: 5,
    pageSignals: cleanPageSignals({ paymentIntegration: fakePaymentIntegration(["ZaloPay", "Visa"]) }),
    rationale: "Domain thay chữ bằng số nhưng chèn logo/cấu trúc ZaloPay hợp lệ giả lập; logo không được giảm rủi ro.",
    expected: {
      target: [
        { field: "typoDetected", op: "equals", value: true, note: "Protected payment typo pool phải bắt zal0pay." },
        { field: "paymentEvidenceBoost", op: "equals", value: 0, note: "Logo giả không được cộng coverage khi Risk không SAFE." }
      ],
      security: [
        { field: "uiVerdict", op: "equals", value: OUTCOMES.DANGER, note: "Typosquat + domain mới vẫn phải là nguy hiểm." },
        { field: "paymentEvidenceEligible", op: "equals", value: false, note: "Payment evidence phải bị khóa." }
      ]
    }
  },
  {
    id: "fake-payment-logo-vietqr-extra-letter",
    category: "PAYMENT_BRAND_IMPERSONATION",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-threat-pattern",
    url: "https://vietqrr.example/pay",
    ageDays: 5,
    pageSignals: cleanPageSignals({ paymentIntegration: fakePaymentIntegration(["VietQR", "NAPAS"]) }),
    rationale: "Domain thêm một ký tự vào VietQR và chèn logo thật giả lập trong checkout.",
    expected: {
      target: [
        { field: "typoDetected", op: "equals", value: true, note: "Protected payment typo pool phải bắt vietqrr." },
        { field: "paymentEvidenceBoost", op: "equals", value: 0, note: "Logo không được bù cho typosquat." }
      ],
      security: [
        { field: "uiVerdict", op: "equals", value: OUTCOMES.DANGER, note: "Verdict vẫn phải nguy hiểm." },
        { field: "paymentEvidenceEligible", op: "equals", value: false, note: "Payment evidence phải bị khóa." }
      ]
    }
  },
  {
    id: "fake-payment-logo-vietcombank-wrong-suffix",
    category: "PAYMENT_BRAND_IMPERSONATION",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-threat-pattern",
    url: "https://vietcombank.example/payment",
    ageDays: 5,
    pageSignals: cleanPageSignals({ paymentIntegration: fakePaymentIntegration(["VietQR", "Visa", "Mastercard"]) }),
    rationale: "Dùng đúng nhãn Vietcombank nhưng đổi suffix và chèn nhiều logo thanh toán.",
    expected: {
      target: [
        { field: "typoDetected", op: "equals", value: true, note: "Brand-suffix mismatch ngân hàng phải bị bắt." },
        { field: "paymentEvidenceBoost", op: "equals", value: 0, note: "Logo Visa/VietQR không được hạ cảnh báo." }
      ],
      security: [
        { field: "uiVerdict", op: "equals", value: OUTCOMES.DANGER, note: "Verdict vẫn phải nguy hiểm." },
        { field: "paymentEvidenceEligible", op: "equals", value: false, note: "Payment evidence phải bị khóa." }
      ]
    }
  },
  {
    id: "fake-payment-logo-momo-digit",
    category: "PAYMENT_BRAND_IMPERSONATION",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-threat-pattern",
    url: "https://m0mo.example/checkout",
    ageDays: 5,
    pageSignals: cleanPageSignals({ paymentIntegration: fakePaymentIntegration(["MoMo", "NAPAS"]) }),
    rationale: "Domain MoMo thay chữ bằng số và chèn logo ví/NAPAS giả lập.",
    expected: {
      target: [
        { field: "typoDetected", op: "equals", value: true, note: "Protected payment typo pool phải bắt m0mo." },
        { field: "paymentEvidenceBoost", op: "equals", value: 0, note: "Logo MoMo không được hạ Risk." }
      ],
      security: [
        { field: "uiVerdict", op: "equals", value: OUTCOMES.DANGER, note: "Verdict vẫn phải nguy hiểm." },
        { field: "paymentEvidenceEligible", op: "equals", value: false, note: "Payment evidence phải bị khóa." }
      ]
    }
  },
  {
    id: "fake-payment-logo-zalopay-homoglyph",
    category: "PAYMENT_BRAND_IMPERSONATION",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-threat-pattern",
    url: "https://xn--zlopay-3nf.example/checkout",
    ageDays: 5,
    pageSignals: cleanPageSignals({ paymentIntegration: fakePaymentIntegration(["ZaloPay", "VietQR"]) }),
    rationale: "Punycode giải mã thành ZaloPay với ký tự Cyrillic giống Latin, đồng thời chèn logo cổng thật.",
    expected: {
      target: [
        { field: "punycodeDetected", op: "equals", value: true, note: "Phải nhận diện Punycode." },
        { field: "homoglyphDetected", op: "equals", value: true, note: "Phải nhận diện homoglyph ZaloPay." },
        { field: "paymentEvidenceBoost", op: "equals", value: 0, note: "Logo giả không được cộng coverage." }
      ],
      security: [
        { field: "uiVerdict", op: "equals", value: OUTCOMES.DANGER, note: "Verdict vẫn phải nguy hiểm." },
        { field: "paymentEvidenceEligible", op: "equals", value: false, note: "Payment evidence phải bị khóa." }
      ]
    }
  },
  {
    id: "scam-commerce-vn-synonyms-established-gap",
    category: "SCAM_COMMERCE",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-threat-pattern",
    mode: "preflight",
    url: "https://rbx-helper.example/order",
    ageDays: 1200,
    html: scamSynonymHtml,
    rationale: "Từ lóng bơm Rbx/code cào/S-R/IB ad/CK TK cá nhân chưa có trong static keyword set.",
    expected: {
      target: [{ field: "contentDetected", op: "equals", value: true, note: "SCAM_COMMERCE nên nhận ra biến thể Việt hóa." }],
      security: [{ field: "uiVerdict", op: "notEquals", value: OUTCOMES.SAFE, note: "Không được trả trạng thái xanh khi pattern giao dịch trả trước bị bỏ sót." }]
    }
  },
  {
    id: "scam-commerce-vn-synonyms-new-domain-compensated",
    category: "SCAM_COMMERCE",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-threat-pattern",
    mode: "preflight",
    url: "https://rbx-fast-order.example/order",
    ageDays: 5,
    html: scamSynonymHtml,
    rationale: "Cùng semantic gap nhưng domain mới phải tạo lớp cảnh báo bù tối thiểu.",
    expected: {
      target: [{ field: "contentDetected", op: "equals", value: true, note: "Keyword layer lý tưởng phải phát hiện nội dung." }],
      security: [{ field: "uiVerdict", op: "notEquals", value: OUTCOMES.SAFE, note: "Domain-age layer phải ngăn greenlight hoàn toàn." }]
    }
  },
  {
    id: "game-commerce-vn-abbreviations-established-gap",
    category: "GAME_COMMERCE",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-threat-pattern",
    mode: "preflight",
    url: "https://fps-stock.example/catalog",
    ageDays: 1200,
    html: gameCommerceAbbreviationHtml,
    rationale: "Acc clone/nick full đồ/cọc/ib ad/ck cá nhân/chốt đơn là cụm phổ biến nhưng chưa có trong rules.",
    expected: {
      target: [{ field: "contentCategoryIds", op: "includes", value: "GAME_COMMERCE", note: "Static content layer nên gắn cảnh báo giao dịch game." }],
      security: [{ field: "uiVerdict", op: "notEquals", value: OUTCOMES.SAFE, note: "Không greenlight giao dịch bên thứ ba khi semantic rõ." }]
    }
  },
  {
    id: "link-lab-clean-prefix-64k-gap",
    category: "LINK_LAB_LIMIT",
    metricScope: "ADVERSARIAL",
    sourceClass: "reserved-threat-pattern",
    mode: "preflight",
    url: "https://long-prefix.example/preview",
    ageDays: 1200,
    fullHtml: cleanPrefixHtml + hiddenTailHtml,
    truncateAt: MAX_RESPONSE_BYTES,
    rationale: "64 KiB đầu sạch, form mật khẩu/download/JS navigation chỉ xuất hiện sau giới hạn đọc.",
    expected: {
      target: [
        { field: "networkTruncated", op: "equals", value: true, note: "Fixture phải tái hiện đúng giới hạn 64 KiB." },
        { field: "fullHtmlHiddenRiskDetected", op: "equals", value: true, note: "Phần bị cắt thực sự chứa tín hiệu rủi ro." }
      ],
      security: [
        { field: "evidenceStatus", op: "notEquals", value: "COMPLETE", note: "Kết quả truncated không nên được coi đủ phạm vi cốt lõi." },
        { field: "uiVerdict", op: "notEquals", value: OUTCOMES.SAFE, note: "Không greenlight khi nội dung chỉ được đọc một phần." }
      ]
    }
  },
  {
    id: "optional-permission-weighting-structural",
    category: "EXTENSION_AUDIT",
    metricScope: "STRUCTURAL",
    kind: "structural",
    structuralType: "optional-permissions",
    rationale: "So sánh cùng quyền management khi đang active và khi chỉ khai báo optional_permissions.",
    expectedLimitation: "chrome.management cung cấp quyền đang có hiệu lực; manifest intent của extension khác không phải lúc nào cũng có trong ExtensionInfo."
  },
  {
    id: "document-idle-client-redirect-race",
    category: "CONTENT_SCRIPT_RACE",
    metricScope: "STRUCTURAL",
    kind: "structural",
    structuralType: "document-idle-race",
    rationale: "Trang chuyển hướng bằng JavaScript trước lịch quét 900 ms có thể không để lại page signals của trang trung gian.",
    expectedLimitation: "webNavigation vẫn ghi nhận client redirect và final URL, nhưng DOM/hành vi trang trung gian không được bảo đảm quan sát."
  }
];

function round(value, digits = 6) {
  return Number(Number(value || 0).toFixed(digits));
}

function ratio(numerator, denominator) {
  return denominator ? numerator / denominator : 0;
}

function percent(value) {
  return `${(Number(value || 0) * 100).toFixed(2)}%`;
}

function sha256(text) {
  return createHash("sha256").update(text).digest("hex");
}

function canonicalUrl(rawUrl) {
  const parsed = new URL(rawUrl);
  parsed.hostname = parsed.hostname.toLowerCase();
  parsed.hash = "";
  const sorted = [...parsed.searchParams.entries()].sort(([leftKey, leftValue], [rightKey, rightValue]) => (
    leftKey.localeCompare(rightKey) || leftValue.localeCompare(rightValue)
  ));
  parsed.search = "";
  for (const [key, value] of sorted) parsed.searchParams.append(key, value);
  return parsed.href;
}

function getPathValue(source, dottedPath) {
  return String(dottedPath || "").split(".").reduce((value, key) => value?.[key], source);
}

function evaluateCheck(actual, check) {
  const value = getPathValue(actual, check.field);
  let passed = false;
  if (check.op === "equals") passed = value === check.value;
  else if (check.op === "notEquals") passed = value !== check.value;
  else if (check.op === "oneOf") passed = check.value.includes(value);
  else if (check.op === "includes") passed = Array.isArray(value) && value.includes(check.value);
  else if (check.op === "greaterThan") passed = Number(value) > Number(check.value);
  else if (check.op === "greaterOrEqual") passed = Number(value) >= Number(check.value);
  else if (check.op === "rankAtLeast") passed = (RISK_RANK[value] ?? -1) >= (RISK_RANK[check.value] ?? Number.MAX_SAFE_INTEGER);
  else throw new Error(`Unsupported expectation operator: ${check.op}`);

  return {
    ...check,
    actual: value,
    passed
  };
}

function makeRedirectInfo(finalUrl, redirect = null) {
  const initialUrl = redirect?.initialUrl || finalUrl;
  const urls = [...new Set([
    initialUrl,
    ...(redirect?.intermediateUrls || []),
    finalUrl
  ])];
  const domains = urls.map(value => getDomainParts(new URL(value).hostname).registrableDomain).filter(Boolean);
  const uniqueDomains = [...new Set(domains)];
  const initialProtocol = new URL(initialUrl).protocol;
  const finalProtocol = new URL(finalUrl).protocol;
  return {
    initialUrl,
    finalUrl,
    urls,
    hopCount: urls.length,
    uniqueDomains,
    uniqueDomainCount: uniqueDomains.length,
    crossDomainCount: Math.max(0, uniqueDomains.length - 1),
    hasServerRedirect: Boolean(redirect?.hasServerRedirect),
    hasClientRedirect: Boolean(redirect?.hasClientRedirect),
    httpsDowngrade: initialProtocol === "https:" && finalProtocol === "http:",
    ...analyzeFederatedAuthRedirect(initialUrl, finalUrl, getDomainParts),
    observedAt: FIXTURE_SCAN_TIME
  };
}

function staticContentSafety(htmlSignals, available = true) {
  const staticContent = htmlSignals?.staticContent || null;
  return {
    available,
    disabled: false,
    detected: Boolean(staticContent?.findings?.length),
    score: Number(staticContent?.score) || 0,
    level: staticContent?.level || "NONE",
    categories: (staticContent?.findings || []).map(item => ({
      ...item,
      label: CATEGORY_META[item.id]?.label || item.id,
      icon: CATEGORY_META[item.id]?.icon || "!",
      reasons: [item.reason].filter(Boolean),
      evidence: staticContent?.samples || []
    })),
    reasons: staticContent?.reasons || [],
    recommendations: [],
    legalIndicators: [],
    scannedAt: FIXTURE_SCAN_TIME,
    disclaimer: "Fixture offline chỉ đọc HTML giới hạn và không chạy JavaScript."
  };
}

function buildOfflineNetwork(caseItem) {
  const fullHtml = caseItem.fullHtml ?? caseItem.html ?? "";
  const inspectedHtml = Number.isFinite(caseItem.truncateAt)
    ? fullHtml.slice(0, caseItem.truncateAt)
    : fullHtml;
  const htmlSignals = summarizeHtml(inspectedHtml, { url: caseItem.url });
  const contentType = "text/html; charset=utf-8";
  const contentDisposition = "";
  const downloadRisk = classifyDownloadRisk({
    url: caseItem.url,
    contentType,
    contentDisposition,
    htmlSignals
  });

  return {
    reachable: true,
    probeSkipped: false,
    previewAllowed: true,
    finalUrl: caseItem.url,
    status: 200,
    ok: true,
    contentType,
    contentLength: fullHtml.length,
    contentDisposition: null,
    redirects: [{ url: caseItem.url, status: 200, location: null }],
    redirectCount: 0,
    redirectAnomaly: null,
    bytesInspected: inspectedHtml.length,
    truncated: inspectedHtml.length < fullHtml.length,
    htmlSignals,
    downloadRisk,
    error: null
  };
}

function determineUiVerdict(effectiveRisk, contentSafety, evidenceAssessment) {
  if (effectiveRisk.level === "HIGH" || contentSafety?.level === "HIGH") return OUTCOMES.DANGER;
  if (evidenceAssessment?.riskState === "UNDETERMINED") return OUTCOMES.INSUFFICIENT;
  if (
    effectiveRisk.level === "MEDIUM" || effectiveRisk.level === "SUSPICIOUS" ||
    ["WARNING", "NOTICE"].includes(contentSafety?.level)
  ) return OUTCOMES.CHECK;
  return OUTCOMES.SAFE;
}

function toThreeStateVerdict(uiVerdict) {
  if (uiVerdict === OUTCOMES.SAFE) return OUTCOMES.SAFE;
  if (uiVerdict === OUTCOMES.DANGER) return OUTCOMES.DANGER;
  return OUTCOMES.INSUFFICIENT;
}

function classifyExecutableCase(caseItem, actual) {
  const targetChecks = (caseItem.expected?.target || []).map(check => evaluateCheck(actual, check));
  const securityDefinitions = [...(caseItem.expected?.security || [])];
  if (caseItem.expectedVerdict) {
    securityDefinitions.push({
      field: "threeStateVerdict",
      op: "equals",
      value: caseItem.expectedVerdict,
      note: "Verdict ba trạng thái phải khớp sourced-test-urls.json."
    });
  }
  const securityChecks = securityDefinitions.map(check => evaluateCheck(actual, check));
  const targetPassed = targetChecks.every(item => item.passed);
  const securityPassed = securityChecks.every(item => item.passed);
  const classification = securityPassed
    ? targetPassed ? CLASSIFICATIONS.PASS : CLASSIFICATIONS.COMPENSATED
    : CLASSIFICATIONS.GAP;

  return {
    classification,
    targetPassed,
    securityPassed,
    targetChecks,
    securityChecks
  };
}

function compactRisk(risk) {
  return {
    score: risk.score,
    level: risk.level,
    binaryPrediction: risk.binaryPrediction,
    confidenceScore: risk.confidenceScore,
    confidenceLevel: risk.confidenceLevel,
    identityStatus: risk.identityStatus,
    presentation: risk.presentation,
    breakdown: risk.breakdown,
    reasons: risk.reasons,
    recommendations: risk.recommendations,
    urlSignals: risk.urlSignals,
    model: risk.model
  };
}

async function runUrlCase(caseItem, resources) {
  const parsed = new URL(caseItem.url);
  const hostname = parsed.hostname.toLowerCase().replace(/^www\./, "");
  const domainInfo = getDomainParts(hostname);
  const registrableDomain = domainInfo.registrableDomain || hostname;
  const siteContext = classifySiteContext(caseItem.url);
  const ageInfo = siteContext.isPublic && Number.isFinite(caseItem.ageDays)
    ? { ageDays: caseItem.ageDays, source: OFFLINE_RDAP_NOTE }
    : null;
  const rdapMeta = siteContext.isPublic
    ? { available: Boolean(ageInfo), skipped: false, cacheHit: false, source: OFFLINE_RDAP_NOTE }
    : { available: false, skipped: true, cacheHit: false, source: OFFLINE_RDAP_NOTE, skipReason: "non-public-site-context" };
  const mlInfo = siteContext.isPublic
    ? predictWithModel(resources.model, caseItem.url, domainInfo)
    : { available: false, skipped: true, disabled: false, probability: 0, prediction: "NOT_APPLICABLE", reason: "non-public-site-context" };
  const mlFeatures = siteContext.isPublic ? extractUrlMlFeatures(caseItem.url, domainInfo) : null;
  const homoglyphInfo = analyzeHomoglyph(registrableDomain);
  const typoMatch = siteContext.isPublic
    ? findSimilarDomain(homoglyphInfo.skeleton, resources.typoReferenceDomains, {
        exactBrandLabels: resources.protectedTyposquatDomains
      })
    : null;
  const isBlacklisted = resources.blacklist.has(hostname) || resources.blacklist.has(registrableDomain);
  const isKnownDomain = siteContext.isPublic && resources.knownDomains.includes(registrableDomain);
  const redirectInfo = makeRedirectInfo(caseItem.url, caseItem.redirect);
  const threatInfo = {
    checked: false,
    skipped: false,
    isUnsafe: false,
    threats: [],
    reason: "offline-policy-no-external-threat-intelligence"
  };
  const network = caseItem.mode === "preflight" ? buildOfflineNetwork(caseItem) : null;
  const pageSignals = caseItem.mode === "preflight" ? null : (caseItem.pageSignals || cleanPageSignals());
  const contentSafety = caseItem.mode === "preflight"
    ? staticContentSafety(network.htmlSignals, true)
    : analyzeContentSafety(pageSignals, { enabled: true });

  const risk = calculateRisk({
    url: caseItem.url,
    domain: hostname,
    domainInfo,
    ageInfo,
    typoMatch,
    homoglyphInfo,
    isBlacklisted,
    isWhitelisted: false,
    isKnownDomain,
    pageSignals,
    redirectInfo,
    threatInfo,
    mlInfo,
    siteContext
  });
  const preflightVerdict = network ? buildPreflightVerdict(risk, network) : null;
  const effectiveRisk = preflightVerdict || risk;
  const evidenceAssessment = buildEvidenceAssessment({
    mode: network ? "preflight" : "live",
    domain: hostname,
    registrableDomain,
    risk: network ? { ...preflightVerdict, identityStatus: risk.identityStatus } : risk,
    contentSafety,
    pageSignals,
    rdapMeta,
    ageInfo,
    mlInfo,
    redirectInfo,
    threatInfo,
    siteContext,
    listStatus: { blacklisted: isBlacklisted, whitelisted: false, knownDomain: isKnownDomain },
    settings: {
      analyzePage: true,
      contentSafetyEnabled: true,
      urlModelEnabled: true,
      redirectAnalysis: true
    },
    network
  });

  const trustedIdentityProvider = isTrustedIdentityProviderUrl(caseItem.url);
  const sensitiveAction = classifySensitiveActionUrl(caseItem.url);
  const fullHtmlSignals = caseItem.fullHtml ? summarizeHtml(caseItem.fullHtml, { url: caseItem.url }) : null;
  const fullHtmlDownloadRisk = fullHtmlSignals ? classifyDownloadRisk({
    url: caseItem.url,
    contentType: "text/html; charset=utf-8",
    contentDisposition: "",
    htmlSignals: fullHtmlSignals
  }) : null;
  const uiVerdict = determineUiVerdict(effectiveRisk, contentSafety, evidenceAssessment);
  const threeStateVerdict = toThreeStateVerdict(uiVerdict);
  const actual = {
    uiVerdict,
    threeStateVerdict,
    siteContext: siteContext.type,
    mlAvailable: Boolean(mlInfo.available),
    mlPrediction: mlInfo.prediction,
    mlProbability: round(mlInfo.probability),
    authTrusted: Boolean(trustedIdentityProvider),
    federatedAuthFlow: Boolean(redirectInfo.isFederatedAuthFlow),
    sensitiveAction: Boolean(sensitiveAction.sensitive),
    probeWouldSkip: Boolean(sensitiveAction.sensitive),
    blockedLiteralHost: isBlockedLiteralHost(parsed.hostname),
    typoDetected: Boolean(typoMatch),
    punycodeDetected: Boolean(homoglyphInfo.isPunycode),
    homoglyphDetected: Boolean(homoglyphInfo.hasHomoglyph),
    contentDetected: Boolean(contentSafety.detected),
    contentCategoryIds: (contentSafety.categories || []).map(item => item.id),
    riskLevel: risk.level,
    riskBinaryPrediction: risk.binaryPrediction,
    shouldWarnOnPage: Boolean(risk.presentation?.shouldWarnOnPage),
    preflightLevel: preflightVerdict?.level || null,
    evidenceStatus: evidenceAssessment.status,
    evidenceRiskState: evidenceAssessment.riskState,
    evidenceScore: evidenceAssessment.evidenceScore,
    paymentEvidenceBoost: evidenceAssessment.paymentEvidenceBoost,
    paymentEvidenceEligible: evidenceAssessment.paymentEvidenceEligible,
    identityStatus: risk.identityStatus?.code || "UNVERIFIED",
    networkTruncated: Boolean(network?.truncated),
    inspectedHtmlRiskDetected: Boolean(
      network?.htmlSignals?.passwordInputCount ||
      network?.htmlSignals?.riskyDownloadLinkCount ||
      network?.htmlSignals?.autoNavigationSignalCount
    ),
    fullHtmlHiddenRiskDetected: Boolean(
      fullHtmlSignals?.passwordInputCount ||
      fullHtmlSignals?.riskyDownloadLinkCount ||
      fullHtmlSignals?.autoNavigationSignalCount
    )
  };
  const evaluation = classifyExecutableCase(caseItem, actual);

  return {
    id: caseItem.id,
    category: caseItem.category,
    sourceCategory: caseItem.sourceCategory,
    source: caseItem.source,
    snapshotDate: caseItem.snapshotDate,
    expectedVerdict: caseItem.expectedVerdict,
    sourceRationale: caseItem.sourceRationale,
    metricScope: caseItem.metricScope,
    sourceClass: caseItem.sourceClass,
    rationale: caseItem.rationale,
    url: caseItem.url,
    domain: hostname,
    registrableDomain,
    ageInfo,
    rdapMeta,
    listStatus: { blacklisted: isBlacklisted, knownDomain: isKnownDomain, whitelisted: false },
    siteContext,
    authFlow: {
      trustedIdentityProvider,
      redirectInfo
    },
    linkLab: {
      sensitiveAction,
      blockedLiteralHost: actual.blockedLiteralHost,
      network,
      preflightVerdict,
      fullHtmlSignals,
      fullHtmlDownloadRisk
    },
    ml: {
      modelVersion: mlInfo.modelVersion || resources.model.modelVersion,
      available: Boolean(mlInfo.available),
      probability: actual.mlProbability,
      prediction: mlInfo.prediction,
      threshold: mlInfo.threshold ?? resources.model.threshold,
      features: mlFeatures?.values || null
    },
    homoglyphInfo,
    typoMatch,
    pageSignals,
    contentSafety,
    risk: compactRisk(risk),
    evidenceAssessment,
    actual,
    evaluation
  };
}

function runStructuralCase(caseItem, resources) {
  if (caseItem.structuralType === "optional-permissions") {
    const base = {
      id: "fixture-extension",
      name: "Offline Fixture Extension",
      enabled: true,
      installType: "development",
      type: "extension",
      hostPermissions: []
    };
    const activeGrant = auditExtension({ ...base, permissions: ["management"] });
    const optionalDeclaration = auditExtension({
      ...base,
      permissions: [],
      optionalPermissions: ["management"]
    });
    return {
      id: caseItem.id,
      category: caseItem.category,
      metricScope: caseItem.metricScope,
      rationale: caseItem.rationale,
      expectedLimitation: caseItem.expectedLimitation,
      result: {
        activeGrantScore: activeGrant.score,
        activeGrantReasons: activeGrant.reasons,
        optionalDeclarationScore: optionalDeclaration.score,
        optionalDeclarationReasons: optionalDeclaration.reasons,
        managementWeight: PERMISSION_WEIGHTS.management,
        observation: "auditExtension chấm quyền đang có hiệu lực; optionalPermissions không phải input được module sử dụng."
      },
      evaluation: {
        classification: CLASSIFICATIONS.STRUCTURAL,
        targetPassed: true,
        securityPassed: true,
        targetChecks: [],
        securityChecks: []
      }
    };
  }

  const contentScript = resources.manifest.content_scripts?.[0] || {};
  const scanDelayMatch = resources.contentSource.match(/schedulePageScan\((\d+)\);\s*\}\)\(\);\s*$/m);
  return {
    id: caseItem.id,
    category: caseItem.category,
    metricScope: caseItem.metricScope,
    rationale: caseItem.rationale,
    expectedLimitation: caseItem.expectedLimitation,
    result: {
      runAt: contentScript.run_at || "document_idle",
      initialScanDelayMs: scanDelayMatch ? Number(scanDelayMatch[1]) : null,
      navigationCapturePresent: /chrome\.webNavigation\.onBeforeNavigate/.test(resources.backgroundSource) &&
        /chrome\.webNavigation\.onCommitted/.test(resources.backgroundSource),
      finalTabAnalysisPresent: /chrome\.tabs\.onUpdated/.test(resources.backgroundSource),
      intermediateDomCaptureGuaranteed: false,
      observation: "Navigation metadata có lớp bù, nhưng DOM trước redirect có thể biến mất trước lần collectPageSignals đầu tiên."
    },
    evaluation: {
      classification: CLASSIFICATIONS.STRUCTURAL,
      targetPassed: true,
      securityPassed: true,
      targetChecks: [],
      securityChecks: []
    }
  };
}

function summarizeClassifications(rows) {
  const counts = Object.fromEntries(Object.values(CLASSIFICATIONS).map(value => [value, 0]));
  for (const row of rows) counts[row.evaluation.classification] += 1;
  return counts;
}

function buildPersonaEvaluation(summary, rows) {
  const hasTruncationGap = rows.some(row => row.id === "link-lab-clean-prefix-64k-gap" && row.evaluation.classification === CLASSIFICATIONS.GAP);
  const actionGaps = rows.filter(row => row.category === "ACTION_TOKEN" && row.evaluation.classification === CLASSIFICATIONS.GAP).length;
  const benignFailures = rows.filter(row => row.metricScope === "BENIGN" && row.evaluation.classification !== CLASSIFICATIONS.PASS).length;

  const personas = [
    {
      id: "PENTESTER",
      label: "Pentester / security researcher",
      behavior: "Mở Signal Observatory, so ML raw với từng bucket, thử Link Lab bằng fixture reserved và kiểm tra lớp nào tạo hoặc triệt tiêu verdict.",
      scores: [
        { criterion: "Kháng bypass nhiều lớp", score: summary.realGaps <= 3 ? 4 : 3, severity: "CAO", note: "Auth allowlist, site context và typosquat hoạt động; vẫn còn semantic gap ở action-token/content." },
        { criterion: "An toàn Link Lab", score: hasTruncationGap ? 3 : 4, severity: "CAO", note: "Không chạy JS/cookie/form, nhưng truncated 64 KiB chưa hạ coverage." },
        { criterion: "Minh bạch bằng chứng", score: 4, severity: "TRUNG BÌNH", note: "Có bucket, ML contribution, evidence coverage và reason riêng." },
        { criterion: "Extension Audit", score: 3, severity: "TRUNG BÌNH", note: "Chấm active grants tốt hơn manifest intent; optional declaration là giới hạn dữ liệu." },
        { criterion: "Khả năng tái lập", score: 5, severity: "THẤP", note: "Probe offline, deterministic, JSON + Markdown và không gọi mạng." }
      ]
    },
    {
      id: "GENERAL_USER",
      label: "Người dùng phổ thông có hiểu biết CNTT cơ bản",
      behavior: "Dán link vào Link Lab, đọc verdict đơn giản trước, rồi mở chi tiết khi cần biết vì sao ML và domain-age khác nhau.",
      scores: [
        { criterion: "Tránh cảnh báo nhầm", score: benignFailures === 0 ? 5 : 3, severity: "CAO", note: `${rows.filter(row => row.metricScope === "BENIGN").length - benignFailures}/${rows.filter(row => row.metricScope === "BENIGN").length} hard-negative mới đạt kỳ vọng.` },
        { criterion: "Hiểu CHƯA ĐỦ DỮ LIỆU", score: 4, severity: "CAO", note: `${percent(summary.insufficientVerdictRate)} case thực thi quy về trạng thái chưa đủ dữ liệu; RiskState tách UNDETERMINED khỏi score xanh.` },
        { criterion: "Quy trình check nhanh", score: 4, severity: "TRUNG BÌNH", note: "Một ô dán link, verdict và hành động chính; phần kỹ thuật nằm sau." },
        { criterion: "Ma sát khi bỏ qua cảnh báo", score: 4, severity: "CAO", note: "HIGH yêu cầu gõ đúng domain, giảm bấm nhầm." },
        { criterion: "Ngữ cảnh lừa đảo Việt Nam", score: summary.contentSemanticGaps > 0 ? 3 : 4, severity: "CAO", note: "Cảnh báo hiện có tốt với từ khóa chuẩn nhưng còn thiếu từ lóng/viết tắt." }
      ]
    },
    {
      id: "NON_TECHNICAL_USER",
      label: "Người không rành kỹ thuật / phụ huynh",
      behavior: "Chỉ nhìn Simple UI hoặc Child Mode, nghe hướng dẫn, quay lại trang an toàn và nhờ người lớn thay vì tự đọc bucket kỹ thuật.",
      scores: [
        { criterion: "Ngôn ngữ đời thường", score: 4, severity: "CAO", note: "Simple UI tránh RDAP/entropy; lý do được rút gọn." },
        { criterion: "Child Mode và focus lock", score: 4, severity: "CAO", note: "Có inert, focus trap, PIN và hành động quay lại rõ ràng." },
        { criterion: "Không hiểu nhầm màu amber", score: 4, severity: "CAO", note: "CHƯA ĐỦ DỮ LIỆU ghi rõ không nên coi là an toàn." },
        { criterion: "Giải thích scam-commerce", score: summary.contentSemanticGaps > 0 ? 3 : 4, severity: "CAO", note: "Thông điệp hành động rõ, nhưng coverage từ lóng chưa đủ." },
        { criterion: "Kỳ vọng Safe Preview", score: 3, severity: "TRUNG BÌNH", note: "Có disclaimer về IP/sandbox, nhưng tên gọi vẫn dễ bị hiểu là an toàn tuyệt đối." }
      ]
    }
  ];

  return personas.map(persona => ({
    ...persona,
    averageScore: round(persona.scores.reduce((sum, item) => sum + item.score, 0) / persona.scores.length, 2),
    observedGaps: persona.id === "PENTESTER" ? actionGaps + Number(hasTruncationGap) : undefined
  }));
}

function markdownEscape(value) {
  return String(value ?? "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

function caseRowsMarkdown(rows) {
  return rows.map(row => {
    const risk = row.risk || {};
    const ml = row.ml || {};
    const actual = row.actual || {};
    return `| \`${row.id}\` | ${markdownEscape(row.category)} | ${markdownEscape(row.evaluation.classification)} | ${markdownEscape(actual.uiVerdict || "N/A")} | ${risk.score ?? "-"} / ${risk.level || "-"} | ${ml.probability ?? "-"} / ${ml.prediction || "-"} |`;
  }).join("\n");
}

function findingList(rows, fallback) {
  if (!rows.length) return fallback;
  return rows.map(row => {
    const failed = [
      ...(row.evaluation.targetChecks || []),
      ...(row.evaluation.securityChecks || [])
    ].filter(item => !item.passed).map(item => item.note);
    return `- \`${row.id}\`: ${row.rationale}${failed.length ? ` Điểm chưa đạt: ${failed.join(" ")}` : ""}`;
  }).join("\n");
}

function personaMarkdown(personas) {
  return personas.map(persona => `### ${persona.label}

Hành vi mô phỏng: ${persona.behavior}

| Tiêu chí | Điểm /5 | Mức nghiêm trọng | Nhận xét |
| --- | ---: | --- | --- |
${persona.scores.map(item => `| ${markdownEscape(item.criterion)} | ${item.score} | ${item.severity} | ${markdownEscape(item.note)} |`).join("\n")}

Điểm trung bình: **${persona.averageScore}/5**.`).join("\n\n");
}

await fs.mkdir(reportDir, { recursive: true });

const [
  pslText,
  manifestText,
  modelText,
  blacklistText,
  knownDomainsText,
  protectedPaymentText,
  protectedGameText,
  releaseCasesText,
  complexCasesText,
  sourcedCasesText,
  previousResultsText,
  previousReportText,
  falsePositiveFixText,
  experienceReportText,
  backgroundSource,
  contentSource,
  probeSource
] = await Promise.all([
  fs.readFile(path.join(root, "data", "public_suffix_list.dat"), "utf8"),
  fs.readFile(path.join(root, "manifest.json"), "utf8"),
  fs.readFile(path.join(root, "data", "url-model.json"), "utf8"),
  fs.readFile(path.join(root, "data", "blacklist.json"), "utf8"),
  fs.readFile(path.join(root, "data", "known-domains.json"), "utf8"),
  fs.readFile(path.join(root, "data", "protected-payment-domains.json"), "utf8"),
  fs.readFile(path.join(root, "data", "protected-game-domains.json"), "utf8"),
  fs.readFile(path.join(root, "evaluation", "release-regression-cases.json"), "utf8"),
  fs.readFile(path.join(root, "evaluation", "complex-legit-cases.json"), "utf8"),
  fs.readFile(path.join(root, "evaluation", "sourced-test-urls.json"), "utf8"),
  fs.readFile(path.join(reportDir, "evaluation-results.json"), "utf8"),
  fs.readFile(path.join(reportDir, "EVALUATION_REPORT.md"), "utf8"),
  fs.readFile(path.join(root, "FALSE_POSITIVE_FIX.md"), "utf8"),
  fs.readFile(path.join(root, "EXPERIENCE_REPORT_v2.6.0_POST_QA.md"), "utf8"),
  fs.readFile(path.join(root, "background.js"), "utf8"),
  fs.readFile(path.join(root, "content.js"), "utf8"),
  fs.readFile(fileURLToPath(import.meta.url), "utf8")
]);

initializeFromText(pslText);

const forbiddenNetworkPrimitives = [
  { label: "fetch call", regex: /\bfetch\s*\(/ },
  { label: "Node HTTP request", regex: /\bhttps?\.(?:get|request)\s*\(/ },
  { label: "Link Lab network probe", regex: /\bprobeUrlNetwork\s*\(/ }
];
const networkViolations = forbiddenNetworkPrimitives.filter(item => item.regex.test(probeSource));
if (networkViolations.length) {
  throw new Error(`Offline policy violation: ${networkViolations.map(item => item.label).join(", ")}`);
}

const manifest = JSON.parse(manifestText);
const model = JSON.parse(modelText);
const blacklistValues = JSON.parse(blacklistText).map(value => String(value).toLowerCase());
const knownDomains = JSON.parse(knownDomainsText).map(value => String(value).toLowerCase());
const protectedPaymentData = JSON.parse(protectedPaymentText);
const protectedPaymentDomains = (protectedPaymentData.entries || [])
  .map(item => String(item.domain || "").toLowerCase())
  .filter(Boolean);
const protectedGameData = JSON.parse(protectedGameText);
const protectedGameDomains = (protectedGameData.entries || [])
  .map(item => String(item.domain || "").toLowerCase())
  .filter(Boolean);
const protectedTyposquatDomains = [...new Set([...protectedPaymentDomains, ...protectedGameDomains])];
const typoReferenceDomains = [...new Set([...knownDomains, ...protectedTyposquatDomains])];
const releaseCases = JSON.parse(releaseCasesText);
const complexCases = JSON.parse(complexCasesText);
const sourcedCases = JSON.parse(sourcedCasesText);
const previousResults = JSON.parse(previousResultsText);
const allowedSourceCategories = new Set(["phishing", "benign", "malware", "typosquat", "scam-commerce"]);
const invalidSourceRows = sourcedCases.filter(item => (
  !item.id || !item.url || !allowedSourceCategories.has(item.category) ||
  !item.source || !item.snapshotDate || !item.rationale || !item.expectedVerdict
));
if (invalidSourceRows.length) {
  throw new Error(`Invalid sourced-test-urls.json rows: ${invalidSourceRows.map(item => item.id || "missing-id").join(", ")}`);
}

const definedExecutableCases = CASES.filter(item => item.kind !== "structural");
const sourcedById = new Map(sourcedCases.map(item => [item.id, item]));
const definedById = new Map(definedExecutableCases.map(item => [item.id, item]));
const missingSourceRows = definedExecutableCases.filter(item => !sourcedById.has(item.id)).map(item => item.id);
const extraSourceRows = sourcedCases.filter(item => !definedById.has(item.id)).map(item => item.id);
const mismatchedSourceUrls = definedExecutableCases.filter(item => {
  const sourced = sourcedById.get(item.id);
  return sourced && canonicalUrl(sourced.url) !== canonicalUrl(item.url);
}).map(item => item.id);
if (missingSourceRows.length || extraSourceRows.length || mismatchedSourceUrls.length) {
  throw new Error(
    `Source manifest mismatch: missing=${missingSourceRows.join(",")}; extra=${extraSourceRows.join(",")}; url=${mismatchedSourceUrls.join(",")}`
  );
}

const materializedCases = CASES.map(item => {
  if (item.kind === "structural") return item;
  const sourced = sourcedById.get(item.id);
  return {
    ...item,
    sourceCategory: sourced.category,
    source: sourced.source,
    snapshotDate: sourced.snapshotDate,
    expectedVerdict: sourced.expectedVerdict,
    sourceRationale: sourced.rationale
  };
});
const existingIds = new Set([...releaseCases, ...complexCases].map(item => item.id));
const existingUrls = new Set(
  [...releaseCases, ...complexCases]
    .map(item => item.url)
    .filter(Boolean)
    .map(canonicalUrl)
);
const duplicateIds = materializedCases.filter(item => existingIds.has(item.id)).map(item => item.id);
const duplicateUrls = materializedCases.filter(item => item.url && existingUrls.has(canonicalUrl(item.url))).map(item => item.id);
if (duplicateIds.length || duplicateUrls.length) {
  throw new Error(`Adversarial cases duplicate existing evaluation entries: ids=${duplicateIds.join(",")}; urls=${duplicateUrls.join(",")}`);
}

const unsafeRealThreatShapes = materializedCases.filter(item => {
  if (item.sourceClass !== "reserved-threat-pattern" || !item.url) return false;
  const hostname = new URL(item.url).hostname.toLowerCase();
  return !(hostname.endsWith(".example") || hostname.endsWith(".invalid"));
});
if (unsafeRealThreatShapes.length) {
  throw new Error(`Threat-shaped cases must use reserved domains: ${unsafeRealThreatShapes.map(item => item.id).join(", ")}`);
}

const resources = {
  manifest,
  model,
  blacklist: new Set(blacklistValues),
  knownDomains,
  protectedPaymentDomains,
  protectedGameDomains,
  protectedTyposquatDomains,
  typoReferenceDomains,
  backgroundSource,
  contentSource
};

const executableRows = [];
const structuralRows = [];
for (const caseItem of materializedCases) {
  if (caseItem.kind === "structural") structuralRows.push(runStructuralCase(caseItem, resources));
  else executableRows.push(await runUrlCase(caseItem, resources));
}
const rows = [...executableRows, ...structuralRows];
const classificationCounts = summarizeClassifications(rows);
const adversarialRows = executableRows.filter(row => row.metricScope === "ADVERSARIAL");
const benignRows = executableRows.filter(row => row.metricScope === "BENIGN");
const realGapRows = rows.filter(row => row.evaluation.classification === CLASSIFICATIONS.GAP);
const compensatedRows = rows.filter(row => row.evaluation.classification === CLASSIFICATIONS.COMPENSATED);
const passRows = rows.filter(row => row.evaluation.classification === CLASSIFICATIONS.PASS);
const structuralLimitations = rows.filter(row => row.evaluation.classification === CLASSIFICATIONS.STRUCTURAL);
const paymentBrandRows = executableRows.filter(row => row.category === "PAYMENT_BRAND_IMPERSONATION");
const contentSemanticGaps = realGapRows.filter(row => ["SCAM_COMMERCE", "GAME_COMMERCE"].includes(row.category)).length;
const threeStateCounts = executableRows.reduce((counts, row) => {
  const verdict = row.actual.threeStateVerdict;
  counts[verdict] = (counts[verdict] || 0) + 1;
  return counts;
}, { [OUTCOMES.SAFE]: 0, [OUTCOMES.INSUFFICIENT]: 0, [OUTCOMES.DANGER]: 0 });
const gapCategories = realGapRows.reduce((counts, row) => {
  counts[row.category] = (counts[row.category] || 0) + 1;
  return counts;
}, {});

const summary = {
  totalCases: rows.length,
  executableCases: executableRows.length,
  adversarialCases: adversarialRows.length,
  benignCases: benignRows.length,
  structuralCases: structuralRows.length,
  classifications: classificationCounts,
  realGaps: realGapRows.length,
  hybridCompensated: compensatedRows.length,
  expectedPasses: passRows.length,
  contentSemanticGaps,
  paymentBrandCases: paymentBrandRows.length,
  paymentBrandDangerVerdicts: paymentBrandRows.filter(row => row.actual.uiVerdict === OUTCOMES.DANGER).length,
  paymentBrandBoostedThreatCases: paymentBrandRows.filter(row => row.actual.paymentEvidenceBoost > 0).length,
  threeStateCounts,
  gapCategories,
  gapRate: round(ratio(adversarialRows.filter(row => row.evaluation.classification === CLASSIFICATIONS.GAP).length, adversarialRows.length)),
  hybridCompensationRate: round(ratio(adversarialRows.filter(row => row.evaluation.classification === CLASSIFICATIONS.COMPENSATED).length, adversarialRows.length)),
  expectedPassRate: round(ratio(passRows.length, executableRows.length)),
  benignExpectedPassRate: round(ratio(benignRows.filter(row => row.evaluation.classification === CLASSIFICATIONS.PASS).length, benignRows.length)),
  insufficientVerdictRate: round(ratio(threeStateCounts[OUTCOMES.INSUFFICIENT], executableRows.length))
};

const personaEvaluation = buildPersonaEvaluation(summary, rows);
const comparisonDocuments = {
  evaluationResults: {
    file: "evaluation/results/evaluation-results.json",
    sha256: sha256(previousResultsText),
    release: previousResults.release,
    releaseRegressionCases: previousResults.releaseRegression?.cases ?? null,
    complexLegitCases: previousResults.complexLegitRegression?.cases ?? null,
    hybridAccuracy: previousResults.releaseRegression?.hybrid?.accuracy ?? null
  },
  evaluationReport: {
    file: "evaluation/results/EVALUATION_REPORT.md",
    sha256: sha256(previousReportText),
    bytes: Buffer.byteLength(previousReportText)
  },
  falsePositiveFix: {
    file: "FALSE_POSITIVE_FIX.md",
    sha256: sha256(falsePositiveFixText),
    bytes: Buffer.byteLength(falsePositiveFixText)
  },
  experienceReport: {
    file: "EXPERIENCE_REPORT_v2.6.0_POST_QA.md",
    sha256: sha256(experienceReportText),
    bytes: Buffer.byteLength(experienceReportText),
    note: "Báo cáo trải nghiệm gần nhất hiện có trong release v2.7.0."
  }
};

const architectureSummary = {
  verdictLayers: ["threat-intel", "domain/RDAP/PSL", "URL heuristics", "network redirects", "page behavior", "URL ML", "content safety", "evidence coverage"],
  urlModelVersion: model.modelVersion,
  urlModelThreshold: model.threshold,
  urlFeatureCount: model.featureNames?.length || 0,
  hybridThresholds: {
    suspicious: 10,
    medium: 30,
    high: 70,
    binaryPhishing: 30
  },
  existingCoverage: {
    releaseRegression: releaseCases.map(item => item.id),
    complexLegit: complexCases.map(item => item.id)
  }
};

const regressionMergeCandidates = {
  releaseRegressionCases: [
    { id: "probe-fake-oauth-untrusted-host", label: "PHISHING", url: "https://accounts-login.example/o/oauth2/v2/auth?client_id=sample&response_type=code", ageDays: 3 },
    { id: "probe-paypal-digit-typosquat", label: "PHISHING", url: "https://paypa1.example/account/verify", ageDays: 5 },
    { id: "probe-apple-homoglyph-reserved", label: "PHISHING", url: "https://xn--pple-43d.example/account/verify", ageDays: 5 }
  ],
  complexLegitCases: [
    { id: "probe-benign-ml-above-threshold", url: "https://client-support.example/signin/support?confirm=profile&alert=notice", knownDomain: false, ageDays: 1200, context: "PUBLIC_WEB" },
    { id: "probe-benign-mdn-auth-guide", url: "https://developer.mozilla.org/en-US/docs/Web/Security/Authentication/login-account-verify-password?redirect_uri=%2Fdocs&token=placeholder", knownDomain: true, ageDays: 9000, context: "PUBLIC_WEB" },
    { id: "probe-public-internal-label", url: "https://api.internal-tools.example/v1/account/health?view=security", knownDomain: false, ageDays: 1200, context: "PUBLIC_WEB" }
  ],
  releaseTestOnly: [
    "action-token-resume-session-gap",
    "action-token-finalize-change-gap",
    "scam-commerce-vn-synonyms-established-gap",
    "game-commerce-vn-abbreviations-established-gap",
    "link-lab-clean-prefix-64k-gap"
  ]
};

const report = {
  schemaVersion: 1,
  generatedAt,
  release: manifest.version,
  modelVersion: model.modelVersion,
  probeType: "offline-adversarial-headless",
  safetyPolicy: {
    networkRequestsMade: 0,
    networkEnabled: false,
    rdap: OFFLINE_RDAP_NOTE,
    externalThreatIntelligence: "không gọi",
    threatShapedDomains: "chỉ dùng .example/.invalid dành riêng",
    realDomains: "chỉ dùng URL benign đã biết và không truy cập mạng",
    sourcing: "Không thực hiện OpenPhish/URLhaus/ThreatFox/crt.sh/VNNIC/Tranco network collection vì chỉ thị offline/pattern-only của người dùng có ưu tiên cao hơn.",
    exploitPayloads: false,
    credentialCollection: false
  },
  sourceManifest: {
    file: "evaluation/sourced-test-urls.json",
    sha256: sha256(sourcedCasesText),
    cases: sourcedCases.length,
    oneToOneWithExecutableCases: true
  },
  protectedPaymentReferences: {
    file: "data/protected-payment-domains.json",
    sha256: sha256(protectedPaymentText),
    entries: protectedPaymentDomains.length,
    trustAllowlist: protectedPaymentData.trustAllowlist === true
  },
  protectedGameReferences: {
    file: "data/protected-game-domains.json",
    sha256: sha256(protectedGameText),
    entries: protectedGameDomains.length,
    trustAllowlist: protectedGameData.trustAllowlist === true
  },
  architectureSummary,
  comparisonDocuments,
  nonDuplicateCheck: {
    comparedAgainst: [
      "evaluation/release-regression-cases.json",
      "evaluation/complex-legit-cases.json"
    ],
    existingReleaseCases: releaseCases.length,
    existingComplexLegitCases: complexCases.length,
    duplicateIds,
    duplicateUrls,
    passed: duplicateIds.length === 0 && duplicateUrls.length === 0,
    newCaseIds: CASES.map(item => item.id)
  },
  summary,
  personaEvaluation,
  regressionMergeCandidates,
  cases: rows
};

const summaryPersonaRows = [
  ["Kháng bypass / logic", personaEvaluation[0].averageScore, personaEvaluation[1].scores[0].score, personaEvaluation[2].scores[2].score, "CAO"],
  ["Minh bạch verdict", personaEvaluation[0].scores[2].score, personaEvaluation[1].scores[1].score, personaEvaluation[2].scores[0].score, "CAO"],
  ["Link Lab / Safe Preview", personaEvaluation[0].scores[1].score, personaEvaluation[1].scores[2].score, personaEvaluation[2].scores[4].score, "CAO"],
  ["Cảnh báo giao dịch Việt Nam", 3, personaEvaluation[1].scores[4].score, personaEvaluation[2].scores[3].score, "CAO"],
  ["Khả năng sử dụng hằng ngày", 4, personaEvaluation[1].averageScore, personaEvaluation[2].averageScore, "TRUNG BÌNH"]
];

const markdown = `# Adversarial Probe Report - DNS Phishing Guard v${manifest.version}

Thời điểm tạo: ${generatedAt}

## Kết luận điều hành

- Probe chạy **hoàn toàn offline**, số request mạng: **0**; RDAP dùng **${OFFLINE_RDAP_NOTE}** cho từng case public.
- ${rows.length} case mới đã được đối chiếu; **không trùng URL hoặc ID** với ${releaseCases.length} release-regression và ${complexCases.length} complex-legit hiện có.
- Gap rate trên ${adversarialRows.length} case adversarial thực thi: **${percent(summary.gapRate)}**.
- Hybrid compensation rate trên cùng tập adversarial: **${percent(summary.hybridCompensationRate)}**.
- Expected-pass rate trên ${executableRows.length} case thực thi: **${percent(summary.expectedPassRate)}**; benign hard-negative: **${percent(summary.benignExpectedPassRate)}**.
- Logo giả payment: **${summary.paymentBrandDangerVerdicts}/${summary.paymentBrandCases}** vẫn ra NGUY HIỂM; số threat case được cộng payment evidence: **${summary.paymentBrandBoostedThreatCases}**.
- Kết luận: kiến trúc multi-layer bù tốt cho ML URL bị bỏ sót, nhưng action-token semantics, từ lóng giao dịch Việt Nam và coverage khi HTML bị cắt ở 64 KiB cần ưu tiên sửa.

## Phạm vi an toàn

| Chỉ số | Giá trị |
| --- | ---: |
| Request mạng thực | 0 |
| RDAP | ${OFFLINE_RDAP_NOTE} |
| Threat Intelligence ngoài | Không gọi |
| Domain dạng threat | Chỉ .example/.invalid dành riêng |
| Payload khai thác / thu credential | Không có |
| Source manifest offline | evaluation/sourced-test-urls.json · ${sourcedCases.length} URL |

Giai đoạn thu thập feed thật trong đặc tả mới **không được thực hiện** vì chỉ thị đang có yêu cầu toàn bộ case ở mức pattern/kịch bản, không gọi network và không sinh hoặc sử dụng domain phishing thật. File sourced dùng case reserved cùng URL benign đã biết từ dữ liệu cục bộ.

## Tóm tắt kiến trúc đã nạp

- Hybrid verdict đi qua threat intelligence, domain/RDAP/PSL, URL heuristics, redirect/network, page behavior, URL ML, content safety và evidence coverage.
- URL ML: \`${model.modelVersion}\`, ${model.featureNames?.length || 0} feature, Platt calibration, ngưỡng xác suất **${model.threshold}**. Ngưỡng hybrid: suspicious 10, medium/binary 30, high 70.
- ${releaseCases.length} release-regression hiện đã cover OAuth chính thức, các mẫu phishing rõ, IP/userinfo/Punycode và một số domain legit; ${complexCases.length} complex-legit cover social profile, bài viết/sản phẩm, tracking query, OAuth, checkout payment, localhost và private network.
- Probe này chỉ thêm pattern chưa có: lexical sát ngưỡng mới, OAuth-shaped host lạ, public host chứa internal/local/dev, semantic action-token mới, typosquat suffix reserved, 5 ca logo payment giả, từ lóng giao dịch Việt Nam và clean-prefix 64 KiB.

## Đối chiếu bộ đánh giá hiện có

| Chỉ số | Baseline | Adversarial probe mới |
| --- | ---: | ---: |
| Release regression | ${previousResults.releaseRegression?.cases ?? releaseCases.length} | Không sửa |
| Complex legit | ${previousResults.complexLegitRegression?.cases ?? complexCases.length} | Không sửa |
| Case mới | 0 | ${rows.length} |
| Case trùng URL/ID | - | 0 |
| Hybrid accuracy baseline | ${previousResults.releaseRegression?.hybrid?.accuracy === undefined ? "-" : percent(previousResults.releaseRegression.hybrid.accuracy)} | Không dùng làm prevalence estimate |

Các case sau đây **KHÔNG trùng** với \`release-regression-cases.json\` hoặc \`complex-legit-cases.json\` hiện có:

${CASES.map(item => `- \`${item.id}\``).join("\n")}

## Tổng hợp kết quả

| Chỉ số | Giá trị |
| --- | ---: |
| Tổng case | ${rows.length} |
| Case thực thi / structural | ${executableRows.length} / ${structuralRows.length} |
| Expected pass | ${passRows.length} |
| Hybrid compensated | ${compensatedRows.length} |
| Real gap | ${realGapRows.length} |
| Expected structural limitation | ${structuralLimitations.length} |
| Gap rate (adversarial) | ${percent(summary.gapRate)} |
| Hybrid compensation rate (adversarial) | ${percent(summary.hybridCompensationRate)} |
| Expected-pass rate (executable) | ${percent(summary.expectedPassRate)} |
| Benign expected-pass rate | ${percent(summary.benignExpectedPassRate)} |
| CHƯA ĐỦ DỮ LIỆU (ba trạng thái) | ${threeStateCounts[OUTCOMES.INSUFFICIENT]} / ${executableRows.length} · ${percent(summary.insufficientVerdictRate)} |

| Case | Nhóm | Phân loại | UI verdict | Risk score / level | ML probability / prediction |
| --- | --- | --- | --- | ---: | ---: |
${caseRowsMarkdown(executableRows)}

## Case lộ gap thật

${findingList(realGapRows, "Không có real gap trong probe này.")}

## Case Hybrid Risk Engine đã tự bù đắp qua layer khác

${findingList(compensatedRows, "Không có case cần layer khác bù đắp.")}

## Expected structural limitations

${structuralLimitations.map(row => `- \`${row.id}\`: ${row.rationale} ${row.expectedLimitation}`).join("\n") || "Không có."}

Layer yếu nhất theo kết quả thực thi là **Link Lab/content semantics**: hai gap action-token, hai gap từ lóng giao dịch Việt Nam và một gap coverage 64 KiB. Domain/site-context/auth allowlist/typosquat không lộ gap trong các fixture mới.

## QA/UX theo ba persona

Đây là trải nghiệm headless dựa trên logic thật, source UI và fixture offline; không thay thế usability test với người tham gia độc lập.

| Tiêu chí | Pentester | User thường | User không rành kỹ thuật | Mức nghiêm trọng |
| --- | ---: | ---: | ---: | --- |
${summaryPersonaRows.map(row => `| ${row[0]} | ${row[1]} | ${row[2]} | ${row[3]} | ${row[4]} |`).join("\n")}

${personaMarkdown(personaEvaluation)}

## Case đề xuất merge vào regression chính thức

Các case URL-only phù hợp với schema hiện tại:

\`evaluation/release-regression-cases.json\`

\`\`\`json
${JSON.stringify(regressionMergeCandidates.releaseRegressionCases, null, 2)}
\`\`\`

\`evaluation/complex-legit-cases.json\`

\`\`\`json
${JSON.stringify(regressionMergeCandidates.complexLegitCases, null, 2)}
\`\`\`

Các case action-token, content semantics và 64 KiB cần merge vào \`tests/release.test.mjs\` hoặc một schema Link Lab riêng vì hai JSON URL-only hiện tại không mang page/network fixture: ${regressionMergeCandidates.releaseTestOnly.map(id => `\`${id}\``).join(", ")}.

## Ưu tiên cải tiến

1. Khi \`network.truncated === true\`, hạ evidence coverage xuống PARTIAL/INSUFFICIENT, không hiển thị xanh và cân nhắc khóa Safe Preview cho tới khi có lớp xác minh khác.
2. Mở rộng action-token classifier bằng semantic path/parameter mới như resume/finalize/complete/grant/proof, nhưng thêm negative fixtures cho bài viết trợ giúp để tránh false positive.
3. Bổ sung từ lóng Việt Nam theo cụm hành vi, không chỉ keyword đơn: bơm Rbx, code cào, S/R, ib ad, ck TK cá nhân, cọc trước, chốt đơn, acc clone/nick full đồ.
4. Extension Audit nên ghi rõ đang chấm **quyền active**, không phải toàn bộ optional intent; nếu có manifest metadata đáng tin cậy thì hiển thị riêng, không cộng lẫn.
5. Giữ \`webNavigation\` làm lớp bù cho redirect race và cân nhắc thu tín hiệu tối thiểu sớm hơn; không coi page behavior của trang trung gian là đã được quan sát nếu redirect xảy ra trước content scan.

## Kết luận ưu tiên

Ba lỗ hổng logic cần sửa trước:

1. Link Lab vẫn có thể trả coverage COMPLETE/AN TOÀN khi response bị cắt ở 64 KiB và tín hiệu rủi ro nằm phía sau.
2. Action-token classifier phụ thuộc convention hữu hạn, bỏ sót resume/finalize/grant/proof semantics.
3. SCAM_COMMERCE/GAME_COMMERCE bỏ sót cụm từ lóng Việt Nam; domain-age đôi lúc bù được nhưng domain lâu năm có thể được greenlight.

Ba vấn đề UX cần ưu tiên:

1. Trạng thái xanh sau nội dung truncated tạo cảm giác chắc chắn hơn phạm vi quan sát thật.
2. Tên Safe Preview có thể bị hiểu như máy ảo an toàn tuyệt đối dù vẫn kết nối thật và có thể lộ IP.
3. Amber/CHƯA ĐỦ DỮ LIỆU đã diễn đạt tốt hơn v2.6, nhưng vẫn cần usability test để chắc người dùng lớn tuổi không đọc nó như “gần như an toàn”.

## Giới hạn

- Probe không load Chrome/Edge thật, không kiểm thử focus/inert bằng accessibility tree và không chạy review của cửa hàng extension.
- Case RDAP dùng tuổi domain giả lập offline; không dùng kết quả này để kết luận uy tín domain thật.
- Fixture HTML chỉ mô tả pattern; không có form thu credential hoạt động, exploit hoặc domain phishing thật.
- Tỷ lệ gap/compensation phản ánh bộ adversarial tuyển chọn, không phải tỷ lệ lỗi ngoài production.
- Safe Preview vẫn là kết nối thật khi người dùng chủ động mở trong extension; có thể lộ IP và không phải máy ảo hệ điều hành.

## Cách tái lập

Chạy \`npm run probe:adversarial\` trong thư mục release. Lệnh chỉ đọc dữ liệu cục bộ, dùng ${OFFLINE_RDAP_NOTE}, rồi ghi JSON và Markdown vào \`evaluation/results/\`.
`;

await Promise.all([
  fs.writeFile(path.join(reportDir, "adversarial-probe-results.json"), JSON.stringify(report, null, 2) + "\n", "utf8"),
  fs.writeFile(path.join(reportDir, "ADVERSARIAL_PROBE_REPORT.md"), markdown, "utf8")
]);

console.log(JSON.stringify({
  release: report.release,
  modelVersion: report.modelVersion,
  networkRequestsMade: report.safetyPolicy.networkRequestsMade,
  duplicateCheckPassed: report.nonDuplicateCheck.passed,
  summary: report.summary,
  outputs: [
    "evaluation/results/adversarial-probe-results.json",
    "evaluation/results/ADVERSARIAL_PROBE_REPORT.md"
  ]
}, null, 2));
