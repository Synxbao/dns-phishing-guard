(() => {
  const PAYMENT_PROVIDER_RULES = Object.freeze([
    { id: "VIETQR", label: "VietQR", terms: ["vietqr", "viet qr"], domains: ["vietqr.vn", "vietqr.io"] },
    { id: "ZALOPAY", label: "ZaloPay", terms: ["zalopay", "zalo pay"], domains: ["zalopay.vn"] },
    { id: "MOMO", label: "MoMo", terms: ["vi momo", "momo"], domains: ["momo.vn"] },
    { id: "VNPAY", label: "VNPay", terms: ["vnpay", "vn pay"], domains: ["vnpay.vn", "vnpayment.vn"] },
    { id: "NAPAS", label: "NAPAS", terms: ["napas"], domains: ["napas.com.vn"] },
    { id: "VISA", label: "Visa", terms: ["visa"], domains: ["visa.com", "visa.com.vn"] },
    { id: "MASTERCARD", label: "Mastercard", terms: ["mastercard", "master card"], domains: ["mastercard.com"] }
  ]);

  const PAYMENT_CONTAINER_SELECTOR = [
    "form", "[role='dialog']", "[data-payment]", "[data-checkout]",
    "[id*='payment' i]", "[class*='payment' i]", "[id*='checkout' i]", "[class*='checkout' i]",
    "[id*='billing' i]", "[class*='billing' i]", "[id*='order' i]", "[class*='order' i]",
    "[id*='cart' i]", "[class*='cart' i]", "[id*='topup' i]", "[class*='topup' i]",
    "[id*='nap-tien' i]", "[class*='nap-tien' i]", "[id*='nap-game' i]", "[class*='nap-game' i]"
  ].join(",");

  const INTERACTIVE_SELECTOR = [
    "button", "a[href]", "input[type='submit']", "input[type='button']",
    "input[type='radio']", "input[type='checkbox']", "select", "[role='button']", "[role='radio']"
  ].join(",");

  const PAYMENT_CONTEXT_TERMS = [
    "thanh toan", "phuong thuc thanh toan", "cong thanh toan", "chon ngan hang",
    "quet ma", "ma qr", "vietqr", "checkout", "payment", "payment method",
    "billing", "order summary", "don hang", "tong tien", "thanh tien", "so tien",
    "nap tien", "nap game", "top up", "mua ngay"
  ];

  const PAYMENT_ACTION_TERMS = [
    "thanh toan", "tiep tuc thanh toan", "xac nhan thanh toan", "pay now", "proceed to pay",
    "checkout", "dat hang", "hoan tat", "nap ngay", "nap tien", "quet ma", "tao ma qr"
  ];

  function foldText(value) {
    return String(value || "")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .replace(/đ/g, "d")
      .replace(/Đ/g, "D")
      .toLowerCase();
  }

  function queryLimited(root, selector, limit = 500) {
    try {
      return Array.from(root?.querySelectorAll?.(selector) || []).slice(0, Math.max(0, limit));
    } catch {
      return [];
    }
  }

  function attributeText(element) {
    return [
      element?.id,
      typeof element?.className === "string" ? element.className : element?.getAttribute?.("class"),
      element?.getAttribute?.("name"),
      element?.getAttribute?.("value"),
      element?.getAttribute?.("alt"),
      element?.getAttribute?.("aria-label"),
      element?.getAttribute?.("title"),
      element?.getAttribute?.("data-payment"),
      element?.getAttribute?.("data-checkout")
    ].filter(Boolean).join(" ");
  }

  function elementText(element) {
    return [element?.innerText, element?.textContent, attributeText(element)]
      .filter(Boolean)
      .join(" ");
  }

  function sameOrSubdomain(hostname, domain) {
    const host = String(hostname || "").toLowerCase();
    const target = String(domain || "").toLowerCase();
    return host === target || host.endsWith(`.${target}`);
  }

  function resourceHostname(element, currentOrigin) {
    const value = element?.getAttribute?.("src") || element?.getAttribute?.("href") || "";
    if (!value) return "";
    try {
      return new URL(value, currentOrigin || "https://invalid.local").hostname.toLowerCase();
    } catch {
      return "";
    }
  }

  function isInsideAdRegion(element, adRegions) {
    const filter = globalThis.DPGPageSignalFilter;
    if (typeof filter?.isInsideAdRegion === "function") {
      return filter.isInsideAdRegion(element, adRegions);
    }
    return (adRegions || []).some(region => region === element || region?.contains?.(element));
  }

  function providerEvidence(container, currentOrigin) {
    const descendants = queryLimited(
      container,
      "img,source,picture,a[href],iframe[src],script[src],button,input,label,[aria-label],[title]",
      320
    );
    const nodes = [container, ...descendants];
    const folded = foldText(nodes.map(elementText).join(" "));

    return PAYMENT_PROVIDER_RULES.map(rule => {
      const termHit = rule.terms.some(term => folded.includes(foldText(term)));
      const domainHit = nodes.some(node => {
        const hostname = resourceHostname(node, currentOrigin);
        return hostname && rule.domains.some(domain => sameOrSubdomain(hostname, domain));
      });
      if (!termHit && !domainHit) return null;
      const evidence = [];
      if (termHit) evidence.push("logo-or-text");
      if (domainHit) evidence.push("provider-resource-domain");
      return { id: rule.id, label: rule.label, evidence };
    }).filter(Boolean);
  }

  function hasAmountOrCurrency(text) {
    const folded = foldText(text);
    return /\b\d[\d.,\s]{0,14}\s*(?:d|vnd|usd)\b/i.test(folded) ||
      /\b(?:vnd|usd)\s*\d/i.test(folded) ||
      ["tong tien", "thanh tien", "so tien thanh toan", "amount due", "order total"]
        .some(term => folded.includes(term));
  }

  function inspectPaymentContainer(container, options) {
    const currentOrigin = options.currentOrigin || "";
    const text = elementText(container);
    const folded = foldText(text);
    const contextText = foldText(`${attributeText(container)} ${text.slice(0, 12000)}`);
    const hasPaymentContext = PAYMENT_CONTEXT_TERMS.some(term => contextText.includes(term));
    const controls = queryLimited(container, INTERACTIVE_SELECTOR, 180)
      .filter(control => !isInsideAdRegion(control, options.adRegions));
    const controlText = foldText(controls.map(elementText).join(" "));
    const hasPaymentAction = PAYMENT_ACTION_TERMS.some(term => controlText.includes(term));
    const hasAmount = hasAmountOrCurrency(folded);
    const providers = providerEvidence(container, currentOrigin);
    const interactiveControlCount = controls.length;

    let score = 0;
    if (hasPaymentContext) score += 25;
    if (interactiveControlCount > 0) score += 20;
    if (hasPaymentAction) score += 20;
    if (hasAmount) score += 15;
    score += Math.min(20, providers.length * 8);
    if (hasPaymentAction && hasAmount) score += 10;
    score = Math.min(100, score);

    const detected = hasPaymentContext && providers.length > 0 && interactiveControlCount > 0 &&
      (hasPaymentAction || hasAmount) && score >= 70;

    return {
      detected,
      confidence: detected && hasPaymentAction && hasAmount ? "STRONG" : detected ? "MODERATE" : "NONE",
      score,
      providers,
      context: {
        paymentContext: hasPaymentContext,
        interactiveControlCount,
        hasPaymentAction,
        hasAmountOrCurrency: hasAmount
      }
    };
  }

  function emptyResult() {
    return {
      detected: false,
      confidence: "NONE",
      score: 0,
      providers: [],
      context: {
        paymentContext: false,
        interactiveControlCount: 0,
        hasPaymentAction: false,
        hasAmountOrCurrency: false
      },
      disclaimer: "Không dùng tín hiệu logo/cổng thanh toán như bằng chứng xác thực website."
    };
  }

  function detectPaymentIntegration(root, options = {}) {
    if (!root) return emptyResult();
    const adRegions = Array.from(options.adRegions || []);
    const candidates = queryLimited(root, PAYMENT_CONTAINER_SELECTOR, 900)
      .filter(candidate => !isInsideAdRegion(candidate, adRegions));
    let best = emptyResult();

    for (const candidate of candidates) {
      const result = inspectPaymentContainer(candidate, {
        currentOrigin: options.currentOrigin || "",
        adRegions
      });
      if (result.score > best.score) best = result;
      if (result.detected && result.confidence === "STRONG" && result.score >= 95) break;
    }

    return {
      ...best,
      scannedContainerCount: candidates.length,
      disclaimer: "Đã quan sát tích hợp cổng thanh toán được công nhận; đây không phải xác thực website, đơn vị bán hàng hoặc giao dịch thật."
    };
  }

  globalThis.DPGPaymentSignals = Object.freeze({
    PAYMENT_PROVIDER_RULES,
    PAYMENT_CONTAINER_SELECTOR,
    detectPaymentIntegration
  });
})();
