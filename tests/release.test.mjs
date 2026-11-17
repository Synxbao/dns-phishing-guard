import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeFederatedAuthRedirect, isTrustedIdentityProviderUrl } from "../modules/auth-flow.js";
import { buildIdentityStatus, calculateRisk } from "../modules/risk-engine.js";
import { extractUrlMlFeatures, FEATURE_NAMES } from "../modules/url-ml-features.js";
import { predictWithModel, standardizedValue } from "../modules/url-model.js";
import { getDomainParts, initializeFromText } from "../modules/public-suffix.js";
import { classifySiteContext, SITE_CONTEXT_TYPES } from "../modules/site-context.js";
import { findSimilarDomain } from "../modules/typosquat.js";
import {
  buildPreflightVerdict,
  classifySensitiveActionUrl,
  classifyDownloadRisk,
  isBlockedLiteralHost,
  normalizeLinkLabUrl,
  probeUrlNetwork,
  summarizeHtml
} from "../modules/link-lab.js";
import { buildThreatIntelPayload, sanitizeUrlForHistory } from "../modules/url-privacy.js";
import { analyzeContentSafety } from "../modules/content-safety.js";
import {
  buildEvidenceAssessment,
  isRiskUndetermined
} from "../modules/evidence-coverage.js";
import { classifySearchEnginePage, isSearchEngineHome } from "../modules/search-engines.js";
import "../modules/page-signal-filter.js";
import "../modules/payment-signals.js";
import "../modules/brand-rules.js";

const {
  containsAdMarker,
  isLikelyAdElement,
  findLikelyAdRegions,
  filterElementsOutsideAdRegions,
  collectTextOutsideAdRegions
} = globalThis.DPGPageSignalFilter;
const { detectPaymentIntegration } = globalThis.DPGPaymentSignals;
const {
  foldText,
  normalizeBrandRuleData,
  analyzeBrandPresentation,
  deriveCommerceBrandSignals
} = globalThis.DPGBrandRules;

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
initializeFromText(await fs.readFile(path.join(root, "data/public_suffix_list.dat"), "utf8"));

const manifest = JSON.parse(await fs.readFile(path.join(root, "manifest.json"), "utf8"));
const model = JSON.parse(await fs.readFile(path.join(root, "data/url-model.json"), "utf8"));
const popupCss = await fs.readFile(path.join(root, "popup.css"), "utf8");
const popupHtml = await fs.readFile(path.join(root, "popup.html"), "utf8");
const popupJs = await fs.readFile(path.join(root, "popup.js"), "utf8");
const contentJs = await fs.readFile(path.join(root, "content.js"), "utf8");
const backgroundJs = await fs.readFile(path.join(root, "background.js"), "utf8");
const blockingJs = await fs.readFile(path.join(root, "modules/blocking.js"), "utf8");
const pageSignalFilterJs = await fs.readFile(path.join(root, "modules/page-signal-filter.js"), "utf8");
const paymentSignalsJs = await fs.readFile(path.join(root, "modules/payment-signals.js"), "utf8");
const blockedHtml = await fs.readFile(path.join(root, "blocked.html"), "utf8");
const packageJson = JSON.parse(await fs.readFile(path.join(root, "package.json"), "utf8"));
const releaseRegressionCases = JSON.parse(await fs.readFile(path.join(root, "evaluation/release-regression-cases.json"), "utf8"));
const complexLegitCases = JSON.parse(await fs.readFile(path.join(root, "evaluation/complex-legit-cases.json"), "utf8"));
const knownDomains = JSON.parse(await fs.readFile(path.join(root, "data/known-domains.json"), "utf8"));
const protectedPaymentData = JSON.parse(await fs.readFile(path.join(root, "data/protected-payment-domains.json"), "utf8"));
const protectedGameData = JSON.parse(await fs.readFile(path.join(root, "data/protected-game-domains.json"), "utf8"));
const brandRuleData = normalizeBrandRuleData(
  JSON.parse(await fs.readFile(path.join(root, "data/brand-rules.json"), "utf8"))
);
const adversarialProbeSource = await fs.readFile(path.join(root, "evaluation/adversarial-probe.mjs"), "utf8");
const sourcedTestUrls = JSON.parse(await fs.readFile(path.join(root, "evaluation/sourced-test-urls.json"), "utf8"));
const adversarialProbeResults = JSON.parse(await fs.readFile(path.join(root, "evaluation/results/adversarial-probe-results.json"), "utf8"));

assert.equal(manifest.name, "DNS Phishing Guard");
assert.equal(manifest.version, "2.7.5");
assert.match(popupCss, /min-width:\s*320px/);
assert.match(popupCss, /@media \(max-width:\s*430px\)[\s\S]*?width:\s*420px/);
assert.match(popupCss, /@media \(max-width:\s*360px\)[\s\S]*?width:\s*320px/);
assert.match(popupCss, /@media \(max-width:\s*360px\)[\s\S]*?\.mode-link\s*\{[\s\S]*?display:\s*none/);
assert.doesNotMatch(popupCss, /width:\s*100vw/);
assert.match(popupCss, /\.setting\s*>\s*div\s*\{[\s\S]*?min-width:\s*0/);
assert.match(popupCss, /\.setting b\s*\{[\s\S]*?overflow-wrap:\s*anywhere/);
assert.match(popupHtml, /id="simpleShell"/);
assert.match(popupHtml, /TRANG ĐANG MỞ/);
assert.match(popupHtml, /LINK BẠN ĐANG KIỂM TRA/);
assert.match(popupHtml, /Phạm vi bằng chứng/);
assert.match(popupHtml, /id="simpleCoverage"/);
assert.match(popupHtml, /id="scoreUnit"/);
assert.match(popupHtml, /id="simpleLanguageBtn"/);
assert.match(popupHtml, /id="technicalLanguageBtn"/);
assert.match(popupHtml, /id="uiLanguageSelect"/);
assert.match(popupHtml, /v2\.7\.5/);
assert.match(popupJs, /uiProfile:\s*"simple"/);
assert.match(popupJs, /uiLanguage:\s*"vi"/);
assert.match(popupJs, /ENGLISH_UI_TEXT/);
assert.match(popupJs, /function setUiLanguage/);
assert.match(popupJs, /const determinedSafe = result\?\.risk\?\.level === "SAFE"[\s\S]*?assessment\.status === "COMPLETE"[\s\S]*?assessment\.riskState === "DETERMINED"/);
assert.match(popupJs, /return !determinedSafe && \(isRiskUndetermined\(result\) \|\| assessment\.safeDisplayState === "CAUTION"\)/);
assert.match(popupCss, /\.language-control\s*\{[\s\S]*?min-height:\s*44px/);
assert.match(popupCss, /\.tab\s*\{[\s\S]*?min-height:\s*44px/);
assert.match(popupCss, /\.action\s*\{[\s\S]*?min-height:\s*44px/);
assert.match(backgroundJs, /uiProfile:\s*"simple"/);
assert.match(popupJs, /showSearchEnginePageUi:\s*false/);
assert.match(backgroundJs, /showSearchEnginePageUi:\s*false/);
assert.match(popupHtml, /data-setting="showSearchEnginePageUi"/);
assert.match(popupHtml, /Mặc định ẩn khi an toàn; cảnh báo rủi ro vẫn luôn hiện/);
assert.match(backgroundJs, /chrome\.storage\.session\.set/);
assert.match(backgroundJs, /webNavigation\.onCommitted[\s\S]*?consumeAllowDomainOnce\(details\.tabId\)/);
assert.deepEqual(manifest.content_scripts[0].js, [
  "modules/page-signal-filter.js",
  "modules/payment-signals.js",
  "modules/brand-rules.js",
  "content.js"
]);
assert.ok(manifest.web_accessible_resources.some(group => group.resources.includes("data/brand-rules.json")));
assert.match(contentJs, /document\.body\.inert\s*=\s*true/);
assert.match(contentJs, /"keydown",\s*"beforeinput",\s*"input",\s*"submit"/);
assert.match(contentJs, /activateSecurityLock\(shadow,\s*"dpg-back"\)/);
assert.match(contentJs, /const isHigh = result\.risk\.level === "HIGH" \|\| result\.contentSafety\?\.level === "HIGH"/);
assert.match(contentJs, /const isBlockingContent = content\.level === "HIGH"[\s\S]*?STRICT_CONTENT_CATEGORY_IDS\.has/);
assert.match(contentJs, /isBlockingContent \? "" : '<button class="close"/);
assert.match(contentJs, /if \(isBlockingContent\) \{[\s\S]*?activateSecurityLock\(shadow, "dpg-back"\)/);
assert.match(contentJs, /function bypassNeedsTypedDomain[\s\S]*?result\.contentSafety\?\.level === "HIGH"/);
assert.match(contentJs, /confirmationDomain/);
assert.match(contentJs, /commerceBrandMismatch/);
assert.match(contentJs, /gameCommerceBrandMismatch/);
assert.match(contentJs, /officialClaimMismatch/);
assert.match(popupJs, /const officialClaimMismatch = Boolean\(page\.officialClaimMismatch \|\| page\.gameCommerceOfficialClaimMismatch\)/);
assert.match(popupJs, /Địa chỉ website này rất giống/);
assert.match(popupJs, /Trang tự nhận là chính thức hoặc đối tác/);
assert.match(popupJs, /ID game hoặc mã thẻ \(số serial\/PIN\)/);
assert.match(contentJs, /await brandRulesReady/);
assert.doesNotMatch(contentJs, /const BRAND_RULES\s*=\s*\[/);
assert.match(contentJs, /gameOffPlatformContactCount/);
assert.match(contentJs, /findLikelyAdRegions\(document\.body, currentOrigin\)/);
assert.match(contentJs, /collectTextOutsideAdRegions\(document\.body, adRegions, 120000\)/);
assert.match(contentJs, /detectPaymentIntegration\(document\.body/);
assert.match(contentJs, /paymentIntegration/);
assert.match(contentJs, /contentQueryLimited\('article, \[class\*="profile"\]/);
assert.match(pageSignalFilterJs, /STANDARD_AD_SIZES/);
assert.match(pageSignalFilterJs, /thirdPartyResource/);
assert.match(pageSignalFilterJs, /WEAK_AD_REGION_SELECTOR/);
assert.match(pageSignalFilterJs, /\[class\*='widget' i\]/);
assert.match(pageSignalFilterJs, /\[class\*='promo' i\]/);
assert.match(paymentSignalsJs, /PAYMENT_PROVIDER_RULES/);
assert.match(paymentSignalsJs, /hasPaymentAction && hasAmount/);
assert.match(paymentSignalsJs, /không phải xác thực website, đơn vị bán hàng hoặc giao dịch thật/);
assert.match(contentJs, /function installNonBlockingPanelBehavior/);
assert.match(contentJs, /document\.addEventListener\("contextmenu", collapseFromPageEvent, true\)/);
assert.match(contentJs, /document\.addEventListener\("selectionchange", collapseForPageSelection, true\)/);
assert.match(contentJs, /if \(!isHigh\) installNonBlockingPanelBehavior\(shadow\)/);
assert.match(contentJs, /if \(!isBlockingContent\) installNonBlockingPanelBehavior\(shadow\)/);
assert.match(contentJs, /position:fixed;right:14px;bottom:14px/);
assert.match(contentJs, /\.bar-score\{[^}]*white-space:nowrap/);
assert.match(contentJs, /\.bar strong\{min-width:0;flex:1 1 auto;overflow:hidden/);
assert.doesNotMatch(contentJs, /\.bar\{[^}]*position:fixed;top:10px;left:50%/);
for (const breakpoint of [700, 620, 520, 468, 420, 320]) {
  assert.match(contentJs, new RegExp(`@media\\(max-width:${breakpoint}px\\)`));
}
assert.match(contentJs, /function shouldSuppressSearchEngineUi/);
assert.match(contentJs, /result\.isSearchEngineHome/);
assert.match(contentJs, /result\.risk\?\.level === "SAFE"/);
assert.match(backgroundJs, /classifySearchEnginePage/);
assert.match(backgroundJs, /const identityDomain = domainInfo\.registrableDomain \|\| hostname/);
assert.match(backgroundJs, /checkDomainAge\(identityDomain\)/);
assert.match(backgroundJs, /getTyposquatReferenceDomains\(\)/);
assert.match(backgroundJs, /exactBrandLabels:\s*protectedTyposquatDomains/);
assert.match(backgroundJs, /const isKnownDomain = siteContext\.isPublic && knownDomains\.includes\(identityDomain\)/);
assert.match(backgroundJs, /isSearchEngineHome: Boolean\(staticAnalysis\.isSearchEngineHome\)/);
assert.match(contentJs, /CHƯA ĐỦ DỮ LIỆU/);
assert.match(contentJs, /showChildUnverifiedBanner/);
assert.match(backgroundJs, /incompleteSafeEvidence/);
assert.match(backgroundJs, /!network\.redirectAnomaly[\s\S]*?network\.reachable === true[\s\S]*?network\.ok === true/);
assert.match(blockingJs, /async function consumeAllowDomainOnce/);
assert.match(blockingJs, /allow_once_/);
assert.match(blockedHtml, /id="confirmationInput"/);
assert.match(backgroundJs, /buildEvidenceAssessment/);
assert.match(popupJs, /CHƯA XÁC ĐỊNH/);
assert.match(blockedHtml, /blocked\.js\?v=2\.7\.5/);
assert.equal(packageJson.scripts["probe:adversarial"], "node evaluation/adversarial-probe.mjs");
assert.match(packageJson.scripts.validate, /probe:adversarial/);
assert.doesNotMatch(adversarialProbeSource, /\bfetch\s*\(/);
assert.doesNotMatch(adversarialProbeSource, /\bprobeUrlNetwork\s*\(/);
assert.doesNotMatch(adversarialProbeSource, /https:\/\/rdap\.org/i);
assert.equal(sourcedTestUrls.length, 30);
assert.ok(sourcedTestUrls.every(item => ["phishing", "benign", "malware", "typosquat", "scam-commerce"].includes(item.category)));
assert.ok(sourcedTestUrls.every(item => item.source && item.snapshotDate && item.rationale && item.expectedVerdict));
assert.ok(sourcedTestUrls.filter(item => item.source === "manual-offline-reserved-pattern").every(item => new URL(item.url).hostname.endsWith(".example")));
assert.equal(adversarialProbeResults.safetyPolicy.networkRequestsMade, 0);
assert.equal(adversarialProbeResults.safetyPolicy.rdap, "ageInfo giả lập offline");
assert.equal(adversarialProbeResults.nonDuplicateCheck.passed, true);
assert.equal(adversarialProbeResults.sourceManifest.cases, sourcedTestUrls.length);
assert.equal(adversarialProbeResults.sourceManifest.oneToOneWithExecutableCases, true);
assert.equal(adversarialProbeResults.summary.benignExpectedPassRate, 1);
const fakePaymentProbeCases = adversarialProbeResults.cases.filter(item => item.category === "PAYMENT_BRAND_IMPERSONATION");
assert.equal(fakePaymentProbeCases.length, 5);
assert.ok(fakePaymentProbeCases.every(item => item.actual.riskLevel === "HIGH"));
assert.ok(fakePaymentProbeCases.every(item => item.actual.uiVerdict === "NGUY_HIEM"));
assert.ok(fakePaymentProbeCases.every(item => item.actual.paymentEvidenceBoost === 0));
assert.ok(fakePaymentProbeCases.every(item => item.actual.paymentEvidenceEligible === false));
assert.ok(fakePaymentProbeCases.every(item => item.evaluation.classification === "EXPECTED_PASS"));
const fakeGameTopupProbe = adversarialProbeResults.cases.find(item => item.id === "fake-game-topup-garena-official-claim");
assert.equal(fakeGameTopupProbe?.actual.riskLevel, "HIGH");
assert.equal(fakeGameTopupProbe?.actual.uiVerdict, "NGUY_HIEM");
assert.ok(fakeGameTopupProbe?.actual.contentCategoryIds.includes("SCAM_COMMERCE"));
assert.equal(adversarialProbeResults.protectedGameReferences.trustAllowlist, false);
assert.deepEqual(model.featureNames, FEATURE_NAMES);
assert.equal(model.training.datasetSize, 4000);
assert.equal(model.training.safeCount, 2000);
assert.equal(model.training.maliciousCount, 2000);
assert.equal(model.training.testCount, 398);
assert.equal(model.training.benignCounterfactualCount, 800);
assert.ok(model.training.hardNegativeTrainingCount >= 450);
assert.equal(model.training.testMetrics.tp + model.training.testMetrics.tn + model.training.testMetrics.fp + model.training.testMetrics.fn, 398);
assert.equal(model.standardizationClamp, 6);
assert.equal(standardizedValue(100, 0, 1, 6), 6);

const searchEngineCases = complexLegitCases.filter(item => item.searchEngineHome === true);
const paymentLegitCases = complexLegitCases.filter(item => item.pageSignals?.paymentIntegration?.detected === true);
const complexTopupPair = complexLegitCases.filter(item => item.pairId === "garena-topup-official-vs-impostor");
const releaseTopupPair = releaseRegressionCases.filter(item => item.pairId === "garena-topup-official-vs-impostor");
assert.equal(complexLegitCases.length, 34);
assert.equal(searchEngineCases.length, 6);
assert.equal(paymentLegitCases.length, 2);
assert.equal(complexTopupPair.length, 2);
assert.equal(releaseTopupPair.length, 2);
assert.deepEqual(new Set(complexTopupPair.map(item => item.expectedVerdict)), new Set(["SAFE", "PHISHING"]));
assert.deepEqual(new Set(releaseTopupPair.map(item => item.expectedVerdict)), new Set(["SAFE", "PHISHING"]));
assert.equal(complexTopupPair.find(item => item.pairRole === "official")?.expectedVerifiedBrandEvidenceEligible, true);
assert.equal(complexTopupPair.find(item => item.pairRole === "impostor")?.expectedVerifiedBrandEvidenceEligible, false);
assert.equal(releaseTopupPair.find(item => item.pairRole === "official")?.expectedSafeDisplayState, "CONFIDENT");
assert.ok(paymentLegitCases.every(item => item.expectedPaymentEvidenceEligible === true));
assert.ok(paymentLegitCases.some(item => item.ageDays === 420));
assert.ok(paymentLegitCases.some(item => !Object.prototype.hasOwnProperty.call(item, "ageDays")));
assert.ok(searchEngineCases.every(item => classifySearchEnginePage(item.url).isSearchEngineHome));
assert.ok(searchEngineCases.every(item => knownDomains.includes(getDomainParts(new URL(item.url).hostname).registrableDomain)));
assert.equal(isSearchEngineHome("https://www.bing.com/search?q=phishing+awareness"), true);
assert.equal(isSearchEngineHome("https://docs.google.com/document/d/example/edit"), false);
assert.equal(isSearchEngineHome("https://accounts.google.com/o/oauth2/v2/auth"), false);
assert.equal(isSearchEngineHome("https://google.com.evil.example/search?q=test"), false);

const protectedPaymentDomains = protectedPaymentData.entries.map(item => item.domain);
const protectedGameDomains = protectedGameData.entries.map(item => item.domain);
const protectedTyposquatDomains = [...new Set([...protectedPaymentDomains, ...protectedGameDomains])];
const paymentTypoReferences = [...new Set([...knownDomains, ...protectedTyposquatDomains])];
assert.equal(protectedPaymentData.purpose, "typosquat-reference-only");
assert.equal(protectedPaymentData.trustAllowlist, false);
assert.ok(protectedPaymentData.sources.every(item => item.publisher && item.reference && item.url));
assert.equal(protectedGameData.purpose, "typosquat-reference-only");
assert.equal(protectedGameData.trustAllowlist, false);
assert.ok(protectedGameData.sources.every(item => item.publisher && item.reference && item.url));
assert.equal(brandRuleData.trustAllowlist, false);
assert.ok(brandRuleData.rules.some(item => item.id === "garena-vn" && item.domains.includes("napthe.vn")));
assert.ok(brandRuleData.rules.some(item => item.id === "vnggames-zing" && item.domains.includes("vnggames.com")));
assert.ok(brandRuleData.rules.some(item => item.id === "vtcgame-vcoin" && item.domains.includes("vtcgame.vn")));
assert.ok(brandRuleData.sources.every(item => item.publisher && item.reference && item.url));
assert.ok(!knownDomains.includes("zalopay.vn"));
assert.ok(!knownDomains.includes("napthe.vn"));
assert.equal(findSimilarDomain("zal0pay.example", paymentTypoReferences, {
  exactBrandLabels: protectedPaymentDomains
})?.closest, "zalopay.vn");
assert.equal(findSimilarDomain("vietqrr.example", paymentTypoReferences, {
  exactBrandLabels: protectedTyposquatDomains
})?.closest, "vietqr.vn");
assert.equal(findSimilarDomain("napthevn.example", paymentTypoReferences, {
  exactBrandLabels: protectedTyposquatDomains
})?.closest, "napthe.vn");

const ageTierContext = classifySiteContext("https://age-tier.example/");
const identityInput = {
  siteContext: ageTierContext,
  isBlacklisted: false,
  isWhitelisted: false,
  isKnownDomain: false,
  officialSuffix: false
};
assert.equal(buildIdentityStatus({ ...identityInput, ageInfo: { ageDays: 364 } }).code, "UNVERIFIED");
assert.equal(buildIdentityStatus({ ...identityInput, ageInfo: { ageDays: 365 } }).code, "MODERATELY_ESTABLISHED");
assert.equal(buildIdentityStatus({ ...identityInput, ageInfo: { ageDays: 729 } }).code, "MODERATELY_ESTABLISHED");
assert.equal(buildIdentityStatus({ ...identityInput, ageInfo: { ageDays: 730 } }).code, "ESTABLISHED_DOMAIN");

class FixtureElement {
  constructor(tagName, options = {}) {
    this.tagName = String(tagName || "div").toUpperCase();
    this.id = options.id || "";
    this.className = options.className || "";
    this.attributes = { ...(options.attributes || {}) };
    this.style = { ...(options.style || {}) };
    this.text = options.text || "";
    this.width = options.width || 0;
    this.height = options.height || 0;
    this.children = [];
    this.parentElement = null;
    for (const child of options.children || []) this.appendChild(child);
  }

  appendChild(child) {
    child.parentElement = this;
    this.children.push(child);
    return child;
  }

  getAttribute(name) {
    if (name === "id") return this.id || null;
    if (name === "class") return this.className || null;
    if (name === "style") {
      const declarations = Object.entries(this.style)
        .map(([property, value]) => `${property}:${value}`)
        .join(";");
      return declarations || null;
    }
    return Object.prototype.hasOwnProperty.call(this.attributes, name) ? this.attributes[name] : null;
  }

  hasAttribute(name) {
    if (name === "id") return Boolean(this.id);
    if (name === "class") return Boolean(this.className);
    return Object.prototype.hasOwnProperty.call(this.attributes, name);
  }

  getBoundingClientRect() {
    return { width: this.width, height: this.height };
  }

  descendants() {
    return this.children.flatMap(child => [child, ...child.descendants()]);
  }

  querySelectorAll(selector = "*") {
    const selectors = String(selector).split(",").map(item => item.trim()).filter(Boolean);
    return this.descendants().filter(candidate => selectors.some(item => fixtureMatchesSelector(candidate, item)));
  }

  querySelector(selector = "*") {
    return this.querySelectorAll(selector)[0] || null;
  }

  contains(candidate) {
    return this === candidate || this.children.some(child => child.contains(candidate));
  }

  get innerText() {
    return [this.text, ...this.children.map(child => child.innerText)].filter(Boolean).join("\n");
  }
}

function fixtureMatchesSelector(element, selector) {
  if (selector === "*") return true;
  const tagMatch = selector.match(/^[a-z][a-z0-9-]*/i);
  if (tagMatch && element.tagName !== tagMatch[0].toUpperCase()) return false;

  const attributePattern = /\[([^\s~*\]=]+)(?:\s*([~*]?=)\s*['\"]?([^'\"\]]*?)['\"]?\s*(i)?)?\]/gi;
  for (const match of selector.matchAll(attributePattern)) {
    const [, name, operator, expectedRaw, insensitive] = match;
    const actualRaw = element.getAttribute(name);
    if (actualRaw === null) return false;
    if (!operator) continue;
    const actual = insensitive ? String(actualRaw).toLowerCase() : String(actualRaw);
    const expected = insensitive ? String(expectedRaw).toLowerCase() : String(expectedRaw);
    if (operator === "=" && actual !== expected) return false;
    if (operator === "*=" && !actual.includes(expected)) return false;
    if (operator === "~=" && !actual.split(/\s+/).includes(expected)) return false;
  }
  return true;
}

function uniqueFixtureHits(text, keywords) {
  const normalized = String(text || "").toLowerCase();
  return keywords.filter(keyword => normalized.includes(keyword));
}

function sexualFixtureSignals(text, contacts, profiles, titleHit = false) {
  const direct = uniqueFixtureHits(text, ["gai goi", "escort service"]);
  const context = uniqueFixtureHits(text, ["tim ban tinh", "hen ho 18+", "tinh mot dem"]);
  const transactions = uniqueFixtureHits(text, ["dat lich", "theo gio", "lien he zalo"]);
  return {
    sexualServiceDirectHitCount: direct.length,
    sexualServiceContextHitCount: context.length,
    sexualServiceTransactionHitCount: transactions.length,
    sexualServiceContactCount: contacts.length,
    sexualServiceProfileCount: profiles.length,
    sexualServiceTitleHit: titleHit,
    contentSamples: { sexualServices: [...direct, ...context, ...transactions] }
  };
}

function gamblingFixtureSignals(text, titleHit = false) {
  const core = uniqueFixtureHits(text, ["casino", "sportsbook", "live casino", "betting"]);
  const actions = uniqueFixtureHits(text, ["bet now", "join now", "choi ngay"]);
  const payments = uniqueFixtureHits(text, ["nap tien", "rut tien", "deposit"]);
  return {
    gamblingCoreHitCount: core.length,
    gamblingActionHitCount: actions.length,
    gamblingPaymentHitCount: payments.length,
    gamblingTitleHit: titleHit,
    contentSamples: { gambling: [...core, ...actions, ...payments] }
  };
}

const topupHeading = new FixtureElement("h1", {
  text: "Garena Free Fire - Đối tác chính thức"
});
const topupForm = new FixtureElement("form", {
  className: "game-topup checkout",
  text: "Nạp game chính thức. Chọn gói và thanh toán.",
  children: [
    new FixtureElement("input", { attributes: { name: "game-id", placeholder: "ID game" } }),
    new FixtureElement("input", { attributes: { name: "card-serial", placeholder: "Số seri" } }),
    new FixtureElement("input", { attributes: { name: "card-pin", placeholder: "Mã thẻ" } }),
    new FixtureElement("button", { text: "Nạp ngay" })
  ]
});
const topupFixtureBody = new FixtureElement("body", { children: [topupHeading, topupForm] });
const topupBrandText = topupFixtureBody.innerText;
const officialTopupPresentation = analyzeBrandPresentation({
  data: brandRuleData,
  currentDomain: "napthe.vn",
  text: topupBrandText,
  prominentText: topupHeading.innerText
});
const impostorTopupPresentation = analyzeBrandPresentation({
  data: brandRuleData,
  currentDomain: "napthevn.example",
  text: topupBrandText,
  prominentText: topupHeading.innerText
});
const officialTopupBrandSignals = deriveCommerceBrandSignals(officialTopupPresentation, {
  hasSensitiveCommerceAction: true,
  hasSensitiveTransactionInput: true,
  hasGameCommerceContext: true
});
const impostorTopupBrandSignals = deriveCommerceBrandSignals(impostorTopupPresentation, {
  hasSensitiveCommerceAction: true,
  hasSensitiveTransactionInput: true,
  hasGameCommerceContext: true
});
assert.equal(officialTopupBrandSignals.officialClaim, true);
assert.equal(officialTopupBrandSignals.officialClaimMismatch, false);
assert.equal(officialTopupBrandSignals.gameCommerceOfficialBrand, true);
assert.equal(impostorTopupBrandSignals.officialClaimMismatch, true);
assert.equal(impostorTopupBrandSignals.officialClaimBrandName, "Garena");
assert.equal(impostorTopupBrandSignals.gameCommerceOfficialClaimMismatch, true);
const officialWithPaymentLogo = deriveCommerceBrandSignals(analyzeBrandPresentation({
  data: brandRuleData,
  currentDomain: "napthe.vn",
  text: `${topupBrandText} Thanh toán qua ví MoMo`,
  prominentText: `${topupHeading.innerText} MoMo`
}), {
  hasSensitiveCommerceAction: true,
  hasSensitiveTransactionInput: true,
  hasGameCommerceContext: true
});
assert.equal(officialWithPaymentLogo.commerceBrandMismatch, false);
assert.equal(officialWithPaymentLogo.officialClaimMismatch, false);
assert.equal(foldText("Gare\u200Bna"), "garena");
assert.equal(foldText("Free-Fire"), "free fire");
const normalizedVariantPresentation = analyzeBrandPresentation({
  data: brandRuleData,
  currentDomain: "napthevn.example",
  text: "Đối tác chính thức Gare\u200Bna cho Free-Fire. Nhập ID game và mã thẻ để nạp ngay.",
  prominentText: "Gare\u200Bna Free-Fire chính thức"
});
const normalizedVariantSignals = deriveCommerceBrandSignals(normalizedVariantPresentation, {
  hasSensitiveCommerceAction: true,
  hasSensitiveTransactionInput: true,
  hasGameCommerceContext: true
});
assert.equal(normalizedVariantSignals.officialClaimMismatch, true);
assert.equal(normalizedVariantSignals.officialClaimBrandName, "Garena");

const sharedTopupSignals = {
  prepaidValueHitCount: 3,
  gameTopupHitCount: 4,
  unofficialCommerceHitCount: 0,
  promoClaimHitCount: 0,
  commerceActionCount: 2,
  prepaidCodeInputCount: 2,
  gameAccountInputCount: 1,
  gameMarketplaceHitCount: 0,
  gameTransactionHitCount: 2,
  gameOffPlatformContactCount: 0,
  gameCommerceActionCount: 2,
  contentSamples: {
    scamCommerce: ["ma the", "so seri", "nap game", "id game"],
    gameCommerce: ["nap tien", "thanh toan"]
  }
};
const officialTopupSignals = { ...sharedTopupSignals, ...officialTopupBrandSignals };
const impostorTopupSignals = { ...sharedTopupSignals, ...impostorTopupBrandSignals };
const officialTopupContent = analyzeContentSafety(officialTopupSignals, { enabled: true });
const impostorTopupContent = analyzeContentSafety(impostorTopupSignals, { enabled: true });
assert.equal(officialTopupContent.level, "NONE");
assert.equal(impostorTopupContent.level, "HIGH");
assert.ok(impostorTopupContent.categories.some(item => item.id === "SCAM_COMMERCE" && item.score >= 78));
assert.ok(impostorTopupContent.categories.some(item => item.id === "GAME_COMMERCE" && item.score >= 65));

function calculateTopupPairRisk(url, ageDays, pageSignals) {
  const parsed = new URL(url);
  const domainInfo = getDomainParts(parsed.hostname);
  const mlInfo = predictWithModel(model, url, domainInfo);
  const typoMatch = findSimilarDomain(parsed.hostname, paymentTypoReferences, {
    exactBrandLabels: protectedTyposquatDomains
  });
  return calculateRisk({
    url,
    domain: parsed.hostname,
    domainInfo,
    ageInfo: { ageDays },
    typoMatch,
    homoglyphInfo: { isPunycode: false, hasHomoglyph: false, decodeFailed: false, displayDomain: parsed.hostname },
    isBlacklisted: false,
    isWhitelisted: false,
    isKnownDomain: false,
    pageSignals,
    redirectInfo: null,
    threatInfo: { checked: false, isUnsafe: false, threats: [] },
    mlInfo,
    siteContext: classifySiteContext(url)
  });
}

const officialTopupRisk = calculateTopupPairRisk("https://napthe.vn/app/32837/buy/0", 3000, officialTopupSignals);
const impostorTopupRisk = calculateTopupPairRisk("https://napthevn.example/app/32837/buy/0", 5, impostorTopupSignals);
assert.equal(officialTopupRisk.binaryPrediction, "SAFE");
assert.equal(impostorTopupRisk.binaryPrediction, "PHISHING");
assert.equal(impostorTopupRisk.level, "HIGH");
assert.ok(impostorTopupRisk.score >= officialTopupRisk.score + 50);

const officialTopupAssessment = buildEvidenceAssessment({
  domain: "napthe.vn",
  registrableDomain: "napthe.vn",
  risk: officialTopupRisk,
  contentSafety: officialTopupContent,
  pageSignals: officialTopupSignals,
  rdapMeta: { available: true, skipped: false },
  ageInfo: { ageDays: 3000 },
  mlInfo: { available: true, probability: officialTopupRisk.model.urlModel?.probability || 0 },
  redirectInfo: null,
  threatInfo: { checked: false, skipped: false, isUnsafe: false },
  listStatus: { blacklisted: false, knownDomain: false, whitelisted: false },
  settings: { analyzePage: true, urlModelEnabled: true, redirectAnalysis: true }
});
const impostorTopupAssessment = buildEvidenceAssessment({
  domain: "napthevn.example",
  registrableDomain: "napthevn.example",
  risk: impostorTopupRisk,
  contentSafety: impostorTopupContent,
  pageSignals: impostorTopupSignals,
  rdapMeta: { available: true, skipped: false },
  ageInfo: { ageDays: 5 },
  mlInfo: { available: true, probability: impostorTopupRisk.model.urlModel?.probability || 0 },
  redirectInfo: null,
  threatInfo: { checked: false, skipped: false, isUnsafe: false },
  listStatus: { blacklisted: false, knownDomain: false, whitelisted: false },
  settings: { analyzePage: true, urlModelEnabled: true, redirectAnalysis: true }
});
assert.equal(officialTopupAssessment.verifiedBrandEvidenceEligible, true);
assert.equal(officialTopupAssessment.verifiedBrandEvidenceBoost, 10);
assert.equal(officialTopupAssessment.evidenceScore, 48);
assert.equal(officialTopupAssessment.riskState, "DETERMINED");
assert.equal(officialTopupAssessment.safeDisplayState, "CONFIDENT");
assert.equal(impostorTopupAssessment.verifiedBrandEvidenceEligible, false);
assert.equal(impostorTopupAssessment.verifiedBrandEvidenceBoost, 0);
assert.equal(impostorTopupAssessment.safeDisplayState, "NOT_APPLICABLE");

const articleOnlyPresentation = analyzeBrandPresentation({
  data: brandRuleData,
  currentDomain: "news.example",
  text: "Bài viết: Garena công bố đối tác chính thức cho một giải đấu Free Fire.",
  prominentText: "Tin game Garena"
});
const articleOnlySignals = deriveCommerceBrandSignals(articleOnlyPresentation, {
  hasSensitiveCommerceAction: false,
  hasSensitiveTransactionInput: false,
  hasGameCommerceContext: false
});
assert.equal(articleOnlySignals.commerceBrandMismatch, false);
assert.equal(articleOnlySignals.officialClaimMismatch, false);

assert.equal(containsAdMarker("ads"), true);
assert.equal(containsAdMarker("sponsor-panel"), true);
assert.equal(containsAdMarker("banner-ad"), true);
assert.equal(containsAdMarker("quang-cao"), true);
assert.equal(containsAdMarker("address-card"), false);

const dimensionOnlyAd = new FixtureElement("div", {
  style: { width: "300px", height: "250px" },
  children: [
    new FixtureElement("a", {
      attributes: { href: "https://creative.example/offer" },
      children: [new FixtureElement("img", { attributes: { src: "https://creative.example/banner.png" } })]
    })
  ]
});
assert.equal(isLikelyAdElement(dimensionOnlyAd, "https://reader.example"), true);

const embeddedAdProfiles = Array.from({ length: 4 }, (_, index) => new FixtureElement("article", {
  className: "profile-card",
  text: `Ho so quang cao ${index + 1}`,
  children: [new FixtureElement("img", { attributes: { src: `https://creative.example/profile-${index + 1}.jpg` } })]
}));
const embeddedAdContacts = [
  new FixtureElement("a", { attributes: { href: "https://zalo.me/offline-fixture" }, text: "Lien he Zalo" }),
  new FixtureElement("a", { attributes: { href: "tel:0000000000" }, text: "Goi ngay" })
];
const legitimateStory = new FixtureElement("article", {
  className: "story-card",
  text: "Chuong moi cua bo truyen hop phap. Doc truyen, danh dau chuong va binh luan.",
  children: [new FixtureElement("img", { attributes: { src: "/covers/story.jpg" } })]
});
const embeddedAd = new FixtureElement("aside", {
  className: "banner-ad",
  attributes: { width: "300", height: "250" },
  text: "Gai goi, tim ban tinh, hen ho 18+, dat lich theo gio va lien he Zalo.",
  children: [...embeddedAdProfiles, ...embeddedAdContacts]
});
const mixedFixtureBody = new FixtureElement("body", { children: [legitimateStory, embeddedAd] });
const mixedAdRegions = findLikelyAdRegions(mixedFixtureBody, "https://reader.example");
assert.deepEqual(mixedAdRegions, [embeddedAd]);

const rawAdDrivenContent = analyzeContentSafety(sexualFixtureSignals(
  mixedFixtureBody.innerText,
  embeddedAdContacts,
  [legitimateStory, ...embeddedAdProfiles]
));
assert.equal(rawAdDrivenContent.level, "HIGH");
assert.ok(rawAdDrivenContent.categories.some(item => item.id === "SEXUAL_SERVICES"));

const filteredMixedText = collectTextOutsideAdRegions(mixedFixtureBody, mixedAdRegions, 120000);
const filteredContacts = filterElementsOutsideAdRegions(embeddedAdContacts, mixedAdRegions);
const filteredProfiles = filterElementsOutsideAdRegions([legitimateStory, ...embeddedAdProfiles], mixedAdRegions);
const filteredAdDrivenContent = analyzeContentSafety(sexualFixtureSignals(
  filteredMixedText.text,
  filteredContacts,
  filteredProfiles
));
assert.equal(filteredMixedText.excludedRegionCount, 1);
assert.ok(filteredMixedText.excludedTextLength > 0);
assert.ok(filteredMixedText.text.includes("bo truyen hop phap"));
assert.ok(!filteredMixedText.text.toLowerCase().includes("gai goi"));
assert.equal(filteredContacts.length, 0);
assert.equal(filteredProfiles.length, 1);
assert.equal(filteredAdDrivenContent.detected, false);

const checkoutForm = new FixtureElement("form", {
  className: "checkout-payment",
  text: "Phương thức thanh toán. Tổng tiền 100.000 VND.",
  children: [
    new FixtureElement("img", {
      attributes: { alt: "ZaloPay", src: "https://cdn.zalopay.vn/assets/logo.png" }
    }),
    new FixtureElement("img", {
      attributes: { alt: "VietQR", src: "https://static.vietqr.vn/logo.svg" }
    }),
    new FixtureElement("input", { attributes: { type: "radio", name: "payment-method" } }),
    new FixtureElement("button", { text: "Thanh toán ngay" })
  ]
});
const paymentFixtureBody = new FixtureElement("body", { children: [checkoutForm] });
const paymentIntegration = detectPaymentIntegration(paymentFixtureBody, {
  currentOrigin: "https://publisher.example",
  adRegions: []
});
assert.equal(paymentIntegration.detected, true);
assert.equal(paymentIntegration.confidence, "STRONG");
assert.ok(paymentIntegration.providers.some(item => item.id === "ZALOPAY"));
assert.ok(paymentIntegration.providers.some(item => item.id === "VIETQR"));

const logoOnlyPayment = new FixtureElement("section", {
  className: "payment-partners",
  text: "Đối tác ZaloPay và VietQR",
  children: [new FixtureElement("img", { attributes: { alt: "ZaloPay", src: "/logo.png" } })]
});
assert.equal(detectPaymentIntegration(new FixtureElement("body", { children: [logoOnlyPayment] }), {
  currentOrigin: "https://merchant.example",
  adRegions: []
}).detected, false);

const paymentAdRegion = new FixtureElement("aside", {
  className: "banner-ad",
  children: [checkoutForm]
});
const paymentAdBody = new FixtureElement("body", { children: [paymentAdRegion] });
assert.equal(detectPaymentIntegration(paymentAdBody, {
  currentOrigin: "https://reader.example",
  adRegions: [paymentAdRegion]
}).detected, false);

// Regression fixture based on the reported reader-site failure: the ad wrapper
// has only a generic promo/widget class and receives its 300x250 size from CSS.
const netTruyenStyleProfiles = Array.from({ length: 4 }, (_, index) => new FixtureElement("article", {
  className: "profile-card",
  text: `Ho so quang cao ${index + 1}`,
  children: [new FixtureElement("img", { attributes: { src: `https://creative.example/person-${index + 1}.jpg` } })]
}));
const netTruyenStyleContacts = [
  new FixtureElement("a", { attributes: { href: "https://zalo.me/offline-ad-fixture" }, text: "Lien he Zalo" }),
  new FixtureElement("a", { attributes: { href: "tel:0000000000" }, text: "Dat lich" })
];
const netTruyenStyleMain = new FixtureElement("main", {
  className: "chapter-list",
  text: "Danh sach truyen hop phap, chuong moi, lich su doc va binh luan cua doc gia."
});
const netTruyenStyleAd = new FixtureElement("div", {
  className: "sidebar-widget promo-slot",
  width: 300,
  height: 250,
  text: "Gai goi, tim ban tinh, hen ho 18+, dat lich theo gio va lien he Zalo.",
  children: [
    new FixtureElement("a", {
      attributes: { href: "https://creative.example/campaign" },
      children: [new FixtureElement("img", { attributes: { src: "https://creative.example/300x250.jpg" } })]
    }),
    ...netTruyenStyleProfiles,
    ...netTruyenStyleContacts
  ]
});
const netTruyenStyleBody = new FixtureElement("body", { children: [netTruyenStyleMain, netTruyenStyleAd] });
const netTruyenStyleRaw = analyzeContentSafety(sexualFixtureSignals(
  netTruyenStyleBody.innerText,
  netTruyenStyleContacts,
  netTruyenStyleProfiles
));
assert.equal(netTruyenStyleRaw.level, "HIGH");
assert.ok(netTruyenStyleRaw.categories.some(item => item.id === "SEXUAL_SERVICES"));

const netTruyenStyleAdRegions = findLikelyAdRegions(netTruyenStyleBody, "https://reader.example");
assert.deepEqual(netTruyenStyleAdRegions, [netTruyenStyleAd]);
const netTruyenStyleFilteredText = collectTextOutsideAdRegions(netTruyenStyleBody, netTruyenStyleAdRegions, 120000);
const netTruyenStyleFilteredContacts = filterElementsOutsideAdRegions(netTruyenStyleContacts, netTruyenStyleAdRegions);
const netTruyenStyleFilteredProfiles = filterElementsOutsideAdRegions(netTruyenStyleProfiles, netTruyenStyleAdRegions);
const netTruyenStyleFiltered = analyzeContentSafety(sexualFixtureSignals(
  netTruyenStyleFilteredText.text,
  netTruyenStyleFilteredContacts,
  netTruyenStyleFilteredProfiles
));
assert.ok(netTruyenStyleFilteredText.text.includes("Danh sach truyen hop phap"));
assert.ok(!netTruyenStyleFilteredText.text.toLowerCase().includes("gai goi"));
assert.equal(netTruyenStyleFilteredContacts.length, 0);
assert.equal(netTruyenStyleFilteredProfiles.length, 0);
assert.equal(netTruyenStyleFiltered.detected, false);

const genuineSexualProfiles = Array.from({ length: 5 }, (_, index) => new FixtureElement("article", {
  className: "profile-card",
  text: `Ho so ${index + 1}`,
  children: [new FixtureElement("img", { attributes: { src: `/profiles/${index + 1}.jpg` } })]
}));
const genuineSexualContacts = [
  new FixtureElement("a", { attributes: { href: "https://zalo.me/first-party-fixture" }, text: "Lien he Zalo" }),
  new FixtureElement("a", { attributes: { href: "tel:1111111111" }, text: "Dat lich" })
];
const genuineSexualBody = new FixtureElement("main", {
  className: "profiles",
  text: "Gai goi va escort service, tim ban tinh, hen ho 18+, tinh mot dem, dat lich theo gio, lien he Zalo.",
  children: [...genuineSexualProfiles, ...genuineSexualContacts]
});
const genuineSexualAdRegions = findLikelyAdRegions(genuineSexualBody, "https://content.example");
assert.equal(genuineSexualAdRegions.length, 0);
const genuineSexualContent = analyzeContentSafety(sexualFixtureSignals(
  collectTextOutsideAdRegions(genuineSexualBody, genuineSexualAdRegions).text,
  genuineSexualContacts,
  genuineSexualProfiles,
  true
));
assert.equal(genuineSexualContent.level, "HIGH");
assert.ok(genuineSexualContent.categories.some(item => item.id === "SEXUAL_SERVICES"));

const genuineGamblingBody = new FixtureElement("main", {
  className: "sportsbook-page",
  text: "Casino, sportsbook, live casino, betting. Bet now, join now, nap tien, rut tien va deposit."
});
const genuineGamblingAdRegions = findLikelyAdRegions(genuineGamblingBody, "https://content.example");
assert.equal(genuineGamblingAdRegions.length, 0);
const genuineGamblingContent = analyzeContentSafety(gamblingFixtureSignals(
  collectTextOutsideAdRegions(genuineGamblingBody, genuineGamblingAdRegions).text,
  true
));
assert.equal(genuineGamblingContent.level, "HIGH");
assert.ok(genuineGamblingContent.categories.some(item => item.id === "GAMBLING"));

const contentRegressionCases = releaseRegressionCases.filter(item => item.kind === "CONTENT_SAFETY");
assert.deepEqual(contentRegressionCases.map(item => item.expectedCategory).sort(), ["GAMBLING", "SEXUAL_SERVICES"]);
for (const regressionCase of contentRegressionCases) {
  const result = analyzeContentSafety(regressionCase.pageSignals);
  assert.equal(result.level, regressionCase.minimumLevel);
  assert.ok(result.categories.some(item => item.id === regressionCase.expectedCategory));
}

assert.equal(normalizeLinkLabUrl("example.com/login").href, "https://example.com/login");
assert.throws(() => normalizeLinkLabUrl("javascript:alert(1)"), /HTTP hoặc HTTPS/);
assert.throws(() => normalizeLinkLabUrl("http://127.0.0.1/admin"), /mạng nội bộ/);
assert.equal(isBlockedLiteralHost("192.168.1.1"), true);
assert.equal(isBlockedLiteralHost("example.com"), false);
assert.equal(classifySensitiveActionUrl("https://example.com/reset-password?token=abcdefghijk").sensitive, true);
assert.equal(classifySensitiveActionUrl("https://example.com/articles/password-reset-safety").sensitive, false);
const skippedProbeRequests = [];
const skippedProbe = await probeUrlNetwork("https://example.com/verify?token=abcdefghijk", async (...args) => {
  skippedProbeRequests.push(args);
  throw new Error("fetch must not run for action-token URLs");
});
assert.equal(skippedProbeRequests.length, 0);
assert.equal(skippedProbe.probeSkipped, true);
assert.equal(skippedProbe.previewAllowed, false);
const skippedVerdict = buildPreflightVerdict({ level: "SAFE", score: 2, confidenceScore: 40 }, skippedProbe);
assert.equal(skippedVerdict.level, "SUSPICIOUS");
assert.ok(skippedVerdict.reasons.some(reason => reason.includes("token")));
const historyUrl = sanitizeUrlForHistory("https://example.com/reset?token=secret&utm_source=mail#private");
assert.ok(historyUrl.includes("token=%3Credacted%3E"));
assert.ok(historyUrl.includes("utm_source=%3Credacted%3E"));
assert.ok(!historyUrl.includes("secret"));
assert.ok(!historyUrl.includes("private"));
const threatPayload = buildThreatIntelPayload("https://example.com/login?ticket=secret-value#fragment");
assert.equal(threatPayload.hostname, "example.com");
assert.equal(threatPayload.path, "/login");
assert.ok(!JSON.stringify(threatPayload).includes("secret-value"));
const linkLabSignals = summarizeHtml(`
  <script>location.href = "/next"</script>
  <form><input type="password"></form>
  <a download href="payload.exe">Tải</a>
`);
assert.equal(linkLabSignals.scriptCount, 1);
assert.equal(linkLabSignals.formCount, 1);
assert.equal(linkLabSignals.passwordInputCount, 1);
assert.equal(linkLabSignals.riskyDownloadLinkCount, 1);
const assetOnlySignals = summarizeHtml(`
  <link rel="modulepreload" href="/assets/app.js">
  <script src="/assets/app.js"></script>
`);
assert.equal(assetOnlySignals.riskyDownloadLinkCount, 0);
const napLauStaticSignals = summarizeHtml(`
  <title>N&#x1EA1;p l&#x1EAD;u Robux Roblox giá rẻ</title>
  <form><input name="idgame" placeholder="Username"><button>Nạp thẻ ngay</button></form>
  <p>Chuẩn bị thẻ cào, số seri và mã thẻ. Cam kết 100%, x2 lần nạp đầu.</p>
`);
assert.equal(napLauStaticSignals.staticContent.level, "HIGH");
assert.ok(napLauStaticSignals.staticContent.findings.some(item => item.id === "SCAM_COMMERCE"));
const officialTopupStaticSignals = summarizeHtml(`
  <title>Roblox gift card redemption help</title>
  <form><input name="redeem-code" placeholder="Redeem code"><button>Redeem</button></form>
  <p>Use a gift card to add Robux to your own account.</p>
`);
assert.equal(officialTopupStaticSignals.staticContent.level, "NONE");
const commerceArticleStaticSignals = summarizeHtml(`
  <article>
    <h1>Cảnh báo nạp lậu Robux</h1>
    <p>Bài viết giải thích vì sao không nên gửi mã thẻ hoặc số seri cho dịch vụ lạ.</p>
    <a href="https://www.roblox.com/giftcards">Mua ngay tại kênh chính thức</a>
  </article>
  <form><input name="search" placeholder="Tìm bài viết"></form>
`);
assert.equal(commerceArticleStaticSignals.staticContent.level, "NONE");

const napLauContentSafety = analyzeContentSafety({
  prepaidValueHitCount: 4,
  gameTopupHitCount: 3,
  unofficialCommerceHitCount: 2,
  promoClaimHitCount: 2,
  commerceActionCount: 2,
  prepaidCodeInputCount: 2,
  gameAccountInputCount: 1,
  commerceBrandMismatch: true,
  commerceBrandName: "Roblox",
  contentSamples: { scamCommerce: ["nap lau", "the cao", "robux", "cam ket 100%"] }
});
assert.equal(napLauContentSafety.level, "HIGH");
assert.ok(napLauContentSafety.categories.some(item => item.id === "SCAM_COMMERCE"));
const officialTopupContentSafety = analyzeContentSafety({
  prepaidValueHitCount: 2,
  gameTopupHitCount: 2,
  unofficialCommerceHitCount: 0,
  promoClaimHitCount: 0,
  commerceActionCount: 1,
  prepaidCodeInputCount: 1,
  gameAccountInputCount: 0,
  commerceBrandMismatch: false,
  contentSamples: { scamCommerce: ["gift card", "robux"] }
});
assert.equal(officialTopupContentSafety.detected, false);
const commerceArticleContentSafety = analyzeContentSafety({
  prepaidValueHitCount: 2,
  gameTopupHitCount: 2,
  unofficialCommerceHitCount: 1,
  promoClaimHitCount: 0,
  commerceActionCount: 1,
  prepaidCodeInputCount: 0,
  gameAccountInputCount: 0,
  commerceBrandMismatch: true,
  commerceBrandName: "Roblox",
  contentSamples: { scamCommerce: ["nap lau", "ma the", "robux"] }
});
assert.equal(commerceArticleContentSafety.detected, false);

const gameMarketplaceStaticSignals = summarizeHtml(`
  <title>Shop Acc Valorant Văn Mạnh</title>
  <h1>Mua bán tài khoản Valorant và dịch vụ game</h1>
  <nav>
    <a href="/nap-tien">Nạp tiền</a>
    <a href="https://zalo.me/example">Zalo hỗ trợ</a>
    <a href="https://discord.gg/example">Discord community</a>
  </nav>
  <a href="/acc-valorant">Mua acc Valorant</a>
  <a href="/cay-rank">Cày rank Valorant</a>
  <p>ACC tự chọn Deadmail, Dropmail, giao mail gốc, hỗ trợ back acc, chuyển vùng và check skin.</p>
  <p>Giao dịch nhanh, trả góp và chính sách bảo hành tài khoản.</p>
`, { url: "https://shopvanmanh.example/" });
assert.equal(gameMarketplaceStaticSignals.staticContent.level, "WARNING");
assert.ok(gameMarketplaceStaticSignals.staticContent.findings.some(item => item.id === "GAME_COMMERCE"));

const officialGameStoreStaticSignals = summarizeHtml(`
  <title>Riot Games Valorant account services</title>
  <h1>Valorant account, skin game and rank support</h1>
  <a href="/top-up">Nạp tiền</a>
  <a href="https://discord.gg/riotgames">Discord</a>
  <a href="https://facebook.com/riotgames">Facebook</a>
  <p>Account Valorant, kho skin, check skin, giao dịch và bảo hành.</p>
`, { url: "https://support.riotgames.com/" });
assert.ok(!officialGameStoreStaticSignals.staticContent.findings.some(item => item.id === "GAME_COMMERCE"));

const gameCommerceArticleStaticSignals = summarizeHtml(`
  <article>
    <h1>Cảnh báo khi mua bán tài khoản Valorant</h1>
    <p>Bài viết giải thích rủi ro của acc tự chọn, deadmail, dropmail, back acc, cày thuê, Zalo và Discord.</p>
    <p>Không nên nạp tiền, chuyển khoản hoặc giao dịch trước khi kiểm tra chính sách bảo hành.</p>
  </article>
`, { url: "https://security.example/articles/game-account-scams" });
assert.ok(!gameCommerceArticleStaticSignals.staticContent.findings.some(item => item.id === "GAME_COMMERCE"));

const gameMarketplaceContentSafety = analyzeContentSafety({
  gameMarketplaceHitCount: 9,
  gameTransactionHitCount: 4,
  gameOffPlatformContactCount: 5,
  gameCommerceActionCount: 3,
  gameCommerceBrandMismatch: true,
  gameCommerceOfficialBrand: false,
  gameCommerceBrandName: "Riot Games",
  contentSamples: { gameCommerce: ["acc tu chon", "deadmail", "dropmail", "nap tien", "giao dich"] }
});
assert.equal(gameMarketplaceContentSafety.level, "WARNING");
assert.ok(gameMarketplaceContentSafety.categories.some(item => item.id === "GAME_COMMERCE"));
assert.ok(gameMarketplaceContentSafety.categories.find(item => item.id === "GAME_COMMERCE").score <= 70);

const officialGameContentSafety = analyzeContentSafety({
  gameMarketplaceHitCount: 9,
  gameTransactionHitCount: 4,
  gameOffPlatformContactCount: 5,
  gameCommerceActionCount: 3,
  gameCommerceBrandMismatch: false,
  gameCommerceOfficialBrand: true,
  gameCommerceBrandName: "Riot Games",
  contentSamples: { gameCommerce: ["acc valorant", "skin game"] }
});
assert.ok(!officialGameContentSafety.categories.some(item => item.id === "GAME_COMMERCE"));

const partialGameAssessment = buildEvidenceAssessment({
  domain: "shopvanmanh.example",
  registrableDomain: "shopvanmanh.example",
  risk: {
    level: "SAFE",
    score: 0,
    confidenceScore: 26,
    identityStatus: { code: "UNVERIFIED", label: "Chưa xác minh" }
  },
  contentSafety: gameMarketplaceContentSafety,
  rdapMeta: { available: false, skipped: false },
  mlInfo: { available: true, probability: 0.08 },
  redirectInfo: { hopCount: 1, crossDomainCount: 0 },
  threatInfo: { checked: false, skipped: false },
  settings: { analyzePage: true, urlModelEnabled: true, redirectAnalysis: true }
});
assert.equal(partialGameAssessment.status, "PARTIAL");
assert.equal(partialGameAssessment.riskState, "UNDETERMINED");
assert.equal(partialGameAssessment.evidenceScore, 26);
assert.ok(partialGameAssessment.missingLayers.some(item => item.id === "IDENTITY"));
assert.equal(partialGameAssessment.contextAdvisory.id, "GAME_COMMERCE");
assert.equal(isRiskUndetermined({ evidenceAssessment: partialGameAssessment }), true);

const completeKnownAssessment = buildEvidenceAssessment({
  domain: "example.com",
  risk: {
    level: "SAFE",
    score: 2,
    confidenceScore: 88,
    identityStatus: { code: "ESTABLISHED_DOMAIN", label: "Domain lâu năm" }
  },
  contentSafety: { available: true, detected: false, categories: [] },
  rdapMeta: { available: true, skipped: false },
  ageInfo: { ageDays: 9000 },
  mlInfo: { available: true, probability: 0.01 },
  redirectInfo: { hopCount: 1, crossDomainCount: 0 },
  threatInfo: { checked: false, skipped: false },
  settings: { analyzePage: true, urlModelEnabled: true, redirectAnalysis: true }
});
assert.equal(completeKnownAssessment.status, "COMPLETE");
assert.equal(completeKnownAssessment.riskState, "DETERMINED");
assert.equal(completeKnownAssessment.safeDisplayState, "CONFIDENT");
assert.equal(isRiskUndetermined({ evidenceAssessment: completeKnownAssessment }), false);
assert.equal(completeKnownAssessment.checkedLayers.find(item => item.id === "URL_ML")?.label, "Cấu trúc địa chỉ website");
assert.equal(completeKnownAssessment.missingLayers.find(item => item.id === "THREAT_INTEL")?.label, "Nguồn uy tín bên ngoài");
const lowEvidenceKnownAssessment = buildEvidenceAssessment({
  domain: "bing.com",
  risk: {
    level: "SAFE",
    score: 0,
    confidenceScore: 26,
    identityStatus: { code: "KNOWN_DOMAIN", label: "Domain phổ biến" }
  },
  contentSafety: { available: true, detected: false, categories: [] },
  rdapMeta: { available: true, skipped: false },
  ageInfo: { ageDays: 9000 },
  mlInfo: { available: true, probability: 0.01 },
  redirectInfo: { hopCount: 1, crossDomainCount: 0 },
  threatInfo: { checked: false, skipped: false },
  settings: { analyzePage: true, urlModelEnabled: true, redirectAnalysis: true }
});
assert.equal(lowEvidenceKnownAssessment.status, "COMPLETE");
assert.equal(lowEvidenceKnownAssessment.riskState, "DETERMINED");
assert.equal(lowEvidenceKnownAssessment.safeDisplayState, "CAUTION");
assert.match(lowEvidenceKnownAssessment.summary, /chất lượng bằng chứng còn thấp/i);

const strongPaymentPageSignals = {
  paymentIntegration: {
    detected: true,
    confidence: "STRONG",
    score: 100,
    providers: [
      { id: "ZALOPAY", label: "ZaloPay", evidence: ["logo-or-text", "provider-resource-domain"] },
      { id: "VIETQR", label: "VietQR", evidence: ["logo-or-text"] }
    ],
    context: {
      paymentContext: true,
      interactiveControlCount: 4,
      hasPaymentAction: true,
      hasAmountOrCurrency: true
    }
  }
};
const moderatePaymentAssessment = buildEvidenceAssessment({
  domain: "publisher.example",
  risk: {
    level: "SAFE",
    score: 0,
    confidenceScore: 26,
    identityStatus: { code: "MODERATELY_ESTABLISHED", label: "Domain đã hoạt động hơn một năm" }
  },
  contentSafety: { available: true, detected: false, categories: [] },
  pageSignals: strongPaymentPageSignals,
  rdapMeta: { available: true, skipped: false },
  ageInfo: { ageDays: 420 },
  mlInfo: { available: true, probability: 0.12 },
  redirectInfo: { hopCount: 1, crossDomainCount: 0 },
  threatInfo: { checked: false, skipped: false, isUnsafe: false },
  listStatus: { blacklisted: false, knownDomain: false, whitelisted: false },
  settings: { analyzePage: true, urlModelEnabled: true, redirectAnalysis: true }
});
assert.equal(moderatePaymentAssessment.status, "COMPLETE");
assert.equal(moderatePaymentAssessment.paymentEvidenceEligible, true);
assert.equal(moderatePaymentAssessment.paymentEvidenceBoost, 20);
assert.equal(moderatePaymentAssessment.evidenceScore, 46);
assert.equal(moderatePaymentAssessment.safeDisplayState, "CONFIDENT");
assert.ok(!moderatePaymentAssessment.missingLayers.some(item => item.id === "IDENTITY"));

const rdapUnavailablePaymentAssessment = buildEvidenceAssessment({
  domain: "merchant.example",
  risk: {
    level: "SAFE",
    score: 0,
    confidenceScore: 14,
    identityStatus: { code: "UNVERIFIED", label: "Chưa xác minh" }
  },
  contentSafety: { available: true, detected: false, categories: [] },
  pageSignals: strongPaymentPageSignals,
  rdapMeta: { available: false, skipped: false },
  mlInfo: { available: true, probability: 0.11 },
  redirectInfo: { hopCount: 1, crossDomainCount: 0 },
  threatInfo: { checked: false, skipped: false, isUnsafe: false },
  listStatus: { blacklisted: false, knownDomain: false, whitelisted: false },
  settings: { analyzePage: true, urlModelEnabled: true, redirectAnalysis: true }
});
assert.equal(rdapUnavailablePaymentAssessment.status, "PARTIAL");
assert.equal(rdapUnavailablePaymentAssessment.riskState, "PROVISIONAL");
assert.equal(rdapUnavailablePaymentAssessment.safeDisplayState, "CONFIDENT");
assert.equal(rdapUnavailablePaymentAssessment.coverageExecutionFloor, 25);
assert.equal(rdapUnavailablePaymentAssessment.paymentEvidenceBoost, 20);
assert.equal(rdapUnavailablePaymentAssessment.evidenceScore, 45);
assert.equal(rdapUnavailablePaymentAssessment.label, "BẰNG CHỨNG HỖ TRỢ TỐT");
assert.ok(rdapUnavailablePaymentAssessment.missingLayers.some(item => item.id === "IDENTITY"));

const blockedPaymentAssessment = buildEvidenceAssessment({
  domain: "zal0pay.example",
  risk: {
    level: "HIGH",
    score: 80,
    confidenceScore: 90,
    identityStatus: { code: "NEW_DOMAIN", label: "Domain mới" }
  },
  contentSafety: { available: true, detected: false, categories: [] },
  pageSignals: strongPaymentPageSignals,
  rdapMeta: { available: true, skipped: false },
  ageInfo: { ageDays: 5 },
  mlInfo: { available: true, probability: 0.95 },
  redirectInfo: { hopCount: 1, crossDomainCount: 0 },
  threatInfo: { checked: false, skipped: false, isUnsafe: false },
  listStatus: { blacklisted: false, knownDomain: false, whitelisted: false },
  settings: { analyzePage: true, urlModelEnabled: true, redirectAnalysis: true }
});
assert.equal(blockedPaymentAssessment.paymentEvidenceEligible, false);
assert.equal(blockedPaymentAssessment.paymentEvidenceBoost, 0);
assert.ok(blockedPaymentAssessment.paymentEvidenceBlockers.includes("risk-not-safe"));

const fakeGatewayDomainInfo = getDomainParts("zal0pay.example");
const fakeGatewayTypo = findSimilarDomain("zal0pay.example", paymentTypoReferences, {
  exactBrandLabels: protectedPaymentDomains
});
const fakeGatewayRiskInput = {
  url: "https://zal0pay.example/checkout",
  domain: "zal0pay.example",
  domainInfo: fakeGatewayDomainInfo,
  ageInfo: { ageDays: 5 },
  typoMatch: fakeGatewayTypo,
  homoglyphInfo: { isPunycode: false, hasHomoglyph: false, decodeFailed: false, displayDomain: "zal0pay.example" },
  isBlacklisted: false,
  isWhitelisted: false,
  isKnownDomain: false,
  redirectInfo: { hopCount: 1, crossDomainCount: 0 },
  threatInfo: { checked: false, isUnsafe: false, threats: [] },
  mlInfo: { available: true, probability: 0.95, threshold: model.threshold, prediction: "PHISHING", modelVersion: model.modelVersion },
  siteContext: classifySiteContext("https://zal0pay.example/checkout")
};
const fakeGatewayRiskWithoutLogos = calculateRisk({ ...fakeGatewayRiskInput, pageSignals: null });
const fakeGatewayRiskWithLogos = calculateRisk({ ...fakeGatewayRiskInput, pageSignals: strongPaymentPageSignals });
assert.equal(fakeGatewayRiskWithoutLogos.level, "HIGH");
assert.equal(fakeGatewayRiskWithLogos.level, fakeGatewayRiskWithoutLogos.level);
assert.equal(fakeGatewayRiskWithLogos.score, fakeGatewayRiskWithoutLogos.score);
assert.equal(fakeGatewayRiskWithLogos.binaryPrediction, fakeGatewayRiskWithoutLogos.binaryPrediction);
const preflightCoverageAssessment = buildEvidenceAssessment({
  mode: "preflight",
  domain: "example.com",
  risk: {
    level: "SAFE",
    score: 0,
    confidenceScore: 80,
    identityStatus: { code: "ESTABLISHED_DOMAIN", label: "Domain lâu năm" }
  },
  contentSafety: { available: true, detected: false, categories: [] },
  rdapMeta: { available: true },
  mlInfo: { available: true, probability: 0.01 },
  threatInfo: { checked: true, isUnsafe: false },
  settings: { analyzePage: true, urlModelEnabled: true }
});
assert.equal(preflightCoverageAssessment.checkedLayers.find(item => item.id === "STATIC_CONTENT")?.label, "Nội dung xem trước giới hạn");
assert.equal(preflightCoverageAssessment.checkedLayers.find(item => item.id === "THREAT_INTEL")?.label, "Nguồn uy tín bên ngoài");
const downloadFinding = classifyDownloadRisk({
  url: "https://example.com/setup.exe",
  contentType: "application/octet-stream",
  contentDisposition: "attachment; filename=setup.exe",
  htmlSignals: linkLabSignals
});
assert.equal(downloadFinding.level, "HIGH");
const safeRisk = { level: "SAFE", score: 4, confidenceScore: 80 };
const forbiddenVerdict = buildPreflightVerdict(safeRisk, {
  reachable: true,
  ok: false,
  status: 403,
  htmlSignals: summarizeHtml("Forbidden"),
  downloadRisk: { level: "NONE" }
});
assert.equal(forbiddenVerdict.level, "SUSPICIOUS");
assert.ok(forbiddenVerdict.reasons.some(reason => reason.includes("HTTP 403")));
const downloadVerdict = buildPreflightVerdict(safeRisk, {
  reachable: true,
  downloadRisk: { level: "HIGH" }
});
assert.equal(downloadVerdict.level, "HIGH");
assert.ok(downloadVerdict.score >= 75);
const probeRequests = [];
const probeResult = await probeUrlNetwork("https://start.example/check", async (url, options) => {
  probeRequests.push({ url, options });
  if (url === "https://start.example/check") {
    return new Response(null, {
      status: 302,
      headers: { Location: "https://final.example/login" }
    });
  }
  return new Response(`<form><input type="password"></form>${"x".repeat(70 * 1024)}`, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
});
assert.equal(probeRequests.length, 2);
assert.equal(probeRequests[0].options.credentials, "omit");
assert.equal(probeRequests[0].options.referrerPolicy, "no-referrer");
assert.equal(probeResult.redirectCount, 1);
assert.equal(probeResult.finalUrl, "https://final.example/login");
assert.equal(probeResult.htmlSignals.passwordInputCount, 1);
assert.equal(probeResult.truncated, true);

const redirectLoopRequests = [];
const redirectLoopProbe = await probeUrlNetwork("https://loop.example/a", async url => {
  redirectLoopRequests.push(url);
  return new Response(null, {
    status: 302,
    headers: { Location: url.endsWith("/a") ? "/b" : "/a" }
  });
});
assert.equal(redirectLoopRequests.length, 2);
assert.equal(redirectLoopProbe.reachable, false);
assert.equal(redirectLoopProbe.redirectCount, 2);
assert.equal(redirectLoopProbe.redirectAnomaly?.type, "LOOP");
const redirectLoopVerdict = buildPreflightVerdict(safeRisk, redirectLoopProbe);
assert.equal(redirectLoopVerdict.level, "SUSPICIOUS");
assert.ok(redirectLoopVerdict.score >= 28);
assert.ok(redirectLoopVerdict.reasons.some(reason => reason.includes("vòng lặp chuyển hướng")));

const oauthUrl = "https://accounts.google.com/o/oauth2/v2/auth?client_id=demo&redirect_uri=https%3A%2F%2Ffeid.fpt.edu.vn%2Fcallback&response_type=code";
assert.equal(isTrustedIdentityProviderUrl(oauthUrl)?.providerName, "Google");

const oauthFlow = analyzeFederatedAuthRedirect("https://feid.fpt.edu.vn/Account/Login", oauthUrl, getDomainParts);
assert.equal(oauthFlow.isFederatedAuthFlow, true);
assert.equal(oauthFlow.relyingPartyDomain, "fpt.edu.vn");

const oauthDomain = getDomainParts("accounts.google.com");
const oauthRisk = calculateRisk({
  url: oauthUrl,
  domain: "accounts.google.com",
  domainInfo: oauthDomain,
  ageInfo: { ageDays: 9000 },
  typoMatch: null,
  homoglyphInfo: { isPunycode: false, hasHomoglyph: false, decodeFailed: false, displayDomain: "accounts.google.com" },
  isBlacklisted: false,
  isWhitelisted: false,
  isKnownDomain: true,
  pageSignals: null,
  redirectInfo: { hopCount: 1, crossDomainCount: 1, isFederatedAuthFlow: true },
  threatInfo: { checked: false, isUnsafe: false, threats: [] },
  mlInfo: { available: true, probability: 1, threshold: model.threshold, prediction: "PHISHING", modelVersion: model.modelVersion }
});
assert.equal(oauthRisk.binaryPrediction, "SAFE");
assert.ok(oauthRisk.score <= 8);
assert.equal(oauthRisk.breakdown.network, 0);

const samplePrediction = predictWithModel(model, "https://recoveries-coinbase.com/login", getDomainParts("recoveries-coinbase.com"));
assert.equal(samplePrediction.available, true);
assert.equal(samplePrediction.modelVersion, "url-logistic-5.0.0");
assert.equal(samplePrediction.prediction, "PHISHING");

const tiktokUrl = "https://www.tiktok.com/@brainrotdepot1?_r=1&_t=ZS-98kQwnShntt";
const tiktokDomain = getDomainParts("tiktok.com");
const tiktokFeatures = extractUrlMlFeatures(tiktokUrl, tiktokDomain);
const tiktokPrediction = predictWithModel(model, tiktokUrl, tiktokDomain);
assert.equal(tiktokFeatures.values.hasCredentials, 0);
assert.equal(tiktokPrediction.prediction, "SAFE");
assert.ok(tiktokPrediction.probability < 0.05);
const tiktokRisk = calculateRisk({
  url: tiktokUrl,
  domain: "tiktok.com",
  domainInfo: tiktokDomain,
  ageInfo: { ageDays: 11000 },
  typoMatch: null,
  homoglyphInfo: { isPunycode: false, hasHomoglyph: false, decodeFailed: false, displayDomain: "tiktok.com" },
  isBlacklisted: false,
  isWhitelisted: false,
  isKnownDomain: true,
  mlInfo: tiktokPrediction,
  siteContext: classifySiteContext(tiktokUrl)
});
assert.equal(tiktokRisk.urlSignals.containsAtSymbol, false);
assert.equal(tiktokRisk.level, "SAFE");
assert.equal(tiktokRisk.presentation.shouldWarnOnPage, false);

const userInfoUrl = "http://paypal.com@secure-wallet-update.xyz/login";
const userInfoDomain = getDomainParts("secure-wallet-update.xyz");
assert.equal(extractUrlMlFeatures(userInfoUrl, userInfoDomain).values.hasCredentials, 1);

const articleBrandFeatures = extractUrlMlFeatures(
  "https://example.com/articles/how-paypal-protects-accounts",
  getDomainParts("example.com")
);
assert.equal(articleBrandFeatures.values.brandTokenMismatch, 0);

const localContext = classifySiteContext("http://localhost:20128/dashboard/combos");
assert.equal(localContext.type, SITE_CONTEXT_TYPES.LOCAL_DEVELOPMENT);
assert.equal(classifySiteContext("http://127.0.0.1:8080/").type, SITE_CONTEXT_TYPES.LOCAL_DEVELOPMENT);
assert.equal(classifySiteContext("http://192.168.1.1/admin").type, SITE_CONTEXT_TYPES.PRIVATE_NETWORK);
assert.equal(classifySiteContext("http://[fd00::1]/admin").type, SITE_CONTEXT_TYPES.PRIVATE_NETWORK);
assert.equal(classifySiteContext("https://[2001:4860:4860::8888]/").type, SITE_CONTEXT_TYPES.PUBLIC_WEB);
assert.equal(classifySiteContext("https://www.tiktok.com/").type, SITE_CONTEXT_TYPES.PUBLIC_WEB);

const localRisk = calculateRisk({
  url: "http://localhost:20128/dashboard/combos",
  domain: "localhost",
  domainInfo: getDomainParts("localhost"),
  ageInfo: null,
  typoMatch: null,
  homoglyphInfo: { isPunycode: false, hasHomoglyph: false, decodeFailed: false, displayDomain: "localhost" },
  isBlacklisted: false,
  isWhitelisted: false,
  isKnownDomain: false,
  pageSignals: null,
  redirectInfo: null,
  threatInfo: { checked: false, skipped: true, isUnsafe: false, threats: [] },
  mlInfo: { available: false, skipped: true, probability: 0, prediction: "NOT_APPLICABLE" },
  siteContext: localContext
});
assert.equal(localRisk.score, 0);
assert.equal(localRisk.level, "SAFE");
assert.equal(localRisk.identityStatus.code, "LOCAL_DEVELOPMENT");
assert.equal(localRisk.presentation.shouldWarnOnPage, false);
assert.ok(!localRisk.reasons.some(reason => reason.includes("không sử dụng HTTPS")));

const mlOnlyRisk = calculateRisk({
  url: "https://unverified-example-domain.com/a-very-long-but-benign-looking-path",
  domain: "unverified-example-domain.com",
  domainInfo: getDomainParts("unverified-example-domain.com"),
  ageInfo: null,
  typoMatch: null,
  homoglyphInfo: null,
  isBlacklisted: false,
  isWhitelisted: false,
  mlInfo: { available: true, probability: 0.99, threshold: model.threshold, prediction: "PHISHING", modelVersion: model.modelVersion }
});
assert.equal(mlOnlyRisk.binaryPrediction, "SAFE");
assert.equal(mlOnlyRisk.level, "SUSPICIOUS");
assert.equal(mlOnlyRisk.presentation.tier, "BADGE_ADVISORY");
assert.equal(mlOnlyRisk.presentation.shouldWarnOnPage, false);

const hopAmChuanUrl = "https://hopamchuan.com/song/57692/muon-em-la-cua-rieng-minh/?s=1";
const hopAmChuanDomain = getDomainParts("hopamchuan.com");
const hopAmChuanPrediction = predictWithModel(model, hopAmChuanUrl, hopAmChuanDomain);
assert.equal(hopAmChuanPrediction.prediction, "SAFE");
assert.ok(hopAmChuanPrediction.probability < 0.20);

const cappedLegitRisk = calculateRisk({
  url: hopAmChuanUrl,
  domain: "hopamchuan.com",
  domainInfo: hopAmChuanDomain,
  ageInfo: { ageDays: 4843 },
  typoMatch: null,
  homoglyphInfo: { isPunycode: false, hasHomoglyph: false, decodeFailed: false, displayDomain: "hopamchuan.com" },
  isBlacklisted: false,
  isWhitelisted: false,
  isKnownDomain: true,
  pageSignals: null,
  redirectInfo: null,
  threatInfo: { checked: false, isUnsafe: false, threats: [] },
  mlInfo: { available: true, probability: 0.97, threshold: model.threshold, prediction: "PHISHING", modelVersion: model.modelVersion }
});
assert.equal(cappedLegitRisk.binaryPrediction, "SAFE");
assert.ok(cappedLegitRisk.score <= 8);
assert.ok(cappedLegitRisk.reasons.some(reason => reason.includes("không dùng để kết luận phishing")));
assert.ok(!cappedLegitRisk.reasons.some(reason => reason.includes("rất giống mẫu phishing")));

const sleeperDomainUrl = "https://seasoned-wallet.example/verify/account/payment";
const sleeperDomainInfo = getDomainParts("seasoned-wallet.example");
const sleeperDomainRisk = calculateRisk({
  url: sleeperDomainUrl,
  domain: "seasoned-wallet.example",
  domainInfo: sleeperDomainInfo,
  ageInfo: { ageDays: 420 },
  typoMatch: null,
  homoglyphInfo: { isPunycode: false, hasHomoglyph: false, decodeFailed: false, displayDomain: "seasoned-wallet.example" },
  isBlacklisted: false,
  isWhitelisted: false,
  isKnownDomain: false,
  pageSignals: null,
  redirectInfo: null,
  threatInfo: { checked: false, isUnsafe: false, threats: [] },
  mlInfo: { available: true, probability: 0.97, threshold: model.threshold, prediction: "PHISHING", modelVersion: model.modelVersion },
  siteContext: classifySiteContext(sleeperDomainUrl)
});
assert.equal(sleeperDomainRisk.identityStatus.code, "MODERATELY_ESTABLISHED");
assert.equal(sleeperDomainRisk.breakdown.mlReduction, 0);
assert.ok(sleeperDomainRisk.score > 8);
assert.ok(!sleeperDomainRisk.reasons.some(reason => reason.includes("domain đã biết/lâu năm")));

const steamMatch = findSimilarDomain("steamcommunity.asia", ["steamcommunity.com", "steampowered.com"]);
assert.equal(steamMatch?.exactBrandDifferentSuffix, true);
assert.equal(steamMatch?.closest, "steamcommunity.com");
assert.equal(findSimilarDomain("microsoft.co.uk", ["microsoft.com"]), null);

const steamUrl = "https://steamcommunity.asia/76482b527f0700555252547e57535a5765510151";
const steamDomainInfo = getDomainParts("steamcommunity.asia");
const steamMl = predictWithModel(model, steamUrl, steamDomainInfo);
const steamRisk = calculateRisk({
  url: steamUrl,
  domain: "steamcommunity.asia",
  domainInfo: steamDomainInfo,
  ageInfo: null,
  typoMatch: steamMatch,
  homoglyphInfo: { isPunycode: false, hasHomoglyph: false, decodeFailed: false, displayDomain: "steamcommunity.asia" },
  isBlacklisted: false,
  isWhitelisted: false,
  pageSignals: { passwordInputCount: 1, externalPasswordFormCount: 0, externalIframeCount: 0, externalScriptCount: 5, riskyDownloadLinkCount: 0, hasUrgencyText: false, brandMismatch: true, brandName: "Steam" },
  redirectInfo: null,
  threatInfo: { checked: false, isUnsafe: false, threats: [] },
  mlInfo: steamMl
});
assert.equal(steamRisk.binaryPrediction, "PHISHING");
assert.equal(steamRisk.level, "HIGH");
assert.ok(steamRisk.score >= 70);

const blacklistedRisk = calculateRisk({
  url: "https://malicious.example/login",
  domain: "malicious.example",
  domainInfo: getDomainParts("malicious.example"),
  ageInfo: null,
  typoMatch: null,
  homoglyphInfo: null,
  isBlacklisted: true,
  isWhitelisted: false
});
assert.equal(blacklistedRisk.level, "HIGH");
assert.equal(blacklistedRisk.score, 100);

console.log("release tests: PASS (v2.7.5 GUI, game-brand rules, official-claim mismatch, paired discrimination)");
