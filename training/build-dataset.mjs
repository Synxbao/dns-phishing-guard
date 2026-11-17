import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { extractUrlMlFeatures, FEATURE_NAMES } from "../modules/url-ml-features.js";
import { getDomainParts, initializeFromText } from "../modules/public-suffix.js";

const releaseRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outputDir = path.join(releaseRoot, "training", "data");
const sourceDir = path.join(releaseRoot, "training", "source");
const FEATURE_VERSION = "url-lexical-v4";

const BENIGN_COUNTERFACTUAL_TEMPLATES = [
  "/@sample_creator_2026?_r=1&_t=example123&utm_source=profile",
  "/news/2026/08/security-awareness-guide?utm_source=newsletter&ref=homepage",
  "/products/wireless-headphones/model-x200?color=black&campaign=summer&ref=search",
  "/users/demo-profile-2026/posts/how-to-protect-your-account?share=1",
  "/dashboard/projects/550e8400-e29b-41d4-a716-446655440000/settings?tab=members",
  "/search?q=how+to+identify+phishing&page=2&sort=relevance",
  "/login?return_to=%2Faccount%2Fsettings%2Fsecurity&source=header",
  "/download/reports/annual-security-review.pdf?source=portal&lang=en",
  "/watch?v=dQw4w9WgXcQ&feature=share&utm_medium=social",
  "/vi-vn/help/account/recovery-and-password-security/index.html?ref=support",
  "/support/kb/article.php?id=12345&lang=en&ref=help-center",
  "/portal/Account/Profile.aspx?tab=security&ReturnUrl=%2Fhome",
  "/docs/reference/index.jsp?section=authentication&page=2",
  "/api/v2/share/7f3a16b8-6cf1-4df2-8c21-0e7b13a1249f?view=public",
  "/articles/technology/why-long-descriptive-paths-are-normal-on-modern-websites?page=3"
];

const sourceFiles = {
  benignUser: path.join(sourceDir, "benign_urls_1000.txt"),
  phishingUser: path.join(sourceDir, "phishing_urls_1000.txt"),
  tranco: path.join(sourceDir, "tranco-top-5000.csv"),
  openphish: path.join(sourceDir, "openphish-feed-2026-08-10.txt"),
  urlhaus: path.join(sourceDir, "urlhaus-recent-2026-08-10.csv")
};

function normalizeUrl(rawValue) {
  try {
    const parsed = new URL(String(rawValue || "").trim());
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    parsed.hash = "";
    parsed.hostname = parsed.hostname.toLowerCase();
    return parsed.href;
  } catch {
    return null;
  }
}

function csvCell(value) {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function sourceRecord(url, label, source, sourceType) {
  const parsed = new URL(url);
  const hostname = parsed.hostname.toLowerCase().replace(/^www\./, "");
  const domainInfo = getDomainParts(hostname);
  const extracted = extractUrlMlFeatures(url, domainInfo);
  if (!extracted) return null;
  return {
    url,
    label,
    actual: label ? "MALICIOUS" : "SAFE",
    source,
    sourceType,
    hostname,
    registrableDomain: domainInfo.registrableDomain || hostname,
    publicSuffix: domainInfo.publicSuffix || "",
    features: extracted.values,
    featureVector: extracted.featureVector
  };
}

function addUnique(records, seenUrls, rawUrl, label, source, sourceType, blockedDomains = null) {
  const url = normalizeUrl(rawUrl);
  if (!url || seenUrls.has(url)) return false;
  const record = sourceRecord(url, label, source, sourceType);
  if (!record || blockedDomains?.has(record.registrableDomain)) return false;
  seenUrls.add(url);
  records.push(record);
  return true;
}

function enrichBenignCandidates(records) {
  const seen = new Set();
  let counterfactualCount = 0;
  const enriched = records.map((record, index) => {
    let candidate = record;
    // Forty percent of benign candidates receive realistic path/query shapes so
    // the independent domain-separated holdout is not a root-URL-only test.
    if (index % 5 < 2) {
      const template = BENIGN_COUNTERFACTUAL_TEMPLATES[index % BENIGN_COUNTERFACTUAL_TEMPLATES.length];
      const parsed = new URL(template, new URL(record.url).origin);
      if (index % 8 === 0) parsed.protocol = "http:";
      const generated = sourceRecord(
        parsed.href,
        0,
        `${record.source}-counterfactual`,
        "benign-counterfactual"
      );
      if (generated && !seen.has(generated.url)) {
        candidate = generated;
        counterfactualCount += 1;
      }
    }
    if (seen.has(candidate.url)) candidate = record;
    seen.add(candidate.url);
    return candidate;
  });
  return { records: enriched, counterfactualCount };
}

const sourceBuffers = {};
for (const [name, file] of Object.entries(sourceFiles)) {
  sourceBuffers[name] = await fs.readFile(file);
}
initializeFromText(await fs.readFile(path.join(releaseRoot, "data", "public_suffix_list.dat"), "utf8"));

const safe = [];
const safeSeen = new Set();
for (const line of sourceBuffers.benignUser.toString("utf8").split(/\r?\n/)) {
  addUnique(safe, safeSeen, line, 0, "user-benign-1000", "benign-candidate");
}

for (const line of sourceBuffers.tranco.toString("utf8").split(/\r?\n/)) {
  if (safe.length >= 2000) break;
  const comma = line.indexOf(",");
  if (comma < 0) continue;
  const domain = line.slice(comma + 1).trim().toLowerCase();
  if (!domain || domain.includes("/") || domain.includes(" ")) continue;
  addUnique(safe, safeSeen, `https://${domain}/`, 0, "tranco-top-sites", "benign-candidate");
}

if (safe.length !== 2000) throw new Error(`Không tạo đủ 2.000 URL sạch: ${safe.length}`);
const enrichedSafe = enrichBenignCandidates(safe);
safe.splice(0, safe.length, ...enrichedSafe.records);
const safeDomains = new Set(safe.map(item => item.registrableDomain));

const malicious = [];
const maliciousSeen = new Set();
for (const line of sourceBuffers.phishingUser.toString("utf8").split(/\r?\n/)) {
  addUnique(malicious, maliciousSeen, line, 1, "user-phishing-1000", "phishing", safeDomains);
}
for (const line of sourceBuffers.openphish.toString("utf8").split(/\r?\n/)) {
  if (malicious.length >= 1400) break;
  addUnique(malicious, maliciousSeen, line, 1, "openphish-2026-08-10", "phishing", safeDomains);
}
for (const line of sourceBuffers.urlhaus.toString("utf8").split(/\r?\n/)) {
  if (malicious.length >= 2000) break;
  if (!line.startsWith('"')) continue;
  const match = line.match(/^"[^"]*","[^"]*","([^"]+)"/);
  if (!match) continue;
  addUnique(malicious, maliciousSeen, match[1], 1, "urlhaus-recent-2026-08-10", "malware-download", safeDomains);
}

if (malicious.length !== 2000) throw new Error(`Không tạo đủ 2.000 URL độc hại: ${malicious.length}`);

const records = [...safe, ...malicious].map((item, index) => ({
  id: `${item.label ? "malicious" : "safe"}-${String(index + 1).padStart(4, "0")}`,
  ...item
}));

const hardNegativeUrls = [
  "https://www.tiktok.com/@brainrotdepot1?_r=1&_t=ZS-98kQwnShntt",
  "https://www.tiktok.com/@scout2015/video/6718335390845095173?lang=en&utm_source=copy",
  "https://www.youtube.com/@OpenAI/videos?view=0&sort=dd&shelf_id=0",
  "https://www.youtube.com/watch?v=dQw4w9WgXcQ&si=example123&feature=shared",
  "https://www.instagram.com/p/C8Example123/?igsh=example_tracking_value",
  "https://x.com/OpenAI/status/1823094818459341136?s=20&t=example",
  "https://github.com/openai/openai-python/blob/main/src/openai/resources/chat/completions/completions.py#L100",
  "https://www.amazon.com/dp/B0D1234567?ref_=ast_sto_dp&th=1&psc=1",
  "https://shopee.vn/product/123456789/9876543210?utm_campaign=share_product&utm_medium=seller",
  "https://en.wikipedia.org/wiki/Uniform_Resource_Locator#Syntax",
  "https://www.reddit.com/r/cybersecurity/comments/1example/how_do_you_validate_suspicious_links/",
  "https://docs.google.com/document/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit?usp=sharing",
  "https://drive.google.com/file/d/1A2B3C4D5E6F7G8H9I0J/view?usp=drive_link",
  "https://maps.google.com/maps?f=q&source=s_q&hl=en&geocode=&q=security+conference",
  "https://accounts.google.com/o/oauth2/v2/auth?client_id=demo.apps.googleusercontent.com&redirect_uri=https%3A%2F%2Ffeid.fpt.edu.vn%2Fsignin-google&response_type=code&scope=openid%20email",
  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=demo&redirect_uri=https%3A%2F%2Fexample.edu.vn%2Fcallback&response_type=code&scope=openid",
  "https://appleid.apple.com/auth/authorize?client_id=com.example.web&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&response_type=code&scope=name%20email",
  "https://www.bing.com/search?q=phishing+awareness&utm_source=training&cvid=demo123",
  "https://github.com/login?return_to=%2Fsettings%2Fsecurity",
  "https://dash.cloudflare.com/login?redirect_url=%2Fexample.com%2Fsecurity",
  "https://feid.fpt.edu.vn/Account/Login?ReturnUrl=%2Fconnect%2Fauthorize%2Fcallback%3Fclient_id%3Dfap",
  "https://steamcommunity.com/account/settings/profile?tab=privacy&ref=header",
  "https://www.chess.com/play/online/new?opponent=demo-user",
  "https://www.microsoft.com/vi-vn/microsoft-365?rtc=1",
  "https://hopamchuan.com/song/57692/muon-em-la-cua-rieng-minh/?s=1",
  "https://hopamchuan.com/song/57692/muon-em-la-cua-rieng-minh/",
  "https://hopamchuan.com/song/57692/muon-em-la-cua-rieng-minh/tiendat170197?s=1",
  "https://hopamchuan.com/song/57692/muon-em-la-cua-rieng-minh/BemIuuEm?s=1",
  "https://hopamchuan.com/song/43377/muon-em-la-cua-rieng-minh-tinh-dang-nhu-ly-ca-phe-vuong-mashup/?s=1"
];
const hardNegativeTemplates = [
  "/account/settings/profile?tab=security&return_url=%2Fdashboard&utm_source=training",
  "/search?q=account+security&page=2&session=demo123456&utm_campaign=help",
  "/@community_member_2026/posts/550e8400-e29b-41d4-a716-446655440000?ref=profile",
  "/products/category/model-2026-long-descriptive-name?variant=black&currency=VND&source=ads",
  "/help/login-and-account-recovery/index.aspx?return_url=%2Fdashboard%2Fsecurity"
];
for (const item of safe.slice(0, 90)) {
  const origin = new URL(item.url).origin;
  for (const template of hardNegativeTemplates) hardNegativeUrls.push(`${origin}${template}`);
}
const hardNegativeRecords = [];
const hardNegativeSeen = new Set();
for (const rawUrl of hardNegativeUrls) {
  addUnique(hardNegativeRecords, hardNegativeSeen, rawUrl, 0, "generated-hard-negative", "hard-negative");
}
const sourceCounts = Object.fromEntries(
  [...new Set(records.map(item => item.source))].map(source => [source, records.filter(item => item.source === source).length])
);
const sourceTypeCounts = Object.fromEntries(
  [...new Set(records.map(item => item.sourceType))].map(sourceType => [sourceType, records.filter(item => item.sourceType === sourceType).length])
);

const payload = {
  generatedAt: new Date().toISOString(),
  safetyNotice: "Defensive training data only. Do not visit malicious URLs or use them outside an isolated analysis workflow.",
  featureVersion: FEATURE_VERSION,
  featureNames: FEATURE_NAMES,
  counts: {
    total: records.length,
    safe: safe.length,
    malicious: malicious.length,
    uniqueUrls: new Set(records.map(item => item.url)).size,
    uniqueRegistrableDomains: new Set(records.map(item => item.registrableDomain)).size,
    benignCounterfactual: enrichedSafe.counterfactualCount,
    hardNegativeGenerated: hardNegativeRecords.length,
    sourceCounts,
    sourceTypeCounts
  },
  sources: Object.fromEntries(Object.entries(sourceFiles).map(([name, file]) => [name, {
    file: path.basename(file),
    sha256: sha256(sourceBuffers[name]),
    bytes: sourceBuffers[name].length
  }])),
  records,
  hardNegativeRecords,
  notes: [
    "Benign candidates are not safety certificates.",
    "A documented subset of benign rows uses deterministic counterfactual path/query shapes on benign candidate origins to reduce root-URL source bias.",
    "Malicious URLs are retained for offline defensive feature extraction only and must not be opened."
  ]
};

await fs.mkdir(outputDir, { recursive: true });
await fs.writeFile(path.join(outputDir, "dataset-4000.json"), JSON.stringify(payload, null, 2) + "\n", "utf8");

const headers = ["id", "url", "actual", "label", "source", "sourceType", "hostname", "registrableDomain", ...FEATURE_NAMES];
const csv = [
  headers.join(","),
  ...records.map(record => headers.map(key => csvCell(record[key] ?? record.features[key])).join(","))
].join("\n");
await fs.writeFile(path.join(outputDir, "dataset-4000.csv"), `\uFEFF${csv}\n`, "utf8");

console.log(JSON.stringify(payload.counts, null, 2));
