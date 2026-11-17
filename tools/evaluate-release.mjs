import fs from "node:fs/promises";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { calculateRisk } from "../modules/risk-engine.js";
import { analyzeHomoglyph } from "../modules/homoglyph.js";
import { predictWithModel } from "../modules/url-model.js";
import { getDomainParts, initializeFromText } from "../modules/public-suffix.js";
import { findSimilarDomain } from "../modules/typosquat.js";
import { classifySiteContext } from "../modules/site-context.js";
import { analyzeContentSafety } from "../modules/content-safety.js";
import { buildEvidenceAssessment } from "../modules/evidence-coverage.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const reportDir = path.join(root, "evaluation", "results");

const divide = (numerator, denominator) => denominator ? numerator / denominator : 0;
const rounded = value => Number(value.toFixed(6));
const percent = value => `${(value * 100).toFixed(2)}%`;

function metricsFromCounts({ tp, tn, fp, fn }) {
  const total = tp + tn + fp + fn;
  const precision = divide(tp, tp + fp);
  const recall = divide(tp, tp + fn);
  return {
    total,
    tp,
    tn,
    fp,
    fn,
    accuracy: rounded(divide(tp + tn, total)),
    precision: rounded(precision),
    recall: rounded(recall),
    f1: rounded(divide(2 * precision * recall, precision + recall)),
    specificity: rounded(divide(tn, tn + fp)),
    falsePositiveRate: rounded(divide(fp, fp + tn)),
    falseNegativeRate: rounded(divide(fn, fn + tp))
  };
}

function countPredictions(rows, predictionKey) {
  const counts = { tp: 0, tn: 0, fp: 0, fn: 0 };
  for (const row of rows) {
    const predicted = row[predictionKey];
    if (row.label === "PHISHING" && predicted === "PHISHING") counts.tp += 1;
    else if (row.label === "SAFE" && predicted === "SAFE") counts.tn += 1;
    else if (row.label === "SAFE") counts.fp += 1;
    else counts.fn += 1;
  }
  return metricsFromCounts(counts);
}

function riskInput(item, parsed, domainInfo, mlInfo, typoMatch, siteContext) {
  const hostname = parsed.hostname.toLowerCase().replace(/^www\./, "");
  return {
    url: item.url,
    domain: hostname,
    domainInfo,
    ageInfo: Number.isFinite(item.ageDays) ? { ageDays: item.ageDays } : null,
    typoMatch,
    homoglyphInfo: analyzeHomoglyph(domainInfo.registrableDomain || hostname),
    isBlacklisted: false,
    isWhitelisted: false,
    isKnownDomain: Boolean(item.knownDomain),
    pageSignals: item.pageSignals || null,
    redirectInfo: null,
    threatInfo: { checked: false, isUnsafe: false, threats: [] },
    mlInfo,
    siteContext
  };
}

await Promise.all([
  fs.readFile(path.join(root, "data", "public_suffix_list.dat"), "utf8").then(initializeFromText),
  fs.mkdir(reportDir, { recursive: true })
]);

const [manifest, model, cases, complexLegitCases, knownDomains, protectedPaymentData, protectedGameData, trainingDataset, testSplitCsv] = await Promise.all([
  fs.readFile(path.join(root, "manifest.json"), "utf8").then(JSON.parse),
  fs.readFile(path.join(root, "data", "url-model.json"), "utf8").then(JSON.parse),
  fs.readFile(path.join(root, "evaluation", "release-regression-cases.json"), "utf8").then(JSON.parse),
  fs.readFile(path.join(root, "evaluation", "complex-legit-cases.json"), "utf8").then(JSON.parse),
  fs.readFile(path.join(root, "data", "known-domains.json"), "utf8").then(JSON.parse),
  fs.readFile(path.join(root, "data", "protected-payment-domains.json"), "utf8").then(JSON.parse),
  fs.readFile(path.join(root, "data", "protected-game-domains.json"), "utf8").then(JSON.parse),
  fs.readFile(path.join(root, "training", "data", "dataset-4000.json"), "utf8").then(JSON.parse),
  fs.readFile(path.join(root, "training", "splits", "test.csv"), "utf8")
]);

const protectedPaymentDomains = (protectedPaymentData.entries || [])
  .map(item => String(item.domain || "").toLowerCase())
  .filter(Boolean);
const protectedGameDomains = (protectedGameData.entries || [])
  .map(item => String(item.domain || "").toLowerCase())
  .filter(Boolean);
const protectedTyposquatDomains = [...new Set([...protectedPaymentDomains, ...protectedGameDomains])];
const typoReferenceDomains = [...new Set([...knownDomains, ...protectedTyposquatDomains])];

function evaluateCase(item, defaultLabel = null) {
  const parsed = new URL(item.url);
  const hostname = parsed.hostname.toLowerCase().replace(/^www\./, "");
  const domainInfo = getDomainParts(hostname);
  const siteContext = classifySiteContext(item.url);
  const mlInfo = siteContext.isPublic
    ? predictWithModel(model, item.url, domainInfo)
    : { available: false, skipped: true, probability: 0, prediction: "NOT_APPLICABLE" };
  const homoglyphInfo = analyzeHomoglyph(domainInfo.registrableDomain || hostname);
  const typoMatch = siteContext.isPublic
    ? findSimilarDomain(homoglyphInfo.skeleton, typoReferenceDomains, { exactBrandLabels: protectedTyposquatDomains })
    : null;
  const label = item.label || item.expectedVerdict || defaultLabel;
  const risk = calculateRisk(riskInput(item, parsed, domainInfo, mlInfo, typoMatch, siteContext));
  const contentSafety = item.pageSignals
    ? analyzeContentSafety(item.pageSignals, { enabled: true })
    : { available: true, detected: false, level: "NONE", score: 0, categories: [] };
  const ageInfo = Number.isFinite(item.ageDays) ? { ageDays: item.ageDays } : null;
  const evidenceAssessment = buildEvidenceAssessment({
    domain: hostname,
    registrableDomain: domainInfo.registrableDomain || hostname,
    risk,
    contentSafety,
    pageSignals: item.pageSignals || null,
    rdapMeta: siteContext.isPublic
      ? { available: Boolean(ageInfo), skipped: false }
      : { available: false, skipped: true },
    ageInfo,
    mlInfo,
    redirectInfo: null,
    threatInfo: { checked: false, skipped: false, isUnsafe: false },
    siteContext,
    listStatus: { blacklisted: false, whitelisted: false, knownDomain: Boolean(item.knownDomain) },
    settings: { analyzePage: true, contentSafetyEnabled: true, urlModelEnabled: true, redirectAnalysis: true }
  });
  return {
    id: item.id,
    label,
    pairId: item.pairId || null,
    pairRole: item.pairRole || null,
    url: item.url,
    mlProbability: rounded(mlInfo.probability),
    mlPrediction: mlInfo.prediction,
    hybridScore: risk.score,
    hybridLevel: risk.level,
    hybridPrediction: risk.binaryPrediction,
    shouldWarnOnPage: Boolean(risk.presentation?.shouldWarnOnPage),
    presentationTier: risk.presentation?.tier || "NONE",
    siteContext: siteContext.type,
    expectedContext: item.context || siteContext.type,
    identityStatus: risk.identityStatus?.code || "",
    evidenceStatus: evidenceAssessment.status,
    evidenceRiskState: evidenceAssessment.riskState,
    safeDisplayState: evidenceAssessment.safeDisplayState,
    evidenceScore: evidenceAssessment.evidenceScore,
    baseEvidenceScore: evidenceAssessment.baseEvidenceScore,
    paymentEvidenceBoost: evidenceAssessment.paymentEvidenceBoost,
    paymentEvidenceEligible: evidenceAssessment.paymentEvidenceEligible,
    verifiedBrandEvidenceBoost: evidenceAssessment.verifiedBrandEvidenceBoost,
    verifiedBrandEvidenceEligible: evidenceAssessment.verifiedBrandEvidenceEligible,
    positiveEvidenceBoost: evidenceAssessment.positiveEvidenceBoost,
    contentLevel: contentSafety.level,
    contentScore: contentSafety.score,
    contentCategoryIds: contentSafety.categories.map(entry => entry.id),
    correctContext: !item.context || item.context === siteContext.type,
    correctMl: mlInfo.prediction === "NOT_APPLICABLE" || mlInfo.prediction === label,
    correctHybrid: risk.binaryPrediction === label,
    correctContent: (
      (!item.expectedContentLevel || contentSafety.level === item.expectedContentLevel) &&
      (!item.expectedContentCategory || contentSafety.categories.some(entry => entry.id === item.expectedContentCategory)) &&
      (!Number.isFinite(item.minimumContentScore) || contentSafety.score >= item.minimumContentScore)
    ),
    correctIdentity: !item.expectedIdentityStatus || risk.identityStatus?.code === item.expectedIdentityStatus,
    correctEvidence: (
      (!item.expectedSafeDisplayState || evidenceAssessment.safeDisplayState === item.expectedSafeDisplayState) &&
      (!item.expectedEvidenceRiskState || evidenceAssessment.riskState === item.expectedEvidenceRiskState) &&
      (!Number.isFinite(item.minimumEvidenceScore) || evidenceAssessment.evidenceScore >= item.minimumEvidenceScore) &&
      (typeof item.expectedPaymentEvidenceEligible !== "boolean" || evidenceAssessment.paymentEvidenceEligible === item.expectedPaymentEvidenceEligible) &&
      (typeof item.expectedVerifiedBrandEvidenceEligible !== "boolean" || evidenceAssessment.verifiedBrandEvidenceEligible === item.expectedVerifiedBrandEvidenceEligible)
    )
  };
}

const contentLevelRank = { NONE: 0, NOTICE: 1, WARNING: 2, HIGH: 3 };

function summarizePairs(inputRows) {
  const groups = new Map();
  for (const row of inputRows.filter(item => item.pairId)) {
    if (!groups.has(row.pairId)) groups.set(row.pairId, []);
    groups.get(row.pairId).push(row);
  }
  const pairs = [...groups.entries()].map(([pairId, pairRows]) => {
    const expectedLabels = new Set(pairRows.map(row => row.label));
    const actualLabels = new Set(pairRows.map(row => row.hybridPrediction));
    const passed = pairRows.length >= 2 && expectedLabels.size >= 2 && actualLabels.size >= 2 &&
      pairRows.every(row => row.correctHybrid && row.correctContent);
    return { pairId, cases: pairRows.map(row => row.id), passed };
  });
  return {
    pairs: pairs.length,
    passed: pairs.filter(pair => pair.passed).length,
    failures: pairs.filter(pair => !pair.passed).map(pair => pair.pairId),
    details: pairs
  };
}

function evaluateContentCase(item) {
  const result = analyzeContentSafety(item.pageSignals, { enabled: true });
  const category = result.categories.find(entry => entry.id === item.expectedCategory) || null;
  const passed = Boolean(category) &&
    contentLevelRank[result.level] >= contentLevelRank[item.minimumLevel || "NOTICE"];
  return {
    id: item.id,
    expectedCategory: item.expectedCategory,
    minimumLevel: item.minimumLevel || "NOTICE",
    actualLevel: result.level,
    actualScore: result.score,
    categoryScore: category?.score ?? 0,
    passed
  };
}

const urlCases = cases.filter(item => item.kind !== "CONTENT_SAFETY");
const contentCases = cases.filter(item => item.kind === "CONTENT_SAFETY");
const rows = urlCases.map(item => evaluateCase(item));
const contentRows = contentCases.map(evaluateContentCase);
const complexLegitRows = complexLegitCases.map(item => evaluateCase(item, "SAFE"));

const benchmarkSamples = [];
for (let iteration = 0; iteration < 100; iteration += 1) {
  for (const item of urlCases) {
    const parsed = new URL(item.url);
    const hostname = parsed.hostname.toLowerCase().replace(/^www\./, "");
    const domainInfo = getDomainParts(hostname);
    const startedAt = performance.now();
    predictWithModel(model, item.url, domainInfo);
    benchmarkSamples.push(performance.now() - startedAt);
  }
}
benchmarkSamples.sort((left, right) => left - right);
const percentile = ratio => benchmarkSamples[Math.min(benchmarkSamples.length - 1, Math.floor(benchmarkSamples.length * ratio))];
const runtimeBenchmark = {
  environment: `Node ${process.version} on ${process.platform}/${process.arch}`,
  predictions: benchmarkSamples.length,
  meanMilliseconds: rounded(benchmarkSamples.reduce((sum, value) => sum + value, 0) / benchmarkSamples.length),
  p50Milliseconds: rounded(percentile(0.50)),
  p95Milliseconds: rounded(percentile(0.95)),
  maxMilliseconds: rounded(benchmarkSamples.at(-1))
};

const embedded = model.training.testMetrics;
const recomputedEmbedded = metricsFromCounts(embedded);
const metricKeys = ["accuracy", "precision", "recall", "f1", "specificity", "falsePositiveRate", "falseNegativeRate"];
const embeddedConsistent = metricKeys.every(key => Math.abs(recomputedEmbedded[key] - embedded[key]) <= 1e-6);
const testIds = new Set(
  testSplitCsv.replace(/^\uFEFF/, "").split(/\r?\n/).slice(1).filter(Boolean).map(line => line.split(",", 1)[0])
);
const replayRows = trainingDataset.records.filter(item => testIds.has(item.id)).map(item => {
  const parsed = new URL(item.url);
  const hostname = parsed.hostname.toLowerCase().replace(/^www\./, "");
  const probability = predictWithModel(model, item.url, getDomainParts(hostname)).probability;
  return {
    label: item.label ? "PHISHING" : "SAFE",
    prediction: probability >= model.threshold ? "PHISHING" : "SAFE"
  };
});
const replayMetrics = countPredictions(replayRows, "prediction");
const holdoutReplayConsistent = replayRows.length === model.training.testCount &&
  ["tp", "tn", "fp", "fn"].every(key => replayMetrics[key] === embedded[key]);
const complexPublicRows = complexLegitRows.filter(row => row.mlPrediction !== "NOT_APPLICABLE");
const complexSafeRows = complexLegitRows.filter(row => row.label === "SAFE");
const complexThreatRows = complexLegitRows.filter(row => row.label === "PHISHING");
const releasePairSummary = summarizePairs(rows);
const complexPairSummary = summarizePairs(complexLegitRows);
const complexLegitSummary = {
  purpose: "Curated stress test for realistic legitimate path/query shapes, local/private context handling, and paired official-versus-impostor discrimination; not a prevalence estimate.",
  cases: complexLegitRows.length,
  safeCases: complexSafeRows.length,
  threatControlCases: complexThreatRows.length,
  publicCases: complexPublicRows.length,
  localOrPrivateCases: complexLegitRows.length - complexPublicRows.length,
  mlFalsePositives: complexPublicRows.filter(row => row.label === "SAFE" && row.mlPrediction === "PHISHING").length,
  hybridFalsePositives: complexSafeRows.filter(row => row.hybridPrediction !== "SAFE").length,
  hybridFalseNegatives: complexThreatRows.filter(row => row.hybridPrediction !== "PHISHING").length,
  onPageWarnings: complexSafeRows.filter(row => row.shouldWarnOnPage).length,
  advisoryOnly: complexSafeRows.filter(row => row.hybridLevel === "SUSPICIOUS" && !row.shouldWarnOnPage).length,
  contextMismatches: complexLegitRows.filter(row => !row.correctContext).length,
  identityMismatches: complexLegitRows.filter(row => !row.correctIdentity).length,
  evidenceMismatches: complexLegitRows.filter(row => !row.correctEvidence).length,
  contentMismatches: complexLegitRows.filter(row => !row.correctContent).length,
  pairedDiscrimination: complexPairSummary
};
const contentRegressionSummary = {
  purpose: "Offline first-party content recall gate for categories affected by ad-region filtering.",
  cases: contentRows.length,
  passed: contentRows.filter(row => row.passed).length,
  recall: rounded(divide(contentRows.filter(row => row.passed).length, contentRows.length)),
  allPassed: contentRows.every(row => row.passed)
};
const report = {
  generatedAt: new Date().toISOString(),
  release: manifest.version,
  modelVersion: model.modelVersion,
  evaluationOrder: "Metrics were computed before this report was rendered.",
  embeddedIndependentTest: {
    provenance: "Metrics embedded by the training pipeline and replayed from the packaged domain-separated test split.",
    counts: { total: model.training.testCount, tp: embedded.tp, tn: embedded.tn, fp: embedded.fp, fn: embedded.fn },
    metrics: recomputedEmbedded,
    reportedRocAuc: embedded.rocAuc,
    reportedAveragePrecision: embedded.averagePrecision,
    reportedBrierScore: embedded.brierScore,
    confidenceIntervals95: model.training.testConfidenceIntervals95,
    internallyConsistent: embeddedConsistent,
    replayedRows: replayRows.length,
    replayMetrics,
    holdoutReplayConsistent
  },
  releaseRegression: {
    purpose: "Small curated release gate for known safe/OAuth and obvious phishing patterns; not an independent estimate of real-world prevalence.",
    cases: cases.length,
    urlRiskCases: rows.length,
    contentSafetyCases: contentRows.length,
    mlOnly: countPredictions(rows, "mlPrediction"),
    hybrid: countPredictions(rows, "hybridPrediction"),
    urlContentMismatches: rows.filter(row => !row.correctContent).length,
    pairedDiscrimination: releasePairSummary,
    contentSafety: contentRegressionSummary
  },
  complexLegitRegression: complexLegitSummary,
  runtimeBenchmark,
  limitations: [
    ...model.limitations,
    "Holdout được đóng kèm để replay, nhưng vẫn thuộc cùng đợt thu thập dữ liệu và chưa phải temporal holdout tương lai.",
    "Bộ release regression được tuyển chọn và cố ý giữ nhỏ; kết quả 100% không được trình bày như độ chính xác production.",
    "Tích hợp cổng thanh toán quan sát được chỉ là coverage evidence; logo/text có thể bị giả nên không thay đổi Risk score hoặc xác thực merchant.",
    "Đánh giá Node.js này chưa chạy end-to-end trên Chrome/Edge thật hoặc quy trình review của cửa hàng extension."
  ],
  predictions: rows,
  contentSafetyPredictions: contentRows,
  complexLegitPredictions: complexLegitRows
};

const markdown = `# Báo cáo đánh giá - DNS Phishing Guard v${manifest.version}

Thời điểm tạo: ${report.generatedAt}

## Kết quả điều hành

- Model: \`${model.modelVersion}\`, ngưỡng xác suất \`${model.threshold}\`.
- Holdout độc lập: ${model.training.testCount} URL; replay từng dự đoán: **${holdoutReplayConsistent ? "PASS" : "FAIL"}**.
- Release regression: ${rows.length} ca URL và ${contentRows.length} ca content-safety; độ chính xác hybrid URL **${percent(report.releaseRegression.hybrid.accuracy)}**, recall nội dung **${percent(contentRegressionSummary.recall)}**, cặp phân biệt **${releasePairSummary.passed}/${releasePairSummary.pairs}**.
- Complex regression: ${complexLegitSummary.cases} ca (${complexLegitSummary.safeCases} safe + ${complexLegitSummary.threatControlCases} threat control); FP/FN hybrid **${complexLegitSummary.hybridFalsePositives}/${complexLegitSummary.hybridFalseNegatives}**, cặp phân biệt **${complexPairSummary.passed}/${complexPairSummary.pairs}**.
- Quyết định: **${embeddedConsistent && holdoutReplayConsistent && report.releaseRegression.hybrid.fp === 0 && report.releaseRegression.hybrid.fn === 0 && report.releaseRegression.urlContentMismatches === 0 && releasePairSummary.failures.length === 0 && contentRegressionSummary.allPassed && complexLegitSummary.hybridFalsePositives === 0 && complexLegitSummary.hybridFalseNegatives === 0 && complexLegitSummary.onPageWarnings === 0 && complexLegitSummary.contextMismatches === 0 && complexLegitSummary.identityMismatches === 0 && complexLegitSummary.evidenceMismatches === 0 && complexLegitSummary.contentMismatches === 0 && complexPairSummary.failures.length === 0 ? "PASS" : "CẦN XEM XÉT"}**.

## Metrics holdout độc lập

Các giá trị dưới đây được tính lại từ confusion matrix và replay trực tiếp trên test split đóng kèm. Domain giữa train/calibration/threshold/test không bị trùng.

| Chỉ số | Giá trị |
| --- | ---: |
| TP / TN / FP / FN | ${embedded.tp} / ${embedded.tn} / ${embedded.fp} / ${embedded.fn} |
| Accuracy (độ chính xác tổng thể) | ${percent(recomputedEmbedded.accuracy)} |
| Precision | ${percent(recomputedEmbedded.precision)} |
| Recall | ${percent(recomputedEmbedded.recall)} |
| F1 | ${percent(recomputedEmbedded.f1)} |
| Specificity | ${percent(recomputedEmbedded.specificity)} |
| False-positive rate (FPR) | ${percent(recomputedEmbedded.falsePositiveRate)} |
| False-negative rate (FNR) | ${percent(recomputedEmbedded.falseNegativeRate)} |
| ROC-AUC (từ pipeline train) | ${embedded.rocAuc.toFixed(4)} |
| Average precision (từ pipeline train) | ${embedded.averagePrecision.toFixed(4)} |
| Brier score (từ pipeline train) | ${embedded.brierScore.toFixed(4)} |

## Metrics release regression

| Bộ đánh giá | Accuracy | Precision | Recall | F1 | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Chỉ URL ML | ${percent(report.releaseRegression.mlOnly.accuracy)} | ${percent(report.releaseRegression.mlOnly.precision)} | ${percent(report.releaseRegression.mlOnly.recall)} | ${percent(report.releaseRegression.mlOnly.f1)} | ${percent(report.releaseRegression.mlOnly.falsePositiveRate)} | ${percent(report.releaseRegression.mlOnly.falseNegativeRate)} |
| Hybrid Risk Engine | ${percent(report.releaseRegression.hybrid.accuracy)} | ${percent(report.releaseRegression.hybrid.precision)} | ${percent(report.releaseRegression.hybrid.recall)} | ${percent(report.releaseRegression.hybrid.f1)} | ${percent(report.releaseRegression.hybrid.falsePositiveRate)} | ${percent(report.releaseRegression.hybrid.falseNegativeRate)} |

Release regression đo riêng khả năng bảo vệ các ca OAuth/safe đã biết và các mẫu phishing rõ ràng; không dùng kết quả này thay cho holdout độc lập.

## Recall content-safety sau lọc quảng cáo

| Case | Danh mục kỳ vọng | Mức tối thiểu | Kết quả | Điểm danh mục | Trạng thái |
| --- | --- | --- | --- | ---: | --- |
${contentRows.map(row => `| ${row.id} | ${row.expectedCategory} | ${row.minimumLevel} | ${row.actualLevel} | ${row.categoryScore} | ${row.passed ? "PASS" : "FAIL"} |`).join("\n")}

Hai fixture này mô phỏng nội dung nhạy cảm là nội dung chính của trang, vì vậy bộ lọc vùng quảng cáo không được làm giảm recall của \`GAMBLING\` và \`SEXUAL_SERVICES\`.

## Stress test legitimate thực tế

| Chỉ số | Giá trị |
| --- | ---: |
| Tổng số ca | ${complexLegitSummary.cases} |
| Ca SAFE / threat control | ${complexLegitSummary.safeCases} / ${complexLegitSummary.threatControlCases} |
| Ca public / local-private | ${complexLegitSummary.publicCases} / ${complexLegitSummary.localOrPrivateCases} |
| ML raw false positive (public) | ${complexLegitSummary.mlFalsePositives} |
| Hybrid false positive | ${complexLegitSummary.hybridFalsePositives} |
| Hybrid false negative | ${complexLegitSummary.hybridFalseNegatives} |
| Cảnh báo hiển thị on-page | ${complexLegitSummary.onPageWarnings} |
| Chỉ còn advisory badge | ${complexLegitSummary.advisoryOnly} |
| Context mismatch | ${complexLegitSummary.contextMismatches} |
| Identity tier mismatch | ${complexLegitSummary.identityMismatches} |
| Payment/evidence mismatch | ${complexLegitSummary.evidenceMismatches} |
| Content expectation mismatch | ${complexLegitSummary.contentMismatches} |
| Cặp official/impostor đạt | ${complexPairSummary.passed} / ${complexPairSummary.pairs} |

Bộ này chứa cả ca hợp pháp phức tạp và threat control ghép cặp. Nó là regression gate để đồng thời chặn báo nhầm và phát hiện việc official/impostor bị trả cùng verdict; không phải ước lượng prevalence ngoài thực tế.

## Hiệu năng inference

| Chỉ số | Giá trị |
| --- | ---: |
| Môi trường | ${runtimeBenchmark.environment} |
| Số lượt dự đoán | ${runtimeBenchmark.predictions} |
| Trung bình | ${runtimeBenchmark.meanMilliseconds.toFixed(3)} ms/URL |
| p50 | ${runtimeBenchmark.p50Milliseconds.toFixed(3)} ms/URL |
| p95 | ${runtimeBenchmark.p95Milliseconds.toFixed(3)} ms/URL |
| Lớn nhất | ${runtimeBenchmark.maxMilliseconds.toFixed(3)} ms/URL |

Đây là microbenchmark Node.js trên máy chạy báo cáo, không phải latency end-to-end của extension trong Chrome/Edge.

## Ca phân loại sai

${rows.filter(row => !row.correctHybrid).map(row => `- \`${row.id}\`: kỳ vọng ${row.label}, nhận ${row.hybridPrediction} (score ${row.hybridScore}, ML ${percent(row.mlProbability)}).`).join("\n") || "Không có ca hybrid phân loại sai trong bộ release regression tuyển chọn."}

## Giới hạn

${report.limitations.map(item => `- ${item}`).join("\n")}

## Cách tái lập

Chạy \`npm run validate\` trong thư mục release. Lệnh sẽ chạy test, tính metrics, rồi mới ghi lại báo cáo này.
`;

await Promise.all([
  fs.writeFile(path.join(reportDir, "evaluation-results.json"), JSON.stringify(report, null, 2) + "\n", "utf8"),
  fs.writeFile(path.join(reportDir, "EVALUATION_REPORT.md"), markdown, "utf8")
]);

console.log(JSON.stringify({
  release: report.release,
  modelVersion: report.modelVersion,
  embeddedIndependentTest: report.embeddedIndependentTest.metrics,
  embeddedConsistent,
  holdoutReplayConsistent,
  releaseRegression: report.releaseRegression,
  complexLegitRegression: report.complexLegitRegression,
  runtimeBenchmark: report.runtimeBenchmark
}, null, 2));

if (
  !embeddedConsistent || !holdoutReplayConsistent ||
  report.releaseRegression.hybrid.fp > 0 || report.releaseRegression.hybrid.fn > 0 ||
  report.releaseRegression.urlContentMismatches > 0 || releasePairSummary.failures.length > 0 ||
  !contentRegressionSummary.allPassed ||
  complexLegitSummary.hybridFalsePositives > 0 || complexLegitSummary.hybridFalseNegatives > 0 ||
  complexLegitSummary.onPageWarnings > 0 || complexLegitSummary.contextMismatches > 0 ||
  complexLegitSummary.identityMismatches > 0 || complexLegitSummary.evidenceMismatches > 0 ||
  complexLegitSummary.contentMismatches > 0 || complexPairSummary.failures.length > 0
) {
  process.exitCode = 1;
}
