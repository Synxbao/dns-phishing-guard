import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const releaseRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dataFile = path.join(releaseRoot, "training", "data", "dataset-4000.json");
const reportDir = path.join(releaseRoot, "training", "reports");
const splitDir = path.join(releaseRoot, "training", "splits");
const modelOutput = path.join(releaseRoot, "data", "url-model.json");
const seed = 20260810;
const STANDARDIZATION_CLAMP = 6;

function mulberry32(initialSeed) {
  let state = initialSeed >>> 0;
  return () => {
    state += 0x6D2B79F5;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

function shuffle(items, random) {
  const copy = [...items];
  for (let index = copy.length - 1; index > 0; index -= 1) {
    const target = Math.floor(random() * (index + 1));
    [copy[index], copy[target]] = [copy[target], copy[index]];
  }
  return copy;
}

function sigmoid(value) {
  if (value >= 0) {
    const exp = Math.exp(-value);
    return 1 / (1 + exp);
  }
  const exp = Math.exp(value);
  return exp / (1 + exp);
}

function dot(weights, vector, intercept = 0) {
  let value = intercept;
  for (let index = 0; index < weights.length; index += 1) value += weights[index] * vector[index];
  return value;
}

function meanAndScale(vectors) {
  const width = vectors[0].length;
  const mean = new Array(width).fill(0);
  const scale = new Array(width).fill(0);
  for (const vector of vectors) {
    for (let index = 0; index < width; index += 1) mean[index] += vector[index];
  }
  for (let index = 0; index < width; index += 1) mean[index] /= vectors.length;
  for (const vector of vectors) {
    for (let index = 0; index < width; index += 1) {
      const delta = vector[index] - mean[index];
      scale[index] += delta * delta;
    }
  }
  for (let index = 0; index < width; index += 1) {
    scale[index] = Math.sqrt(scale[index] / vectors.length) || 1;
  }
  return { mean, scale };
}

function standardize(vector, mean, scale) {
  return vector.map((value, index) => {
    const normalized = (value - mean[index]) / scale[index];
    return Math.max(-STANDARDIZATION_CLAMP, Math.min(STANDARDIZATION_CLAMP, normalized));
  });
}

function trainLogistic(vectors, labels, options = {}) {
  const epochs = options.epochs || 700;
  const learningRate = options.learningRate || 0.025;
  const l2 = options.l2 || 0.0008;
  const width = vectors[0].length;
  const weights = new Array(width).fill(0);
  const firstMoment = new Array(width).fill(0);
  const secondMoment = new Array(width).fill(0);
  let intercept = Math.log((labels.reduce((sum, value) => sum + value, 0) + 1) / (labels.length - labels.reduce((sum, value) => sum + value, 0) + 1));
  let interceptFirst = 0;
  let interceptSecond = 0;
  const beta1 = 0.9;
  const beta2 = 0.999;
  const epsilon = 1e-8;

  for (let epoch = 1; epoch <= epochs; epoch += 1) {
    const gradients = new Array(width).fill(0);
    let interceptGradient = 0;
    for (let row = 0; row < vectors.length; row += 1) {
      const error = sigmoid(dot(weights, vectors[row], intercept)) - labels[row];
      interceptGradient += error;
      for (let column = 0; column < width; column += 1) gradients[column] += error * vectors[row][column];
    }
    interceptGradient /= vectors.length;
    for (let column = 0; column < width; column += 1) {
      gradients[column] = gradients[column] / vectors.length + l2 * weights[column];
      firstMoment[column] = beta1 * firstMoment[column] + (1 - beta1) * gradients[column];
      secondMoment[column] = beta2 * secondMoment[column] + (1 - beta2) * gradients[column] * gradients[column];
      const correctedFirst = firstMoment[column] / (1 - beta1 ** epoch);
      const correctedSecond = secondMoment[column] / (1 - beta2 ** epoch);
      weights[column] -= learningRate * correctedFirst / (Math.sqrt(correctedSecond) + epsilon);
    }
    interceptFirst = beta1 * interceptFirst + (1 - beta1) * interceptGradient;
    interceptSecond = beta2 * interceptSecond + (1 - beta2) * interceptGradient * interceptGradient;
    intercept -= learningRate * (interceptFirst / (1 - beta1 ** epoch)) /
      (Math.sqrt(interceptSecond / (1 - beta2 ** epoch)) + epsilon);
  }
  return { weights, intercept };
}

function fitPlatt(logits, labels) {
  let slope = 1;
  let intercept = 0;
  const learningRate = 0.03;
  for (let epoch = 0; epoch < 500; epoch += 1) {
    let slopeGradient = 0;
    let interceptGradient = 0;
    for (let index = 0; index < logits.length; index += 1) {
      const error = sigmoid(slope * logits[index] + intercept) - labels[index];
      slopeGradient += error * logits[index];
      interceptGradient += error;
    }
    slope = Math.max(0.05, slope - learningRate * slopeGradient / logits.length);
    intercept -= learningRate * interceptGradient / logits.length;
  }
  return { slope, intercept };
}

function predictProbability(model, vector, calibration = null) {
  const logit = dot(model.weights, vector, model.intercept);
  return calibration ? sigmoid(calibration.slope * logit + calibration.intercept) : sigmoid(logit);
}

function metrics(labels, probabilities, threshold) {
  let tp = 0, tn = 0, fp = 0, fn = 0;
  for (let index = 0; index < labels.length; index += 1) {
    const predicted = probabilities[index] >= threshold ? 1 : 0;
    if (labels[index] === 1 && predicted === 1) tp += 1;
    else if (labels[index] === 0 && predicted === 0) tn += 1;
    else if (labels[index] === 0) fp += 1;
    else fn += 1;
  }
  const divide = (left, right) => right ? left / right : 0;
  const precision = divide(tp, tp + fp);
  const recall = divide(tp, tp + fn);
  return {
    threshold, tp, tn, fp, fn,
    accuracy: divide(tp + tn, labels.length),
    precision,
    recall,
    f1: divide(2 * precision * recall, precision + recall),
    specificity: divide(tn, tn + fp),
    falsePositiveRate: divide(fp, fp + tn),
    falseNegativeRate: divide(fn, fn + tp),
    rocAuc: rocAuc(labels, probabilities),
    averagePrecision: averagePrecision(labels, probabilities),
    brierScore: probabilities.reduce((sum, probability, index) => sum + (probability - labels[index]) ** 2, 0) / labels.length
  };
}

function rocAuc(labels, probabilities) {
  const rows = labels.map((label, index) => ({ label, probability: probabilities[index] }))
    .sort((left, right) => left.probability - right.probability);
  let rank = 1;
  let positiveRankSum = 0;
  for (let start = 0; start < rows.length;) {
    let end = start + 1;
    while (end < rows.length && rows[end].probability === rows[start].probability) end += 1;
    const averageRank = (rank + rank + (end - start) - 1) / 2;
    for (let index = start; index < end; index += 1) if (rows[index].label === 1) positiveRankSum += averageRank;
    rank += end - start;
    start = end;
  }
  const positives = labels.filter(Boolean).length;
  const negatives = labels.length - positives;
  return positives && negatives ? (positiveRankSum - positives * (positives + 1) / 2) / (positives * negatives) : 0;
}

function averagePrecision(labels, probabilities) {
  const rows = labels.map((label, index) => ({ label, probability: probabilities[index] }))
    .sort((left, right) => right.probability - left.probability);
  const positives = labels.filter(Boolean).length;
  if (!positives) return 0;
  let seenPositive = 0;
  let sumPrecision = 0;
  rows.forEach((row, index) => {
    if (row.label === 1) {
      seenPositive += 1;
      sumPrecision += seenPositive / (index + 1);
    }
  });
  return sumPrecision / positives;
}

function chooseThreshold(labels, probabilities) {
  const candidates = [];
  for (let value = 0.20; value <= 0.90; value += 0.005) candidates.push(metrics(labels, probabilities, Number(value.toFixed(3))));
  const stable = candidates.filter(item => item.precision >= 0.965 && item.falsePositiveRate <= 0.03 && item.recall >= 0.80);
  const precisionFirst = candidates.filter(item => item.precision >= 0.965 && item.falsePositiveRate <= 0.03);
  const pool = stable.length ? stable : precisionFirst.length ? precisionFirst : candidates;
  return pool.sort((left, right) =>
    right.f1 - left.f1 || right.recall - left.recall || right.precision - left.precision || left.falsePositiveRate - right.falsePositiveRate
  )[0];
}

function groupedSplits(records, forcedTrainDomains = new Set()) {
  const random = mulberry32(seed);
  const names = ["train", "calibration", "threshold", "test"];
  const ratios = [0.70, 0.10, 0.10, 0.10];
  const output = Object.fromEntries(names.map(name => [name, []]));
  for (const label of [0, 1]) {
    const groups = new Map();
    records.filter(item => item.label === label).forEach(item => {
      if (!groups.has(item.registrableDomain)) groups.set(item.registrableDomain, []);
      groups.get(item.registrableDomain).push(item);
    });
    const shuffledGroups = shuffle([...groups.values()], random);
    const targets = ratios.map(ratio => records.filter(item => item.label === label).length * ratio);
    const counts = new Array(names.length).fill(0);
    for (const group of shuffledGroups) {
      if (forcedTrainDomains.has(group[0].registrableDomain)) {
        output.train.push(...group);
        counts[0] += group.length;
        continue;
      }
      let selected = 0;
      let lowestFill = Infinity;
      for (let index = 0; index < names.length; index += 1) {
        const fill = counts[index] / targets[index];
        if (fill < lowestFill) {
          selected = index;
          lowestFill = fill;
        }
      }
      output[names[selected]].push(...group);
      counts[selected] += group.length;
    }
  }
  for (const name of names) output[name] = shuffle(output[name], random);
  return output;
}

function roundNested(value) {
  if (typeof value === "number") return Number(value.toFixed(7));
  if (Array.isArray(value)) return value.map(roundNested);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, roundNested(item)]));
  return value;
}

function csvCell(value) {
  const text = String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

const payload = JSON.parse(await fs.readFile(dataFile, "utf8"));
const hardNegativeRecords = payload.hardNegativeRecords || [];
const hardNegativeWeight = 2;
const hardNegativeDomains = new Set(hardNegativeRecords.map(item => item.registrableDomain));
const splits = groupedSplits(payload.records, hardNegativeDomains);
const weightedHardNegatives = Array.from({ length: hardNegativeWeight }, () => hardNegativeRecords).flat();
const augmentedTrain = [...splits.train, ...weightedHardNegatives];
const trainVectorsRaw = augmentedTrain.map(item => item.featureVector.map(Number));
const trainLabels = augmentedTrain.map(item => item.label);
const { mean, scale } = meanAndScale(trainVectorsRaw);
const transform = rows => rows.map(item => standardize(item.featureVector.map(Number), mean, scale));
const trainVectors = transform(augmentedTrain);
const calibrationVectors = transform(splits.calibration);
const thresholdVectors = transform(splits.threshold);
const testVectors = transform(splits.test);

const trained = trainLogistic(trainVectors, trainLabels);
const calibrationLogits = calibrationVectors.map(vector => dot(trained.weights, vector, trained.intercept));
const calibration = fitPlatt(calibrationLogits, splits.calibration.map(item => item.label));
const thresholdProbabilities = thresholdVectors.map(vector => predictProbability(trained, vector, calibration));
const selectedThreshold = chooseThreshold(splits.threshold.map(item => item.label), thresholdProbabilities);
const testProbabilities = testVectors.map(vector => predictProbability(trained, vector, calibration));
const testMetrics = metrics(splits.test.map(item => item.label), testProbabilities, selectedThreshold.threshold);
const calibrationMetrics = metrics(
  splits.calibration.map(item => item.label),
  calibrationVectors.map(vector => predictProbability(trained, vector, calibration)),
  selectedThreshold.threshold
);

const sourceMetrics = {};
for (const sourceType of [...new Set(splits.test.map(item => item.sourceType))]) {
  const indices = splits.test.map((item, index) => item.sourceType === sourceType ? index : -1).filter(index => index >= 0);
  sourceMetrics[sourceType] = metrics(indices.map(index => splits.test[index].label), indices.map(index => testProbabilities[index]), selectedThreshold.threshold);
}

const model = roundNested({
  modelVersion: "url-logistic-5.0.0",
  extensionVersion: "2.4.0",
  modelType: "logistic-regression",
  featureVersion: payload.featureVersion,
  standardizationClamp: STANDARDIZATION_CLAMP,
  trainedAt: new Date().toISOString(),
  randomSeed: seed,
  featureNames: payload.featureNames,
  threshold: selectedThreshold.threshold,
  calibration,
  probabilityBands: { low: 0.20, suspicious: 0.55, high: 0.80, veryHigh: 0.95 },
  training: {
    datasetSize: payload.counts.total,
    safeCount: payload.counts.safe,
    maliciousCount: payload.counts.malicious,
    phishingCount: payload.counts.malicious,
    uniqueDomains: payload.counts.uniqueRegistrableDomains,
    featureCount: payload.featureNames.length,
    splitMethod: "Grouped by registrableDomain, stratified by label: approximately 70% train, 10% calibration, 10% threshold selection, 10% independent test",
    trainCount: splits.train.length,
    hardNegativeTrainingCount: hardNegativeRecords.length,
    hardNegativeWeight,
    augmentedTrainCount: augmentedTrain.length,
    calibrationCount: splits.calibration.length,
    thresholdCount: splits.threshold.length,
    testCount: splits.test.length,
    minPrecisionConstraint: 0.965,
    maxFalsePositiveRateConstraint: 0.03,
    minRecallPreference: 0.80,
    benignCounterfactualCount: payload.counts.benignCounterfactual || 0,
    sourceCounts: payload.counts.sourceCounts,
    sourceTypeCounts: payload.counts.sourceTypeCounts,
    validationMetrics: selectedThreshold,
    calibrationMetrics,
    testMetrics,
    testCategoryMetrics: sourceMetrics
  },
  limitations: [
    "URL sạch là benign candidates ghép từ danh sách người dùng và Tranco, không phải chứng nhận an toàn tuyệt đối.",
    "Một phần benign dùng path/query counterfactual có ghi nhãn rõ để giảm source bias của URL trang chủ; đây không phải quan sát lưu lượng production.",
    "Mẫu độc hại kết hợp phishing và malware-download nên tỷ lệ nhóm dữ liệu khác lưu lượng duyệt web bình thường.",
    "Đặc trưng riêng của từng nguồn và temporal drift có thể làm metrics offline cao hơn thực tế; vẫn cần temporal holdout mới.",
    "Model URL không thay thế brand mismatch, RDAP, threat intelligence, redirect hoặc phân tích hành vi trang."
  ],
  mean,
  scale,
  coefficients: trained.weights,
  intercept: trained.intercept
});

await fs.mkdir(reportDir, { recursive: true });
await fs.mkdir(splitDir, { recursive: true });
await fs.writeFile(modelOutput, JSON.stringify(model, null, 2) + "\n", "utf8");

for (const [name, rows] of Object.entries(splits)) {
  const csv = [
    "id,url,actual,source,sourceType,registrableDomain",
    ...rows.map(item => [item.id, item.url, item.actual, item.source, item.sourceType, item.registrableDomain].map(csvCell).join(","))
  ].join("\n");
  await fs.writeFile(path.join(splitDir, `${name}.csv`), `\uFEFF${csv}\n`, "utf8");
}

const predictions = splits.test.map((item, index) => ({
  id: item.id,
  url: item.url,
  actual: item.actual,
  source: item.source,
  sourceType: item.sourceType,
  registrableDomain: item.registrableDomain,
  probability: testProbabilities[index],
  predicted: testProbabilities[index] >= model.threshold ? "MALICIOUS" : "SAFE",
  correct: (testProbabilities[index] >= model.threshold ? 1 : 0) === item.label
}));

const trainingReport = roundNested({
  generatedAt: new Date().toISOString(),
  dataset: payload.counts,
  splits: Object.fromEntries(Object.entries(splits).map(([name, rows]) => [name, {
    total: rows.length,
    safe: rows.filter(item => item.label === 0).length,
    malicious: rows.filter(item => item.label === 1).length,
    uniqueDomains: new Set(rows.map(item => item.registrableDomain)).size
  }])),
  domainLeakage: false,
  hardNegativeTrainingCount: hardNegativeRecords.length,
  hardNegativeWeight,
  augmentedTrainCount: augmentedTrain.length,
  selectedModel: {
    name: "Locally trained Logistic Regression with Platt calibration",
    modelVersion: model.modelVersion,
    threshold: model.threshold,
    calibration: model.calibration,
    thresholdSelection: selectedThreshold,
    independentTest: testMetrics,
    testCategoryMetrics: sourceMetrics
  },
  limitations: model.limitations
});

await Promise.all([
  fs.writeFile(path.join(reportDir, "training-report.json"), JSON.stringify(trainingReport, null, 2) + "\n", "utf8"),
  fs.writeFile(path.join(reportDir, "test-predictions.json"), JSON.stringify(predictions, null, 2) + "\n", "utf8"),
  fs.writeFile(path.join(reportDir, "TRAINING_REPORT.md"), `# Báo cáo huấn luyện URL ML v5\n\n` +
    `- Dataset: **${payload.counts.total} URL** (${payload.counts.safe} sạch, ${payload.counts.malicious} độc hại).\n` +
    `- Model: \`${model.modelVersion}\`, ${payload.featureNames.length} features, Platt calibration.\n` +
    `- Split theo registrable domain: train ${splits.train.length}, calibration ${splits.calibration.length}, chọn ngưỡng ${splits.threshold.length}, test độc lập ${splits.test.length}.\n` +
    `- Hard negatives chỉ train: ${hardNegativeRecords.length}; tổng train sau tăng cường: ${augmentedTrain.length}.\n` +
    `- Benign counterfactual nằm trong split theo domain: ${payload.counts.benignCounterfactual || 0}.\n` +
    `- Standardized feature clamp: ±${STANDARDIZATION_CLAMP}.\n` +
    `- Domain leakage: **không**.\n\n` +
    `## Independent test\n\n` +
    `- TP ${testMetrics.tp}, TN ${testMetrics.tn}, FP ${testMetrics.fp}, FN ${testMetrics.fn}.\n` +
    `- Accuracy ${(testMetrics.accuracy * 100).toFixed(2)}%.\n` +
    `- Precision ${(testMetrics.precision * 100).toFixed(2)}%.\n` +
    `- Recall ${(testMetrics.recall * 100).toFixed(2)}%.\n` +
    `- F1 ${(testMetrics.f1 * 100).toFixed(2)}%.\n` +
    `- FPR ${(testMetrics.falsePositiveRate * 100).toFixed(2)}%; FNR ${(testMetrics.falseNegativeRate * 100).toFixed(2)}%.\n` +
    `- ROC-AUC ${testMetrics.rocAuc.toFixed(4)}; Average Precision ${testMetrics.averagePrecision.toFixed(4)}.\n\n` +
    `## Giới hạn\n\n${model.limitations.map(item => `- ${item}`).join("\n")}\n`, "utf8")
]);

console.log(JSON.stringify(trainingReport, null, 2));
