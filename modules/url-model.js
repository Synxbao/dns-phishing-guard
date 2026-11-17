import { extractUrlMlFeatures, FEATURE_NAMES } from "./url-ml-features.js";

let cachedModelPromise = null;

function sigmoid(value) {
  if (value >= 0) {
    const exp = Math.exp(-value);
    return 1 / (1 + exp);
  }
  const exp = Math.exp(value);
  return exp / (1 + exp);
}

function validateMember(member, length) {
  if (!member || member.mean?.length !== length || member.scale?.length !== length || member.coefficients?.length !== length) {
    throw new Error("Kích thước thành viên URL model không khớp");
  }
  return member;
}

function validateModel(model) {
  if (!model || !["logistic-regression", "bagged-logistic-ensemble"].includes(model.modelType)) {
    throw new Error("URL model không hợp lệ");
  }
  const length = model.featureNames?.length || 0;
  if (!length || JSON.stringify(model.featureNames) !== JSON.stringify(FEATURE_NAMES)) {
    throw new Error("Thứ tự feature của URL model không khớp extension");
  }

  if (model.modelType === "logistic-regression") {
    validateMember(model, length);
  } else {
    if (!Array.isArray(model.members) || model.members.length < 2) {
      throw new Error("URL ensemble không có đủ thành viên");
    }
    model.members.forEach(member => validateMember(member, length));
  }
  return model;
}

async function loadUrlModel() {
  if (!cachedModelPromise) {
    cachedModelPromise = (async () => {
      const modelUrl = new URL("../data/url-model.json", import.meta.url);
      const response = await fetch(modelUrl);
      if (!response.ok) throw new Error(`Không tải được URL model: HTTP ${response.status}`);
      return validateModel(await response.json());
    })().catch(error => {
      cachedModelPromise = null;
      throw error;
    });
  }
  return cachedModelPromise;
}

function standardizedValue(value, mean, scale, limit = 6) {
  const normalized = (value - mean) / (scale || 1);
  if (!Number.isFinite(limit) || limit <= 0) return normalized;
  return Math.max(-limit, Math.min(limit, normalized));
}

function memberLogit(member, vector, standardizationClamp = 6) {
  let logit = Number(member.intercept) || 0;
  for (let index = 0; index < vector.length; index += 1) {
    const value = vector[index];
    const mean = Number(member.mean[index]) || 0;
    const scale = Number(member.scale[index]) || 1;
    const coefficient = Number(member.coefficients[index]) || 0;
    logit += coefficient * standardizedValue(value, mean, scale, standardizationClamp);
  }
  return logit;
}

function calibrateProbability(rawProbability, calibration = null) {
  const clipped = Math.min(1 - 1e-7, Math.max(1e-7, Number(rawProbability) || 0));
  if (!calibration) return clipped;
  const rawLogit = Math.log(clipped / (1 - clipped));
  const slope = Number(calibration.slope);
  const intercept = Number(calibration.intercept);
  if (!Number.isFinite(slope) || !Number.isFinite(intercept)) return clipped;
  return sigmoid(slope * rawLogit + intercept);
}

function predictWithModel(model, url, domainInfo = {}) {
  const validated = validateModel(model);
  const extracted = extractUrlMlFeatures(url, domainInfo);
  if (!extracted) {
    return {
      available: false,
      error: "URL không hợp lệ",
      probability: 0,
      prediction: "SAFE"
    };
  }

  const standardizationClamp = Number(validated.standardizationClamp) || 6;
  const memberProbabilities = validated.modelType === "bagged-logistic-ensemble"
    ? validated.members.map(member => sigmoid(memberLogit(member, extracted.featureVector, standardizationClamp)))
    : [sigmoid(memberLogit(validated, extracted.featureVector, standardizationClamp))];

  const rawProbability = memberProbabilities.reduce((sum, value) => sum + value, 0) / memberProbabilities.length;
  const probability = calibrateProbability(rawProbability, validated.calibration);
  const threshold = Number(validated.threshold) || 0.5;
  const prediction = probability >= threshold ? "PHISHING" : "SAFE";

  return {
    available: true,
    modelVersion: validated.modelVersion,
    modelType: validated.modelType,
    probability,
    percentage: Math.round(probability * 100),
    threshold,
    prediction,
    featureVersion: validated.featureVersion || "url-lexical-v4",
    ensembleSize: memberProbabilities.length,
    rawProbability,
    memberProbabilities,
    calibration: validated.calibration || null,
    standardizationClamp,
    normalizedUrl: extracted.metadata.normalizedUrl,
    removedTrackingParameterCount: extracted.metadata.removedTrackingParameterCount,
    features: extracted.values
  };
}

async function predictUrlRisk(url, domainInfo = {}) {
  try {
    const model = await loadUrlModel();
    return predictWithModel(model, url, domainInfo);
  } catch (error) {
    return {
      available: false,
      error: error?.message || String(error),
      probability: 0,
      percentage: 0,
      prediction: "SAFE"
    };
  }
}

function resetUrlModelCacheForTests() {
  cachedModelPromise = null;
}

export {
  sigmoid,
  calibrateProbability,
  standardizedValue,
  validateModel,
  loadUrlModel,
  predictWithModel,
  predictUrlRisk,
  resetUrlModelCacheForTests
};
