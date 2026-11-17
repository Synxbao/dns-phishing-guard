import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { extractUrlMlFeatures } from "../modules/url-ml-features.js";
import { predictWithModel } from "../modules/url-model.js";
import { getDomainParts, initializeFromText } from "../modules/public-suffix.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const url = process.argv[2];
if (!url) throw new Error('Dùng: npm run explain-url -- "https://example.com/path"');

initializeFromText(await fs.readFile(path.join(root, "data", "public_suffix_list.dat"), "utf8"));
const model = JSON.parse(await fs.readFile(path.join(root, "data", "url-model.json"), "utf8"));
const parsed = new URL(url);
const hostname = parsed.hostname.toLowerCase().replace(/^www\./, "");
const domainInfo = getDomainParts(hostname);
const extracted = extractUrlMlFeatures(url, domainInfo);
const prediction = predictWithModel(model, url, domainInfo);

if (model.modelType !== "logistic-regression") throw new Error("Công cụ hiện hỗ trợ logistic-regression");
const clamp = Number(model.standardizationClamp) || 6;
const contributions = model.featureNames.map((name, index) => {
  const rawStandardized = (extracted.featureVector[index] - model.mean[index]) / (model.scale[index] || 1);
  const standardized = Math.max(-clamp, Math.min(clamp, rawStandardized));
  return {
    feature: name,
    value: extracted.featureVector[index],
    standardized,
    rawStandardized,
    coefficient: model.coefficients[index],
    contribution: model.coefficients[index] * standardized
  };
}).sort((left, right) => Math.abs(right.contribution) - Math.abs(left.contribution));

console.log(JSON.stringify({
  url,
  modelVersion: model.modelVersion,
  threshold: model.threshold,
  probability: prediction.probability,
  prediction: prediction.prediction,
  rawProbability: prediction.rawProbability,
  registrableDomain: domainInfo.registrableDomain,
  topContributions: contributions.slice(0, 15)
}, null, 2));
