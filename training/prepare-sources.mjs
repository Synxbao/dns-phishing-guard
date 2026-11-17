import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const releaseRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const workspaceRoot = path.resolve(releaseRoot, "..");
const outputDir = path.join(releaseRoot, "training", "source");

const sources = {
  benign_urls_1000: path.join(workspaceRoot, "benign_urls_1000.txt"),
  phishing_urls_1000: path.join(workspaceRoot, "phishing_urls_1000.txt"),
  openphish: path.join(workspaceRoot, "training-4000-source", "openphish-feed-2026-08-10.txt"),
  urlhaus: path.join(workspaceRoot, "training-4000-source", "urlhaus-recent-2026-08-10.csv"),
  tranco: path.join(workspaceRoot, "dns-phishing-guard-v1.5.1", "evaluation", "raw", "tranco.csv")
};

await fs.mkdir(outputDir, { recursive: true });
await Promise.all([
  fs.copyFile(sources.benign_urls_1000, path.join(outputDir, "benign_urls_1000.txt")),
  fs.copyFile(sources.phishing_urls_1000, path.join(outputDir, "phishing_urls_1000.txt")),
  fs.copyFile(sources.openphish, path.join(outputDir, "openphish-feed-2026-08-10.txt")),
  fs.copyFile(sources.urlhaus, path.join(outputDir, "urlhaus-recent-2026-08-10.csv"))
]);

const trancoLines = (await fs.readFile(sources.tranco, "utf8")).split(/\r?\n/).filter(Boolean).slice(0, 5000);
await fs.writeFile(path.join(outputDir, "tranco-top-5000.csv"), `${trancoLines.join("\n")}\n`, "utf8");

console.log(JSON.stringify({
  outputDir,
  files: 5,
  trancoRows: trancoLines.length
}, null, 2));
