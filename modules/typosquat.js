// ============================================================
// Typosquatting detection module
// False-positive reduction rules introduced in v1.7.1.
// ============================================================

const SINGLE_SUFFIX_PROTECTED_LABELS = new Set([
  "steamcommunity", "steampowered", "paypal", "coinbase", "wellsfargo",
  "bankofamerica", "vietcombank", "techcombank", "vietinbank"
]);

function levenshtein(a, b) {
  const left = String(a || "");
  const right = String(b || "");
  const dp = Array.from({ length: left.length + 1 }, () =>
    new Array(right.length + 1).fill(0)
  );

  for (let i = 0; i <= left.length; i += 1) dp[i][0] = i;
  for (let j = 0; j <= right.length; j += 1) dp[0][j] = j;

  for (let i = 1; i <= left.length; i += 1) {
    for (let j = 1; j <= right.length; j += 1) {
      dp[i][j] =
        left[i - 1] === right[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }

  return dp[left.length][right.length];
}

function splitDomain(domain) {
  const normalized = String(domain || "")
    .trim()
    .toLowerCase()
    .replace(/^www\./, "")
    .replace(/\.$/, "");
  const labels = normalized.split(".").filter(Boolean);
  return {
    normalized,
    label: labels[0] || "",
    suffix: labels.slice(1).join(".")
  };
}

function isAdjacentTransposition(a, b) {
  if (a.length !== b.length || a === b) return false;
  const differing = [];
  for (let index = 0; index < a.length; index += 1) {
    if (a[index] !== b[index]) differing.push(index);
    if (differing.length > 2) return false;
  }
  if (differing.length !== 2) return false;
  const [first, second] = differing;
  return (
    second === first + 1 &&
    a[first] === b[second] &&
    a[second] === b[first]
  );
}

function qualifiesAsTyposquat(inputLabel, knownLabel, distance) {
  const maxLength = Math.max(inputLabel.length, knownLabel.length);
  if (maxLength < 4) return false;

  const ratio = distance / maxLength;

  // One edit is suspicious for labels of at least four characters.
  if (distance === 1 && ratio <= 0.25) return true;

  // Adjacent swaps are common typo attacks, but require a reasonable label length.
  if (distance === 2 && maxLength >= 6 && isAdjacentTransposition(inputLabel, knownLabel)) {
    return true;
  }

  // Two arbitrary edits are accepted only for longer brand labels.
  // This prevents chess.com from matching chase.com (2/5 = 40%).
  return distance === 2 && maxLength >= 8 && ratio <= 0.25;
}

/**
 * Tìm domain nổi tiếng gần giống nhất với domain đầu vào đã chuyển về skeleton.
 * So sánh nhãn đăng ký thay vì toàn bộ chuỗi domain và áp dụng ngưỡng tương đối
 * để hạn chế false positive trên các domain ngắn, độc lập.
 *
 * @param {string} domainSkeleton
 * @param {string[]} knownDomains
 */
function findSimilarDomain(domainSkeleton, knownDomains, options = {}) {
  const input = splitDomain(domainSkeleton);
  if (!input.normalized || !input.label) return null;

  const normalizedKnown = (knownDomains || []).map(splitDomain);
  const protectedLabels = new Set([
    ...SINGLE_SUFFIX_PROTECTED_LABELS,
    ...(options.exactBrandLabels || []).map(value => splitDomain(value).label).filter(Boolean)
  ]);
  if (normalizedKnown.some(item => item.normalized === input.normalized)) return null;

  let closest = null;

  for (const known of normalizedKnown) {
    if (!known.label) continue;

    const lengthDifference = Math.abs(known.label.length - input.label.length);
    if (lengthDifference > 2) continue;

    const distance = levenshtein(input.label, known.label);
    const exactBrandDifferentSuffix = (
      distance === 0 &&
      input.suffix !== known.suffix &&
      protectedLabels.has(known.label)
    );
    if (!exactBrandDifferentSuffix && !qualifiesAsTyposquat(input.label, known.label, distance)) continue;

    const maxLength = Math.max(input.label.length, known.label.length);
    const similarity = 1 - distance / maxLength;
    const suffixMatches = Boolean(input.suffix && known.suffix && input.suffix === known.suffix);

    const candidate = {
      closest: known.normalized,
      distance,
      similarity,
      suffixMatches,
      exactBrandDifferentSuffix,
      matchType: exactBrandDifferentSuffix ? "brand-suffix-mismatch" : "typosquat",
      inputLabel: input.label,
      knownLabel: known.label
    };

    if (
      !closest ||
      candidate.distance < closest.distance ||
      (candidate.distance === closest.distance && candidate.similarity > closest.similarity) ||
      (candidate.distance === closest.distance && candidate.similarity === closest.similarity && candidate.suffixMatches)
    ) {
      closest = candidate;
    }
  }

  return closest;
}

export {
  levenshtein,
  splitDomain,
  isAdjacentTransposition,
  qualifiesAsTyposquat,
  findSimilarDomain
};
