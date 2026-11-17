// ============================================================
// Homoglyph & Punycode detection module
// ============================================================

// Bảng ánh xạ các ký tự Unicode "giống" ký tự Latin thường gặp
// trong tấn công phishing (Cyrillic, Greek, các ký tự đặc biệt...)
const HOMOGLYPH_MAP = {
  // Cyrillic look-alikes
  "а": "a", // U+0430
  "е": "e", // U+0435
  "о": "o", // U+043E
  "р": "p", // U+0440
  "с": "c", // U+0441
  "у": "y", // U+0443
  "х": "x", // U+0445
  "і": "i", // U+0456
  "ј": "j", // U+0458
  "ѕ": "s", // U+0455
  "һ": "h", // U+04BB
  "ԁ": "d", // U+0501
  "ԛ": "q", // U+051B
  "ѡ": "w", // U+0461
  "к": "k", // U+043A
  "м": "m", // U+043C
  "н": "h", // U+043D
  "т": "t", // U+0442
  "в": "b", // U+0432
  "г": "r", // U+0433

  // Greek look-alikes
  "α": "a",
  "ο": "o",
  "ρ": "p",
  "υ": "y",
  "ι": "i",
  "κ": "k",
  "ν": "v",
  "τ": "t",

  // Ký tự đặc biệt / full-width / khác
  "ⅰ": "i",
  "ⅼ": "l",
  "０": "0",
  "１": "1",
  "２": "2",
  "３": "3",
  "５": "5",
  "６": "6",
  "８": "8",
  "ｏ": "o",
  "а́": "a"
};

/**
 * Kiểm tra domain có chứa ký tự Punycode (IDN) hay không.
 * Domain dạng xn--xxxx là dấu hiệu phổ biến của tấn công IDN homograph.
 */
function isPunycode(domain) {
  return domain
    .split(".")
    .some(label => label.toLowerCase().startsWith("xn--"));
}

/**
 * Giải mã Punycode sang Unicode để phân tích (dùng API built-in của trình duyệt
 * thông qua URL/domain APIs không hỗ trợ decode trực tiếp, nên ta dùng thuật toán
 * Punycode chuẩn RFC 3492 rút gọn).
 */
function punycodeDecode(input) {
  // Bootstring params theo RFC 3492
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700, initialBias = 72, initialN = 128;

  function adapt(delta, numPoints, firstTime) {
    delta = firstTime ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((base - tMin) * tMax) >> 1) {
      delta = Math.floor(delta / (base - tMin));
      k += base;
    }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  }

  function decodeDigit(cp) {
    if (cp - 48 < 10) return cp - 22;
    if (cp - 65 < 26) return cp - 65;
    if (cp - 97 < 26) return cp - 97;
    return base;
  }

  input = input.replace(/^xn--/i, "");
  let output = [];
  let inputArr = input;
  let basicLength = inputArr.lastIndexOf("-");
  if (basicLength < 0) basicLength = 0;

  for (let j = 0; j < basicLength; j++) {
    const code = inputArr.charCodeAt(j);
    if (code >= 0x80) return null; // invalid
    output.push(code);
  }

  let i = 0, n = initialN, bias = initialBias;
  let index = basicLength > 0 ? basicLength + 1 : 0;

  while (index < inputArr.length) {
    let oldi = i, w = 1;
    for (let k = base; ; k += base) {
      if (index >= inputArr.length) return null;
      const digit = decodeDigit(inputArr.charCodeAt(index++));
      if (digit >= base) return null;
      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    const numPoints = output.length + 1;
    bias = adapt(i - oldi, numPoints, oldi === 0);
    n += Math.floor(i / numPoints);
    i %= numPoints;
    output.splice(i, 0, n);
    i++;
  }

  try {
    return String.fromCodePoint(...output);
  } catch (e) {
    return null;
  }
}

/**
 * Chuẩn hóa domain: nếu có label punycode, decode để lấy dạng Unicode gốc.
 * Trả về { displayDomain, isPunycode, decodeFailed }
 */
function resolveUnicodeDomain(domain) {
  const labels = domain.split(".");
  let hasPunycode = false;
  let decodeFailed = false;

  const resolved = labels.map(label => {
    if (label.toLowerCase().startsWith("xn--")) {
      hasPunycode = true;
      const decoded = punycodeDecode(label);
      if (decoded === null) {
        decodeFailed = true;
        return label;
      }
      return decoded;
    }
    return label;
  });

  return {
    displayDomain: resolved.join("."),
    isPunycode: hasPunycode,
    decodeFailed
  };
}

/**
 * Chuyển một chuỗi Unicode về dạng "ASCII-skeleton" bằng cách thay
 * các ký tự homoglyph bằng ký tự Latin tương ứng.
 */
function toSkeleton(str) {
  let result = "";
  for (const ch of str) {
    result += HOMOGLYPH_MAP[ch] || ch;
  }
  return result.toLowerCase();
}

/**
 * Kiểm tra xem domain (sau khi decode Unicode) có chứa ký tự
 * homoglyph đáng ngờ hay không, và trả về bản "skeleton" để
 * so sánh typosquatting.
 */
function analyzeHomoglyph(domain) {
  const { displayDomain, isPunycode: punycodeFlag, decodeFailed } = resolveUnicodeDomain(domain);

  let hasHomoglyph = false;
  const suspiciousChars = [];

  for (const ch of displayDomain) {
    if (HOMOGLYPH_MAP[ch]) {
      hasHomoglyph = true;
      suspiciousChars.push(ch);
    }
    // Ký tự ngoài phạm vi ASCII cơ bản mà không phải dấu chấm/gạch ngang
    const code = ch.codePointAt(0);
    if (code > 127 && ch !== "." && ch !== "-") {
      hasHomoglyph = true;
    }
  }

  const skeleton = toSkeleton(displayDomain);

  return {
    displayDomain,
    isPunycode: punycodeFlag,
    decodeFailed,
    hasHomoglyph,
    suspiciousChars: [...new Set(suspiciousChars)],
    skeleton
  };
}

export { analyzeHomoglyph, isPunycode, punycodeDecode, resolveUnicodeDomain, toSkeleton };
