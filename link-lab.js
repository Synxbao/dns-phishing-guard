let session = null;

function sessionIdFromQuery() {
  return new URLSearchParams(location.search).get("session") || "";
}

function toneForLevel(level) {
  if (level === "HIGH") return "#ff5a5f";
  if (level === "MEDIUM") return "#ffd45a";
  if (level === "SUSPICIOUS") return "#ffad32";
  return "#37df8d";
}

function titleForLevel(level) {
  if (level === "HIGH") return "Link có rủi ro cao — không nên mở trực tiếp";
  if (level === "MEDIUM") return "Link cần được xác minh kỹ";
  if (level === "SUSPICIOUS") return "Có tín hiệu cần kiểm tra thêm";
  return "Chưa thấy bằng chứng phishing rõ ràng";
}

function formatAge(ageInfo) {
  const days = Number(ageInfo?.ageDays);
  if (!Number.isFinite(days)) return "Không rõ";
  if (days < 60) return `${Math.round(days)} ngày`;
  if (days < 730) return `${Math.round(days / 30)} tháng`;
  return `${(days / 365.25).toFixed(1)} năm`;
}

function setText(id, value) {
  const element = document.getElementById(id);
  if (element) element.textContent = String(value ?? "—");
}

function renderList(id, items, fallback) {
  const list = document.getElementById(id);
  list.replaceChildren();
  const values = items?.length ? items : [fallback];
  for (const value of values) {
    const item = document.createElement("li");
    item.textContent = value;
    list.appendChild(item);
  }
}

function showFatal(title, message) {
  const wrapper = document.createElement("div");
  wrapper.className = "fatal";
  const heading = document.createElement("h1");
  heading.textContent = title;
  const paragraph = document.createElement("p");
  paragraph.textContent = message;
  wrapper.append(heading, paragraph);
  document.querySelector("main").replaceChildren(wrapper);
}

function buildReport(result) {
  return {
    exportedAt: new Date().toISOString(),
    tool: "DNS Phishing Guard Link Lab",
    mode: "preflight",
    privacyNote: "Giá trị query được che trong các URL hiển thị; không xuất URL đầy đủ.",
    target: {
      originalUrl: result.displayOriginalUrl,
      finalUrl: result.displayFinalUrl,
      domain: result.domain
    },
    risk: result.risk,
    verdict: result.verdict,
    network: {
      ...result.network,
      finalUrl: result.displayFinalUrl,
      redirects: (result.network?.redirects || []).map(item => ({ ...item, url: item.displayUrl }))
    },
    coverage: result.coverage,
    checkedAt: result.checkedAt
  };
}

function render(result) {
  const verdict = result.verdict || result.risk || {};
  const level = verdict.level || "SAFE";
  const score = Math.max(0, Math.min(100, Number(verdict.score) || 0));
  const tone = toneForLevel(level);
  const network = result.network || {};
  const signals = network.htmlSignals || {};
  const mlSkipped = Boolean(result.mlInfo?.skipped);
  const mlProbability = Number(result.mlInfo?.probability);

  document.documentElement.style.setProperty("--tone", tone);
  setText("resultTitle", verdict.label || titleForLevel(level));
  setText(
    "resultSummary",
    verdict.reasons?.[0] || result.risk?.recommendations?.[0] || "Hãy kiểm tra kỹ trước khi tiếp tục."
  );
  setText("finalUrl", result.displayFinalUrl || result.domain);
  setText("riskScore", score);
  const dial = document.getElementById("riskDial");
  dial.style.setProperty("--score-angle", `${score * 3.6}deg`);
  dial.style.setProperty("--tone", tone);

  setText("confidence", `${verdict.confidenceScore ?? 0}/100`);
  setText("domainAge", formatAge(result.ageInfo));
  setText("redirectCount", `${network.redirectCount || 0} lần`);
  setText("mlProbability", mlSkipped
    ? "Không áp dụng cho mạng cục bộ"
    : Number.isFinite(mlProbability) ? `${Math.round(mlProbability * 1000) / 10}% · chỉ báo` : "Không chạy");
  setText("httpStatus", network.reachable ? `${network.status || "—"}` : "Không kết nối");
  setText("contentType", network.contentType || "Không xác định");
  setText("downloadRisk", network.downloadRisk?.label || "Chưa xác định");

  setText("scriptCount", signals.scriptCount ?? 0);
  setText("formCount", signals.formCount ?? 0);
  setText("passwordCount", signals.passwordInputCount ?? 0);
  setText("iframeCount", signals.iframeCount ?? 0);
  setText("downloadLinkCount", signals.riskyDownloadLinkCount ?? 0);
  setText("autoNavCount", (signals.autoNavigationSignalCount || 0) + (signals.metaRefreshCount || 0));

  const riskReasons = [...(verdict.reasons || []), ...(result.risk?.reasons || [])];
  if (network.error) riskReasons.unshift(`Probe mạng: ${network.error}`);
  renderList("riskReasons", riskReasons, "Không phát hiện tín hiệu rủi ro rõ ràng trong phạm vi quét trước.");
  renderList("downloadReasons", network.downloadRisk?.reasons, "Không thấy dấu hiệu tải tự động trong tối đa 64 KiB đầu đã đọc.");
  renderList("limitations", result.coverage?.limitations, "Kết quả chỉ phản ánh phạm vi preflight hiện tại.");

  const openNormalBtn = document.getElementById("openNormalBtn");
  openNormalBtn.disabled = level !== "SAFE" || result.previewAllowed === false;
  openNormalBtn.title = result.previewAllowed === false
    ? "Link nhạy cảm, phản hồi chưa xác minh hoặc chuyển hướng bất thường nên thao tác mở đã bị khóa"
    : level === "SAFE"
    ? "Vẫn cần xác nhận trước khi mở tab thường"
    : "Chỉ bật khi kết quả hiện tại là SAFE";
}

function loadPreview() {
  const result = session?.result;
  if (!result?.finalUrl || result.previewAllowed === false || result.network?.probeSkipped) return;
  const button = document.getElementById("loadPreviewBtn");
  const frame = document.getElementById("previewFrame");
  const placeholder = document.getElementById("framePlaceholder");
  const status = document.getElementById("previewStatus");

  button.disabled = true;
  button.textContent = "Đang tải preview…";
  status.textContent = "Đang kết nối không cookie, không referrer; script/form/download vẫn bị khóa.";
  if ("credentialless" in frame) frame.credentialless = true;
  frame.src = result.finalUrl;

  const timer = setTimeout(() => {
    status.textContent = "Nếu vùng preview trống, website có thể đã chặn iframe bằng X-Frame-Options hoặc CSP.";
  }, 9000);

  frame.addEventListener("load", () => {
    clearTimeout(timer);
    placeholder.classList.add("hidden");
    button.textContent = "Preview đã tải";
    status.textContent = "Bản xem trước đã tải với script, form, popup và download bị khóa. Không tương tác hay nhập dữ liệu tại đây.";
  }, { once: true });
}

async function init() {
  const id = sessionIdFromQuery();
  const key = `link_lab_session_${id}`;
  const data = id ? await chrome.storage.session.get(key) : {};
  session = data[key] || null;
  if (!session || Number(session.expiresAt || 0) <= Date.now()) {
    showFatal(
      "Phiên Link Lab không còn hiệu lực",
      "Hãy mở popup DNS Phishing Guard, quét lại URL rồi mở Safe Preview mới."
    );
    return;
  }

  render(session.result);
  if (session.result.previewAllowed === false || session.result.network?.probeSkipped) {
    document.getElementById("loadPreviewBtn").disabled = true;
    document.getElementById("openNormalBtn").disabled = true;
    document.getElementById("previewStatus").textContent = "Preview và mở trực tiếp đã bị khóa vì link nhạy cảm, phản hồi chưa xác minh hoặc chuyển hướng bất thường.";
    return;
  }
  const isolation = await chrome.runtime.sendMessage({ type: "ENSURE_SAFE_PREVIEW_MODE" }).catch(() => null);
  if (isolation?.done) {
    document.getElementById("loadPreviewBtn").addEventListener("click", loadPreview);
  } else {
    document.getElementById("loadPreviewBtn").disabled = true;
    document.getElementById("previewStatus").textContent = isolation?.error || "Không thể kích hoạt luật cô lập; preview đã bị khóa.";
  }
  document.getElementById("openNormalBtn").addEventListener("click", async () => {
    const confirmed = window.confirm("Kết quả SAFE không phải bảo đảm tuyệt đối. Chỉ mở tab thường nếu bạn nhận ra domain và không định nhập dữ liệu nhạy cảm. Tiếp tục?");
    if (confirmed) await chrome.tabs.create({ url: session.result.finalUrl });
  });
  document.getElementById("copyBtn").addEventListener("click", async event => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(buildReport(session.result), null, 2));
      event.currentTarget.textContent = "Đã sao chép";
    } catch {
      event.currentTarget.textContent = "Không thể sao chép";
    }
  });
}

document.getElementById("closeBtn").addEventListener("click", async () => {
  const tab = await chrome.tabs.getCurrent().catch(() => null);
  if (tab?.id) await chrome.tabs.remove(tab.id).catch(() => {});
  else window.close();
});
init().catch(error => {
  showFatal("Không thể mở Link Lab", String(error.message || error));
});
