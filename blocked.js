let context = null;

function queryDomain() {
  return new URLSearchParams(location.search).get("domain") || "";
}

async function loadContext() {
  const domain = queryDomain();
  const response = await chrome.runtime.sendMessage({ type: "GET_BLOCK_CONTEXT", domain }).catch(() => null);
  context = response?.done ? response : { domain };
  document.getElementById("domain").textContent = context.domain || domain || "Không xác định";
  document.getElementById("blockedAt").textContent = new Date().toLocaleTimeString("vi-VN", {
    hour: "2-digit",
    minute: "2-digit"
  });
}

document.getElementById("backBtn").addEventListener("click", () => {
  if (history.length > 1) history.back();
  else location.href = "about:blank";
});

function normalizedConfirmation(value) {
  return String(value || "").trim().toLowerCase().replace(/^www\./, "");
}

function openAllowConfirmation() {
  const panel = document.getElementById("allowConfirm");
  const input = document.getElementById("confirmationInput");
  document.getElementById("confirmDomain").textContent = context?.domain || "—";
  panel.classList.remove("hidden");
  input.value = "";
  document.getElementById("confirmAllowBtn").disabled = true;
  input.focus();
}

async function confirmAllowOnce() {
  const status = document.getElementById("status");
  if (!context?.attemptedUrl) {
    status.textContent = "Không lấy được URL ban đầu. Hãy quay lại và tự nhập địa chỉ nếu thực sự cần thiết.";
    return;
  }

  status.textContent = "Đang yêu cầu cho phép…";
  const response = await chrome.runtime.sendMessage({
    type: "ALLOW_BLOCKED_ONCE",
    domain: context.domain,
    url: context.attemptedUrl,
    tabId: context.tabId,
    confirmationDomain: document.getElementById("confirmationInput").value
  }).catch(() => null);

  if (response?.requiresParent) {
    status.textContent = "Chế độ trẻ em đang bật. Hãy mở popup extension và nhờ người lớn nhập PIN trước.";
  } else if (!response?.done) {
    status.textContent = response?.error || "Không thể cho phép. Hãy quay lại.";
  }
}

document.getElementById("allowBtn").addEventListener("click", openAllowConfirmation);
document.getElementById("cancelAllowBtn").addEventListener("click", () => {
  document.getElementById("allowConfirm").classList.add("hidden");
  document.getElementById("backBtn").focus();
});
document.getElementById("confirmationInput").addEventListener("input", event => {
  document.getElementById("confirmAllowBtn").disabled =
    normalizedConfirmation(event.target.value) !== normalizedConfirmation(context?.domain);
});
document.getElementById("confirmationInput").addEventListener("keydown", event => {
  if (event.key === "Enter" && !document.getElementById("confirmAllowBtn").disabled) confirmAllowOnce();
});
document.getElementById("confirmAllowBtn").addEventListener("click", confirmAllowOnce);

loadContext().then(() => document.getElementById("backBtn").focus());
