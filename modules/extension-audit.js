const PERMISSION_WEIGHTS = {
  debugger: 45,
  nativeMessaging: 35,
  proxy: 35,
  cookies: 25,
  history: 25,
  downloads: 20,
  clipboardRead: 20,
  clipboardWrite: 10,
  management: 20,
  webRequest: 15,
  webRequestBlocking: 25,
  privacy: 15,
  geolocation: 15
};

function auditExtension(extension) {
  let score = 0;
  const reasons = [];
  const permissions = extension.permissions || [];
  const hostPermissions = extension.hostPermissions || [];

  for (const permission of permissions) {
    const points = PERMISSION_WEIGHTS[permission] || 0;
    if (points > 0) {
      score += points;
      reasons.push(`Có quyền ${permission}`);
    }
  }

  if (hostPermissions.some(item => item === "<all_urls>" || item === "*://*/*")) {
    score += 30;
    reasons.push("Có thể hoạt động trên hầu hết website");
  } else if (hostPermissions.length >= 10) {
    score += 15;
    reasons.push("Được cấp quyền trên nhiều website");
  }

  score = Math.min(100, score);
  let level = "THẤP";
  if (score >= 70) level = "CAO";
  else if (score >= 35) level = "TRUNG BÌNH";

  return {
    id: extension.id,
    name: extension.name,
    description: extension.description || "",
    enabled: extension.enabled,
    installType: extension.installType,
    type: extension.type,
    score,
    level,
    reasons,
    permissions,
    hostPermissions
  };
}

async function requestManagementPermission() {
  return chrome.permissions.request({ permissions: ["management"] });
}

async function getExtensionAudit() {
  const allowed = await chrome.permissions.contains({ permissions: ["management"] });
  if (!allowed) return { granted: false, items: [] };

  const self = await chrome.management.getSelf();
  const all = await chrome.management.getAll();
  const items = all
    .filter(item => item.type === "extension" && item.id !== self.id)
    .map(auditExtension)
    .sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));

  return { granted: true, items };
}

async function setExtensionEnabled(id, enabled) {
  await chrome.management.setEnabled(id, enabled);
}

export {
  auditExtension,
  requestManagementPermission,
  getExtensionAudit,
  setExtensionEnabled,
  PERMISSION_WEIGHTS
};
