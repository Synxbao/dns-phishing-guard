// Parent-control helpers for Child Mode.
// The PIN is never stored as plain text. It is derived with PBKDF2-SHA-256.
// This protects the extension UI from casual use; it is not a replacement for
// Windows accounts, browser profiles, or operating-system parental controls.

const PIN_HASH_KEY = "parentPinHash";
const PIN_SALT_KEY = "parentPinSalt";
const PIN_ITERATIONS_KEY = "parentPinIterations";
const PARENT_UNLOCKED_UNTIL_KEY = "parentUnlockedUntil";
const DEFAULT_ITERATIONS = 120000;
const DEFAULT_UNLOCK_MINUTES = 10;

function validatePin(pin) {
  return /^\d{4,8}$/.test(String(pin || ""));
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function derivePinHash(pin, saltBytes, iterations = DEFAULT_ITERATIONS) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(String(pin)),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations
    },
    keyMaterial,
    256
  );

  return new Uint8Array(bits);
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i += 1) difference |= a[i] ^ b[i];
  return difference === 0;
}

async function hasParentPin() {
  const data = await chrome.storage.local.get(PIN_HASH_KEY);
  return Boolean(data[PIN_HASH_KEY]);
}

async function setParentPin(pin) {
  if (!validatePin(pin)) {
    return { ok: false, error: "PIN phải gồm từ 4 đến 8 chữ số." };
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derivePinHash(pin, salt, DEFAULT_ITERATIONS);

  await chrome.storage.local.set({
    [PIN_HASH_KEY]: bytesToBase64(hash),
    [PIN_SALT_KEY]: bytesToBase64(salt),
    [PIN_ITERATIONS_KEY]: DEFAULT_ITERATIONS
  });

  return { ok: true };
}

async function verifyParentPin(pin) {
  if (!validatePin(pin)) return false;

  const data = await chrome.storage.local.get([
    PIN_HASH_KEY,
    PIN_SALT_KEY,
    PIN_ITERATIONS_KEY
  ]);

  if (!data[PIN_HASH_KEY] || !data[PIN_SALT_KEY]) return false;

  try {
    const expected = base64ToBytes(data[PIN_HASH_KEY]);
    const salt = base64ToBytes(data[PIN_SALT_KEY]);
    const actual = await derivePinHash(
      pin,
      salt,
      Number(data[PIN_ITERATIONS_KEY]) || DEFAULT_ITERATIONS
    );
    return constantTimeEqual(expected, actual);
  } catch {
    return false;
  }
}

async function unlockParent(pin, minutes = DEFAULT_UNLOCK_MINUTES) {
  const valid = await verifyParentPin(pin);
  if (!valid) return { ok: false, error: "PIN không đúng." };

  const safeMinutes = Math.min(60, Math.max(1, Number(minutes) || DEFAULT_UNLOCK_MINUTES));
  const unlockedUntil = Date.now() + safeMinutes * 60 * 1000;
  await chrome.storage.session.set({ [PARENT_UNLOCKED_UNTIL_KEY]: unlockedUntil });
  return { ok: true, unlockedUntil };
}

async function isParentUnlocked() {
  const data = await chrome.storage.session.get(PARENT_UNLOCKED_UNTIL_KEY);
  const unlockedUntil = Number(data[PARENT_UNLOCKED_UNTIL_KEY]) || 0;
  if (unlockedUntil <= Date.now()) {
    if (unlockedUntil) await chrome.storage.session.remove(PARENT_UNLOCKED_UNTIL_KEY);
    return false;
  }
  return true;
}

async function getParentState() {
  const configured = await hasParentPin();
  const data = await chrome.storage.session.get(PARENT_UNLOCKED_UNTIL_KEY);
  const unlockedUntil = Number(data[PARENT_UNLOCKED_UNTIL_KEY]) || 0;
  const unlocked = configured && unlockedUntil > Date.now();
  return { configured, unlocked, unlockedUntil: unlocked ? unlockedUntil : 0 };
}

async function lockParent() {
  await chrome.storage.session.remove(PARENT_UNLOCKED_UNTIL_KEY);
  return { ok: true };
}

async function clearParentPin() {
  await chrome.storage.local.remove([
    PIN_HASH_KEY,
    PIN_SALT_KEY,
    PIN_ITERATIONS_KEY
  ]);
  await lockParent();
  return { ok: true };
}

export {
  validatePin,
  hasParentPin,
  setParentPin,
  verifyParentPin,
  unlockParent,
  isParentUnlocked,
  getParentState,
  lockParent,
  clearParentPin,
  DEFAULT_UNLOCK_MINUTES
};
