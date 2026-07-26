import { createHash } from 'node:crypto';

export const TARGET_USB = Object.freeze({
  vendorId: '0fd9',
  productId: '0080',
  label: 'Elgato Stream Deck MK.2',
});

export const CLAIM_BOUNDARY = Object.freeze({
  proves: [
    'exact host, kernel, architecture, principal, and group observation',
    'USB enumeration for vendor 0fd9 and product 0080',
    'current sysfs HID identity to hidraw-node mapping',
    'current device-node ownership, mode, effective access, and nonblocking open capability',
    'point-in-time owner-process and Companion-process observation',
  ],
  excludes: [
    'stable USB bus, device number, or hidraw index across reconnect or reboot',
    'Companion acquisition or ownership of the device',
    'physical key event delivery or rendered button pixels',
    'USB reconnect, reboot, login, startup, or visual-state recovery',
    'OverlayKit command or production-state authority',
    'OBS output truth or operator perception',
  ],
});

export function parseProperties(text) {
  const properties = {};
  for (const line of text.split(/\r?\n/u)) {
    const separator = line.indexOf('=');
    if (separator <= 0) continue;
    properties[line.slice(0, separator)] = line.slice(separator + 1);
  }
  return properties;
}

export function parseHidId(value) {
  const match = /^([0-9a-f]+):([0-9a-f]+):([0-9a-f]+)$/iu.exec(value ?? '');
  if (!match) return null;
  return {
    bus: match[1].toLowerCase(),
    vendorId: match[2].slice(-4).toLowerCase(),
    productId: match[3].slice(-4).toLowerCase(),
  };
}

export function matchesTargetHid(properties, target = TARGET_USB) {
  const identity = parseHidId(properties.HID_ID);
  return (
    identity !== null &&
    identity.vendorId === target.vendorId &&
    identity.productId === target.productId
  );
}

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value === null || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, canonicalize(value[key])])
  );
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function sha256Canonical(value) {
  return sha256(canonicalJson(value));
}

export function parseFuserPids(stdout, stderr) {
  const combined = `${stdout}\n${stderr}`;
  return [
    ...new Set(
      [...combined.matchAll(/(?:^|\s)([1-9][0-9]*)(?=\s|$)/gu)].map((match) => Number(match[1]))
    ),
  ].sort((left, right) => left - right);
}

export function classifyFuserResult({ exitCode, errorCode, stdout, stderr }) {
  const diagnostic = `${stdout}\n${stderr}`;
  const usageError = /(?:Usage:\s*fuser|No process specification given)/u.test(diagnostic);
  return {
    observed: errorCode === null && !usageError && (exitCode === 0 || exitCode === 1),
    usageError,
    pids: parseFuserPids(stdout, stderr),
  };
}

export function stableDeviceSnapshot({ mode, uid, gid, rdev, ueventSha256 }) {
  return { mode, uid, gid, rdev, ueventSha256 };
}
