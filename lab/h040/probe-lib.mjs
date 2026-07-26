const PROBE_VALUE_KEYS = [
  'ctimeNs',
  'inode',
  'isCharacterDevice',
  'major',
  'minor',
  'rdev',
  'rdevHex',
  'stDev',
];

const PREDICATE_KEYS = [
  'complete',
  'dynamicAbsent',
  'dynamicInitialMatchesHost',
  'dynamicReturnedMatchesHost',
  'hostEpochChanged',
  'metadataOnly',
  'staticPersists',
  'staticUnchanged',
];

const RESULT_PREDICATES = [
  'dynamicInitialMatchesHost',
  'dynamicReturnedMatchesHost',
  'dynamicAbsent',
  'staticPersists',
  'staticUnchanged',
  'hostEpochChanged',
];

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value, keys) {
  return (
    isPlainRecord(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort())
  );
}

function normalizeAbsolutePath(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.includes('\u0000')) return null;
  const segments = value.split('/');
  if (
    segments.length < 2 ||
    segments.slice(1).some((segment) => segment.length === 0 || segment === '.' || segment === '..')
  ) {
    return null;
  }
  return value;
}

function normalizeDecimal(value, { positive = false } = {}) {
  if (typeof value !== 'string' || !/^[0-9]+$/u.test(value)) return null;
  const parsed = BigInt(value);
  if (positive ? parsed <= 0n : parsed < 0n) return null;
  return parsed.toString();
}

function encodedLinuxDeviceNumber(major, minor) {
  const majorBigInt = BigInt(major);
  const minorBigInt = BigInt(minor);
  return (
    ((majorBigInt & 0xfffn) << 8n) |
    (minorBigInt & 0xffn) |
    ((majorBigInt & ~0xfffn) << 32n) |
    ((minorBigInt & ~0xffn) << 12n)
  );
}

function normalizeDeviceValue(value, exactKeys) {
  if (!isPlainRecord(value)) return null;
  if (exactKeys && !hasExactKeys(value, PROBE_VALUE_KEYS)) return null;
  if (!PROBE_VALUE_KEYS.every((key) => Object.hasOwn(value, key))) return null;
  const stDev = normalizeDecimal(value.stDev);
  const inode = normalizeDecimal(value.inode, { positive: true });
  const ctimeNs = normalizeDecimal(value.ctimeNs);
  const rdev = normalizeDecimal(value.rdev);
  if (stDev === null || inode === null || ctimeNs === null || rdev === null) return null;
  if (
    !Number.isSafeInteger(value.major) ||
    value.major < 0 ||
    !Number.isSafeInteger(value.minor) ||
    value.minor < 0 ||
    value.isCharacterDevice !== true
  ) {
    return null;
  }
  if (typeof value.rdevHex !== 'string') return null;
  const rdevHexMatch = /^([0-9a-f]+):([0-9a-f]+)$/iu.exec(value.rdevHex);
  if (!rdevHexMatch) return null;
  const hexMajor = Number.parseInt(rdevHexMatch[1], 16);
  const hexMinor = Number.parseInt(rdevHexMatch[2], 16);
  if (
    !Number.isSafeInteger(hexMajor) ||
    !Number.isSafeInteger(hexMinor) ||
    hexMajor !== value.major ||
    hexMinor !== value.minor ||
    encodedLinuxDeviceNumber(value.major, value.minor).toString() !== rdev
  ) {
    return null;
  }
  return {
    stDev,
    inode,
    ctimeNs,
    rdev,
    rdevHex: `${value.major.toString(16)}:${value.minor.toString(16)}`,
    major: value.major,
    minor: value.minor,
    isCharacterDevice: true,
  };
}

export function normalizeProbeStat(receipt) {
  try {
    if (!isPlainRecord(receipt)) return null;
    const path = normalizeAbsolutePath(receipt.path);
    if (path === null) return null;
    if (receipt.kind === 'missing') {
      const keys = Object.keys(receipt).sort();
      const withoutCode = JSON.stringify(keys) === JSON.stringify(['kind', 'path']);
      const withCode =
        JSON.stringify(keys) === JSON.stringify(['code', 'kind', 'path']) &&
        receipt.code === 'ENOENT';
      return withoutCode || withCode ? { kind: 'missing', path, code: 'ENOENT' } : null;
    }
    if (receipt.kind !== 'value' || !hasExactKeys(receipt, ['kind', 'path', 'value'])) return null;
    const value = normalizeDeviceValue(receipt.value, true);
    return value === null ? null : { kind: 'value', path, value };
  } catch {
    return null;
  }
}

export function dynamicMatchesHost(probeReceipt, hostNode) {
  try {
    const probe = normalizeProbeStat(probeReceipt);
    if (probe === null) return null;
    if (probe.kind === 'missing') return false;
    if (!isPlainRecord(hostNode)) return null;
    const hostPath = normalizeAbsolutePath(hostNode.devicePath);
    const hostStat = normalizeDeviceValue(hostNode.stat, false);
    if (hostPath === null || hostStat === null) return null;
    const hostName = /^\/dev\/(hidraw[0-9]+)$/u.exec(hostPath)?.[1];
    if (!hostName) return null;
    return (
      probe.path === `/host-dev/${hostName}` &&
      JSON.stringify(probe.value) === JSON.stringify(hostStat)
    );
  } catch {
    return null;
  }
}

function normalizeHostEpoch(node) {
  if (!isPlainRecord(node) || !isPlainRecord(node.usbAncestor)) return null;
  const deviceNumber = normalizeDecimal(node.usbAncestor.deviceNumber, { positive: true });
  const hidDevicePath = normalizeAbsolutePath(node.hidDevicePath);
  const stat = normalizeDeviceValue(node.stat, false);
  if (deviceNumber === null || hidDevicePath === null || stat === null) return null;
  return {
    deviceNumber,
    hidDevicePath,
    inode: stat.inode,
    ctimeNs: stat.ctimeNs,
  };
}

export function hostEpochChanged(beforeHostNode, afterHostNode) {
  try {
    const before = normalizeHostEpoch(beforeHostNode);
    const after = normalizeHostEpoch(afterHostNode);
    if (before === null || after === null) return null;
    return (
      before.deviceNumber !== after.deviceNumber ||
      before.hidDevicePath !== after.hidDevicePath ||
      before.inode !== after.inode ||
      before.ctimeNs !== after.ctimeNs
    );
  } catch {
    return null;
  }
}

export function staticIdentityUnchanged(initialStatic, absentStatic, returnedStatic) {
  try {
    const receipts = [initialStatic, absentStatic, returnedStatic].map(normalizeProbeStat);
    if (receipts.some((receipt) => receipt === null)) return null;
    if (receipts.some((receipt) => receipt.kind !== 'value')) return false;
    const [initial, ...rest] = receipts;
    return rest.every((receipt) => JSON.stringify(receipt) === JSON.stringify(initial));
  } catch {
    return null;
  }
}

export function classifyMappingOutcome(predicates) {
  try {
    if (!hasExactKeys(predicates, PREDICATE_KEYS)) return 'inconclusive';
    if (!PREDICATE_KEYS.every((key) => typeof predicates[key] === 'boolean')) {
      return 'inconclusive';
    }
    if (!predicates.complete || !predicates.metadataOnly) return 'inconclusive';
    return RESULT_PREDICATES.every((key) => predicates[key]) ? 'supported' : 'refuted';
  } catch {
    return 'inconclusive';
  }
}
