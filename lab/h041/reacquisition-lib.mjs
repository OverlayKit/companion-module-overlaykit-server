import { randomBytes } from 'node:crypto';

const STAT_IDENTITY_KEYS = ['stDev', 'inode', 'ctimeNs', 'rdevHex'];
const LIFECYCLE_KEYS = [
  'containerId',
  'imageId',
  'startedAt',
  'restartCount',
  'hostPid',
  'pid1StartTicks',
  'pidNamespace',
  'mountNamespace',
  'cgroup',
  'hostCgroup',
  'cgroupNamespaceMode',
];
const SURFACE_WORKER_KEYS = [
  'pid',
  'startTicks',
  'ppid',
  'parentStartTicks',
  'pidNamespace',
  'mountNamespace',
  'cgroup',
];
const PREDICATE_KEYS = [
  'complete',
  'interventionFree',
  'permissionBoundaryExact',
  'hostEpochChanged',
  'dynamicViewTracksHost',
  'topLevelLifecycleUnchanged',
  'baselineAcquired',
  'descriptorAbsent',
  'postReturnDescriptorObserved',
  'postReturnLogMarkersObserved',
  'deadlineBoundaryConsistent',
];
const PREREQUISITE_KEYS = PREDICATE_KEYS.slice(0, 8);

export const H041_CLAIM_BOUNDARY = Object.freeze({
  proves: [
    'post-login behavior on the exact Fedora 43 host, official Companion 4.3.3 image, and physical MK.2 identity',
    'one intervention-free human-bounded USB disappearance and return through the declared dynamic device view',
    'baseline acquisition, descriptor absence, and bounded post-return Companion descriptor and log observations',
    'top-level container and PID 1 continuity across the exact observed host enumeration epoch',
    'release of the lab-owned container and the currently enumerable MK.2 node after the run',
  ],
  excludes: [
    'physical button command delivery, OverlayKit configuration, rendered pixels, and operator perception',
    'production acceptance or security approval of any device-directory bind or device cgroup rule',
    'udev, systemd, supervisor, rescan, restart, recreation, native deployment, or reboot behavior',
    'pre-login availability, multiple devices, long outages, OBS truth, or complete production recovery',
    'support beyond the exact tested host, image, principal, device, and process identities',
  ],
});

export function runId() {
  return `h041-${new Date().toISOString().replaceAll(/[:.]/gu, '-')}-${randomBytes(4).toString('hex')}`;
}

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value, keys) {
  if (!isPlainRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function nonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function normalizeDecimal(value, { positive = false } = {}) {
  if (typeof value !== 'string' || !/^[0-9]+$/u.test(value)) return null;
  const parsed = BigInt(value);
  if (positive ? parsed <= 0n : parsed < 0n) return null;
  return parsed.toString();
}

function normalizeRdevHex(value) {
  if (typeof value !== 'string') return null;
  const match = /^([0-9a-f]+):([0-9a-f]+)$/iu.exec(value);
  if (!match) return null;
  const major = Number.parseInt(match[1], 16);
  const minor = Number.parseInt(match[2], 16);
  if (!Number.isSafeInteger(major) || !Number.isSafeInteger(minor)) return null;
  return `${major.toString(16)}:${minor.toString(16)}`;
}

function normalizeStatIdentity(value) {
  if (!isPlainRecord(value) || !STAT_IDENTITY_KEYS.every((key) => Object.hasOwn(value, key))) {
    return null;
  }
  const stDev = normalizeDecimal(value.stDev);
  const inode = normalizeDecimal(value.inode, { positive: true });
  const ctimeNs = normalizeDecimal(value.ctimeNs);
  const rdevHex = normalizeRdevHex(value.rdevHex);
  if (stDev === null || inode === null || ctimeNs === null || rdevHex === null) return null;
  return { stDev, inode, ctimeNs, rdevHex };
}

export function statIdentityEqual(left, right) {
  try {
    const normalizedLeft = normalizeStatIdentity(left);
    const normalizedRight = normalizeStatIdentity(right);
    return (
      normalizedLeft !== null &&
      normalizedRight !== null &&
      STAT_IDENTITY_KEYS.every((key) => normalizedLeft[key] === normalizedRight[key])
    );
  } catch {
    return false;
  }
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

function normalizeDynamicReceipt(value) {
  if (!isPlainRecord(value)) return null;
  const path = normalizeAbsolutePath(value.path);
  if (path === null) return null;
  if (value.kind === 'missing') {
    return hasExactKeys(value, ['kind', 'path', 'code']) && value.code === 'ENOENT'
      ? { kind: 'missing', path, code: 'ENOENT' }
      : null;
  }
  if (
    value.kind !== 'value' ||
    !hasExactKeys(value, ['kind', 'path', 'value']) ||
    normalizeStatIdentity(value.value) === null
  ) {
    return null;
  }
  return { kind: 'value', path, value: value.value };
}

export function dynamicStageMatchesHost(stage) {
  try {
    if (!hasExactKeys(stage, ['hostNode', 'dynamic'])) return false;
    const dynamic = normalizeDynamicReceipt(stage.dynamic);
    if (dynamic === null) return false;
    if (stage.hostNode === null) {
      return dynamic.kind === 'missing' && /^\/host-dev\/hidraw[0-9]+$/u.test(dynamic.path);
    }
    if (!isPlainRecord(stage.hostNode)) return false;
    const hostMatch = /^\/dev\/(hidraw[0-9]+)$/u.exec(
      normalizeAbsolutePath(stage.hostNode.devicePath) ?? ''
    );
    if (!hostMatch || normalizeStatIdentity(stage.hostNode.stat) === null) return false;
    return (
      dynamic.kind === 'value' &&
      dynamic.path === `/host-dev/${hostMatch[1]}` &&
      statIdentityEqual(dynamic.value, stage.hostNode.stat)
    );
  } catch {
    return false;
  }
}

function exactPresentHostSnapshot(snapshot) {
  if (
    !isPlainRecord(snapshot) ||
    snapshot.state !== 'present' ||
    !nonEmptyString(snapshot.expectedSerial) ||
    !isPlainRecord(snapshot.scope) ||
    !nonEmptyString(snapshot.scope.bootId) ||
    !nonEmptyString(snapshot.scope.mountNamespace) ||
    !Array.isArray(snapshot.errors) ||
    snapshot.errors.length !== 0 ||
    !Array.isArray(snapshot.usb) ||
    !Array.isArray(snapshot.hidraw)
  ) {
    return null;
  }
  const usbMatches = snapshot.usb.filter(
    (entry) =>
      isPlainRecord(entry) &&
      entry.serialMatches === true &&
      entry.serial === snapshot.expectedSerial
  );
  const hidrawMatches = snapshot.hidraw.filter(
    (entry) =>
      isPlainRecord(entry) &&
      entry.serialMatches === true &&
      entry.hid?.unique === snapshot.expectedSerial
  );
  if (usbMatches.length !== 1 || hidrawMatches.length !== 1) return null;
  const usb = usbMatches[0];
  const node = hidrawMatches[0];
  const usbDeviceNumber = normalizeDecimal(usb.deviceNumber, { positive: true });
  const ancestorDeviceNumber = normalizeDecimal(node.usbAncestor?.deviceNumber, {
    positive: true,
  });
  const hidDevicePath = normalizeAbsolutePath(node.hidDevicePath);
  const stat = normalizeStatIdentity(node.stat);
  if (
    usbDeviceNumber === null ||
    ancestorDeviceNumber === null ||
    usbDeviceNumber !== ancestorDeviceNumber ||
    node.usbAncestor?.serial !== snapshot.expectedSerial ||
    hidDevicePath === null ||
    stat === null
  ) {
    return null;
  }
  return {
    expectedSerial: snapshot.expectedSerial,
    bootId: snapshot.scope.bootId,
    mountNamespace: snapshot.scope.mountNamespace,
    deviceNumber: usbDeviceNumber,
    hidDevicePath,
    stat,
  };
}

export function hostEpochChanged(beforeSnapshot, afterSnapshot) {
  try {
    const before = exactPresentHostSnapshot(beforeSnapshot);
    const after = exactPresentHostSnapshot(afterSnapshot);
    if (
      before === null ||
      after === null ||
      before.expectedSerial !== after.expectedSerial ||
      before.bootId !== after.bootId ||
      before.mountNamespace !== after.mountNamespace
    ) {
      return false;
    }
    return (
      before.deviceNumber !== after.deviceNumber ||
      before.hidDevicePath !== after.hidDevicePath ||
      before.stat.inode !== after.stat.inode ||
      before.stat.ctimeNs !== after.stat.ctimeNs
    );
  } catch {
    return false;
  }
}

function completeLifecycle(value) {
  return (
    isPlainRecord(value) &&
    LIFECYCLE_KEYS.every((key) => Object.hasOwn(value, key)) &&
    nonEmptyString(value.containerId) &&
    nonEmptyString(value.imageId) &&
    nonEmptyString(value.startedAt) &&
    Number.isSafeInteger(value.restartCount) &&
    value.restartCount >= 0 &&
    Number.isSafeInteger(value.hostPid) &&
    value.hostPid > 0 &&
    Number.isSafeInteger(value.pid1StartTicks) &&
    value.pid1StartTicks > 0 &&
    nonEmptyString(value.pidNamespace) &&
    nonEmptyString(value.mountNamespace) &&
    nonEmptyString(value.cgroup) &&
    nonEmptyString(value.hostCgroup) &&
    value.cgroupNamespaceMode === 'private'
  );
}

export function sameTopLevelLifecycle(before, after) {
  try {
    return (
      completeLifecycle(before) &&
      completeLifecycle(after) &&
      LIFECYCLE_KEYS.every((key) => before[key] === after[key])
    );
  } catch {
    return false;
  }
}

function completeSurfaceWorker(value) {
  return (
    isPlainRecord(value) &&
    SURFACE_WORKER_KEYS.every((key) => Object.hasOwn(value, key)) &&
    Number.isSafeInteger(value.pid) &&
    value.pid > 0 &&
    Number.isSafeInteger(value.startTicks) &&
    value.startTicks > 0 &&
    Number.isSafeInteger(value.ppid) &&
    value.ppid > 0 &&
    Number.isSafeInteger(value.parentStartTicks) &&
    value.parentStartTicks > 0 &&
    nonEmptyString(value.pidNamespace) &&
    nonEmptyString(value.mountNamespace) &&
    nonEmptyString(value.cgroup)
  );
}

export function sameSurfaceWorker(before, after) {
  try {
    return (
      completeSurfaceWorker(before) &&
      completeSurfaceWorker(after) &&
      SURFACE_WORKER_KEYS.every((key) => before[key] === after[key])
    );
  } catch {
    return false;
  }
}

function requiredString(value, label) {
  if (!nonEmptyString(value)) throw new TypeError(`${label} must be a non-empty string`);
  return value;
}

export function countAcquisitionMarkers(logs, serial, paths) {
  if (typeof logs !== 'string') throw new TypeError('logs must be a string');
  const identity = `streamdeck:${requiredString(serial, 'serial')}`;
  if (!Array.isArray(paths) || paths.length === 0) {
    throw new TypeError('paths must contain at least one device path');
  }
  const exactPaths = paths.map((value, index) => {
    const path = normalizeAbsolutePath(requiredString(value, `paths[${index}]`));
    if (path === null) throw new TypeError(`paths[${index}] must be an absolute normalized path`);
    return path;
  });
  let opening = 0;
  let ready = 0;
  let openFailed = 0;
  const relevantLines = [];
  for (const rawLine of logs.replace(/\u001b\[[0-9;]*m/gu, '').split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (line.length === 0 || !line.includes(identity)) continue;
    const isOpening = line.includes(`Opening surface panel: ${identity}`);
    const isReady = line.includes(`Surface panel ready: ${identity}`);
    const isOpenFailure = exactPaths.some((path) =>
      line.includes(`cannot open device with path ${path}`)
    );
    if (isOpening) opening += 1;
    if (isReady) ready += 1;
    if (isOpenFailure) openFailed += 1;
    if (isOpening || isReady || isOpenFailure) relevantLines.push(line);
  }
  return { opening, ready, openFailed, relevantLines };
}

export function descriptorMatchesDynamicNode(descriptor, dynamicNode) {
  try {
    if (!isPlainRecord(descriptor)) return false;
    const descriptorMatch = /^\/(?:dev|host-dev)\/(hidraw[0-9]+)$/u.exec(
      normalizeAbsolutePath(descriptor.target) ?? ''
    );
    const dynamic = normalizeDynamicReceipt(dynamicNode);
    const dynamicMatch =
      dynamic?.kind === 'value' ? /^\/host-dev\/(hidraw[0-9]+)$/u.exec(dynamic.path) : null;
    return (
      descriptorMatch !== null &&
      dynamicMatch !== null &&
      descriptorMatch[1] === dynamicMatch[1] &&
      statIdentityEqual(descriptor.stat, dynamic.value)
    );
  } catch {
    return false;
  }
}

function outcome(status, stage, reason) {
  return { status, stage, reason };
}

export function classifyH041Outcome(predicates) {
  try {
    if (
      !hasExactKeys(predicates, PREDICATE_KEYS) ||
      !PREDICATE_KEYS.every((key) => typeof predicates[key] === 'boolean') ||
      !PREREQUISITE_KEYS.every((key) => predicates[key])
    ) {
      return outcome(
        'inconclusive',
        'preconditions',
        'H-041 prerequisites are incomplete, malformed, or false.'
      );
    }
    if (!predicates.deadlineBoundaryConsistent) {
      return outcome(
        'inconclusive',
        'contradictory-reacquisition',
        'The first observation at the deadline contained acquisition evidence whose event time could not be bounded.'
      );
    }
    if (predicates.postReturnDescriptorObserved && predicates.postReturnLogMarkersObserved) {
      return outcome(
        'supported',
        'complete',
        'The complete intervention-free observation found both a current descriptor and new acquisition markers after the host epoch returned.'
      );
    }
    if (!predicates.postReturnDescriptorObserved && !predicates.postReturnLogMarkersObserved) {
      return outcome(
        'refuted',
        'companion-reacquisition',
        'The complete intervention-free observation found neither a current descriptor nor new acquisition markers before the deadline.'
      );
    }
    return outcome(
      'inconclusive',
      'contradictory-reacquisition',
      'Post-return descriptor and acquisition-log observations disagree.'
    );
  } catch {
    return outcome(
      'inconclusive',
      'preconditions',
      'H-041 prerequisites are incomplete, malformed, or false.'
    );
  }
}
