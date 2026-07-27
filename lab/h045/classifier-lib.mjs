import { createHash } from 'node:crypto';

import {
  isSurfaceThreadCmdline,
  parseCgroup,
  parseCmdline,
  parseLsusb,
  parseNamespace,
  parseOsRelease,
  parseProcStat,
  parseProcStatus,
} from './observer-lib.mjs';

export const H045_ACCEPTED_IMAGE_REFERENCE = 'ghcr.io/bitfocus/companion/companion:v4.3.3';
export const H045_ACCEPTED_IMAGE_ID =
  'sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e';
export const H045_ACCEPTED_SERIAL_SHA256 =
  '08e7fdb9e9bd371297e96f27f75b77bc3920181d1d448ed2d6f6a1d123548f5f';
const H045_ACCEPTED_SERIAL = 'A00SA5492OQMLF';

export const H045_PREDICATE_KEYS = Object.freeze([
  'sourceAdmissionExact',
  'auditExact',
  'framesComplete',
  'frameOrderExact',
  'exposureBounded',
  'hostStable',
  'deviceStable',
  'deviceExact',
  'acceptedImageSelectorExact',
  'deploymentUnique',
  'deploymentStable',
  'deploymentRunning',
  'pid1Stable',
  'workerUnique',
  'workerStable',
  'descriptorStable',
  'descriptorAbsent',
  'markersStable',
]);

export const H045_PROHIBITED_COUNT_KEYS = Object.freeze([
  'externalNetwork',
  'unrestrictedContainerInventory',
  'dockerExec',
  'hidrawOpen',
  'hidrawRead',
  'hidrawWrite',
  'hidrawIoctl',
  'signal',
  'lifecycleMutation',
  'configurationMutation',
  'mountMutation',
  'cgroupMutation',
  'sysfsWrite',
  'productionMutation',
]);

export const H045_COMMAND_ENVIRONMENT_POLICY = Object.freeze({
  mode: 'closed-fixed',
  inheritedKeys: Object.freeze([]),
  fixed: Object.freeze({
    DOCKER_CONFIG: '/nonexistent/overlaykit-h045-docker-config',
    GIT_CONFIG_COUNT: '0',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    LANG: 'C',
    LC_ALL: 'C',
  }),
});

export const H045_ALLOWED_PROCESS_KEYS = Object.freeze([
  'git',
  'lsusb',
  'dockerVersion',
  'dockerPs',
  'dockerInspect',
  'dockerLogs',
]);

const H045_PROTECTED_MAIN_COMMIT = 'e7c9406dc75d6d8c9cb771d9d62d4fd1359b975d';
const H045_SOURCE_CONTRACT_COMMIT = '2dc13d02f3d054fe54cb253869134c872e965601';
const DOCKER_UNIX_HOST = 'unix:///var/run/docker.sock';
const DOCKER_ANCESTOR_FILTER = `ancestor=${H045_ACCEPTED_IMAGE_ID}`;
const DOCKER_VERSION_FORMAT =
  '{"Client":{"Version":{{json .Client.Version}},"ApiVersion":{{json .Client.APIVersion}}},' +
  '"Server":{"Version":{{json .Server.Version}},"ApiVersion":{{json .Server.APIVersion}}}}';
const DOCKER_PS_FORMAT = '{"ID":{{json .ID}},"State":{{json .State}}}';
const DOCKER_INSPECT_FORMAT =
  '{"Id":{{json .Id}},"Image":{{json .Image}},"State":{' +
  '"Status":{{json .State.Status}},"Running":{{json .State.Running}},' +
  '"Pid":{{json .State.Pid}},"StartedAt":{{json .State.StartedAt}}},' +
  '"RestartCount":{{json .RestartCount}},' +
  '"CgroupnsMode":{{json .HostConfig.CgroupnsMode}}}';
const COMMAND_MAX_BUFFER_BYTES = 4 * 1024 * 1024;
const COMMAND_TIMEOUT_MS = null;
const COMMAND_OVERFLOW = 'drain-without-signal';
const FILESYSTEM_MAX_PATH_BYTES = 4_096;
const FILESYSTEM_MAX_READ_BYTES = 1024 * 1024;
const FILESYSTEM_MAX_DIRECTORY_ENTRIES = 4_096;
const FILESYSTEM_MAX_HIDRAW_ENTRIES = 64;
const FILESYSTEM_MAX_PROC_ENTRIES = 1_024;
const FILESYSTEM_MAX_RECEIPTS_PER_FRAME = 16_384;
const FILESYSTEM_MAX_RECEIPTS_PER_RUN = 32_768;
const FILESYSTEM_OPERATIONS = Object.freeze([
  'readFileSync',
  'readdirSync',
  'realpathSync',
  'statSync',
  'lstatSync',
  'readlinkSync',
]);

const INPUT_KEYS = Object.freeze(['frames', 'capabilityAudit', 'sourceAdmissionExact']);
const FRAME_KEYS = Object.freeze([
  'id',
  'complete',
  'startedAt',
  'endedAt',
  'startedMonotonicNs',
  'endedMonotonicNs',
  'observationCutoff',
  'host',
  'device',
  'deploymentInventory',
  'auditBinding',
  'digestSha256',
]);
const DEPLOYMENT_KEYS = Object.freeze([
  'complete',
  'exact',
  'container',
  'lifecycle',
  'pid1',
  'workers',
  'descriptors',
  'markers',
]);
const LIFECYCLE_KEYS = Object.freeze([
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
]);
const WORKER_KEYS = Object.freeze([
  'pid',
  'startTicks',
  'ppid',
  'parentStartTicks',
  'uid',
  'gid',
  'groups',
  'cmdline',
  'cgroup',
  'pidNamespace',
  'mountNamespace',
]);
const EPOCH_KEYS = Object.freeze([
  'serial',
  'busNumber',
  'deviceNumber',
  'usbDevicePath',
  'usbDev',
  'hidDevicePath',
  'devicePath',
  'stat',
]);
const STAT_KEYS = Object.freeze([
  'stDev',
  'inode',
  'ctimeNs',
  'mode',
  'uid',
  'gid',
  'rdev',
  'rdevHex',
  'major',
  'minor',
  'isCharacterDevice',
]);
const AUDIT_KEYS = Object.freeze([
  'mode',
  'environmentPolicy',
  'commandReceipts',
  'filesystemReceipts',
  'allowedProcessCounts',
  'commandCount',
  'filesystemReceiptCount',
  'complete',
  'exact',
  'frameCount',
  'lsusbCount',
  'unrecordedObservationCount',
  'prohibitedCounts',
]);

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const IMAGE_ID_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const MONOTONIC_PATTERN = /^(?:0|[1-9][0-9]*)$/u;
const DATE_TIME_PATTERN =
  /^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?Z$/u;
const MAX_EXPOSURE_NS = 5_000_000_000n;
const SURFACE_THREAD_ENTRYPOINT = '/app/SurfaceThread.js';

function clone(value) {
  return structuredClone(value);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])])
    );
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function sha256Canonical(value) {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function plainObject(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function exactKeys(value, keys) {
  return (
    plainObject(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function sha256(value) {
  return typeof value === 'string' && SHA256_PATTERN.test(value);
}

function sha256Bytes(value) {
  return createHash('sha256').update(value).digest('hex');
}

function sha256Text(value) {
  return typeof value === 'string' ? sha256Bytes(Buffer.from(value, 'utf8')) : null;
}

function imageId(value) {
  return typeof value === 'string' && IMAGE_ID_PATTERN.test(value);
}

function scalarString(value) {
  return typeof value === 'string' && value.length > 0;
}

function dateTime(value) {
  return (
    typeof value === 'string' && DATE_TIME_PATTERN.test(value) && Number.isFinite(Date.parse(value))
  );
}

function monotonic(value) {
  if (typeof value !== 'string' || !MONOTONIC_PATTERN.test(value)) {
    throw new TypeError('invalid monotonic nanosecond value');
  }
  return BigInt(value);
}

function nonNegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function canonicalDecimal(value, { positive = false } = {}) {
  if (typeof value !== 'string' || !MONOTONIC_PATTERN.test(value)) return null;
  const parsed = BigInt(value);
  return positive ? (parsed > 0n ? parsed : null) : parsed;
}

function linuxDeviceIdentity(value) {
  const encoded = canonicalDecimal(value);
  if (encoded === null || encoded > 0xffff_ffff_ffff_ffffn) return null;
  const major =
    ((encoded & 0x0000_0000_000f_ff00n) >> 8n) | ((encoded & 0xffff_f000_0000_0000n) >> 32n);
  const minor = (encoded & 0x0000_0000_0000_00ffn) | ((encoded & 0x0000_0fff_fff0_0000n) >> 12n);
  const majorNumber = Number(major);
  const minorNumber = Number(minor);
  return Number.isSafeInteger(majorNumber) && Number.isSafeInteger(minorNumber)
    ? {
        major: majorNumber,
        minor: minorNumber,
        rdevHex: `${major.toString(16)}:${minor.toString(16)}`,
      }
    : null;
}

function namespaceExact(value, kind) {
  return typeof value === 'string' && new RegExp(`^${kind}:\\[[1-9][0-9]*\\]$`, 'u').test(value);
}

function strictlyIncreasingIndexes(value) {
  return (
    Array.isArray(value) &&
    value.every(
      (entry, index) => nonNegativeInteger(entry) && (index === 0 || entry > value[index - 1])
    )
  );
}

function allFalsePredicates() {
  return Object.fromEntries(H045_PREDICATE_KEYS.map((key) => [key, false]));
}

function classification(disposition, stage, reasonCode, predicates, receipts = []) {
  return { disposition, stage, reasonCode, predicates, receipts };
}

function exactStatShape(value) {
  if (!(
    exactKeys(value, STAT_KEYS) &&
    canonicalDecimal(value.stDev) !== null &&
    canonicalDecimal(value.inode, { positive: true }) !== null &&
    canonicalDecimal(value.ctimeNs) !== null &&
    typeof value.mode === 'string' &&
    /^[0-7]{4}$/u.test(value.mode) &&
    nonNegativeInteger(value.uid) &&
    nonNegativeInteger(value.gid) &&
    canonicalDecimal(value.rdev) !== null &&
    typeof value.rdevHex === 'string' &&
    nonNegativeInteger(value.major) &&
    nonNegativeInteger(value.minor) &&
    typeof value.isCharacterDevice === 'boolean'
  )) {
    return false;
  }
  const decoded = linuxDeviceIdentity(value.rdev);
  return (
    decoded !== null &&
    decoded.major === value.major &&
    decoded.minor === value.minor &&
    decoded.rdevHex === value.rdevHex
  );
}

function exactStat(value) {
  return exactStatShape(value) && value.isCharacterDevice === true && value.major > 0;
}

function exactEpochShape(value) {
  return (
    exactKeys(value, EPOCH_KEYS) &&
    scalarString(value.serial) &&
    scalarString(value.busNumber) &&
    scalarString(value.deviceNumber) &&
    scalarString(value.usbDevicePath) &&
    scalarString(value.usbDev) &&
    scalarString(value.hidDevicePath) &&
    scalarString(value.devicePath) &&
    exactStatShape(value.stat)
  );
}

function exactEpoch(value) {
  return exactEpochShape(value) && exactStat(value.stat);
}

function exactHost(value) {
  return (
    exactKeys(value, ['hostname', 'bootId', 'osRelease']) &&
    scalarString(value.hostname) &&
    scalarString(value.bootId) &&
    scalarString(value.osRelease)
  );
}

function deviceIdentityShape(value) {
  return (
    exactKeys(value, ['serial', 'vendorId', 'productId', 'epoch']) &&
    scalarString(value.serial) &&
    value.vendorId === '0fd9' &&
    value.productId === '0080' &&
    exactEpochShape(value.epoch)
  );
}

function exactDeviceIdentity(value) {
  return (
    deviceIdentityShape(value) &&
    sha256Text(value.serial) === H045_ACCEPTED_SERIAL_SHA256 &&
    value.epoch.serial === value.serial &&
    exactEpoch(value.epoch)
  );
}

function exactDeviceShape(value) {
  if (
    !exactKeys(value, ['complete', 'present', 'identity']) ||
    typeof value.complete !== 'boolean' ||
    typeof value.present !== 'boolean'
  ) {
    return false;
  }
  if (!value.present) return value.identity === null;
  return deviceIdentityShape(value.identity);
}

function exactLifecycle(value) {
  return (
    exactKeys(value, LIFECYCLE_KEYS) &&
    sha256(value.containerId) &&
    imageId(value.imageId) &&
    dateTime(value.startedAt) &&
    nonNegativeInteger(value.restartCount) &&
    positiveInteger(value.hostPid) &&
    positiveInteger(value.pid1StartTicks) &&
    namespaceExact(value.pidNamespace, 'pid') &&
    namespaceExact(value.mountNamespace, 'mnt') &&
    scalarString(value.cgroup) &&
    scalarString(value.hostCgroup) &&
    scalarString(value.cgroupNamespaceMode)
  );
}

function exactPid1(value) {
  return (
    exactKeys(value, ['hostPid', 'startTicks', 'pidNamespace', 'mountNamespace', 'cgroup']) &&
    positiveInteger(value.hostPid) &&
    positiveInteger(value.startTicks) &&
    namespaceExact(value.pidNamespace, 'pid') &&
    namespaceExact(value.mountNamespace, 'mnt') &&
    scalarString(value.cgroup)
  );
}

function exactWorker(value) {
  return (
    exactKeys(value, WORKER_KEYS) &&
    positiveInteger(value.pid) &&
    positiveInteger(value.startTicks) &&
    nonNegativeInteger(value.ppid) &&
    positiveInteger(value.parentStartTicks) &&
    nonNegativeInteger(value.uid) &&
    nonNegativeInteger(value.gid) &&
    Array.isArray(value.groups) &&
    value.groups.every(nonNegativeInteger) &&
    Array.isArray(value.cmdline) &&
    value.cmdline.length > 0 &&
    value.cmdline.every((entry) => typeof entry === 'string') &&
    value.cmdline.at(-1) === SURFACE_THREAD_ENTRYPOINT &&
    scalarString(value.cgroup) &&
    namespaceExact(value.pidNamespace, 'pid') &&
    namespaceExact(value.mountNamespace, 'mnt')
  );
}

function exactDescriptor(value) {
  return (
    exactKeys(value, ['descriptor', 'target', 'lstat', 'stat']) &&
    typeof value.descriptor === 'string' &&
    /^(?:0|[1-9][0-9]*)$/u.test(value.descriptor) &&
    scalarString(value.target) &&
    exactFilesystemStat(value.lstat) &&
    value.lstat.isSymbolicLink === true &&
    exactFilesystemStat(value.stat) &&
    value.stat.isCharacterDevice === true &&
    value.stat.major > 0
  );
}

function exactMarkers(value) {
  return (
    exactKeys(value, ['opening', 'ready', 'relevantLinesSha256']) &&
    nonNegativeInteger(value.opening) &&
    nonNegativeInteger(value.ready) &&
    sha256(value.relevantLinesSha256)
  );
}

function exactContainer(value) {
  return (
    exactKeys(value, ['id', 'imageReference', 'imageId', 'state']) &&
    sha256(value.id) &&
    scalarString(value.imageReference) &&
    imageId(value.imageId) &&
    typeof value.state === 'string' &&
    /^[a-z][a-z0-9_-]*$/u.test(value.state)
  );
}

function exactDeployment(value) {
  return (
    exactKeys(value, DEPLOYMENT_KEYS) &&
    typeof value.complete === 'boolean' &&
    typeof value.exact === 'boolean' &&
    exactContainer(value.container) &&
    (value.lifecycle === null || exactLifecycle(value.lifecycle)) &&
    (value.pid1 === null || exactPid1(value.pid1)) &&
    Array.isArray(value.workers) &&
    value.workers.every(exactWorker) &&
    Array.isArray(value.descriptors) &&
    value.descriptors.every(exactDescriptor) &&
    exactMarkers(value.markers)
  );
}

function exactDeploymentInventory(value) {
  return (
    exactKeys(value, ['complete', 'exact', 'selector', 'rows', 'matches']) &&
    typeof value.complete === 'boolean' &&
    typeof value.exact === 'boolean' &&
    exactKeys(value.selector, ['imageReference', 'imageId']) &&
    scalarString(value.selector.imageReference) &&
    imageId(value.selector.imageId) &&
    Array.isArray(value.rows) &&
    value.rows.every(
      (row) =>
        exactKeys(row, ['containerId', 'state']) &&
        sha256(row.containerId) &&
        typeof row.state === 'string' &&
        /^[a-z][a-z0-9_-]*$/u.test(row.state)
    ) &&
    Array.isArray(value.matches) &&
    value.matches.every(exactDeployment)
  );
}

function digestFrame(frame) {
  const { digestSha256: _digestSha256, ...body } = frame;
  return sha256Canonical(body);
}

export function frameExactShape(frame) {
  if (
    !exactKeys(frame, FRAME_KEYS) ||
    !scalarString(frame.id) ||
    typeof frame.complete !== 'boolean' ||
    !dateTime(frame.startedAt) ||
    !dateTime(frame.endedAt) ||
    typeof frame.startedMonotonicNs !== 'string' ||
    !MONOTONIC_PATTERN.test(frame.startedMonotonicNs) ||
    typeof frame.endedMonotonicNs !== 'string' ||
    !MONOTONIC_PATTERN.test(frame.endedMonotonicNs) ||
    !exactKeys(frame.observationCutoff, ['at', 'monotonicNs']) ||
    !dateTime(frame.observationCutoff.at) ||
    !MONOTONIC_PATTERN.test(frame.observationCutoff.monotonicNs) ||
    !exactHost(frame.host) ||
    !exactDeviceShape(frame.device) ||
    !exactDeploymentInventory(frame.deploymentInventory) ||
    !exactKeys(frame.auditBinding, ['commandReceiptIndexes', 'filesystemReceiptIndexes']) ||
    !strictlyIncreasingIndexes(frame.auditBinding.commandReceiptIndexes) ||
    !strictlyIncreasingIndexes(frame.auditBinding.filesystemReceiptIndexes) ||
    !sha256(frame.digestSha256)
  ) {
    return false;
  }
  return digestFrame(frame) === frame.digestSha256;
}

function prohibitedCapabilityObserved(audit) {
  return (
    plainObject(audit?.prohibitedCounts) &&
    Object.values(audit.prohibitedCounts).some((value) => nonNegativeInteger(value) && value > 0)
  );
}

function environmentPolicyExact(value) {
  return (
    exactKeys(value, ['mode', 'inheritedKeys', 'fixed']) &&
    value.mode === H045_COMMAND_ENVIRONMENT_POLICY.mode &&
    same(value.inheritedKeys, H045_COMMAND_ENVIRONMENT_POLICY.inheritedKeys) &&
    exactKeys(value.fixed, Object.keys(H045_COMMAND_ENVIRONMENT_POLICY.fixed)) &&
    same(value.fixed, H045_COMMAND_ENVIRONMENT_POLICY.fixed)
  );
}

function lineCardinality(text) {
  if (text === '') return 0;
  const withoutFinalNewline = text.endsWith('\n') ? text.slice(0, -1) : text;
  return withoutFinalNewline === '' ? 0 : withoutFinalNewline.split('\n').length;
}

function exactBase64(value) {
  if (typeof value !== 'string') return null;
  const bytes = Buffer.from(value, 'base64');
  return bytes.toString('base64') === value ? bytes : null;
}

function exactOutputReceipt(value) {
  if (
    !exactKeys(value, ['encoding', 'text', 'base64', 'byteLength', 'lineCount', 'sha256']) ||
    !['utf8', 'base64'].includes(value.encoding) ||
    !nonNegativeInteger(value.byteLength) ||
    value.byteLength > COMMAND_MAX_BUFFER_BYTES ||
    !sha256(value.sha256)
  ) {
    return false;
  }
  const bytes = exactBase64(value.base64);
  if (
    bytes === null ||
    bytes.byteLength !== value.byteLength ||
    sha256Bytes(bytes) !== value.sha256
  ) {
    return false;
  }
  const decoded = bytes.toString('utf8');
  const utf8Exact = Buffer.from(decoded, 'utf8').equals(bytes);
  return utf8Exact
    ? value.encoding === 'utf8' &&
        value.text === decoded &&
        value.lineCount === lineCardinality(decoded)
    : value.encoding === 'base64' && value.text === null && value.lineCount === null;
}

function exactReceiptTiming(value) {
  if (
    !dateTime(value.startedAt) ||
    !dateTime(value.endedAt) ||
    typeof value.startedMonotonicNs !== 'string' ||
    typeof value.endedMonotonicNs !== 'string' ||
    typeof value.durationNs !== 'string' ||
    !MONOTONIC_PATTERN.test(value.startedMonotonicNs) ||
    !MONOTONIC_PATTERN.test(value.endedMonotonicNs) ||
    !MONOTONIC_PATTERN.test(value.durationNs)
  ) {
    return false;
  }
  const started = BigInt(value.startedMonotonicNs);
  const ended = BigInt(value.endedMonotonicNs);
  return (
    ended >= started &&
    BigInt(value.durationNs) === ended - started &&
    Date.parse(value.endedAt) >= Date.parse(value.startedAt)
  );
}

function commandOrdinalKey(receipt) {
  return receipt.kind === 'git' ? receipt.observerKind : receipt.kind;
}

function exactCommandReceipt(receipt, index, ordinals) {
  const baseKeys = [
    'index',
    'kind',
    'ordinal',
    'executable',
    'args',
    'startedAt',
    'endedAt',
    'startedMonotonicNs',
    'endedMonotonicNs',
    'durationNs',
    'limits',
    'environmentPolicy',
    'exitCode',
    'signal',
    'stdout',
    'stderr',
    'cardinality',
    'errorCode',
  ];
  const keys = receipt?.kind === 'git' ? [...baseKeys, 'observerKind'] : baseKeys;
  if (
    !exactKeys(receipt, keys) ||
    !H045_ALLOWED_PROCESS_KEYS.includes(receipt.kind) ||
    (receipt.kind === 'git' &&
      !['gitRevParse', 'gitMergeBaseAncestor', 'gitRemoteGetUrl'].includes(receipt.observerKind)) ||
    !scalarString(receipt.executable) ||
    !Array.isArray(receipt.args) ||
    !receipt.args.every((entry) => typeof entry === 'string') ||
    !exactReceiptTiming(receipt) ||
    !exactKeys(receipt.limits, ['maxBufferBytes', 'timeoutMs', 'overflow']) ||
    receipt.limits.maxBufferBytes !== COMMAND_MAX_BUFFER_BYTES ||
    receipt.limits.timeoutMs !== COMMAND_TIMEOUT_MS ||
    receipt.limits.overflow !== COMMAND_OVERFLOW ||
    !environmentPolicyExact(receipt.environmentPolicy) ||
    receipt.exitCode !== 0 ||
    receipt.signal !== null ||
    receipt.errorCode !== null ||
    !exactOutputReceipt(receipt.stdout) ||
    !exactOutputReceipt(receipt.stderr) ||
    !exactKeys(receipt.cardinality, ['global', 'kind']) ||
    receipt.index !== index ||
    receipt.cardinality.global !== index + 1
  ) {
    return false;
  }
  const ordinalKey = commandOrdinalKey(receipt);
  const expectedOrdinal = (ordinals.get(ordinalKey) ?? 0) + 1;
  if (receipt.ordinal !== expectedOrdinal || receipt.cardinality.kind !== expectedOrdinal) {
    return false;
  }
  ordinals.set(ordinalKey, expectedOrdinal);
  return true;
}

function filesystemPathExact(operation, value) {
  if (
    typeof value !== 'string' ||
    value === '' ||
    value.includes('\u0000') ||
    !value.startsWith('/') ||
    value.includes('/../') ||
    value.endsWith('/..') ||
    value.includes('/./') ||
    value.endsWith('/.')
  ) {
    return false;
  }
  if (operation === 'readFileSync') {
    return (
      ['/etc/os-release', '/proc/sys/kernel/random/boot_id', '/proc/sys/kernel/hostname'].includes(
        value
      ) ||
      /^\/sys\/class\/hidraw\/hidraw(?:0|[1-9][0-9]*)\/(?:device\/uevent|dev)$/u.test(value) ||
      /^\/sys\/devices\/.+\/(?:idVendor|idProduct|serial|manufacturer|product|busnum|devnum|devpath|dev)$/u.test(
        value
      ) ||
      /^\/proc\/[1-9][0-9]*\/cgroup$/u.test(value) ||
      /^\/proc\/[1-9][0-9]*\/root\/proc\/[1-9][0-9]*\/(?:stat|status|cmdline|cgroup)$/u.test(value)
    );
  }
  if (operation === 'readdirSync') {
    return (
      value === '/sys/class/hidraw' ||
      /^\/proc\/[1-9][0-9]*\/root\/proc$/u.test(value) ||
      /^\/proc\/[1-9][0-9]*\/root\/proc\/[1-9][0-9]*\/fd$/u.test(value)
    );
  }
  if (operation === 'realpathSync') {
    return /^\/sys\/class\/hidraw\/hidraw(?:0|[1-9][0-9]*)\/device$/u.test(value);
  }
  if (operation === 'statSync' || operation === 'lstatSync') {
    return (
      /^\/(?:dev|host-dev)\/hidraw(?:0|[1-9][0-9]*)$/u.test(value) ||
      /^\/proc\/[1-9][0-9]*\/root\/proc\/[1-9][0-9]*\/fd\/(?:0|[1-9][0-9]*)$/u.test(value)
    );
  }
  return (
    operation === 'readlinkSync' &&
    (/^\/(?:dev|host-dev)\/hidraw(?:0|[1-9][0-9]*)$/u.test(value) ||
      /^\/proc\/[1-9][0-9]*\/root\/proc\/[1-9][0-9]*\/ns\/(?:pid|mnt)$/u.test(value) ||
      /^\/proc\/[1-9][0-9]*\/root\/proc\/[1-9][0-9]*\/fd\/(?:0|[1-9][0-9]*)$/u.test(value))
  );
}

function exactFilesystemStat(value) {
  if (
    !exactKeys(value, [...STAT_KEYS, 'isSymbolicLink']) ||
    typeof value.isSymbolicLink !== 'boolean'
  ) {
    return false;
  }
  const projected = Object.fromEntries(STAT_KEYS.map((key) => [key, value[key]]));
  return exactStatShape(projected);
}

function exactFilesystemReadResult(value) {
  if (
    !exactKeys(value, ['cardinality', 'byteLength', 'bytes', 'encoding', 'text', 'sha256']) ||
    value.cardinality !== 1 ||
    !nonNegativeInteger(value.byteLength) ||
    value.byteLength > FILESYSTEM_MAX_READ_BYTES ||
    !exactKeys(value.bytes, ['encoding', 'base64', 'byteLength', 'sha256']) ||
    value.bytes.encoding !== 'base64' ||
    !nonNegativeInteger(value.bytes.byteLength) ||
    !sha256(value.bytes.sha256) ||
    !sha256(value.sha256)
  ) {
    return false;
  }
  const bytes = exactBase64(value.bytes.base64);
  if (
    bytes === null ||
    bytes.byteLength !== value.byteLength ||
    bytes.byteLength !== value.bytes.byteLength ||
    sha256Bytes(bytes) !== value.sha256 ||
    value.sha256 !== value.bytes.sha256
  ) {
    return false;
  }
  const decoded = bytes.toString('utf8');
  const utf8Exact = Buffer.from(decoded, 'utf8').equals(bytes);
  return utf8Exact
    ? value.encoding === 'utf8' && value.text === decoded
    : value.encoding === 'base64' && value.text === null;
}

function filesystemDirectoryLimit(path) {
  if (path === '/sys/class/hidraw') return FILESYSTEM_MAX_HIDRAW_ENTRIES;
  if (
    /^\/proc\/[1-9][0-9]*\/root\/proc$/u.test(path) ||
    /^\/proc\/[1-9][0-9]*\/root\/proc\/[1-9][0-9]*\/fd$/u.test(path)
  ) {
    return FILESYSTEM_MAX_PROC_ENTRIES;
  }
  return FILESYSTEM_MAX_DIRECTORY_ENTRIES;
}

function exactFilesystemResult(receipt) {
  const result = receipt.result;
  if (!plainObject(result)) return false;
  if (receipt.disposition !== 'observed') {
    return (
      ['missing', 'error'].includes(receipt.disposition) &&
      exactKeys(result, ['cardinality', 'sha256']) &&
      result.cardinality === 0 &&
      result.sha256 === sha256Bytes(Buffer.alloc(0))
    );
  }
  if (receipt.operation === 'readFileSync') return exactFilesystemReadResult(result);
  if (receipt.operation === 'readdirSync') {
    return (
      exactKeys(result, ['entries', 'cardinality', 'sha256']) &&
      Array.isArray(result.entries) &&
      result.entries.every((entry) => typeof entry === 'string') &&
      result.cardinality === result.entries.length &&
      result.cardinality <= filesystemDirectoryLimit(receipt.path) &&
      result.sha256 === sha256Bytes(Buffer.from(JSON.stringify(result.entries), 'utf8'))
    );
  }
  if (receipt.operation === 'realpathSync' || receipt.operation === 'readlinkSync') {
    return (
      exactKeys(result, ['value', 'cardinality', 'sha256']) &&
      scalarString(result.value) &&
      Buffer.byteLength(result.value, 'utf8') <= FILESYSTEM_MAX_PATH_BYTES &&
      result.cardinality === 1 &&
      result.sha256 === sha256Bytes(Buffer.from(result.value, 'utf8'))
    );
  }
  return (
    ['statSync', 'lstatSync'].includes(receipt.operation) &&
    exactKeys(result, ['cardinality', 'metadata', 'sha256']) &&
    result.cardinality === 1 &&
    exactFilesystemStat(result.metadata) &&
    result.sha256 === sha256Bytes(Buffer.from(JSON.stringify(result.metadata), 'utf8'))
  );
}

function exactFilesystemReceipt(receipt, index, ordinals) {
  if (
    !exactKeys(receipt, [
      'index',
      'operation',
      'path',
      'startedAt',
      'endedAt',
      'startedMonotonicNs',
      'endedMonotonicNs',
      'durationNs',
      'disposition',
      'result',
      'errorCode',
      'cardinality',
    ]) ||
    !FILESYSTEM_OPERATIONS.includes(receipt.operation) ||
    typeof receipt.path !== 'string' ||
    Buffer.byteLength(receipt.path, 'utf8') > FILESYSTEM_MAX_PATH_BYTES ||
    !filesystemPathExact(receipt.operation, receipt.path) ||
    !exactReceiptTiming(receipt) ||
    !['observed', 'missing', 'error'].includes(receipt.disposition) ||
    (receipt.disposition === 'observed'
      ? receipt.errorCode !== null
      : !scalarString(receipt.errorCode)) ||
    !exactFilesystemResult(receipt) ||
    !exactKeys(receipt.cardinality, ['global', 'operation']) ||
    receipt.index !== index ||
    receipt.cardinality.global !== index + 1
  ) {
    return false;
  }
  const expectedOrdinal = (ordinals.get(receipt.operation) ?? 0) + 1;
  if (receipt.cardinality.operation !== expectedOrdinal) return false;
  ordinals.set(receipt.operation, expectedOrdinal);
  return true;
}

function commandPlanForFrames(frames) {
  const plan = [
    {
      kind: 'git',
      observerKind: 'gitRevParse',
      executable: 'git',
      args: ['rev-parse', 'HEAD'],
    },
    {
      kind: 'git',
      observerKind: 'gitMergeBaseAncestor',
      executable: 'git',
      args: ['merge-base', '--is-ancestor', H045_PROTECTED_MAIN_COMMIT, 'HEAD'],
    },
    {
      kind: 'git',
      observerKind: 'gitMergeBaseAncestor',
      executable: 'git',
      args: ['merge-base', '--is-ancestor', H045_SOURCE_CONTRACT_COMMIT, 'HEAD'],
    },
    {
      kind: 'git',
      observerKind: 'gitRemoteGetUrl',
      executable: 'git',
      args: ['remote', 'get-url', 'origin'],
    },
    {
      kind: 'lsusb',
      executable: 'lsusb',
      args: [],
    },
    {
      kind: 'dockerVersion',
      executable: 'docker',
      args: ['--host', DOCKER_UNIX_HOST, 'version', '--format', DOCKER_VERSION_FORMAT],
    },
  ];
  const framePlans = [];
  for (const frame of frames) {
    const rows = frame.deploymentInventory.rows;
    const matches = frame.deploymentInventory.matches;
    if (
      rows.length === 0
        ? matches.length !== 0
        : rows.length === 1
          ? matches.length !== 1 ||
            rows[0].containerId !== matches[0].container.id ||
            rows[0].state !== matches[0].container.state
          : matches.length !== 0
    ) {
      return null;
    }
    const dynamic = [
      {
        kind: 'dockerPs',
        executable: 'docker',
        args: [
          '--host',
          DOCKER_UNIX_HOST,
          'ps',
          '--all',
          '--no-trunc',
          '--filter',
          DOCKER_ANCESTOR_FILTER,
          '--format',
          DOCKER_PS_FORMAT,
        ],
        phase: 'before-cutoff',
        frame,
      },
    ];
    if (rows.length === 1) {
      dynamic.push({
        kind: 'dockerInspect',
        executable: 'docker',
        args: [
          '--host',
          DOCKER_UNIX_HOST,
          'inspect',
          '--format',
          DOCKER_INSPECT_FORMAT,
          rows[0].containerId,
        ],
        phase: 'before-cutoff',
        frame,
      });
      if (matches[0].container.state === 'running') {
        dynamic.push({
          kind: 'dockerLogs',
          executable: 'docker',
          containerId: rows[0].containerId,
          cutoff: frame.observationCutoff,
          phase: 'at-or-after-cutoff',
          frame,
        });
      }
    }
    const startIndex = plan.length;
    plan.push(...dynamic);
    framePlans.push({
      frame,
      indexes: dynamic.map((_, index) => startIndex + index),
      dynamic,
    });
  }
  return { plan, framePlans };
}

function commandText(receipt, stream = 'stdout') {
  const output = receipt?.[stream];
  return output?.encoding === 'utf8' && typeof output.text === 'string' ? output.text : null;
}

function parseExactJson(value) {
  if (typeof value !== 'string' || value.trim() === '') return null;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function dockerPsOutputExact(receipt, frame) {
  const text = commandText(receipt);
  if (text === null) return false;
  const lines = text.split(/\r?\n/u).filter(Boolean);
  const rows = [];
  for (const line of lines) {
    const entry = parseExactJson(line);
    if (
      !exactKeys(entry, ['ID', 'State']) ||
      !SHA256_PATTERN.test(entry.ID) ||
      typeof entry.State !== 'string' ||
      !/^[a-z][a-z0-9_-]*$/u.test(entry.State)
    ) {
      return false;
    }
    rows.push({
      containerId: entry.ID,
      state: entry.State,
    });
  }
  return same(rows, frame.deploymentInventory.rows);
}

function lsusbEvidenceExact(receipt, frames) {
  try {
    const text = commandText(receipt);
    if (text === null) return false;
    const matches = parseLsusb(text).filter(
      (entry) => entry.vendorId === '0fd9' && entry.productId === '0080'
    );
    return frames.every((frame) => {
      if (!frame.device.present) return matches.length === 0;
      const epoch = frame.device.identity.epoch;
      return (
        matches.filter(
          (entry) =>
            entry.busNumber === epoch.busNumber && entry.deviceNumber === epoch.deviceNumber
        ).length === 1
      );
    });
  } catch {
    return false;
  }
}

function dockerInspectOutputExact(receipt, frame) {
  const entry = parseExactJson(commandText(receipt));
  const row = frame.deploymentInventory.rows[0];
  const selected = frame.deploymentInventory.matches[0];
  if (
    !exactKeys(entry, ['Id', 'Image', 'State', 'RestartCount', 'CgroupnsMode']) ||
    !exactKeys(entry.State, ['Status', 'Running', 'Pid', 'StartedAt']) ||
    entry.Id !== row.containerId ||
    entry.Image !== H045_ACCEPTED_IMAGE_ID ||
    entry.State.Status !== row.state ||
    typeof entry.State.Running !== 'boolean' ||
    (entry.State.Status === 'running') !== entry.State.Running ||
    !nonNegativeInteger(entry.State.Pid) ||
    !dateTime(entry.State.StartedAt) ||
    !nonNegativeInteger(entry.RestartCount) ||
    !scalarString(entry.CgroupnsMode)
  ) {
    return false;
  }
  if (!entry.State.Running) return entry.State.Pid === 0;
  return (
    selected?.lifecycle !== null &&
    selected?.lifecycle !== undefined &&
    entry.State.Pid === selected.lifecycle.hostPid &&
    entry.State.StartedAt === selected.lifecycle.startedAt &&
    entry.RestartCount === selected.lifecycle.restartCount &&
    entry.CgroupnsMode === selected.lifecycle.cgroupNamespaceMode
  );
}

function dockerLogsOutputExact(receipt, frame) {
  const streams = [
    ['stdout', commandText(receipt, 'stdout')],
    ['stderr', commandText(receipt, 'stderr')],
  ];
  if (streams.some(([, text]) => text === null)) return false;
  const entries = [];
  for (const [stream, text] of streams) {
    for (const line of text.split(/\r?\n/u).filter(Boolean)) {
      const separator = line.indexOf(' ');
      if (separator <= 0) return false;
      const at = line.slice(0, separator);
      if (
        !dateTime(at) ||
        Date.parse(at) < Date.parse(receipt.args[5]) ||
        Date.parse(at) > Date.parse(receipt.args[7])
      ) {
        return false;
      }
      entries.push({
        at,
        stream,
        line: line.slice(separator + 1),
      });
    }
  }
  entries.sort(
    (left, right) =>
      Date.parse(left.at) - Date.parse(right.at) ||
      left.at.localeCompare(right.at) ||
      left.stream.localeCompare(right.stream) ||
      left.line.localeCompare(right.line)
  );
  const markers = [
    ['opening', `Opening surface panel: streamdeck:${H045_ACCEPTED_SERIAL}`],
    ['ready', `Surface panel ready: streamdeck:${H045_ACCEPTED_SERIAL}`],
  ];
  const relevant = entries
    .map((entry) => {
      const marker = markers.find(
        ([, text]) =>
          entry.line.includes(text) &&
          (entry.line.endsWith(text) ||
            /\s/u.test(entry.line[entry.line.indexOf(text) + text.length]))
      );
      return { ...entry, markerKind: marker?.[0] ?? null };
    })
    .filter((entry) => entry.markerKind !== null);
  const selected = frame.deploymentInventory.matches[0];
  return (
    selected !== undefined &&
    selected.markers.opening ===
      relevant.filter((entry) => entry.markerKind === 'opening').length &&
    selected.markers.ready === relevant.filter((entry) => entry.markerKind === 'ready').length &&
    selected.markers.relevantLinesSha256 ===
      sha256Bytes(
        Buffer.from(
          relevant.map((entry) => `${entry.at}\t${entry.stream}\t${entry.line}`).join('\n'),
          'utf8'
        )
      )
  );
}

function commandOutputMatches(receipt, expected) {
  const stdout = commandText(receipt);
  const stderr = commandText(receipt, 'stderr');
  if (stdout === null || stderr === null) return false;
  if (expected.observerKind === 'gitRevParse') {
    return /^[0-9a-f]{40}\n?$/u.test(stdout) && stderr === '';
  }
  if (expected.observerKind === 'gitMergeBaseAncestor') {
    return stdout === '' && stderr === '';
  }
  if (expected.observerKind === 'gitRemoteGetUrl') {
    return (
      stdout.trim() === 'https://github.com/OverlayKit/companion-module-overlaykit-server.git' &&
      stderr === ''
    );
  }
  if (expected.kind === 'lsusb') {
    return stderr === '' && typeof stdout === 'string';
  }
  if (expected.kind === 'dockerVersion') {
    const version = parseExactJson(stdout);
    return (
      stderr === '' &&
      exactKeys(version, ['Client', 'Server']) &&
      ['Client', 'Server'].every(
        (key) =>
          exactKeys(version[key], ['Version', 'ApiVersion']) &&
          scalarString(version[key].Version) &&
          scalarString(version[key].ApiVersion)
      )
    );
  }
  if (expected.kind === 'dockerPs') {
    return stderr === '' && dockerPsOutputExact(receipt, expected.frame);
  }
  if (expected.kind === 'dockerInspect') {
    return stderr === '' && dockerInspectOutputExact(receipt, expected.frame);
  }
  return expected.kind === 'dockerLogs' && dockerLogsOutputExact(receipt, expected.frame);
}

function commandMatchesPlan(receipt, expected) {
  if (
    receipt.kind !== expected.kind ||
    receipt.executable !== expected.executable ||
    (expected.observerKind === undefined
      ? Object.hasOwn(receipt, 'observerKind')
      : receipt.observerKind !== expected.observerKind)
  ) {
    return false;
  }
  const argsExact =
    expected.kind !== 'dockerLogs'
      ? same(receipt.args, expected.args)
      : receipt.args.length === 9 &&
        same(receipt.args.slice(0, 5), [
          '--host',
          DOCKER_UNIX_HOST,
          'logs',
          '--timestamps',
          '--since',
        ]) &&
        dateTime(receipt.args[5]) &&
        Date.parse(receipt.args[5]) <= Date.parse(expected.cutoff.at) &&
        receipt.args[6] === '--until' &&
        receipt.args[7] === expected.cutoff.at &&
        receipt.args[8] === expected.containerId;
  return argsExact && commandOutputMatches(receipt, expected);
}

function receiptWithinFrame(receipt, frame) {
  return (
    BigInt(receipt.startedMonotonicNs) >= BigInt(frame.startedMonotonicNs) &&
    BigInt(receipt.endedMonotonicNs) <= BigInt(frame.endedMonotonicNs) &&
    Date.parse(receipt.startedAt) >= Date.parse(frame.startedAt) &&
    Date.parse(receipt.endedAt) <= Date.parse(frame.endedAt)
  );
}

function receiptEndsAtOrBeforeCutoff(receipt, frame) {
  return (
    BigInt(receipt.endedMonotonicNs) <= BigInt(frame.observationCutoff.monotonicNs) &&
    Date.parse(receipt.endedAt) <= Date.parse(frame.observationCutoff.at)
  );
}

function receiptStartsAtOrAfterCutoff(receipt, frame) {
  return (
    BigInt(receipt.startedMonotonicNs) >= BigInt(frame.observationCutoff.monotonicNs) &&
    Date.parse(receipt.startedAt) >= Date.parse(frame.observationCutoff.at)
  );
}

function observedText(receipt) {
  return receipt?.disposition === 'observed' &&
    receipt.operation === 'readFileSync' &&
    receipt.result.encoding === 'utf8' &&
    typeof receipt.result.text === 'string'
    ? receipt.result.text.trim()
    : null;
}

function observedRawText(receipt) {
  return receipt?.disposition === 'observed' &&
    receipt.operation === 'readFileSync' &&
    receipt.result.encoding === 'utf8' &&
    typeof receipt.result.text === 'string'
    ? receipt.result.text
    : null;
}

function observedEntries(receipt) {
  return receipt?.disposition === 'observed' &&
    receipt.operation === 'readdirSync' &&
    Array.isArray(receipt.result.entries)
    ? receipt.result.entries
    : null;
}

function observedPath(receipt) {
  return receipt?.disposition === 'observed' &&
    ['realpathSync', 'readlinkSync'].includes(receipt.operation) &&
    typeof receipt.result.value === 'string'
    ? receipt.result.value
    : null;
}

function parentPath(value) {
  const index = value.lastIndexOf('/');
  return index <= 0 ? '/' : value.slice(0, index);
}

function projectedFilesystemStat(value) {
  return Object.fromEntries(STAT_KEYS.map((key) => [key, value[key]]));
}

function normalizeUsbId(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{1,8}$/iu.test(value)) return null;
  const parsed = BigInt(`0x${value}`);
  return parsed <= 0xffffn ? parsed.toString(16).padStart(4, '0') : null;
}

function parseHidUeventExact(value) {
  if (typeof value !== 'string') return null;
  const properties = {};
  for (const line of value.split(/\r?\n/u)) {
    if (line === '') continue;
    const separator = line.indexOf('=');
    if (separator <= 0 || !/^[A-Z][A-Z0-9_]*$/u.test(line.slice(0, separator))) {
      return null;
    }
    const key = line.slice(0, separator);
    if (Object.hasOwn(properties, key)) return null;
    properties[key] = line.slice(separator + 1);
  }
  const id =
    typeof properties.HID_ID === 'string'
      ? /^([0-9a-f]{1,8}):([0-9a-f]{1,8}):([0-9a-f]{1,8})$/iu.exec(properties.HID_ID)
      : null;
  if (id === null) return null;
  const bus = normalizeUsbId(id[1]);
  const vendorId = normalizeUsbId(id[2]);
  const productId = normalizeUsbId(id[3]);
  if (bus === null || vendorId === null || productId === null) return null;
  return {
    bus,
    vendorId,
    productId,
    unique:
      typeof properties.HID_UNIQ === 'string' && properties.HID_UNIQ !== ''
        ? properties.HID_UNIQ
        : null,
  };
}

function parseDeviceTuple(value) {
  const match =
    typeof value === 'string' ? /^((?:0|[1-9][0-9]*)):((?:0|[1-9][0-9]*))$/u.exec(value) : null;
  if (match === null) return null;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  return Number.isSafeInteger(major) && Number.isSafeInteger(minor) ? { major, minor } : null;
}

function numericDirectoryEntries(receipt) {
  const entries = observedEntries(receipt);
  if (entries === null || new Set(entries).size !== entries.length) return null;
  return entries
    .filter((entry) => /^[1-9][0-9]*$/u.test(entry))
    .map(Number)
    .sort((left, right) => left - right);
}

function descriptorDirectoryEntries(receipt) {
  const entries = observedEntries(receipt);
  if (entries === null || new Set(entries).size !== entries.length) return null;
  const descriptors = entries.filter((entry) => /^(?:0|[1-9][0-9]*)$/u.test(entry));
  if (descriptors.some((entry) => !Number.isSafeInteger(Number(entry)))) return null;
  return descriptors.sort((left, right) => Number(left) - Number(right));
}

function descriptorIsInScope(target, identity, targetMajor) {
  return (
    identity?.isCharacterDevice === true &&
    (/^\/dev\/hidraw(?:0|[1-9][0-9]*)(?: \(deleted\))?$/u.test(target) ||
      identity.major === targetMajor)
  );
}

function replayFilesystemFrame(frame, receipts) {
  let cursor = 0;
  function take(operation, path) {
    const receipt = receipts[cursor];
    if (receipt?.operation !== operation || receipt.path !== path) {
      throw new Error('filesystem replay mismatch');
    }
    cursor += 1;
    return receipt;
  }
  function takeObserved(operation, path) {
    const receipt = take(operation, path);
    if (receipt.disposition !== 'observed') {
      throw new Error('required filesystem observation is unavailable');
    }
    return receipt;
  }
  function takeOptionalText(path) {
    const receipt = take('readFileSync', path);
    if (receipt.disposition === 'missing') return null;
    const text = observedText(receipt);
    if (text === null) throw new Error('optional filesystem observation is inexact');
    return text;
  }
  function observeProcess(procRoot, pid) {
    const directory = `${procRoot}/${pid}`;
    const statText = observedRawText(takeObserved('readFileSync', `${directory}/stat`));
    const statusText = observedRawText(takeObserved('readFileSync', `${directory}/status`));
    const cmdlineText = observedRawText(takeObserved('readFileSync', `${directory}/cmdline`));
    const cgroupText = observedRawText(takeObserved('readFileSync', `${directory}/cgroup`));
    const pidNamespace = observedPath(takeObserved('readlinkSync', `${directory}/ns/pid`));
    const mountNamespace = observedPath(takeObserved('readlinkSync', `${directory}/ns/mnt`));
    if (
      statText === null ||
      statusText === null ||
      cmdlineText === null ||
      cgroupText === null ||
      pidNamespace === null ||
      mountNamespace === null
    ) {
      throw new Error('process evidence is unavailable');
    }
    const stat = parseProcStat(statText);
    const status = parseProcStatus(statusText);
    if (stat.pid !== pid || status.namespacePids.at(-1) !== pid) {
      throw new Error('process identity mismatch');
    }
    return {
      pid,
      startTicks: stat.startTicks,
      ppid: stat.ppid,
      uid: status.uid,
      gid: status.gid,
      groups: status.groups,
      cmdline: parseCmdline(cmdlineText),
      cgroup: parseCgroup(cgroupText),
      pidNamespace: parseNamespace(pidNamespace, 'pid'),
      mountNamespace: parseNamespace(mountNamespace, 'mnt'),
    };
  }

  try {
    const osReleaseText = observedRawText(takeObserved('readFileSync', '/etc/os-release'));
    const bootId = observedText(takeObserved('readFileSync', '/proc/sys/kernel/random/boot_id'));
    const hostname = observedText(takeObserved('readFileSync', '/proc/sys/kernel/hostname'));
    if (osReleaseText === null) return false;
    const osRelease = parseOsRelease(osReleaseText);
    const projectedOsRelease = JSON.parse(frame.host.osRelease);
    if (
      !same(osRelease, projectedOsRelease) ||
      bootId !== frame.host.bootId ||
      hostname !== frame.host.hostname
    ) {
      return false;
    }

    const classNames = observedEntries(takeObserved('readdirSync', '/sys/class/hidraw'));
    if (
      classNames === null ||
      classNames.some((entry) => !/^hidraw(?:0|[1-9][0-9]*)$/u.test(entry)) ||
      new Set(classNames).size !== classNames.length
    ) {
      return false;
    }
    const names = [...classNames].sort(
      (left, right) => Number(left.slice('hidraw'.length)) - Number(right.slice('hidraw'.length))
    );
    const entries = [];
    for (const name of names) {
      const classPath = `/sys/class/hidraw/${name}`;
      const devicePath = `/dev/${name}`;
      const hidDevicePath = observedPath(takeObserved('realpathSync', `${classPath}/device`));
      if (hidDevicePath === null || !hidDevicePath.startsWith('/sys/devices/')) return false;
      const hid = parseHidUeventExact(
        observedRawText(takeObserved('readFileSync', `${classPath}/device/uevent`))
      );
      const classDevice = parseDeviceTuple(
        observedText(takeObserved('readFileSync', `${classPath}/dev`))
      );
      const statBefore = takeObserved('statSync', devicePath).result.metadata;
      let ancestorPath = hidDevicePath;
      let ancestor = null;
      for (let depth = 0; depth < 64 && ancestorPath.startsWith('/sys/devices'); depth += 1) {
        const vendor = takeOptionalText(`${ancestorPath}/idVendor`);
        const product = takeOptionalText(`${ancestorPath}/idProduct`);
        if (vendor !== null || product !== null) {
          if (vendor === null || product === null) return false;
          ancestor = {
            path: ancestorPath,
            vendorId: normalizeUsbId(vendor),
            productId: normalizeUsbId(product),
            serial: takeOptionalText(`${ancestorPath}/serial`),
            manufacturer: takeOptionalText(`${ancestorPath}/manufacturer`),
            product: takeOptionalText(`${ancestorPath}/product`),
            busNumber: takeOptionalText(`${ancestorPath}/busnum`),
            deviceNumber: takeOptionalText(`${ancestorPath}/devnum`),
            devicePath: takeOptionalText(`${ancestorPath}/devpath`),
          };
          break;
        }
        ancestorPath = parentPath(ancestorPath);
      }
      if (ancestor === null) return false;
      const statAfter = takeObserved('statSync', devicePath).result.metadata;
      if (
        hid === null ||
        classDevice === null ||
        ancestor.vendorId === null ||
        ancestor.productId === null ||
        !same(statBefore, statAfter) ||
        statBefore.major !== classDevice.major ||
        statBefore.minor !== classDevice.minor
      ) {
        return false;
      }
      entries.push({
        name,
        classPath,
        devicePath,
        hidDevicePath,
        hid,
        classDevice,
        stat: statBefore,
        ancestor,
      });
    }

    for (const entry of entries) {
      const lstat = takeObserved('lstatSync', entry.devicePath).result.metadata;
      const finalStat = takeObserved('statSync', entry.devicePath).result.metadata;
      if (!same(finalStat, entry.stat)) return false;
      entry.lstat = lstat;
      entry.linkTarget = null;
      if (lstat.isSymbolicLink === true) {
        entry.linkTarget = observedPath(takeObserved('readlinkSync', entry.devicePath));
        if (entry.linkTarget === null || entry.linkTarget === '') return false;
      }
    }

    const targets = entries.filter((entry) => {
      const serial = entry.ancestor.serial;
      return (
        entry.hid.vendorId === '0fd9' &&
        entry.hid.productId === '0080' &&
        entry.hid.unique === serial &&
        entry.ancestor.vendorId === '0fd9' &&
        entry.ancestor.productId === '0080' &&
        typeof serial === 'string' &&
        sha256Text(serial) === H045_ACCEPTED_SERIAL_SHA256 &&
        entry.stat.isCharacterDevice === true &&
        entry.stat.major > 0
      );
    });
    const serialContradictions = entries.filter(
      (entry) =>
        entry.hid.vendorId === '0fd9' &&
        entry.hid.productId === '0080' &&
        entry.ancestor.vendorId === '0fd9' &&
        entry.ancestor.productId === '0080' &&
        (sha256Text(entry.hid.unique ?? '') === H045_ACCEPTED_SERIAL_SHA256 ||
          sha256Text(entry.ancestor.serial ?? '') === H045_ACCEPTED_SERIAL_SHA256) &&
        entry.hid.unique !== entry.ancestor.serial
    );
    for (const entry of targets) {
      entry.usbDev = observedText(takeObserved('readFileSync', `${entry.ancestor.path}/dev`));
      if (parseDeviceTuple(entry.usbDev) === null) return false;
    }
    if (serialContradictions.length > 0) return false;
    if (frame.device.present) {
      if (targets.length !== 1) return false;
      const identity = frame.device.identity;
      const target = targets[0];
      if (
        target.devicePath !== identity.epoch.devicePath ||
        target.hidDevicePath !== identity.epoch.hidDevicePath ||
        target.ancestor.serial !== identity.serial ||
        target.ancestor.busNumber !== identity.epoch.busNumber ||
        target.ancestor.deviceNumber !== identity.epoch.deviceNumber ||
        target.ancestor.devicePath !== identity.epoch.usbDevicePath ||
        target.usbDev !== identity.epoch.usbDev ||
        !same(projectedFilesystemStat(target.stat), identity.epoch.stat) ||
        target.classDevice.major !== identity.epoch.stat.major ||
        target.classDevice.minor !== identity.epoch.stat.minor ||
        entries.some(
          (entry) =>
            entry !== target &&
            entry.classDevice.major === target.classDevice.major &&
            entry.classDevice.minor === target.classDevice.minor
        )
      ) {
        return false;
      }
    } else if (targets.length !== 0) {
      return false;
    }

    const inventory = frame.deploymentInventory;
    if (inventory.rows.length === 1 && inventory.matches.length === 1) {
      const selected = inventory.matches[0];
      if (selected.container.state === 'running' && selected.lifecycle !== null) {
        const procRoot = `/proc/${selected.lifecycle.hostPid}/root/proc`;
        const processIds = numericDirectoryEntries(takeObserved('readdirSync', procRoot));
        if (processIds === null) return false;
        const processes = processIds.map((pid) => observeProcess(procRoot, pid));
        const processIdsAfter = numericDirectoryEntries(takeObserved('readdirSync', procRoot));
        if (processIdsAfter === null || !same(processIds, processIdsAfter)) return false;
        const byPid = new Map(processes.map((entry) => [entry.pid, entry]));
        const rawPid1 = byPid.get(1) ?? null;
        if (selected.pid1 === null || rawPid1 === null || rawPid1.ppid !== 0) return false;
        const projectedPid1 = {
          hostPid: selected.lifecycle.hostPid,
          startTicks: rawPid1.startTicks,
          pidNamespace: rawPid1.pidNamespace,
          mountNamespace: rawPid1.mountNamespace,
          cgroup: rawPid1.cgroup,
        };
        if (
          !same(projectedPid1, selected.pid1) ||
          selected.lifecycle.pid1StartTicks !== rawPid1.startTicks ||
          selected.lifecycle.pidNamespace !== rawPid1.pidNamespace ||
          selected.lifecycle.mountNamespace !== rawPid1.mountNamespace ||
          selected.lifecycle.cgroup !== rawPid1.cgroup
        ) {
          return false;
        }
        const rawWorkers = processes.filter((entry) => isSurfaceThreadCmdline(entry.cmdline));
        const projectedWorkers = rawWorkers.map((entry) => ({
          pid: entry.pid,
          startTicks: entry.startTicks,
          ppid: entry.ppid,
          parentStartTicks: byPid.get(entry.ppid)?.startTicks ?? null,
          uid: entry.uid,
          gid: entry.gid,
          groups: entry.groups,
          cmdline: entry.cmdline,
          cgroup: entry.cgroup,
          pidNamespace: entry.pidNamespace,
          mountNamespace: entry.mountNamespace,
        }));
        if (!same(projectedWorkers, selected.workers)) return false;

        const descriptors = [];
        if (frame.device.present) {
          const targetMajor = frame.device.identity.epoch.stat.major;
          for (const worker of rawWorkers) {
            const directory = `${procRoot}/${worker.pid}/fd`;
            const before = descriptorDirectoryEntries(takeObserved('readdirSync', directory));
            if (before === null) return false;
            for (const descriptor of before) {
              const descriptorPath = `${directory}/${descriptor}`;
              const lstat = takeObserved('lstatSync', descriptorPath).result.metadata;
              const target = observedPath(takeObserved('readlinkSync', descriptorPath));
              const stat = takeObserved('statSync', descriptorPath).result.metadata;
              if (target === null || lstat.isSymbolicLink !== true) {
                return false;
              }
              if (descriptorIsInScope(target, stat, targetMajor)) {
                descriptors.push({ descriptor, target, lstat, stat });
              }
            }
            const after = descriptorDirectoryEntries(takeObserved('readdirSync', directory));
            if (after === null || !same(before, after)) return false;
          }
        }
        if (!same(descriptors, selected.descriptors)) return false;

        const hostCgroupText = observedRawText(
          takeObserved('readFileSync', `/proc/${selected.lifecycle.hostPid}/cgroup`)
        );
        if (
          hostCgroupText === null ||
          parseCgroup(hostCgroupText) !== selected.lifecycle.hostCgroup
        ) {
          return false;
        }
      }
    }
    return cursor === receipts.length;
  } catch {
    return false;
  }
}

function nonRunningInspectEvidenceStable(audit, framePlans) {
  const entries = [];
  for (const { frame, indexes, dynamic } of framePlans) {
    const selected = frame.deploymentInventory.matches[0];
    if (frame.deploymentInventory.rows.length !== 1 || selected?.container.state === 'running') {
      return true;
    }
    const inspectPosition = dynamic.findIndex((entry) => entry.kind === 'dockerInspect');
    if (inspectPosition < 0) return false;
    const entry = parseExactJson(commandText(audit.commandReceipts[indexes[inspectPosition]]));
    if (entry === null) return false;
    entries.push(entry);
  }
  return entries.length === framePlans.length && entries.every((entry) => same(entry, entries[0]));
}

function auditBindingsExact(audit, frames, framePlans) {
  const boundCommands = [];
  const boundFiles = [];
  for (const { frame, indexes, dynamic } of framePlans) {
    if (frame.auditBinding.filesystemReceiptIndexes.length > FILESYSTEM_MAX_RECEIPTS_PER_FRAME) {
      return false;
    }
    if (!same(frame.auditBinding.commandReceiptIndexes, indexes)) return false;
    for (let position = 0; position < indexes.length; position += 1) {
      const receipt = audit.commandReceipts[indexes[position]];
      if (
        !receiptWithinFrame(receipt, frame) ||
        (dynamic[position].phase === 'before-cutoff'
          ? !receiptEndsAtOrBeforeCutoff(receipt, frame)
          : !receiptStartsAtOrAfterCutoff(receipt, frame))
      ) {
        return false;
      }
      boundCommands.push(indexes[position]);
    }
    for (const index of frame.auditBinding.filesystemReceiptIndexes) {
      const receipt = audit.filesystemReceipts[index];
      if (
        receipt === undefined ||
        !receiptWithinFrame(receipt, frame) ||
        !receiptEndsAtOrBeforeCutoff(receipt, frame)
      ) {
        return false;
      }
      boundFiles.push(index);
    }
    const frameFiles = frame.auditBinding.filesystemReceiptIndexes.map(
      (index) => audit.filesystemReceipts[index]
    );
    if (!replayFilesystemFrame(frame, frameFiles)) return false;
  }
  const expectedDynamic = framePlans.flatMap(({ indexes }) => indexes);
  return (
    new Set(boundCommands).size === boundCommands.length &&
    new Set(boundFiles).size === boundFiles.length &&
    nonRunningInspectEvidenceStable(audit, framePlans) &&
    same(boundCommands, expectedDynamic) &&
    same(
      [...boundFiles].sort((left, right) => left - right),
      audit.filesystemReceipts.map((_, index) => index)
    )
  );
}

function capabilityAuditExact(audit, frames) {
  if (
    !exactKeys(audit, AUDIT_KEYS) ||
    audit.mode !== 'live-readonly-dynamic-acquisition-capability-bounded' ||
    !environmentPolicyExact(audit.environmentPolicy) ||
    !Array.isArray(audit.commandReceipts) ||
    !Array.isArray(audit.filesystemReceipts) ||
    audit.filesystemReceipts.length > FILESYSTEM_MAX_RECEIPTS_PER_RUN ||
    !exactKeys(audit.allowedProcessCounts, H045_ALLOWED_PROCESS_KEYS) ||
    !H045_ALLOWED_PROCESS_KEYS.every((key) =>
      nonNegativeInteger(audit.allowedProcessCounts[key])
    ) ||
    !nonNegativeInteger(audit.commandCount) ||
    !nonNegativeInteger(audit.filesystemReceiptCount) ||
    audit.commandReceipts.length !== audit.commandCount ||
    audit.filesystemReceipts.length !== audit.filesystemReceiptCount ||
    audit.complete !== true ||
    audit.exact !== true ||
    audit.frameCount !== 2 ||
    audit.lsusbCount !== 1 ||
    audit.unrecordedObservationCount !== 0 ||
    !exactKeys(audit.prohibitedCounts, H045_PROHIBITED_COUNT_KEYS) ||
    !H045_PROHIBITED_COUNT_KEYS.every(
      (key) => nonNegativeInteger(audit.prohibitedCounts[key]) && audit.prohibitedCounts[key] === 0
    )
  ) {
    return false;
  }

  const commandOrdinals = new Map();
  if (
    !audit.commandReceipts.every((receipt, index) =>
      exactCommandReceipt(receipt, index, commandOrdinals)
    )
  ) {
    return false;
  }
  const filesystemOrdinals = new Map();
  if (
    !audit.filesystemReceipts.every((receipt, index) =>
      exactFilesystemReceipt(receipt, index, filesystemOrdinals)
    )
  ) {
    return false;
  }

  const expected = commandPlanForFrames(frames);
  if (
    expected === null ||
    expected.plan.length !== audit.commandReceipts.length ||
    !expected.plan.every((entry, index) =>
      commandMatchesPlan(audit.commandReceipts[index], entry)
    ) ||
    !lsusbEvidenceExact(
      audit.commandReceipts.find((receipt) => receipt.kind === 'lsusb'),
      frames
    )
  ) {
    return false;
  }
  const receiptCounts = Object.fromEntries(H045_ALLOWED_PROCESS_KEYS.map((key) => [key, 0]));
  for (const receipt of audit.commandReceipts) receiptCounts[receipt.kind] += 1;
  return (
    H045_ALLOWED_PROCESS_KEYS.every(
      (key) => receiptCounts[key] === audit.allowedProcessCounts[key]
    ) &&
    Object.values(audit.allowedProcessCounts).reduce((sum, count) => sum + count, 0) ===
      audit.commandCount &&
    auditBindingsExact(audit, frames, expected.framePlans)
  );
}

function orderedFrames(first, second) {
  const firstStarted = monotonic(first.startedMonotonicNs);
  const firstEnded = monotonic(first.endedMonotonicNs);
  const secondStarted = monotonic(second.startedMonotonicNs);
  const secondEnded = monotonic(second.endedMonotonicNs);
  const firstCutoff = monotonic(first.observationCutoff.monotonicNs);
  const secondCutoff = monotonic(second.observationCutoff.monotonicNs);
  const firstStartedAt = Date.parse(first.startedAt);
  const firstEndedAt = Date.parse(first.endedAt);
  const secondStartedAt = Date.parse(second.startedAt);
  const secondEndedAt = Date.parse(second.endedAt);
  const firstCutoffAt = Date.parse(first.observationCutoff.at);
  const secondCutoffAt = Date.parse(second.observationCutoff.at);
  return (
    first.id !== second.id &&
    firstStarted <= firstEnded &&
    firstStarted <= firstCutoff &&
    firstCutoff <= firstEnded &&
    firstEnded <= secondStarted &&
    secondStarted <= secondEnded &&
    secondStarted <= secondCutoff &&
    secondCutoff <= secondEnded &&
    firstStartedAt <= firstEndedAt &&
    firstStartedAt <= firstCutoffAt &&
    firstCutoffAt <= firstEndedAt &&
    firstEndedAt <= secondStartedAt &&
    secondStartedAt <= secondEndedAt &&
    secondStartedAt <= secondCutoffAt &&
    secondCutoffAt <= secondEndedAt
  );
}

function acceptedSelector(value) {
  return (
    value.imageReference === H045_ACCEPTED_IMAGE_REFERENCE &&
    value.imageId === H045_ACCEPTED_IMAGE_ID
  );
}

function deploymentUsesAcceptedImage(deployment) {
  return (
    deployment.container.imageReference === H045_ACCEPTED_IMAGE_REFERENCE &&
    deployment.container.imageId === H045_ACCEPTED_IMAGE_ID &&
    (deployment.lifecycle === null || deployment.lifecycle.imageId === H045_ACCEPTED_IMAGE_ID)
  );
}

function deploymentCoherent(deployment) {
  if (deployment.lifecycle === null) {
    return (
      deployment.container.state !== 'running' &&
      deployment.pid1 === null &&
      deployment.workers.length === 0 &&
      deployment.descriptors.length === 0
    );
  }

  if (
    deployment.lifecycle.containerId !== deployment.container.id ||
    deployment.lifecycle.imageId !== deployment.container.imageId
  ) {
    return false;
  }

  if (deployment.pid1 !== null) {
    if (
      deployment.pid1.hostPid !== deployment.lifecycle.hostPid ||
      deployment.pid1.startTicks !== deployment.lifecycle.pid1StartTicks ||
      deployment.pid1.pidNamespace !== deployment.lifecycle.pidNamespace ||
      deployment.pid1.mountNamespace !== deployment.lifecycle.mountNamespace ||
      deployment.pid1.cgroup !== deployment.lifecycle.cgroup
    ) {
      return false;
    }
    if (
      deployment.workers.some(
        (worker) =>
          worker.ppid !== 1 ||
          worker.parentStartTicks !== deployment.pid1.startTicks ||
          worker.pidNamespace !== deployment.pid1.pidNamespace ||
          worker.mountNamespace !== deployment.pid1.mountNamespace ||
          worker.cgroup !== deployment.pid1.cgroup
      )
    ) {
      return false;
    }
  } else if (deployment.workers.length > 0) {
    return false;
  }

  return true;
}

function stableContainerAndLifecycle(first, second) {
  return same(first.container, second.container) && same(first.lifecycle, second.lifecycle);
}

function inventoryRowsAndMatchesCoherent(inventory) {
  if (inventory.rows.length === 0) return inventory.matches.length === 0;
  if (inventory.rows.length !== 1 || inventory.matches.length !== 1) return false;
  const row = inventory.rows[0];
  const match = inventory.matches[0];
  return row.containerId === match.container.id && row.state === match.container.state;
}

function receiptFor({ frames, capabilityAudit, exposureNs }) {
  const [first, second] = frames;
  const selected = second.deploymentInventory.matches[0];
  const body = {
    schemaVersion: 'overlaykit-h045-dynamic-tuple-receipt/v1',
    kind: 'cutoff-bound-dynamic-readonly-tuple',
    authority: 'none',
    action: null,
    authorizesAction: false,
    validAtCutoffOnly: true,
    revalidatedAtCutoff: true,
    requiresRevalidation: true,
    cutoff: clone(second.observationCutoff),
    exposure: {
      startedAt: first.startedAt,
      endedAt: second.observationCutoff.at,
      startedMonotonicNs: first.startedMonotonicNs,
      endedMonotonicNs: second.observationCutoff.monotonicNs,
      milliseconds: Number(exposureNs) / 1_000_000,
    },
    identity: {
      host: clone(second.host),
      device: clone(second.device.identity),
      deployment: {
        container: clone(selected.container),
        lifecycle: clone(selected.lifecycle),
        pid1: clone(selected.pid1),
        worker: clone(selected.workers[0]),
        descriptors: clone(selected.descriptors),
      },
    },
    markers: clone(selected.markers),
    sources: {
      acceptedImage: {
        imageReference: H045_ACCEPTED_IMAGE_REFERENCE,
        imageId: H045_ACCEPTED_IMAGE_ID,
      },
      frameDigests: frames.map((frame) => frame.digestSha256),
      capabilityAuditSha256: sha256Canonical(capabilityAudit),
    },
  };
  return { ...body, receiptSha256: sha256Canonical(body) };
}

export function classifyDynamicFrames(input = {}) {
  const predicates = allFalsePredicates();

  try {
    predicates.sourceAdmissionExact =
      exactKeys(input, INPUT_KEYS) && input.sourceAdmissionExact === true;
    if (!predicates.sourceAdmissionExact) {
      return classification(
        'inconclusive',
        'source-admission',
        'source-admission-inexact',
        predicates
      );
    }

    const { frames, capabilityAudit } = input;
    if (!Array.isArray(frames) || frames.length !== 2) {
      return classification(
        'inconclusive',
        'frame-admission',
        'two-complete-frames-required',
        predicates
      );
    }

    predicates.framesComplete =
      frames.every(
        (frame) =>
          frameExactShape(frame) &&
          frame.complete === true &&
          frame.device.complete === true &&
          frame.deploymentInventory.complete === true &&
          frame.deploymentInventory.exact === true &&
          frame.deploymentInventory.matches.every(
            (deployment) => deployment.complete === true && deployment.exact === true
          )
      ) && new Set(frames.map((frame) => frame.digestSha256)).size === 2;
    if (!predicates.framesComplete) {
      return classification(
        'inconclusive',
        'frame-admission',
        'incomplete-or-invalid-live-frame',
        predicates
      );
    }

    const presentIdentities = frames
      .filter((frame) => frame.device.present === true)
      .map((frame) => frame.device.identity);
    if (
      presentIdentities.some(
        (identity) =>
          sha256Text(identity.serial) !== H045_ACCEPTED_SERIAL_SHA256 ||
          identity.epoch.serial !== identity.serial
      )
    ) {
      return classification(
        'inconclusive',
        'identity',
        'accepted-device-serial-inexact',
        predicates
      );
    }
    if (
      presentIdentities.some(
        (identity) =>
          identity.epoch.stat.isCharacterDevice !== true ||
          identity.epoch.stat.major <= 0 ||
          !exactDeviceIdentity(identity)
      )
    ) {
      return classification('inconclusive', 'identity', 'accepted-device-node-inexact', predicates);
    }

    predicates.auditExact = capabilityAuditExact(capabilityAudit, frames);
    if (!predicates.auditExact) {
      return classification(
        'inconclusive',
        'capability-audit',
        prohibitedCapabilityObserved(capabilityAudit)
          ? 'prohibited-capability-observed'
          : 'capability-audit-incomplete-or-inexact',
        predicates
      );
    }

    const [first, second] = frames;
    predicates.frameOrderExact = orderedFrames(first, second);
    if (!predicates.frameOrderExact) {
      return classification('inconclusive', 'temporal-boundary', 'frame-order-invalid', predicates);
    }

    const exposureNs =
      monotonic(second.observationCutoff.monotonicNs) - monotonic(first.startedMonotonicNs);
    predicates.exposureBounded = exposureNs >= 0n && exposureNs <= MAX_EXPOSURE_NS;
    if (!predicates.exposureBounded) {
      return classification(
        'inconclusive',
        'temporal-boundary',
        'exposure-window-exceeded',
        predicates
      );
    }

    predicates.hostStable = same(first.host, second.host);
    if (!predicates.hostStable) {
      return classification('inconclusive', 'live-drift', 'host-identity-drift', predicates);
    }

    predicates.deviceStable = same(first.device, second.device);
    if (!predicates.deviceStable) {
      return classification('inconclusive', 'live-drift', 'device-identity-drift', predicates);
    }
    predicates.deviceExact = first.device.present === true && second.device.present === true;

    predicates.acceptedImageSelectorExact =
      acceptedSelector(first.deploymentInventory.selector) &&
      acceptedSelector(second.deploymentInventory.selector);
    if (!predicates.acceptedImageSelectorExact) {
      return classification(
        'inconclusive',
        'selector-boundary',
        'accepted-image-selector-inexact',
        predicates
      );
    }

    const firstRows = first.deploymentInventory.rows;
    const secondRows = second.deploymentInventory.rows;
    const firstMatches = first.deploymentInventory.matches;
    const secondMatches = second.deploymentInventory.matches;
    if (firstRows.length > 1 || secondRows.length > 1) {
      return classification(
        'inconclusive',
        'deployment-selection',
        'multiple-image-matches',
        predicates
      );
    }
    if (firstRows.length !== secondRows.length) {
      return classification('inconclusive', 'live-drift', 'deployment-presence-drift', predicates);
    }
    if (!same(firstRows, secondRows)) {
      return classification('inconclusive', 'live-drift', 'deployment-row-drift', predicates);
    }
    if (
      !inventoryRowsAndMatchesCoherent(first.deploymentInventory) ||
      !inventoryRowsAndMatchesCoherent(second.deploymentInventory)
    ) {
      return classification(
        'inconclusive',
        'deployment-selection',
        'deployment-inventory-inconsistent',
        predicates
      );
    }

    if (firstRows.length === 0) {
      predicates.deploymentStable = true;
      predicates.pid1Stable = true;
      predicates.workerStable = true;
      predicates.descriptorStable = true;
      predicates.descriptorAbsent = true;
      predicates.markersStable = true;
      return classification(
        'withheld',
        'not-eligible',
        'accepted-image-deployment-absent',
        predicates
      );
    }

    const firstDeployment = firstMatches[0];
    const secondDeployment = secondMatches[0];
    if (
      !deploymentUsesAcceptedImage(firstDeployment) ||
      !deploymentUsesAcceptedImage(secondDeployment)
    ) {
      return classification(
        'inconclusive',
        'selector-boundary',
        'accepted-image-match-inexact',
        predicates
      );
    }
    if (!deploymentCoherent(firstDeployment) || !deploymentCoherent(secondDeployment)) {
      return classification(
        'inconclusive',
        'contradictory-evidence',
        'deployment-observation-contradiction',
        predicates
      );
    }

    predicates.deploymentUnique = true;
    predicates.deploymentStable = stableContainerAndLifecycle(firstDeployment, secondDeployment);
    if (!predicates.deploymentStable) {
      return classification(
        'inconclusive',
        'live-drift',
        'deployment-identity-or-lifecycle-drift',
        predicates
      );
    }

    predicates.deploymentRunning =
      firstDeployment.container.state === 'running' &&
      secondDeployment.container.state === 'running';
    predicates.pid1Stable = same(firstDeployment.pid1, secondDeployment.pid1);
    if (!predicates.pid1Stable) {
      return classification('inconclusive', 'live-drift', 'pid1-identity-drift', predicates);
    }

    if (firstDeployment.workers.length > 1 || secondDeployment.workers.length > 1) {
      return classification('inconclusive', 'identity', 'worker-ambiguity', predicates);
    }
    if (firstDeployment.workers.length !== secondDeployment.workers.length) {
      return classification('inconclusive', 'identity', 'worker-presence-drift', predicates);
    }

    predicates.workerUnique =
      firstDeployment.workers.length === 1 && secondDeployment.workers.length === 1;
    predicates.workerStable =
      firstDeployment.workers.length === 0 ||
      same(firstDeployment.workers[0], secondDeployment.workers[0]);
    if (!predicates.workerStable) {
      return classification('inconclusive', 'identity', 'worker-identity-drift', predicates);
    }

    predicates.descriptorStable = same(firstDeployment.descriptors, secondDeployment.descriptors);
    if (!predicates.descriptorStable) {
      return classification('inconclusive', 'live-drift', 'descriptor-state-drift', predicates);
    }
    predicates.descriptorAbsent =
      firstDeployment.descriptors.length === 0 && secondDeployment.descriptors.length === 0;

    predicates.markersStable = same(firstDeployment.markers, secondDeployment.markers);
    if (!predicates.markersStable) {
      return classification('inconclusive', 'live-drift', 'marker-drift', predicates);
    }

    if (!predicates.deploymentRunning) {
      return classification('withheld', 'not-eligible', 'deployment-not-running', predicates);
    }
    if (!predicates.deviceExact) {
      return classification('withheld', 'not-eligible', 'device-absent', predicates);
    }
    if (firstDeployment.pid1 === null || secondDeployment.pid1 === null) {
      return classification(
        'inconclusive',
        'frame-admission',
        'running-deployment-pid1-incomplete',
        predicates
      );
    }
    if (!predicates.workerUnique) {
      return classification('withheld', 'not-eligible', 'surface-worker-absent', predicates);
    }
    if (!predicates.descriptorAbsent) {
      return classification('withheld', 'not-eligible', 'current-descriptor-present', predicates);
    }

    if (!Object.values(predicates).every((value) => value === true)) {
      return classification('inconclusive', 'classification', 'predicate-gap', predicates);
    }

    return classification(
      'candidate',
      'dynamic-readonly-acquisition',
      'cutoff-bound-dynamic-tuple',
      predicates,
      [receiptFor({ frames, capabilityAudit, exposureNs })]
    );
  } catch {
    return classification(
      'inconclusive',
      'input-admission',
      'malformed-live-input',
      allFalsePredicates()
    );
  }
}

function receiptExactShape(value) {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'kind',
      'authority',
      'action',
      'authorizesAction',
      'validAtCutoffOnly',
      'revalidatedAtCutoff',
      'requiresRevalidation',
      'cutoff',
      'exposure',
      'identity',
      'markers',
      'sources',
      'receiptSha256',
    ]) ||
    value.schemaVersion !== 'overlaykit-h045-dynamic-tuple-receipt/v1' ||
    value.kind !== 'cutoff-bound-dynamic-readonly-tuple' ||
    value.authority !== 'none' ||
    value.action !== null ||
    value.authorizesAction !== false ||
    value.validAtCutoffOnly !== true ||
    value.revalidatedAtCutoff !== true ||
    value.requiresRevalidation !== true ||
    !exactKeys(value.cutoff, ['at', 'monotonicNs']) ||
    !dateTime(value.cutoff.at) ||
    !MONOTONIC_PATTERN.test(value.cutoff.monotonicNs) ||
    !exactKeys(value.exposure, [
      'startedAt',
      'endedAt',
      'startedMonotonicNs',
      'endedMonotonicNs',
      'milliseconds',
    ]) ||
    !dateTime(value.exposure.startedAt) ||
    !dateTime(value.exposure.endedAt) ||
    !MONOTONIC_PATTERN.test(value.exposure.startedMonotonicNs) ||
    !MONOTONIC_PATTERN.test(value.exposure.endedMonotonicNs) ||
    !Number.isFinite(value.exposure.milliseconds) ||
    value.exposure.milliseconds < 0 ||
    value.exposure.milliseconds > Number(MAX_EXPOSURE_NS) / 1_000_000 ||
    value.exposure.endedAt !== value.cutoff.at ||
    value.exposure.endedMonotonicNs !== value.cutoff.monotonicNs ||
    !exactKeys(value.identity, ['host', 'device', 'deployment']) ||
    !exactHost(value.identity.host) ||
    !exactDeviceIdentity(value.identity.device) ||
    !exactKeys(value.identity.deployment, [
      'container',
      'lifecycle',
      'pid1',
      'worker',
      'descriptors',
    ]) ||
    !exactContainer(value.identity.deployment.container) ||
    !exactLifecycle(value.identity.deployment.lifecycle) ||
    !exactPid1(value.identity.deployment.pid1) ||
    !exactWorker(value.identity.deployment.worker) ||
    !Array.isArray(value.identity.deployment.descriptors) ||
    value.identity.deployment.descriptors.length !== 0 ||
    !exactMarkers(value.markers) ||
    !exactKeys(value.sources, ['acceptedImage', 'frameDigests', 'capabilityAuditSha256']) ||
    !exactKeys(value.sources.acceptedImage, ['imageReference', 'imageId']) ||
    !acceptedSelector(value.sources.acceptedImage) ||
    !Array.isArray(value.sources.frameDigests) ||
    value.sources.frameDigests.length !== 2 ||
    !value.sources.frameDigests.every(sha256) ||
    new Set(value.sources.frameDigests).size !== 2 ||
    !sha256(value.sources.capabilityAuditSha256) ||
    !sha256(value.receiptSha256)
  ) {
    return false;
  }

  const exposureNs =
    monotonic(value.exposure.endedMonotonicNs) - monotonic(value.exposure.startedMonotonicNs);
  const deployment = value.identity.deployment;
  if (
    exposureNs < 0n ||
    value.exposure.milliseconds !== Number(exposureNs) / 1_000_000 ||
    deployment.container.state !== 'running' ||
    !deploymentUsesAcceptedImage(deployment) ||
    !deploymentCoherent({
      complete: true,
      exact: true,
      container: deployment.container,
      lifecycle: deployment.lifecycle,
      pid1: deployment.pid1,
      workers: [deployment.worker],
      descriptors: deployment.descriptors,
      markers: value.markers,
    })
  ) {
    return false;
  }

  const { receiptSha256, ...body } = value;
  return receiptSha256 === sha256Canonical(body);
}

export function classificationExactShape(value) {
  return (
    exactKeys(value, ['disposition', 'stage', 'reasonCode', 'predicates', 'receipts']) &&
    ['candidate', 'withheld', 'inconclusive'].includes(value.disposition) &&
    scalarString(value.stage) &&
    scalarString(value.reasonCode) &&
    exactKeys(value.predicates, H045_PREDICATE_KEYS) &&
    H045_PREDICATE_KEYS.every((key) => typeof value.predicates[key] === 'boolean') &&
    Array.isArray(value.receipts) &&
    value.receipts.length <= 1 &&
    (value.disposition === 'candidate'
      ? Object.values(value.predicates).every((predicate) => predicate === true) &&
        value.receipts.length === 1 &&
        receiptExactShape(value.receipts[0])
      : value.receipts.length === 0)
  );
}
