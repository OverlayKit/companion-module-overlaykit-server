import { createHash } from 'node:crypto';
import path from 'node:path';

import { inventoryHostHidraw, selectExactTargetHidraw } from '../h041/host-inventory.mjs';
import {
  ObserverFilesystemError,
  createFilesystemAuditor as createBaseFilesystemAuditor,
  decodeLinuxDeviceNumber,
  filesystemReceiptResultExact,
  isSurfaceThreadCmdline,
  parseCgroup,
  parseCmdline,
  parseDeviceNumber,
  parseDockerVersion,
  parseLsusb,
  parseNamespace,
  parseOsRelease,
  parseProcStat,
  parseProcStatus,
  statIdentity,
} from '../h044/observer-lib.mjs';

export {
  ObserverFilesystemError,
  decodeLinuxDeviceNumber,
  filesystemReceiptResultExact,
  isSurfaceThreadCmdline,
  parseCgroup,
  parseCmdline,
  parseDeviceNumber,
  parseDockerVersion,
  parseLsusb,
  parseNamespace,
  parseOsRelease,
  parseProcStat,
  parseProcStatus,
  statIdentity,
};

const SHA256 = /^[0-9a-f]{64}$/u;
const IMAGE_ID = /^sha256:[0-9a-f]{64}$/u;
const GIT_SHA1 = /^[0-9a-f]{40}$/u;
const CONTAINER_ID = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const POSITIVE_DECIMAL = /^[1-9][0-9]*$/u;
const HIDRAW_NAME = /^hidraw(?:0|[1-9][0-9]*)$/u;
const USB_ID = /^[0-9a-f]{1,8}$/iu;
const RFC3339 =
  /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$/u;

const ACCEPTED_IMAGE_ID = 'sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e';
const ACCEPTED_DEVICE = Object.freeze({
  vendorId: '0fd9',
  productId: '0080',
});
const DOCKER_UNIX_HOST = 'unix:///var/run/docker.sock';
const DOCKER_HOST_PREFIX = Object.freeze(['--host', DOCKER_UNIX_HOST]);
const DOCKER_ANCESTOR_FILTER = `ancestor=${ACCEPTED_IMAGE_ID}`;
const DOCKER_VERSION_FORMAT =
  '{"Client":{"Version":{{json .Client.Version}},' +
  '"ApiVersion":{{json .Client.APIVersion}}},' +
  '"Server":{"Version":{{json .Server.Version}},' +
  '"ApiVersion":{{json .Server.APIVersion}}}}';
const DOCKER_PS_FORMAT = '{"ID":{{json .ID}},"State":{{json .State}}}';
const DOCKER_INSPECT_FORMAT =
  '{"Id":{{json .Id}},"Image":{{json .Image}},"State":{' +
  '"Status":{{json .State.Status}},"Running":{{json .State.Running}},' +
  '"Pid":{{json .State.Pid}},"StartedAt":{{json .State.StartedAt}}},' +
  '"RestartCount":{{json .RestartCount}},' +
  '"CgroupnsMode":{{json .HostConfig.CgroupnsMode}}}';

const COMMAND_ENVIRONMENT_POLICY = Object.freeze({
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
const FILESYSTEM_OPERATIONS = Object.freeze([
  'readFileSync',
  'readdirSync',
  'realpathSync',
  'statSync',
  'lstatSync',
  'readlinkSync',
]);
const FILESYSTEM_LIMITS = Object.freeze({
  maxReadBytes: 1024 * 1024,
  maxPathBytes: 4096,
  maxDirectoryEntries: 4096,
  maxHidrawEntries: 64,
  maxProcessEntries: 1024,
  maxDescriptorEntries: 1024,
  maxReceiptsPerFrame: 16_384,
});
const FILESYSTEM_CONTROLLERS = new WeakMap();
const COMMAND_LIMITS = Object.freeze({
  gitRevParse: 1,
  gitMergeBaseAncestor: 2,
  gitRemoteGetUrl: 1,
  lsusb: 1,
  dockerVersion: 1,
  dockerPs: 2,
  dockerInspect: 2,
  dockerLogs: 2,
});
const PROHIBITED_CAPABILITIES = Object.freeze({
  externalNetwork: 0,
  unrestrictedContainerInventory: 0,
  dockerExec: 0,
  hidrawOpen: 0,
  hidrawRead: 0,
  hidrawWrite: 0,
  hidrawIoctl: 0,
  signal: 0,
  lifecycleMutation: 0,
  configurationMutation: 0,
  mountMutation: 0,
  cgroupMutation: 0,
  sysfsWrite: 0,
  productionMutation: 0,
});

export const OBSERVER_ACCEPTED_IMAGE_ID = ACCEPTED_IMAGE_ID;
export const OBSERVER_ACCEPTED_DEVICE = ACCEPTED_DEVICE;
export const OBSERVER_COMMAND_LIMITS = COMMAND_LIMITS;
export const OBSERVER_COMMAND_ENVIRONMENT_POLICY = COMMAND_ENVIRONMENT_POLICY;
export const OBSERVER_FILESYSTEM_LIMITS = FILESYSTEM_LIMITS;
export const OBSERVER_DOCKER_ANCESTOR_FILTER = DOCKER_ANCESTOR_FILTER;
export const OBSERVER_DOCKER_INSPECT_FORMAT = DOCKER_INSPECT_FORMAT;
export const OBSERVER_DOCKER_PS_FORMAT = DOCKER_PS_FORMAT;
export const OBSERVER_DOCKER_UNIX_HOST = DOCKER_UNIX_HOST;
export const OBSERVER_DOCKER_VERSION_FORMAT = DOCKER_VERSION_FORMAT;
export const OBSERVER_PROHIBITED_CAPABILITIES = PROHIBITED_CAPABILITIES;

export class ObserverPolicyError extends Error {
  constructor(code, details = {}) {
    super(code);
    this.name = 'ObserverPolicyError';
    this.code = code;
    this.details = details;
  }
}

export class ObserverCommandError extends Error {
  constructor(code, receipt, cause = null) {
    super(code);
    this.name = 'ObserverCommandError';
    this.code = code;
    this.receipt = receipt;
    this.cause = cause;
  }
}

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function clone(value) {
  return structuredClone(value);
}

function exactKeys(value, keys) {
  return (
    isPlainRecord(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function requiredString(value, label) {
  if (typeof value !== 'string' || value === '' || value.includes('\u0000')) {
    throw new TypeError(`${label} must be a non-empty NUL-free string`);
  }
  return value;
}

function exactContainerId(value, label = 'container id') {
  const text = requiredString(value, label).toLowerCase();
  if (!CONTAINER_ID.test(text)) {
    throw new TypeError(`${label} must be an exact 64-byte-hex container id`);
  }
  return text;
}

function exactGitCommit(value, label) {
  const text = requiredString(value, label).toLowerCase();
  if (!GIT_SHA1.test(text)) throw new TypeError(`${label} must be an exact Git SHA-1`);
  return text;
}

function exactRfc3339(value, label) {
  const text = requiredString(value, label);
  if (!RFC3339.test(text) || !Number.isFinite(Date.parse(text))) {
    throw new TypeError(`${label} must be an RFC3339 timestamp`);
  }
  return text;
}

function rfc3339EpochNs(value, label) {
  const text = exactRfc3339(value, label);
  const match =
    /^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]+))?(Z|[+-][0-9]{2}:[0-9]{2})$/u.exec(
      text
    );
  if (match === null) throw new TypeError(`${label} must be an RFC3339 timestamp`);
  const wholeSecondMs = Date.parse(`${match[1]}${match[3]}`);
  const fractionalNs = BigInt((match[2] ?? '').padEnd(9, '0'));
  return BigInt(wholeSecondMs) * 1_000_000n + fractionalNs;
}

function wallTime(clock, label) {
  const value = clock();
  const text = value instanceof Date ? value.toISOString() : exactRfc3339(value, label);
  if (!Number.isFinite(Date.parse(text))) throw new TypeError(`${label} is invalid`);
  return text;
}

function monotonicTime(clock, label) {
  const value = clock();
  const parsed =
    typeof value === 'bigint'
      ? value
      : typeof value === 'string' && DECIMAL.test(value)
        ? BigInt(value)
        : null;
  if (parsed === null || parsed < 0n) {
    throw new TypeError(`${label} must be a non-negative bigint or decimal string`);
  }
  return parsed;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function asBuffer(value, label) {
  if (Buffer.isBuffer(value)) return value;
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  if (value instanceof Uint8Array) return Buffer.from(value);
  throw new TypeError(`${label} must be a string, Buffer, or Uint8Array`);
}

function exactUtf8(value, label) {
  const buffer = asBuffer(value, label);
  const text = buffer.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(buffer)) {
    throw new TypeError(`${label} is not exact UTF-8`);
  }
  return { buffer, text };
}

function lineCardinality(text) {
  if (text === '') return 0;
  const withoutFinalNewline = text.endsWith('\n') ? text.slice(0, -1) : text;
  return withoutFinalNewline === '' ? 0 : withoutFinalNewline.split('\n').length;
}

function outputReceipt(value, label) {
  const buffer = asBuffer(value, label);
  const decoded = buffer.toString('utf8');
  const utf8Exact = Buffer.from(decoded, 'utf8').equals(buffer);
  return {
    encoding: utf8Exact ? 'utf8' : 'base64',
    text: utf8Exact ? decoded : null,
    base64: buffer.toString('base64'),
    byteLength: buffer.byteLength,
    lineCount: utf8Exact ? lineCardinality(decoded) : null,
    sha256: sha256(buffer),
  };
}

function errorCode(error) {
  return typeof error?.code === 'string' && error.code !== '' ? error.code : 'UNKNOWN';
}

function parseJson(value, label) {
  const text = exactUtf8(value, label).text.trim();
  if (text === '') throw new Error(`${label} is empty`);
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${label} is not JSON`);
  }
}

function sanitizedEnvironment(environment) {
  if (!isPlainRecord(environment)) throw new TypeError('environment must be an object');
  return { ...COMMAND_ENVIRONMENT_POLICY.fixed };
}

function commandKind(executable, args) {
  if (!Array.isArray(args) || args.some((entry) => typeof entry !== 'string')) {
    throw new ObserverPolicyError('COMMAND_ARGS_INVALID');
  }
  if (executable === 'lsusb' && args.length === 0) return 'lsusb';
  if (executable === 'git') {
    if (JSON.stringify(args) === JSON.stringify(['rev-parse', 'HEAD'])) return 'gitRevParse';
    if (JSON.stringify(args) === JSON.stringify(['remote', 'get-url', 'origin'])) {
      return 'gitRemoteGetUrl';
    }
    if (
      args.length === 4 &&
      args[0] === 'merge-base' &&
      args[1] === '--is-ancestor' &&
      GIT_SHA1.test(args[2]) &&
      args[3] === 'HEAD'
    ) {
      return 'gitMergeBaseAncestor';
    }
    throw new ObserverPolicyError('GIT_COMMAND_PROHIBITED', { executable, args: [...args] });
  }
  if (executable === 'docker') {
    if (args[0] !== DOCKER_HOST_PREFIX[0] || args[1] !== DOCKER_HOST_PREFIX[1]) {
      throw new ObserverPolicyError('DOCKER_UNIX_HOST_REQUIRED', {
        executable,
        args: [...args],
      });
    }
    const dockerArgs = args.slice(DOCKER_HOST_PREFIX.length);
    if (
      JSON.stringify(dockerArgs) === JSON.stringify(['version', '--format', DOCKER_VERSION_FORMAT])
    ) {
      return 'dockerVersion';
    }
    if (
      JSON.stringify(dockerArgs) ===
      JSON.stringify([
        'ps',
        '--all',
        '--no-trunc',
        '--filter',
        DOCKER_ANCESTOR_FILTER,
        '--format',
        DOCKER_PS_FORMAT,
      ])
    ) {
      return 'dockerPs';
    }
    if (
      dockerArgs.length === 4 &&
      dockerArgs[0] === 'inspect' &&
      dockerArgs[1] === '--format' &&
      dockerArgs[2] === DOCKER_INSPECT_FORMAT &&
      CONTAINER_ID.test(dockerArgs[3])
    ) {
      return 'dockerInspect';
    }
    if (
      dockerArgs.length === 7 &&
      dockerArgs[0] === 'logs' &&
      dockerArgs[1] === '--timestamps' &&
      dockerArgs[2] === '--since' &&
      RFC3339.test(dockerArgs[3]) &&
      dockerArgs[4] === '--until' &&
      RFC3339.test(dockerArgs[5]) &&
      CONTAINER_ID.test(dockerArgs[6]) &&
      rfc3339EpochNs(dockerArgs[3], 'docker logs since') <=
        rfc3339EpochNs(dockerArgs[5], 'docker logs until')
    ) {
      return 'dockerLogs';
    }
    throw new ObserverPolicyError('DOCKER_COMMAND_PROHIBITED', {
      executable,
      args: [...args],
    });
  }
  throw new ObserverPolicyError('EXECUTABLE_PROHIBITED', { executable, args: [...args] });
}

export function validateObserverCommand(executable, args) {
  return commandKind(requiredString(executable, 'command executable'), args);
}

function normalizeRunnerResult(result) {
  if (!isPlainRecord(result)) throw new TypeError('command runner result must be an object');
  if (!(
    result.exitCode === null ||
    (Number.isInteger(result.exitCode) && result.exitCode >= 0 && result.exitCode <= 255)
  )) {
    throw new TypeError('command runner exitCode must be null or an integer from 0 through 255');
  }
  if (!(
    result.signal === null ||
    result.signal === undefined ||
    typeof result.signal === 'string'
  )) {
    throw new TypeError('command runner signal must be null or a string');
  }
  return {
    exitCode: result.exitCode,
    signal: result.signal ?? null,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

export function createCommandAuditor({
  runner,
  wallNow,
  monotonicNowNs,
  environment = {},
  maxBufferBytes = 4 * 1024 * 1024,
  timeoutMs = null,
} = {}) {
  if (typeof runner !== 'function') throw new TypeError('runner must be a function');
  if (typeof wallNow !== 'function') throw new TypeError('wallNow must be a function');
  if (typeof monotonicNowNs !== 'function') {
    throw new TypeError('monotonicNowNs must be a function');
  }
  if (!Number.isSafeInteger(maxBufferBytes) || maxBufferBytes <= 0) {
    throw new TypeError('maxBufferBytes must be a positive safe integer');
  }
  if (timeoutMs !== null) {
    throw new TypeError('timeoutMs must be null for the signal-free observer');
  }
  const childEnvironment = sanitizedEnvironment(environment);
  const receipts = [];
  const rejectedAttempts = [];
  const cardinality = Object.fromEntries(Object.keys(COMMAND_LIMITS).map((key) => [key, 0]));

  async function invoke(executable, args) {
    let kind;
    try {
      kind = validateObserverCommand(executable, args);
    } catch (error) {
      rejectedAttempts.push({
        executable: typeof executable === 'string' ? executable : String(executable),
        args: Array.isArray(args) ? [...args] : [],
        code: errorCode(error),
      });
      throw error;
    }
    const nextOrdinal = cardinality[kind] + 1;
    if (nextOrdinal > COMMAND_LIMITS[kind]) {
      rejectedAttempts.push({
        executable,
        args: [...args],
        code: 'COMMAND_CARDINALITY_EXCEEDED',
      });
      throw new ObserverPolicyError('COMMAND_CARDINALITY_EXCEEDED', {
        kind,
        limit: COMMAND_LIMITS[kind],
      });
    }
    const startedAt = wallTime(wallNow, 'command startedAt');
    const startedMonotonic = monotonicTime(monotonicNowNs, 'command started monotonic time');
    cardinality[kind] = nextOrdinal;
    let result;
    let invocationError = null;
    try {
      result = normalizeRunnerResult(
        await runner(executable, [...args], {
          env: { ...childEnvironment },
          maxBufferBytes,
        })
      );
    } catch (error) {
      invocationError = error;
      result = {
        exitCode:
          Number.isInteger(error?.exitCode) && error.exitCode >= 0 && error.exitCode <= 255
            ? error.exitCode
            : null,
        signal: typeof error?.signal === 'string' ? error.signal : null,
        stdout: error?.stdout ?? '',
        stderr: error?.stderr ?? '',
      };
    }
    const endedMonotonic = monotonicTime(monotonicNowNs, 'command ended monotonic time');
    const endedAt = wallTime(wallNow, 'command endedAt');
    if (endedMonotonic < startedMonotonic) {
      throw new ObserverPolicyError('MONOTONIC_CLOCK_REGRESSED', { kind });
    }
    if (Date.parse(endedAt) < Date.parse(startedAt)) {
      throw new ObserverPolicyError('WALL_CLOCK_REGRESSED', { kind });
    }
    const receipt = {
      index: receipts.length,
      kind,
      ordinal: nextOrdinal,
      executable,
      args: [...args],
      startedAt,
      endedAt,
      startedMonotonicNs: startedMonotonic.toString(),
      endedMonotonicNs: endedMonotonic.toString(),
      durationNs: (endedMonotonic - startedMonotonic).toString(),
      limits: {
        maxBufferBytes,
        timeoutMs,
        overflow: 'drain-without-signal',
      },
      environmentPolicy: clone(COMMAND_ENVIRONMENT_POLICY),
      exitCode: result.exitCode,
      signal: result.signal,
      stdout: outputReceipt(result.stdout, 'command stdout'),
      stderr: outputReceipt(result.stderr, 'command stderr'),
      cardinality: {
        global: receipts.length + 1,
        kind: nextOrdinal,
      },
      errorCode: invocationError === null ? null : errorCode(invocationError),
    };
    receipts.push(receipt);
    if (invocationError !== null) {
      throw new ObserverCommandError('COMMAND_RUNNER_FAILED', clone(receipt), invocationError);
    }
    return {
      receipt: clone(receipt),
      stdout: receipt.stdout.text ?? Buffer.from(receipt.stdout.base64, 'base64'),
      stderr: receipt.stderr.text ?? Buffer.from(receipt.stderr.base64, 'base64'),
    };
  }

  function snapshot() {
    return {
      receipts: clone(receipts),
      commandCardinality: { ...cardinality },
      rejectedAttempts: clone(rejectedAttempts),
      environmentPolicy: clone(COMMAND_ENVIRONMENT_POLICY),
    };
  }

  return Object.freeze({
    invoke,
    snapshot,
  });
}

function normalizedFilesystemPath(operation, value) {
  const target = requiredString(value, `${operation} path`);
  if (
    !path.posix.isAbsolute(target) ||
    path.posix.normalize(target) !== target ||
    Buffer.byteLength(target, 'utf8') > FILESYSTEM_LIMITS.maxPathBytes
  ) {
    throw new ObserverPolicyError('FILESYSTEM_PATH_INVALID', {
      operation,
      path: target,
    });
  }
  return target;
}

function incrementBudget(budgets, operation, targetPath, amount = 1) {
  const key = `${operation}\u0000${targetPath}`;
  budgets.set(key, (budgets.get(key) ?? 0) + amount);
}

function consumeBudget(scope, operation, targetPath, limit) {
  const key = `${operation}\u0000${targetPath}`;
  const next = (scope.counts.get(key) ?? 0) + 1;
  if (!Number.isSafeInteger(limit) || limit < next) {
    throw new ObserverPolicyError('FILESYSTEM_SCOPE_CARDINALITY_EXCEEDED', {
      operation,
      path: targetPath,
      limit,
    });
  }
  scope.counts.set(key, next);
}

function consumeRegisteredBudget(scope, budgets, operation, targetPath) {
  const key = `${operation}\u0000${targetPath}`;
  consumeBudget(scope, operation, targetPath, budgets.get(key) ?? 0);
}

function normalizeUsbId(value) {
  let text;
  try {
    text = exactUtf8(value, 'USB id').text.trim();
  } catch {
    return null;
  }
  if (!USB_ID.test(text)) return null;
  const parsed = BigInt(`0x${text}`);
  return parsed <= 0xffffn ? parsed.toString(16).padStart(4, '0') : null;
}

function sysfsAncestors(value) {
  if (
    typeof value !== 'string' ||
    path.posix.normalize(value) !== value ||
    !value.startsWith('/sys/devices/')
  ) {
    throw new ObserverPolicyError('HIDRAW_REALPATH_OUT_OF_SCOPE', {
      path: typeof value === 'string' ? value : String(value),
    });
  }
  const ancestors = [];
  let cursor = value;
  while (cursor.startsWith('/sys/devices/')) {
    ancestors.push(cursor);
    cursor = path.posix.dirname(cursor);
  }
  return ancestors;
}

function scopeFilesystemOperation(scope, operation, targetPath) {
  if (targetPath === '/etc/os-release' && operation === 'readFileSync') {
    consumeBudget(scope, operation, targetPath, 1);
    return;
  }
  if (
    ['/proc/sys/kernel/random/boot_id', '/proc/sys/kernel/hostname'].includes(targetPath) &&
    operation === 'readFileSync'
  ) {
    consumeBudget(scope, operation, targetPath, 1);
    return;
  }
  if (targetPath === '/sys/class/hidraw' && operation === 'readdirSync') {
    consumeBudget(scope, operation, targetPath, 1);
    return;
  }

  const classMatch =
    /^\/sys\/class\/hidraw\/(hidraw(?:0|[1-9][0-9]*))\/(device|device\/uevent|dev)$/u.exec(
      targetPath
    );
  if (classMatch !== null && scope.hidrawNames.has(classMatch[1])) {
    const [, name, leaf] = classMatch;
    const expectedOperation =
      leaf === 'device'
        ? 'realpathSync'
        : leaf === 'device/uevent'
          ? 'readFileSync'
          : 'readFileSync';
    if (operation === expectedOperation) {
      consumeBudget(scope, operation, targetPath, 1);
      if (leaf === 'device') scope.pendingRealpathName = name;
      return;
    }
  }

  const deviceMatch = /^\/dev\/(hidraw(?:0|[1-9][0-9]*))$/u.exec(targetPath);
  if (deviceMatch !== null && scope.hidrawNames.has(deviceMatch[1])) {
    const name = deviceMatch[1];
    if (operation === 'statSync') {
      consumeBudget(scope, operation, targetPath, 3);
      return;
    }
    if (operation === 'lstatSync') {
      consumeBudget(scope, operation, targetPath, 1);
      return;
    }
    if (operation === 'readlinkSync' && scope.symlinkDeviceNames.has(name)) {
      consumeBudget(scope, operation, targetPath, 1);
      return;
    }
  }

  if (operation === 'readFileSync') {
    const basename = path.posix.basename(targetPath);
    if (basename === 'idVendor' || basename === 'idProduct') {
      consumeRegisteredBudget(scope, scope.usbProbeBudgets, operation, targetPath);
      return;
    }
    if (['serial', 'manufacturer', 'product', 'busnum', 'devnum', 'devpath'].includes(basename)) {
      consumeRegisteredBudget(scope, scope.usbPropertyBudgets, operation, targetPath);
      return;
    }
    if (basename === 'dev') {
      consumeRegisteredBudget(scope, scope.usbDeviceBudgets, operation, targetPath);
      return;
    }
  }

  if (scope.proc !== null) {
    const { procRoot, hostPid, pids, surfaceWorkers, descriptorBudgets, targetMajor } = scope.proc;
    if (targetPath === procRoot && operation === 'readdirSync') {
      consumeBudget(scope, operation, targetPath, 2);
      return;
    }
    if (targetPath === `/proc/${hostPid}/cgroup` && operation === 'readFileSync') {
      consumeBudget(scope, operation, targetPath, 1);
      return;
    }
    const escapedProcRoot = procRoot.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
    const processMatch = new RegExp(
      `^${escapedProcRoot}/([1-9][0-9]*)/(stat|status|cmdline|cgroup|ns/pid|ns/mnt)$`,
      'u'
    ).exec(targetPath);
    if (processMatch !== null && pids.has(processMatch[1])) {
      const leaf = processMatch[2];
      const expectedOperation = leaf.startsWith('ns/') ? 'readlinkSync' : 'readFileSync';
      if (operation === expectedOperation) {
        consumeBudget(scope, operation, targetPath, 1);
        return;
      }
    }
    const descriptorDirectoryMatch = new RegExp(`^${escapedProcRoot}/([1-9][0-9]*)/fd$`, 'u').exec(
      targetPath
    );
    if (
      descriptorDirectoryMatch !== null &&
      operation === 'readdirSync' &&
      Number.isSafeInteger(targetMajor) &&
      targetMajor > 0 &&
      surfaceWorkers.has(descriptorDirectoryMatch[1])
    ) {
      consumeBudget(scope, operation, targetPath, 2);
      return;
    }
    const descriptorMatch = new RegExp(
      `^${escapedProcRoot}/([1-9][0-9]*)/fd/(0|[1-9][0-9]*)$`,
      'u'
    ).exec(targetPath);
    if (
      descriptorMatch !== null &&
      surfaceWorkers.has(descriptorMatch[1]) &&
      ['lstatSync', 'readlinkSync', 'statSync'].includes(operation)
    ) {
      consumeRegisteredBudget(scope, descriptorBudgets, operation, targetPath);
      return;
    }
  }

  throw new ObserverPolicyError('FILESYSTEM_PATH_OUTSIDE_FRAME_SCOPE', {
    operation,
    path: targetPath,
  });
}

function observeScopedFilesystemResult(scope, operation, targetPath, value) {
  if (targetPath === '/sys/class/hidraw' && operation === 'readdirSync') {
    if (
      !Array.isArray(value) ||
      value.length > FILESYSTEM_LIMITS.maxHidrawEntries ||
      value.some((entry) => typeof entry !== 'string')
    ) {
      throw new ObserverPolicyError('HIDRAW_INVENTORY_LIMIT_EXCEEDED', {
        limit: FILESYSTEM_LIMITS.maxHidrawEntries,
      });
    }
    scope.hidrawNames = new Set(value.filter((entry) => HIDRAW_NAME.test(entry)));
    return;
  }

  const realpathMatch = /^\/sys\/class\/hidraw\/(hidraw(?:0|[1-9][0-9]*))\/device$/u.exec(
    targetPath
  );
  if (realpathMatch !== null && operation === 'realpathSync') {
    const name = realpathMatch[1];
    if (scope.pendingRealpathName !== name) {
      throw new ObserverPolicyError('HIDRAW_REALPATH_SEQUENCE_INVALID', { name });
    }
    scope.pendingRealpathName = null;
    const resolved = requiredString(value, `${targetPath} realpath`);
    scope.hidrawRealpaths.set(name, resolved);
    for (const ancestor of sysfsAncestors(resolved)) {
      incrementBudget(scope.usbProbeBudgets, 'readFileSync', `${ancestor}/idVendor`);
      incrementBudget(scope.usbProbeBudgets, 'readFileSync', `${ancestor}/idProduct`);
    }
    return;
  }

  const deviceMatch = /^\/dev\/(hidraw(?:0|[1-9][0-9]*))$/u.exec(targetPath);
  if (deviceMatch !== null && operation === 'lstatSync') {
    if (value?.isSymbolicLink?.() === true) scope.symlinkDeviceNames.add(deviceMatch[1]);
    return;
  }

  if (operation === 'readFileSync') {
    const basename = path.posix.basename(targetPath);
    if (basename === 'idVendor' || basename === 'idProduct') {
      const directory = path.posix.dirname(targetPath);
      const pair = scope.usbPairs.get(directory) ?? {
        vendor: [],
        product: [],
        registered: 0,
      };
      const normalized = normalizeUsbId(value);
      if (basename === 'idVendor') pair.vendor.push(normalized);
      else pair.product.push(normalized);
      const completePairs = Math.min(pair.vendor.length, pair.product.length);
      while (
        pair.registered < completePairs &&
        pair.vendor[pair.registered] !== null &&
        pair.product[pair.registered] !== null
      ) {
        for (const property of [
          'serial',
          'manufacturer',
          'product',
          'busnum',
          'devnum',
          'devpath',
        ]) {
          incrementBudget(scope.usbPropertyBudgets, 'readFileSync', `${directory}/${property}`);
        }
        pair.registered += 1;
      }
      scope.usbPairs.set(directory, pair);
      return;
    }
  }

  if (scope.proc === null) return;
  const { procRoot, pids, surfaceWorkers, descriptorBudgets } = scope.proc;
  if (targetPath === procRoot && operation === 'readdirSync') {
    if (
      !Array.isArray(value) ||
      value.length > FILESYSTEM_LIMITS.maxProcessEntries ||
      value.some((entry) => typeof entry !== 'string')
    ) {
      throw new ObserverPolicyError('PROCESS_INVENTORY_LIMIT_EXCEEDED', {
        limit: FILESYSTEM_LIMITS.maxProcessEntries,
      });
    }
    if (scope.proc.processInventoryCaptured === false) {
      scope.proc.processInventoryCaptured = true;
      for (const entry of value.filter((candidate) => POSITIVE_DECIMAL.test(candidate))) {
        pids.add(entry);
      }
    }
    return;
  }
  const escapedProcRoot = procRoot.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const cmdlineMatch = new RegExp(`^${escapedProcRoot}/([1-9][0-9]*)/cmdline$`, 'u').exec(
    targetPath
  );
  if (cmdlineMatch !== null && operation === 'readFileSync') {
    try {
      if (isSurfaceThreadCmdline(parseCmdline(value))) surfaceWorkers.add(cmdlineMatch[1]);
    } catch {
      // Parsing failure is recorded by the observation; it must not widen the descriptor scope.
    }
    return;
  }
  const descriptorDirectoryMatch = new RegExp(`^${escapedProcRoot}/([1-9][0-9]*)/fd$`, 'u').exec(
    targetPath
  );
  if (descriptorDirectoryMatch !== null && operation === 'readdirSync') {
    if (
      !Array.isArray(value) ||
      value.length > FILESYSTEM_LIMITS.maxDescriptorEntries ||
      value.some((entry) => typeof entry !== 'string')
    ) {
      throw new ObserverPolicyError('DESCRIPTOR_INVENTORY_LIMIT_EXCEEDED', {
        limit: FILESYSTEM_LIMITS.maxDescriptorEntries,
      });
    }
    if (!scope.proc.descriptorInventories.has(descriptorDirectoryMatch[1])) {
      scope.proc.descriptorInventories.add(descriptorDirectoryMatch[1]);
      for (const descriptor of value.filter((entry) => DECIMAL.test(entry))) {
        const descriptorPath = `${targetPath}/${descriptor}`;
        for (const descriptorOperation of ['lstatSync', 'readlinkSync', 'statSync']) {
          incrementBudget(descriptorBudgets, descriptorOperation, descriptorPath);
        }
      }
    }
  }
}

function filesystemScopeState(frameId, receiptStart, grantStart) {
  return {
    frameId,
    receiptStart,
    grantStart,
    counts: new Map(),
    hidrawNames: new Set(),
    hidrawRealpaths: new Map(),
    pendingRealpathName: null,
    symlinkDeviceNames: new Set(),
    usbProbeBudgets: new Map(),
    usbPropertyBudgets: new Map(),
    usbDeviceBudgets: new Map(),
    usbPairs: new Map(),
    proc: null,
  };
}

export function createFilesystemAuditor({ filesystem, wallNow, monotonicNowNs } = {}) {
  if (!isPlainRecord(filesystem)) throw new TypeError('filesystem must be an object');
  for (const operation of FILESYSTEM_OPERATIONS) {
    if (typeof filesystem[operation] !== 'function') {
      throw new TypeError(`filesystem.${operation} must be a function`);
    }
  }

  const policyRejectedAttempts = [];
  const grants = [];
  const scopeRecords = [];
  const usedFrameIds = new Set();
  let activeScope = null;

  function reject(operation, targetPath, error) {
    policyRejectedAttempts.push({
      operation,
      path: typeof targetPath === 'string' ? targetPath : String(targetPath),
      code: errorCode(error),
    });
  }

  const limitedFilesystem = Object.fromEntries(
    FILESYSTEM_OPERATIONS.map((operation) => [
      operation,
      (targetPath, ...args) => {
        const value = filesystem[operation](targetPath, ...args);
        try {
          if (operation === 'readFileSync') {
            if (
              asBuffer(value, `${targetPath} read result`).byteLength >
              FILESYSTEM_LIMITS.maxReadBytes
            ) {
              throw new ObserverPolicyError('FILESYSTEM_READ_LIMIT_EXCEEDED', {
                operation,
                path: targetPath,
                limit: FILESYSTEM_LIMITS.maxReadBytes,
              });
            }
          } else if (operation === 'readdirSync') {
            let limit = FILESYSTEM_LIMITS.maxDirectoryEntries;
            let code = 'FILESYSTEM_DIRECTORY_LIMIT_EXCEEDED';
            if (targetPath === '/sys/class/hidraw') {
              limit = FILESYSTEM_LIMITS.maxHidrawEntries;
              code = 'HIDRAW_INVENTORY_LIMIT_EXCEEDED';
            } else if (activeScope?.proc?.procRoot === targetPath) {
              limit = FILESYSTEM_LIMITS.maxProcessEntries;
              code = 'PROCESS_INVENTORY_LIMIT_EXCEEDED';
            } else if (
              typeof targetPath === 'string' &&
              targetPath.startsWith(`${activeScope?.proc?.procRoot ?? '\u0000'}/`) &&
              targetPath.endsWith('/fd')
            ) {
              limit = FILESYSTEM_LIMITS.maxDescriptorEntries;
              code = 'DESCRIPTOR_INVENTORY_LIMIT_EXCEEDED';
            }
            if (Array.isArray(value) && value.length > limit) {
              throw new ObserverPolicyError(code, {
                operation,
                path: targetPath,
                limit,
              });
            }
          } else if (
            ['realpathSync', 'readlinkSync'].includes(operation) &&
            typeof value === 'string' &&
            Buffer.byteLength(value, 'utf8') > FILESYSTEM_LIMITS.maxPathBytes
          ) {
            throw new ObserverPolicyError('FILESYSTEM_RESULT_PATH_LIMIT_EXCEEDED', {
              operation,
              path: targetPath,
              limit: FILESYSTEM_LIMITS.maxPathBytes,
            });
          }
          if (
            operation === 'realpathSync' &&
            /^\/sys\/class\/hidraw\/hidraw(?:0|[1-9][0-9]*)\/device$/u.test(targetPath)
          ) {
            sysfsAncestors(value);
          }
          return value;
        } catch (error) {
          reject(operation, targetPath, error);
          throw error;
        }
      },
    ])
  );
  const baseAuditor = createBaseFilesystemAuditor({
    filesystem: limitedFilesystem,
    wallNow,
    monotonicNowNs,
  });

  function scopedInvoke(operation, targetPath, args) {
    let admittedPath;
    try {
      if (activeScope === null) {
        throw new ObserverPolicyError('FILESYSTEM_SCOPE_REQUIRED');
      }
      admittedPath = normalizedFilesystemPath(operation, targetPath);
      const receiptCount = baseAuditor.snapshot().receipts.length - activeScope.receiptStart;
      if (receiptCount >= FILESYSTEM_LIMITS.maxReceiptsPerFrame) {
        throw new ObserverPolicyError('FILESYSTEM_RECEIPT_LIMIT_EXCEEDED', {
          frameId: activeScope.frameId,
          limit: FILESYSTEM_LIMITS.maxReceiptsPerFrame,
        });
      }
      scopeFilesystemOperation(activeScope, operation, admittedPath);
    } catch (error) {
      reject(operation, targetPath, error);
      throw error;
    }

    const receiptIndex = baseAuditor.snapshot().receipts.length;
    grants.push({
      index: grants.length,
      frameId: activeScope.frameId,
      receiptIndex,
      operation,
      path: admittedPath,
    });
    try {
      const value = baseAuditor.filesystem[operation](admittedPath, ...args);
      observeScopedFilesystemResult(activeScope, operation, admittedPath, value);
      return value;
    } catch (error) {
      if (error instanceof ObserverPolicyError) reject(operation, admittedPath, error);
      throw error;
    }
  }

  const scopedFilesystem = Object.freeze(
    Object.fromEntries(
      FILESYSTEM_OPERATIONS.map((operation) => [
        operation,
        (targetPath, ...args) => scopedInvoke(operation, targetPath, args),
      ])
    )
  );
  const publicFilesystem = Object.freeze(
    Object.fromEntries(
      FILESYSTEM_OPERATIONS.map((operation) => [
        operation,
        (targetPath) => {
          const error = new ObserverPolicyError('FILESYSTEM_SCOPE_REQUIRED');
          reject(operation, targetPath, error);
          throw error;
        },
      ])
    )
  );

  const controller = Object.freeze({
    filesystem: scopedFilesystem,
    beginFrame(frameId) {
      const id = requiredString(frameId, 'filesystem frame id');
      if (activeScope !== null) {
        throw new ObserverPolicyError('FILESYSTEM_SCOPE_ALREADY_ACTIVE', {
          activeFrameId: activeScope.frameId,
        });
      }
      if (usedFrameIds.has(id)) {
        throw new ObserverPolicyError('FILESYSTEM_SCOPE_FRAME_REUSED', { frameId: id });
      }
      usedFrameIds.add(id);
      activeScope = filesystemScopeState(id, baseAuditor.snapshot().receipts.length, grants.length);
    },
    registerUsbDevicePath(usbDirectory) {
      if (activeScope === null) throw new ObserverPolicyError('FILESYSTEM_SCOPE_REQUIRED');
      const directory = normalizedFilesystemPath('readFileSync', usbDirectory);
      const pair = activeScope.usbPairs.get(directory);
      if (!directory.startsWith('/sys/devices/') || pair === undefined || pair.registered === 0) {
        throw new ObserverPolicyError('USB_DEVICE_PATH_NOT_DERIVED', { path: directory });
      }
      incrementBudget(activeScope.usbDeviceBudgets, 'readFileSync', `${directory}/dev`);
    },
    registerProcScope(hostPid, targetMajor) {
      if (activeScope === null) throw new ObserverPolicyError('FILESYSTEM_SCOPE_REQUIRED');
      if (
        activeScope.proc !== null ||
        !Number.isSafeInteger(hostPid) ||
        hostPid <= 0 ||
        !(targetMajor === null || (Number.isSafeInteger(targetMajor) && targetMajor > 0))
      ) {
        throw new ObserverPolicyError('PROC_SCOPE_INVALID', { hostPid, targetMajor });
      }
      activeScope.proc = {
        hostPid,
        targetMajor,
        procRoot: `/proc/${hostPid}/root/proc`,
        processInventoryCaptured: false,
        descriptorInventories: new Set(),
        pids: new Set(),
        surfaceWorkers: new Set(),
        descriptorBudgets: new Map(),
      };
    },
    endFrame(frameId) {
      const id = requiredString(frameId, 'filesystem frame id');
      if (activeScope === null || activeScope.frameId !== id) {
        throw new ObserverPolicyError('FILESYSTEM_SCOPE_END_MISMATCH', {
          frameId: id,
          activeFrameId: activeScope?.frameId ?? null,
        });
      }
      const receiptEnd = baseAuditor.snapshot().receipts.length;
      scopeRecords.push({
        frameId: id,
        receiptStart: activeScope.receiptStart,
        receiptEnd,
        grantStart: activeScope.grantStart,
        grantEnd: grants.length,
        closed: true,
      });
      activeScope = null;
    },
  });

  function snapshot() {
    const base = baseAuditor.snapshot();
    const rejectedAttempts = [...policyRejectedAttempts, ...base.rejectedAttempts];
    const policyExact =
      activeScope === null &&
      rejectedAttempts.length === 0 &&
      grants.length === base.receipts.length &&
      grants.every(
        (grant, index) =>
          grant.index === index &&
          grant.receiptIndex === index &&
          grant.operation === base.receipts[index]?.operation &&
          grant.path === base.receipts[index]?.path
      );
    return {
      ...base,
      rejectedAttempts: clone(rejectedAttempts),
      policyExact,
      scopeRecords: clone(scopeRecords),
      grants: clone(grants),
      limits: clone(FILESYSTEM_LIMITS),
    };
  }

  const auditor = Object.freeze({
    filesystem: publicFilesystem,
    snapshot,
  });
  FILESYSTEM_CONTROLLERS.set(publicFilesystem, controller);
  return auditor;
}

export function parseDockerInventory(value) {
  const text = exactUtf8(value, 'docker ps output').text;
  if (text === '') return [];
  const rows = [];
  const seen = new Set();
  for (const line of text.split(/\r?\n/u).filter(Boolean)) {
    const entry = parseJson(line, 'docker ps row');
    if (!isPlainRecord(entry) || !exactKeys(entry, ['ID', 'State'])) {
      throw new Error('docker ps row must be an exact ID and State object');
    }
    const containerId = exactContainerId(entry.ID, 'docker ps container id');
    const state = requiredString(entry.State, 'docker ps state').toLowerCase();
    if (seen.has(containerId)) throw new Error('docker ps contains a duplicate container id');
    seen.add(containerId);
    rows.push({
      containerId,
      state,
    });
  }
  return rows;
}

export const parseDockerPs = parseDockerInventory;

export function parseDockerInspect(value) {
  const entry = parseJson(value, 'docker inspect output');
  if (
    !isPlainRecord(entry) ||
    !exactKeys(entry, ['Id', 'Image', 'State', 'RestartCount', 'CgroupnsMode']) ||
    !isPlainRecord(entry.State) ||
    !exactKeys(entry.State, ['Status', 'Running', 'Pid', 'StartedAt']) ||
    !Number.isSafeInteger(entry.RestartCount) ||
    entry.RestartCount < 0
  ) {
    throw new Error('docker inspect output is incomplete or over-broad');
  }
  const imageId = requiredString(entry.Image, 'docker inspect Image').toLowerCase();
  if (!IMAGE_ID.test(imageId) || imageId !== ACCEPTED_IMAGE_ID) {
    throw new Error('docker inspect Image does not equal the accepted image id');
  }
  const status = requiredString(entry.State.Status, 'docker inspect State.Status').toLowerCase();
  if (typeof entry.State.Running !== 'boolean') {
    throw new Error('docker inspect State.Running must be boolean');
  }
  const running = entry.State.Running;
  if ((status === 'running') !== running) {
    throw new Error('docker inspect State.Status contradicts State.Running');
  }
  const hostPid = entry.State.Pid;
  if (!Number.isSafeInteger(hostPid) || (running && hostPid <= 0) || (!running && hostPid !== 0)) {
    throw new Error('docker inspect State.Pid is inconsistent with running state');
  }
  return {
    containerId: exactContainerId(entry.Id, 'docker inspect Id'),
    imageId,
    status,
    running,
    hostPid,
    startedAt: exactRfc3339(entry.State.StartedAt, 'docker inspect State.StartedAt'),
    restartCount: entry.RestartCount,
    cgroupNamespaceMode: requiredString(entry.CgroupnsMode, 'docker inspect CgroupnsMode'),
  };
}

export function parseDockerLogs(stdout, stderr, serial) {
  const expectedSerial = requiredString(serial, 'device serial');
  const streams = [
    ['stdout', exactUtf8(stdout, 'docker logs stdout').text],
    ['stderr', exactUtf8(stderr, 'docker logs stderr').text],
  ];
  const entries = [];
  for (const [stream, text] of streams) {
    for (const line of text.split(/\r?\n/u).filter(Boolean)) {
      const separator = line.indexOf(' ');
      if (separator <= 0) throw new Error('docker logs contain an untimestamped line');
      entries.push({
        at: exactRfc3339(line.slice(0, separator), 'docker log timestamp'),
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
    ['opening', `Opening surface panel: streamdeck:${expectedSerial}`],
    ['ready', `Surface panel ready: streamdeck:${expectedSerial}`],
  ];
  const relevantEntries = entries
    .map((entry) => {
      const marker = markers.find(
        ([, text]) =>
          entry.line.includes(text) &&
          (entry.line.endsWith(text) ||
            /\s/u.test(entry.line[entry.line.indexOf(text) + text.length]))
      );
      return {
        ...entry,
        markerKind: marker?.[0] ?? null,
      };
    })
    .filter((entry) => entry.markerKind !== null);
  return {
    entries,
    serialAvailable: true,
    openingCount: relevantEntries.filter((entry) => entry.markerKind === 'opening').length,
    readyCount: relevantEntries.filter((entry) => entry.markerKind === 'ready').length,
    relevantLinesSha256: sha256(
      Buffer.from(
        relevantEntries.map((entry) => `${entry.at}\t${entry.stream}\t${entry.line}`).join('\n'),
        'utf8'
      )
    ),
  };
}

export async function captureGitAdmission(
  commandAuditor,
  { protectedMainCommit, sourceContractCommit } = {}
) {
  if (typeof commandAuditor?.invoke !== 'function') {
    throw new TypeError('commandAuditor must expose invoke');
  }
  const protectedCommit = exactGitCommit(protectedMainCommit, 'protected main commit');
  const sourceCommit = exactGitCommit(sourceContractCommit, 'source contract commit');
  const revParse = await commandAuditor.invoke('git', ['rev-parse', 'HEAD']);
  if (revParse.receipt.exitCode !== 0) {
    throw new ObserverCommandError('GIT_REV_PARSE_FAILED', revParse.receipt);
  }
  const head = exactGitCommit(revParse.stdout.trim(), 'observed HEAD');
  const ancestry = await commandAuditor.invoke('git', [
    'merge-base',
    '--is-ancestor',
    protectedCommit,
    'HEAD',
  ]);
  if (ancestry.receipt.exitCode !== 0) {
    throw new ObserverCommandError('PROTECTED_MAIN_NOT_ANCESTOR', ancestry.receipt);
  }
  const sourceAncestry = await commandAuditor.invoke('git', [
    'merge-base',
    '--is-ancestor',
    sourceCommit,
    'HEAD',
  ]);
  if (sourceAncestry.receipt.exitCode !== 0) {
    throw new ObserverCommandError('SOURCE_CONTRACT_NOT_ANCESTOR', sourceAncestry.receipt);
  }
  const remote = await commandAuditor.invoke('git', ['remote', 'get-url', 'origin']);
  if (remote.receipt.exitCode !== 0) {
    throw new ObserverCommandError('GIT_REMOTE_FAILED', remote.receipt);
  }
  const remoteUrl = requiredString(remote.stdout.trim(), 'origin remote URL');
  if (remoteUrl.includes('\n') || remoteUrl.includes('\r')) {
    throw new Error('origin remote URL must contain exactly one line');
  }
  return {
    head,
    protectedMainCommit: protectedCommit,
    protectedMainIsAncestor: true,
    sourceContractCommit: sourceCommit,
    sourceContractIsAncestor: true,
    remoteUrl,
    commandReceiptIndexes: [
      revParse.receipt.index,
      ancestry.receipt.index,
      sourceAncestry.receipt.index,
      remote.receipt.index,
    ],
  };
}

export async function captureLsusbAdmission(commandAuditor) {
  if (typeof commandAuditor?.invoke !== 'function') {
    throw new TypeError('commandAuditor must expose invoke');
  }
  const observed = await commandAuditor.invoke('lsusb', []);
  if (observed.receipt.exitCode !== 0) {
    throw new ObserverCommandError('LSUSB_FAILED', observed.receipt);
  }
  return {
    devices: parseLsusb(observed.stdout),
    commandReceiptIndex: observed.receipt.index,
    stdoutSha256: observed.receipt.stdout.sha256,
  };
}

export async function captureDockerAdmission(commandAuditor) {
  if (typeof commandAuditor?.invoke !== 'function') {
    throw new TypeError('commandAuditor must expose invoke');
  }
  const observed = await commandAuditor.invoke('docker', [
    ...DOCKER_HOST_PREFIX,
    'version',
    '--format',
    DOCKER_VERSION_FORMAT,
  ]);
  if (observed.receipt.exitCode !== 0) {
    throw new ObserverCommandError('DOCKER_VERSION_FAILED', observed.receipt);
  }
  return {
    version: parseDockerVersion(observed.stdout),
    commandReceiptIndex: observed.receipt.index,
    stdoutSha256: observed.receipt.stdout.sha256,
    unixHost: DOCKER_UNIX_HOST,
  };
}

function receiptOutputBytes(receipt, stream) {
  const output = receipt?.[stream];
  if (!isPlainRecord(output) || typeof output.base64 !== 'string') {
    throw new Error(`command receipt lacks exact ${stream} bytes`);
  }
  const bytes = Buffer.from(output.base64, 'base64');
  if (
    bytes.toString('base64') !== output.base64 ||
    bytes.byteLength !== output.byteLength ||
    sha256(bytes) !== output.sha256
  ) {
    throw new Error(`command receipt ${stream} bytes do not match their digest`);
  }
  return bytes;
}

function validateAdmissionBinding(commandAuditor, lsusbAdmission, dockerAdmission) {
  const receipts = commandAuditor.snapshot().receipts;
  const lsusbReceipt = receipts[lsusbAdmission.commandReceiptIndex];
  if (
    lsusbReceipt?.kind !== 'lsusb' ||
    lsusbReceipt.exitCode !== 0 ||
    lsusbReceipt.stdout.sha256 !== lsusbAdmission.stdoutSha256 ||
    JSON.stringify(parseLsusb(receiptOutputBytes(lsusbReceipt, 'stdout'))) !==
      JSON.stringify(lsusbAdmission.devices)
  ) {
    throw new ObserverPolicyError('LSUSB_ADMISSION_UNBOUND');
  }
  const dockerReceipt = receipts[dockerAdmission.commandReceiptIndex];
  if (
    dockerReceipt?.kind !== 'dockerVersion' ||
    dockerReceipt.exitCode !== 0 ||
    dockerReceipt.stdout.sha256 !== dockerAdmission.stdoutSha256 ||
    dockerAdmission.unixHost !== DOCKER_UNIX_HOST ||
    JSON.stringify(parseDockerVersion(receiptOutputBytes(dockerReceipt, 'stdout'))) !==
      JSON.stringify(dockerAdmission.version)
  ) {
    throw new ObserverPolicyError('DOCKER_ADMISSION_UNBOUND');
  }
}

function recordFrameError(errors, stage, error) {
  errors.push({
    stage,
    code: errorCode(error),
    receiptIndex: Number.isSafeInteger(error?.receipt?.index) ? error.receipt.index : null,
  });
}

function readText(filesystem, targetPath) {
  return exactUtf8(filesystem.readFileSync(targetPath), targetPath).text.trim();
}

function observerTarget(value) {
  if (
    !exactKeys(value, ['serial', 'vendorId', 'productId']) ||
    value.vendorId !== ACCEPTED_DEVICE.vendorId ||
    value.productId !== ACCEPTED_DEVICE.productId
  ) {
    throw new ObserverPolicyError('TARGET_MUST_EQUAL_ACCEPTED_DEVICE');
  }
  return {
    serial: requiredString(value.serial, 'target serial'),
    vendorId: ACCEPTED_DEVICE.vendorId,
    productId: ACCEPTED_DEVICE.productId,
  };
}

function observeHost(filesystem, errors) {
  const host = {
    osRelease: null,
    bootId: null,
    hostname: null,
  };
  try {
    host.osRelease = parseOsRelease(filesystem.readFileSync('/etc/os-release'));
  } catch (error) {
    recordFrameError(errors, 'host-os-release', error);
  }
  try {
    const bootId = readText(filesystem, '/proc/sys/kernel/random/boot_id');
    if (
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(bootId)
    ) {
      throw new Error('boot id is malformed');
    }
    host.bootId = bootId.toLowerCase();
  } catch (error) {
    recordFrameError(errors, 'host-boot-id', error);
  }
  try {
    host.hostname = requiredString(readText(filesystem, '/proc/sys/kernel/hostname'), 'hostname');
  } catch (error) {
    recordFrameError(errors, 'host-hostname', error);
  }
  return host;
}

function observeDevice(filesystem, filesystemController, lsusbAdmission, target, errors) {
  let inventory = [];
  let inventoryCaptured = false;
  try {
    inventory = inventoryHostHidraw({ filesystem });
    inventoryCaptured = true;
  } catch (error) {
    recordFrameError(errors, 'hidraw-inventory', error);
  }
  const decorated = inventory.map((entry) => {
    const metadata = {
      lstat: null,
      stat: null,
      linkTarget: null,
    };
    if (entry.devicePath !== null) {
      try {
        metadata.lstat = statIdentity(filesystem.lstatSync(entry.devicePath, { bigint: true }));
      } catch (error) {
        recordFrameError(errors, `hidraw-lstat:${entry.name}`, error);
      }
      try {
        metadata.stat = statIdentity(filesystem.statSync(entry.devicePath, { bigint: true }));
      } catch (error) {
        recordFrameError(errors, `hidraw-stat:${entry.name}`, error);
      }
      if (metadata.lstat?.isSymbolicLink === true) {
        try {
          metadata.linkTarget = requiredString(
            filesystem.readlinkSync(entry.devicePath),
            `${entry.devicePath} link target`
          );
        } catch (error) {
          recordFrameError(errors, `hidraw-readlink:${entry.name}`, error);
        }
      }
    }
    return {
      ...entry,
      metadata,
    };
  });
  for (const entry of decorated) {
    if (entry.errors.length > 0) {
      errors.push({
        stage: `hidraw-entry:${entry.name}`,
        code: 'INCOMPLETE_HIDRAW_ENTRY',
        receiptIndex: null,
      });
    }
  }
  const lsusbMatches = lsusbAdmission.devices.filter(
    (entry) =>
      entry.vendorId === ACCEPTED_DEVICE.vendorId && entry.productId === ACCEPTED_DEVICE.productId
  );
  const exactEntries = decorated.filter(
    (entry) =>
      entry.errors.length === 0 &&
      entry.hid?.vendorId === target.vendorId &&
      entry.hid?.productId === target.productId &&
      entry.hid?.unique === target.serial &&
      entry.usbAncestor?.vendorId === target.vendorId &&
      entry.usbAncestor?.productId === target.productId &&
      entry.usbAncestor?.serial === target.serial
  );
  const targetSerialContradictions = decorated.filter(
    (entry) =>
      entry.errors.length === 0 &&
      entry.hid?.vendorId === target.vendorId &&
      entry.hid?.productId === target.productId &&
      entry.usbAncestor?.vendorId === target.vendorId &&
      entry.usbAncestor?.productId === target.productId &&
      (entry.hid?.unique === target.serial || entry.usbAncestor?.serial === target.serial) &&
      entry.hid?.unique !== entry.usbAncestor?.serial
  );
  let selectedEntry = null;
  if (exactEntries.length > 0) {
    try {
      selectedEntry = selectExactTargetHidraw(decorated, target);
    } catch (error) {
      recordFrameError(errors, 'device-selection-exact', error);
    }
  }
  const usbEpochs = exactEntries.map((entry) => {
    const ancestor = entry.usbAncestor;
    let usbDev = null;
    try {
      filesystemController.registerUsbDevicePath(ancestor.sysfsPath);
      usbDev = parseDeviceNumber(readText(filesystem, `${ancestor.sysfsPath}/dev`));
    } catch (error) {
      recordFrameError(errors, `usb-dev:${entry.name}`, error);
    }
    return {
      serial: ancestor.serial,
      vendorId: ancestor.vendorId,
      productId: ancestor.productId,
      busNumber: ancestor.busNumber,
      deviceNumber: ancestor.deviceNumber,
      usbDevicePath: ancestor.devicePath,
      usbDev,
      hidDevicePath: entry.hidDevicePath,
      devicePath: entry.devicePath,
      stat: entry.stat.value,
      hidrawName: entry.name,
    };
  });
  const correlatedEpochs = usbEpochs.map((epoch) => ({
    ...epoch,
    lsusbMatched: lsusbMatches.some(
      (entry) => entry.busNumber === epoch.busNumber && entry.deviceNumber === epoch.deviceNumber
    ),
  }));
  const inventoryExact = inventoryCaptured && decorated.every((entry) => entry.errors.length === 0);
  const exactAbsence =
    inventoryExact &&
    exactEntries.length === 0 &&
    lsusbMatches.length === 0 &&
    targetSerialContradictions.length === 0;
  const selectedEpoch =
    selectedEntry === null
      ? null
      : (correlatedEpochs.find((epoch) => epoch.hidrawName === selectedEntry.name) ?? null);
  const exactUnique =
    inventoryExact &&
    exactEntries.length === 1 &&
    selectedEpoch !== null &&
    lsusbMatches.filter(
      (entry) =>
        entry.busNumber === selectedEpoch.busNumber &&
        entry.deviceNumber === selectedEpoch.deviceNumber
    ).length === 1 &&
    selectedEpoch.lsusbMatched === true;
  const status = exactAbsence
    ? 'none'
    : exactUnique
      ? 'unique'
      : correlatedEpochs.length > 1
        ? 'multiple'
        : 'inconclusive';
  if (status === 'multiple') {
    errors.push({
      stage: 'device-selection',
      code: 'MULTIPLE_DEVICE_EPOCHS',
      receiptIndex: null,
    });
  } else if (status === 'inconclusive') {
    errors.push({
      stage: 'device-selection',
      code: 'DEVICE_CORRELATION_INCOMPLETE',
      receiptIndex: null,
    });
  }
  return {
    selector: clone(target),
    complete: exactAbsence || exactUnique,
    present: correlatedEpochs.length > 0,
    status,
    matchCount: correlatedEpochs.length,
    selectedEpoch: exactUnique ? selectedEpoch : null,
    lsusbMatches,
    usbEpochs: correlatedEpochs,
    targetSerialContradictionCount: targetSerialContradictions.length,
    hidrawEntries: decorated,
  };
}

function processIds(filesystem, procRoot) {
  return filesystem
    .readdirSync(procRoot)
    .filter((entry) => /^[1-9][0-9]*$/u.test(entry))
    .map(Number)
    .sort((left, right) => left - right);
}

function observeProcess(filesystem, procRoot, pid) {
  const directory = `${procRoot}/${pid}`;
  const stat = parseProcStat(filesystem.readFileSync(`${directory}/stat`));
  if (stat.pid !== pid) throw new Error(`proc stat PID mismatch for ${pid}`);
  const status = parseProcStatus(filesystem.readFileSync(`${directory}/status`));
  const namespacePid = status.namespacePids.at(-1);
  if (namespacePid !== pid) {
    throw new Error(`container proc status NSpid mismatch for ${pid}`);
  }
  return {
    pid,
    startTicks: stat.startTicks,
    ppid: stat.ppid,
    parentStartTicks: null,
    uid: status.uid,
    gid: status.gid,
    groups: status.groups,
    command: stat.command,
    cmdline: parseCmdline(filesystem.readFileSync(`${directory}/cmdline`)),
    cgroup: parseCgroup(filesystem.readFileSync(`${directory}/cgroup`)),
    pidNamespace: parseNamespace(filesystem.readlinkSync(`${directory}/ns/pid`), 'pid'),
    mountNamespace: parseNamespace(filesystem.readlinkSync(`${directory}/ns/mnt`), 'mnt'),
  };
}

function descriptorIsInScope(target, identity, targetMajor) {
  return (
    identity?.isCharacterDevice === true &&
    (/^\/dev\/hidraw(?:0|[1-9][0-9]*)(?: \(deleted\))?$/u.test(target) ||
      identity.major === targetMajor)
  );
}

function observeDescriptors(filesystem, procRoot, workerPid, targetMajor, errors) {
  const directory = `${procRoot}/${workerPid}/fd`;
  let before;
  try {
    before = filesystem
      .readdirSync(directory)
      .filter((entry) => DECIMAL.test(entry))
      .sort((left, right) => Number(left) - Number(right));
  } catch (error) {
    recordFrameError(errors, `worker-fd-list-before:${workerPid}`, error);
    return { stable: false, entries: [] };
  }
  const entries = [];
  for (const descriptor of before) {
    const descriptorPath = `${directory}/${descriptor}`;
    try {
      const linkMetadata = statIdentity(filesystem.lstatSync(descriptorPath, { bigint: true }));
      const target = requiredString(
        filesystem.readlinkSync(descriptorPath),
        `${descriptorPath} target`
      );
      const targetMetadata = statIdentity(filesystem.statSync(descriptorPath, { bigint: true }));
      if (descriptorIsInScope(target, targetMetadata, targetMajor)) {
        entries.push({
          descriptor,
          target,
          lstat: linkMetadata,
          stat: targetMetadata,
        });
      }
    } catch (error) {
      recordFrameError(errors, `worker-fd:${workerPid}:${descriptor}`, error);
    }
  }
  let after = null;
  try {
    after = filesystem
      .readdirSync(directory)
      .filter((entry) => DECIMAL.test(entry))
      .sort((left, right) => Number(left) - Number(right));
  } catch (error) {
    recordFrameError(errors, `worker-fd-list-after:${workerPid}`, error);
  }
  return {
    stable: after !== null && JSON.stringify(before) === JSON.stringify(after),
    entries,
  };
}

function emptyProcessObservation() {
  return {
    procRoot: null,
    stable: false,
    pid1: null,
    all: [],
    surfaceWorkers: [],
  };
}

function observeProcesses(filesystem, hostPid, targetMajor, errors) {
  const procRoot = `/proc/${hostPid}/root/proc`;
  let before;
  try {
    before = processIds(filesystem, procRoot);
  } catch (error) {
    recordFrameError(errors, 'process-list-before', error);
    return {
      ...emptyProcessObservation(),
      procRoot,
    };
  }
  const observed = [];
  for (const pid of before) {
    try {
      observed.push(observeProcess(filesystem, procRoot, pid));
    } catch (error) {
      recordFrameError(errors, `process:${pid}`, error);
    }
  }
  let after = null;
  try {
    after = processIds(filesystem, procRoot);
  } catch (error) {
    recordFrameError(errors, 'process-list-after', error);
  }
  const tableStable =
    after !== null &&
    JSON.stringify(before) === JSON.stringify(after) &&
    observed.length === before.length;
  if (!tableStable) {
    errors.push({
      stage: 'process-table-drift',
      code: 'PROCESS_TABLE_DRIFT',
      receiptIndex: null,
    });
  }
  const byPid = new Map(observed.map((entry) => [entry.pid, entry]));
  for (const entry of observed) {
    if (entry.ppid === 0) continue;
    const parent = byPid.get(entry.ppid);
    if (parent === undefined) {
      errors.push({
        stage: `process-parent:${entry.pid}`,
        code: 'PARENT_NOT_OBSERVED',
        receiptIndex: null,
      });
      continue;
    }
    entry.parentStartTicks = parent.startTicks;
  }
  const targetMajorValid = Number.isSafeInteger(targetMajor) && targetMajor > 0;
  const surfaceWorkers = observed
    .filter((entry) => isSurfaceThreadCmdline(entry.cmdline))
    .map((entry) => {
      if (!targetMajorValid) {
        return {
          ...entry,
          fileDescriptors: [],
          descriptorTableStable: false,
        };
      }
      const descriptors = observeDescriptors(filesystem, procRoot, entry.pid, targetMajor, errors);
      if (!descriptors.stable) {
        errors.push({
          stage: `worker-fd-drift:${entry.pid}`,
          code: 'DESCRIPTOR_TABLE_DRIFT',
          receiptIndex: null,
        });
      }
      return {
        ...entry,
        fileDescriptors: descriptors.entries,
        descriptorTableStable: descriptors.stable,
      };
    });
  if (!byPid.has(1)) {
    errors.push({
      stage: 'process-pid1',
      code: 'PID1_NOT_OBSERVED',
      receiptIndex: null,
    });
  }
  if (surfaceWorkers.length > 1) {
    errors.push({
      stage: 'surface-worker-selection',
      code: 'MULTIPLE_SURFACE_WORKERS',
      receiptIndex: null,
    });
  }
  return {
    procRoot,
    stable: tableStable,
    pid1: byPid.get(1) ?? null,
    all: observed,
    surfaceWorkers,
  };
}

function lifecycleFromInspect(filesystem, inspected, processes, errors) {
  const lifecycle = {
    ...inspected,
    pid1StartTicks: processes.pid1?.startTicks ?? null,
    pidNamespace: processes.pid1?.pidNamespace ?? null,
    mountNamespace: processes.pid1?.mountNamespace ?? null,
    cgroup: processes.pid1?.cgroup ?? null,
    hostCgroup: null,
  };
  if (!inspected.running) return lifecycle;
  try {
    lifecycle.hostCgroup = parseCgroup(
      filesystem.readFileSync(`/proc/${inspected.hostPid}/cgroup`)
    );
  } catch (error) {
    recordFrameError(errors, 'host-pid-cgroup', error);
  }
  return lifecycle;
}

const FRAME_INPUT_KEYS = Object.freeze([
  'commandAuditor',
  'dockerAdmission',
  'filesystemAuditor',
  'frameId',
  'logSince',
  'lsusbAdmission',
  'monotonicNowNs',
  'target',
  'wallNow',
]);

export async function captureObservationFrame(options = {}) {
  if (!isPlainRecord(options)) throw new TypeError('frame options must be an object');
  const unexpected = Object.keys(options).filter((key) => !FRAME_INPUT_KEYS.includes(key));
  if (unexpected.length > 0) {
    throw new ObserverPolicyError('FRAME_INPUT_PROHIBITED_FIELD', {
      fields: unexpected.sort(),
    });
  }
  const {
    frameId,
    commandAuditor,
    filesystemAuditor,
    lsusbAdmission,
    dockerAdmission,
    logSince,
    target: targetInput,
    wallNow,
    monotonicNowNs,
  } = options;
  const id = requiredString(frameId, 'frame id');
  if (
    typeof commandAuditor?.invoke !== 'function' ||
    typeof commandAuditor?.snapshot !== 'function'
  ) {
    throw new TypeError('commandAuditor must expose invoke and snapshot');
  }
  if (
    typeof filesystemAuditor?.snapshot !== 'function' ||
    !isPlainRecord(filesystemAuditor.filesystem)
  ) {
    throw new TypeError('filesystemAuditor must expose filesystem and snapshot');
  }
  const filesystemController = FILESYSTEM_CONTROLLERS.get(filesystemAuditor.filesystem);
  if (filesystemController === undefined) {
    throw new TypeError('filesystemAuditor must be created by createFilesystemAuditor');
  }
  if (!isPlainRecord(lsusbAdmission) || !Array.isArray(lsusbAdmission.devices)) {
    throw new TypeError('lsusbAdmission is invalid');
  }
  if (!isPlainRecord(dockerAdmission) || !isPlainRecord(dockerAdmission.version)) {
    throw new TypeError('dockerAdmission is invalid');
  }
  validateAdmissionBinding(commandAuditor, lsusbAdmission, dockerAdmission);
  if (typeof wallNow !== 'function' || typeof monotonicNowNs !== 'function') {
    throw new TypeError('frame clocks are required');
  }
  const since = exactRfc3339(logSince, 'log since');
  const target = observerTarget(targetInput);
  const errors = [];
  const commandStart = commandAuditor.snapshot().receipts.length;
  const filesystemStart = filesystemAuditor.snapshot().receipts.length;
  const startedAt = wallTime(wallNow, 'frame startedAt');
  const startedMonotonic = monotonicTime(monotonicNowNs, 'frame started monotonic time');
  filesystemController.beginFrame(id);
  const filesystem = filesystemController.filesystem;
  const host = observeHost(filesystem, errors);
  const device = observeDevice(filesystem, filesystemController, lsusbAdmission, target, errors);

  let inventoryRows = [];
  let inventoryExact = false;
  let inventoryStatus = 'inconclusive';
  let psReceipt = null;
  try {
    const observed = await commandAuditor.invoke('docker', [
      ...DOCKER_HOST_PREFIX,
      'ps',
      '--all',
      '--no-trunc',
      '--filter',
      DOCKER_ANCESTOR_FILTER,
      '--format',
      DOCKER_PS_FORMAT,
    ]);
    psReceipt = observed.receipt;
    if (observed.receipt.exitCode !== 0) {
      throw new ObserverCommandError('DOCKER_PS_FAILED', observed.receipt);
    }
    inventoryRows = parseDockerInventory(observed.stdout);
    inventoryExact = true;
    inventoryStatus =
      inventoryRows.length === 0 ? 'none' : inventoryRows.length === 1 ? 'unique' : 'multiple';
  } catch (error) {
    if (isPlainRecord(error?.receipt) && error.receipt.kind === 'dockerPs') {
      psReceipt = error.receipt;
    }
    recordFrameError(errors, 'docker-inventory', error);
  }

  const selectedRow = inventoryStatus === 'unique' ? inventoryRows[0] : null;
  let inspectReceipt = null;
  let inspected = null;
  let inspectionExact = false;
  if (selectedRow !== null) {
    try {
      const observed = await commandAuditor.invoke('docker', [
        ...DOCKER_HOST_PREFIX,
        'inspect',
        '--format',
        DOCKER_INSPECT_FORMAT,
        selectedRow.containerId,
      ]);
      inspectReceipt = observed.receipt;
      if (observed.receipt.exitCode !== 0) {
        throw new ObserverCommandError('DOCKER_INSPECT_FAILED', observed.receipt);
      }
      inspected = parseDockerInspect(observed.stdout);
      if (inspected.containerId !== selectedRow.containerId) {
        throw new Error('docker inspect returned a different container');
      }
      if (inspected.status !== selectedRow.state) {
        throw new Error('docker inspect state contradicts docker ps');
      }
      inspectionExact = true;
    } catch (error) {
      if (isPlainRecord(error?.receipt) && error.receipt.kind === 'dockerInspect') {
        inspectReceipt = error.receipt;
      }
      recordFrameError(errors, 'docker-inspect', error);
    }
  }

  const targetMajor = device.selectedEpoch?.stat?.major ?? null;
  if (inspected?.running === true) {
    filesystemController.registerProcScope(inspected.hostPid, targetMajor);
  }
  const processes =
    inspected?.running === true
      ? observeProcesses(filesystem, inspected.hostPid, targetMajor, errors)
      : emptyProcessObservation();
  const lifecycle =
    inspected === null ? null : lifecycleFromInspect(filesystem, inspected, processes, errors);

  let observationCutoff = inspectReceipt ?? psReceipt ?? null;
  observationCutoff =
    observationCutoff === null
      ? null
      : {
          at: observationCutoff.endedAt,
          monotonicNs: observationCutoff.endedMonotonicNs,
        };
  let logsUntil = null;
  let markers = {
    entries: [],
    serialAvailable: true,
    openingCount: inventoryStatus === 'none' || lifecycle?.running === false ? 0 : null,
    readyCount: inventoryStatus === 'none' || lifecycle?.running === false ? 0 : null,
    relevantLinesSha256:
      inventoryStatus === 'none' || lifecycle?.running === false ? sha256(Buffer.alloc(0)) : null,
  };
  if (inspectionExact && lifecycle?.running === true) {
    const cutoffAt = wallTime(wallNow, 'observation cutoff');
    const cutoffMonotonic = monotonicTime(monotonicNowNs, 'observation cutoff monotonic time');
    observationCutoff = {
      at: cutoffAt,
      monotonicNs: cutoffMonotonic.toString(),
    };
    logsUntil = cutoffAt;
    try {
      const observed = await commandAuditor.invoke('docker', [
        ...DOCKER_HOST_PREFIX,
        'logs',
        '--timestamps',
        '--since',
        since,
        '--until',
        logsUntil,
        selectedRow.containerId,
      ]);
      if (observed.receipt.exitCode !== 0) {
        throw new ObserverCommandError('DOCKER_LOGS_FAILED', observed.receipt);
      }
      markers = parseDockerLogs(observed.stdout, observed.stderr, target.serial);
      if (
        markers.entries.some(
          (entry) =>
            rfc3339EpochNs(entry.at, 'docker log entry timestamp') <
              rfc3339EpochNs(since, 'docker logs since') ||
            rfc3339EpochNs(entry.at, 'docker log entry timestamp') >
              rfc3339EpochNs(logsUntil, 'docker logs until')
        )
      ) {
        throw new Error('docker logs returned an entry outside the requested window');
      }
    } catch (error) {
      recordFrameError(errors, 'docker-logs', error);
    }
  }
  if (observationCutoff === null) {
    observationCutoff = {
      at: wallTime(wallNow, 'observation cutoff'),
      monotonicNs: monotonicTime(monotonicNowNs, 'observation cutoff monotonic time').toString(),
    };
  }

  const endedMonotonic = monotonicTime(monotonicNowNs, 'frame ended monotonic time');
  const endedAt = wallTime(wallNow, 'frame endedAt');
  if (endedMonotonic < startedMonotonic) {
    throw new ObserverPolicyError('MONOTONIC_CLOCK_REGRESSED', { frameId: id });
  }
  if (Date.parse(endedAt) < Date.parse(startedAt)) {
    throw new ObserverPolicyError('WALL_CLOCK_REGRESSED', { frameId: id });
  }
  if (
    BigInt(observationCutoff.monotonicNs) < startedMonotonic ||
    BigInt(observationCutoff.monotonicNs) > endedMonotonic
  ) {
    throw new ObserverPolicyError('MONOTONIC_CLOCK_REGRESSED', { frameId: id });
  }
  if (
    rfc3339EpochNs(observationCutoff.at, 'observation cutoff') <
      rfc3339EpochNs(startedAt, 'frame startedAt') ||
    rfc3339EpochNs(observationCutoff.at, 'observation cutoff') >
      rfc3339EpochNs(endedAt, 'frame endedAt')
  ) {
    throw new ObserverPolicyError('WALL_CLOCK_REGRESSED', { frameId: id });
  }

  filesystemController.endFrame(id);
  const commandSnapshot = commandAuditor.snapshot();
  const filesystemSnapshot = filesystemAuditor.snapshot();
  const frameFilesystemReceipts = filesystemSnapshot.receipts.slice(filesystemStart);
  const hardFilesystemFailure = frameFilesystemReceipts.some(
    (receipt) => receipt.disposition === 'error'
  );
  const commandReceiptIndexes = commandSnapshot.receipts
    .slice(commandStart)
    .map((receipt) => receipt.index);
  const filesystemReceiptIndexes = frameFilesystemReceipts.map((receipt) => receipt.index);
  const runningTupleComplete =
    lifecycle?.running === true &&
    processes.stable === true &&
    processes.pid1 !== null &&
    processes.surfaceWorkers.length <= 1 &&
    (device.status === 'none' ||
      (device.status === 'unique' &&
        markers.serialAvailable === true &&
        Number.isInteger(markers.openingCount) &&
        Number.isInteger(markers.readyCount)));
  const inventoryBranchComplete =
    inventoryStatus === 'none' ||
    inventoryStatus === 'multiple' ||
    (inventoryStatus === 'unique' &&
      inspectionExact &&
      (lifecycle?.running === false || runningTupleComplete));
  const complete =
    errors.length === 0 &&
    hardFilesystemFailure === false &&
    device.complete === true &&
    inventoryExact === true &&
    inventoryBranchComplete;

  return {
    schemaVersion: 'overlaykit-h045-observation-frame/v1',
    frameId: id,
    startedAt,
    endedAt,
    startedMonotonicNs: startedMonotonic.toString(),
    endedMonotonicNs: endedMonotonic.toString(),
    exposureNs: (endedMonotonic - startedMonotonic).toString(),
    observationCutoff,
    complete,
    errors,
    host,
    device,
    docker: {
      version: clone(dockerAdmission.version),
      inventory: {
        selector: {
          kind: 'ancestor-image-id',
          imageId: ACCEPTED_IMAGE_ID,
          filter: DOCKER_ANCESTOR_FILTER,
          unixHost: DOCKER_UNIX_HOST,
          projection: DOCKER_PS_FORMAT,
        },
        matches: inventoryRows,
        matchCount: inventoryRows.length,
        status: inventoryStatus,
        exact: inventoryExact,
        commandReceiptIndex: psReceipt?.index ?? null,
      },
      selected: selectedRow,
      inspectExact: inspectionExact,
      lifecycle,
      logWindow: {
        since,
        until: logsUntil,
      },
      markers,
    },
    processes,
    auditBinding: {
      commandReceiptIndexes,
      filesystemReceiptIndexes,
    },
    auditCursor: {
      commandCardinality: commandSnapshot.commandCardinality,
      filesystemCardinality: filesystemSnapshot.filesystemCardinality,
      rejectedCommandAttempts: commandSnapshot.rejectedAttempts.length,
      rejectedFilesystemAttempts: filesystemSnapshot.rejectedAttempts.length,
    },
  };
}

function receiptSequenceExact(receipts) {
  return receipts.every(
    (receipt, index) =>
      isPlainRecord(receipt) && receipt.index === index && receipt.cardinality?.global === index + 1
  );
}

function commandOutputsExact(receipts) {
  return receipts.every((receipt) =>
    ['stdout', 'stderr'].every((stream) => {
      try {
        const bytes = receiptOutputBytes(receipt, stream);
        const output = receipt[stream];
        return (
          SHA256.test(output.sha256) &&
          (output.encoding === 'utf8'
            ? output.text === bytes.toString('utf8')
            : output.encoding === 'base64' && output.text === null)
        );
      } catch {
        return false;
      }
    })
  );
}

function sortedUniqueIndexes(value) {
  return (
    Array.isArray(value) &&
    value.every((entry) => Number.isSafeInteger(entry) && entry >= 0) &&
    value.every((entry, index) => index === 0 || value[index - 1] < entry)
  );
}

function receiptWithinFrame(receipt, frame) {
  try {
    return (
      BigInt(receipt.startedMonotonicNs) >= BigInt(frame.startedMonotonicNs) &&
      BigInt(receipt.endedMonotonicNs) <= BigInt(frame.endedMonotonicNs) &&
      rfc3339EpochNs(receipt.startedAt, 'receipt start') >=
        rfc3339EpochNs(frame.startedAt, 'frame start') &&
      rfc3339EpochNs(receipt.endedAt, 'receipt end') <= rfc3339EpochNs(frame.endedAt, 'frame end')
    );
  } catch {
    return false;
  }
}

function cutoffWithinFrame(frame) {
  try {
    return (
      isPlainRecord(frame.observationCutoff) &&
      BigInt(frame.observationCutoff.monotonicNs) >= BigInt(frame.startedMonotonicNs) &&
      BigInt(frame.observationCutoff.monotonicNs) <= BigInt(frame.endedMonotonicNs) &&
      rfc3339EpochNs(frame.observationCutoff.at, 'frame cutoff') >=
        rfc3339EpochNs(frame.startedAt, 'frame start') &&
      rfc3339EpochNs(frame.observationCutoff.at, 'frame cutoff') <=
        rfc3339EpochNs(frame.endedAt, 'frame end')
    );
  } catch {
    return false;
  }
}

function receiptEndsAtOrBeforeCutoff(receipt, cutoff) {
  try {
    return (
      BigInt(receipt.endedMonotonicNs) <= BigInt(cutoff.monotonicNs) &&
      rfc3339EpochNs(receipt.endedAt, 'receipt end') <= rfc3339EpochNs(cutoff.at, 'frame cutoff')
    );
  } catch {
    return false;
  }
}

function receiptStartsAtOrAfterCutoff(receipt, cutoff) {
  try {
    return (
      BigInt(receipt.startedMonotonicNs) >= BigInt(cutoff.monotonicNs) &&
      rfc3339EpochNs(receipt.startedAt, 'receipt start') >=
        rfc3339EpochNs(cutoff.at, 'frame cutoff')
    );
  } catch {
    return false;
  }
}

export function frameAuditBindingExact(frame, commandReceipts, filesystemReceipts) {
  if (
    !isPlainRecord(frame) ||
    !exactKeys(frame.auditBinding, ['commandReceiptIndexes', 'filesystemReceiptIndexes']) ||
    !cutoffWithinFrame(frame) ||
    !sortedUniqueIndexes(frame.auditBinding.commandReceiptIndexes) ||
    !sortedUniqueIndexes(frame.auditBinding.filesystemReceiptIndexes) ||
    !Array.isArray(commandReceipts) ||
    !Array.isArray(filesystemReceipts)
  ) {
    return false;
  }
  const commandIndexes = frame.auditBinding.commandReceiptIndexes;
  const filesystemIndexes = frame.auditBinding.filesystemReceiptIndexes;
  const commands = commandIndexes.map((index) => commandReceipts[index]);
  const reads = filesystemIndexes.map((index) => filesystemReceipts[index]);
  if (
    commands.some(
      (receipt, position) =>
        !isPlainRecord(receipt) ||
        receipt.index !== commandIndexes[position] ||
        !receiptWithinFrame(receipt, frame)
    ) ||
    reads.some(
      (receipt, position) =>
        !isPlainRecord(receipt) ||
        receipt.index !== filesystemIndexes[position] ||
        !receiptWithinFrame(receipt, frame) ||
        !filesystemReceiptResultExact(receipt)
    )
  ) {
    return false;
  }
  const kinds = commands.map((receipt) => receipt.kind);
  const cutoff = frame.observationCutoff;
  if (JSON.stringify(kinds) === JSON.stringify(['dockerPs'])) {
    return (
      ['none', 'multiple'].includes(frame.docker?.inventory?.status) &&
      frame.docker?.logWindow?.until === null &&
      cutoff.at === commands[0].endedAt &&
      cutoff.monotonicNs === commands[0].endedMonotonicNs &&
      reads.every((receipt) => receiptEndsAtOrBeforeCutoff(receipt, cutoff))
    );
  }
  if (JSON.stringify(kinds) === JSON.stringify(['dockerPs', 'dockerInspect'])) {
    return (
      frame.docker?.inventory?.status === 'unique' &&
      frame.docker?.lifecycle?.running === false &&
      frame.docker?.logWindow?.until === null &&
      cutoff.at === commands[1].endedAt &&
      cutoff.monotonicNs === commands[1].endedMonotonicNs &&
      reads.every((receipt) => receiptEndsAtOrBeforeCutoff(receipt, cutoff))
    );
  }
  if (
    JSON.stringify(kinds) !== JSON.stringify(['dockerPs', 'dockerInspect', 'dockerLogs']) ||
    frame.docker?.inventory?.status !== 'unique' ||
    frame.docker?.lifecycle?.running !== true
  ) {
    return false;
  }
  const logsReceipt = commands[2];
  const untilIndex = logsReceipt.args.indexOf('--until');
  return (
    untilIndex >= 0 &&
    logsReceipt.args[untilIndex + 1] === cutoff.at &&
    frame.docker?.logWindow?.until === cutoff.at &&
    commands.slice(0, 2).every((receipt) => receiptEndsAtOrBeforeCutoff(receipt, cutoff)) &&
    reads.every((receipt) => receiptEndsAtOrBeforeCutoff(receipt, cutoff)) &&
    receiptStartsAtOrAfterCutoff(logsReceipt, cutoff)
  );
}

function frameBindingsCoverAudit(frames, commandReceipts, filesystemReceipts) {
  if (
    frames.length !== 2 ||
    !frames.every((frame) => frameAuditBindingExact(frame, commandReceipts, filesystemReceipts))
  ) {
    return false;
  }
  const boundCommands = frames.flatMap((frame) => frame.auditBinding.commandReceiptIndexes);
  const expectedCommands = commandReceipts
    .filter((receipt) => ['dockerPs', 'dockerInspect', 'dockerLogs'].includes(receipt.kind))
    .map((receipt) => receipt.index);
  const boundFilesystem = frames.flatMap((frame) => frame.auditBinding.filesystemReceiptIndexes);
  const expectedFilesystem = filesystemReceipts.map((receipt) => receipt.index);
  return (
    new Set(boundCommands).size === boundCommands.length &&
    new Set(boundFilesystem).size === boundFilesystem.length &&
    JSON.stringify([...boundCommands].sort((left, right) => left - right)) ===
      JSON.stringify(expectedCommands) &&
    JSON.stringify([...boundFilesystem].sort((left, right) => left - right)) ===
      JSON.stringify(expectedFilesystem)
  );
}

function environmentPolicyExact(receipt) {
  return JSON.stringify(receipt.environmentPolicy) === JSON.stringify(COMMAND_ENVIRONMENT_POLICY);
}

function commandLimitsExact(receipt) {
  return (
    exactKeys(receipt?.limits, ['maxBufferBytes', 'timeoutMs', 'overflow']) &&
    Number.isSafeInteger(receipt.limits.maxBufferBytes) &&
    receipt.limits.maxBufferBytes > 0 &&
    receipt.limits.timeoutMs === null &&
    receipt.limits.overflow === 'drain-without-signal'
  );
}

function filesystemScopesExact(filesystem, frames) {
  if (
    filesystem.policyExact !== true ||
    JSON.stringify(filesystem.limits) !== JSON.stringify(FILESYSTEM_LIMITS) ||
    !Array.isArray(filesystem.scopeRecords) ||
    !Array.isArray(filesystem.grants) ||
    filesystem.scopeRecords.length !== frames.length ||
    filesystem.grants.length !== filesystem.receipts.length
  ) {
    return false;
  }
  let receiptCursor = 0;
  let grantCursor = 0;
  const seenFrameIds = new Set();
  for (const [position, frame] of frames.entries()) {
    const scope = filesystem.scopeRecords[position];
    if (
      !isPlainRecord(scope) ||
      scope.closed !== true ||
      typeof scope.frameId !== 'string' ||
      scope.frameId !== frame?.frameId ||
      seenFrameIds.has(scope.frameId) ||
      scope.receiptStart !== receiptCursor ||
      scope.grantStart !== grantCursor ||
      !Number.isSafeInteger(scope.receiptEnd) ||
      !Number.isSafeInteger(scope.grantEnd) ||
      scope.receiptEnd < scope.receiptStart ||
      scope.grantEnd < scope.grantStart
    ) {
      return false;
    }
    seenFrameIds.add(scope.frameId);
    const expectedReceiptIndexes = Array.from(
      { length: scope.receiptEnd - scope.receiptStart },
      (_, index) => scope.receiptStart + index
    );
    if (
      JSON.stringify(frame?.auditBinding?.filesystemReceiptIndexes) !==
        JSON.stringify(expectedReceiptIndexes) ||
      scope.grantEnd - scope.grantStart !== expectedReceiptIndexes.length
    ) {
      return false;
    }
    const scopeGrants = filesystem.grants.slice(scope.grantStart, scope.grantEnd);
    if (
      scopeGrants.some((grant, index) => {
        const receiptIndex = expectedReceiptIndexes[index];
        const receipt = filesystem.receipts[receiptIndex];
        return (
          !isPlainRecord(grant) ||
          grant.index !== scope.grantStart + index ||
          grant.frameId !== scope.frameId ||
          grant.receiptIndex !== receiptIndex ||
          grant.operation !== receipt?.operation ||
          grant.path !== receipt?.path
        );
      })
    ) {
      return false;
    }
    receiptCursor = scope.receiptEnd;
    grantCursor = scope.grantEnd;
  }
  return receiptCursor === filesystem.receipts.length && grantCursor === filesystem.grants.length;
}

export function buildCapabilityAudit({ commandAuditor, filesystemAuditor, frames } = {}) {
  if (typeof commandAuditor?.snapshot !== 'function') {
    throw new TypeError('commandAuditor must expose snapshot');
  }
  if (typeof filesystemAuditor?.snapshot !== 'function') {
    throw new TypeError('filesystemAuditor must expose snapshot');
  }
  if (!Array.isArray(frames)) throw new TypeError('frames must be an array');
  const command = commandAuditor.snapshot();
  const filesystem = filesystemAuditor.snapshot();
  const frameCount = frames.length;
  const uniqueFrames = frames.filter(
    (frame) => frame?.docker?.inventory?.status === 'unique'
  ).length;
  const runningFrames = frames.filter((frame) => frame?.docker?.lifecycle?.running === true).length;
  const allowedProcessCounts = {
    git:
      command.commandCardinality.gitRevParse +
      command.commandCardinality.gitMergeBaseAncestor +
      command.commandCardinality.gitRemoteGetUrl,
    lsusb: command.commandCardinality.lsusb,
    dockerVersion: command.commandCardinality.dockerVersion,
    dockerPs: command.commandCardinality.dockerPs,
    dockerInspect: command.commandCardinality.dockerInspect,
    dockerLogs: command.commandCardinality.dockerLogs,
  };
  const commandCount = command.receipts.length;
  const filesystemReceiptCount = filesystem.receipts.length;
  const observedSignalCount = command.receipts.filter(
    (receipt) => typeof receipt?.signal === 'string' && receipt.signal !== ''
  ).length;
  const exact =
    frameCount === 2 &&
    allowedProcessCounts.git === 4 &&
    command.commandCardinality.gitRevParse === 1 &&
    command.commandCardinality.gitMergeBaseAncestor === 2 &&
    command.commandCardinality.gitRemoteGetUrl === 1 &&
    allowedProcessCounts.lsusb === 1 &&
    allowedProcessCounts.dockerVersion === 1 &&
    allowedProcessCounts.dockerPs === frameCount &&
    allowedProcessCounts.dockerInspect === uniqueFrames &&
    allowedProcessCounts.dockerLogs === runningFrames &&
    commandCount === Object.values(allowedProcessCounts).reduce((sum, count) => sum + count, 0) &&
    command.rejectedAttempts.length === 0 &&
    filesystem.rejectedAttempts.length === 0 &&
    receiptSequenceExact(command.receipts) &&
    command.receipts.every(
      (receipt) =>
        receipt.exitCode === 0 &&
        receipt.signal === null &&
        receipt.errorCode === null &&
        environmentPolicyExact(receipt) &&
        commandLimitsExact(receipt)
    ) &&
    receiptSequenceExact(filesystem.receipts) &&
    commandOutputsExact(command.receipts) &&
    filesystem.receipts.every(filesystemReceiptResultExact) &&
    filesystemScopesExact(filesystem, frames) &&
    frameBindingsCoverAudit(frames, command.receipts, filesystem.receipts);
  const commandReceipts = command.receipts.map((receipt) =>
    receipt.kind.startsWith('git')
      ? {
          ...receipt,
          observerKind: receipt.kind,
          kind: 'git',
        }
      : receipt
  );
  return {
    mode: 'live-readonly-dynamic-acquisition-capability-bounded',
    complete: exact,
    exact,
    frameCount,
    lsusbCount: allowedProcessCounts.lsusb,
    unrecordedObservationCount: 0,
    commandReceipts,
    filesystemReceipts: filesystem.receipts,
    allowedProcessCounts,
    commandCount,
    filesystemReceiptCount,
    environmentPolicy: clone(COMMAND_ENVIRONMENT_POLICY),
    prohibitedCounts: {
      ...PROHIBITED_CAPABILITIES,
      signal: observedSignalCount,
    },
  };
}
