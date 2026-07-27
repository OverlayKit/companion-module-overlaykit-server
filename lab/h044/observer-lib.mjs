import { createHash } from 'node:crypto';
import path from 'node:path';

import { inventoryHostHidraw } from '../h041/host-inventory.mjs';

const SHA256 = /^[0-9a-f]{64}$/u;
const GIT_SHA1 = /^[0-9a-f]{40}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const RFC3339 =
  /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})$/u;
const HIDRAW_NAME = /^hidraw(0|[1-9][0-9]*)$/u;
const CONTAINER_ID = /^[0-9a-f]{64}$/u;
const DOCKER_UNIX_HOST = 'unix:///var/run/docker.sock';
const DOCKER_HOST_PREFIX = Object.freeze(['--host', DOCKER_UNIX_HOST]);
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

const COMMAND_LIMITS = Object.freeze({
  gitRevParse: 1,
  gitMergeBaseAncestor: 1,
  gitRemoteGetUrl: 1,
  lsusb: 1,
  dockerVersion: 1,
  dockerPs: 2,
  dockerInspect: 2,
  dockerLogs: 2,
});

const PROHIBITED_CAPABILITIES = Object.freeze({
  externalNetwork: 0,
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

const FILESYSTEM_OPERATIONS = Object.freeze([
  'readFileSync',
  'readdirSync',
  'realpathSync',
  'statSync',
  'lstatSync',
  'readlinkSync',
]);

export const OBSERVER_COMMAND_LIMITS = COMMAND_LIMITS;
export const OBSERVER_DOCKER_UNIX_HOST = DOCKER_UNIX_HOST;
export const OBSERVER_DOCKER_VERSION_FORMAT = DOCKER_VERSION_FORMAT;
export const OBSERVER_DOCKER_PS_FORMAT = DOCKER_PS_FORMAT;
export const OBSERVER_DOCKER_INSPECT_FORMAT = DOCKER_INSPECT_FORMAT;
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

export class ObserverFilesystemError extends Error {
  constructor(code, receipt, cause = null, observationCode = 'FILESYSTEM_OBSERVATION_FAILED') {
    super(observationCode);
    this.name = 'ObserverFilesystemError';
    this.code = code;
    this.observationCode = observationCode;
    this.receipt = receipt;
    this.cause = cause;
  }
}

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requiredString(value, label) {
  if (typeof value !== 'string' || value === '' || value.includes('\u0000')) {
    throw new TypeError(`${label} must be a non-empty NUL-free string`);
  }
  return value;
}

function normalizeUsbId(value, label) {
  const text = requiredString(value, label).toLowerCase();
  if (!/^[0-9a-f]{1,8}$/u.test(text)) throw new TypeError(`${label} must be hexadecimal`);
  const parsed = BigInt(`0x${text}`);
  if (parsed > 0xffffn) throw new RangeError(`${label} exceeds the USB identifier range`);
  return parsed.toString(16).padStart(4, '0');
}

function normalizeDecimal(value, label, { positive = false } = {}) {
  const text = requiredString(String(value), label);
  if (!DECIMAL.test(text)) throw new TypeError(`${label} must be an unsigned decimal integer`);
  const parsed = BigInt(text);
  if (positive ? parsed <= 0n : parsed < 0n) {
    throw new RangeError(`${label} is outside the supported range`);
  }
  if (parsed > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError(`${label} exceeds the safe integer range`);
  }
  return Number(parsed);
}

function exactGitCommit(value, label) {
  const text = requiredString(value, label).toLowerCase();
  if (!GIT_SHA1.test(text)) throw new TypeError(`${label} must be an exact 40-byte-hex Git SHA-1`);
  return text;
}

function exactContainerId(value, label = 'container id') {
  const text = requiredString(value, label).toLowerCase();
  if (!CONTAINER_ID.test(text)) {
    throw new TypeError(`${label} must be an exact 64-byte-hex container id`);
  }
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
  if (!Number.isFinite(wholeSecondMs)) throw new TypeError(`${label} is invalid`);
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
      dockerArgs.length === 7 &&
      dockerArgs[0] === 'ps' &&
      dockerArgs[1] === '--all' &&
      dockerArgs[2] === '--no-trunc' &&
      dockerArgs[3] === '--filter' &&
      /^id=[0-9a-f]{64}$/u.test(dockerArgs[4]) &&
      dockerArgs[5] === '--format' &&
      dockerArgs[6] === DOCKER_PS_FORMAT
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
  const exitCode = result.exitCode;
  if (!(exitCode === null || (Number.isInteger(exitCode) && exitCode >= 0 && exitCode <= 255))) {
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
    exitCode,
    signal: result.signal ?? null,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

export function createCommandAuditor({
  runner,
  wallNow,
  monotonicNowNs,
  maxBufferBytes = 4 * 1024 * 1024,
  timeoutMs = 10_000,
} = {}) {
  if (typeof runner !== 'function') throw new TypeError('runner must be a function');
  if (typeof wallNow !== 'function') throw new TypeError('wallNow must be a function');
  if (typeof monotonicNowNs !== 'function') {
    throw new TypeError('monotonicNowNs must be a function');
  }
  if (!Number.isSafeInteger(maxBufferBytes) || maxBufferBytes <= 0) {
    throw new TypeError('maxBufferBytes must be a positive safe integer');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError('timeoutMs must be a positive safe integer');
  }

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
          maxBufferBytes,
          timeoutMs,
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
      },
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
      prohibited: { ...PROHIBITED_CAPABILITIES },
    };
  }

  return Object.freeze({
    invoke,
    snapshot,
  });
}

function safeBigInt(value, label) {
  if (typeof value === 'bigint') {
    if (value < 0n) throw new RangeError(`${label} must not be negative`);
    return value;
  }
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${label} is outside the supported integer range`);
  }
  return BigInt(value);
}

function safeNumber(value, label) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new RangeError(`${label} is outside the supported integer range`);
  }
  return parsed;
}

export function decodeLinuxDeviceNumber(value) {
  const encoded = safeBigInt(value, 'device number');
  if (encoded > 0xffff_ffff_ffff_ffffn) {
    throw new RangeError('device number exceeds the Linux 64-bit dev_t range');
  }
  const major =
    ((encoded & 0x0000_0000_000f_ff00n) >> 8n) | ((encoded & 0xffff_f000_0000_0000n) >> 32n);
  const minor = (encoded & 0x0000_0000_0000_00ffn) | ((encoded & 0x0000_0fff_fff0_0000n) >> 12n);
  return {
    major: safeNumber(major, 'device major'),
    minor: safeNumber(minor, 'device minor'),
  };
}

export function statIdentity(stats) {
  if (
    stats === null ||
    typeof stats !== 'object' ||
    typeof stats.isCharacterDevice !== 'function' ||
    typeof stats.isSymbolicLink !== 'function'
  ) {
    throw new TypeError('stats must be an fs stat-like object');
  }
  const rdev = safeBigInt(stats.rdev, 'stat rdev');
  const { major, minor } = decodeLinuxDeviceNumber(rdev);
  return {
    stDev: safeBigInt(stats.dev, 'stat device').toString(),
    inode: safeBigInt(stats.ino, 'stat inode').toString(),
    ctimeNs: safeBigInt(stats.ctimeNs, 'stat ctimeNs').toString(),
    mode: (safeBigInt(stats.mode, 'stat mode') & 0o7777n).toString(8).padStart(4, '0'),
    uid: safeNumber(safeBigInt(stats.uid, 'stat uid'), 'stat uid'),
    gid: safeNumber(safeBigInt(stats.gid, 'stat gid'), 'stat gid'),
    rdev: rdev.toString(),
    rdevHex: `${major.toString(16)}:${minor.toString(16)}`,
    major,
    minor,
    isCharacterDevice: stats.isCharacterDevice(),
    isSymbolicLink: stats.isSymbolicLink(),
  };
}

function validateObservedPath(operation, value) {
  const target = requiredString(value, `${operation} path`);
  if (!path.posix.isAbsolute(target) || path.posix.normalize(target) !== target) {
    throw new ObserverPolicyError('FILESYSTEM_PATH_INVALID', { operation, path: target });
  }
  const ordinaryRoot =
    target === '/etc' ||
    target.startsWith('/etc/') ||
    target === '/proc' ||
    target.startsWith('/proc/') ||
    target === '/sys' ||
    target.startsWith('/sys/');
  const deviceMetadata =
    ['statSync', 'lstatSync', 'readlinkSync'].includes(operation) &&
    /^\/(?:dev|host-dev)\/hidraw(?:0|[1-9][0-9]*)$/u.test(target);
  if (!ordinaryRoot && !deviceMetadata) {
    throw new ObserverPolicyError('FILESYSTEM_PATH_PROHIBITED', { operation, path: target });
  }
  if (
    ['readFileSync', 'readdirSync', 'realpathSync'].includes(operation) &&
    /^\/(?:dev|host-dev)\//u.test(target)
  ) {
    throw new ObserverPolicyError('HIDRAW_CONTENT_ACCESS_PROHIBITED', {
      operation,
      path: target,
    });
  }
  return target;
}

function filesystemResult(operation, value) {
  if (operation === 'readFileSync') {
    const receipt = outputReceipt(value, 'filesystem read result');
    return {
      cardinality: 1,
      byteLength: receipt.byteLength,
      bytes: {
        encoding: 'base64',
        base64: receipt.base64,
        byteLength: receipt.byteLength,
        sha256: receipt.sha256,
      },
      encoding: receipt.encoding,
      text: receipt.text,
      sha256: receipt.sha256,
    };
  }
  if (operation === 'readdirSync') {
    if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
      throw new TypeError('filesystem readdir result must be an array of strings');
    }
    const entries = [...value];
    return {
      entries,
      cardinality: entries.length,
      sha256: sha256(Buffer.from(JSON.stringify(entries), 'utf8')),
    };
  }
  if (operation === 'realpathSync' || operation === 'readlinkSync') {
    const target = requiredString(value, `${operation} result`);
    return {
      value: target,
      cardinality: 1,
      sha256: sha256(Buffer.from(target, 'utf8')),
    };
  }
  const identity = statIdentity(value);
  return {
    cardinality: 1,
    metadata: identity,
    sha256: sha256(Buffer.from(JSON.stringify(identity), 'utf8')),
  };
}

export function filesystemReceiptResultExact(receipt) {
  if (
    !isPlainRecord(receipt) ||
    typeof receipt.operation !== 'string' ||
    !FILESYSTEM_OPERATIONS.includes(receipt.operation) ||
    !isPlainRecord(receipt.result)
  ) {
    return false;
  }
  const result = receipt.result;
  if (receipt.disposition !== 'observed') {
    return (
      (receipt.disposition === 'missing' || receipt.disposition === 'error') &&
      exactKeys(result, ['cardinality', 'sha256']) &&
      result.cardinality === 0 &&
      result.sha256 === sha256(Buffer.alloc(0))
    );
  }

  if (receipt.operation === 'readFileSync') {
    if (
      !exactKeys(result, ['cardinality', 'byteLength', 'bytes', 'encoding', 'text', 'sha256']) ||
      result.cardinality !== 1 ||
      !isPlainRecord(result.bytes) ||
      !exactKeys(result.bytes, ['encoding', 'base64', 'byteLength', 'sha256']) ||
      result.bytes.encoding !== 'base64' ||
      typeof result.bytes.base64 !== 'string'
    ) {
      return false;
    }
    const bytes = Buffer.from(result.bytes.base64, 'base64');
    if (
      bytes.toString('base64') !== result.bytes.base64 ||
      bytes.byteLength !== result.byteLength ||
      bytes.byteLength !== result.bytes.byteLength ||
      sha256(bytes) !== result.sha256 ||
      result.sha256 !== result.bytes.sha256
    ) {
      return false;
    }
    const decoded = bytes.toString('utf8');
    const utf8Exact = Buffer.from(decoded, 'utf8').equals(bytes);
    return utf8Exact
      ? result.encoding === 'utf8' && result.text === decoded
      : result.encoding === 'base64' && result.text === null;
  }

  if (receipt.operation === 'readdirSync') {
    return (
      exactKeys(result, ['entries', 'cardinality', 'sha256']) &&
      Array.isArray(result.entries) &&
      result.entries.every((entry) => typeof entry === 'string') &&
      result.cardinality === result.entries.length &&
      result.sha256 === sha256(Buffer.from(JSON.stringify(result.entries), 'utf8'))
    );
  }

  if (receipt.operation === 'realpathSync' || receipt.operation === 'readlinkSync') {
    return (
      exactKeys(result, ['value', 'cardinality', 'sha256']) &&
      typeof result.value === 'string' &&
      result.value !== '' &&
      result.cardinality === 1 &&
      result.sha256 === sha256(Buffer.from(result.value, 'utf8'))
    );
  }

  return (
    exactKeys(result, ['cardinality', 'metadata', 'sha256']) &&
    result.cardinality === 1 &&
    exactKeys(result.metadata, [
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
      'isSymbolicLink',
    ]) &&
    result.sha256 === sha256(Buffer.from(JSON.stringify(result.metadata), 'utf8'))
  );
}

export function createFilesystemAuditor({ filesystem, wallNow, monotonicNowNs } = {}) {
  if (!isPlainRecord(filesystem)) throw new TypeError('filesystem must be an object');
  for (const operation of FILESYSTEM_OPERATIONS) {
    if (typeof filesystem[operation] !== 'function') {
      throw new TypeError(`filesystem.${operation} must be a function`);
    }
  }
  if (typeof wallNow !== 'function') throw new TypeError('wallNow must be a function');
  if (typeof monotonicNowNs !== 'function') {
    throw new TypeError('monotonicNowNs must be a function');
  }

  const receipts = [];
  const rejectedAttempts = [];
  const cardinality = Object.fromEntries(FILESYSTEM_OPERATIONS.map((key) => [key, 0]));

  function invoke(operation, targetPath, args) {
    let admittedPath;
    try {
      admittedPath = validateObservedPath(operation, targetPath);
    } catch (error) {
      rejectedAttempts.push({
        operation,
        path: typeof targetPath === 'string' ? targetPath : String(targetPath),
        code: errorCode(error),
      });
      throw error;
    }

    const startedAt = wallTime(wallNow, 'filesystem startedAt');
    const startedMonotonic = monotonicTime(monotonicNowNs, 'filesystem started monotonic time');
    cardinality[operation] += 1;
    let value;
    let observedError = null;
    try {
      value = filesystem[operation](admittedPath, ...args);
    } catch (error) {
      observedError = error;
    }
    const endedMonotonic = monotonicTime(monotonicNowNs, 'filesystem ended monotonic time');
    const endedAt = wallTime(wallNow, 'filesystem endedAt');
    if (endedMonotonic < startedMonotonic) {
      throw new ObserverPolicyError('MONOTONIC_CLOCK_REGRESSED', {
        operation,
        path: admittedPath,
      });
    }
    if (Date.parse(endedAt) < Date.parse(startedAt)) {
      throw new ObserverPolicyError('WALL_CLOCK_REGRESSED', {
        operation,
        path: admittedPath,
      });
    }

    const missing =
      observedError !== null &&
      (observedError?.code === 'ENOENT' || observedError?.code === 'ENOTDIR');
    let result;
    if (observedError === null) {
      try {
        result = filesystemResult(operation, value);
      } catch (error) {
        observedError = error;
      }
    }
    result ??= {
      cardinality: 0,
      sha256: sha256(Buffer.alloc(0)),
    };
    const receipt = {
      index: receipts.length,
      operation,
      path: admittedPath,
      startedAt,
      endedAt,
      startedMonotonicNs: startedMonotonic.toString(),
      endedMonotonicNs: endedMonotonic.toString(),
      durationNs: (endedMonotonic - startedMonotonic).toString(),
      disposition: observedError === null ? 'observed' : missing ? 'missing' : 'error',
      result,
      errorCode: observedError === null ? null : errorCode(observedError),
      cardinality: {
        global: receipts.length + 1,
        operation: cardinality[operation],
      },
    };
    receipts.push(receipt);

    if (observedError !== null) {
      throw new ObserverFilesystemError(
        errorCode(observedError),
        clone(receipt),
        observedError,
        missing ? 'FILESYSTEM_ENTRY_MISSING' : 'FILESYSTEM_OBSERVATION_FAILED'
      );
    }
    return value;
  }

  const auditedFilesystem = Object.freeze(
    Object.fromEntries(
      FILESYSTEM_OPERATIONS.map((operation) => [
        operation,
        (targetPath, ...args) => invoke(operation, targetPath, args),
      ])
    )
  );

  function snapshot() {
    return {
      receipts: clone(receipts),
      filesystemCardinality: { ...cardinality },
      rejectedAttempts: clone(rejectedAttempts),
    };
  }

  return Object.freeze({
    filesystem: auditedFilesystem,
    snapshot,
  });
}

export function parseProperties(value) {
  const text = exactUtf8(value, 'properties').text;
  const properties = {};
  for (const rawLine of text.split(/\r?\n/u)) {
    if (rawLine === '' || rawLine.startsWith('#')) continue;
    const separator = rawLine.indexOf('=');
    if (separator <= 0) throw new Error('properties record is malformed');
    const key = rawLine.slice(0, separator);
    if (Object.hasOwn(properties, key)) throw new Error(`duplicate property ${key}`);
    properties[key] = rawLine.slice(separator + 1);
  }
  return properties;
}

export function parseOsRelease(value) {
  const properties = parseProperties(value);
  const required = ['ID', 'VERSION_ID', 'PRETTY_NAME'];
  if (required.some((key) => typeof properties[key] !== 'string' || properties[key] === '')) {
    throw new Error('os-release lacks ID, VERSION_ID, or PRETTY_NAME');
  }
  function unquote(text) {
    if (text.startsWith('"') && text.endsWith('"')) {
      return text.slice(1, -1).replaceAll('\\"', '"').replaceAll('\\\\', '\\');
    }
    if (/^[A-Za-z0-9._+-]+$/u.test(text)) return text;
    throw new Error('os-release value uses an unsupported encoding');
  }
  return {
    id: unquote(properties.ID),
    versionId: unquote(properties.VERSION_ID),
    prettyName: unquote(properties.PRETTY_NAME),
  };
}

export function parseLsusb(value) {
  const { text } = exactUtf8(value, 'lsusb output');
  if (text === '') return [];
  const devices = [];
  const seen = new Set();
  for (const line of text.split(/\r?\n/u).filter(Boolean)) {
    const match =
      /^Bus ([0-9]{3}) Device ([0-9]{3}): ID ([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4})(?: (.*))?$/u.exec(
        line
      );
    if (match === null) throw new Error('lsusb output contains a malformed line');
    const busNumber = normalizeDecimal(BigInt(match[1]).toString(), 'lsusb bus', {
      positive: true,
    }).toString();
    const deviceNumber = normalizeDecimal(BigInt(match[2]).toString(), 'lsusb device', {
      positive: true,
    }).toString();
    const key = `${busNumber}:${deviceNumber}`;
    if (seen.has(key)) throw new Error('lsusb output contains a duplicate bus/device tuple');
    seen.add(key);
    devices.push({
      busNumber,
      deviceNumber,
      vendorId: normalizeUsbId(match[3], 'lsusb vendor'),
      productId: normalizeUsbId(match[4], 'lsusb product'),
      description: match[5] || null,
      line,
    });
  }
  return devices;
}

function parseJson(value, label) {
  const text = exactUtf8(value, label).text.trim();
  if (text === '') throw new Error(`${label} is empty`);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`${label} is not JSON`);
  }
  return parsed;
}

export function parseDockerVersion(value) {
  const parsed = parseJson(value, 'docker version output');
  if (
    !isPlainRecord(parsed) ||
    !exactKeys(parsed, ['Client', 'Server']) ||
    !isPlainRecord(parsed.Client) ||
    !exactKeys(parsed.Client, ['Version', 'ApiVersion']) ||
    !isPlainRecord(parsed.Server) ||
    !exactKeys(parsed.Server, ['Version', 'ApiVersion'])
  ) {
    throw new Error('docker version output lacks Client or Server');
  }
  const clientVersion = requiredString(parsed.Client.Version, 'docker client version');
  const serverVersion = requiredString(parsed.Server.Version, 'docker server version');
  const clientApiVersion = requiredString(parsed.Client.ApiVersion, 'docker client API version');
  const serverApiVersion = requiredString(parsed.Server.ApiVersion, 'docker server API version');
  return {
    client: {
      version: clientVersion,
      apiVersion: clientApiVersion,
    },
    server: {
      version: serverVersion,
      apiVersion: serverApiVersion,
    },
  };
}

export function parseDockerPs(value) {
  const text = exactUtf8(value, 'docker ps output').text;
  if (text === '') return [];
  const containers = [];
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
    containers.push({
      containerId,
      state,
    });
  }
  return containers;
}

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
    throw new Error('docker inspect output is incomplete');
  }
  const state = entry.State;
  const imageId = requiredString(entry.Image, 'docker inspect Image');
  if (!/^sha256:[0-9a-f]{64}$/u.test(imageId)) {
    throw new Error('docker inspect Image must be an exact sha256 image id');
  }
  const cgroupNamespaceMode = requiredString(entry.CgroupnsMode, 'docker inspect CgroupnsMode');
  return {
    containerId: exactContainerId(entry.Id, 'docker inspect Id'),
    imageId,
    running: state.Running === true,
    status: requiredString(state.Status, 'docker inspect State.Status'),
    startedAt: exactRfc3339(state.StartedAt, 'docker inspect State.StartedAt'),
    hostPid:
      Number.isSafeInteger(state.Pid) && state.Pid > 0
        ? state.Pid
        : (() => {
            throw new Error('docker inspect State.Pid must be positive');
          })(),
    restartCount: entry.RestartCount,
    cgroupNamespaceMode,
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
      const at = exactRfc3339(line.slice(0, separator), 'docker log timestamp');
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
  const openingMarker = `Opening surface panel: streamdeck:${expectedSerial}`;
  const readyMarker = `Surface panel ready: streamdeck:${expectedSerial}`;
  function markerKind(line) {
    for (const [kind, marker] of [
      ['opening', openingMarker],
      ['ready', readyMarker],
    ]) {
      const markerIndex = line.indexOf(marker);
      if (
        markerIndex !== -1 &&
        (markerIndex + marker.length === line.length ||
          /\s/u.test(line[markerIndex + marker.length]))
      ) {
        return kind;
      }
    }
    return null;
  }
  const relevantEntries = entries
    .map((entry) => ({ ...entry, markerKind: markerKind(entry.line) }))
    .filter((entry) => entry.markerKind !== null);
  return {
    entries,
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

export function parseProcStat(value) {
  const text = exactUtf8(value, 'proc stat').text.trim();
  if (text.includes('\n') || text.includes('\r')) {
    throw new Error('proc stat must contain exactly one record');
  }
  const match = /^([1-9][0-9]*)\s+\((.*)\)\s+([A-Za-z])\s+(.+)$/u.exec(text);
  if (match === null) throw new Error('proc stat record is malformed');
  const fieldsAfterState = match[4].trim().split(/\s+/u);
  if (fieldsAfterState.length < 19) throw new Error('proc stat lacks field 22 start time');
  return {
    pid: normalizeDecimal(match[1], 'proc stat pid', { positive: true }),
    ppid: normalizeDecimal(fieldsAfterState[0], 'proc stat ppid'),
    startTicks: normalizeDecimal(fieldsAfterState[18], 'proc stat start ticks', {
      positive: true,
    }),
    command: match[2],
    state: match[3],
  };
}

function statusNumbers(properties, key, minimum) {
  const value = properties[key];
  if (typeof value !== 'string') throw new Error(`proc status lacks ${key}`);
  const parsed = value
    .split(/\s+/u)
    .filter(Boolean)
    .map((entry) => normalizeDecimal(entry, `proc status ${key}`));
  if (parsed.length < minimum) throw new Error(`proc status ${key} is incomplete`);
  return parsed;
}

export function parseProcStatus(value) {
  const text = exactUtf8(value, 'proc status').text;
  const properties = {};
  for (const line of text.split(/\r?\n/u)) {
    const separator = line.indexOf(':');
    if (separator <= 0) continue;
    const key = line.slice(0, separator);
    if (Object.hasOwn(properties, key)) throw new Error(`duplicate proc status field ${key}`);
    properties[key] = line.slice(separator + 1).trim();
  }
  const uids = statusNumbers(properties, 'Uid', 4);
  const gids = statusNumbers(properties, 'Gid', 4);
  const groups = statusNumbers(properties, 'Groups', 0);
  const namespacePids = statusNumbers(properties, 'NSpid', 1);
  return {
    uid: uids[0],
    gid: gids[0],
    groups,
    namespacePids,
  };
}

export function parseCmdline(value) {
  const text = exactUtf8(value, 'proc cmdline').text;
  if (text === '') return [];
  const payload = text.endsWith('\u0000') ? text.slice(0, -1) : text;
  const arguments_ = payload.split('\u0000');
  if (arguments_.some((argument) => argument === '')) {
    throw new Error('proc cmdline contains an empty argument');
  }
  return arguments_;
}

export function parseCgroup(value) {
  const lines = exactUtf8(value, 'proc cgroup')
    .text.split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length === 0 || lines.some((line) => !/^[0-9]+:[^:]*:.+$/u.test(line))) {
    throw new Error('proc cgroup record is malformed');
  }
  return lines.join('\n');
}

export function parseNamespace(value, namespaceType) {
  const type = requiredString(namespaceType, 'namespace type');
  const text = requiredString(value, `${type} namespace`);
  if (!new RegExp(`^${type.replaceAll('/', '\\/')}:\\[[0-9]+\\]$`, 'u').test(text)) {
    throw new Error(`${type} namespace record is malformed`);
  }
  return text;
}

export function isSurfaceThreadCmdline(cmdline) {
  return (
    Array.isArray(cmdline) &&
    cmdline.some(
      (argument) =>
        typeof argument === 'string' && path.posix.basename(argument) === 'SurfaceThread.js'
    )
  );
}

export async function captureGitAdmission(commandAuditor, { protectedMainCommit } = {}) {
  if (typeof commandAuditor?.invoke !== 'function') {
    throw new TypeError('commandAuditor must expose invoke');
  }
  const protectedCommit = exactGitCommit(protectedMainCommit, 'protected main commit');
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
    remoteUrl,
    commandReceiptIndexes: [revParse.receipt.index, ancestry.receipt.index, remote.receipt.index],
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
  };
}

function receiptSequenceExact(receipts) {
  return receipts.every(
    (receipt, index) =>
      receipt.index === index &&
      receipt.cardinality?.global === index + 1 &&
      receipt.endedMonotonicNs !== undefined &&
      BigInt(receipt.endedMonotonicNs) >= BigInt(receipt.startedMonotonicNs) &&
      Date.parse(receipt.endedAt) >= Date.parse(receipt.startedAt)
  );
}

function commandOutputsExact(receipts) {
  return receipts.every((receipt) =>
    ['stdout', 'stderr'].every((stream) => {
      const output = receipt[stream];
      if (
        !isPlainRecord(output) ||
        typeof output.base64 !== 'string' ||
        typeof output.sha256 !== 'string' ||
        !SHA256.test(output.sha256)
      ) {
        return false;
      }
      const bytes = Buffer.from(output.base64, 'base64');
      return (
        bytes.toString('base64') === output.base64 &&
        bytes.byteLength === output.byteLength &&
        sha256(bytes) === output.sha256 &&
        (output.text === null ||
          (output.encoding === 'utf8' &&
            Buffer.from(output.text, 'utf8').equals(bytes) &&
            output.lineCount === lineCardinality(output.text)))
      );
    })
  );
}

function sortedUniqueIndexes(value) {
  return (
    Array.isArray(value) &&
    value.every((index) => Number.isSafeInteger(index) && index >= 0) &&
    value.every((index, position) => position === 0 || value[position - 1] < index)
  );
}

function receiptWithinFrame(receipt, frame) {
  try {
    return (
      Date.parse(receipt.startedAt) >= Date.parse(frame.startedAt) &&
      Date.parse(receipt.endedAt) <= Date.parse(frame.endedAt) &&
      BigInt(receipt.startedMonotonicNs) >= BigInt(frame.startedMonotonicNs) &&
      BigInt(receipt.endedMonotonicNs) <= BigInt(frame.endedMonotonicNs)
    );
  } catch {
    return false;
  }
}

function cutoffWithinFrame(frame) {
  if (
    !exactKeys(frame.observationCutoff, ['at', 'monotonicNs']) ||
    typeof frame.observationCutoff.monotonicNs !== 'string' ||
    !DECIMAL.test(frame.observationCutoff.monotonicNs)
  ) {
    return false;
  }
  try {
    const cutoffAt = rfc3339EpochNs(frame.observationCutoff.at, 'observation cutoff');
    const cutoffMonotonic = BigInt(frame.observationCutoff.monotonicNs);
    return (
      cutoffAt >= rfc3339EpochNs(frame.startedAt, 'frame startedAt') &&
      cutoffAt <= rfc3339EpochNs(frame.endedAt, 'frame endedAt') &&
      cutoffMonotonic >= BigInt(frame.startedMonotonicNs) &&
      cutoffMonotonic <= BigInt(frame.endedMonotonicNs)
    );
  } catch {
    return false;
  }
}

function receiptEndsAtOrBeforeCutoff(receipt, cutoff) {
  try {
    return (
      rfc3339EpochNs(receipt.endedAt, 'receipt endedAt') <=
        rfc3339EpochNs(cutoff.at, 'observation cutoff') &&
      BigInt(receipt.endedMonotonicNs) <= BigInt(cutoff.monotonicNs)
    );
  } catch {
    return false;
  }
}

function receiptStartsAtOrAfterCutoff(receipt, cutoff) {
  try {
    return (
      rfc3339EpochNs(receipt.startedAt, 'receipt startedAt') >=
        rfc3339EpochNs(cutoff.at, 'observation cutoff') &&
      BigInt(receipt.startedMonotonicNs) >= BigInt(cutoff.monotonicNs)
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
      frame.docker?.targetState !== 'running' &&
      frame.docker?.logWindow?.until === null &&
      cutoff.at === commands[0].endedAt &&
      cutoff.monotonicNs === commands[0].endedMonotonicNs &&
      reads.every((receipt) => receiptEndsAtOrBeforeCutoff(receipt, cutoff))
    );
  }
  if (
    JSON.stringify(kinds) !== JSON.stringify(['dockerPs', 'dockerInspect', 'dockerLogs']) ||
    frame.docker?.targetState !== 'running'
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
  const observedContainerFrames = frames.filter(
    (frame) => frame?.docker?.targetState === 'running'
  ).length;
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
  const exact =
    frameCount === 2 &&
    allowedProcessCounts.git === 3 &&
    allowedProcessCounts.lsusb === 1 &&
    allowedProcessCounts.dockerVersion === 1 &&
    allowedProcessCounts.dockerPs === frameCount &&
    allowedProcessCounts.dockerInspect === observedContainerFrames &&
    allowedProcessCounts.dockerLogs === observedContainerFrames &&
    commandCount === Object.values(allowedProcessCounts).reduce((sum, count) => sum + count, 0) &&
    command.rejectedAttempts.length === 0 &&
    filesystem.rejectedAttempts.length === 0 &&
    receiptSequenceExact(command.receipts) &&
    command.receipts.every(
      (receipt) => receipt.exitCode === 0 && receipt.signal === null && receipt.errorCode === null
    ) &&
    receiptSequenceExact(filesystem.receipts) &&
    commandOutputsExact(command.receipts) &&
    filesystem.receipts.every(filesystemReceiptResultExact) &&
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
    mode: 'live-readonly-capability-bounded',
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
    prohibitedCounts: { ...PROHIBITED_CAPABILITIES },
  };
}

function recordFrameError(errors, stage, error) {
  errors.push({
    stage,
    code: errorCode(error),
    receiptIndex: Number.isSafeInteger(error?.receipt?.index) ? error.receipt.index : null,
  });
}

function readText(filesystem, targetPath) {
  const value = filesystem.readFileSync(targetPath);
  return exactUtf8(value, targetPath).text.trim();
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
    const hostname = readText(filesystem, '/proc/sys/kernel/hostname');
    host.hostname = requiredString(hostname, 'hostname');
  } catch (error) {
    recordFrameError(errors, 'host-hostname', error);
  }
  return host;
}

function targetDeviceObservation(filesystem, lsusbAdmission, target, errors) {
  let inventory = [];
  try {
    inventory = inventoryHostHidraw({ filesystem });
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
    (entry) => entry.vendorId === target.vendorId && entry.productId === target.productId
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

  const usbEpochs = exactEntries.map((entry) => {
    const ancestor = entry.usbAncestor;
    let usbDev = null;
    try {
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

  return {
    complete:
      decorated.every((entry) => entry.errors.length === 0) &&
      ((correlatedEpochs.length === 0 && lsusbMatches.length === 0) ||
        (correlatedEpochs.length === 1 &&
          lsusbMatches.length === 1 &&
          correlatedEpochs[0].lsusbMatched === true)),
    present: correlatedEpochs.length > 0,
    target: { ...target },
    lsusbMatches,
    usbEpochs: correlatedEpochs,
    hidrawEntries: decorated,
  };
}

export function parseDeviceNumber(value) {
  const text = requiredString(value, 'device number').trim();
  const match = /^([0-9]+):([0-9]+)$/u.exec(text);
  if (match === null) throw new Error('device number must be major:minor');
  const major = normalizeDecimal(BigInt(match[1]).toString(), 'device major');
  const minor = normalizeDecimal(BigInt(match[2]).toString(), 'device minor');
  return `${major}:${minor}`;
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

function observeProcesses(filesystem, hostPid, targetMajor, errors) {
  const procRoot = `/proc/${hostPid}/root/proc`;
  let before;
  try {
    before = processIds(filesystem, procRoot);
  } catch (error) {
    recordFrameError(errors, 'process-list-before', error);
    return {
      procRoot,
      stable: false,
      pid1: null,
      all: [],
      surfaceWorkers: [],
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
    recordFrameError(errors, 'process-table-drift', {
      code: 'PROCESS_TABLE_DRIFT',
    });
  }
  const byPid = new Map(observed.map((entry) => [entry.pid, entry]));
  for (const entry of observed) {
    if (entry.ppid === 0) continue;
    const parent = byPid.get(entry.ppid);
    if (parent === undefined) {
      recordFrameError(errors, `process-parent:${entry.pid}`, {
        code: 'PARENT_NOT_OBSERVED',
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
        recordFrameError(errors, `worker-target-major:${entry.pid}`, {
          code: 'TARGET_MAJOR_UNAVAILABLE',
        });
        return {
          ...entry,
          fileDescriptors: [],
          descriptorTableStable: false,
        };
      }
      const descriptors = observeDescriptors(filesystem, procRoot, entry.pid, targetMajor, errors);
      if (!descriptors.stable) {
        recordFrameError(errors, `worker-fd-drift:${entry.pid}`, {
          code: 'DESCRIPTOR_TABLE_DRIFT',
        });
      }
      return {
        ...entry,
        fileDescriptors: descriptors.entries,
        descriptorTableStable: descriptors.stable,
      };
    });

  if (!byPid.has(1)) {
    recordFrameError(errors, 'process-pid1', {
      code: 'PID1_NOT_OBSERVED',
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
  try {
    lifecycle.hostCgroup = parseCgroup(
      filesystem.readFileSync(`/proc/${inspected.hostPid}/cgroup`)
    );
  } catch (error) {
    recordFrameError(errors, 'host-pid-cgroup', error);
  }
  return lifecycle;
}

function observerTarget(value) {
  if (!isPlainRecord(value)) throw new TypeError('target must be an object');
  return {
    serial: requiredString(value.serial, 'target serial'),
    vendorId: normalizeUsbId(value.vendorId, 'target vendor id'),
    productId: normalizeUsbId(value.productId, 'target product id'),
    containerId: exactContainerId(value.containerId, 'target container id'),
    deviceMajor:
      Number.isSafeInteger(value.deviceMajor) && value.deviceMajor > 0
        ? value.deviceMajor
        : (() => {
            throw new TypeError('target deviceMajor must be a positive safe integer');
          })(),
    deviceMinor:
      Number.isSafeInteger(value.deviceMinor) && value.deviceMinor >= 0
        ? value.deviceMinor
        : (() => {
            throw new TypeError('target deviceMinor must be a non-negative safe integer');
          })(),
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
    JSON.stringify(parseDockerVersion(receiptOutputBytes(dockerReceipt, 'stdout'))) !==
      JSON.stringify(dockerAdmission.version)
  ) {
    throw new ObserverPolicyError('DOCKER_ADMISSION_UNBOUND');
  }
}

export async function captureObservationFrame({
  frameId,
  commandAuditor,
  filesystemAuditor,
  lsusbAdmission,
  dockerAdmission,
  target: targetInput,
  logSince,
  wallNow,
  monotonicNowNs,
} = {}) {
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
  const target = observerTarget(targetInput);
  const since = exactRfc3339(logSince, 'log since');
  const errors = [];
  const commandStart = commandAuditor.snapshot().receipts.length;
  const filesystemStart = filesystemAuditor.snapshot().receipts.length;
  const startedAt = wallTime(wallNow, 'frame startedAt');
  const startedMonotonic = monotonicTime(monotonicNowNs, 'frame started monotonic time');
  const filesystem = filesystemAuditor.filesystem;

  const host = observeHost(filesystem, errors);
  const device = targetDeviceObservation(filesystem, lsusbAdmission, target, errors);

  let ps = [];
  let psExact = false;
  let psReceipt = null;
  try {
    const psObserved = await commandAuditor.invoke('docker', [
      ...DOCKER_HOST_PREFIX,
      'ps',
      '--all',
      '--no-trunc',
      '--filter',
      `id=${target.containerId}`,
      '--format',
      DOCKER_PS_FORMAT,
    ]);
    psReceipt = psObserved.receipt;
    if (psObserved.receipt.exitCode !== 0) {
      throw new ObserverCommandError('DOCKER_PS_FAILED', psObserved.receipt);
    }
    const parsedPs = parseDockerPs(psObserved.stdout);
    if (parsedPs.length > 1 || parsedPs.some((entry) => entry.containerId !== target.containerId)) {
      throw new Error('filtered docker ps returned an unrelated or duplicate container');
    }
    ps = parsedPs;
    psExact = true;
  } catch (error) {
    if (isPlainRecord(error?.receipt) && error.receipt.kind === 'dockerPs') {
      psReceipt = error.receipt;
    }
    recordFrameError(errors, 'docker-ps', error);
  }

  const targetPsEntry = ps.find((entry) => entry.containerId === target.containerId) ?? null;
  const targetPresent = psExact && targetPsEntry !== null;
  const exactAbsence = psExact && targetPresent === false;
  const targetRunning = targetPresent && targetPsEntry.state?.toLowerCase() === 'running';
  const exactNonRunning =
    targetPresent &&
    typeof targetPsEntry.state === 'string' &&
    targetPsEntry.state !== '' &&
    targetRunning === false;
  if (targetPresent && !targetRunning && !exactNonRunning) {
    errors.push({
      stage: 'docker-ps-state',
      code: 'CONTAINER_STATE_INCOMPLETE',
      receiptIndex: null,
    });
  }
  let inspected = null;
  if (targetRunning) {
    try {
      const inspectObserved = await commandAuditor.invoke('docker', [
        ...DOCKER_HOST_PREFIX,
        'inspect',
        '--format',
        DOCKER_INSPECT_FORMAT,
        target.containerId,
      ]);
      if (inspectObserved.receipt.exitCode !== 0) {
        throw new ObserverCommandError('DOCKER_INSPECT_FAILED', inspectObserved.receipt);
      }
      inspected = parseDockerInspect(inspectObserved.stdout);
      if (inspected.containerId !== target.containerId) {
        throw new Error('docker inspect returned a different container');
      }
      if (inspected.running !== true || inspected.status.toLowerCase() !== 'running') {
        throw new Error('docker inspect contradicts the running docker ps state');
      }
    } catch (error) {
      recordFrameError(errors, 'docker-inspect', error);
    }
  }

  const processes =
    inspected === null
      ? {
          procRoot: null,
          stable: false,
          pid1: null,
          all: [],
          surfaceWorkers: [],
        }
      : observeProcesses(filesystem, inspected.hostPid, target.deviceMajor, errors);
  const lifecycle =
    inspected === null ? null : lifecycleFromInspect(filesystem, inspected, processes, errors);

  let observationCutoff =
    psReceipt === null
      ? null
      : {
          at: psReceipt.endedAt,
          monotonicNs: psReceipt.endedMonotonicNs,
        };
  let logsUntil = null;
  let markers = {
    entries: [],
    openingCount: exactAbsence || exactNonRunning ? 0 : null,
    readyCount: exactAbsence || exactNonRunning ? 0 : null,
    relevantLinesSha256: exactAbsence || exactNonRunning ? sha256(Buffer.alloc(0)) : null,
  };
  if (targetRunning) {
    const cutoffAt = wallTime(wallNow, 'observation cutoff');
    const cutoffMonotonic = monotonicTime(monotonicNowNs, 'observation cutoff monotonic time');
    observationCutoff = {
      at: cutoffAt,
      monotonicNs: cutoffMonotonic.toString(),
    };
    logsUntil = cutoffAt;
    try {
      const logsObserved = await commandAuditor.invoke('docker', [
        ...DOCKER_HOST_PREFIX,
        'logs',
        '--timestamps',
        '--since',
        since,
        '--until',
        logsUntil,
        target.containerId,
      ]);
      if (logsObserved.receipt.exitCode !== 0) {
        throw new ObserverCommandError('DOCKER_LOGS_FAILED', logsObserved.receipt);
      }
      markers = parseDockerLogs(logsObserved.stdout, logsObserved.stderr, target.serial);
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
    const cutoffAt = wallTime(wallNow, 'observation cutoff');
    const cutoffMonotonic = monotonicTime(monotonicNowNs, 'observation cutoff monotonic time');
    observationCutoff = {
      at: cutoffAt,
      monotonicNs: cutoffMonotonic.toString(),
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
  const complete =
    errors.length === 0 &&
    hardFilesystemFailure === false &&
    device.complete === true &&
    psExact === true &&
    (exactAbsence ||
      exactNonRunning ||
      (inspected !== null &&
        processes.stable === true &&
        processes.pid1 !== null &&
        markers.openingCount !== null &&
        markers.readyCount !== null));

  return {
    schemaVersion: 'overlaykit-h044-observation-frame/v1',
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
      ps,
      targetState: targetPsEntry?.state?.toLowerCase() ?? null,
      lifecycle,
      logWindow: {
        since,
        until: logsUntil,
      },
      markers,
    },
    absence: {
      historicalContainerAbsent: exactAbsence,
      exact: psExact,
    },
    nonEligible: {
      containerNotRunning: exactNonRunning,
      exact: exactNonRunning,
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
