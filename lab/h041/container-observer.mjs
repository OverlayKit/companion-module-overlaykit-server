#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync, readlinkSync, statSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const PROC_ROOT = '/proc';
const SURFACE_THREAD_BASENAME = 'SurfaceThread.js';
const MAX_PROCESS_SNAPSHOT_ATTEMPTS = 4;

function requiredString(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\u0000')) {
    throw new TypeError(`${label} must be a non-empty NUL-free string`);
  }
  return value;
}

export function parseUnsignedInteger(value, label, { positive = false } = {}) {
  const text = requiredString(value, label);
  if (!/^[0-9]+$/u.test(text)) {
    throw new TypeError(`${label} must be an unsigned decimal integer`);
  }
  const parsed = Number(text);
  if (!Number.isSafeInteger(parsed) || (positive ? parsed <= 0 : parsed < 0)) {
    throw new RangeError(`${label} is outside the supported integer range`);
  }
  return parsed;
}

function exactHidrawPath(value, root, label) {
  const text = requiredString(value, label);
  const match = new RegExp(`^${root.replaceAll('/', '\\/')}\\/(hidraw[0-9]+)$`, 'u').exec(text);
  if (!match) throw new TypeError(`${label} must match ${root}/hidrawN`);
  return { path: text, basename: match[1] };
}

export function parseObservationEnvironment(environment) {
  if (environment === null || typeof environment !== 'object') {
    throw new TypeError('environment must be an object');
  }
  const dynamic = exactHidrawPath(environment.H041_DYNAMIC_PATH, '/host-dev', 'H041_DYNAMIC_PATH');
  const compat = exactHidrawPath(environment.H041_COMPAT_PATH, '/dev', 'H041_COMPAT_PATH');
  if (dynamic.basename !== compat.basename) {
    throw new Error('H041_DYNAMIC_PATH and H041_COMPAT_PATH must name the same hidraw index');
  }
  return {
    dynamicPath: dynamic.path,
    compatPath: compat.path,
    target: {
      major: parseUnsignedInteger(environment.H041_DEVICE_MAJOR, 'H041_DEVICE_MAJOR', {
        positive: true,
      }),
      minor: parseUnsignedInteger(environment.H041_DEVICE_MINOR, 'H041_DEVICE_MINOR'),
    },
  };
}

export function parseCompatibilityLinkTarget(value) {
  return exactHidrawPath(value, '/host-dev', 'H041 compatibility link target').path;
}

export function parseProcStat(value) {
  const text = requiredString(value, 'proc stat').trim();
  if (text.includes('\n') || text.includes('\r')) {
    throw new Error('proc stat must contain exactly one record');
  }
  const match = /^([1-9][0-9]*)\s+\((.*)\)\s+([A-Za-z])\s+(.+)$/u.exec(text);
  if (!match) throw new Error('proc stat record is malformed');
  const fieldsAfterState = match[4].trim().split(/\s+/u);
  if (fieldsAfterState.length < 19) {
    throw new Error('proc stat lacks field 22 start time');
  }
  const pid = parseUnsignedInteger(match[1], 'proc stat pid', { positive: true });
  const ppid = parseUnsignedInteger(fieldsAfterState[0], 'proc stat ppid');
  const startTicks = parseUnsignedInteger(fieldsAfterState[18], 'proc stat start time', {
    positive: true,
  });
  return {
    pid,
    ppid,
    startTicks,
    command: match[2],
    state: match[3],
  };
}

function parseStatusNumbers(properties, key, minimumLength) {
  const raw = properties.get(key);
  if (raw === undefined) throw new Error(`proc status lacks ${key}`);
  const values = raw
    .split(/\s+/u)
    .filter(Boolean)
    .map((value) => parseUnsignedInteger(value, `proc status ${key}`));
  if (values.length < minimumLength) {
    throw new Error(`proc status ${key} is incomplete`);
  }
  return values;
}

export function parseProcStatus(value) {
  const properties = new Map();
  for (const line of requiredString(value, 'proc status').split(/\r?\n/u)) {
    const separator = line.indexOf(':');
    if (separator === -1) continue;
    properties.set(line.slice(0, separator), line.slice(separator + 1).trim());
  }
  const uids = parseStatusNumbers(properties, 'Uid', 4);
  const gids = parseStatusNumbers(properties, 'Gid', 4);
  const groups = parseStatusNumbers(properties, 'Groups', 0);
  return {
    uid: uids[0],
    gid: gids[0],
    groups,
  };
}

export function parseCmdline(value) {
  const text = Buffer.isBuffer(value)
    ? value.toString('utf8')
    : requiredString(value, 'proc cmdline');
  if (text.length === 0) return [];
  const withoutTerminator = text.endsWith('\u0000') ? text.slice(0, -1) : text;
  return withoutTerminator.split('\u0000');
}

export function parseCgroup(value) {
  const lines = requiredString(value, 'proc cgroup')
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length === 0 || lines.some((line) => !/^[0-9]+:[^:]*:.+$/u.test(line))) {
    throw new Error('proc cgroup record is malformed');
  }
  return lines.join('\n');
}

export function parseNamespace(value, type) {
  const namespace = requiredString(value, `${type} namespace`);
  if (namespace !== `${type}:${namespace.slice(type.length + 1)}`) {
    throw new Error(`${type} namespace has an unexpected prefix`);
  }
  if (!new RegExp(`^${type.replaceAll('/', '\\/')}:\\[[0-9]+\\]$`, 'u').test(namespace)) {
    throw new Error(`${type} namespace record is malformed`);
  }
  return namespace;
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
  const result = Number(value);
  if (!Number.isSafeInteger(result) || result < 0) {
    throw new RangeError(`${label} is outside the supported integer range`);
  }
  return result;
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
  const mode = safeBigInt(stats.mode, 'stat mode') & 0o7777n;
  return {
    stDev: safeBigInt(stats.dev, 'stat device').toString(),
    inode: safeBigInt(stats.ino, 'stat inode').toString(),
    ctimeNs: safeBigInt(stats.ctimeNs, 'stat ctimeNs').toString(),
    mode: mode.toString(8).padStart(4, '0'),
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

function pathMetadataReceipt(targetPath, operation) {
  try {
    const stats =
      operation === 'lstat'
        ? lstatSync(targetPath, { bigint: true })
        : statSync(targetPath, { bigint: true });
    return { kind: 'value', path: targetPath, value: statIdentity(stats) };
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return { kind: 'missing', path: targetPath, code: 'ENOENT' };
    }
    throw error;
  }
}

export function isSurfaceThreadCmdline(cmdline) {
  return (
    Array.isArray(cmdline) &&
    cmdline.some(
      (argument) =>
        typeof argument === 'string' && path.posix.basename(argument) === SURFACE_THREAD_BASENAME
    )
  );
}

export function descriptorIsInScope(target, identity, targetMajor) {
  if (
    typeof target !== 'string' ||
    identity === null ||
    typeof identity !== 'object' ||
    identity.isCharacterDevice !== true ||
    !Number.isSafeInteger(targetMajor) ||
    targetMajor <= 0
  ) {
    return false;
  }
  const hidrawTarget = /^\/(?:dev|host-dev)\/hidraw[0-9]+(?: \(deleted\))?$/u.test(target);
  return hidrawTarget || identity.major === targetMajor;
}

function processIds() {
  return readdirSync(PROC_ROOT)
    .filter((entry) => /^[1-9][0-9]*$/u.test(entry))
    .map(Number)
    .sort((left, right) => left - right);
}

function processIdentity(pid) {
  const procDirectory = `${PROC_ROOT}/${pid}`;
  const stat = parseProcStat(readFileSync(`${procDirectory}/stat`, 'utf8'));
  if (stat.pid !== pid) throw new Error(`proc stat PID mismatch for ${pid}`);
  const status = parseProcStatus(readFileSync(`${procDirectory}/status`, 'utf8'));
  return {
    pid: stat.pid,
    startTicks: stat.startTicks,
    ppid: stat.ppid,
    parentStartTicks: null,
    uid: status.uid,
    gid: status.gid,
    groups: status.groups,
    command: stat.command,
    cmdline: parseCmdline(readFileSync(`${procDirectory}/cmdline`)),
    cgroup: parseCgroup(readFileSync(`${procDirectory}/cgroup`, 'utf8')),
    pidNamespace: parseNamespace(readlinkSync(`${procDirectory}/ns/pid`), 'pid'),
    mountNamespace: parseNamespace(readlinkSync(`${procDirectory}/ns/mnt`), 'mnt'),
  };
}

function samePidList(left, right) {
  return left.length === right.length && left.every((pid, index) => pid === right[index]);
}

function stableProcessSnapshot() {
  for (let attempt = 0; attempt < MAX_PROCESS_SNAPSHOT_ATTEMPTS; attempt += 1) {
    const before = processIds();
    const observed = [];
    let raced = false;
    for (const pid of before) {
      try {
        observed.push(processIdentity(pid));
      } catch (error) {
        if (error?.code === 'ENOENT' || error?.code === 'ESRCH') {
          raced = true;
          break;
        }
        throw error;
      }
    }
    const after = processIds();
    if (raced || !samePidList(before, after)) continue;
    const byPid = new Map(observed.map((entry) => [entry.pid, entry]));
    for (const entry of observed) {
      if (entry.ppid === 0) continue;
      const parent = byPid.get(entry.ppid);
      if (!parent) {
        raced = true;
        break;
      }
      entry.parentStartTicks = parent.startTicks;
    }
    if (!raced) return observed;
  }
  throw new Error('process table did not remain stable for one metadata snapshot');
}

function descriptorReceipt(workerPid, descriptor, targetMajor) {
  const fdPath = `${PROC_ROOT}/${workerPid}/fd/${descriptor}`;
  const target = readlinkSync(fdPath);
  const identity = statIdentity(statSync(fdPath, { bigint: true }));
  if (!descriptorIsInScope(target, identity, targetMajor)) return null;
  const fdinfo = readFileSync(`${PROC_ROOT}/${workerPid}/fdinfo/${descriptor}`);
  return {
    descriptor,
    target,
    stat: identity,
    fdinfoSha256: createHash('sha256').update(fdinfo).digest('hex'),
  };
}

function workerDescriptors(workerPid, targetMajor) {
  const descriptors = readdirSync(`${PROC_ROOT}/${workerPid}/fd`)
    .filter((entry) => /^[0-9]+$/u.test(entry))
    .sort((left, right) => Number(left) - Number(right));
  const observed = [];
  for (const descriptor of descriptors) {
    try {
      const receipt = descriptorReceipt(workerPid, descriptor, targetMajor);
      if (receipt !== null) observed.push(receipt);
    } catch (error) {
      if (error?.code === 'ENOENT' || error?.code === 'EBADF') continue;
      throw error;
    }
  }
  return observed;
}

export function observeContainer(environment = process.env) {
  const input = parseObservationEnvironment(environment);
  const processes = stableProcessSnapshot();
  const pid1 = processes.find((entry) => entry.pid === 1);
  if (!pid1) throw new Error('container observation lacks PID 1');
  const workers = processes.filter((entry) => isSurfaceThreadCmdline(entry.cmdline));
  const surfaceWorkers = workers.map((worker) => {
    if (worker.ppid <= 0 || !Number.isSafeInteger(worker.parentStartTicks)) {
      throw new Error(`SurfaceThread worker ${worker.pid} lacks a complete parent identity`);
    }
    return {
      ...worker,
      fileDescriptors: workerDescriptors(worker.pid, input.target.major),
    };
  });
  return {
    schemaVersion: 'overlaykit-h041-container-observation/v1',
    capturedAt: new Date().toISOString(),
    monotonicNs: process.hrtime.bigint().toString(),
    metadataOnly: true,
    paths: {
      dynamic: {
        path: input.dynamicPath,
        lstat: pathMetadataReceipt(input.dynamicPath, 'lstat'),
        stat: pathMetadataReceipt(input.dynamicPath, 'stat'),
      },
      compat: {
        path: input.compatPath,
        lstat: pathMetadataReceipt(input.compatPath, 'lstat'),
        stat: pathMetadataReceipt(input.compatPath, 'stat'),
        linkTarget: parseCompatibilityLinkTarget(readlinkSync(input.compatPath)),
      },
    },
    target: input.target,
    pid1,
    processes,
    surfaceWorkers,
  };
}

function isMainModule() {
  return (
    typeof process.argv[1] === 'string' &&
    path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
  );
}

if (isMainModule()) {
  try {
    process.stdout.write(`${JSON.stringify(observeContainer())}\n`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`H-041 container observation failed: ${message}\n`);
    process.exitCode = 1;
  }
}
