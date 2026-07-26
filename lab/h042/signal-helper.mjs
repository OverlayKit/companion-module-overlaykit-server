#!/usr/bin/env node

import { readFileSync, readdirSync, readlinkSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const EXACT_CMDLINE = [
  '/app/node-runtimes/node22/bin/node',
  '--enable-source-maps',
  '/app/SurfaceThread.js',
];

function requiredPositiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return value;
}

export function parseProcStat(text) {
  const match = /^([1-9][0-9]*)\s+\((.*)\)\s+[A-Za-z]\s+(.+)$/u.exec(text.trim());
  if (!match) throw new Error('proc stat is malformed');
  const fields = match[3].trim().split(/\s+/u);
  if (fields.length < 19) throw new Error('proc stat lacks start ticks');
  return {
    pid: Number(match[1]),
    ppid: Number(fields[0]),
    startTicks: Number(fields[18]),
  };
}

export function parseStatus(text) {
  const properties = Object.fromEntries(
    text.split(/\r?\n/u).flatMap((line) => {
      const separator = line.indexOf(':');
      return separator === -1 ? [] : [[line.slice(0, separator), line.slice(separator + 1).trim()]];
    })
  );
  const numbers = (key) => (properties[key] ?? '').split(/\s+/u).filter(Boolean).map(Number);
  return {
    uid: numbers('Uid')[0] ?? null,
    gid: numbers('Gid')[0] ?? null,
    groups: numbers('Groups'),
  };
}

function parseCmdline(bytes) {
  const text = bytes.toString('utf8');
  const withoutTerminator = text.endsWith('\u0000') ? text.slice(0, -1) : text;
  return withoutTerminator.length === 0 ? [] : withoutTerminator.split('\u0000');
}

function sameArray(left, right) {
  return (
    Array.isArray(left) &&
    Array.isArray(right) &&
    left.length === right.length &&
    left.every((entry, index) => entry === right[index])
  );
}

function observeTarget(pid) {
  const directory = `/proc/${pid}`;
  const initialStat = parseProcStat(readFileSync(`${directory}/stat`, 'utf8'));
  const initialParent = parseProcStat(readFileSync(`/proc/${initialStat.ppid}/stat`, 'utf8'));
  const status = parseStatus(readFileSync(`${directory}/status`, 'utf8'));
  const cmdline = parseCmdline(readFileSync(`${directory}/cmdline`));
  const cgroup = readFileSync(`${directory}/cgroup`, 'utf8').trim();
  const pidNamespace = readlinkSync(`${directory}/ns/pid`);
  const mountNamespace = readlinkSync(`${directory}/ns/mnt`);
  const descriptorNames = readdirSync(`${directory}/fd`)
    .filter((descriptor) => /^[0-9]+$/u.test(descriptor))
    .sort((left, right) => Number(left) - Number(right));
  const descriptorTargets = descriptorNames.map((descriptor) => ({
    descriptor,
    target: readlinkSync(`${directory}/fd/${descriptor}`),
  }));
  const descriptorNamesAfter = readdirSync(`${directory}/fd`)
    .filter((descriptor) => /^[0-9]+$/u.test(descriptor))
    .sort((left, right) => Number(left) - Number(right));
  const descriptorTargetsAfter = descriptorNamesAfter.map((descriptor) => ({
    descriptor,
    target: readlinkSync(`${directory}/fd/${descriptor}`),
  }));
  if (
    !sameArray(descriptorNames, descriptorNamesAfter) ||
    JSON.stringify(descriptorTargets) !== JSON.stringify(descriptorTargetsAfter)
  ) {
    throw new Error('SurfaceThread descriptor table changed during signal revalidation');
  }
  const targetHidrawDescriptors = descriptorTargets.filter(({ target }) =>
    /^\/(?:dev|host-dev)\/hidraw[0-9]+(?: \(deleted\))?$/u.test(target)
  );
  const finalStat = parseProcStat(readFileSync(`${directory}/stat`, 'utf8'));
  const finalParent = parseProcStat(readFileSync(`/proc/${finalStat.ppid}/stat`, 'utf8'));
  if (
    initialStat.pid !== finalStat.pid ||
    initialStat.startTicks !== finalStat.startTicks ||
    initialStat.ppid !== finalStat.ppid ||
    initialParent.pid !== finalParent.pid ||
    initialParent.startTicks !== finalParent.startTicks
  ) {
    throw new Error('SurfaceThread or parent tuple changed during signal revalidation');
  }
  return {
    pid: finalStat.pid,
    startTicks: finalStat.startTicks,
    ppid: finalStat.ppid,
    parentStartTicks: finalParent.startTicks,
    uid: status.uid,
    gid: status.gid,
    groups: status.groups,
    cmdline,
    cgroup,
    pidNamespace,
    mountNamespace,
    targetHidrawDescriptors,
    revalidation: {
      initial: {
        pid: initialStat.pid,
        startTicks: initialStat.startTicks,
        ppid: initialStat.ppid,
        parentStartTicks: initialParent.startTicks,
      },
      final: {
        pid: finalStat.pid,
        startTicks: finalStat.startTicks,
        ppid: finalStat.ppid,
        parentStartTicks: finalParent.startTicks,
      },
    },
  };
}

export function parseExpectedTarget(environment) {
  const encoded = environment.H042_EXPECTED_TARGET;
  if (typeof encoded !== 'string' || encoded.length === 0) {
    throw new Error('H042_EXPECTED_TARGET is required');
  }
  let expected;
  try {
    expected = JSON.parse(encoded);
  } catch {
    throw new Error('H042_EXPECTED_TARGET is not valid JSON');
  }
  const keys = [
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
  ];
  if (
    expected === null ||
    typeof expected !== 'object' ||
    Array.isArray(expected) ||
    Object.keys(expected).length !== keys.length ||
    !keys.every((key) => Object.hasOwn(expected, key))
  ) {
    throw new Error('H042_EXPECTED_TARGET has an inexact envelope');
  }
  requiredPositiveInteger(expected.pid, 'target pid');
  requiredPositiveInteger(expected.startTicks, 'target start ticks');
  const deviceGid = Number(environment.H042_DEVICE_GID);
  if (
    expected.pid === 1 ||
    expected.ppid !== 1 ||
    !sameArray(expected.cmdline, EXACT_CMDLINE) ||
    !Number.isSafeInteger(deviceGid) ||
    deviceGid <= 0 ||
    !sameArray(
      [...expected.groups].sort((left, right) => left - right),
      [1000, deviceGid]
    ) ||
    expected.uid !== 1000 ||
    expected.gid !== 1000
  ) {
    throw new Error('H042_EXPECTED_TARGET escapes the exact SurfaceThread boundary');
  }
  return expected;
}

export function sameTarget(expected, observed) {
  return Object.keys(expected).every((key) => {
    if (key === 'groups' || key === 'cmdline') return sameArray(expected[key], observed[key]);
    return expected[key] === observed[key];
  });
}

export function executeSignal({
  environment = process.env,
  observe = observeTarget,
  kill = process.kill.bind(process),
  now = () => new Date().toISOString(),
  monotonic = () => process.hrtime.bigint().toString(),
} = {}) {
  const startedAt = now();
  const startedMonotonicNs = monotonic();
  const expected = parseExpectedTarget(environment);
  const observed = observe(expected.pid);
  if (!sameTarget(expected, observed)) {
    throw new Error('SurfaceThread tuple changed before SIGTERM');
  }
  if (
    !Array.isArray(observed.targetHidrawDescriptors) ||
    observed.targetHidrawDescriptors.length !== 0
  ) {
    throw new Error('SurfaceThread regained a hidraw descriptor before SIGTERM');
  }
  let processKillCallCount = 0;
  processKillCallCount += 1;
  kill(expected.pid, 'SIGTERM');
  const receivedAt = now();
  const receivedMonotonicNs = monotonic();
  return {
    schemaVersion: 'overlaykit-h042-signal-receipt/v1',
    signal: 'SIGTERM',
    processKillCallCount,
    startedAt,
    startedMonotonicNs,
    receivedAt,
    receivedMonotonicNs,
    expected,
    observed,
  };
}

const modulePath = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === modulePath) {
  try {
    process.stdout.write(`${JSON.stringify(executeSignal())}\n`);
  } catch (error) {
    process.stderr.write(
      `H-042 signal helper refused the intervention: ${error instanceof Error ? error.message : String(error)}\n`
    );
    process.exitCode = 1;
  }
}
