#!/usr/bin/env node

// Independent H-042 verifier.  Deliberately does not import H-042 producer
// libraries: the verifier reconstructs the claim from archived raw evidence.

import { createHash } from 'node:crypto';
import { lstat, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { verifyDynamicReacquisitionRun } from '../h041/verify.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const H041_RUN_PATH = 'artifacts/h041/h041-2026-07-26T00-56-42-118Z-0423725f/run.json';
const H041_FILE_SHA256 = 'b1bc36cb4c480ca0e34ae9a5810d9ea890e1d44242b2525789da443fa720acd4';
const H041_EVIDENCE_SHA256 = 'c430a034e684dd3d492e1a750aa8ff0fdd6fa5d53f3772ee63b5876040f1392a';
const H041_VERIFICATION_SHA256 = '7217b3d80f80c8b509388a941c9a6e3752b5036eb0a545cfeafb0a4ffb599426';
const EXPECTED_PREDECESSOR_EVIDENCE = Object.freeze({
  h037: '22d8f1d440a521af2ec8dd75cbfa68db09b7140c85f90bc48310aa78d27d6e9c',
  h039: 'e78ed04dd10469e863b33e4fa497ddc745a20574fb18095c2bde7cf3fdb594ce',
  h040: '04b3b9aedeb51e1bd5d6c1bd4e68e9d284951d2b21276aea3f5a180f0fe2a108',
});
const OFFICIAL_IMAGE =
  'ghcr.io/bitfocus/companion/companion:v4.3.3@sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e';
const OFFICIAL_REPO_DIGEST =
  'ghcr.io/bitfocus/companion/companion@sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e';
const EXPECTED_IMAGE_ID = 'sha256:e7d24e3b0e32b0edb799f262493536cb1a47d307af4e6527551427e09266bf10';
const EXPECTED_IMAGE_REVISION = '06a7406709d6a858039333a8988047296ef3aa4a';
const SIGNAL_HELPER_COMMAND = '/app/node-runtimes/main/bin/node /h042-signal-helper.mjs';
const OBSERVER_COMMAND = '/app/node-runtimes/main/bin/node /h041-container-observer.mjs';
const SURFACE_THREAD_CMDLINE = Object.freeze([
  '/app/node-runtimes/node22/bin/node',
  '--enable-source-maps',
  '/app/SurfaceThread.js',
]);
const SECOND_NS = 1_000_000_000n;
const MILLISECOND_NS = 1_000_000n;
const PRE_SIGNAL_NS = 30n * SECOND_NS;
const POST_SIGNAL_NS = 30n * SECOND_NS;

export const REQUIRED_SOURCE_PATHS = Object.freeze(
  [
    '.overlaykit/governance/changes/CHG-0012.json',
    '.overlaykit/governance/changes/CHG-0013.json',
    'lab/h034/lib/util.mjs',
    'lab/h035/inventory-lib.mjs',
    'lab/h037/acquisition-lib.mjs',
    'lab/h038/physical-lib.mjs',
    'lab/h039/host-observer.mjs',
    'lab/h039/reconnect-lib.mjs',
    'lab/h039/schemas/reconnect-run.schema.json',
    'lab/h039/verify.mjs',
    'lab/h040/probe-lib.mjs',
    'lab/h040/schemas/docker-mapping-run.schema.json',
    'lab/h040/verify.mjs',
    'lab/h041/container-observer.mjs',
    'lab/h041/container-observer.test.mjs',
    'lab/h041/entrypoint.sh',
    'lab/h041/host-inventory.mjs',
    'lab/h041/host-inventory.test.mjs',
    'lab/h041/reacquisition-lib.mjs',
    'lab/h041/reacquisition-lib.test.mjs',
    'lab/h041/run.mjs',
    'lab/h041/schema.test.mjs',
    'lab/h041/schemas/dynamic-reacquisition-run.schema.json',
    'lab/h041/verify.mjs',
    'lab/h041/verify.test.mjs',
    'lab/h042/run.mjs',
    'lab/h042/run.test.mjs',
    'lab/h042/runtime-lib.mjs',
    'lab/h042/runtime-lib.test.mjs',
    'lab/h042/schema.test.mjs',
    'lab/h042/schemas/surface-worker-recycle-run.schema.json',
    'lab/h042/signal-helper.mjs',
    'lab/h042/signal-helper.test.mjs',
    'lab/h042/signal-lib.mjs',
    'lab/h042/signal-lib.test.mjs',
    'lab/h042/verify.mjs',
    'lab/h042/verify.test.mjs',
  ].sort()
);

export const PREDICATE_KEYS = Object.freeze([
  'complete',
  'permissionBoundaryExact',
  'hostEpochChanged',
  'dynamicViewTracksHost',
  'baselineAcquired',
  'preSignalWindowComplete',
  'preSignalNegative',
  'signalTargetUnique',
  'signalTargetRevalidated',
  'exactlyOneSigterm',
  'signalSucceeded',
  'invocationAuditExact',
  'topLevelLifecycleUnchanged',
  'oldWorkerExited',
  'replacementWorkerUnique',
  'singleReplacementGeneration',
  'replacementWorkerChanged',
  'postSignalObservationComplete',
  'postSignalDescriptorObserved',
  'postSignalOpeningObserved',
  'postSignalReadyObserved',
  'postSignalMarkersOrdered',
  'postSignalWithinDeadline',
  'deadlineBoundaryConsistent',
  'latePositiveObserved',
]);

const PRECONDITION_KEYS = Object.freeze(PREDICATE_KEYS.slice(0, 12));
const WORKER_IDENTITY_KEYS = Object.freeze([
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
const DEVICE_ACCESS_KEYS = Object.freeze([
  'mode',
  'uid',
  'gid',
  'rdev',
  'major',
  'minor',
  'rdevHex',
  'isCharacterDevice',
]);

export const INDEPENDENT_CLAIM_BOUNDARY = Object.freeze({
  proves: [
    'post-login behavior on the exact Fedora 43 host, official Companion 4.3.3 image, and physical MK.2 identity',
    'one new human-bounded USB enumeration epoch through the exact H-041 dynamic device view',
    'a complete thirty-second negative automatic-reacquisition control before fault injection',
    'one agent-issued SIGTERM delivered to one revalidated SurfaceThread process tuple',
    'bounded worker replacement and descriptor plus serial-specific marker observations under one unchanged container and PID 1, with exact dynamic inode and rdev continuity checked on every post-signal poll as the host-epoch proxy',
    'cleanup temporally separated from classification and release of the lab-owned container',
  ],
  excludes: [
    'physical button command delivery, OverlayKit configuration, rendered pixels, and operator perception',
    'production acceptance of a signal, supervisor, restart policy, device-directory bind, or device cgroup rule',
    'docker kill, docker restart, container recreation, rescan, reconfiguration, or more than one fault-injection signal',
    'pre-login behavior, reboot behavior, repeated recovery, multiple devices, long outages, or complete production recovery',
    'support beyond the exact tested host, image, principal, device, process, and timing identities',
  ],
});

function assertion(condition, message) {
  if (!condition) throw new Error(message);
}

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, keys) {
  if (!isPlainRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return (
    actual.length === expected.length && actual.every((entry, index) => entry === expected[index])
  );
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value === null || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, canonicalize(value[key])])
  );
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function sameCanonical(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function sha256Canonical(value) {
  return sha256(canonicalJson(value));
}

function validDateTime(value) {
  return (
    typeof value === 'string' &&
    /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$/u.test(value) &&
    rfc3339NanoToEpochNs(value) !== null
  );
}

export function rfc3339NanoToEpochNs(value) {
  if (typeof value !== 'string') return null;
  const match =
    /^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z$/u.exec(value);
  if (!match || Number(match[2]) > 59) return null;
  const wholeSeconds = `${match[1]}:${match[2]}`;
  const milliseconds = Date.parse(`${wholeSeconds}Z`);
  if (
    !Number.isFinite(milliseconds) ||
    new Date(milliseconds).toISOString().slice(0, 19) !== wholeSeconds
  ) {
    return null;
  }
  return BigInt(milliseconds) * MILLISECOND_NS + BigInt((match[3] ?? '').padEnd(9, '0') || '0');
}

function wallNs(value, label) {
  const parsed = rfc3339NanoToEpochNs(value);
  assertion(parsed !== null, `${label} is not an exact UTC timestamp`);
  return parsed;
}

function monotonicNs(value, label) {
  assertion(
    typeof value === 'string' && /^[0-9]+$/u.test(value),
    `${label} is not an unsigned decimal nanosecond value`
  );
  return BigInt(value);
}

function optionSet(value) {
  return typeof value === 'string' ? [...value.split(',')].sort().join(',') : null;
}

function normalizedGroups(groups) {
  return Array.isArray(groups) ? [...groups].sort((left, right) => left - right) : null;
}

function normalizedEnvironment(entries) {
  if (!Array.isArray(entries)) return null;
  const result = {};
  for (const entry of entries) {
    if (typeof entry !== 'string' || !entry.includes('=')) return null;
    const separator = entry.indexOf('=');
    const key = entry.slice(0, separator);
    if (Object.hasOwn(result, key)) return null;
    result[key] = entry.slice(separator + 1);
  }
  return result;
}

async function readJson(filePath, label = filePath) {
  try {
    return JSON.parse(await readFile(filePath, 'utf8'));
  } catch (error) {
    throw new Error(`${label} is not valid JSON`, { cause: error });
  }
}

function safeRepositoryPath(relativePath, label) {
  assertion(
    typeof relativePath === 'string' && relativePath.length > 0 && !path.isAbsolute(relativePath),
    `${label} is not repository-relative`
  );
  const absolute = path.resolve(REPOSITORY_ROOT, relativePath);
  assertion(
    absolute.startsWith(`${REPOSITORY_ROOT}${path.sep}`),
    `${label} escaped the repository`
  );
  return absolute;
}

function safeEvidencePath(runPath, relativePath, label) {
  assertion(
    typeof relativePath === 'string' &&
      relativePath.length > 0 &&
      !path.isAbsolute(relativePath) &&
      path.basename(relativePath) === relativePath,
    `${label} is not a direct evidence artifact`
  );
  const directory = path.dirname(runPath);
  const absolute = path.resolve(directory, relativePath);
  assertion(
    absolute.startsWith(`${directory}${path.sep}`),
    `${label} escaped the evidence directory`
  );
  return absolute;
}

async function assertRegularFile(filePath, label) {
  const metadata = await lstat(filePath);
  assertion(metadata.isFile() && !metadata.isSymbolicLink(), `${label} is not a regular file`);
  const resolved = await realpath(filePath);
  assertion(resolved === filePath, `${label} resolves through an alias or symbolic link`);
}

function compileSchema(schema) {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  ajv.addFormat('date-time', validDateTime);
  return ajv.compile(schema);
}

function assertSchema(validate, value, label) {
  assertion(
    validate(value),
    `${label} schema failed: ${(validate.errors ?? [])
      .map((error) => `${error.instancePath || '/'} ${error.message}`)
      .join('; ')}`
  );
}

function parseJsonLines(bytes, label) {
  const text = bytes.toString('utf8');
  assertion(text.endsWith('\n'), `${label} lacks its terminal newline`);
  const lines = text.split(/\r?\n/u);
  lines.pop();
  assertion(lines.length > 0 && lines.every((line) => line.length > 0), `${label} is empty`);
  try {
    return lines.map((line) => JSON.parse(line));
  } catch (error) {
    throw new Error(`${label} is not valid JSON Lines`, { cause: error });
  }
}

async function verifiedArtifact(runPath, receipt, expectedName, label) {
  assertion(
    exactKeys(receipt, ['path', 'sha256']) && receipt.path === expectedName,
    `${label} receipt is not exact`
  );
  const filePath = safeEvidencePath(runPath, receipt.path, label);
  await assertRegularFile(filePath, label);
  const bytes = await readFile(filePath);
  assertion(sha256(bytes) === receipt.sha256, `${label} hash mismatch`);
  return bytes;
}

function statIdentityEqual(left, right) {
  return (
    isPlainRecord(left) &&
    isPlainRecord(right) &&
    ['stDev', 'inode', 'ctimeNs', 'rdevHex'].every(
      (key) => typeof left[key] === 'string' && left[key] === right[key]
    )
  );
}

function sameDeviceAccessBoundary(reference, candidate) {
  return (
    isPlainRecord(reference) &&
    isPlainRecord(candidate) &&
    reference.isCharacterDevice === true &&
    candidate.isCharacterDevice === true &&
    DEVICE_ACCESS_KEYS.every((key) => reference[key] === candidate[key])
  );
}

export function exactPresentHostTuple(snapshot, serial, label) {
  assertion(
    snapshot?.state === 'present' &&
      snapshot.expectedSerial === serial &&
      snapshot.lsusb?.observed === true &&
      snapshot.lsusb.exitCode === 0 &&
      snapshot.lsusb.errorCode === null &&
      Array.isArray(snapshot.errors) &&
      snapshot.errors.length === 0 &&
      isPlainRecord(snapshot.scope) &&
      typeof snapshot.scope.bootId === 'string' &&
      typeof snapshot.scope.mountNamespace === 'string',
    `${label} host snapshot is incomplete`
  );
  const usb = snapshot.usb.filter(
    (entry) =>
      entry.vendorId === '0fd9' &&
      entry.productId === '0080' &&
      entry.serial === serial &&
      entry.serialMatches === true
  );
  const nodes = snapshot.hidraw.filter(
    (entry) =>
      entry.serialMatches === true &&
      entry.hid?.id === '0003:00000FD9:00000080' &&
      entry.hid?.unique === serial &&
      entry.usbAncestor?.vendorId === '0fd9' &&
      entry.usbAncestor?.productId === '0080' &&
      entry.usbAncestor?.serial === serial
  );
  assertion(usb.length === 1 && nodes.length === 1, `${label} lacks one exact MK.2 tuple`);
  const node = nodes[0];
  assertion(
    node.nodeStable === true &&
      node.nodeMatchesClass === true &&
      node.stat?.isCharacterDevice === true &&
      node.stat.major === node.classDevice?.major &&
      node.stat.minor === node.classDevice?.minor &&
      node.stat.rdevHex ===
        `${node.classDevice.major.toString(16)}:${node.classDevice.minor.toString(16)}` &&
      usb[0].deviceNumber === node.usbAncestor.deviceNumber,
    `${label} HID, USB, and character-node identities disagree`
  );
  return { usb: usb[0], node };
}

function assertAbsentHostSnapshot(snapshot, serial, label) {
  assertion(
    snapshot?.state === 'absent' &&
      snapshot.expectedSerial === serial &&
      snapshot.lsusb?.observed === true &&
      snapshot.lsusb.exitCode === 0 &&
      snapshot.lsusb.errorCode === null &&
      snapshot.lsusb.matches.length === 0 &&
      snapshot.usb.length === 0 &&
      snapshot.hidraw.length === 0 &&
      snapshot.priorPath?.stat?.kind === 'missing' &&
      snapshot.priorPath.stat.code === 'ENOENT' &&
      snapshot.errors.length === 0,
    `${label} did not prove exact physical absence`
  );
}

function selectExactInventory(inventory, { serial, path: expectedPath, label }) {
  assertion(Array.isArray(inventory) && inventory.length > 0, `${label} inventory is empty`);
  for (const entry of inventory) {
    assertion(
      Array.isArray(entry.errors) &&
        entry.errors.length === 0 &&
        entry.stat?.stable === true &&
        entry.stat.matchesClass === true &&
        entry.stat.before?.kind === 'value' &&
        entry.stat.after?.kind === 'value' &&
        sameCanonical(entry.stat.before.value, entry.stat.after.value) &&
        sameCanonical(entry.stat.value, entry.stat.before.value) &&
        entry.stat.value.isCharacterDevice === true &&
        entry.stat.value.major === entry.classDevice?.major &&
        entry.stat.value.minor === entry.classDevice?.minor,
      `${label} inventory contains an incomplete hidraw observation`
    );
  }
  const matches = inventory.filter(
    (entry) =>
      entry.devicePath === expectedPath &&
      entry.hid?.vendorId === '0fd9' &&
      entry.hid?.productId === '0080' &&
      entry.hid?.unique === serial &&
      entry.usbAncestor?.vendorId === '0fd9' &&
      entry.usbAncestor?.productId === '0080' &&
      entry.usbAncestor?.serial === serial
  );
  assertion(matches.length === 1, `${label} inventory does not select one exact MK.2`);
  return matches[0];
}

function hostEpochChanged(initial, returned) {
  const serial = initial.expectedSerial;
  const before = exactPresentHostTuple(initial, serial, 'initial epoch');
  const after = exactPresentHostTuple(returned, serial, 'returned epoch');
  return (
    initial.scope.bootId === returned.scope.bootId &&
    initial.scope.mountNamespace === returned.scope.mountNamespace &&
    (before.usb.deviceNumber !== after.usb.deviceNumber ||
      before.node.hidDevicePath !== after.node.hidDevicePath ||
      before.node.stat.inode !== after.node.stat.inode ||
      before.node.stat.ctimeNs !== after.node.stat.ctimeNs)
  );
}

function dynamicStageMatchesHost(hostNode, dynamic) {
  if (hostNode === null) {
    return (
      dynamic?.kind === 'missing' &&
      dynamic.code === 'ENOENT' &&
      /^\/host-dev\/hidraw[0-9]+$/u.test(dynamic.path)
    );
  }
  const match = /^\/dev\/(hidraw[0-9]+)$/u.exec(hostNode.devicePath ?? '');
  return (
    match !== null &&
    dynamic?.kind === 'value' &&
    dynamic.path === `/host-dev/${match[1]}` &&
    statIdentityEqual(hostNode.stat, dynamic.value)
  );
}

function sameLifecycle(left, right) {
  return (
    isPlainRecord(left) &&
    isPlainRecord(right) &&
    LIFECYCLE_KEYS.every((key) => left[key] === right[key])
  );
}

function exactWorkerIdentity(worker, lifecycle, deviceGid) {
  if (!isPlainRecord(worker)) return null;
  const identity = Object.fromEntries(WORKER_IDENTITY_KEYS.map((key) => [key, worker[key]]));
  if (
    !Number.isSafeInteger(identity.pid) ||
    identity.pid <= 1 ||
    !Number.isSafeInteger(identity.startTicks) ||
    identity.startTicks <= 0 ||
    identity.ppid !== 1 ||
    identity.parentStartTicks !== lifecycle?.pid1StartTicks ||
    identity.uid !== 1000 ||
    identity.gid !== 1000 ||
    !sameCanonical(normalizedGroups(identity.groups), normalizedGroups([1000, deviceGid])) ||
    !sameCanonical(identity.cmdline, SURFACE_THREAD_CMDLINE) ||
    identity.cgroup !== lifecycle?.cgroup ||
    identity.pidNamespace !== lifecycle?.pidNamespace ||
    identity.mountNamespace !== lifecycle?.mountNamespace
  ) {
    return null;
  }
  return identity;
}

function sameWorker(left, right) {
  return (
    isPlainRecord(left) &&
    isPlainRecord(right) &&
    WORKER_IDENTITY_KEYS.every((key) => sameCanonical(left[key], right[key]))
  );
}

function matchingTargetDescriptors(runtime) {
  const dynamic = runtime?.observer?.paths?.dynamic?.stat;
  if (dynamic?.kind !== 'value') return [];
  const nodeMatch = /^\/host-dev\/(hidraw[0-9]+)$/u.exec(dynamic.path ?? '');
  if (nodeMatch === null) return [];
  return runtime.observer.surfaceWorkers.flatMap((worker) =>
    worker.fileDescriptors.filter((descriptor) => {
      const descriptorMatch = /^\/(?:dev|host-dev)\/(hidraw[0-9]+)$/u.exec(descriptor.target ?? '');
      return (
        descriptorMatch !== null &&
        descriptorMatch[1] === nodeMatch[1] &&
        statIdentityEqual(descriptor.stat, dynamic.value)
      );
    })
  );
}

function descriptorAbsent(runtime) {
  return (
    runtime?.observer?.paths?.dynamic?.stat?.kind === 'missing' &&
    runtime.observer.paths.dynamic.stat.code === 'ENOENT' &&
    runtime.observer.paths.compat.stat.kind === 'missing' &&
    runtime.observer.paths.compat.stat.code === 'ENOENT' &&
    runtime.observer.surfaceWorkers.every((worker) => worker.fileDescriptors.length === 0)
  );
}

function verifyContainerBoundary(runtime, run, label) {
  const { container, lifecycle, observer } = runtime;
  const environment = normalizedEnvironment(container.environment);
  const expectedMounts = [
    ['/host-dev', '/dev', true],
    ['/h041-entrypoint.sh', path.join(REPOSITORY_ROOT, 'lab/h041/entrypoint.sh'), false],
    [
      '/h041-container-observer.mjs',
      path.join(REPOSITORY_ROOT, 'lab/h041/container-observer.mjs'),
      false,
    ],
    ['/h042-signal-helper.mjs', path.join(REPOSITORY_ROOT, 'lab/h042/signal-helper.mjs'), false],
  ];
  assertion(
    container.containerId === run.companion.containerId &&
      container.name === run.companion.name &&
      container.imageId === EXPECTED_IMAGE_ID &&
      container.running === true &&
      container.restartCount === 0 &&
      container.restartPolicy === 'no' &&
      container.autoRemove === true &&
      container.networkMode === 'none' &&
      container.cgroupNamespaceMode === 'private' &&
      container.privileged === false &&
      container.readOnlyRootfs === true &&
      sameCanonical([...container.capAdd].sort(), ['CAP_SETGID', 'CAP_SETUID']) &&
      sameCanonical(container.capDrop, ['ALL']) &&
      sameCanonical(container.securityOpt, ['no-new-privileges']) &&
      sameCanonical(container.groupAdd, [String(run.companion.deviceGid)]) &&
      container.pidsLimit === 128 &&
      container.memory === 1024 * 1024 * 1024 &&
      sameCanonical(container.deviceCgroupRules, [run.companion.deviceCgroupRule]) &&
      sameCanonical(container.devices, []) &&
      sameCanonical(Object.keys(container.tmpfs).sort(), ['/companion', '/tmp']) &&
      optionSet(container.tmpfs['/companion']) ===
        optionSet('rw,nosuid,nodev,noexec,size=268435456,uid=1000,gid=1000,mode=0700') &&
      optionSet(container.tmpfs['/tmp']) ===
        optionSet('rw,nosuid,nodev,size=67108864,uid=1000,gid=1000,mode=1777') &&
      container.user === '0:0' &&
      environment !== null &&
      environment.COMPANION_CONFIG_BASEDIR === '/companion' &&
      environment.H041_UID === '1000' &&
      environment.H041_GID === '1000' &&
      environment.H041_DEVICE_GID === String(run.companion.deviceGid) &&
      environment.H041_DYNAMIC_PATH === run.companion.dynamicPath &&
      environment.H041_COMPAT_PATH === run.companion.compatibilityPath &&
      !Object.keys(environment).some((key) => key.includes('OVERLAYKIT')) &&
      container.labels['dev.overlaykit.hypothesis'] === 'H-042' &&
      container.labels['org.opencontainers.image.version'] === 'v4.3.3' &&
      container.labels['org.opencontainers.image.revision'] === EXPECTED_IMAGE_REVISION &&
      sameCanonical(container.entrypoint, ['/bin/bash']) &&
      sameCanonical(container.command, ['/h041-entrypoint.sh']) &&
      container.mounts.length === expectedMounts.length &&
      container.declaredMounts.length === expectedMounts.length &&
      expectedMounts.every(([destination, source]) =>
        container.mounts.some(
          (entry) =>
            entry.type === 'bind' &&
            entry.destination === destination &&
            entry.source === source &&
            entry.rw === false &&
            entry.propagation === 'rprivate'
        )
      ) &&
      expectedMounts.every(([target, source, nonRecursive]) =>
        container.declaredMounts.some(
          (entry) =>
            entry.type === 'bind' &&
            entry.target === target &&
            entry.source === source &&
            entry.readOnly === true &&
            (nonRecursive ? entry.bindOptions?.NonRecursive === true : entry.bindOptions === null)
        )
      ),
    `${label} container permission or provenance boundary is invalid`
  );
  assertion(
    lifecycle.containerId === container.containerId &&
      lifecycle.imageId === container.imageId &&
      lifecycle.startedAt === container.startedAt &&
      lifecycle.restartCount === container.restartCount &&
      lifecycle.hostPid === container.hostPid &&
      lifecycle.pid1StartTicks === container.hostPidStartTicks &&
      lifecycle.pidNamespace === container.hostPidNamespace &&
      lifecycle.mountNamespace === container.hostMountNamespace &&
      lifecycle.hostCgroup === container.hostCgroup &&
      lifecycle.cgroupNamespaceMode === container.cgroupNamespaceMode &&
      lifecycle.cgroup === '0::/' &&
      observer.schemaVersion === 'overlaykit-h041-container-observation/v1' &&
      observer.metadataOnly === true &&
      observer.pid1.pid === 1 &&
      observer.pid1.startTicks === lifecycle.pid1StartTicks &&
      observer.pid1.ppid === 0 &&
      observer.pid1.parentStartTicks === null &&
      observer.pid1.uid === 1000 &&
      observer.pid1.gid === 1000 &&
      observer.pid1.command === 'node' &&
      sameCanonical(observer.pid1.cmdline, [
        './node-runtimes/main/bin/node',
        './main.js',
        '--admin-address',
        '::',
        '--admin-port',
        '8000',
        '--config-dir',
        '/companion',
        '--extra-module-path',
        '/app/module-local-dev',
      ]) &&
      sameCanonical(
        normalizedGroups(observer.pid1.groups),
        normalizedGroups([1000, run.companion.deviceGid])
      ) &&
      observer.pid1.cgroup === lifecycle.cgroup &&
      observer.pid1.pidNamespace === lifecycle.pidNamespace &&
      observer.pid1.mountNamespace === lifecycle.mountNamespace &&
      observer.paths.dynamic.path === run.companion.dynamicPath &&
      observer.paths.compat.path === run.companion.compatibilityPath &&
      observer.paths.compat.linkTarget === run.companion.dynamicPath &&
      observer.paths.compat.lstat.kind === 'value' &&
      observer.paths.compat.lstat.value.isSymbolicLink === true &&
      observer.target.major === Number(run.companion.deviceCgroupRule.split(/[ :]/u)[1]) &&
      observer.target.minor === Number(run.companion.deviceCgroupRule.split(/[ :]/u)[2]),
    `${label} container lifecycle or PID 1 binding is invalid`
  );
  for (const worker of observer.surfaceWorkers) {
    assertion(
      exactWorkerIdentity(worker, lifecycle, run.companion.deviceGid) !== null,
      `${label} contains a worker outside the exact SurfaceThread boundary`
    );
  }
  assertion(
    observer.surfaceWorkers.every((worker) =>
      observer.processes.some(
        (candidate) => candidate.pid === worker.pid && candidate.startTicks === worker.startTicks
      )
    ),
    `${label} worker list is not backed by the process inventory`
  );
}

function baselineAcquired(runtime, run) {
  return (
    runtime.observer.surfaceWorkers.length === 1 &&
    exactWorkerIdentity(
      runtime.observer.surfaceWorkers[0],
      runtime.lifecycle,
      run.companion.deviceGid
    ) !== null &&
    runtime.markers.opening > 0 &&
    runtime.markers.ready > 0 &&
    matchingTargetDescriptors(runtime).length === 1
  );
}

function stripAnsi(value) {
  return value.replace(/\u001b\[[0-9;]*m/gu, '');
}

export function countAcquisitionMarkers(logs, serial, paths) {
  assertion(typeof logs === 'string', 'marker source is not text');
  assertion(
    typeof serial === 'string' && serial.length > 0 && Array.isArray(paths) && paths.length === 2,
    'marker identity boundary is invalid'
  );
  const identity = `streamdeck:${serial}`;
  let opening = 0;
  let ready = 0;
  let openFailed = 0;
  const relevantLines = [];
  for (const rawLine of stripAnsi(logs).split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (line.length === 0 || !line.includes(identity)) continue;
    const isOpening = line.includes(`Opening surface panel: ${identity}`);
    const isReady = line.includes(`Surface panel ready: ${identity}`);
    const isOpenFailure = paths.some((devicePath) =>
      line.includes(`cannot open device with path ${devicePath}`)
    );
    if (isOpening) opening += 1;
    if (isReady) ready += 1;
    if (isOpenFailure) openFailed += 1;
    if (isOpening || isReady || isOpenFailure) relevantLines.push(line);
  }
  return { opening, ready, openFailed, relevantLines };
}

function markerTimestamp(line) {
  if (typeof line !== 'string') return null;
  const separator = line.indexOf(' ');
  if (separator <= 0) return null;
  return rfc3339NanoToEpochNs(line.slice(0, separator));
}

export function recomputeMarkerDelta(before, after, signalReceivedAt) {
  const receivedFloor = rfc3339NanoToEpochNs(signalReceivedAt);
  const beforeLines = before?.relevantLines;
  const afterLines = after?.relevantLines;
  if (
    receivedFloor === null ||
    !Array.isArray(beforeLines) ||
    !Array.isArray(afterLines) ||
    beforeLines.length > afterLines.length ||
    !beforeLines.every((line, index) => line === afterLines[index])
  ) {
    return {
      prefixValid: false,
      openingObserved: false,
      readyObserved: false,
      ordered: false,
      allAfterSignal: false,
      lines: [],
    };
  }
  const lines = afterLines.slice(beforeLines.length);
  const events = lines.map((line, index) => ({
    line,
    index,
    time: markerTimestamp(line),
    opening: line.includes('Opening surface panel:'),
    ready: line.includes('Surface panel ready:'),
  }));
  const opening = events.find((entry) => entry.opening);
  const ready = events.find(
    (entry) => entry.ready && opening !== undefined && entry.index > opening.index
  );
  const relevant = events.filter((entry) => entry.opening || entry.ready);
  // Signal timestamps are millisecond-truncated by Date#toISOString.  A marker
  // at the same millisecond cannot prove that it followed delivery.
  const signalUpperExclusive = receivedFloor + MILLISECOND_NS;
  const allAfterSignal =
    relevant.length > 0 &&
    relevant.every((entry) => entry.time !== null && entry.time >= signalUpperExclusive);
  return {
    prefixValid: true,
    openingObserved: opening !== undefined,
    readyObserved: ready !== undefined,
    ordered:
      opening !== undefined &&
      ready !== undefined &&
      opening.index < ready.index &&
      opening.time !== null &&
      ready.time !== null &&
      opening.time < ready.time,
    allAfterSignal,
    lines,
  };
}

function markersWithinConservativeWallDeadline(delta, signalReceivedAt) {
  const lower = rfc3339NanoToEpochNs(signalReceivedAt);
  if (lower === null || delta.lines.length === 0) return false;
  const deadline = lower + POST_SIGNAL_NS;
  return delta.lines.every((line) => {
    const observed = markerTimestamp(line);
    return observed !== null && observed <= deadline;
  });
}

function markersUnchanged(reference, candidate) {
  return sameCanonical(reference, candidate);
}

function verifyMarkerReceipt(receipt, serial, paths, label) {
  const recomputed = countAcquisitionMarkers(
    `${receipt.relevantLines.join('\n')}${receipt.relevantLines.length > 0 ? '\n' : ''}`,
    serial,
    paths
  );
  assertion(sameCanonical(receipt, recomputed), `${label} marker receipt is internally invalid`);
}

function workerPresent(runtime, identity) {
  return runtime.observer.processes.some(
    (candidate) => candidate.pid === identity.pid && candidate.startTicks === identity.startTicks
  );
}

export function reconstructReplacementTimeline(oldWorker, runtimes, deviceGid) {
  if (!Array.isArray(runtimes) || runtimes.length === 0 || !isPlainRecord(oldWorker)) {
    return {
      oldWorkerExited: false,
      replacementWorkerUnique: false,
      singleReplacementGeneration: false,
      replacementWorkerChanged: false,
      replacement: null,
    };
  }
  let oldWorkerExited = false;
  let oldReappeared = false;
  let ambiguous = false;
  const replacements = new Map();
  for (const runtime of runtimes) {
    const workers = runtime?.observer?.surfaceWorkers;
    if (!Array.isArray(workers) || !Array.isArray(runtime?.observer?.processes)) {
      ambiguous = true;
      continue;
    }
    const oldPresent = workerPresent(runtime, oldWorker);
    if (!oldPresent) oldWorkerExited = true;
    else if (oldWorkerExited) oldReappeared = true;
    if (workers.length > 1) ambiguous = true;
    for (const candidate of workers) {
      if (sameWorker(oldWorker, candidate)) continue;
      const identity = exactWorkerIdentity(candidate, runtime.lifecycle, deviceGid);
      if (identity === null) {
        ambiguous = true;
      } else {
        replacements.set(`${identity.pid}:${identity.startTicks}`, candidate);
      }
    }
  }
  const final = runtimes.at(-1);
  const finalWorkers = final?.observer?.surfaceWorkers;
  const finalReplacement =
    Array.isArray(finalWorkers) &&
    finalWorkers.length === 1 &&
    !sameWorker(oldWorker, finalWorkers[0]) &&
    exactWorkerIdentity(finalWorkers[0], final.lifecycle, deviceGid) !== null
      ? finalWorkers[0]
      : null;
  const singleReplacementGeneration = !ambiguous && !oldReappeared && replacements.size <= 1;
  const replacement =
    replacements.size === 1 &&
    finalReplacement !== null &&
    sameWorker([...replacements.values()][0], finalReplacement)
      ? finalReplacement
      : null;
  return {
    oldWorkerExited,
    replacementWorkerUnique: singleReplacementGeneration && replacement !== null,
    singleReplacementGeneration,
    replacementWorkerChanged:
      singleReplacementGeneration &&
      replacement !== null &&
      oldWorkerExited &&
      !sameWorker(oldWorker, replacement),
    replacement,
  };
}

function exactSignalTarget(worker) {
  return Object.fromEntries(WORKER_IDENTITY_KEYS.map((key) => [key, worker[key]]));
}

export function verifySignalReceipt({
  signal,
  receiptText,
  signalTargetRuntime,
  oldWorker,
  signalAudit,
}) {
  assertion(
    typeof receiptText === 'string' && receiptText.endsWith('\n'),
    'signal receipt text is not exact'
  );
  let archived;
  try {
    archived = JSON.parse(receiptText);
  } catch (error) {
    throw new Error('signal receipt artifact is not JSON', { cause: error });
  }
  assertion(
    sameCanonical(archived, signal.receipt),
    'signal receipt artifact differs from the run'
  );
  const receipt = archived;
  const target = exactSignalTarget(oldWorker);
  const tuple = {
    pid: target.pid,
    startTicks: target.startTicks,
    ppid: target.ppid,
    parentStartTicks: target.parentStartTicks,
  };
  const observedIdentity = Object.fromEntries(
    WORKER_IDENTITY_KEYS.map((key) => [key, receipt.observed?.[key]])
  );
  assertion(
    signal.command.length === 2 &&
      signal.command[0] === '/app/node-runtimes/main/bin/node' &&
      signal.command[1] === '/h042-signal-helper.mjs' &&
      signal.user === '1000:1000' &&
      signal.exitCode === 0 &&
      sameCanonical(signal.target, target) &&
      receipt.schemaVersion === 'overlaykit-h042-signal-receipt/v1' &&
      receipt.signal === 'SIGTERM' &&
      sameCanonical(receipt.expected, target) &&
      sameCanonical(observedIdentity, target) &&
      Array.isArray(receipt.observed.targetHidrawDescriptors) &&
      receipt.observed.targetHidrawDescriptors.length === 0 &&
      sameCanonical(receipt.observed.revalidation?.initial, tuple) &&
      sameCanonical(receipt.observed.revalidation?.final, tuple) &&
      sameCanonical(signal.startedAt, receipt.startedAt) &&
      sameCanonical(signal.receivedAt, receipt.receivedAt) &&
      signal.startedMonotonicNs === receipt.startedMonotonicNs &&
      signal.receivedMonotonicNs === receipt.receivedMonotonicNs,
    'signal helper receipt does not bind both revalidation tuples to the target'
  );
  const targetObserved = monotonicNs(signalTargetRuntime.monotonicNs, 'signal target poll');
  const started = monotonicNs(receipt.startedMonotonicNs, 'signal receipt start');
  const received = monotonicNs(receipt.receivedMonotonicNs, 'signal receipt delivery');
  assertion(
    targetObserved < started &&
      started < received &&
      wallNs(receipt.startedAt, 'signal receipt start') <=
        wallNs(receipt.receivedAt, 'signal receipt delivery'),
    'signal receipt chronology is invalid'
  );
  assertion(
    signalAudit?.signal === 'SIGTERM' &&
      signalAudit.user === '1000:1000' &&
      signalAudit.exitCode === 0 &&
      sameCanonical(signalAudit.command, signal.command) &&
      sameCanonical(signalAudit.processTarget, target) &&
      signalAudit.receiptSha256 === sha256(receiptText),
    'signal invocation audit is not source- and receipt-bound'
  );
  // processKillCallCount is intentionally not used as evidence of cardinality.
  // Cardinality is reconstructed from the audit plus Docker exec events.
  return { target, tuple, started, received, receipt };
}

const HEALTHCHECK_COMMAND = 'sh -c curl -fSsq http://localhost:${COMPANION_ADMIN_PORT:-8000}/';

export function parseDockerEventLines(text, label = 'Docker event stream') {
  assertion(typeof text === 'string' && text.endsWith('\n'), `${label} lacks a terminal newline`);
  const lines = text.split(/\r?\n/u);
  lines.pop();
  assertion(lines.length > 0 && lines.every(Boolean), `${label} is empty`);
  return lines.map((line, index) => {
    const timeMatches = [...line.matchAll(/"timeNano"\s*:\s*([0-9]+)(?=\s*[,}])/gu)];
    assertion(
      timeMatches.length === 1,
      `${label} line ${index + 1} lacks one raw numeric timeNano`
    );
    const exactTimeNano = timeMatches[0][1];
    let event;
    try {
      event = JSON.parse(line.replace(/("timeNano"\s*:\s*)([0-9]+)(?=\s*[,}])/u, '$1"$2"'));
    } catch (error) {
      throw new Error(`${label} line ${index + 1} is not JSON`, { cause: error });
    }
    assertion(
      event.timeNano === exactTimeNano &&
        typeof event.time === 'number' &&
        Number.isSafeInteger(event.time) &&
        BigInt(event.time) === BigInt(exactTimeNano) / SECOND_NS &&
        isPlainRecord(event.Actor) &&
        typeof event.Actor.ID === 'string' &&
        event.Actor.ID.length > 0 &&
        (event.id === undefined || event.id === event.Actor.ID) &&
        isPlainRecord(event.Actor.Attributes) &&
        Object.values(event.Actor.Attributes).every((value) => typeof value === 'string'),
      `${label} line ${index + 1} has an invalid timestamp or actor envelope`
    );
    return {
      type: event.Type,
      action: event.Action,
      status: event.status ?? null,
      id: event.Actor.ID,
      time: event.time,
      timeNano: exactTimeNano,
      attributes: event.Actor.Attributes,
    };
  });
}

function analyzeExecTriples(events, allowedCommands, label) {
  const creates = events.filter((event) => event.action.startsWith('exec_create: '));
  const starts = events.filter((event) => event.action.startsWith('exec_start: '));
  const dies = events.filter((event) => event.action === 'exec_die');
  const records = [];
  const seen = new Set();
  for (const created of creates) {
    const command = created.action.slice('exec_create: '.length);
    const execId = created.attributes.execID;
    assertion(
      allowedCommands.includes(command) &&
        typeof execId === 'string' &&
        execId.length > 0 &&
        !seen.has(execId),
      `${label} contains an unknown or duplicate exec_create`
    );
    seen.add(execId);
    const matchingStarts = starts.filter(
      (entry) => entry.attributes.execID === execId && entry.action === `exec_start: ${command}`
    );
    const matchingDies = dies.filter(
      (entry) => entry.attributes.execID === execId && entry.attributes.exitCode === '0'
    );
    assertion(
      matchingStarts.length === 1 &&
        matchingDies.length === 1 &&
        BigInt(created.timeNano) < BigInt(matchingStarts[0].timeNano) &&
        BigInt(matchingStarts[0].timeNano) < BigInt(matchingDies[0].timeNano),
      `${label} contains an incomplete, failed, or unordered exec triple`
    );
    records.push({
      command,
      execId,
      create: created,
      start: matchingStarts[0],
      die: matchingDies[0],
    });
  }
  assertion(
    starts.length === creates.length &&
      dies.length === creates.length &&
      starts.every((entry) => seen.has(entry.attributes.execID)) &&
      dies.every((entry) => seen.has(entry.attributes.execID)),
    `${label} contains an orphan exec_start or exec_die`
  );
  return records;
}

function assertExactEventScope(events, containerId, label) {
  assertion(events.length > 0, `${label} is empty`);
  let previous = null;
  for (const event of events) {
    const observed = BigInt(event.timeNano);
    assertion(
      event.type === 'container' &&
        event.id === containerId &&
        (previous === null || observed >= previous),
      `${label} escaped the exact container or is not chronologically ordered`
    );
    previous = observed;
  }
}

export function analyzeExperimentDockerEvents(
  events,
  {
    containerId,
    expectedObserverExecCount,
    signalStartedAt,
    signalReceivedAt,
    experimentStartedAt,
    experimentBoundaryAt,
  }
) {
  assertExactEventScope(events, containerId, 'experiment Docker events');
  const experimentStart = wallNs(experimentStartedAt, 'experiment event start');
  const experimentBoundary = wallNs(experimentBoundaryAt, 'experiment event boundary');
  assertion(
    experimentStart <= experimentBoundary &&
      events.every((event) => {
        const observed = BigInt(event.timeNano);
        return observed >= experimentStart && observed <= experimentBoundary;
      }),
    'experiment Docker event timestamps escaped the requested interval'
  );
  const forbidden = events.filter((event) =>
    ['kill', 'stop', 'die', 'restart', 'destroy', 'oom'].includes(event.action)
  );
  assertion(forbidden.length === 0, 'experiment Docker events contain lifecycle intervention');
  const execs = analyzeExecTriples(
    events,
    [SIGNAL_HELPER_COMMAND, OBSERVER_COMMAND, HEALTHCHECK_COMMAND],
    'experiment Docker events'
  );
  const helpers = execs.filter((entry) => entry.command === SIGNAL_HELPER_COMMAND);
  const observers = execs.filter((entry) => entry.command === OBSERVER_COMMAND);
  const healthchecks = execs.filter((entry) => entry.command === HEALTHCHECK_COMMAND);
  const nonExec = events.filter(
    (event) =>
      !event.action.startsWith('exec_create: ') &&
      !event.action.startsWith('exec_start: ') &&
      event.action !== 'exec_die'
  );
  const creates = nonExec.filter((event) => event.action === 'create');
  const starts = nonExec.filter((event) => event.action === 'start');
  const healthStatuses = nonExec.filter((event) =>
    ['health_status: starting', 'health_status: healthy'].includes(event.action)
  );
  assertion(
    creates.length === 1 &&
      starts.length === 1 &&
      BigInt(creates[0].timeNano) < BigInt(starts[0].timeNano) &&
      nonExec.length === creates.length + starts.length + healthStatuses.length,
    'experiment Docker events contain an unknown non-exec action'
  );
  assertion(
    helpers.length === 1 && observers.length === expectedObserverExecCount,
    'experiment Docker events do not contain the exact helper/observer cardinality'
  );
  const receiptStart = wallNs(signalStartedAt, 'signal wall start');
  const receiptEnd = wallNs(signalReceivedAt, 'signal wall delivery');
  assertion(
    BigInt(helpers[0].create.timeNano) < BigInt(helpers[0].start.timeNano) &&
      BigInt(helpers[0].start.timeNano) < receiptStart + MILLISECOND_NS &&
      BigInt(helpers[0].die.timeNano) >= receiptEnd,
    'signal helper Docker exec cannot be correlated to the signal receipt'
  );
  return {
    passed: true,
    execId: helpers[0].execId,
    helperCreateCount: 1,
    helperStartCount: 1,
    helperDieZeroCount: 1,
    ordered: true,
    forbiddenActions: [],
    execCreateCount: execs.length,
    observerExecCount: observers.length,
    healthcheckExecCount: healthchecks.length,
    execBoundaryExact: true,
    healthcheckExecIds: healthchecks.map((entry) => entry.execId),
    containerStartExact: true,
    healthStatusEvents: healthStatuses,
    experimentStartedAt,
    experimentBoundaryAt,
  };
}

function healthcheckReceipt(records) {
  return {
    command: HEALTHCHECK_COMMAND,
    createCount: records.length,
    tripletCount: records.length,
    execIds: records.map((entry) => entry.execId).sort(),
    complete: true,
  };
}

export function analyzeCleanupDockerEvents(
  events,
  { containerId, experimentBoundaryAt, classificationCompletedAt, eventsUntilAt }
) {
  assertExactEventScope(events, containerId, 'cleanup Docker events');
  const boundary = wallNs(experimentBoundaryAt, 'cleanup experiment boundary');
  const classified = wallNs(classificationCompletedAt, 'cleanup classification boundary');
  const until = wallNs(eventsUntilAt, 'cleanup event upper boundary');
  assertion(
    boundary <= classified &&
      classified <= until &&
      events.every((event) => {
        const observed = BigInt(event.timeNano);
        return observed > boundary && observed <= until;
      }),
    'cleanup Docker events escaped the gap/cleanup interval'
  );
  const gapEvents = events.filter((event) => BigInt(event.timeNano) <= classified);
  const cleanupEvents = events.filter((event) => BigInt(event.timeNano) > classified);
  const gapExecs = analyzeExecTriples(
    gapEvents,
    [HEALTHCHECK_COMMAND],
    'classification-gap Docker events'
  );
  const cleanupExecs = analyzeExecTriples(
    cleanupEvents,
    [HEALTHCHECK_COMMAND],
    'cleanup Docker events'
  );
  const gapNonExec = gapEvents.filter(
    (event) =>
      !event.action.startsWith('exec_create: ') &&
      !event.action.startsWith('exec_start: ') &&
      event.action !== 'exec_die'
  );
  assertion(
    gapNonExec.every((event) =>
      ['health_status: starting', 'health_status: healthy'].includes(event.action)
    ),
    'classification gap contains a causal action other than a known healthcheck'
  );
  const nonExec = cleanupEvents.filter(
    (event) =>
      !event.action.startsWith('exec_create: ') &&
      !event.action.startsWith('exec_start: ') &&
      event.action !== 'exec_die'
  );
  const allowedActions = new Set(['kill', 'stop', 'die', 'destroy']);
  assertion(
    nonExec.every(
      (event) =>
        allowedActions.has(event.action) ||
        ['health_status: starting', 'health_status: healthy'].includes(event.action)
    ),
    'cleanup Docker events contain an unknown action'
  );
  const signal15 = nonExec.filter(
    (event) => event.action === 'kill' && event.attributes.signal === '15'
  );
  const signal9 = nonExec.filter(
    (event) => event.action === 'kill' && event.attributes.signal === '9'
  );
  const dies = nonExec.filter((event) => event.action === 'die');
  const destroys = nonExec.filter((event) => event.action === 'destroy');
  const stops = nonExec.filter((event) => event.action === 'stop');
  assertion(
    signal15.length === 1 &&
      signal9.length === 1 &&
      dies.length === 1 &&
      stops.length === 1 &&
      destroys.length === 1 &&
      dies[0].attributes.exitCode === '137' &&
      BigInt(signal15[0].timeNano) < BigInt(dies[0].timeNano) &&
      BigInt(signal15[0].timeNano) < BigInt(signal9[0].timeNano) &&
      BigInt(signal9[0].timeNano) < BigInt(stops[0].timeNano) &&
      BigInt(stops[0].timeNano) < BigInt(dies[0].timeNano) &&
      BigInt(dies[0].timeNano) < BigInt(destroys[0].timeNano),
    'cleanup Docker lifecycle is incomplete or unordered'
  );
  return {
    passed: true,
    experimentBoundaryAt,
    classifiedAt: classificationCompletedAt,
    eventsUntilAt,
    eventCount: events.length,
    timestampsValid: true,
    gap: {
      eventCount: gapEvents.length,
      healthcheck: healthcheckReceipt(gapExecs),
      healthStatusEvents: gapNonExec,
      boundaryExact: true,
    },
    cleanup: {
      eventCount: cleanupEvents.length,
      signal15Count: signal15.length,
      signal9Count: signal9.length,
      killCount: signal15.length + signal9.length,
      dieCount: dies.length,
      dieExitCode: dies[0].attributes.exitCode,
      stopCount: stops.length,
      destroyCount: destroys.length,
      healthcheck: healthcheckReceipt(cleanupExecs),
      healthStatusEvents: nonExec.filter((event) => event.action.startsWith('health_status: ')),
      lifecycleOrdered: true,
      boundaryExact: true,
    },
    firstTimeNano: events[0].timeNano,
    lastTimeNano: events.at(-1).timeNano,
  };
}

async function verifyCollector(runPath, run) {
  assertion(
    run.collector.sourceStable === true &&
      run.collector.repository ===
        'https://github.com/OverlayKit/companion-module-overlaykit-server.git' &&
      /^[0-9a-f]{40}$/u.test(run.collector.commit),
    'collector did not freeze the canonical repository and source set'
  );
  assertion(
    sameCanonical(run.collector.requiredSources, REQUIRED_SOURCE_PATHS),
    'collector requiredSources differs from the independent verifier list'
  );
  assertion(
    exactKeys(run.collector.sourceSha256, REQUIRED_SOURCE_PATHS),
    'collector source hashes are missing or expanded'
  );
  for (const relativePath of REQUIRED_SOURCE_PATHS) {
    const sourcePath = safeRepositoryPath(relativePath, `source ${relativePath}`);
    await assertRegularFile(sourcePath, `source ${relativePath}`);
    const bytes = await readFile(sourcePath);
    assertion(
      sha256(bytes) === run.collector.sourceSha256[relativePath],
      `collector source hash mismatch: ${relativePath}`
    );
  }
  const governance = run.collector.governance;
  const manifestBytes = await verifiedArtifact(
    runPath,
    {
      path: governance.manifestSnapshotPath,
      sha256: governance.manifestFileSha256,
    },
    'governance-manifest.json',
    'governance manifest'
  );
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes);
  } catch (error) {
    throw new Error('archived governance manifest is not JSON', { cause: error });
  }
  assertion(
    manifest.contentHash === governance.manifestContentHash &&
      manifest.planHash === governance.planHash &&
      manifest.changes?.['CHG-0013'] === governance.changeSha256 &&
      governance.changeSha256 ===
        run.collector.sourceSha256['.overlaykit/governance/changes/CHG-0013.json'],
    'archived governance manifest is not CHG-0013 bound'
  );
  const governanceReceipt = await verifiedArtifact(
    runPath,
    {
      path: governance.verifyReceiptPath,
      sha256: governance.verifyReceiptSha256,
    },
    'governance-verify.txt',
    'governance verification receipt'
  );
  assertion(
    governanceReceipt.toString('utf8').includes(`governance ok ${governance.planHash}`),
    'archived governance verification does not bind the plan'
  );
}

function canonicalEvidence(record, expected) {
  const { evidenceSha256, ...evidence } = record;
  assertion(
    record.schemaVersion === expected.schemaVersion &&
      record.hypothesis === expected.hypothesis &&
      evidenceSha256 === expected.evidenceSha256 &&
      sha256Canonical(evidence) === evidenceSha256,
    `${expected.hypothesis} canonical evidence is invalid`
  );
}

async function verifyInputs(runPath, run) {
  assertion(
    run.inputs.h041.path === H041_RUN_PATH &&
      run.inputs.h041.fileSha256 === H041_FILE_SHA256 &&
      run.inputs.h041.evidenceSha256 === H041_EVIDENCE_SHA256,
    'H-041 predecessor identity is not exact'
  );
  const h041Path = safeRepositoryPath(run.inputs.h041.path, 'H-041 input');
  await assertRegularFile(h041Path, 'H-041 input');
  const h041Bytes = await readFile(h041Path);
  assertion(sha256(h041Bytes) === H041_FILE_SHA256, 'H-041 predecessor file hash mismatch');
  const h041 = JSON.parse(h041Bytes);
  canonicalEvidence(h041, {
    schemaVersion: 'overlaykit-h041-dynamic-reacquisition-run/v1',
    hypothesis: 'H-041',
    evidenceSha256: H041_EVIDENCE_SHA256,
  });
  assertion(
    h041.outcome.status === 'refuted' &&
      h041.inputs.h037.evidenceSha256 === EXPECTED_PREDECESSOR_EVIDENCE.h037 &&
      h041.inputs.h039.evidenceSha256 === EXPECTED_PREDECESSOR_EVIDENCE.h039 &&
      h041.inputs.h040.evidenceSha256 === EXPECTED_PREDECESSOR_EVIDENCE.h040,
    'H-041 does not carry the exact accepted predecessor chain'
  );

  const originalDirectory = path.dirname(h041Path);
  for (const [key, specification] of Object.entries({
    h037: {
      field: 'validationReceipt',
      name: 'h037-validation.json',
    },
    h039: {
      field: 'verificationReceipt',
      name: 'h039-verification.json',
    },
    h040: {
      field: 'verificationReceipt',
      name: 'h040-verification.json',
    },
  })) {
    const originalInput = h041.inputs[key];
    const expectedReceipt = originalInput[specification.field];
    const originalReceiptPath = path.resolve(originalDirectory, expectedReceipt.path);
    assertion(
      originalReceiptPath.startsWith(`${originalDirectory}${path.sep}`),
      `${key.toUpperCase()} original receipt escaped H-041 evidence`
    );
    await assertRegularFile(originalReceiptPath, `${key.toUpperCase()} original receipt`);
    const originalReceiptBytes = await readFile(originalReceiptPath);
    assertion(
      sha256(originalReceiptBytes) === expectedReceipt.sha256,
      `${key.toUpperCase()} original receipt hash mismatch`
    );
    const copiedReceipt = run.inputs[key][specification.field];
    const copiedBytes = await verifiedArtifact(
      runPath,
      copiedReceipt,
      specification.name,
      `${key.toUpperCase()} copied receipt`
    );
    assertion(
      Buffer.compare(originalReceiptBytes, copiedBytes) === 0,
      `${key.toUpperCase()} copied receipt differs from H-041`
    );
    const expectedInput = {
      ...originalInput,
      [specification.field]: {
        path: specification.name,
        sha256: sha256(originalReceiptBytes),
      },
    };
    assertion(
      sameCanonical(run.inputs[key], expectedInput),
      `${key.toUpperCase()} input differs from the H-041 chain`
    );
  }

  const originalStoredVerificationPath = path.join(originalDirectory, 'verification.json');
  await assertRegularFile(originalStoredVerificationPath, 'stored H-041 verification');
  const originalStoredVerification = await readFile(originalStoredVerificationPath);
  assertion(
    sha256(originalStoredVerification) === H041_VERIFICATION_SHA256,
    'stored H-041 verification has changed'
  );
  const copiedVerification = await verifiedArtifact(
    runPath,
    run.inputs.h041.verificationReceipt,
    'h041-verification.json',
    'copied H-041 verification'
  );
  assertion(
    Buffer.compare(copiedVerification, originalStoredVerification) === 0,
    'copied H-041 verification differs byte-for-byte'
  );

  const freshVerification = await verifyDynamicReacquisitionRun(h041Path);
  assertion(
    freshVerification.outcome === 'refuted' &&
      freshVerification.workerMechanism === 'same-worker' &&
      freshVerification.cleaned === true &&
      freshVerification.verified === true,
    'fresh H-041 verification no longer establishes the accepted refutation'
  );
  const copiedReverification = await verifiedArtifact(
    runPath,
    run.inputs.h041.reverificationReceipt,
    'h041-reverification.json',
    'fresh H-041 reverification'
  );
  const archivedFreshVerification = JSON.parse(copiedReverification);
  assertion(
    sameCanonical(archivedFreshVerification, freshVerification),
    'archived H-041 reverification differs from an independent current verification'
  );
  const storedReceipt = JSON.parse(originalStoredVerification);
  assertion(
    sameCanonical(storedReceipt, freshVerification) &&
      storedReceipt.evidenceSha256 === H041_EVIDENCE_SHA256,
    'stored and fresh H-041 verification receipts disagree'
  );
  return { h041, freshVerification };
}

function compactHostSnapshot(snapshot, stage) {
  return {
    stage,
    capturedAt: snapshot.capturedAt,
    monotonicNs: snapshot.monotonicNs,
    state: snapshot.state,
    usb: snapshot.usb.map((entry) => ({
      serial: entry.serial,
      busNumber: entry.busNumber,
      deviceNumber: entry.deviceNumber,
      sysfsPath: entry.sysfsPath,
    })),
    hidraw: snapshot.hidraw.map((entry) => ({
      serial: entry.hid.unique,
      devicePath: entry.devicePath,
      hidDevicePath: entry.hidDevicePath,
      rdevHex: entry.stat?.rdevHex ?? null,
      inode: entry.stat?.inode ?? null,
    })),
    errors: snapshot.errors,
  };
}

function verifyHostTimeline(entries, run) {
  assertion(Array.isArray(entries) && entries.length >= 14, 'host poll is incomplete');
  const signalTargetEntry = entries.at(-2);
  const cleanupEntry = entries.at(-1);
  assertion(
    sameCanonical(signalTargetEntry, run.observations.preSignal.host) &&
      sameCanonical(cleanupEntry, run.cleanup.host),
    'host poll does not end with the exact signal-target and cleanup snapshots'
  );
  const causalEntries = entries.slice(0, -2);
  let previous = null;
  for (const entry of entries) {
    const current = monotonicNs(entry.monotonicNs, 'host poll');
    assertion(
      previous === null || current > previous,
      'host poll monotonic chronology is not strict'
    );
    previous = current;
    wallNs(entry.capturedAt, 'host poll wall timestamp');
    assertion(
      Array.isArray(entry.errors) && entry.errors.length === 0,
      'host poll contains an observation error'
    );
  }
  const fullIndexes = causalEntries.flatMap((entry, index) =>
    entry.stage.endsWith('-full') ? [index] : []
  );
  assertion(
    fullIndexes.length === 3 &&
      causalEntries[fullIndexes[0]].stage === 'present-full' &&
      causalEntries[fullIndexes[1]].stage === 'absent-full' &&
      causalEntries[fullIndexes[2]].stage === 'present-full',
    'host poll lacks exact present/absent/present stable boundaries'
  );
  const groups = [
    {
      start: 0,
      end: fullIndexes[0],
      stage: 'present',
      snapshot: run.observations.preflight.host,
    },
    {
      start: fullIndexes[0] + 1,
      end: fullIndexes[1],
      stage: 'absent',
      snapshot: run.observations.absent.host,
    },
    {
      start: fullIndexes[1] + 1,
      end: fullIndexes[2],
      stage: 'present',
      snapshot: run.observations.returned.host,
    },
  ];
  for (const group of groups) {
    assertion(group.end - group.start + 1 >= 4, `host ${group.stage} boundary is not stable`);
    const members = causalEntries.slice(group.start, group.end + 1);
    assertion(
      members.slice(0, -1).every((entry) => entry.stage === group.stage) &&
        members.at(-1).stage === `${group.stage}-full` &&
        members.slice(-4).every((entry) => entry.state === group.stage) &&
        sameCanonical(members.at(-1), compactHostSnapshot(group.snapshot, `${group.stage}-full`)),
      `host ${group.stage} boundary is not an exact three-poll plus full receipt`
    );
  }
  assertion(
    fullIndexes[2] === causalEntries.length - 1,
    'host poll contains observations after the returned stable boundary'
  );
}

function verifyRuntimeObservation(runtime, run, label) {
  verifyContainerBoundary(runtime, run, label);
  const captured = wallNs(runtime.capturedAt, `${label} runtime capture`);
  const observerCaptured = wallNs(runtime.observer.capturedAt, `${label} observer capture`);
  const observed = monotonicNs(runtime.monotonicNs, `${label} runtime monotonic`);
  const observerObserved = monotonicNs(runtime.observer.monotonicNs, `${label} observer monotonic`);
  assertion(
    observerCaptured <= captured && observerObserved <= observed,
    `${label} runtime predates its observer receipt`
  );
  verifyMarkerReceipt(
    runtime.markers,
    run.device.serial,
    [run.companion.compatibilityPath, run.companion.dynamicPath],
    label
  );
}

function embeddedRuntimeInPoll(entries, embedded, label) {
  const matches = entries.filter((entry) => sameCanonical(entry, embedded));
  assertion(matches.length === 1, `runtime poll does not contain one exact ${label} observation`);
}

function verifyRuntimePoll(entries, run) {
  assertion(Array.isArray(entries) && entries.length >= 5, 'runtime poll is incomplete');
  let previous = null;
  const order = {
    'baseline-poll': 0,
    'absent-poll': 1,
    'pre-signal-poll': 2,
    'signal-target-revalidate': 3,
    'post-signal-poll': 4,
  };
  let phaseOrder = -1;
  for (const [index, runtime] of entries.entries()) {
    assertion(Object.hasOwn(order, runtime.phase), `runtime poll ${index} has an unknown phase`);
    assertion(order[runtime.phase] >= phaseOrder, 'runtime poll phases are interleaved');
    phaseOrder = order[runtime.phase];
    const current = monotonicNs(runtime.monotonicNs, `runtime poll ${index}`);
    assertion(
      previous === null || current > previous,
      'runtime poll monotonic chronology is not strict'
    );
    previous = current;
    verifyRuntimeObservation(runtime, run, `runtime poll ${index}`);
  }
  for (const phase of Object.keys(order)) {
    const count = entries.filter((entry) => entry.phase === phase).length;
    assertion(
      phase === 'signal-target-revalidate' ? count === 1 : count >= 1,
      `runtime poll has invalid ${phase} cardinality`
    );
  }
  embeddedRuntimeInPoll(entries, run.observations.initial.runtime, 'initial');
  embeddedRuntimeInPoll(entries, run.observations.absent.runtime, 'absent');
  embeddedRuntimeInPoll(entries, run.observations.returned.runtime, 'returned');
  embeddedRuntimeInPoll(entries, run.observations.preSignal.runtime, 'signal target');
  embeddedRuntimeInPoll(entries, run.observations.postSignal.runtime, 'post-signal final');
  const preSignal = entries.filter((entry) => entry.phase === 'pre-signal-poll');
  const postSignal = entries.filter((entry) => entry.phase === 'post-signal-poll');
  assertion(
    sameCanonical(preSignal[0], run.observations.returned.runtime) &&
      sameCanonical(
        entries.find((entry) => entry.phase === 'signal-target-revalidate'),
        run.observations.preSignal.runtime
      ) &&
      sameCanonical(postSignal.at(-1), run.observations.postSignal.runtime),
    'embedded runtime endpoints do not match their raw causal phases'
  );
  return {
    all: entries,
    baseline: entries.filter((entry) => entry.phase === 'baseline-poll'),
    absent: entries.filter((entry) => entry.phase === 'absent-poll'),
    preSignal,
    signalTarget: entries.find((entry) => entry.phase === 'signal-target-revalidate'),
    postSignal,
  };
}

function verifyCumulativeLogs(logs, run, runtimeGroups) {
  const paths = [run.companion.compatibilityPath, run.companion.dynamicPath];
  const receipts = {
    initial: countAcquisitionMarkers(logs.initial, run.device.serial, paths),
    absent: countAcquisitionMarkers(logs.absent, run.device.serial, paths),
    preSignal: countAcquisitionMarkers(logs.preSignal, run.device.serial, paths),
    final: countAcquisitionMarkers(logs.final, run.device.serial, paths),
  };
  assertion(
    sameCanonical(receipts.initial, run.observations.initial.runtime.markers) &&
      sameCanonical(receipts.absent, run.observations.absent.runtime.markers) &&
      sameCanonical(receipts.preSignal, run.observations.preSignal.runtime.markers) &&
      sameCanonical(receipts.final, run.observations.postSignal.runtime.markers),
    'embedded acquisition markers differ from raw Docker logs'
  );
  assertion(
    logs.absent.startsWith(logs.initial) &&
      logs.preSignal.startsWith(logs.absent) &&
      logs.final.startsWith(logs.preSignal),
    'Docker log artifacts are not cumulative exact prefixes'
  );
  const finalLines = receipts.final.relevantLines;
  for (const runtime of runtimeGroups.all) {
    assertion(
      runtime.markers.relevantLines.every((line, index) => finalLines[index] === line),
      `runtime ${runtime.phase} marker receipt is not a prefix of final raw logs`
    );
  }
  return receipts;
}

export function verifyCausalChronology(run, runtimeGroups) {
  const disconnect = run.windows.disconnect;
  const reconnect = run.windows.reconnect;
  const pre = run.windows.preSignal;
  const signal = run.windows.signal;
  const post = run.windows.postSignal;
  const initialRuntimeNs = monotonicNs(
    run.observations.initial.runtime.monotonicNs,
    'initial runtime'
  );
  const disconnectOpen = monotonicNs(disconnect.openedMonotonicNs, 'disconnect open');
  const disconnectClose = monotonicNs(disconnect.closedMonotonicNs, 'disconnect close');
  const absentHostNs = monotonicNs(run.observations.absent.host.monotonicNs, 'absent host');
  const absentRuntimeNs = monotonicNs(
    run.observations.absent.runtime.monotonicNs,
    'absent runtime'
  );
  const reconnectOpen = monotonicNs(reconnect.openedMonotonicNs, 'reconnect open');
  const reconnectClose = monotonicNs(reconnect.closedMonotonicNs, 'reconnect close');
  const returnedHostNs = monotonicNs(run.observations.returned.host.monotonicNs, 'returned host');
  assertion(
    initialRuntimeNs < disconnectOpen &&
      disconnectOpen < absentHostNs &&
      absentHostNs <= absentRuntimeNs &&
      absentRuntimeNs < disconnectClose &&
      disconnectClose < reconnectOpen &&
      reconnectOpen < returnedHostNs &&
      returnedHostNs < reconnectClose,
    'physical window chronology is not causal'
  );
  assertion(
    pre.startedAt === run.observations.returned.host.capturedAt &&
      pre.startedMonotonicNs === run.observations.returned.host.monotonicNs,
    'pre-signal control is not anchored to the returned host epoch'
  );
  const preStart = monotonicNs(pre.startedMonotonicNs, 'pre-signal start');
  const preComplete = monotonicNs(pre.completedMonotonicNs, 'pre-signal completion');
  const preDeadline = preStart + PRE_SIGNAL_NS;
  const boundaryIndex = runtimeGroups.preSignal.findIndex(
    (entry) => monotonicNs(entry.monotonicNs, 'pre-signal poll') >= preDeadline
  );
  assertion(
    pre.timeoutSeconds === 30 &&
      pre.deadlineExpired === preComplete >= preDeadline &&
      pre.deadlineExpired === true &&
      boundaryIndex === runtimeGroups.preSignal.length - 1 &&
      boundaryIndex >= 0 &&
      (boundaryIndex === 0 ||
        monotonicNs(
          runtimeGroups.preSignal[boundaryIndex - 1].monotonicNs,
          'pre-signal prior poll'
        ) < preDeadline) &&
      preComplete >=
        monotonicNs(runtimeGroups.preSignal.at(-1).monotonicNs, 'pre-signal boundary poll') &&
      pre.boundaryNegative === true,
    'pre-signal fixed deadline boundary is incomplete'
  );
  const signalTargetNs = monotonicNs(
    runtimeGroups.signalTarget.monotonicNs,
    'signal target revalidation'
  );
  const signalStart = monotonicNs(signal.startedMonotonicNs, 'signal start');
  const signalReceived = monotonicNs(signal.receivedMonotonicNs, 'signal delivery');
  assertion(
    preComplete <= signalTargetNs &&
      monotonicNs(runtimeGroups.preSignal.at(-1).monotonicNs, 'pre-signal last poll') <
        signalTargetNs &&
      signalTargetNs < signalStart &&
      signalStart < signalReceived,
    'negative control, revalidation, and signal chronology is invalid'
  );
  assertion(
    post.startedAt === signal.receivedAt &&
      post.startedMonotonicNs === signal.receivedMonotonicNs &&
      post.timeoutSeconds === 30,
    'post-signal window is not anchored to the signal receipt'
  );
  const postComplete = monotonicNs(post.completedMonotonicNs, 'post-signal completion');
  const postDeadline = signalReceived + POST_SIGNAL_NS;
  const firstBoundaryIndex = runtimeGroups.postSignal.findIndex(
    (entry) => monotonicNs(entry.monotonicNs, 'post-signal poll') >= postDeadline
  );
  assertion(
    runtimeGroups.postSignal.every((entry) => {
      const observed = monotonicNs(entry.monotonicNs, 'post-signal poll');
      return observed > signalReceived && observed <= postComplete;
    }),
    'post-signal poll escaped its declared window'
  );
  if (post.supportObserved) {
    assertion(
      post.deadlineExpired === postComplete >= postDeadline &&
        monotonicNs(runtimeGroups.postSignal.at(-1).monotonicNs, 'supporting post-signal poll') <=
          postDeadline,
      'supported observation crossed the fixed post-signal deadline'
    );
  } else {
    assertion(
      post.deadlineExpired === true &&
        postComplete >= postDeadline &&
        firstBoundaryIndex === runtimeGroups.postSignal.length - 1 &&
        firstBoundaryIndex >= 0 &&
        (firstBoundaryIndex === 0 ||
          monotonicNs(
            runtimeGroups.postSignal[firstBoundaryIndex - 1].monotonicNs,
            'post-signal prior poll'
          ) < postDeadline),
      'negative post-signal observation lacks its first deadline boundary poll'
    );
  }
  assertion(
    wallNs(run.startedAt, 'run start') <=
      wallNs(run.observations.preflight.host.capturedAt, 'preflight host') &&
      wallNs(post.completedAt, 'post-signal completion') <=
        wallNs(run.cleanup.experimentBoundaryAt, 'experiment boundary') &&
      wallNs(run.cleanup.experimentBoundaryAt, 'experiment boundary') <=
        wallNs(run.cleanup.startedAt, 'cleanup start') &&
      wallNs(run.cleanup.completedAt, 'cleanup completion') ===
        wallNs(run.completedAt, 'run completion'),
    'run wall-clock chronology is invalid'
  );
  return {
    preDeadline,
    preBoundaryIndex: boundaryIndex,
    signalReceived,
    postDeadline,
    postBoundaryIndex: firstBoundaryIndex,
  };
}

function expectedDockerRunArguments(run) {
  return [
    'run',
    '--detach',
    '--rm',
    '--name',
    run.companion.name,
    '--label',
    'dev.overlaykit.hypothesis=H-042',
    '--network',
    'none',
    '--cgroupns',
    'private',
    '--read-only',
    '--tmpfs',
    '/companion:rw,nosuid,nodev,noexec,size=268435456,uid=1000,gid=1000,mode=0700',
    '--tmpfs',
    '/tmp:rw,nosuid,nodev,size=67108864,uid=1000,gid=1000,mode=1777',
    '--cap-drop',
    'ALL',
    '--cap-add',
    'SETUID',
    '--cap-add',
    'SETGID',
    '--security-opt',
    'no-new-privileges',
    '--pids-limit',
    '128',
    '--memory',
    '1g',
    '--user',
    '0:0',
    '--group-add',
    String(run.companion.deviceGid),
    '--device-cgroup-rule',
    run.companion.deviceCgroupRule,
    '--mount',
    'type=bind,src=/dev,dst=/host-dev,readonly,bind-recursive=disabled',
    '--mount',
    `type=bind,src=${path.join(REPOSITORY_ROOT, 'lab/h041/entrypoint.sh')},dst=/h041-entrypoint.sh,readonly`,
    '--mount',
    `type=bind,src=${path.join(REPOSITORY_ROOT, 'lab/h041/container-observer.mjs')},dst=/h041-container-observer.mjs,readonly`,
    '--mount',
    `type=bind,src=${path.join(REPOSITORY_ROOT, 'lab/h042/signal-helper.mjs')},dst=/h042-signal-helper.mjs,readonly`,
    '--env',
    'H041_UID=1000',
    '--env',
    'H041_GID=1000',
    '--env',
    `H041_DEVICE_GID=${run.companion.deviceGid}`,
    '--env',
    `H041_DYNAMIC_PATH=${run.companion.dynamicPath}`,
    '--env',
    `H041_COMPAT_PATH=${run.companion.compatibilityPath}`,
    '--entrypoint',
    '/bin/bash',
    OFFICIAL_IMAGE,
    '/h041-entrypoint.sh',
  ];
}

export function verifyInvocationAudit(run, runtimeGroups, signalReceiptText) {
  const audit = run.invocationAudit;
  const entries = audit.entries;
  const allowed = new Set([
    'docker-run',
    'docker-inspect',
    'docker-exec-observer',
    'docker-logs',
    'physical-disconnect-window',
    'physical-reconnect-window',
    'docker-exec-signal',
    'docker-events-experiment',
    'experiment-classified',
    'docker-stop',
    'docker-ps-cleanup',
    'docker-events-cleanup',
  ]);
  assertion(Array.isArray(entries), 'invocation audit entries are missing');
  let prior = null;
  for (const entry of entries) {
    const current = monotonicNs(entry.monotonicNs, 'audit entry');
    assertion(
      allowed.has(entry.kind) && (prior === null || current > prior) && validDateTime(entry.at),
      'invocation audit contains a forbidden action or non-strict chronology'
    );
    prior = current;
  }
  const byKind = (kind) => entries.filter((entry) => entry.kind === kind);
  const only = (kind) => {
    const matches = byKind(kind);
    assertion(matches.length === 1, `invocation audit has invalid ${kind} cardinality`);
    return matches[0];
  };
  const runEntry = only('docker-run');
  assertion(
    runEntry.phase === 'setup' &&
      runEntry.target === run.companion.name &&
      runEntry.imageReference === OFFICIAL_IMAGE &&
      runEntry.runnerDeviceIo === false &&
      sameCanonical(runEntry.arguments, expectedDockerRunArguments(run)),
    'docker-run audit does not bind the exact sandbox arguments'
  );
  const disconnect = only('physical-disconnect-window');
  const reconnect = only('physical-reconnect-window');
  assertion(
    disconnect.phase === 'disconnect' &&
      disconnect.challenge === run.windows.disconnect.challenge &&
      disconnect.expectedActor === 'human-principal' &&
      reconnect.phase === 'reconnect' &&
      reconnect.challenge === run.windows.reconnect.challenge &&
      reconnect.expectedActor === 'human-principal',
    'physical-window audit is not challenge-bound'
  );
  const signals = byKind('docker-exec-signal');
  assertion(signals.length === 1, 'invocation audit did not record exactly one signal exec');
  const signal = signals[0];
  const oldWorker = run.observations.initial.runtime.observer.surfaceWorkers[0];
  assertion(
    signal.phase === 'fault-injection' &&
      signal.target === run.companion.name &&
      signal.user === '1000:1000' &&
      signal.signal === 'SIGTERM' &&
      signal.exitCode === 0 &&
      sameCanonical(signal.command, [
        '/app/node-runtimes/main/bin/node',
        '/h042-signal-helper.mjs',
      ]) &&
      sameCanonical(signal.processTarget, exactSignalTarget(oldWorker)) &&
      signal.receiptSha256 === sha256(signalReceiptText),
    'signal audit is not exact'
  );
  const observerEntries = byKind('docker-exec-observer');
  const logEntries = byKind('docker-logs');
  const inspectEntries = byKind('docker-inspect');
  assertion(
    observerEntries.length === runtimeGroups.all.length &&
      logEntries.length === runtimeGroups.all.length &&
      inspectEntries.length === runtimeGroups.all.length * 2,
    'runtime metadata audit cardinality differs from raw runtime polls'
  );
  const phaseCounts = Object.groupBy(runtimeGroups.all, (entry) => entry.phase);
  for (const [phase, runtimes] of Object.entries(phaseCounts)) {
    assertion(
      observerEntries.filter((entry) => entry.phase === phase).length === runtimes.length &&
        logEntries.filter((entry) => entry.phase === phase).length === runtimes.length &&
        inspectEntries.filter((entry) => entry.phase === phase).length === runtimes.length &&
        inspectEntries.filter((entry) => entry.phase === `${phase}-revalidate`).length ===
          runtimes.length,
      `runtime audit does not exactly cover ${phase}`
    );
  }
  assertion(
    observerEntries.every(
      (entry) =>
        entry.target === run.companion.name &&
        entry.user === '1000:1000' &&
        entry.operation === 'proc-fd-stat-only' &&
        sameCanonical(entry.command, [
          '/app/node-runtimes/main/bin/node',
          '/h041-container-observer.mjs',
        ])
    ) &&
      logEntries.every(
        (entry) =>
          entry.target === run.companion.name && entry.operation === 'read-container-stdout-stderr'
      ) &&
      inspectEntries.every(
        (entry) => entry.target === run.companion.name && entry.operation === 'metadata'
      ),
    'runtime metadata audit contains an expanded operation'
  );
  const experimentEvents = only('docker-events-experiment');
  const classification = only('experiment-classified');
  const stop = only('docker-stop');
  const ps = only('docker-ps-cleanup');
  const cleanupEvents = only('docker-events-cleanup');
  assertion(
    experimentEvents.target === run.companion.containerId &&
      experimentEvents.since === run.startedAt &&
      experimentEvents.until === run.cleanup.experimentBoundaryAt &&
      classification.experimentBoundaryAt === run.cleanup.experimentBoundaryAt &&
      classification.outcome === run.outcome.status &&
      classification.stage === run.outcome.stage &&
      stop.target === run.companion.name &&
      stop.timeoutSeconds === 5 &&
      ps.target === run.companion.name &&
      cleanupEvents.target === run.companion.containerId &&
      cleanupEvents.since === run.cleanup.experimentBoundaryAt &&
      cleanupEvents.until === run.cleanup.eventsUntilAt,
    'event/classification/cleanup audit boundaries are not exact'
  );
  assertion(
    wallNs(run.cleanup.experimentBoundaryAt, 'experiment boundary') <=
      wallNs(experimentEvents.at, 'experiment event audit') &&
      wallNs(run.cleanup.classificationCompletedAt, 'classification completion') <=
        wallNs(classification.at, 'classification audit') &&
      wallNs(run.cleanup.startedAt, 'cleanup start') <= wallNs(stop.at, 'cleanup stop audit') &&
      wallNs(run.cleanup.eventsUntilAt, 'cleanup event upper bound') <=
        wallNs(cleanupEvents.at, 'cleanup event audit'),
    'audit wall timestamps precede the boundaries they attest'
  );
  const causal = [
    runEntry,
    disconnect,
    reconnect,
    signal,
    experimentEvents,
    classification,
    stop,
    ps,
    cleanupEvents,
  ];
  assertion(
    causal.every(
      (entry, index) =>
        index === 0 || BigInt(entry.monotonicNs) > BigInt(causal[index - 1].monotonicNs)
    ),
    'invocation audit causal action order is invalid'
  );
  assertion(
    audit.mode === 'metadata-observation-plus-one-source-bound-surface-sigterm' &&
      sameCanonical(audit.forbidden, []) &&
      audit.signalCount === 1 &&
      audit.signalExact === true &&
      audit.exactCardinality === true &&
      audit.strictChronology === true &&
      audit.causalOrder === true &&
      audit.cleanupAfterClassification === true &&
      audit.runnerDeviceOpenCount === 0 &&
      audit.runnerDeviceReadCount === 0 &&
      audit.runnerDeviceWriteCount === 0 &&
      audit.virtualInvocationCount === 0 &&
      audit.forbiddenLifecycleCount === 0 &&
      audit.passed === true,
    'invocation audit summary is not independently exact'
  );
  return { signal, experimentEvents, classification, stop, ps, cleanupEvents };
}

function classifyDeviceTransition(initial, returned) {
  const samePath = initial.devicePath === returned.devicePath;
  const sameRdev = initial.stat.rdev === returned.stat.rdev;
  if (samePath && sameRdev) return 'same-path-same-rdev';
  if (samePath) return 'same-path-changed-rdev';
  if (sameRdev) return 'changed-path-same-rdev';
  return 'changed-path-changed-rdev';
}

function noEpochChange(left, right) {
  const before = exactPresentHostTuple(left, left.expectedSerial, 'stable epoch before');
  const after = exactPresentHostTuple(right, right.expectedSerial, 'stable epoch after');
  return (
    left.scope.bootId === right.scope.bootId &&
    left.scope.mountNamespace === right.scope.mountNamespace &&
    before.usb.deviceNumber === after.usb.deviceNumber &&
    before.node.hidDevicePath === after.node.hidDevicePath &&
    statIdentityEqual(before.node.stat, after.node.stat)
  );
}

function dynamicAccessMatches(runtime, hostNode, run) {
  const dynamic = runtime.observer.paths.dynamic.stat;
  const compatibility = runtime.observer.paths.compat.stat;
  return (
    dynamicStageMatchesHost(hostNode, dynamic) &&
    compatibility?.kind === 'value' &&
    statIdentityEqual(compatibility.value, hostNode.stat) &&
    sameDeviceAccessBoundary(hostNode.stat, dynamic.value) &&
    sameDeviceAccessBoundary(hostNode.stat, compatibility.value) &&
    dynamic.value.mode === '0660' &&
    dynamic.value.uid === 0 &&
    dynamic.value.gid === run.companion.deviceGid
  );
}

function verifyHostAndDevice(run, h041, runtimeGroups) {
  assertion(
    run.host.osId === 'fedora' &&
      run.host.osVersion === '43' &&
      run.host.kernel === h041.host.kernel &&
      run.host.architecture === h041.host.architecture &&
      run.host.machine === h041.host.machine &&
      sameCanonical(run.host.principal, h041.host.principal) &&
      run.host.principal.user === 'rod' &&
      run.host.principal.uid === 1000 &&
      run.host.principal.gid === 1000 &&
      run.host.principal.groups.some((group) => group.gid === 1002 && group.name === 'plugdev') &&
      run.host.graphicalSession.Name === run.host.principal.user &&
      run.host.graphicalSession.Active === 'yes' &&
      run.host.graphicalSession.State === 'active' &&
      run.host.graphicalSession.Class === 'user' &&
      run.host.graphicalSession.Remote === 'no' &&
      ['wayland', 'x11'].includes(run.host.graphicalSession.Type) &&
      typeof run.host.docker.version.Server?.Version === 'string' &&
      typeof run.host.docker.info.ServerVersion === 'string',
    'H-042 is not bound to the exact post-login Fedora principal'
  );
  assertion(
    run.device.vendorId === '0fd9' &&
      run.device.productId === '0080' &&
      run.device.serial === h041.device.serial &&
      run.device.model === h041.device.model &&
      run.companion.imageReference === OFFICIAL_IMAGE &&
      run.companion.imageId === EXPECTED_IMAGE_ID &&
      sameCanonical(run.companion.repoDigests, [OFFICIAL_REPO_DIGEST]) &&
      run.companion.version === 'v4.3.3' &&
      run.companion.revision === EXPECTED_IMAGE_REVISION &&
      run.companion.dynamicRoot === '/host-dev' &&
      run.companion.staticDevices.length === 0 &&
      run.companion.deviceGid === 1002,
    'H-042 image, device, or principal identity is not exact'
  );
  const serial = run.device.serial;
  const preflight = exactPresentHostTuple(run.observations.preflight.host, serial, 'preflight');
  const initial = exactPresentHostTuple(run.observations.initial.host, serial, 'initial');
  assertAbsentHostSnapshot(run.observations.absent.host, serial, 'absent');
  const returned = exactPresentHostTuple(run.observations.returned.host, serial, 'returned');
  const signalTarget = exactPresentHostTuple(
    run.observations.preSignal.host,
    serial,
    'signal target'
  );
  const cleanup = exactPresentHostTuple(run.cleanup.host, serial, 'cleanup');
  assertion(
    preflight.node.owner?.applicable === true &&
      preflight.node.owner.observed === true &&
      preflight.node.owner.usageError === false &&
      preflight.node.owner.pids.length === 0 &&
      signalTarget.node.owner?.applicable === true &&
      signalTarget.node.owner.observed === true &&
      signalTarget.node.owner.usageError === false &&
      signalTarget.node.owner.pids.length === 0,
    'preflight or signal target did not prove a free host-scope device'
  );
  const scopes = [
    run.observations.preflight.host,
    run.observations.initial.host,
    run.observations.absent.host,
    run.observations.returned.host,
    run.observations.preSignal.host,
    run.cleanup.host,
  ].map((snapshot) => snapshot.scope);
  assertion(
    scopes.every(
      (scope) =>
        scope.bootId === scopes[0].bootId && scope.mountNamespace === scopes[0].mountNamespace
    ),
    'host boot or mount namespace changed during H-042'
  );
  assertion(
    noEpochChange(run.observations.preflight.host, run.observations.initial.host) &&
      hostEpochChanged(run.observations.initial.host, run.observations.returned.host) &&
      noEpochChange(run.observations.returned.host, run.observations.preSignal.host) &&
      noEpochChange(run.observations.preSignal.host, run.cleanup.host),
    'H-042 does not isolate exactly one USB enumeration epoch'
  );
  assertion(
    run.device.initialPath === initial.node.devicePath &&
      run.device.returnedPath === returned.node.devicePath &&
      run.device.initialRdevHex === initial.node.stat.rdevHex &&
      run.device.returnedRdevHex === returned.node.stat.rdevHex &&
      run.device.transition === classifyDeviceTransition(initial.node, returned.node) &&
      initial.node.devicePath === returned.node.devicePath &&
      sameDeviceAccessBoundary(initial.node.stat, returned.node.stat) &&
      returned.node.devicePath === signalTarget.node.devicePath &&
      sameDeviceAccessBoundary(returned.node.stat, signalTarget.node.stat),
    'device transition or access boundary changed'
  );
  const initialInventory = selectExactInventory(run.device.initialInventory, {
    serial,
    path: initial.node.devicePath,
    label: 'initial',
  });
  const returnedInventory = selectExactInventory(run.device.returnedInventory, {
    serial,
    path: returned.node.devicePath,
    label: 'returned',
  });
  assertion(
    sameDeviceAccessBoundary(initial.node.stat, initialInventory.stat.value) &&
      sameDeviceAccessBoundary(returned.node.stat, returnedInventory.stat.value) &&
      initialInventory.usbAncestor.deviceNumber === initial.usb.deviceNumber &&
      returnedInventory.usbAncestor.deviceNumber === returned.usb.deviceNumber,
    'host inventory is not bound to both observed epochs'
  );
  assertion(
    run.companion.dynamicPath === `/host-dev/${path.basename(returned.node.devicePath)}` &&
      run.companion.compatibilityPath === returned.node.devicePath &&
      run.companion.deviceCgroupRule ===
        `c ${returned.node.stat.major}:${returned.node.stat.minor} rw`,
    'Companion device path or cgroup rule is not current-epoch bound'
  );
  for (const runtime of runtimeGroups.baseline) {
    assertion(
      dynamicAccessMatches(runtime, initial.node, run),
      'baseline dynamic device does not match the initial host epoch'
    );
  }
  for (const runtime of runtimeGroups.absent) {
    assertion(
      descriptorAbsent(runtime),
      'absent runtime poll retained a dynamic path or descriptor'
    );
  }
  for (const runtime of [
    ...runtimeGroups.preSignal,
    runtimeGroups.signalTarget,
    ...runtimeGroups.postSignal,
  ]) {
    assertion(
      dynamicAccessMatches(runtime, signalTarget.node, run),
      `${runtime.phase} dynamic device does not match the returned host epoch`
    );
  }
  assertion(
    sameCanonical(run.companion.initialLifecycle, run.observations.initial.runtime.lifecycle) &&
      sameCanonical(run.companion.absentLifecycle, run.observations.absent.runtime.lifecycle) &&
      sameCanonical(
        run.companion.preSignalLifecycle,
        run.observations.preSignal.runtime.lifecycle
      ) &&
      sameCanonical(
        run.companion.postSignalLifecycle,
        run.observations.postSignal.runtime.lifecycle
      ) &&
      sameCanonical(
        run.companion.workerLifecycle.initial,
        run.observations.initial.runtime.observer.surfaceWorkers
      ) &&
      sameCanonical(
        run.companion.workerLifecycle.absent,
        run.observations.absent.runtime.observer.surfaceWorkers
      ) &&
      sameCanonical(
        run.companion.workerLifecycle.preSignal,
        run.observations.preSignal.runtime.observer.surfaceWorkers
      ) &&
      sameCanonical(
        run.companion.workerLifecycle.postSignal,
        run.observations.postSignal.runtime.observer.surfaceWorkers
      ),
    'Companion lifecycle summary differs from raw observations'
  );
  assertion(
    run.cleanup.returnedNodeAccess.exact === true &&
      sameCanonical(run.cleanup.returnedNodeAccess.reference, {
        devicePath: signalTarget.node.devicePath,
        stat: signalTarget.node.stat,
      }) &&
      sameCanonical(run.cleanup.returnedNodeAccess.observed, {
        devicePath: cleanup.node.devicePath,
        stat: cleanup.node.stat,
      }) &&
      sameDeviceAccessBoundary(
        run.cleanup.returnedNodeAccess.reference.stat,
        run.cleanup.returnedNodeAccess.observed.stat
      ) &&
      run.cleanup.owners.length === 1 &&
      run.cleanup.owners[0].devicePath === cleanup.node.devicePath &&
      run.cleanup.owners[0].owner.observed === true &&
      run.cleanup.owners[0].owner.usageError === false &&
      run.cleanup.owners[0].owner.pids.length === 0,
    'cleanup did not release the exact returned node'
  );
  return { preflight, initial, returned, signalTarget, cleanup };
}

function experimentReceiptFromIndependent(analysis) {
  const healthcheckIds = [...analysis.healthcheckExecIds].sort();
  return {
    passed: true,
    experimentStartedAt: analysis.experimentStartedAt,
    experimentBoundaryAt: analysis.experimentBoundaryAt,
    execId: analysis.execId,
    helperCreateCount: 1,
    helperStartCount: 1,
    helperDieZeroCount: 1,
    ordered: true,
    forbiddenActions: [],
    containerStartExact: true,
    healthStatusEvents: analysis.healthStatusEvents,
    unexpectedActions: [],
    execCreateCount: analysis.execCreateCount,
    observerExecCount: analysis.observerExecCount,
    healthcheck: {
      command: HEALTHCHECK_COMMAND,
      createCount: healthcheckIds.length,
      tripletCount: healthcheckIds.length,
      execIds: healthcheckIds,
      complete: true,
    },
    unknownExecEvents: [],
    incompleteExecIds: [],
    unscopedEvents: [],
    timestampsWithinWindow: true,
    execBoundaryExact: true,
  };
}

function cleanupReceiptFromIndependent(analysis) {
  return {
    passed: true,
    experimentBoundaryAt: analysis.experimentBoundaryAt,
    classifiedAt: analysis.classifiedAt,
    eventsUntilAt: analysis.eventsUntilAt,
    eventCount: analysis.eventCount,
    timestampsValid: true,
    unscopedEvents: [],
    gap: {
      eventCount: analysis.gap.eventCount,
      healthcheck: analysis.gap.healthcheck,
      healthStatusEvents: analysis.gap.healthStatusEvents,
      unknownExecEvents: [],
      incompleteExecIds: [],
      unknownActions: [],
      boundaryExact: true,
    },
    cleanup: {
      eventCount: analysis.cleanup.eventCount,
      stopCount: analysis.cleanup.stopCount,
      dieCount: analysis.cleanup.dieCount,
      destroyCount: analysis.cleanup.destroyCount,
      killCount: analysis.cleanup.killCount,
      kill15Count: analysis.cleanup.signal15Count,
      kill9Count: analysis.cleanup.signal9Count,
      dieExitCode: analysis.cleanup.dieExitCode,
      healthcheck: analysis.cleanup.healthcheck,
      healthStatusEvents: analysis.cleanup.healthStatusEvents,
      unknownExecEvents: [],
      incompleteExecIds: [],
      unknownActions: [],
      lifecycleOrdered: true,
      boundaryExact: true,
    },
  };
}

function verifyDockerEventReceipts(run, experimentEvents, cleanupEvents, runtimeGroups) {
  const experiment = analyzeExperimentDockerEvents(experimentEvents, {
    containerId: run.companion.containerId,
    expectedObserverExecCount: runtimeGroups.all.length,
    signalStartedAt: run.windows.signal.startedAt,
    signalReceivedAt: run.windows.signal.receivedAt,
    experimentStartedAt: run.startedAt,
    experimentBoundaryAt: run.cleanup.experimentBoundaryAt,
  });
  assertion(
    sameCanonical(
      run.observations.postSignal.dockerEvents,
      experimentReceiptFromIndependent(experiment)
    ),
    'producer experiment Docker-event analysis differs from independent reconstruction'
  );
  const cleanup = analyzeCleanupDockerEvents(cleanupEvents, {
    containerId: run.companion.containerId,
    experimentBoundaryAt: run.cleanup.experimentBoundaryAt,
    classificationCompletedAt: run.cleanup.classificationCompletedAt,
    eventsUntilAt: run.cleanup.eventsUntilAt,
  });
  assertion(
    sameCanonical(run.cleanup.dockerEventsAnalysis, cleanupReceiptFromIndependent(cleanup)),
    'producer cleanup Docker-event analysis differs from independent reconstruction'
  );
  const experimentBoundary = wallNs(run.cleanup.experimentBoundaryAt, 'experiment boundary');
  const classified = wallNs(run.cleanup.classificationCompletedAt, 'classification boundary');
  const cleanupStart = wallNs(run.cleanup.startedAt, 'cleanup start');
  const eventsUntil = wallNs(run.cleanup.eventsUntilAt, 'cleanup events until');
  const cleanupComplete = wallNs(run.cleanup.completedAt, 'cleanup complete');
  assertion(
    experimentBoundary <= classified &&
      classified <= cleanupStart &&
      cleanupStart <= eventsUntil &&
      eventsUntil <= cleanupComplete &&
      BigInt(experimentEvents.at(-1).timeNano) <= experimentBoundary &&
      BigInt(cleanupEvents[0].timeNano) > experimentBoundary &&
      BigInt(cleanupEvents.at(-1).timeNano) <= eventsUntil,
    'Docker event streams leave a gap or cross their declared temporal partition'
  );
  return { experiment, cleanup };
}

function verifyCleanup(run) {
  assertion(
    run.cleanup.containerId === run.companion.containerId &&
      run.cleanup.containerRemoved === true &&
      run.cleanup.hostConfigurationChanged === false &&
      run.cleanup.productionConfigurationChanged === false &&
      run.cleanup.successful === true &&
      run.cleanup.error === null,
    'H-042 cleanup summary is not successful and exact'
  );
}

function replacementOwnsCurrentDescriptor(replacement, runtime) {
  if (replacement === null) return false;
  const matching = matchingTargetDescriptors(runtime);
  return replacement.fileDescriptors.some((descriptor) =>
    matching.some((candidate) => sameCanonical(candidate, descriptor))
  );
}

function reconstructPostSignal(run, runtimeGroups, chronology) {
  const oldWorker = run.observations.initial.runtime.observer.surfaceWorkers[0];
  const before = run.observations.preSignal.runtime.markers;
  const bounded = runtimeGroups.postSignal.filter(
    (runtime) => BigInt(runtime.monotonicNs) <= chronology.postDeadline
  );
  let descriptorObserved = false;
  let openingObserved = false;
  let readyObserved = false;
  let markersOrdered = false;
  let supportObserved = false;
  for (let index = 0; index < runtimeGroups.postSignal.length; index += 1) {
    const runtime = runtimeGroups.postSignal[index];
    if (BigInt(runtime.monotonicNs) > chronology.postDeadline) continue;
    const timeline = reconstructReplacementTimeline(
      oldWorker,
      runtimeGroups.postSignal.slice(0, index + 1),
      run.companion.deviceGid
    );
    const delta = recomputeMarkerDelta(before, runtime.markers, run.windows.signal.receivedAt);
    const descriptor = replacementOwnsCurrentDescriptor(timeline.replacement, runtime);
    const markerTimeExact =
      delta.prefixValid &&
      delta.allAfterSignal &&
      markersWithinConservativeWallDeadline(delta, run.windows.signal.receivedAt);
    descriptorObserved ||= descriptor;
    openingObserved ||= delta.openingObserved && delta.allAfterSignal;
    readyObserved ||= delta.readyObserved && delta.allAfterSignal;
    markersOrdered ||= delta.ordered && markerTimeExact;
    supportObserved ||=
      timeline.oldWorkerExited &&
      timeline.replacementWorkerUnique &&
      timeline.singleReplacementGeneration &&
      timeline.replacementWorkerChanged &&
      descriptor &&
      delta.openingObserved &&
      delta.readyObserved &&
      delta.ordered &&
      markerTimeExact;
  }
  const boundedTimeline = reconstructReplacementTimeline(
    oldWorker,
    bounded,
    run.companion.deviceGid
  );
  const fullTimeline = reconstructReplacementTimeline(
    oldWorker,
    runtimeGroups.postSignal,
    run.companion.deviceGid
  );
  const final = runtimeGroups.postSignal.at(-1);
  const finalDelta = recomputeMarkerDelta(before, final.markers, run.windows.signal.receivedAt);
  const latePositiveObserved =
    !supportObserved &&
    ((!boundedTimeline.oldWorkerExited && fullTimeline.oldWorkerExited) ||
      (!boundedTimeline.replacementWorkerUnique && fullTimeline.replacementWorkerUnique) ||
      (!descriptorObserved && replacementOwnsCurrentDescriptor(fullTimeline.replacement, final)) ||
      (!openingObserved && finalDelta.openingObserved) ||
      (!readyObserved && finalDelta.readyObserved));
  return {
    fullTimeline,
    boundedTimeline,
    finalDelta,
    descriptorObserved,
    openingObserved,
    readyObserved,
    markersOrdered,
    supportObserved,
    latePositiveObserved,
  };
}

export function classifyOutcomeIndependent(predicates) {
  if (
    !exactKeys(predicates, PREDICATE_KEYS) ||
    PREDICATE_KEYS.some((key) => typeof predicates[key] !== 'boolean')
  ) {
    return {
      status: 'inconclusive',
      stage: 'predicate-envelope',
      reason: 'The H-042 predicate envelope is malformed, partial, or expanded.',
    };
  }
  const failedPrecondition = PRECONDITION_KEYS.find((key) => predicates[key] !== true);
  if (failedPrecondition !== undefined) {
    return {
      status: 'inconclusive',
      stage: 'precondition',
      reason: `The required H-042 precondition ${failedPrecondition} was not established.`,
    };
  }
  if (predicates.latePositiveObserved || !predicates.deadlineBoundaryConsistent) {
    return {
      status: 'inconclusive',
      stage: 'deadline-boundary',
      reason:
        'Positive or mixed evidence crossed the causal deadline, so its event time cannot be attributed to the bounded signal.',
    };
  }
  if (!predicates.topLevelLifecycleUnchanged || !predicates.singleReplacementGeneration) {
    return {
      status: 'inconclusive',
      stage: 'worker-replacement',
      reason:
        'The unchanged container/PID 1 boundary or a single unambiguous replacement generation was not established.',
    };
  }
  if (!predicates.postSignalObservationComplete) {
    return {
      status: 'inconclusive',
      stage: 'post-signal-observation',
      reason: 'The post-signal observation did not reach a complete causal boundary.',
    };
  }
  if (!predicates.oldWorkerExited) {
    return {
      status: 'refuted',
      stage: 'worker-termination',
      reason:
        'One exact successful SIGTERM was followed by a complete observation in which the original SurfaceThread tuple did not terminate.',
    };
  }
  if (!predicates.replacementWorkerUnique) {
    return {
      status: 'refuted',
      stage: 'worker-respawn',
      reason:
        'The original SurfaceThread terminated, but no unique replacement worker appeared during the complete bounded observation.',
    };
  }
  if (!predicates.replacementWorkerChanged) {
    return {
      status: 'inconclusive',
      stage: 'worker-lineage',
      reason:
        'The observed replacement could not be proven distinct from the terminated worker tuple.',
    };
  }
  const supported =
    predicates.postSignalDescriptorObserved &&
    predicates.postSignalOpeningObserved &&
    predicates.postSignalReadyObserved &&
    predicates.postSignalMarkersOrdered &&
    predicates.postSignalWithinDeadline;
  if (supported) {
    return {
      status: 'supported',
      stage: 'surface-worker-reacquisition',
      reason:
        'One exact SIGTERM was followed by a unique replacement worker, current-epoch descriptor, and ordered opening/ready markers within 30 seconds under unchanged container and PID 1.',
    };
  }
  const positiveCount = [
    predicates.postSignalDescriptorObserved,
    predicates.postSignalOpeningObserved,
    predicates.postSignalReadyObserved,
  ].filter(Boolean).length;
  if (
    positiveCount > 0 ||
    predicates.postSignalMarkersOrdered ||
    predicates.postSignalWithinDeadline
  ) {
    return {
      status: 'inconclusive',
      stage: 'mixed-reacquisition',
      reason:
        'The post-signal observation is partial or mixed and cannot establish either complete reacquisition or a complete negative result.',
    };
  }
  if (predicates.postSignalObservationComplete) {
    return {
      status: 'refuted',
      stage: 'surface-worker-reacquisition',
      reason:
        'The exact worker was replaced under unchanged container and PID 1, but a complete 30-second observation found no current descriptor and no new opening or ready marker.',
    };
  }
  return {
    status: 'inconclusive',
    stage: 'post-signal-observation',
    reason: 'The post-signal observation did not reach a complete support or negative boundary.',
  };
}

export function recomputePredicatesIndependent(
  run,
  { runtimeGroups, chronology, experimentEventAnalysis, invocationAuditExact }
) {
  const oldWorker = run.observations.initial.runtime.observer.surfaceWorkers[0];
  const signalTargetWorkers = runtimeGroups.signalTarget.observer.surfaceWorkers;
  const signalTarget = signalTargetWorkers.length === 1 ? signalTargetWorkers[0] : null;
  const preSignalNegative =
    descriptorAbsent(run.observations.absent.runtime) &&
    run.observations.absent.runtime.observer.surfaceWorkers.length === 1 &&
    sameWorker(oldWorker, run.observations.absent.runtime.observer.surfaceWorkers[0]) &&
    runtimeGroups.preSignal.every(
      (runtime) =>
        runtime.observer.surfaceWorkers.length === 1 &&
        sameWorker(oldWorker, runtime.observer.surfaceWorkers[0]) &&
        matchingTargetDescriptors(runtime).length === 0 &&
        markersUnchanged(run.observations.absent.runtime.markers, runtime.markers)
    );
  const topLevelLifecycleUnchanged = runtimeGroups.all.every((runtime) =>
    sameLifecycle(run.observations.initial.runtime.lifecycle, runtime.lifecycle)
  );
  const post = reconstructPostSignal(run, runtimeGroups, chronology);
  const predicates = {
    complete: true,
    permissionBoundaryExact: true,
    hostEpochChanged: hostEpochChanged(
      run.observations.initial.host,
      run.observations.returned.host
    ),
    dynamicViewTracksHost: true,
    baselineAcquired: baselineAcquired(run.observations.initial.runtime, run),
    preSignalWindowComplete:
      run.windows.preSignal.deadlineExpired === true &&
      run.windows.preSignal.boundaryNegative === true &&
      chronology.preBoundaryIndex === runtimeGroups.preSignal.length - 1,
    preSignalNegative,
    signalTargetUnique:
      signalTarget !== null &&
      exactWorkerIdentity(
        signalTarget,
        runtimeGroups.signalTarget.lifecycle,
        run.companion.deviceGid
      ) !== null,
    signalTargetRevalidated:
      signalTarget !== null &&
      sameWorker(oldWorker, signalTarget) &&
      sameWorker(run.windows.signal.receipt.observed, signalTarget) &&
      matchingTargetDescriptors(runtimeGroups.signalTarget).length === 0 &&
      markersUnchanged(
        run.observations.absent.runtime.markers,
        runtimeGroups.signalTarget.markers
      ) &&
      run.windows.signal.receipt.observed.targetHidrawDescriptors.length === 0,
    exactlyOneSigterm:
      run.invocationAudit.entries.filter((entry) => entry.kind === 'docker-exec-signal').length ===
        1 &&
      experimentEventAnalysis.helperCreateCount === 1 &&
      experimentEventAnalysis.helperStartCount === 1 &&
      experimentEventAnalysis.helperDieZeroCount === 1,
    signalSucceeded: run.windows.signal.exitCode === 0 && experimentEventAnalysis.ordered === true,
    invocationAuditExact: invocationAuditExact && experimentEventAnalysis.passed === true,
    topLevelLifecycleUnchanged,
    oldWorkerExited: post.fullTimeline.oldWorkerExited,
    replacementWorkerUnique: post.fullTimeline.replacementWorkerUnique,
    singleReplacementGeneration: post.fullTimeline.singleReplacementGeneration,
    replacementWorkerChanged: post.fullTimeline.replacementWorkerChanged,
    postSignalObservationComplete:
      post.supportObserved || run.windows.postSignal.deadlineExpired === true,
    postSignalDescriptorObserved: post.descriptorObserved,
    postSignalOpeningObserved: post.openingObserved,
    postSignalReadyObserved: post.readyObserved,
    postSignalMarkersOrdered: post.markersOrdered,
    postSignalWithinDeadline: post.supportObserved,
    deadlineBoundaryConsistent:
      post.finalDelta.prefixValid &&
      (post.supportObserved ||
        (run.windows.postSignal.deadlineExpired === true && !post.latePositiveObserved)),
    latePositiveObserved: post.latePositiveObserved,
  };
  assertion(
    sameCanonical(run.observations.preSignal.markers, {
      baseline: run.observations.absent.runtime.markers,
      final: runtimeGroups.signalTarget.markers,
    }) &&
      sameCanonical(run.observations.preSignal.control, {
        descriptorObserved: false,
        openingObserved: false,
        readyObserved: false,
        boundaryNegative: true,
      }),
    'pre-signal observation summary differs from raw negative control'
  );
  assertion(
    sameCanonical(run.observations.postSignal.replacement, post.fullTimeline) &&
      sameCanonical(run.observations.postSignal.markerDelta, post.finalDelta) &&
      run.observations.postSignal.descriptorObserved === post.descriptorObserved &&
      run.observations.postSignal.latePositiveObserved === post.latePositiveObserved &&
      run.windows.postSignal.supportObserved === post.supportObserved,
    'post-signal observation summary differs from independent B-to-C reconstruction'
  );
  return { predicates, post };
}

export async function verifySurfaceWorkerRecycleRun(filePath) {
  const runPath = path.resolve(filePath);
  assertion(
    runPath.startsWith(`${REPOSITORY_ROOT}${path.sep}`),
    'H-042 run must remain inside the repository'
  );
  await assertRegularFile(runPath, 'H-042 run');
  const run = await readJson(runPath, 'H-042 run');
  const schema = await readJson(
    path.join(LAB_DIRECTORY, 'schemas/surface-worker-recycle-run.schema.json'),
    'H-042 schema'
  );
  assertSchema(compileSchema(schema), run, 'H-042');
  const { evidenceSha256, ...evidence } = run;
  assertion(
    run.schemaVersion === 'overlaykit-h042-surface-worker-recycle-run/v1' &&
      run.hypothesis === 'H-042' &&
      sha256Canonical(evidence) === evidenceSha256,
    'H-042 canonical evidence hash is invalid'
  );

  await verifyCollector(runPath, run);
  const { h041 } = await verifyInputs(runPath, run);
  const artifacts = run.observations.artifacts;
  const [
    hostPollBytes,
    runtimePollBytes,
    initialLogsBytes,
    absentLogsBytes,
    preSignalLogsBytes,
    finalLogsBytes,
    signalReceiptBytes,
    experimentEventsBytes,
    cleanupEventsBytes,
  ] = await Promise.all([
    verifiedArtifact(runPath, artifacts.hostPoll, 'host-poll.jsonl', 'host poll'),
    verifiedArtifact(runPath, artifacts.runtimePoll, 'runtime-poll.jsonl', 'runtime poll'),
    verifiedArtifact(runPath, artifacts.initialLogs, 'logs-initial.txt', 'initial logs'),
    verifiedArtifact(runPath, artifacts.absentLogs, 'logs-absent.txt', 'absent logs'),
    verifiedArtifact(runPath, artifacts.preSignalLogs, 'logs-pre-signal.txt', 'pre-signal logs'),
    verifiedArtifact(runPath, artifacts.finalLogs, 'logs-final.txt', 'final logs'),
    verifiedArtifact(runPath, artifacts.signalReceipt, 'signal-receipt.json', 'signal receipt'),
    verifiedArtifact(
      runPath,
      artifacts.experimentEvents,
      'docker-events-experiment.jsonl',
      'experiment Docker events'
    ),
    verifiedArtifact(
      runPath,
      artifacts.cleanupEvents,
      'docker-events-cleanup.jsonl',
      'cleanup Docker events'
    ),
  ]);
  const hostPoll = parseJsonLines(hostPollBytes, 'host poll');
  const runtimePoll = parseJsonLines(runtimePollBytes, 'runtime poll');
  const runtimeGroups = verifyRuntimePoll(runtimePoll, run);
  verifyHostTimeline(hostPoll, run);
  verifyCumulativeLogs(
    {
      initial: initialLogsBytes.toString('utf8'),
      absent: absentLogsBytes.toString('utf8'),
      preSignal: preSignalLogsBytes.toString('utf8'),
      final: finalLogsBytes.toString('utf8'),
    },
    run,
    runtimeGroups
  );
  verifyHostAndDevice(run, h041, runtimeGroups);
  const chronology = verifyCausalChronology(run, runtimeGroups);
  const signalAudit = run.invocationAudit.entries.find(
    (entry) => entry.kind === 'docker-exec-signal'
  );
  verifySignalReceipt({
    signal: run.windows.signal,
    receiptText: signalReceiptBytes.toString('utf8'),
    signalTargetRuntime: runtimeGroups.signalTarget,
    oldWorker: run.observations.initial.runtime.observer.surfaceWorkers[0],
    signalAudit,
  });
  const audit = verifyInvocationAudit(run, runtimeGroups, signalReceiptBytes.toString('utf8'));
  const experimentEvents = parseDockerEventLines(
    experimentEventsBytes.toString('utf8'),
    'experiment Docker events'
  );
  const cleanupEvents = parseDockerEventLines(
    cleanupEventsBytes.toString('utf8'),
    'cleanup Docker events'
  );
  const eventBoundary = verifyDockerEventReceipts(
    run,
    experimentEvents,
    cleanupEvents,
    runtimeGroups
  );
  const { predicates } = recomputePredicatesIndependent(run, {
    runtimeGroups,
    chronology,
    experimentEventAnalysis: eventBoundary.experiment,
    invocationAuditExact: audit !== null,
  });
  assertion(
    exactKeys(run.predicates, PREDICATE_KEYS) && sameCanonical(run.predicates, predicates),
    'H-042 predicates differ from independent reconstruction'
  );
  const outcome = classifyOutcomeIndependent(predicates);
  assertion(
    sameCanonical(run.outcome, outcome),
    'H-042 outcome differs from the independent predicate classifier'
  );
  assertion(
    sameCanonical(run.claimBoundary, INDEPENDENT_CLAIM_BOUNDARY),
    'H-042 claim boundary is incomplete or expanded'
  );
  verifyCleanup(run);

  return {
    schemaVersion: 'overlaykit-h042-verification/v1',
    hypothesis: 'H-042',
    runId: run.runId,
    outcome: outcome.status,
    stage: outcome.stage,
    evidenceSha256: run.evidenceSha256,
    h041EvidenceSha256: H041_EVIDENCE_SHA256,
    sourceSetExact: true,
    artifactHashesValid: true,
    signalBoundaryExact: true,
    dockerEventBoundaryExact: true,
    predicates,
    cleaned: true,
    verified: true,
  };
}

const modulePath = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === modulePath) {
  try {
    assertion(process.argv.length === 3, 'usage: verify.mjs <run.json>');
    const receipt = await verifySurfaceWorkerRecycleRun(process.argv[2]);
    process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
  } catch (error) {
    process.stderr.write(
      `H-042 verification failed: ${error instanceof Error ? error.message : String(error)}\n`
    );
    process.exitCode = 1;
  }
}
