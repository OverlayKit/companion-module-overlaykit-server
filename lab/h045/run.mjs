#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  constants as FS_CONSTANTS,
  createReadStream,
  lstatSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  statSync,
} from 'node:fs';
import { mkdir, open, readFile, readdir, realpath, stat } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

import {
  H044_PUBLIC_RECEIPT_PATH,
  H045_ACCEPTED_SERIAL_BINDING,
  H045_ADR_0006_SHA256,
  H045_CHG_0018_SHA256,
  H045_CHG_0019_SHA256,
  H045_CHG_0020_SHA256,
  H045_GOVERNANCE_MANIFEST_SHA256,
  H045_GOVERNANCE_PLAN_SHA256,
  H045_MANIFEST_CONTENT_HASH,
  H045_NODE_ARCH,
  H045_NODE_BINARY_BYTE_LENGTH,
  H045_NODE_BINARY_SHA256,
  H045_NODE_PLATFORM,
  H045_NODE_VERSION,
  H045_PLAN_HASH,
  H045_PROTECTED_MAIN_COMMIT,
  H045_REPOSITORY,
  H045_REQUIRED_SOURCE_PATHS,
  H045_SOURCE_CONTRACT_COMMIT,
  H045_STABLE_TARGET_INPUT,
  buildSourceAdmission,
  readHistoricalEvidence,
  sourceSetSha256,
} from './admission-lib.mjs';
import {
  H045_ACCEPTED_IMAGE_ID,
  H045_ACCEPTED_IMAGE_REFERENCE,
  classificationExactShape,
  classifyDynamicFrames,
  frameExactShape,
  sha256Canonical,
} from './classifier-lib.mjs';
import {
  OBSERVER_COMMAND_ENVIRONMENT_POLICY,
  OBSERVER_DOCKER_ANCESTOR_FILTER,
  OBSERVER_DOCKER_INSPECT_FORMAT,
  OBSERVER_DOCKER_PS_FORMAT,
  OBSERVER_DOCKER_UNIX_HOST,
  OBSERVER_DOCKER_VERSION_FORMAT,
  buildCapabilityAudit,
  captureDockerAdmission,
  captureGitAdmission,
  captureLsusbAdmission,
  captureObservationFrame,
  createCommandAuditor,
  createFilesystemAuditor,
} from './observer-lib.mjs';

const REPOSITORY_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SCHEMA_PATH = fileURLToPath(new URL('./schemas/live-run.schema.json', import.meta.url));
const ARTIFACT_ROOT = path.join(REPOSITORY_ROOT, 'artifacts', 'h045');
const PREDECESSOR_ATTEMPT_DIRECTORY = 'live-attempt';
const REPLACEMENT_ATTEMPT_ID = 'h045-chg-0020-attempt-1';
const PREDECESSOR_RESERVATION_RELATIVE_PATH = 'artifacts/h045/live-attempt/reservation.json';
const PREDECESSOR_FAILURE_RELATIVE_PATH = 'artifacts/h045/live-attempt/failure.json';
const REPLACEMENT_RESERVATION_RELATIVE_PATH =
  'artifacts/h045/h045-chg-0020-attempt-1/reservation.json';
const REPLACEMENT_COMPLETION_RELATIVE_PATH =
  'artifacts/h045/h045-chg-0020-attempt-1/completion.json';
const PREDECESSOR_RESERVATION_SHA256 =
  '27ee9aa2c70adb56682564c6ddc80c43cc40e6a5c5e1edacc23327648aad2f24';
const PREDECESSOR_FAILURE_SHA256 =
  '710b3b28760239f5971c961f8b0011a18c439c10a4974f548c435ff2a4507fc0';
const OFFLINE_FIXTURE_OUTPUT_ROOT = '/nonexistent/overlaykit-h045-offline-fixture';
export const MAX_RUN_JSON_BYTES = 64 * 1024 * 1024;
export const MAX_LEDGER_RECEIPT_BYTES = 64 * 1024;
const MAX_SECURE_PATH_BYTES = 4_096;
const SECURE_DIRECTORY_MODE = 0o700;
const SECURE_FILE_MODE = 0o600;
const ADR_0006_PATH = path.join(REPOSITORY_ROOT, '.overlaykit/governance/decisions/ADR-0006.json');
const EMPTY_SHA256 = createHash('sha256').update('').digest('hex');
const GIT_COMMIT_PATTERN = /^[0-9a-f]{40}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const DECIMAL_PATTERN = /^(?:0|[1-9][0-9]*)$/u;
const DATE_TIME_PATTERN =
  /^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?Z$/u;

export const H045_LIVE_AUTHORIZATION_PREFIX =
  'CHG-0020:h045-one-readonly-replacement-attempt:sha256:';
export const H045_LIVE_AUTHORIZATION = `${H045_LIVE_AUTHORIZATION_PREFIX}<source-set-sha256>`;

export function h046CanonicalCommandEnvironment() {
  return {};
}

export function h045LiveAuthorization(sourceDigest) {
  if (typeof sourceDigest !== 'string' || !SHA256_PATTERN.test(sourceDigest)) {
    throw new TypeError('H-045 source review digest must be a lowercase SHA-256');
  }
  return `${H045_LIVE_AUTHORIZATION_PREFIX}${sourceDigest}`;
}

export function parseH045LiveAuthorization(authorization) {
  if (
    typeof authorization !== 'string' ||
    !authorization.startsWith(H045_LIVE_AUTHORIZATION_PREFIX)
  ) {
    throw new Error('H-045 live execution lacks exact source-bound replacement authorization');
  }
  const sourceDigest = authorization.slice(H045_LIVE_AUTHORIZATION_PREFIX.length);
  if (!SHA256_PATTERN.test(sourceDigest)) {
    throw new Error('H-045 live execution lacks exact source-bound replacement authorization');
  }
  return sourceDigest;
}

export const H045_REQUIRED_CASE_IDS = Object.freeze([
  'multiple-image-matches',
  'selector-broadening',
  'descendant-image-mismatch',
  'hidden-container-row',
  'deployment-presence-drift',
  'container-drift',
  'pid1-drift',
  'worker-ambiguity',
  'pid-reuse',
  'parent-drift',
  'namespace-drift',
  'device-absence',
  'device-epoch-drift',
  'descriptor-recovery',
  'marker-change',
  'frame-reorder',
  'exposure-over-limit',
  'missing-command-audit',
  'duplicate-receipts',
  'input-tampering',
  'source-drift',
  'environment-policy-drift',
  'prohibited-capability',
]);

export const H045_CLAIM_BOUNDARY = Object.freeze({
  proves: Object.freeze([
    'one capability-bounded dynamic read-only observation derived only from the exact accepted Companion image and MK.2 identity without a historical volatile target identifier',
    'two adjacent complete frames no more than 5000 milliseconds apart with exact image-filter cardinality, current device epoch, Docker lifecycle, PID 1, SurfaceThread, descriptor, marker, and audit receipts',
    'one cutoff-bound authority-void dynamic tuple receipt only for one stable running non-healthy deployment, or zero receipts with withheld for complete current non-eligibility',
    'fail-closed inconclusive classification for multiplicity, selector ambiguity, contradiction, inaccessible evidence, PID reuse, inter-frame drift, source drift, or incomplete audit',
    'exact audited cardinality of allowed local Git, lsusb, Docker Unix-socket, and filesystem metadata observations with zero prohibited capabilities',
  ]),
  excludes: Object.freeze([
    'validity after the second-frame cutoff, continuity from H-043, atomicity, race freedom, PID-reuse-safe action, or a closed check-action interval',
    'authorization or safety of SIGTERM, pidfd, any signal, command, restart, rescan, retry, executable action, watcher, controller, or supervisor',
    'physical disconnect or reconnect, hidraw open or I/O, Docker lifecycle mutation, namespace entry, configuration change, installation, production policy, publication, or release',
    'configuration continuity, button delivery, rendered pixels, operator perception, OBS truth, product acceptance, security, or acceptable downtime',
    'multiple-device behavior, image upgrade discovery, pre-login behavior, reboot recovery, long-outage recovery, or production recovery policy',
    'an expansion or satisfaction of accepted SPEC-0001 or SPEC-0002',
    'a successor ADR or architectural authority beyond ADR-0006',
  ]),
});

const ABSOLUTE_EXECUTABLES = Object.freeze({
  git: '/usr/bin/git',
  lsusb: '/usr/bin/lsusb',
  docker: '/usr/bin/docker',
});

function clone(value) {
  return structuredClone(value);
}

function plainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, keys) {
  return (
    plainObject(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function same(left, right) {
  try {
    return JSON.stringify(left) === JSON.stringify(right);
  } catch {
    return false;
  }
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function validDateTime(value) {
  return (
    typeof value === 'string' && DATE_TIME_PATTERN.test(value) && Number.isFinite(Date.parse(value))
  );
}

function validMonotonic(value) {
  return typeof value === 'string' && DECIMAL_PATTERN.test(value);
}

function validMonotonicClockSample(value) {
  return (typeof value === 'bigint' && value >= 0n) || validMonotonic(value);
}

function sealFrame(frame) {
  const body = clone(frame);
  delete body.digestSha256;
  return { ...body, digestSha256: sha256Canonical(body) };
}

function stripStat(value) {
  if (!plainObject(value)) return null;
  const normalized = {
    stDev: value.stDev,
    inode: value.inode,
    ctimeNs: value.ctimeNs,
    mode: value.mode,
    uid: value.uid,
    gid: value.gid,
    rdev: value.rdev,
    rdevHex: value.rdevHex,
    major: value.major,
    minor: value.minor,
    isCharacterDevice: value.isCharacterDevice,
  };
  return Object.values(normalized).some((entry) => entry === null || entry === undefined)
    ? null
    : normalized;
}

function normalizeEpoch(value, acceptedTarget) {
  if (!plainObject(value)) return null;
  const normalized = {
    serial: value.serial,
    busNumber: value.busNumber,
    deviceNumber: value.deviceNumber,
    usbDevicePath: value.usbDevicePath,
    usbDev: value.usbDev,
    hidDevicePath: value.hidDevicePath,
    devicePath: value.devicePath,
    stat: stripStat(value.stat),
  };
  const scalarFieldsExact = Object.entries(normalized)
    .filter(([key]) => key !== 'stat')
    .every(([, entry]) => typeof entry === 'string' && entry !== '');
  return scalarFieldsExact &&
    normalized.stat !== null &&
    value.vendorId === acceptedTarget.vendorId &&
    value.productId === acceptedTarget.productId &&
    normalized.serial === acceptedTarget.serial
    ? normalized
    : null;
}

function normalizeLifecycle(value) {
  if (!plainObject(value) || value.running !== true) return null;
  const normalized = {
    containerId: value.containerId,
    imageId: value.imageId,
    startedAt: value.startedAt,
    restartCount: value.restartCount,
    hostPid: value.hostPid,
    pid1StartTicks: value.pid1StartTicks,
    pidNamespace: value.pidNamespace,
    mountNamespace: value.mountNamespace,
    cgroup: value.cgroup,
    hostCgroup: value.hostCgroup,
    cgroupNamespaceMode: value.cgroupNamespaceMode,
  };
  return Object.values(normalized).some((entry) => entry === null || entry === undefined)
    ? null
    : normalized;
}

function normalizePid1(value, lifecycle) {
  if (!plainObject(value) || lifecycle === null) return null;
  const normalized = {
    hostPid: lifecycle.hostPid,
    startTicks: value.startTicks,
    pidNamespace: value.pidNamespace,
    mountNamespace: value.mountNamespace,
    cgroup: value.cgroup,
  };
  return Object.values(normalized).some((entry) => entry === null || entry === undefined)
    ? null
    : normalized;
}

function normalizeWorker(value) {
  if (!plainObject(value)) return null;
  const normalized = {
    pid: value.pid,
    startTicks: value.startTicks,
    ppid: value.ppid,
    parentStartTicks: value.parentStartTicks,
    uid: value.uid,
    gid: value.gid,
    groups: Array.isArray(value.groups) ? [...value.groups] : null,
    cmdline: Array.isArray(value.cmdline) ? [...value.cmdline] : null,
    cgroup: value.cgroup,
    pidNamespace: value.pidNamespace,
    mountNamespace: value.mountNamespace,
  };
  return Object.values(normalized).some((entry) => entry === null || entry === undefined)
    ? null
    : normalized;
}

function incompleteFrame(frameId, startedAt = '1970-01-01T00:00:00.000Z', startedNs = '0') {
  const at = validDateTime(startedAt) ? startedAt : '1970-01-01T00:00:00.000Z';
  const monotonicNs = validMonotonic(startedNs) ? startedNs : '0';
  return sealFrame({
    id: typeof frameId === 'string' && frameId !== '' ? frameId : 'invalid-frame',
    complete: false,
    startedAt: at,
    endedAt: at,
    startedMonotonicNs: monotonicNs,
    endedMonotonicNs: monotonicNs,
    observationCutoff: {
      at,
      monotonicNs,
    },
    host: {
      hostname: 'unavailable',
      bootId: 'unavailable',
      osRelease: 'unavailable',
    },
    device: {
      complete: false,
      present: false,
      identity: null,
    },
    deploymentInventory: {
      complete: false,
      exact: false,
      selector: {
        imageReference: H045_ACCEPTED_IMAGE_REFERENCE,
        imageId: H045_ACCEPTED_IMAGE_ID,
      },
      rows: [],
      matches: [],
    },
    auditBinding: {
      commandReceiptIndexes: [],
      filesystemReceiptIndexes: [],
    },
  });
}

function inventoryRows(rawInventory) {
  const source = Array.isArray(rawInventory?.matches) ? rawInventory.matches : [];
  const rows = source.map((entry) => ({
    containerId: entry?.containerId,
    state: typeof entry?.state === 'string' ? entry.state.toLowerCase() : entry?.state,
  }));
  const exact = rows.every(
    (row) =>
      typeof row.containerId === 'string' &&
      /^[0-9a-f]{64}$/u.test(row.containerId) &&
      typeof row.state === 'string' &&
      /^[a-z][a-z0-9_-]*$/u.test(row.state)
  );
  return { rows, exact };
}

function normalizedMarkers(value) {
  return {
    opening:
      Number.isSafeInteger(value?.openingCount) && value.openingCount >= 0 ? value.openingCount : 0,
    ready: Number.isSafeInteger(value?.readyCount) && value.readyCount >= 0 ? value.readyCount : 0,
    relevantLinesSha256:
      typeof value?.relevantLinesSha256 === 'string' &&
      SHA256_PATTERN.test(value.relevantLinesSha256)
        ? value.relevantLinesSha256
        : EMPTY_SHA256,
  };
}

function normalizedDeployment(raw, row, acceptedTarget) {
  const running = row.state === 'running';
  const lifecycle = running ? normalizeLifecycle(raw.docker?.lifecycle) : null;
  const pid1 = running ? normalizePid1(raw.processes?.pid1, lifecycle) : null;
  const sourceWorkers = Array.isArray(raw.processes?.surfaceWorkers)
    ? raw.processes.surfaceWorkers
    : [];
  const workers = running
    ? sourceWorkers.map(normalizeWorker).filter((entry) => entry !== null)
    : [];
  const workersExact = !running || workers.length === sourceWorkers.length;
  const exactDevicePresent = raw.device?.status === 'unique';
  const exactDeviceAbsent = raw.device?.status === 'none' && raw.device?.present === false;
  const descriptorObservationExact =
    !running ||
    sourceWorkers.every((worker) =>
      exactDevicePresent
        ? worker?.descriptorTableStable === true
        : exactDeviceAbsent &&
          Array.isArray(worker?.fileDescriptors) &&
          worker.fileDescriptors.length === 0
    );
  const descriptors = running
    ? sourceWorkers.flatMap((worker) =>
        Array.isArray(worker?.fileDescriptors) ? clone(worker.fileDescriptors) : []
      )
    : [];
  const markers = normalizedMarkers(raw.docker?.markers);
  const selectedExact =
    raw.docker?.inspectExact === true &&
    raw.docker?.selected?.containerId === row.containerId &&
    raw.docker?.selected?.state === row.state;
  const lifecycleExact = running
    ? lifecycle !== null &&
      lifecycle.containerId === row.containerId &&
      lifecycle.imageId === acceptedTarget.imageId
    : raw.docker?.lifecycle?.running === false;
  const processExact =
    !running ||
    (raw.processes?.stable === true &&
      pid1 !== null &&
      sourceWorkers.length <= 1 &&
      workersExact &&
      descriptorObservationExact);
  const markerExact =
    !running ||
    (Number.isSafeInteger(raw.docker?.markers?.openingCount) &&
      Number.isSafeInteger(raw.docker?.markers?.readyCount) &&
      SHA256_PATTERN.test(raw.docker?.markers?.relevantLinesSha256 ?? ''));
  const exact = selectedExact && lifecycleExact && processExact && markerExact;
  return {
    complete: exact,
    exact,
    container: {
      id: row.containerId,
      imageReference: acceptedTarget.imageReference,
      imageId: acceptedTarget.imageId,
      state: row.state,
    },
    lifecycle,
    pid1,
    workers,
    descriptors,
    markers,
  };
}

/**
 * Purely project one raw observer frame into the classifier contract. Raw Docker
 * rows remain separate from exact inspected matches, so multiplicity cannot be
 * hidden by inventing image identity for uninspected rows.
 */
export function normalizeObservationFrame(raw, acceptedTarget) {
  if (!plainObject(raw) || !plainObject(acceptedTarget)) {
    return incompleteFrame('invalid-frame');
  }
  const observationCutoffExact =
    plainObject(raw.observationCutoff) &&
    validDateTime(raw.observationCutoff.at) &&
    validMonotonic(raw.observationCutoff.monotonicNs);
  const observationCutoff = observationCutoffExact
    ? {
        at: raw.observationCutoff.at,
        monotonicNs: raw.observationCutoff.monotonicNs,
      }
    : {
        at: raw.startedAt,
        monotonicNs: raw.startedMonotonicNs,
      };
  const host = {
    hostname:
      typeof raw.host?.hostname === 'string' && raw.host.hostname !== ''
        ? raw.host.hostname
        : 'unavailable',
    bootId:
      typeof raw.host?.bootId === 'string' && raw.host.bootId !== ''
        ? raw.host.bootId
        : 'unavailable',
    osRelease: plainObject(raw.host?.osRelease)
      ? JSON.stringify(raw.host.osRelease)
      : 'unavailable',
  };
  const epoch =
    raw.device?.status === 'unique'
      ? normalizeEpoch(raw.device?.selectedEpoch, acceptedTarget)
      : null;
  const devicePresent = raw.device?.status === 'unique' && epoch !== null;
  const deviceComplete =
    raw.device?.complete === true &&
    ((raw.device?.status === 'none' && raw.device.present === false) || devicePresent);
  const device = {
    complete: deviceComplete,
    present: devicePresent,
    identity: devicePresent
      ? {
          serial: epoch.serial,
          vendorId: acceptedTarget.vendorId,
          productId: acceptedTarget.productId,
          epoch,
        }
      : null,
  };
  const observedRows = inventoryRows(raw.docker?.inventory);
  const expectedStatus =
    observedRows.rows.length === 0
      ? 'none'
      : observedRows.rows.length === 1
        ? 'unique'
        : 'multiple';
  const selectorExact =
    raw.docker?.inventory?.selector?.kind === 'ancestor-image-id' &&
    raw.docker.inventory.selector.imageId === acceptedTarget.imageId &&
    raw.docker.inventory.selector.filter === `ancestor=${acceptedTarget.imageId}` &&
    raw.docker.inventory.selector.unixHost === OBSERVER_DOCKER_UNIX_HOST &&
    raw.docker.inventory.selector.projection === OBSERVER_DOCKER_PS_FORMAT;
  const inventoryObservedExact =
    observedRows.exact &&
    raw.docker?.inventory?.exact === true &&
    raw.docker.inventory.matchCount === observedRows.rows.length &&
    raw.docker.inventory.status === expectedStatus &&
    selectorExact;
  let matches = [];
  if (expectedStatus === 'unique' && inventoryObservedExact) {
    const deployment = normalizedDeployment(raw, observedRows.rows[0], acceptedTarget);
    if (deployment.exact) matches = [deployment];
  }
  const inventoryComplete =
    inventoryObservedExact && (expectedStatus !== 'unique' || matches.length === 1);
  const inventory = {
    complete: inventoryComplete,
    exact: inventoryObservedExact,
    selector: {
      imageReference: acceptedTarget.imageReference,
      imageId: acceptedTarget.imageId,
    },
    rows: observedRows.rows,
    matches,
  };
  const errors = Array.isArray(raw.errors) ? raw.errors : [];
  const onlyExpectedMultiplicity =
    expectedStatus === 'multiple' &&
    errors.length > 0 &&
    errors.every(
      (entry) => entry?.stage === 'docker-inventory' && entry?.code === 'MULTIPLE_IMAGE_MATCHES'
    );
  const complete =
    observationCutoffExact &&
    device.complete &&
    inventory.complete &&
    (raw.complete === true || onlyExpectedMultiplicity);
  const normalized = sealFrame({
    id: raw.frameId,
    complete,
    startedAt: raw.startedAt,
    endedAt: raw.endedAt,
    startedMonotonicNs: raw.startedMonotonicNs,
    endedMonotonicNs: raw.endedMonotonicNs,
    observationCutoff,
    host,
    device,
    deploymentInventory: inventory,
    auditBinding: {
      commandReceiptIndexes: Array.isArray(raw.auditBinding?.commandReceiptIndexes)
        ? [...raw.auditBinding.commandReceiptIndexes]
        : [],
      filesystemReceiptIndexes: Array.isArray(raw.auditBinding?.filesystemReceiptIndexes)
        ? [...raw.auditBinding.filesystemReceiptIndexes]
        : [],
    },
  });
  return frameExactShape(normalized)
    ? normalized
    : incompleteFrame(raw.frameId, raw.startedAt, raw.startedMonotonicNs);
}

function syntheticStat() {
  return {
    stDev: '7',
    inode: '4001',
    ctimeNs: '1900000000000000000',
    mode: '0660',
    uid: 0,
    gid: 1002,
    rdev: '61696',
    rdevHex: 'f1:0',
    major: 241,
    minor: 0,
    isCharacterDevice: true,
  };
}

function syntheticDescriptor(descriptor = '20', target = '/dev/hidraw0') {
  return {
    descriptor,
    target,
    lstat: {
      stDev: '7',
      inode: '5001',
      ctimeNs: '1900000000000000000',
      mode: '0777',
      uid: 0,
      gid: 0,
      rdev: '0',
      rdevHex: '0:0',
      major: 0,
      minor: 0,
      isCharacterDevice: false,
      isSymbolicLink: true,
    },
    stat: {
      ...syntheticStat(),
      isSymbolicLink: false,
    },
  };
}

function syntheticEpoch(serial) {
  return {
    serial,
    busNumber: '1',
    deviceNumber: '42',
    usbDevicePath: '2',
    usbDev: '189:41',
    hidDevicePath: '/sys/devices/usb1/1-2/1-2:1.0/0003:0FD9:0080.0042',
    devicePath: '/dev/hidraw0',
    stat: syntheticStat(),
  };
}

function syntheticLifecycle(containerId = 'c'.repeat(64)) {
  return {
    containerId,
    imageId: H045_ACCEPTED_IMAGE_ID,
    startedAt: '2026-07-27T03:00:00.000Z',
    restartCount: 0,
    hostPid: 4242,
    pid1StartTicks: 7000,
    pidNamespace: 'pid:[4026533001]',
    mountNamespace: 'mnt:[4026533002]',
    cgroup: '0::/',
    hostCgroup: `0::/system.slice/docker-${containerId}.scope`,
    cgroupNamespaceMode: 'private',
  };
}

function syntheticPid1() {
  return {
    hostPid: 4242,
    startTicks: 7000,
    pidNamespace: 'pid:[4026533001]',
    mountNamespace: 'mnt:[4026533002]',
    cgroup: '0::/',
  };
}

function syntheticWorker({ pid = 73, startTicks = 7100 } = {}) {
  return {
    pid,
    startTicks,
    ppid: 1,
    parentStartTicks: 7000,
    uid: 1000,
    gid: 1000,
    groups: [1000, 1002],
    cmdline: [
      '/app/node-runtimes/node22/bin/node',
      '--enable-source-maps',
      '/app/SurfaceThread.js',
    ],
    cgroup: '0::/',
    pidNamespace: 'pid:[4026533001]',
    mountNamespace: 'mnt:[4026533002]',
  };
}

function syntheticMarkerEvidence(serial, opening = 4, ready = 4) {
  const entries = [];
  const append = (kind, count, text) => {
    for (let index = 0; index < count; index += 1) {
      const at = new Date(Date.parse('2026-07-27T03:00:01.000Z') + entries.length).toISOString();
      entries.push({
        at,
        stream: 'stdout',
        line: `${kind} ${index + 1}: ${text}`,
      });
    }
  };
  append('opening', opening, `Opening surface panel: streamdeck:${serial}`);
  append('ready', ready, `Surface panel ready: streamdeck:${serial}`);
  return {
    markers: {
      opening,
      ready,
      relevantLinesSha256: sha256(
        Buffer.from(
          entries.map((entry) => `${entry.at}\t${entry.stream}\t${entry.line}`).join('\n'),
          'utf8'
        )
      ),
    },
    stdout: entries
      .map((entry) => `${entry.at} ${entry.line}`)
      .join('\n')
      .concat('\n'),
  };
}

function syntheticDeployment(containerId = 'c'.repeat(64)) {
  return {
    complete: true,
    exact: true,
    container: {
      id: containerId,
      imageReference: H045_ACCEPTED_IMAGE_REFERENCE,
      imageId: H045_ACCEPTED_IMAGE_ID,
      state: 'running',
    },
    lifecycle: syntheticLifecycle(containerId),
    pid1: syntheticPid1(),
    workers: [syntheticWorker()],
    descriptors: [],
    markers: {
      opening: 0,
      ready: 0,
      relevantLinesSha256: sha256(Buffer.alloc(0)),
    },
  };
}

function syntheticFrames(acceptedTarget) {
  if (
    !plainObject(acceptedTarget) ||
    typeof acceptedTarget.serial !== 'string' ||
    acceptedTarget.serial === ''
  ) {
    throw new TypeError('acceptedTarget with an admitted serial is required');
  }
  const deployment = syntheticDeployment();
  deployment.markers = syntheticMarkerEvidence(acceptedTarget.serial).markers;
  const common = {
    complete: true,
    host: {
      hostname: 'h045-synthetic-host',
      bootId: '00000000-0000-4000-8000-000000000045',
      osRelease: '{"id":"linux","prettyName":"H-045 synthetic","versionId":"1"}',
    },
    device: {
      complete: true,
      present: true,
      identity: {
        serial: acceptedTarget.serial,
        vendorId: '0fd9',
        productId: '0080',
        epoch: syntheticEpoch(acceptedTarget.serial),
      },
    },
    deploymentInventory: {
      complete: true,
      exact: true,
      selector: {
        imageReference: H045_ACCEPTED_IMAGE_REFERENCE,
        imageId: H045_ACCEPTED_IMAGE_ID,
      },
      rows: [
        {
          containerId: deployment.container.id,
          state: deployment.container.state,
        },
      ],
      matches: [deployment],
    },
  };
  return [
    sealFrame({
      id: 'hostile-frame-1',
      startedAt: '2026-07-27T03:00:10.000Z',
      endedAt: '2026-07-27T03:00:10.900Z',
      startedMonotonicNs: '200000000000',
      endedMonotonicNs: '200900000000',
      observationCutoff: {
        at: '2026-07-27T03:00:10.800Z',
        monotonicNs: '200800000000',
      },
      ...clone(common),
      auditBinding: {
        commandReceiptIndexes: [6, 7, 8],
        filesystemReceiptIndexes: [0],
      },
    }),
    sealFrame({
      id: 'hostile-frame-2',
      startedAt: '2026-07-27T03:00:10.900Z',
      endedAt: '2026-07-27T03:00:11.800Z',
      startedMonotonicNs: '200900000000',
      endedMonotonicNs: '201800000000',
      observationCutoff: {
        at: '2026-07-27T03:00:11.700Z',
        monotonicNs: '201700000000',
      },
      ...clone(common),
      auditBinding: {
        commandReceiptIndexes: [9, 10, 11],
        filesystemReceiptIndexes: [1],
      },
    }),
  ];
}

function zeroProhibitedCounts() {
  return {
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
  };
}

function syntheticOutputReceipt(value = '') {
  const bytes = Buffer.from(value, 'utf8');
  const text = bytes.toString('utf8');
  const withoutFinalNewline = text.endsWith('\n') ? text.slice(0, -1) : text;
  return {
    encoding: 'utf8',
    text,
    base64: bytes.toString('base64'),
    byteLength: bytes.byteLength,
    lineCount: withoutFinalNewline === '' ? 0 : withoutFinalNewline.split('\n').length,
    sha256: sha256(bytes),
  };
}

function syntheticCommandDefinitions(frames) {
  const definitions = [
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
      args: [
        '--host',
        OBSERVER_DOCKER_UNIX_HOST,
        'version',
        '--format',
        OBSERVER_DOCKER_VERSION_FORMAT,
      ],
    },
  ];
  for (const frame of frames) {
    const indexes = [];
    const add = (definition) => {
      indexes.push(definitions.length);
      definitions.push({ ...definition, frame });
    };
    add({
      kind: 'dockerPs',
      executable: 'docker',
      args: [
        '--host',
        OBSERVER_DOCKER_UNIX_HOST,
        'ps',
        '--all',
        '--no-trunc',
        '--filter',
        OBSERVER_DOCKER_ANCESTOR_FILTER,
        '--format',
        OBSERVER_DOCKER_PS_FORMAT,
      ],
      phase: 'before-cutoff',
    });
    const rows = frame.deploymentInventory.rows;
    const selected = frame.deploymentInventory.matches[0];
    if (rows.length === 1) {
      add({
        kind: 'dockerInspect',
        executable: 'docker',
        args: [
          '--host',
          OBSERVER_DOCKER_UNIX_HOST,
          'inspect',
          '--format',
          OBSERVER_DOCKER_INSPECT_FORMAT,
          rows[0].containerId,
        ],
        phase: 'before-cutoff',
      });
      if (selected?.container.state === 'running' && selected.lifecycle !== null) {
        add({
          kind: 'dockerLogs',
          executable: 'docker',
          args: [
            '--host',
            OBSERVER_DOCKER_UNIX_HOST,
            'logs',
            '--timestamps',
            '--since',
            selected.lifecycle.startedAt,
            '--until',
            frame.observationCutoff.at,
            rows[0].containerId,
          ],
          phase: 'at-or-after-cutoff',
        });
      }
    }
    frame.auditBinding.commandReceiptIndexes = indexes;
  }
  return definitions;
}

function syntheticCommandTiming(index, definition) {
  if (definition.frame === undefined) {
    const startedMs = Date.parse('2026-07-27T03:00:09.000Z') + index * 20;
    const startedNs = 199_000_000_000n + BigInt(index) * 20_000_000n;
    return {
      startedAt: new Date(startedMs).toISOString(),
      endedAt: new Date(startedMs + 10).toISOString(),
      startedMonotonicNs: startedNs.toString(),
      endedMonotonicNs: (startedNs + 10_000_000n).toString(),
      durationNs: '10000000',
    };
  }
  const frame = definition.frame;
  const afterCutoff = definition.phase === 'at-or-after-cutoff';
  const startedAt = afterCutoff ? frame.observationCutoff.at : frame.startedAt;
  const startedNs = afterCutoff
    ? BigInt(frame.observationCutoff.monotonicNs)
    : BigInt(frame.startedMonotonicNs) + BigInt(index + 1);
  return {
    startedAt,
    endedAt: startedAt,
    startedMonotonicNs: startedNs.toString(),
    endedMonotonicNs: startedNs.toString(),
    durationNs: '0',
  };
}

function syntheticLsusbStdout(frames, acceptedTarget) {
  const epochs = new Map();
  for (const frame of frames) {
    if (!frame.device.present) continue;
    const epoch = frame.device.identity.epoch;
    epochs.set(`${epoch.busNumber}:${epoch.deviceNumber}`, epoch);
  }
  return [...epochs.values()]
    .map(
      (epoch) =>
        `Bus ${epoch.busNumber.padStart(3, '0')} Device ${epoch.deviceNumber.padStart(3, '0')}: ` +
        `ID ${acceptedTarget.vendorId}:${acceptedTarget.productId} Elgato Stream Deck MK.2`
    )
    .join('\n')
    .concat(epochs.size === 0 ? '' : '\n');
}

function syntheticCommandStdout(definition, acceptedTarget, frames) {
  if (definition.observerKind === 'gitRevParse') return `${'f'.repeat(40)}\n`;
  if (definition.observerKind === 'gitRemoteGetUrl') return `${H045_REPOSITORY}\n`;
  if (definition.kind === 'lsusb') return syntheticLsusbStdout(frames, acceptedTarget);
  if (definition.kind === 'dockerVersion') {
    return `${JSON.stringify({
      Client: { Version: 'fixture', ApiVersion: '1.47' },
      Server: { Version: 'fixture', ApiVersion: '1.47' },
    })}\n`;
  }
  if (definition.kind === 'dockerPs') {
    return definition.frame.deploymentInventory.rows
      .map((row) => JSON.stringify({ ID: row.containerId, State: row.state }))
      .join('\n')
      .concat(definition.frame.deploymentInventory.rows.length === 0 ? '' : '\n');
  }
  if (definition.kind === 'dockerInspect') {
    const selected = definition.frame.deploymentInventory.matches[0];
    const row = definition.frame.deploymentInventory.rows[0];
    const lifecycle = selected?.lifecycle ?? null;
    return `${JSON.stringify({
      Id: row.containerId,
      Image: H045_ACCEPTED_IMAGE_ID,
      State: {
        Status: row.state,
        Running: row.state === 'running',
        Pid: lifecycle?.hostPid ?? 0,
        StartedAt: lifecycle?.startedAt ?? '0001-01-01T00:00:00Z',
      },
      RestartCount: lifecycle?.restartCount ?? 0,
      CgroupnsMode: lifecycle?.cgroupNamespaceMode ?? 'private',
    })}\n`;
  }
  if (definition.kind === 'dockerLogs') {
    const markers = definition.frame.deploymentInventory.matches[0].markers;
    return syntheticMarkerEvidence(acceptedTarget.serial, markers.opening, markers.ready).stdout;
  }
  return '';
}

function syntheticCommandReceipts(frames, acceptedTarget) {
  const ordinals = new Map();
  const receipts = syntheticCommandDefinitions(frames).map((definition, index) => {
    const ordinalKey = definition.kind === 'git' ? definition.observerKind : definition.kind;
    const ordinal = (ordinals.get(ordinalKey) ?? 0) + 1;
    ordinals.set(ordinalKey, ordinal);
    const receipt = {
      index,
      kind: definition.kind,
      ordinal,
      executable: definition.executable,
      args: [...definition.args],
      ...syntheticCommandTiming(index, definition),
      limits: {
        maxBufferBytes: 4 * 1024 * 1024,
        timeoutMs: null,
        overflow: 'drain-without-signal',
      },
      environmentPolicy: clone(OBSERVER_COMMAND_ENVIRONMENT_POLICY),
      exitCode: 0,
      signal: null,
      stdout: syntheticOutputReceipt(syntheticCommandStdout(definition, acceptedTarget, frames)),
      stderr: syntheticOutputReceipt(),
      cardinality: {
        global: index + 1,
        kind: ordinal,
      },
      errorCode: null,
    };
    return definition.kind === 'git'
      ? { ...receipt, observerKind: definition.observerKind }
      : receipt;
  });
  for (const frame of frames) Object.assign(frame, sealFrame(frame));
  return receipts;
}

function syntheticFilesystemReadResult(value) {
  const bytes = Buffer.from(value, 'utf8');
  const digest = sha256(bytes);
  return {
    cardinality: 1,
    byteLength: bytes.byteLength,
    bytes: {
      encoding: 'base64',
      base64: bytes.toString('base64'),
      byteLength: bytes.byteLength,
      sha256: digest,
    },
    encoding: 'utf8',
    text: value,
    sha256: digest,
  };
}

function syntheticFilesystemStatResult(value) {
  const metadata = plainObject(value)
    ? clone(value)
    : {
        ...syntheticStat(),
        isSymbolicLink: false,
      };
  return {
    cardinality: 1,
    metadata,
    sha256: sha256(Buffer.from(JSON.stringify(metadata), 'utf8')),
  };
}

function syntheticFilesystemResult(operation, value) {
  if (operation === 'readFileSync') return syntheticFilesystemReadResult(value);
  if (operation === 'readdirSync') {
    const entries = [...value];
    return {
      entries,
      cardinality: entries.length,
      sha256: sha256(Buffer.from(JSON.stringify(entries), 'utf8')),
    };
  }
  if (operation === 'realpathSync' || operation === 'readlinkSync') {
    return {
      value,
      cardinality: 1,
      sha256: sha256(Buffer.from(value, 'utf8')),
    };
  }
  return syntheticFilesystemStatResult(value);
}

function syntheticFilesystemDefinitions(frame) {
  const definitions = [
    ['readFileSync', '/etc/os-release', 'ID=linux\nVERSION_ID=1\nPRETTY_NAME="H-045 synthetic"\n'],
    ['readFileSync', '/proc/sys/kernel/random/boot_id', `${frame.host.bootId}\n`],
    ['readFileSync', '/proc/sys/kernel/hostname', `${frame.host.hostname}\n`],
    ['readdirSync', '/sys/class/hidraw', frame.device.present ? ['hidraw0'] : []],
  ];
  if (frame.device.present) {
    const epoch = frame.device.identity.epoch;
    const hidrawName = path.basename(epoch.devicePath);
    const classPath = `/sys/class/hidraw/${hidrawName}`;
    const sysfsPath = epoch.hidDevicePath;
    definitions.push(
      ['realpathSync', `${classPath}/device`, sysfsPath],
      [
        'readFileSync',
        `${classPath}/device/uevent`,
        `HID_ID=0003:0FD9:0080\nHID_UNIQ=${frame.device.identity.serial}\nHID_NAME=Stream Deck MK.2\n`,
      ],
      ['readFileSync', `${classPath}/dev`, '241:0\n'],
      ['statSync', epoch.devicePath, null],
      ['readFileSync', `${sysfsPath}/idVendor`, '0fd9\n'],
      ['readFileSync', `${sysfsPath}/idProduct`, '0080\n'],
      ['readFileSync', `${sysfsPath}/serial`, `${frame.device.identity.serial}\n`],
      ['readFileSync', `${sysfsPath}/manufacturer`, 'Elgato\n'],
      ['readFileSync', `${sysfsPath}/product`, 'Stream Deck MK.2\n'],
      ['readFileSync', `${sysfsPath}/busnum`, `${epoch.busNumber}\n`],
      ['readFileSync', `${sysfsPath}/devnum`, `${epoch.deviceNumber}\n`],
      ['readFileSync', `${sysfsPath}/devpath`, `${epoch.usbDevicePath}\n`],
      ['statSync', epoch.devicePath, null],
      ['lstatSync', epoch.devicePath, null],
      ['statSync', epoch.devicePath, null],
      ['readFileSync', `${sysfsPath}/dev`, epoch.usbDev]
    );
  }
  const selected =
    frame.deploymentInventory.rows.length === 1 && frame.deploymentInventory.matches.length === 1
      ? frame.deploymentInventory.matches[0]
      : null;
  if (selected?.container.state === 'running' && selected.lifecycle !== null) {
    const procRoot = `/proc/${selected.lifecycle.hostPid}/root/proc`;
    const processIdentities = [
      ...(selected.pid1 === null ? [] : [{ ...selected.pid1, pid: 1 }]),
      ...selected.workers,
    ].sort((left, right) => left.pid - right.pid);
    const processEntries = processIdentities.map((identity) => String(identity.pid));
    definitions.push(['readdirSync', procRoot, processEntries]);
    for (const processIdentity of processIdentities) {
      const directory = `${procRoot}/${processIdentity.pid}`;
      const worker =
        processIdentity.pid === 1
          ? null
          : selected.workers.find((entry) => entry.pid === processIdentity.pid);
      const ppid = worker === null ? 0 : worker.ppid;
      definitions.push(
        [
          'readFileSync',
          `${directory}/stat`,
          `${processIdentity.pid} (fixture) S ${[
            String(ppid),
            ...Array.from({ length: 17 }, () => '0'),
            String(processIdentity.startTicks),
          ].join(' ')}\n`,
        ],
        [
          'readFileSync',
          `${directory}/status`,
          `Name:\tfixture\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t1000 1002\nNSpid:\t${processIdentity.pid}\n`,
        ],
        [
          'readFileSync',
          `${directory}/cmdline`,
          `${worker === null ? '/sbin/tini' : worker.cmdline.join('\u0000')}\u0000`,
        ],
        ['readFileSync', `${directory}/cgroup`, '0::/\n'],
        ['readlinkSync', `${directory}/ns/pid`, processIdentity.pidNamespace],
        ['readlinkSync', `${directory}/ns/mnt`, processIdentity.mountNamespace]
      );
    }
    definitions.push(['readdirSync', procRoot, processEntries]);
    if (frame.device.present) {
      for (const worker of [...selected.workers].sort((left, right) => left.pid - right.pid)) {
        const directory = `${procRoot}/${worker.pid}/fd`;
        const descriptorEntries = [...selected.descriptors].sort(
          (left, right) => Number(left.descriptor) - Number(right.descriptor)
        );
        const descriptors = descriptorEntries.map((entry) => entry.descriptor);
        definitions.push(['readdirSync', directory, descriptors]);
        for (const descriptorEntry of descriptorEntries) {
          const descriptorPath = `${directory}/${descriptorEntry.descriptor}`;
          definitions.push(
            ['lstatSync', descriptorPath, descriptorEntry.lstat],
            ['readlinkSync', descriptorPath, descriptorEntry.target],
            ['statSync', descriptorPath, descriptorEntry.stat]
          );
        }
        definitions.push(['readdirSync', directory, descriptors]);
      }
    }
    definitions.push([
      'readFileSync',
      `/proc/${selected.lifecycle.hostPid}/cgroup`,
      selected.lifecycle.hostCgroup,
    ]);
  }
  return definitions;
}

function syntheticFilesystemReceipts(frames) {
  const ordinals = new Map();
  const receipts = [];
  for (const frame of frames) {
    const definitions = syntheticFilesystemDefinitions(frame);
    const frameStartIndex = receipts.length;
    for (const [operation, targetPath, value] of definitions) {
      const index = receipts.length;
      const ordinal = (ordinals.get(operation) ?? 0) + 1;
      ordinals.set(operation, ordinal);
      const frameOffset = index - frameStartIndex + 1;
      const startedNs = BigInt(frame.startedMonotonicNs) + BigInt(100 + frameOffset);
      receipts.push({
        index,
        operation,
        path: targetPath,
        startedAt: frame.startedAt,
        endedAt: frame.startedAt,
        startedMonotonicNs: startedNs.toString(),
        endedMonotonicNs: startedNs.toString(),
        durationNs: '0',
        disposition: 'observed',
        result: syntheticFilesystemResult(operation, value),
        errorCode: null,
        cardinality: {
          global: index + 1,
          operation: ordinal,
        },
      });
    }
    frame.auditBinding.filesystemReceiptIndexes = Array.from(
      { length: definitions.length },
      (_, offset) => frameStartIndex + offset
    );
    Object.assign(frame, sealFrame(frame));
  }
  return receipts;
}

function syntheticCapabilityAudit(frames, acceptedTarget) {
  const commandReceipts = syntheticCommandReceipts(frames, acceptedTarget);
  const filesystemReceipts = syntheticFilesystemReceipts(frames);
  const allowedProcessCounts = Object.fromEntries(
    ['git', 'lsusb', 'dockerVersion', 'dockerPs', 'dockerInspect', 'dockerLogs'].map((kind) => [
      kind,
      commandReceipts.filter((receipt) => receipt.kind === kind).length,
    ])
  );
  return {
    mode: 'live-readonly-dynamic-acquisition-capability-bounded',
    environmentPolicy: clone(OBSERVER_COMMAND_ENVIRONMENT_POLICY),
    commandReceipts,
    filesystemReceipts,
    allowedProcessCounts,
    commandCount: commandReceipts.length,
    filesystemReceiptCount: filesystemReceipts.length,
    complete: true,
    exact: true,
    frameCount: 2,
    lsusbCount: 1,
    unrecordedObservationCount: 0,
    prohibitedCounts: zeroProhibitedCounts(),
  };
}

function reseal(frame) {
  Object.assign(frame, sealFrame(frame));
}

function hostileDefinitions() {
  const definitions = [
    {
      id: 'multiple-image-matches',
      disposition: 'inconclusive',
      reasonCode: 'multiple-image-matches',
      mutate(input) {
        const other = syntheticDeployment('d'.repeat(64));
        for (const frame of input.frames) {
          frame.deploymentInventory.rows.push({
            containerId: other.container.id,
            state: other.container.state,
          });
          frame.deploymentInventory.matches = [];
          reseal(frame);
        }
      },
    },
    {
      id: 'selector-broadening',
      disposition: 'inconclusive',
      reasonCode: 'accepted-image-selector-inexact',
      mutate(input) {
        for (const frame of input.frames) {
          frame.deploymentInventory.selector.imageReference =
            'ghcr.io/bitfocus/companion/companion:latest';
          reseal(frame);
        }
      },
    },
    {
      id: 'descendant-image-mismatch',
      disposition: 'inconclusive',
      reasonCode: 'accepted-image-match-inexact',
      mutate(input) {
        for (const frame of input.frames) {
          const deployment = frame.deploymentInventory.matches[0];
          deployment.container.imageId = `sha256:${'b'.repeat(64)}`;
          deployment.lifecycle.imageId = `sha256:${'b'.repeat(64)}`;
          reseal(frame);
        }
      },
    },
    {
      id: 'hidden-container-row',
      disposition: 'inconclusive',
      reasonCode: 'capability-audit-incomplete-or-inexact',
      mutate(input) {
        for (const receipt of input.capabilityAudit.commandReceipts.filter(
          (entry) => entry.kind === 'dockerPs'
        )) {
          const hidden = `${JSON.stringify({
            ID: 'd'.repeat(64),
            State: 'running',
          })}\n`;
          receipt.stdout = syntheticOutputReceipt(`${receipt.stdout.text}${hidden}`);
        }
      },
    },
    {
      id: 'deployment-presence-drift',
      disposition: 'inconclusive',
      reasonCode: 'deployment-presence-drift',
      mutate(input) {
        input.frames[1].deploymentInventory.rows = [];
        input.frames[1].deploymentInventory.matches = [];
        reseal(input.frames[1]);
      },
    },
    {
      id: 'container-drift',
      disposition: 'inconclusive',
      reasonCode: 'deployment-row-drift',
      mutate(input) {
        const otherId = 'd'.repeat(64);
        const deployment = input.frames[1].deploymentInventory.matches[0];
        input.frames[1].deploymentInventory.rows[0].containerId = otherId;
        deployment.container.id = otherId;
        deployment.lifecycle.containerId = otherId;
        deployment.lifecycle.hostCgroup = `0::/system.slice/docker-${otherId}.scope`;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'pid1-drift',
      disposition: 'inconclusive',
      reasonCode: 'deployment-identity-or-lifecycle-drift',
      mutate(input) {
        const deployment = input.frames[1].deploymentInventory.matches[0];
        deployment.pid1.startTicks += 1;
        deployment.lifecycle.pid1StartTicks += 1;
        deployment.workers[0].parentStartTicks += 1;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'worker-ambiguity',
      disposition: 'inconclusive',
      reasonCode: 'worker-ambiguity',
      mutate(input) {
        for (const frame of input.frames) {
          frame.deploymentInventory.matches[0].workers.push(
            syntheticWorker({ pid: 74, startTicks: 7200 })
          );
          reseal(frame);
        }
      },
    },
    {
      id: 'pid-reuse',
      disposition: 'inconclusive',
      reasonCode: 'worker-identity-drift',
      mutate(input) {
        input.frames[1].deploymentInventory.matches[0].workers[0].startTicks += 1;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'parent-drift',
      disposition: 'inconclusive',
      reasonCode: 'deployment-observation-contradiction',
      mutate(input) {
        const worker = input.frames[1].deploymentInventory.matches[0].workers[0];
        worker.ppid = worker.pid;
        worker.parentStartTicks = worker.startTicks;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'namespace-drift',
      disposition: 'inconclusive',
      reasonCode: 'deployment-observation-contradiction',
      mutate(input) {
        input.frames[1].deploymentInventory.matches[0].workers[0].pidNamespace = 'pid:[4026533999]';
        reseal(input.frames[1]);
      },
    },
    {
      id: 'device-absence',
      disposition: 'withheld',
      reasonCode: 'device-absent',
      mutate(input) {
        for (const frame of input.frames) {
          frame.device = { complete: true, present: false, identity: null };
          reseal(frame);
        }
      },
    },
    {
      id: 'device-epoch-drift',
      disposition: 'inconclusive',
      reasonCode: 'device-identity-drift',
      mutate(input) {
        input.frames[1].device.identity.epoch.deviceNumber = '43';
        reseal(input.frames[1]);
      },
    },
    {
      id: 'descriptor-recovery',
      disposition: 'withheld',
      reasonCode: 'current-descriptor-present',
      mutate(input) {
        for (const frame of input.frames) {
          frame.deploymentInventory.matches[0].descriptors = [
            syntheticDescriptor('20', frame.device.identity.epoch.devicePath),
          ];
          reseal(frame);
        }
      },
    },
    {
      id: 'marker-change',
      disposition: 'inconclusive',
      reasonCode: 'marker-drift',
      mutate(input) {
        const frame = input.frames[1];
        const deployment = frame.deploymentInventory.matches[0];
        deployment.markers = syntheticMarkerEvidence(
          frame.device.identity.serial,
          deployment.markers.opening,
          deployment.markers.ready + 1
        ).markers;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'frame-reorder',
      disposition: 'inconclusive',
      reasonCode: 'frame-order-invalid',
      mutate(input) {
        input.frames[1].startedAt = '2026-07-27T03:00:10.800Z';
        input.frames[1].startedMonotonicNs = '200800000000';
        reseal(input.frames[1]);
      },
    },
    {
      id: 'exposure-over-limit',
      disposition: 'inconclusive',
      reasonCode: 'exposure-window-exceeded',
      mutate(input) {
        input.frames[1].startedAt = '2026-07-27T03:00:15.000Z';
        input.frames[1].endedAt = '2026-07-27T03:00:15.200Z';
        input.frames[1].startedMonotonicNs = '205000000000';
        input.frames[1].endedMonotonicNs = '205200000000';
        input.frames[1].observationCutoff = {
          at: '2026-07-27T03:00:15.100Z',
          monotonicNs: '205100000000',
        };
        reseal(input.frames[1]);
      },
    },
    {
      id: 'missing-command-audit',
      disposition: 'inconclusive',
      reasonCode: 'capability-audit-incomplete-or-inexact',
      mutate(input) {
        input.capabilityAudit.commandReceipts.pop();
      },
    },
    {
      id: 'duplicate-receipts',
      disposition: 'inconclusive',
      reasonCode: 'duplicate-receipts-rejected',
      duplicateOutput: true,
    },
    {
      id: 'input-tampering',
      disposition: 'inconclusive',
      reasonCode: 'source-admission-inexact',
      mutate(input) {
        input.containerId = '0'.repeat(64);
      },
    },
    {
      id: 'source-drift',
      disposition: 'inconclusive',
      reasonCode: 'source-admission-inexact',
      mutate(input) {
        input.sourceAdmissionExact = false;
      },
    },
    {
      id: 'environment-policy-drift',
      disposition: 'inconclusive',
      reasonCode: 'capability-audit-incomplete-or-inexact',
      mutate(input) {
        input.capabilityAudit.environmentPolicy.fixed.LANG = 'en_US.UTF-8';
      },
    },
    {
      id: 'prohibited-capability',
      disposition: 'inconclusive',
      reasonCode: 'prohibited-capability-observed',
      mutate(input) {
        input.capabilityAudit.prohibitedCounts.dockerExec = 1;
      },
    },
  ];
  const semanticCaseIds = new Set([
    'multiple-image-matches',
    'selector-broadening',
    'descendant-image-mismatch',
    'deployment-presence-drift',
    'container-drift',
    'pid1-drift',
    'worker-ambiguity',
    'pid-reuse',
    'parent-drift',
    'namespace-drift',
    'device-absence',
    'device-epoch-drift',
    'descriptor-recovery',
    'marker-change',
    'frame-reorder',
    'exposure-over-limit',
  ]);
  return definitions.map((definition) =>
    semanticCaseIds.has(definition.id)
      ? { ...definition, refreshCapabilityAudit: true }
      : definition
  );
}

export function evaluateHostileMatrix(classify = classifyDynamicFrames, acceptedTarget) {
  if (typeof classify !== 'function') throw new TypeError('classify must be a function');
  const base = {
    frames: syntheticFrames(acceptedTarget),
    capabilityAudit: null,
    sourceAdmissionExact: true,
  };
  base.capabilityAudit = syntheticCapabilityAudit(base.frames, acceptedTarget);
  const definitions = hostileDefinitions();
  const cases = definitions.map((definition) => {
    const input = clone(base);
    let result;
    let digestInput = input;
    if (definition.duplicateOutput) {
      const canonical = classify(input);
      const corrupted = clone(canonical);
      if (Array.isArray(corrupted.receipts) && corrupted.receipts.length === 1) {
        corrupted.receipts.push(clone(corrupted.receipts[0]));
      }
      digestInput = { classification: corrupted };
      result = classificationExactShape(corrupted)
        ? corrupted
        : {
            disposition: 'inconclusive',
            stage: 'output-admission',
            reasonCode: 'duplicate-receipts-rejected',
            receipts: [],
          };
    } else {
      definition.mutate(input);
      if (definition.refreshCapabilityAudit === true) {
        input.capabilityAudit = syntheticCapabilityAudit(input.frames, acceptedTarget);
      }
      result = classify(input);
    }
    const actualReceiptCount = Array.isArray(result?.receipts) ? result.receipts.length : 0;
    const passed =
      result?.disposition === definition.disposition &&
      result?.reasonCode === definition.reasonCode &&
      actualReceiptCount === 0;
    return {
      id: definition.id,
      inputSha256: sha256Canonical(digestInput),
      expectedDisposition: definition.disposition,
      actualDisposition: result?.disposition ?? 'inconclusive',
      expectedReceiptCount: 0,
      actualReceiptCount,
      stage: typeof result?.stage === 'string' ? result.stage : 'input-admission',
      reasonCode:
        typeof result?.reasonCode === 'string' ? result.reasonCode : 'malformed-hostile-output',
      passed,
    };
  });
  return {
    schemaVersion: 'overlaykit-h045-hostile-matrix/v1',
    requiredCaseIds: [...H045_REQUIRED_CASE_IDS],
    caseCount: cases.length,
    passedCount: cases.filter((entry) => entry.passed).length,
    allPassed:
      same(
        cases.map((entry) => entry.id),
        H045_REQUIRED_CASE_IDS
      ) && cases.every((entry) => entry.passed),
    cases,
  };
}

function hasProhibitedCapability(audit) {
  return Object.values(audit?.prohibitedCounts ?? {}).some(
    (value) => Number.isSafeInteger(value) && value > 0
  );
}

export function outcomeFor(sourceAdmission, capabilityAudit, classification, hostileMatrix) {
  if (hasProhibitedCapability(capabilityAudit)) {
    return {
      status: 'refuted',
      stage: 'capability-boundary',
      reasonCode: 'prohibited-capability-observed',
    };
  }
  if (classification?.disposition === 'candidate' && !classificationExactShape(classification)) {
    return {
      status: 'refuted',
      stage: 'live-classification',
      reasonCode: 'unsafe-live-classification',
    };
  }
  if (hostileMatrix?.allPassed !== true) {
    return {
      status: 'refuted',
      stage: 'hostile-matrix',
      reasonCode: 'hostile-case-failed',
    };
  }
  if (sourceAdmission?.allExact !== true) {
    return {
      status: 'inconclusive',
      stage: 'source-admission',
      reasonCode: 'source-admission-inexact',
    };
  }
  if (capabilityAudit?.complete !== true || capabilityAudit?.exact !== true) {
    return {
      status: 'inconclusive',
      stage: 'capability-audit',
      reasonCode: 'capability-audit-incomplete-or-inexact',
    };
  }
  if (classification?.disposition === 'inconclusive') {
    return {
      status: 'inconclusive',
      stage: classification.stage,
      reasonCode: classification.reasonCode,
    };
  }
  if (
    ['candidate', 'withheld'].includes(classification?.disposition) &&
    classificationExactShape(classification)
  ) {
    return {
      status: 'supported',
      stage: 'dynamic-readonly-acquisition',
      reasonCode: 'complete-live-classification-and-hostile-matrix-exact',
    };
  }
  return {
    status: 'inconclusive',
    stage: 'live-classification',
    reasonCode: 'live-classification-invalid',
  };
}

function boundedOutput(stream, maxBufferBytes) {
  const chunks = [];
  let retainedBytes = 0;
  let observedBytes = 0;
  stream.on('data', (value) => {
    const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
    observedBytes += chunk.byteLength;
    const remaining = maxBufferBytes + 1 - retainedBytes;
    if (remaining > 0) {
      const retained = chunk.subarray(0, remaining);
      chunks.push(retained);
      retainedBytes += retained.byteLength;
    }
  });
  return {
    bytes: () => Buffer.concat(chunks, retainedBytes),
    overflowed: () => observedBytes > maxBufferBytes,
  };
}

function commandFailure(code, message, result, cause = null) {
  const error = new Error(message, cause === null ? undefined : { cause });
  error.code = code;
  error.exitCode = result.exitCode;
  error.signal = result.signal;
  error.stdout = result.stdout;
  error.stderr = result.stderr;
  return error;
}

export function createAbsoluteCommandRunner(spawnImpl = spawn) {
  if (typeof spawnImpl !== 'function') throw new TypeError('spawnImpl must be a function');
  return (executable, args, options = {}) =>
    new Promise((resolve, reject) => {
      const binary = ABSOLUTE_EXECUTABLES[executable];
      if (binary === undefined) {
        reject(new Error(`H-045 executable ${String(executable)} is not admitted`));
        return;
      }
      if (!Array.isArray(args) || !plainObject(options.env)) {
        reject(new TypeError('H-045 runner requires args and options.env'));
        return;
      }
      if (!Number.isSafeInteger(options.maxBufferBytes) || options.maxBufferBytes <= 0) {
        reject(new TypeError('H-045 runner requires a positive maxBufferBytes'));
        return;
      }
      let child;
      try {
        child = spawnImpl(binary, [...args], {
          cwd: REPOSITORY_ROOT,
          env: options.env,
          shell: false,
          stdio: ['ignore', 'pipe', 'pipe'],
          windowsHide: true,
        });
      } catch (error) {
        reject(error);
        return;
      }
      if (
        child === null ||
        typeof child !== 'object' ||
        typeof child.once !== 'function' ||
        typeof child.stdout?.on !== 'function' ||
        typeof child.stderr?.on !== 'function'
      ) {
        reject(new TypeError('H-045 spawn implementation returned an invalid child'));
        return;
      }
      const stdout = boundedOutput(child.stdout, options.maxBufferBytes);
      const stderr = boundedOutput(child.stderr, options.maxBufferBytes);
      let spawnError = null;
      child.once('error', (error) => {
        spawnError = error;
      });
      child.once('close', (exitCode, signal) => {
        const result = {
          exitCode: Number.isInteger(exitCode) ? exitCode : null,
          signal: typeof signal === 'string' ? signal : null,
          stdout: stdout.bytes(),
          stderr: stderr.bytes(),
        };
        if (stdout.overflowed() || stderr.overflowed()) {
          reject(
            commandFailure(
              'COMMAND_OUTPUT_OVERFLOW',
              'H-045 command output exceeded the bounded receipt after natural exit',
              result
            )
          );
          return;
        }
        if (spawnError !== null) {
          reject(
            commandFailure('COMMAND_SPAWN_FAILED', 'H-045 command spawn failed', result, spawnError)
          );
          return;
        }
        if (result.signal !== null) {
          reject(
            commandFailure(
              'COMMAND_EXIT_SIGNAL',
              `H-045 command exited by signal ${result.signal}`,
              result
            )
          );
          return;
        }
        if (result.exitCode !== 0) {
          reject(
            commandFailure(
              'COMMAND_EXIT_NONZERO',
              `H-045 command exited with code ${String(result.exitCode)}`,
              result
            )
          );
          return;
        }
        resolve({
          exitCode: result.exitCode,
          signal: null,
          stdout: result.stdout,
          stderr: result.stderr,
        });
      });
    });
}

function liveFilesystem() {
  return {
    readFileSync,
    readdirSync,
    realpathSync,
    statSync,
    lstatSync,
    readlinkSync,
  };
}

async function sha256File(filePath) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filePath)) hash.update(chunk);
  return hash.digest('hex');
}

async function captureRuntimeReceipt() {
  const [binary, binarySha256] = await Promise.all([
    stat(process.execPath),
    sha256File(process.execPath),
  ]);
  return {
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    binarySha256,
    binaryByteLength: binary.size,
  };
}

async function sourceReceipts() {
  return Promise.all(
    H045_REQUIRED_SOURCE_PATHS.map(async (relativePath) => ({
      path: relativePath,
      sha256: sha256(await readFile(path.join(REPOSITORY_ROOT, relativePath))),
    }))
  );
}

async function loadAdmission() {
  const paths = {
    manifest: '.overlaykit/governance/manifest.json',
    plan: '.overlaykit/governance/plan.json',
    chg0018: '.overlaykit/governance/changes/CHG-0018.json',
    chg0019: '.overlaykit/governance/changes/CHG-0019.json',
    chg0020: '.overlaykit/governance/changes/CHG-0020.json',
    adr0006: '.overlaykit/governance/decisions/ADR-0006.json',
  };
  const [publicReceipt, manifestBytes, planBytes, chg0018, chg0019, chg0020, adr0006] =
    await Promise.all([
      readFile(H044_PUBLIC_RECEIPT_PATH),
      ...Object.values(paths).map((relativePath) =>
        readFile(path.join(REPOSITORY_ROOT, relativePath))
      ),
    ]);
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const plan = JSON.parse(planBytes.toString('utf8'));
  const planSha256 = sha256(planBytes);
  const manifestSha256 = sha256(manifestBytes);
  return {
    historical: readHistoricalEvidence(publicReceipt, adr0006),
    governance: {
      verified:
        plan.planHash === H045_PLAN_HASH &&
        planSha256 === H045_GOVERNANCE_PLAN_SHA256 &&
        manifest.contentHash === H045_MANIFEST_CONTENT_HASH &&
        manifestSha256 === H045_GOVERNANCE_MANIFEST_SHA256,
      planHash: plan.planHash,
      planSha256,
      manifestContentHash: manifest.contentHash,
      manifestSha256,
      changes: {
        'CHG-0018': sha256(chg0018),
        'CHG-0019': sha256(chg0019),
        'CHG-0020': sha256(chg0020),
      },
      decisions: {
        'ADR-0006': sha256(adr0006),
      },
      requiredSourcePaths: [...H045_REQUIRED_SOURCE_PATHS],
    },
  };
}

async function compileSchema() {
  const schema = JSON.parse(await readFile(SCHEMA_PATH, 'utf8'));
  return new Ajv2020({ allErrors: true, strict: true }).compile(schema);
}

function artifactOutputRoot(outputRoot) {
  if (typeof outputRoot !== 'string' || outputRoot === '') {
    throw new TypeError('H-045 artifact root must be a non-empty string');
  }
  const resolved = path.resolve(outputRoot);
  if (resolved !== ARTIFACT_ROOT && !resolved.startsWith(`${ARTIFACT_ROOT}${path.sep}`)) {
    throw new Error('H-045 artifacts must remain below artifacts/h045');
  }
  return resolved;
}

function pathWithin(root, candidate) {
  return candidate === root || candidate.startsWith(`${root}${path.sep}`);
}

function effectiveFilesystemIdentity() {
  if (typeof process.geteuid !== 'function' || typeof process.getegid !== 'function') {
    throw new Error('H-045 requires effective POSIX filesystem identity');
  }
  return {
    uid: process.geteuid(),
    gid: process.getegid(),
  };
}

function descriptorPath(handle, childName = null) {
  const root = `/proc/self/fd/${String(handle.fd)}`;
  return childName === null ? root : path.join(root, childName);
}

function safePathComponent(name, label) {
  if (
    typeof name !== 'string' ||
    name === '' ||
    name === '.' ||
    name === '..' ||
    path.basename(name) !== name
  ) {
    throw new Error(`H-045 ${label} must be one safe path component`);
  }
  return name;
}

function assertSecurePathLength(target, label) {
  if (Buffer.byteLength(target, 'utf8') > MAX_SECURE_PATH_BYTES) {
    throw new Error(`H-045 ${label} path exceeds ${MAX_SECURE_PATH_BYTES} UTF-8 bytes`);
  }
}

async function assertDirectoryHandle(receipt) {
  const [metadata, canonical] = await Promise.all([
    receipt.handle.stat(),
    realpath(descriptorPath(receipt.handle)),
  ]);
  if (!metadata.isDirectory() || canonical !== receipt.expectedPath) {
    throw new Error(`H-045 refuses non-canonical or symbolic directory ${receipt.expectedPath}`);
  }
  if (
    receipt.requireEffectiveOwner &&
    (metadata.uid !== receipt.identity.uid || metadata.gid !== receipt.identity.gid)
  ) {
    throw new Error(`H-045 directory owner identity changed for ${receipt.expectedPath}`);
  }
  if (receipt.requiredMode !== null && (metadata.mode & 0o777) !== receipt.requiredMode) {
    throw new Error(
      `H-045 directory mode changed for ${receipt.expectedPath}; expected ${receipt.requiredMode.toString(
        8
      )}`
    );
  }
  return metadata;
}

async function openDirectoryHandle(
  target,
  label,
  {
    requiredMode = null,
    requireEffectiveOwner = false,
    normalizeMode = false,
    viaPath = target,
  } = {}
) {
  const expectedPath = path.resolve(target);
  assertSecurePathLength(expectedPath, label);
  let handle;
  try {
    handle = await open(
      viaPath,
      FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_DIRECTORY | FS_CONSTANTS.O_NOFOLLOW
    );
  } catch (error) {
    throw new Error(`H-045 refuses non-canonical or symbolic directory ${expectedPath}`, {
      cause: error,
    });
  }
  const receipt = {
    handle,
    expectedPath,
    identity: effectiveFilesystemIdentity(),
    label,
    requiredMode,
    requireEffectiveOwner,
  };
  try {
    const admitted = await assertDirectoryHandle({
      ...receipt,
      requiredMode: null,
    });
    if (
      requireEffectiveOwner &&
      (admitted.uid !== receipt.identity.uid || admitted.gid !== receipt.identity.gid)
    ) {
      throw new Error(`H-045 directory owner identity changed for ${expectedPath}`);
    }
    if (normalizeMode) await handle.chmod(requiredMode);
    await assertDirectoryHandle(receipt);
    return receipt;
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function assertDirectoryChain(receipts) {
  for (const receipt of receipts) await assertDirectoryHandle(receipt);
}

async function closeDirectoryChain(receipts) {
  await Promise.allSettled([...receipts].reverse().map((receipt) => receipt.handle.close()));
}

async function openSecureDirectoryChain(target) {
  const resolved = path.resolve(target);
  assertSecurePathLength(resolved, 'artifact root');
  const receipts = [];
  try {
    receipts.push(
      await openDirectoryHandle('/', 'filesystem root', {
        viaPath: '/',
      })
    );
    let expectedPath = '/';
    for (const component of resolved.split(path.sep).filter((entry) => entry !== '')) {
      const parent = receipts.at(-1);
      await assertDirectoryHandle(parent);
      const childPath = descriptorPath(parent.handle, component);
      let created = false;
      try {
        await mkdir(childPath, { mode: SECURE_DIRECTORY_MODE });
        created = true;
      } catch (error) {
        if (error?.code !== 'EEXIST') throw error;
      }
      expectedPath = path.join(expectedPath, component);
      const final = expectedPath === resolved;
      receipts.push(
        await openDirectoryHandle(expectedPath, 'artifact path component', {
          viaPath: childPath,
          requiredMode: created || final ? SECURE_DIRECTORY_MODE : null,
          requireEffectiveOwner: created || final,
          normalizeMode: created || final,
        })
      );
      await assertDirectoryHandle(parent);
    }
    await assertDirectoryChain(receipts);
    return receipts;
  } catch (error) {
    await closeDirectoryChain(receipts);
    throw error;
  }
}

async function createSecureChildDirectory(parent, name, label) {
  safePathComponent(name, label);
  await assertDirectoryHandle(parent);
  const expectedPath = path.join(parent.expectedPath, name);
  assertSecurePathLength(expectedPath, label);
  const childPath = descriptorPath(parent.handle, name);
  await mkdir(childPath, { mode: SECURE_DIRECTORY_MODE });
  const child = await openDirectoryHandle(expectedPath, label, {
    viaPath: childPath,
    requiredMode: SECURE_DIRECTORY_MODE,
    requireEffectiveOwner: true,
    normalizeMode: true,
  });
  try {
    await assertDirectoryHandle(parent);
    return child;
  } catch (error) {
    await child.handle.close();
    throw error;
  }
}

function boundedPrettyJson(value, maximumBytes, label) {
  const text = JSON.stringify(value, null, 2);
  if (typeof text !== 'string') {
    throw new TypeError(`H-045 ${label} is not JSON-serializable`);
  }
  const byteLength = Buffer.byteLength(text, 'utf8') + 1;
  if (byteLength > maximumBytes) {
    throw new RangeError(`H-045 ${label} exceeds ${maximumBytes} bytes`);
  }
  return Buffer.from(`${text}\n`, 'utf8');
}

async function assertNewFileHandle(handle, expectedPath, label, expectedBytes) {
  const identity = effectiveFilesystemIdentity();
  const [metadata, canonical] = await Promise.all([
    handle.stat(),
    realpath(descriptorPath(handle)),
  ]);
  if (!metadata.isFile() || canonical !== expectedPath) {
    throw new Error(`H-045 refuses non-canonical or symbolic file ${expectedPath}`);
  }
  if (metadata.uid !== identity.uid || metadata.gid !== identity.gid) {
    throw new Error(`H-045 file owner identity changed for ${expectedPath}`);
  }
  if (metadata.nlink !== 1) {
    throw new Error(`H-045 file must have exactly one link ${expectedPath}`);
  }
  if ((metadata.mode & 0o777) !== SECURE_FILE_MODE) {
    throw new Error(`H-045 file mode changed for ${expectedPath}; expected 600`);
  }
  if (metadata.size !== expectedBytes.byteLength) {
    throw new Error(`H-045 file byte length changed for ${expectedPath}`);
  }
  return metadata;
}

async function writeJsonExclusive(directory, name, bytes, maximumBytes, label, anchors) {
  safePathComponent(name, `${label} filename`);
  if (!name.endsWith('.json')) {
    throw new Error(`H-045 ${label} filename is invalid`);
  }
  if (!Buffer.isBuffer(bytes) || bytes.byteLength > maximumBytes) {
    throw new RangeError(`H-045 ${label} exceeds ${maximumBytes} bytes`);
  }
  const target = path.join(directory.expectedPath, name);
  assertSecurePathLength(target, label);
  await assertDirectoryChain(anchors);
  const handle = await open(
    descriptorPath(directory.handle, name),
    FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_NOFOLLOW,
    SECURE_FILE_MODE
  );
  try {
    await handle.chmod(SECURE_FILE_MODE);
    const initial = await handle.stat();
    const identity = effectiveFilesystemIdentity();
    const canonical = await realpath(descriptorPath(handle));
    if (
      !initial.isFile() ||
      initial.uid !== identity.uid ||
      initial.gid !== identity.gid ||
      initial.nlink !== 1 ||
      canonical !== target
    ) {
      throw new Error(`H-045 refuses aliased or foreign file ${target}`);
    }
    await handle.writeFile(bytes);
    await handle.sync();
    await assertNewFileHandle(handle, target, label, bytes);
    await assertDirectoryChain(anchors);
    await assertNewFileHandle(handle, target, label, bytes);
  } finally {
    await handle.close();
  }
  return {
    path: target,
    sha256: sha256(bytes),
  };
}

function stableExistingMetadata(before, after) {
  return ['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs'].every(
    (field) => before[field] === after[field]
  );
}

async function readExistingFileBounded(handle, maximumBytes, label) {
  const chunks = [];
  let total = 0;
  let position = 0;
  while (true) {
    const length = Math.min(64 * 1024, maximumBytes - total + 1);
    const buffer = Buffer.allocUnsafe(length);
    const { bytesRead } = await handle.read(buffer, 0, length, position);
    if (bytesRead === 0) break;
    total += bytesRead;
    if (total > maximumBytes) {
      throw new RangeError(`H-045 ${label} exceeds ${maximumBytes} bytes`);
    }
    chunks.push(buffer.subarray(0, bytesRead));
    position += bytesRead;
  }
  return Buffer.concat(chunks, total);
}

async function openPredecessorFile(directory, name, expectedSha256, label) {
  const expectedPath = path.join(directory.expectedPath, name);
  assertSecurePathLength(expectedPath, label);
  let handle;
  try {
    handle = await open(
      descriptorPath(directory.handle, name),
      FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW
    );
  } catch (error) {
    throw new Error(`H-045 predecessor ${label} cannot be opened securely`, { cause: error });
  }
  try {
    const identity = effectiveFilesystemIdentity();
    const [metadata, canonical] = await Promise.all([
      handle.stat({ bigint: true }),
      realpath(descriptorPath(handle)),
    ]);
    if (
      !metadata.isFile() ||
      canonical !== expectedPath ||
      metadata.uid !== BigInt(identity.uid) ||
      metadata.gid !== BigInt(identity.gid) ||
      metadata.nlink !== 1n ||
      (metadata.mode & 0o777n) !== 0o600n ||
      metadata.size > BigInt(MAX_LEDGER_RECEIPT_BYTES)
    ) {
      throw new Error(`H-045 predecessor ${label} metadata is inexact`);
    }
    const bytes = await readExistingFileBounded(handle, MAX_LEDGER_RECEIPT_BYTES, label);
    const [metadataAfter, canonicalAfter] = await Promise.all([
      handle.stat({ bigint: true }),
      realpath(descriptorPath(handle)),
    ]);
    if (
      canonicalAfter !== expectedPath ||
      !stableExistingMetadata(metadata, metadataAfter) ||
      metadataAfter.size !== BigInt(bytes.byteLength) ||
      sha256(bytes) !== expectedSha256
    ) {
      throw new Error(`H-045 predecessor ${label} bytes are inexact`);
    }
    return { handle, expectedPath, expectedSha256, metadata, bytes, label };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function assertPredecessorFileStable(receipt) {
  const [metadataBefore, canonicalBefore] = await Promise.all([
    receipt.handle.stat({ bigint: true }),
    realpath(descriptorPath(receipt.handle)),
  ]);
  const bytes = await readExistingFileBounded(
    receipt.handle,
    MAX_LEDGER_RECEIPT_BYTES,
    receipt.label
  );
  const [metadataAfter, canonicalAfter] = await Promise.all([
    receipt.handle.stat({ bigint: true }),
    realpath(descriptorPath(receipt.handle)),
  ]);
  if (
    canonicalBefore !== receipt.expectedPath ||
    canonicalAfter !== receipt.expectedPath ||
    !stableExistingMetadata(receipt.metadata, metadataBefore) ||
    !stableExistingMetadata(metadataBefore, metadataAfter) ||
    metadataAfter.size !== BigInt(bytes.byteLength) ||
    sha256(bytes) !== receipt.expectedSha256
  ) {
    throw new Error(`H-045 predecessor ${receipt.label} changed`);
  }
}

async function predecessorEntries(directory) {
  let entries;
  try {
    entries = (await readdir(descriptorPath(directory.handle))).sort();
  } catch (error) {
    throw new Error('H-045 predecessor attempt cannot be enumerated', { cause: error });
  }
  if (!same(entries, ['failure.json', 'reservation.json'])) {
    throw new Error('H-045 predecessor attempt membership is inexact');
  }
  return entries;
}

async function openPredecessorAttempt(artifactRoot) {
  const expectedPath = path.join(artifactRoot.expectedPath, PREDECESSOR_ATTEMPT_DIRECTORY);
  let directory;
  let reservation;
  let failure;
  try {
    directory = await openDirectoryHandle(expectedPath, 'predecessor attempt directory', {
      viaPath: descriptorPath(artifactRoot.handle, PREDECESSOR_ATTEMPT_DIRECTORY),
      requiredMode: SECURE_DIRECTORY_MODE,
      requireEffectiveOwner: true,
    });
    await predecessorEntries(directory);
    reservation = await openPredecessorFile(
      directory,
      'reservation.json',
      PREDECESSOR_RESERVATION_SHA256,
      'attempt reservation'
    );
    failure = await openPredecessorFile(
      directory,
      'failure.json',
      PREDECESSOR_FAILURE_SHA256,
      'attempt failure'
    );
    const parsedFailure = JSON.parse(failure.bytes.toString('utf8'));
    if (
      !exactKeys(parsedFailure, [
        'schemaVersion',
        'reservationSha256',
        'stage',
        'observationStarted',
      ]) ||
      parsedFailure.schemaVersion !== 'overlaykit-h045-live-attempt-failure/v1' ||
      parsedFailure.reservationSha256 !== PREDECESSOR_RESERVATION_SHA256 ||
      parsedFailure.stage !== 'runtime-admission' ||
      parsedFailure.observationStarted !== true
    ) {
      throw new Error('H-045 predecessor failure receipt is inexact');
    }
    return { directory, reservation, failure };
  } catch (error) {
    await Promise.allSettled([reservation?.handle.close(), failure?.handle.close()]);
    if (directory !== undefined) await directory.handle.close();
    throw error;
  }
}

async function assertPredecessorAttemptStable(predecessor) {
  await assertDirectoryHandle(predecessor.directory);
  await predecessorEntries(predecessor.directory);
  await assertPredecessorFileStable(predecessor.reservation);
  await assertPredecessorFileStable(predecessor.failure);
  await assertDirectoryHandle(predecessor.directory);
}

async function closePredecessorAttempt(predecessor) {
  if (predecessor === null || predecessor === undefined) return;
  await Promise.allSettled([
    predecessor.reservation.handle.close(),
    predecessor.failure.handle.close(),
  ]);
  await predecessor.directory.handle.close();
}

function createAttemptLedger(outputRoot, canonical) {
  if (typeof outputRoot !== 'string' || outputRoot === '') {
    throw new TypeError('H-045 attempt ledger root must be a non-empty string');
  }
  if (typeof canonical !== 'boolean') {
    throw new TypeError('H-045 attempt ledger mode must be explicit');
  }
  const root = path.resolve(outputRoot);
  const attemptDirectory = path.resolve(root, REPLACEMENT_ATTEMPT_ID);
  if (!pathWithin(root, attemptDirectory) || attemptDirectory === root) {
    throw new Error('H-045 attempt ledger escaped its root');
  }
  let active = null;
  let reservationInProgress = false;

  async function closeActive() {
    if (active === null) return;
    const receipts = [...active.rootChain, active.attemptDirectory];
    const predecessor = active.predecessor;
    active = null;
    await closePredecessorAttempt(predecessor);
    await closeDirectoryChain(receipts);
  }

  function requireActive() {
    if (active === null) {
      throw new Error('H-045 attempt ledger has no active reservation');
    }
    return active;
  }

  return Object.freeze({
    async reserve({
      reservedAt,
      authorization,
      sourceSetSha256: authorizedDigest,
      semantics,
    } = {}) {
      if (!validDateTime(reservedAt)) {
        throw new Error('H-045 reservation timestamp is invalid');
      }
      if (!SHA256_PATTERN.test(authorizedDigest ?? '')) {
        throw new Error('H-045 reservation source digest is invalid');
      }
      if (canonical) {
        const parsedDigest = parseH045LiveAuthorization(authorization);
        if (authorizedDigest !== parsedDigest || semantics !== undefined) {
          throw new Error('H-045 reservation authorization digest mismatch');
        }
      } else if (authorization !== undefined || semantics !== 'offline-non-authorizing-fixture') {
        throw new Error('H-045 offline reservation cannot accept live authority');
      }
      if (active !== null || reservationInProgress) {
        throw new Error('H-045 attempt ledger already has an active reservation');
      }
      const receipt = canonical
        ? {
            schemaVersion: 'overlaykit-h045-live-attempt-reservation/v2',
            reservedAt,
            change: 'CHG-0020',
            hypothesis: 'H-045',
            attempt: REPLACEMENT_ATTEMPT_ID,
            predecessor: {
              reservationSha256: PREDECESSOR_RESERVATION_SHA256,
              failureSha256: PREDECESSOR_FAILURE_SHA256,
            },
            authorization: {
              grant: authorization,
              sourceSetSha256: authorizedDigest,
              semantics: 'one-live-read-only-replacement-attempt',
              authority: 'none',
              action: null,
            },
          }
        : {
            schemaVersion: 'overlaykit-h045-offline-attempt-reservation/v2',
            reservedAt,
            hypothesis: 'H-045',
            attempt: REPLACEMENT_ATTEMPT_ID,
            predecessor: {
              reservationSha256: PREDECESSOR_RESERVATION_SHA256,
              failureSha256: PREDECESSOR_FAILURE_SHA256,
            },
            sourceBinding: {
              sourceSetSha256: authorizedDigest,
              semantics: 'offline-non-authorizing-fixture',
              authority: 'none',
              action: null,
            },
          };
      const bytes = boundedPrettyJson(
        receipt,
        MAX_LEDGER_RECEIPT_BYTES,
        'attempt reservation receipt'
      );
      reservationInProgress = true;
      let rootChain = [];
      let predecessor = null;
      let attempt = null;
      try {
        rootChain = await openSecureDirectoryChain(root);
        predecessor = await openPredecessorAttempt(rootChain.at(-1));
        await assertPredecessorAttemptStable(predecessor);
        attempt = await createSecureChildDirectory(
          rootChain.at(-1),
          REPLACEMENT_ATTEMPT_ID,
          'attempt ledger directory'
        );
        const anchors = [...rootChain, attempt];
        const written = await writeJsonExclusive(
          attempt,
          'reservation.json',
          bytes,
          MAX_LEDGER_RECEIPT_BYTES,
          'attempt reservation receipt',
          anchors
        );
        active = {
          attemptDirectory: attempt,
          predecessor,
          rootChain,
        };
        await assertPredecessorAttemptStable(predecessor);
        return {
          ...written,
          receipt: clone(receipt),
        };
      } catch (error) {
        if (active?.predecessor === predecessor) active = null;
        await closePredecessorAttempt(predecessor);
        await closeDirectoryChain([...rootChain, ...(attempt === null ? [] : [attempt])]);
        throw error;
      } finally {
        reservationInProgress = false;
      }
    },

    async persistRun(run) {
      const session = requireActive();
      await assertPredecessorAttemptStable(session.predecessor);
      const bytes = prepareRunJson(run);
      const persisted = await persistRunWithAnchors(run, bytes, session.rootChain);
      await assertPredecessorAttemptStable(session.predecessor);
      return persisted;
    },

    async fail({ reservationSha256, stage, observationStarted } = {}) {
      const session = requireActive();
      try {
        await assertPredecessorAttemptStable(session.predecessor);
        if (!SHA256_PATTERN.test(reservationSha256 ?? '')) {
          throw new Error('H-045 failure receipt lacks its reservation digest');
        }
        if (typeof stage !== 'string' || stage === '') {
          throw new Error('H-045 failure receipt stage is invalid');
        }
        if (typeof observationStarted !== 'boolean') {
          throw new Error('H-045 failure receipt observationStarted is invalid');
        }
        const receipt = {
          schemaVersion: canonical
            ? 'overlaykit-h045-live-attempt-failure/v2'
            : 'overlaykit-h045-offline-attempt-failure/v2',
          reservationSha256,
          stage,
          observationStarted,
        };
        const bytes = boundedPrettyJson(
          receipt,
          MAX_LEDGER_RECEIPT_BYTES,
          'attempt failure receipt'
        );
        const written = await writeJsonExclusive(
          session.attemptDirectory,
          'failure.json',
          bytes,
          MAX_LEDGER_RECEIPT_BYTES,
          'attempt failure receipt',
          [...session.rootChain, session.attemptDirectory]
        );
        await assertPredecessorAttemptStable(session.predecessor);
        return written;
      } finally {
        await closeActive();
      }
    },

    async complete({ reservationSha256, completedAt, evidenceSha256 } = {}) {
      const session = requireActive();
      try {
        await assertPredecessorAttemptStable(session.predecessor);
        if (
          !SHA256_PATTERN.test(reservationSha256 ?? '') ||
          !validDateTime(completedAt) ||
          !SHA256_PATTERN.test(evidenceSha256 ?? '')
        ) {
          throw new Error('H-045 completion receipt is invalid');
        }
        const receipt = {
          schemaVersion: canonical
            ? 'overlaykit-h045-live-attempt-completion/v2'
            : 'overlaykit-h045-offline-attempt-completion/v2',
          reservationSha256,
          completedAt,
          evidenceSha256,
        };
        const bytes = boundedPrettyJson(
          receipt,
          MAX_LEDGER_RECEIPT_BYTES,
          'attempt completion receipt'
        );
        const written = await writeJsonExclusive(
          session.attemptDirectory,
          'completion.json',
          bytes,
          MAX_LEDGER_RECEIPT_BYTES,
          'attempt completion receipt',
          [...session.rootChain, session.attemptDirectory]
        );
        await assertPredecessorAttemptStable(session.predecessor);
        return written;
      } finally {
        await closeActive();
      }
    },
  });
}

function createCanonicalAttemptLedger() {
  return createAttemptLedger(ARTIFACT_ROOT, true);
}

export function createOfflineAttemptLedgerForTest(outputRoot) {
  return createAttemptLedger(outputRoot, false);
}

function prepareRunJson(run) {
  if (
    typeof run?.runId !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(run.runId) ||
    path.basename(run.runId) !== run.runId
  ) {
    throw new Error('H-045 runId is not one safe path component');
  }
  return boundedPrettyJson(run, MAX_RUN_JSON_BYTES, 'run.json');
}

async function persistRunWithAnchors(run, bytes, rootChain) {
  if (!Array.isArray(rootChain) || rootChain.length === 0) {
    throw new Error('H-045 run persistence lacks its retained artifact root');
  }
  await assertDirectoryChain(rootChain);
  let directory = null;
  try {
    directory = await createSecureChildDirectory(rootChain.at(-1), run.runId, 'run directory');
    return (
      await writeJsonExclusive(directory, 'run.json', bytes, MAX_RUN_JSON_BYTES, 'run.json', [
        ...rootChain,
        directory,
      ])
    ).path;
  } finally {
    if (directory !== null) await closeDirectoryChain([directory]);
  }
}

export async function persistRun(run, outputRoot) {
  const root = artifactOutputRoot(outputRoot);
  const bytes = prepareRunJson(run);
  const rootChain = await openSecureDirectoryChain(root);
  try {
    return await persistRunWithAnchors(run, bytes, rootChain);
  } finally {
    await closeDirectoryChain(rootChain);
  }
}

function publicSourceAdmission({
  preflight,
  finalAdmission,
  governance,
  sourcesInitial,
  sourcesBeforeLive,
  sourcesAfter,
}) {
  const values = {
    h044PublicReceiptExact:
      preflight.checks.h044PublicReceiptExact && finalAdmission.checks.h044PublicReceiptExact,
    h044SemanticEvidenceExact:
      preflight.checks.h044SemanticEvidenceExact && finalAdmission.checks.h044SemanticEvidenceExact,
    acceptedDecisionExact:
      preflight.checks.acceptedDecisionExact && finalAdmission.checks.acceptedDecisionExact,
    acceptedTargetContextExact:
      preflight.checks.acceptedTargetContextExact &&
      finalAdmission.checks.acceptedTargetContextExact,
    historicalBoundaryExact:
      preflight.checks.historicalBoundaryExact && finalAdmission.checks.historicalBoundaryExact,
    chg0018Exact: governance.changes['CHG-0018'] === H045_CHG_0018_SHA256,
    chg0019Exact: governance.changes['CHG-0019'] === H045_CHG_0019_SHA256,
    chg0020Exact: governance.changes['CHG-0020'] === H045_CHG_0020_SHA256,
    adr0006Exact: governance.decisions['ADR-0006'] === H045_ADR_0006_SHA256,
    repositoryRemoteExact:
      preflight.checks.repositoryRemoteExact && finalAdmission.checks.repositoryRemoteExact,
    observedHeadWellFormed:
      preflight.checks.observedHeadWellFormed && finalAdmission.checks.observedHeadWellFormed,
    protectedMainExact:
      preflight.checks.protectedMainExact && finalAdmission.checks.protectedMainExact,
    sourceContractExact:
      preflight.checks.sourceContractExact && finalAdmission.checks.sourceContractExact,
    protectedMainAncestryExact:
      preflight.checks.protectedMainAncestor && finalAdmission.checks.protectedMainAncestor,
    sourceContractAncestryExact:
      preflight.checks.sourceContractAncestor && finalAdmission.checks.sourceContractAncestor,
    runtimeBinaryExact: preflight.checks.nodeRuntimeExact && finalAdmission.checks.nodeRuntimeExact,
    targetInputExact:
      preflight.checks.stableTargetInputExact && finalAdmission.checks.stableTargetInputExact,
    governanceExact: preflight.governanceExact && finalAdmission.governanceExact,
    sourceSetExact: preflight.sourceSetExact && finalAdmission.sourceSetExact,
    sourceStable:
      preflight.sourceStable &&
      finalAdmission.sourceStable &&
      same(sourcesInitial, sourcesBeforeLive) &&
      same(sourcesBeforeLive, sourcesAfter),
    allExact: false,
  };
  values.allExact = Object.entries(values)
    .filter(([key]) => key !== 'allExact')
    .every(([, exact]) => exact === true);
  return values;
}

function gitReceipt(value) {
  return {
    repositoryRemote: value.remoteUrl,
    head: value.head,
    protectedMainCommit: value.protectedMainCommit,
    sourceContractCommit: value.sourceContractCommit,
    protectedMainAncestor: value.protectedMainIsAncestor,
    sourceContractAncestor: value.sourceContractIsAncestor,
  };
}

function runId(startedAt, sources) {
  const timestamp = startedAt.replaceAll(':', '-').replace('.', '-');
  return `h045-${timestamp}-${sha256Canonical({ startedAt, sources }).slice(0, 8)}`;
}

function governanceReceiptExact(governance) {
  return Boolean(
    governance?.verified === true &&
    governance.planHash === H045_PLAN_HASH &&
    governance.planSha256 === H045_GOVERNANCE_PLAN_SHA256 &&
    governance.manifestContentHash === H045_MANIFEST_CONTENT_HASH &&
    governance.manifestSha256 === H045_GOVERNANCE_MANIFEST_SHA256 &&
    governance.changes?.['CHG-0018'] === H045_CHG_0018_SHA256 &&
    governance.changes?.['CHG-0019'] === H045_CHG_0019_SHA256 &&
    governance.changes?.['CHG-0020'] === H045_CHG_0020_SHA256 &&
    governance.decisions?.['ADR-0006'] === H045_ADR_0006_SHA256 &&
    same(governance.requiredSourcePaths, H045_REQUIRED_SOURCE_PATHS)
  );
}

const DEFAULT_DEPENDENCIES = Object.freeze({
  captureRuntimeReceipt,
  sourceReceipts,
  loadAdmission,
  createCommandAuditor,
  createFilesystemAuditor,
  captureGitAdmission,
  captureLsusbAdmission,
  captureDockerAdmission,
  captureObservationFrame,
  buildCapabilityAudit,
  classifyDynamicFrames,
  evaluateHostileMatrix,
  compileSchema,
  persistRun,
});

function resolveDependencies(overrides) {
  if (!plainObject(overrides)) throw new TypeError('dependencies must be an object');
  const unexpected = Object.keys(overrides).filter(
    (key) => !Object.hasOwn(DEFAULT_DEPENDENCIES, key)
  );
  if (unexpected.length > 0) {
    throw new TypeError(`unknown H-045 dependencies: ${unexpected.sort().join(', ')}`);
  }
  const resolved = { ...DEFAULT_DEPENDENCIES, ...overrides };
  for (const [name, implementation] of Object.entries(resolved)) {
    if (typeof implementation !== 'function') {
      throw new TypeError(`H-045 dependency ${name} must be a function`);
    }
  }
  return resolved;
}

async function executeH045({
  executionMode,
  authorization,
  outputRoot,
  wallNow,
  monotonicNowNs,
  runner,
  filesystem,
  environment,
  attemptLedger,
  dependencyOverrides,
}) {
  if (!['canonical', 'offline-fixture'].includes(executionMode)) {
    throw new TypeError('H-045 execution mode is invalid');
  }
  const canonical = executionMode === 'canonical';
  const authorizedSourceDigest = parseH045LiveAuthorization(authorization);
  if (typeof wallNow !== 'function' || typeof monotonicNowNs !== 'function') {
    throw new TypeError('H-045 clocks must be functions');
  }
  const dependencies = resolveDependencies(dependencyOverrides);
  const startedAt = wallNow();
  if (!validDateTime(startedAt)) throw new Error('H-045 startedAt is invalid');
  if (!validMonotonicClockSample(monotonicNowNs())) {
    throw new Error('H-045 monotonic clock sample is invalid');
  }
  const ledger = attemptLedger;
  if (
    typeof ledger?.reserve !== 'function' ||
    typeof ledger?.fail !== 'function' ||
    typeof ledger?.complete !== 'function' ||
    (canonical && typeof ledger?.persistRun !== 'function')
  ) {
    throw new TypeError(
      'H-045 attempt ledger must expose reserve, fail, complete, and canonical persistence'
    );
  }

  let reservation = null;
  let stage = 'attempt-reservation';
  let observationStarted = false;
  try {
    reservation = await ledger.reserve(
      canonical
        ? {
            reservedAt: startedAt,
            authorization,
            sourceSetSha256: authorizedSourceDigest,
          }
        : {
            reservedAt: startedAt,
            sourceSetSha256: authorizedSourceDigest,
            semantics: 'offline-non-authorizing-fixture',
          }
    );
    if (!SHA256_PATTERN.test(reservation?.sha256 ?? '')) {
      throw new Error('H-045 attempt ledger returned an invalid reservation receipt');
    }

    stage = 'review-source-initial';
    const sourcesInitial = await dependencies.sourceReceipts();
    if (sourceSetSha256(sourcesInitial) !== authorizedSourceDigest) {
      throw new Error('H-045 reviewed source authorization does not match current sources');
    }

    stage = 'historical-and-governance-admission';
    const admitted = await dependencies.loadAdmission();
    if (!governanceReceiptExact(admitted?.governance)) {
      throw new Error('H-045 byte-exact governance admission failed');
    }

    stage = 'schema-compile';
    const validateSchema = await dependencies.compileSchema();
    if (typeof validateSchema !== 'function') {
      throw new TypeError('compileSchema must return a validator');
    }

    stage = 'review-source-before-observation';
    const sourcesBeforeLive = await dependencies.sourceReceipts();
    if (
      sourceSetSha256(sourcesBeforeLive) !== authorizedSourceDigest ||
      !same(sourcesInitial, sourcesBeforeLive)
    ) {
      throw new Error('H-045 reviewed sources drifted before live observation');
    }

    stage = 'runtime-admission';
    observationStarted = true;
    const runtime = await dependencies.captureRuntimeReceipt();
    const commandAuditor = dependencies.createCommandAuditor({
      runner,
      wallNow,
      monotonicNowNs,
      environment,
      maxBufferBytes: 4 * 1024 * 1024,
      timeoutMs: null,
    });
    const filesystemAuditor = dependencies.createFilesystemAuditor({
      filesystem,
      wallNow,
      monotonicNowNs,
    });

    stage = 'git-admission';
    const observedGit = await dependencies.captureGitAdmission(commandAuditor, {
      protectedMainCommit: H045_PROTECTED_MAIN_COMMIT,
      sourceContractCommit: H045_SOURCE_CONTRACT_COMMIT,
    });
    const git = gitReceipt(observedGit);
    const preflight = buildSourceAdmission({
      historical: admitted.historical,
      governance: admitted.governance,
      git,
      runtime,
      targetInput: clone(H045_STABLE_TARGET_INPUT),
      sourcesBefore: sourcesInitial,
      sourcesAfter: sourcesBeforeLive,
    });
    if (!preflight.exact || preflight.acceptedTarget === null) {
      throw new Error('H-045 source admission failed before live observation');
    }
    const acceptedTarget = {
      ...clone(preflight.acceptedTarget),
      serialBinding: clone(H045_ACCEPTED_SERIAL_BINDING),
    };
    const observerTarget = {
      serial: acceptedTarget.serial,
      vendorId: acceptedTarget.vendorId,
      productId: acceptedTarget.productId,
    };

    let lsusbAdmission = null;
    let dockerAdmission = null;
    stage = 'lsusb-admission';
    try {
      lsusbAdmission = await dependencies.captureLsusbAdmission(commandAuditor);
    } catch {
      // The auditor retains the exact failed receipt; there is no retry.
    }
    stage = 'docker-admission';
    try {
      dockerAdmission = await dependencies.captureDockerAdmission(commandAuditor);
    } catch {
      // The auditor retains the exact failed receipt; there is no retry.
    }

    const rawFrames = [];
    stage = 'frame-observation';
    if (lsusbAdmission !== null && dockerAdmission !== null) {
      for (const frameId of ['frame-1', 'frame-2']) {
        try {
          rawFrames.push(
            await dependencies.captureObservationFrame({
              frameId,
              commandAuditor,
              filesystemAuditor,
              lsusbAdmission,
              dockerAdmission,
              target: observerTarget,
              logSince: startedAt,
              wallNow,
              monotonicNowNs,
            })
          );
        } catch {
          break;
        }
      }
    }
    stage = 'capability-audit';
    const capabilityAudit = dependencies.buildCapabilityAudit({
      commandAuditor,
      filesystemAuditor,
      frames: rawFrames,
    });

    stage = 'post-observation-source';
    const sourcesAfter = await dependencies.sourceReceipts();
    const frames = rawFrames.map((frame) => normalizeObservationFrame(frame, acceptedTarget));
    while (frames.length < 2) {
      frames.push(incompleteFrame(`frame-${frames.length + 1}`, startedAt, '0'));
    }
    const liveClassification = dependencies.classifyDynamicFrames({
      frames,
      capabilityAudit,
      sourceAdmissionExact: preflight.exact,
    });
    const hostileMatrix = dependencies.evaluateHostileMatrix(
      dependencies.classifyDynamicFrames,
      acceptedTarget
    );
    const finalAdmission = buildSourceAdmission({
      historical: admitted.historical,
      governance: admitted.governance,
      git,
      runtime,
      targetInput: clone(H045_STABLE_TARGET_INPUT),
      sourcesBefore: sourcesInitial,
      sourcesAfter,
    });
    const sourceAdmission = publicSourceAdmission({
      preflight,
      finalAdmission,
      governance: admitted.governance,
      sourcesInitial,
      sourcesBeforeLive,
      sourcesAfter,
    });
    const outcome = outcomeFor(sourceAdmission, capabilityAudit, liveClassification, hostileMatrix);
    const completedAt = wallNow();
    if (!validDateTime(completedAt) || Date.parse(completedAt) < Date.parse(startedAt)) {
      throw new Error('H-045 completedAt is invalid');
    }
    const body = {
      schemaVersion: canonical
        ? 'overlaykit-h045-live-run/v2'
        : 'overlaykit-h045-offline-fixture/v1',
      hypothesis: 'H-045',
      runId: runId(startedAt, sourcesBeforeLive),
      startedAt,
      completedAt,
      outcome,
      collector: {
        ...(canonical
          ? {
              reviewAuthorization: {
                grant: authorization,
                sourceSetSha256: authorizedSourceDigest,
                semantics: 'one-live-read-only-replacement-attempt',
              },
              attemptLedger: {
                predecessorReservationRelativePath: PREDECESSOR_RESERVATION_RELATIVE_PATH,
                predecessorFailureRelativePath: PREDECESSOR_FAILURE_RELATIVE_PATH,
                predecessorReservationSha256: PREDECESSOR_RESERVATION_SHA256,
                predecessorFailureSha256: PREDECESSOR_FAILURE_SHA256,
                reservationRelativePath: REPLACEMENT_RESERVATION_RELATIVE_PATH,
                completionRelativePath: REPLACEMENT_COMPLETION_RELATIVE_PATH,
                reservationSha256: reservation.sha256,
                semantics: 'fixed-local-linked-one-shot-replacement-ledger',
              },
            }
          : {
              offlineSourceBinding: {
                sourceSetSha256: authorizedSourceDigest,
                semantics: 'offline-non-authorizing-source-binding',
              },
              offlineAttemptLedger: {
                reservationSha256: reservation.sha256,
                semantics: 'explicit-offline-fixture-ledger',
              },
            }),
        runtime: clone(runtime),
        repository: git.repositoryRemote,
        observedHead: git.head,
        protectedMain: {
          commit: git.protectedMainCommit,
          isAncestor: git.protectedMainAncestor,
        },
        sourceContract: {
          commit: git.sourceContractCommit,
          isAncestor: git.sourceContractAncestor,
        },
        sourcesBefore: clone(sourcesBeforeLive),
        sourcesAfter: clone(sourcesAfter),
        sourceStable: sourceAdmission.sourceStable,
        governance: clone(admitted.governance),
      },
      input: clone(H045_STABLE_TARGET_INPUT),
      sourceAdmission,
      acceptedTarget,
      frames,
      capabilityAudit: clone(capabilityAudit),
      liveClassification: clone(liveClassification),
      hostileMatrix: clone(hostileMatrix),
      claimBoundary: clone(H045_CLAIM_BOUNDARY),
    };
    const run = { ...body, evidenceSha256: sha256Canonical(body) };
    stage = 'schema-validation';
    if (!validateSchema(run)) {
      throw new Error(
        `H-045 produced schema-invalid evidence: ${JSON.stringify(validateSchema.errors)}`
      );
    }
    stage = 'persistence';
    const runPath = canonical
      ? await ledger.persistRun(run)
      : await dependencies.persistRun(run, outputRoot);
    stage = 'attempt-completion';
    await ledger.complete({
      reservationSha256: reservation.sha256,
      completedAt,
      evidenceSha256: run.evidenceSha256,
    });
    return { run, runPath };
  } catch (error) {
    if (reservation !== null) {
      try {
        await ledger.fail({
          reservationSha256: reservation.sha256,
          stage,
          observationStarted,
        });
      } catch (failureReceiptError) {
        error.failureReceiptError = failureReceiptError;
      }
    }
    throw error;
  }
}

const CANONICAL_RUN_KEYS = Object.freeze(['live', 'authorization']);
const OFFLINE_FIXTURE_KEYS = Object.freeze([
  'reviewedSourceSha256',
  'wallNow',
  'monotonicNowNs',
  'runner',
  'filesystem',
  'environment',
  'attemptLedger',
  'dependencies',
  'persistFixture',
]);
const OFFLINE_DEPENDENCY_KEYS = Object.freeze(
  Object.keys(DEFAULT_DEPENDENCIES).filter((key) => key !== 'persistRun')
);
const OFFLINE_FIXTURE_BOUNDARY = Object.freeze({
  mode: 'offline-fixture',
  canonical: false,
  authorizing: false,
  live: false,
  persistence: 'explicit-fixture-only',
});

/**
 * The only canonical live entry point. Its closed input surface deliberately
 * exposes no dependency, clock, environment, filesystem, persistence, ledger,
 * runner, or artifact-root seam.
 */
export async function runH045(options) {
  if (!exactKeys(options, CANONICAL_RUN_KEYS)) {
    throw new TypeError('H-045 canonical run accepts exactly live and authorization');
  }
  if (options.live !== true) {
    throw new Error('H-045 live execution lacks exact one-run authorization');
  }
  parseH045LiveAuthorization(options.authorization);
  return executeH045({
    executionMode: 'canonical',
    authorization: options.authorization,
    outputRoot: ARTIFACT_ROOT,
    wallNow: () => new Date().toISOString(),
    monotonicNowNs: () => process.hrtime.bigint(),
    runner: createAbsoluteCommandRunner(),
    filesystem: liveFilesystem(),
    environment: h046CanonicalCommandEnvironment(),
    attemptLedger: createCanonicalAttemptLedger(),
    dependencyOverrides: {},
  });
}

/**
 * Explicit non-canonical, non-authorizing test harness. It has no live flag or
 * authority input, accepts no defaults, cannot target the canonical artifact
 * root, and emits an intentionally live-schema-invalid fixture envelope.
 */
export async function runH045OfflineFixture(options) {
  if (!exactKeys(options, OFFLINE_FIXTURE_KEYS)) {
    throw new TypeError('H-045 offline fixture requires every exact fake seam');
  }
  if (!SHA256_PATTERN.test(options.reviewedSourceSha256)) {
    throw new TypeError('H-045 offline fixture source digest must be a lowercase SHA-256');
  }
  if (
    typeof options.wallNow !== 'function' ||
    typeof options.monotonicNowNs !== 'function' ||
    typeof options.runner !== 'function' ||
    !plainObject(options.filesystem) ||
    !plainObject(options.environment) ||
    typeof options.persistFixture !== 'function' ||
    typeof options.attemptLedger?.reserve !== 'function' ||
    typeof options.attemptLedger?.fail !== 'function' ||
    typeof options.attemptLedger?.complete !== 'function'
  ) {
    throw new TypeError('H-045 offline fixture seams must all be explicit fakes');
  }
  if (
    !exactKeys(options.dependencies, OFFLINE_DEPENDENCY_KEYS) ||
    Object.values(options.dependencies).some(
      (implementation) => typeof implementation !== 'function'
    )
  ) {
    throw new TypeError('H-045 offline fixture dependencies must be complete exact fakes');
  }
  const dependencyOverrides = {
    ...options.dependencies,
    async persistRun(run, outputRoot) {
      if (outputRoot !== OFFLINE_FIXTURE_OUTPUT_ROOT) {
        throw new Error('H-045 offline fixture persistence target changed');
      }
      return options.persistFixture(run);
    },
  };
  const fixtureResult = await executeH045({
    executionMode: 'offline-fixture',
    authorization: h045LiveAuthorization(options.reviewedSourceSha256),
    outputRoot: OFFLINE_FIXTURE_OUTPUT_ROOT,
    wallNow: options.wallNow,
    monotonicNowNs: options.monotonicNowNs,
    runner: options.runner,
    filesystem: options.filesystem,
    environment: options.environment,
    attemptLedger: options.attemptLedger,
    dependencyOverrides,
  });
  return {
    fixtureBoundary: clone(OFFLINE_FIXTURE_BOUNDARY),
    fixtureResult,
  };
}

function directInvocation() {
  return process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

function cliAuthorization(args) {
  if (args.length !== 2 || !args.includes('--live')) return null;
  const authorizationArgument = args.find((entry) => entry.startsWith('--authorization='));
  if (authorizationArgument === undefined) return null;
  const authorization = authorizationArgument.slice('--authorization='.length);
  try {
    parseH045LiveAuthorization(authorization);
    return authorization;
  } catch {
    return null;
  }
}

if (directInvocation()) {
  const args = process.argv.slice(2);
  const authorization = cliAuthorization(args);
  if (authorization === null) {
    process.stderr.write(
      `H-045 is inert without --live --authorization=${H045_LIVE_AUTHORIZATION}\n`
    );
    process.exitCode = 2;
  } else {
    try {
      const { run, runPath } = await runH045({
        live: true,
        authorization,
      });
      process.stdout.write(
        `${JSON.stringify({
          runId: run.runId,
          outcome: run.outcome,
          liveClassification: {
            disposition: run.liveClassification.disposition,
            stage: run.liveClassification.stage,
            reasonCode: run.liveClassification.reasonCode,
            receiptCount: run.liveClassification.receipts.length,
          },
          evidenceSha256: run.evidenceSha256,
          runPath: path.relative(REPOSITORY_ROOT, runPath),
        })}\n`
      );
    } catch (error) {
      process.stderr.write(`${error.stack ?? error.message}\n`);
      process.exitCode = 1;
    }
  }
}
