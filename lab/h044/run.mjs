#!/usr/bin/env node

import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  lstatSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  statSync,
} from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import {
  H043_CANDIDATE_TOKEN_SHA256,
  H043_EVIDENCE_SHA256,
  H043_REPLAY_ARCHIVE_PATH,
  H043_REPLAY_ARCHIVE_RELATIVE_PATH,
  H043_REPLAY_ARCHIVE_SHA256,
  H043_RUN_ID,
  H043_RUN_SHA256,
  H043_VERIFICATION_SHA256,
  H044_REQUIRED_SOURCE_PATHS,
  buildSourceAdmission,
  readHistoricalEvidence,
} from './admission-lib.mjs';
import {
  classificationExactShape,
  classifyLiveFrames,
  deviceIdentityFromHistoricalCandidate,
  frameExactShape,
  pid1IdentityFromHistoricalCandidate,
  sha256Canonical,
} from './classifier-lib.mjs';
import {
  buildCapabilityAudit as buildObserverCapabilityAudit,
  captureDockerAdmission,
  captureGitAdmission,
  captureLsusbAdmission,
  captureObservationFrame,
  createCommandAuditor,
  createFilesystemAuditor,
} from './observer-lib.mjs';

const REPOSITORY_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SCHEMA_PATH = fileURLToPath(new URL('./schemas/live-run.schema.json', import.meta.url));
const REPOSITORY = 'https://github.com/OverlayKit/companion-module-overlaykit-server.git';
const PROTECTED_MAIN_COMMIT = '6c329234caddf9e34126be04149f768673bdb8bf';
const SOURCE_CONTRACT_COMMIT = '9e2156e7ddc38ebe223824a07f682421b7ee0589';
const PLAN_HASH = 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4';
const MANIFEST_CONTENT_HASH = 'b36032589f0d652ceffd6aafee502e551b4f86779149be4b9ac1c38636a17013';
const CHG_0016_SHA256 = 'b8ea5a54c666047c7c44e322b21bc5f24836d172b4712c7483507bc2d4739ae6';
const CHG_0017_SHA256 = '858fcc7fde8bf6abd73e58f56224c3eae238ecf46ae70e92aca92f886937e576';
const ADR_0006_SHA256 = '619fbfe60cc8c4c298c6c1eaaa25825b514b1d36bc0b8ec6588d4c3718b9f360';
const EMPTY_MARKERS_SHA256 = sha256Canonical([]);

export const H044_REQUIRED_CASE_IDS = Object.freeze([
  'pid-reuse',
  'worker-ambiguity',
  'parent-drift',
  'namespace-drift',
  'container-drift',
  'pid1-drift',
  'device-absence',
  'device-epoch-drift',
  'descriptor-recovery',
  'marker-change',
  'frame-reorder',
  'exposure-over-limit',
  'missing-command-audit',
  'duplicate-receipts',
  'input-tampering',
  'prohibited-capability',
]);

export const H044_CLAIM_BOUNDARY = Object.freeze({
  proves: Object.freeze([
    'one capability-bounded read-only observation of the exact accepted H-043 candidate on one authorized post-login Linux host',
    'two adjacent complete frames no more than 5000 milliseconds apart with exact current device, Docker lifecycle, PID 1, SurfaceThread, descriptor, and serial-marker receipts',
    'one cutoff-bound authority-void revalidation receipt only when every historical and live identity matches, or zero receipts with withheld for complete non-eligibility',
    'fail-closed inconclusive classification for incomplete, ambiguous, contradictory, inaccessible, drifting, or unaudited evidence',
    'exact audited cardinality of allowed local Git, lsusb, Docker Unix-socket, and filesystem metadata observations with zero prohibited capabilities',
  ]),
  excludes: Object.freeze([
    'validity after the second-frame cutoff, atomicity, race freedom, PID-reuse-safe action, or a closed check-action interval',
    'authorization or safety of SIGTERM or any other signal, command, restart, rescan, retry, or executable action',
    'a watcher, controller, supervisor, systemd or udev unit, production policy, installation, publication, or release',
    'physical disconnect or reconnect, a new USB epoch, hidraw open or I/O, Docker lifecycle mutation, namespace entry, or configuration change',
    'button delivery, OverlayKit configuration continuity, rendered pixels, operator perception, OBS truth, or product acceptance',
    'security, acceptable downtime, multiple-device behavior, pre-login behavior, reboot recovery, or long-outage recovery',
    'an expansion or satisfaction of accepted SPEC-0001 or SPEC-0002',
    'a successor ADR or architectural authority beyond ADR-0006',
  ]),
});

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function clone(value) {
  return structuredClone(value);
}

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function validUtcTimestamp(value) {
  return typeof value === 'string' && Number.isFinite(Date.parse(value)) && value.endsWith('Z');
}

function stripStat(value) {
  if (value === null || typeof value !== 'object') return null;
  const stat = {
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
  return Object.values(stat).some((entry) => entry === null || entry === undefined) ? null : stat;
}

function normalizeEpoch(value) {
  if (value === null || typeof value !== 'object') return null;
  const stat = stripStat(value.stat);
  const epoch = {
    serial: value.serial,
    busNumber: value.busNumber,
    deviceNumber: value.deviceNumber,
    usbDevicePath: value.usbDevicePath,
    usbDev: value.usbDev,
    hidDevicePath: value.hidDevicePath,
    devicePath: value.devicePath,
    stat,
  };
  return stat !== null &&
    Object.entries(epoch)
      .filter(([key]) => key !== 'stat')
      .every(([, entry]) => typeof entry === 'string' && entry !== '')
    ? epoch
    : null;
}

function normalizeLifecycle(value) {
  if (value === null || typeof value !== 'object') return null;
  const lifecycle = {
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
  return Object.values(lifecycle).some((entry) => entry === null || entry === undefined)
    ? null
    : lifecycle;
}

function normalizePid1(value, lifecycle) {
  if (value === null || typeof value !== 'object' || lifecycle === null) return null;
  const pid1 = {
    hostPid: lifecycle.hostPid,
    startTicks: value.startTicks,
    pidNamespace: value.pidNamespace,
    mountNamespace: value.mountNamespace,
    cgroup: value.cgroup,
  };
  return Object.values(pid1).some((entry) => entry === null || entry === undefined) ? null : pid1;
}

function normalizeWorker(value) {
  if (value === null || typeof value !== 'object') return null;
  const worker = {
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
  return Object.values(worker).some((entry) => entry === null || entry === undefined)
    ? null
    : worker;
}

function sealFrame(frame) {
  const body = clone(frame);
  delete body.digestSha256;
  return { ...body, digestSha256: sha256Canonical(body) };
}

function incompleteFrame(frameId, startedAt = new Date().toISOString(), startedNs = '0') {
  return sealFrame({
    id: frameId,
    complete: false,
    startedAt,
    endedAt: startedAt,
    startedMonotonicNs: startedNs,
    endedMonotonicNs: startedNs,
    observationCutoff: {
      at: startedAt,
      monotonicNs: startedNs,
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
    lifecycle: null,
    pid1: null,
    containerObservation: {
      present: false,
      state: null,
      exact: false,
    },
    workers: [],
    descriptors: [],
    markers: {
      opening: 0,
      ready: 0,
      relevantLinesSha256: EMPTY_MARKERS_SHA256,
    },
    absence: {
      historicalContainerAbsent: false,
      exact: false,
    },
    auditBinding: {
      commandReceiptIndexes: [],
      filesystemReceiptIndexes: [],
    },
  });
}

export function normalizeObservationFrame(raw, historicalCandidate) {
  if (raw === null || typeof raw !== 'object') return incompleteFrame('invalid-frame');
  const observationCutoffExact =
    raw.observationCutoff !== null &&
    typeof raw.observationCutoff === 'object' &&
    validUtcTimestamp(raw.observationCutoff.at) &&
    typeof raw.observationCutoff.monotonicNs === 'string' &&
    /^(?:0|[1-9][0-9]*)$/u.test(raw.observationCutoff.monotonicNs);
  const observationCutoff = observationCutoffExact
    ? {
        at: raw.observationCutoff.at,
        monotonicNs: raw.observationCutoff.monotonicNs,
      }
    : {
        at: raw.startedAt,
        monotonicNs: raw.startedMonotonicNs,
      };
  const epoch =
    raw.device?.present === true && raw.device?.usbEpochs?.length === 1
      ? normalizeEpoch(raw.device.usbEpochs[0])
      : null;
  const devicePresent = raw.device?.present === true && epoch !== null;
  const deviceComplete =
    raw.device?.complete === true &&
    ((raw.device?.present === false && epoch === null) || devicePresent);
  const deviceIdentity =
    epoch === null
      ? null
      : {
          serial: historicalCandidate.identity.device.serial,
          vendorId: historicalCandidate.identity.device.vendorId,
          productId: historicalCandidate.identity.device.productId,
          epoch,
        };
  const lifecycle = normalizeLifecycle(raw.docker?.lifecycle);
  const pid1 = normalizePid1(raw.processes?.pid1, lifecycle);
  const workers = (raw.processes?.surfaceWorkers ?? [])
    .map(normalizeWorker)
    .filter((entry) => entry !== null);
  const descriptors = (raw.processes?.surfaceWorkers ?? []).flatMap((worker) =>
    Array.isArray(worker.fileDescriptors) ? clone(worker.fileDescriptors) : []
  );
  const serial = historicalCandidate.identity.device.serial;
  const relevantLines = (raw.docker?.markers?.entries ?? []).filter((entry) => {
    if (typeof entry?.line !== 'string') return false;
    return [
      `Opening surface panel: streamdeck:${serial}`,
      `Surface panel ready: streamdeck:${serial}`,
    ].some((marker) => {
      const markerIndex = entry.line.indexOf(marker);
      return (
        markerIndex !== -1 &&
        (markerIndex + marker.length === entry.line.length ||
          /\s/u.test(entry.line[markerIndex + marker.length]))
      );
    });
  });
  const psExact = !(raw.errors ?? []).some((entry) => entry.stage === 'docker-ps');
  const targetContainer =
    (raw.docker?.ps ?? []).find(
      (entry) => entry.containerId === historicalCandidate.identity.lifecycle.containerId
    ) ?? null;
  const containerState =
    typeof targetContainer?.state === 'string' && targetContainer.state !== ''
      ? targetContainer.state.toLowerCase()
      : null;
  const containerObservation = {
    present: psExact && targetContainer !== null,
    state: psExact && targetContainer !== null ? containerState : null,
    exact: psExact && (targetContainer === null || containerState !== null),
  };
  const historicalContainerAbsent =
    containerObservation.exact && containerObservation.present === false;
  const host = {
    hostname:
      typeof raw.host?.hostname === 'string' && raw.host.hostname !== ''
        ? raw.host.hostname
        : 'unavailable',
    bootId:
      typeof raw.host?.bootId === 'string' && raw.host.bootId !== ''
        ? raw.host.bootId
        : 'unavailable',
    osRelease:
      raw.host?.osRelease && typeof raw.host.osRelease === 'object'
        ? JSON.stringify(raw.host.osRelease)
        : 'unavailable',
  };
  const normalized = {
    id: raw.frameId,
    complete: raw.complete === true && observationCutoffExact,
    startedAt: raw.startedAt,
    endedAt: raw.endedAt,
    startedMonotonicNs: raw.startedMonotonicNs,
    endedMonotonicNs: raw.endedMonotonicNs,
    observationCutoff,
    host,
    device: {
      complete: deviceComplete,
      present: devicePresent,
      identity: deviceIdentity,
    },
    lifecycle,
    pid1,
    containerObservation,
    workers,
    descriptors,
    markers: {
      opening: Number.isSafeInteger(raw.docker?.markers?.openingCount)
        ? raw.docker.markers.openingCount
        : 0,
      ready: Number.isSafeInteger(raw.docker?.markers?.readyCount)
        ? raw.docker.markers.readyCount
        : 0,
      relevantLinesSha256: sha256Canonical(relevantLines),
    },
    absence: {
      historicalContainerAbsent,
      exact: containerObservation.exact,
    },
    auditBinding: {
      commandReceiptIndexes: Array.isArray(raw.auditBinding?.commandReceiptIndexes)
        ? [...raw.auditBinding.commandReceiptIndexes]
        : [],
      filesystemReceiptIndexes: Array.isArray(raw.auditBinding?.filesystemReceiptIndexes)
        ? [...raw.auditBinding.filesystemReceiptIndexes]
        : [],
    },
  };
  let sealed = sealFrame(normalized);
  if (!frameExactShape(sealed)) {
    sealed = incompleteFrame(
      typeof raw.frameId === 'string' ? raw.frameId : 'invalid-frame',
      validUtcTimestamp(raw.startedAt) ? raw.startedAt : new Date().toISOString(),
      typeof raw.startedMonotonicNs === 'string' ? raw.startedMonotonicNs : '0'
    );
  }
  return sealed;
}

function mapCommandKind(kind) {
  if (['gitRevParse', 'gitMergeBaseAncestor', 'gitRemoteGetUrl'].includes(kind)) return 'git';
  return kind;
}

function prohibitedCounts(commandSnapshot) {
  const observed = commandSnapshot?.prohibited ?? {};
  return {
    externalNetwork: observed.externalNetwork ?? observed.externalNetworkCount ?? 0,
    hidrawOpen: observed.hidrawOpen ?? observed.hidrawOpenCount ?? 0,
    hidrawRead: observed.hidrawRead ?? observed.hidrawReadCount ?? 0,
    hidrawWrite: observed.hidrawWrite ?? observed.hidrawWriteCount ?? 0,
    hidrawIoctl: observed.hidrawIoctl ?? observed.hidrawIoctlCount ?? 0,
    signal: observed.signal ?? observed.signalCount ?? 0,
    lifecycleMutation: observed.lifecycleMutation ?? observed.lifecycleMutationCount ?? 0,
    configurationMutation:
      observed.configurationMutation ?? observed.configurationMutationCount ?? 0,
    mountMutation: observed.mountMutation ?? observed.mountMutationCount ?? 0,
    cgroupMutation: observed.cgroupMutation ?? observed.cgroupMutationCount ?? 0,
    sysfsWrite: observed.sysfsWrite ?? observed.sysfsWriteCount ?? 0,
    productionMutation: observed.productionMutation ?? observed.productionMutationCount ?? 0,
  };
}

export function buildCapabilityAudit(commandSnapshot, filesystemSnapshot, frames) {
  const commandReceipts = (commandSnapshot?.receipts ?? []).map((receipt) => ({
    ...clone(receipt),
    observerKind: receipt.kind,
    kind: mapCommandKind(receipt.kind),
  }));
  const filesystemReceipts = clone(filesystemSnapshot?.receipts ?? []);
  const allowedProcessCounts = {
    git: commandReceipts.filter((receipt) => receipt.kind === 'git').length,
    lsusb: commandReceipts.filter((receipt) => receipt.kind === 'lsusb').length,
    dockerVersion: commandReceipts.filter((receipt) => receipt.kind === 'dockerVersion').length,
    dockerPs: commandReceipts.filter((receipt) => receipt.kind === 'dockerPs').length,
    dockerInspect: commandReceipts.filter((receipt) => receipt.kind === 'dockerInspect').length,
    dockerLogs: commandReceipts.filter((receipt) => receipt.kind === 'dockerLogs').length,
  };
  const noRejectedAttempts =
    (commandSnapshot?.rejectedAttempts ?? []).length === 0 &&
    (filesystemSnapshot?.rejectedAttempts ?? []).length === 0;
  const exact =
    noRejectedAttempts &&
    commandReceipts.every(
      (receipt, index) =>
        receipt.index === index &&
        receipt.exitCode === 0 &&
        receipt.signal === null &&
        receipt.errorCode === null &&
        typeof receipt.startedMonotonicNs === 'string' &&
        typeof receipt.endedMonotonicNs === 'string'
    ) &&
    filesystemReceipts.every(
      (receipt, index) =>
        receipt.index === index &&
        receipt.disposition === 'observed' &&
        receipt.errorCode === null &&
        typeof receipt.startedMonotonicNs === 'string' &&
        typeof receipt.endedMonotonicNs === 'string'
    );
  return {
    mode: 'live-readonly-capability-bounded',
    commandReceipts,
    filesystemReceipts,
    allowedProcessCounts,
    commandCount: commandReceipts.length,
    filesystemReceiptCount: filesystemReceipts.length,
    complete: exact,
    exact,
    frameCount: frames.length,
    lsusbCount: allowedProcessCounts.lsusb,
    unrecordedObservationCount: 0,
    prohibitedCounts: prohibitedCounts(commandSnapshot),
  };
}

function syntheticCapabilityAudit() {
  const allowedProcessCounts = {
    git: 3,
    lsusb: 1,
    dockerVersion: 1,
    dockerPs: 2,
    dockerInspect: 2,
    dockerLogs: 2,
  };
  const commandReceipts = Object.entries(allowedProcessCounts).flatMap(([kind, count]) =>
    Array.from({ length: count }, (_, index) => ({ kind, receiptIndex: index }))
  );
  return {
    mode: 'live-readonly-capability-bounded',
    commandReceipts,
    filesystemReceipts: [{ operation: 'readFileSync', path: '/proc/synthetic' }],
    allowedProcessCounts,
    commandCount: commandReceipts.length,
    filesystemReceiptCount: 1,
    complete: true,
    exact: true,
    frameCount: 2,
    lsusbCount: 1,
    unrecordedObservationCount: 0,
    prohibitedCounts: {
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
    },
  };
}

function syntheticFrames(candidate) {
  const common = {
    complete: true,
    host: {
      hostname: 'h044-synthetic-host',
      bootId: '00000000-0000-4000-8000-000000000044',
      osRelease: '{"id":"linux","prettyName":"H-044 synthetic","versionId":"1"}',
    },
    device: {
      complete: true,
      present: true,
      identity: deviceIdentityFromHistoricalCandidate(candidate),
    },
    containerObservation: {
      present: true,
      state: 'running',
      exact: true,
    },
    lifecycle: clone(candidate.identity.lifecycle),
    pid1: pid1IdentityFromHistoricalCandidate(candidate),
    workers: [clone(candidate.identity.worker)],
    descriptors: [],
    markers: {
      opening: 1,
      ready: 1,
      relevantLinesSha256: sha256Canonical(['synthetic-stable-markers']),
    },
    absence: {
      historicalContainerAbsent: false,
      exact: true,
    },
  };
  return [
    sealFrame({
      id: 'hostile-frame-1',
      startedAt: '2026-07-26T18:00:00.000Z',
      endedAt: '2026-07-26T18:00:00.900Z',
      startedMonotonicNs: '100000000000',
      endedMonotonicNs: '100900000000',
      observationCutoff: {
        at: '2026-07-26T18:00:00.800Z',
        monotonicNs: '100800000000',
      },
      auditBinding: {
        commandReceiptIndexes: [5, 7, 9],
        filesystemReceiptIndexes: [0],
      },
      ...clone(common),
    }),
    sealFrame({
      id: 'hostile-frame-2',
      startedAt: '2026-07-26T18:00:00.900Z',
      endedAt: '2026-07-26T18:00:01.800Z',
      startedMonotonicNs: '100900000000',
      endedMonotonicNs: '101800000000',
      observationCutoff: {
        at: '2026-07-26T18:00:01.700Z',
        monotonicNs: '101700000000',
      },
      auditBinding: {
        commandReceiptIndexes: [6, 8, 10],
        filesystemReceiptIndexes: [],
      },
      ...clone(common),
    }),
  ];
}

function reseal(frame) {
  Object.assign(frame, sealFrame(frame));
}

export function evaluateHostileMatrix(historicalCandidate) {
  const base = {
    historicalCandidate: clone(historicalCandidate),
    frames: syntheticFrames(historicalCandidate),
    capabilityAudit: syntheticCapabilityAudit(),
    sourceAdmissionExact: true,
  };
  const definitions = [
    {
      id: 'pid-reuse',
      disposition: 'inconclusive',
      reasonCode: 'worker-identity-drift',
      mutate(input) {
        input.frames[1].workers[0].startTicks += 1;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'worker-ambiguity',
      disposition: 'inconclusive',
      reasonCode: 'worker-ambiguity',
      mutate(input) {
        input.frames[1].workers.push(clone(input.frames[1].workers[0]));
        reseal(input.frames[1]);
      },
    },
    {
      id: 'parent-drift',
      disposition: 'inconclusive',
      reasonCode: 'worker-identity-drift',
      mutate(input) {
        input.frames[1].workers[0].parentStartTicks += 1;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'namespace-drift',
      disposition: 'inconclusive',
      reasonCode: 'worker-identity-drift',
      mutate(input) {
        input.frames[1].workers[0].pidNamespace += '-drift';
        reseal(input.frames[1]);
      },
    },
    {
      id: 'container-drift',
      disposition: 'inconclusive',
      reasonCode: 'container-or-pid1-identity-drift',
      mutate(input) {
        input.frames[1].lifecycle.restartCount += 1;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'pid1-drift',
      disposition: 'inconclusive',
      reasonCode: 'container-or-pid1-identity-drift',
      mutate(input) {
        input.frames[1].pid1.startTicks += 1;
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
        input.frames[1].device.identity.epoch.deviceNumber += '-drift';
        reseal(input.frames[1]);
      },
    },
    {
      id: 'descriptor-recovery',
      disposition: 'withheld',
      reasonCode: 'current-descriptor-present',
      mutate(input) {
        const descriptor = {
          descriptor: 'synthetic-fd',
          devicePath: input.historicalCandidate.identity.device.revalidationEpoch.devicePath,
        };
        for (const frame of input.frames) {
          frame.descriptors = [clone(descriptor)];
          reseal(frame);
        }
      },
    },
    {
      id: 'marker-change',
      disposition: 'inconclusive',
      reasonCode: 'marker-drift',
      mutate(input) {
        input.frames[1].markers.ready += 1;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'frame-reorder',
      disposition: 'inconclusive',
      reasonCode: 'frame-order-invalid',
      mutate(input) {
        input.frames[1].startedAt = input.frames[0].startedAt;
        input.frames[1].startedMonotonicNs = input.frames[0].startedMonotonicNs;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'exposure-over-limit',
      disposition: 'inconclusive',
      reasonCode: 'exposure-window-exceeded',
      mutate(input) {
        input.frames[1].observationCutoff = {
          at: '2026-07-26T18:00:05.100Z',
          monotonicNs: '105100000000',
        };
        input.frames[1].endedAt = '2026-07-26T18:00:05.200Z';
        input.frames[1].endedMonotonicNs = '105200000000';
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
        input.historicalCandidate.tokenSha256 = '0'.repeat(64);
      },
    },
    {
      id: 'prohibited-capability',
      disposition: 'inconclusive',
      reasonCode: 'prohibited-capability-observed',
      mutate(input) {
        input.capabilityAudit.prohibitedCounts.signal = 1;
      },
    },
  ];
  const cases = definitions.map((definition) => {
    const input = clone(base);
    let result;
    let inputForDigest = input;
    if (definition.duplicateOutput) {
      const canonical = classifyLiveFrames(input);
      const corrupted = clone(canonical);
      corrupted.receipts.push(clone(corrupted.receipts[0]));
      inputForDigest = { classification: corrupted };
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
      result = classifyLiveFrames(input);
    }
    const actualReceiptCount = Array.isArray(result.receipts) ? result.receipts.length : 0;
    const passed =
      result.disposition === definition.disposition &&
      result.reasonCode === definition.reasonCode &&
      actualReceiptCount === 0;
    return {
      id: definition.id,
      inputSha256: sha256Canonical(inputForDigest),
      expectedDisposition: definition.disposition,
      actualDisposition: result.disposition,
      expectedReceiptCount: 0,
      actualReceiptCount,
      stage: result.stage,
      reasonCode: result.reasonCode,
      passed,
    };
  });
  return {
    schemaVersion: 'overlaykit-h044-hostile-matrix/v1',
    requiredCaseIds: [...H044_REQUIRED_CASE_IDS],
    caseCount: cases.length,
    passedCount: cases.filter((entry) => entry.passed).length,
    allPassed:
      same(
        cases.map((entry) => entry.id),
        H044_REQUIRED_CASE_IDS
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
      stage: 'live-readonly-revalidation',
      reasonCode: 'complete-live-classification-and-hostile-matrix-exact',
    };
  }
  return {
    status: 'inconclusive',
    stage: 'live-classification',
    reasonCode: 'live-classification-invalid',
  };
}

async function sourceReceipts() {
  return Promise.all(
    H044_REQUIRED_SOURCE_PATHS.map(async (relativePath) => ({
      path: relativePath,
      sha256: sha256(await readFile(path.join(REPOSITORY_ROOT, relativePath))),
    }))
  );
}

async function governanceReceipt() {
  const paths = {
    manifest: '.overlaykit/governance/manifest.json',
    plan: '.overlaykit/governance/plan.json',
    chg0016: '.overlaykit/governance/changes/CHG-0016.json',
    chg0017: '.overlaykit/governance/changes/CHG-0017.json',
    adr0006: '.overlaykit/governance/decisions/ADR-0006.json',
  };
  const [manifestBytes, planBytes, chg0016, chg0017, adr0006] = await Promise.all(
    Object.values(paths).map((relativePath) => readFile(path.join(REPOSITORY_ROOT, relativePath)))
  );
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const plan = JSON.parse(planBytes.toString('utf8'));
  return {
    verified: plan.planHash === PLAN_HASH && manifest.contentHash === MANIFEST_CONTENT_HASH,
    planHash: plan.planHash,
    manifestContentHash: manifest.contentHash,
    changes: {
      'CHG-0016': sha256(chg0016),
      'CHG-0017': sha256(chg0017),
    },
    decisions: {
      'ADR-0006': sha256(adr0006),
    },
    requiredSourcePaths: [...H044_REQUIRED_SOURCE_PATHS],
  };
}

function publicSourceAdmission(admission, governance) {
  const value = {
    h043ArchiveExact: admission.checks.historicalArchiveExact,
    h043RunExact: admission.checks.historicalRunExact,
    h043VerificationExact: admission.checks.historicalVerificationExact,
    h043EvidenceExact:
      admission.checks.historicalRunExact && admission.checks.historicalVerificationExact,
    h043CandidateTokenExact: admission.checks.historicalCandidateExact,
    chg0016Exact: governance.changes['CHG-0016'] === CHG_0016_SHA256,
    adr0006Exact: governance.decisions['ADR-0006'] === ADR_0006_SHA256,
    protectedMainAncestryExact: admission.checks.protectedMainAncestor,
    governanceExact:
      admission.governanceExact &&
      governance.changes['CHG-0017'] === CHG_0017_SHA256 &&
      governance.planHash === PLAN_HASH &&
      governance.manifestContentHash === MANIFEST_CONTENT_HASH,
    sourceSetExact: admission.sourceSetExact && admission.sourceStable,
    allExact: false,
  };
  value.allExact = Object.entries(value)
    .filter(([key]) => key !== 'allExact')
    .every(([, exact]) => exact === true);
  return value;
}

function commandRunner(executable, args, { maxBufferBytes, timeoutMs }) {
  const childEnvironment = { ...process.env };
  for (const key of [
    'DOCKER_HOST',
    'DOCKER_CONTEXT',
    'DOCKER_TLS_VERIFY',
    'DOCKER_CERT_PATH',
    'DOCKER_API_VERSION',
  ]) {
    delete childEnvironment[key];
  }
  return new Promise((resolve) => {
    execFile(
      executable,
      args,
      {
        cwd: REPOSITORY_ROOT,
        encoding: 'buffer',
        env: childEnvironment,
        maxBuffer: maxBufferBytes,
        timeout: timeoutMs,
        windowsHide: true,
      },
      (error, stdout, stderr) => {
        resolve({
          exitCode: error === null ? 0 : Number.isInteger(error?.code) ? error.code : null,
          signal: typeof error?.signal === 'string' ? error.signal : null,
          stdout: stdout ?? Buffer.alloc(0),
          stderr: stderr ?? Buffer.alloc(0),
        });
      }
    );
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

function runId(startedAt, candidateToken) {
  const timestamp = startedAt.replaceAll(':', '-').replace('.', '-');
  return `h044-${timestamp}-${sha256(`${startedAt}:${candidateToken}`).slice(0, 8)}`;
}

async function compileSchema() {
  const schema = JSON.parse(await readFile(SCHEMA_PATH, 'utf8'));
  return new Ajv2020({ allErrors: true, strict: true }).compile(schema);
}

export async function runH044({
  outputRoot = path.join(REPOSITORY_ROOT, 'artifacts', 'h044'),
  wallNow = () => new Date().toISOString(),
  monotonicNowNs = () => process.hrtime.bigint(),
  runner = commandRunner,
  filesystem = liveFilesystem(),
} = {}) {
  if (process.version !== 'v22.20.0') {
    throw new Error(`H-044 requires Node v22.20.0, observed ${process.version}`);
  }
  const startedAt = wallNow();
  if (!validUtcTimestamp(startedAt)) throw new Error('H-044 startedAt is invalid');
  const validateSchema = await compileSchema();
  const sourcesBefore = await sourceReceipts();
  const [archiveBytes, governance] = await Promise.all([
    readFile(H043_REPLAY_ARCHIVE_PATH),
    governanceReceipt(),
  ]);
  const historical = readHistoricalEvidence(archiveBytes);
  const commandAuditor = createCommandAuditor({
    runner,
    wallNow,
    monotonicNowNs,
    maxBufferBytes: 8 * 1024 * 1024,
    timeoutMs: 1500,
  });
  const filesystemAuditor = createFilesystemAuditor({
    filesystem,
    wallNow,
    monotonicNowNs,
  });
  const gitAdmission = await captureGitAdmission(commandAuditor, {
    protectedMainCommit: PROTECTED_MAIN_COMMIT,
  });
  if (gitAdmission.remoteUrl !== REPOSITORY || gitAdmission.head !== SOURCE_CONTRACT_COMMIT) {
    throw new Error('H-044 Git source admission failed before live observation');
  }
  const git = {
    protectedMainCommit: gitAdmission.protectedMainCommit,
    sourceContractCommit: gitAdmission.head,
    protectedMainAncestor: gitAdmission.protectedMainIsAncestor,
  };
  const preflight = buildSourceAdmission({
    historical,
    governance,
    git,
    sourcesBefore,
    sourcesAfter: clone(sourcesBefore),
  });
  if (!preflight.exact) {
    throw new Error('H-044 source admission failed before live observation');
  }

  let lsusbAdmission = null;
  let dockerAdmission = null;
  try {
    lsusbAdmission = await captureLsusbAdmission(commandAuditor);
  } catch {
    // The audited failure is retained and must not be retried.
  }
  try {
    dockerAdmission = await captureDockerAdmission(commandAuditor);
  } catch {
    // The audited failure is retained and must not be retried.
  }

  const target = {
    serial: historical.candidate.identity.device.serial,
    vendorId: historical.candidate.identity.device.vendorId,
    productId: historical.candidate.identity.device.productId,
    containerId: historical.candidate.identity.lifecycle.containerId,
    deviceMajor: historical.candidate.identity.device.revalidationEpoch.stat.major,
    deviceMinor: historical.candidate.identity.device.revalidationEpoch.stat.minor,
  };
  const rawFrames = [];
  if (lsusbAdmission !== null && dockerAdmission !== null) {
    for (const frameId of ['frame-1', 'frame-2']) {
      try {
        rawFrames.push(
          await captureObservationFrame({
            frameId,
            commandAuditor,
            filesystemAuditor,
            lsusbAdmission,
            dockerAdmission,
            target,
            logSince: historical.candidate.identity.lifecycle.startedAt,
            wallNow,
            monotonicNowNs,
          })
        );
      } catch {
        break;
      }
    }
  }
  const frames = rawFrames.map((frame) => normalizeObservationFrame(frame, historical.candidate));
  while (frames.length < 2) {
    const at = wallNow();
    frames.push(incompleteFrame(`frame-${frames.length + 1}`, at, monotonicNowNs().toString()));
  }

  const auditFrames = [...rawFrames];
  while (auditFrames.length < 2) auditFrames.push({ docker: { targetState: null } });
  const capabilityAudit = buildObserverCapabilityAudit({
    commandAuditor,
    filesystemAuditor,
    frames: auditFrames,
  });
  const sourcesAfter = await sourceReceipts();
  const finalAdmission = buildSourceAdmission({
    historical,
    governance,
    git,
    sourcesBefore,
    sourcesAfter,
  });
  const sourceAdmission = publicSourceAdmission(finalAdmission, governance);
  const liveClassification = classifyLiveFrames({
    historicalCandidate: historical.candidate,
    frames,
    capabilityAudit,
    sourceAdmissionExact: sourceAdmission.allExact,
  });
  const hostileMatrix = evaluateHostileMatrix(historical.candidate);
  const completedAt = wallNow();
  const body = {
    schemaVersion: 'overlaykit-h044-live-readonly-revalidation-run/v1',
    hypothesis: 'H-044',
    runId: runId(startedAt, historical.candidate.tokenSha256),
    startedAt,
    completedAt,
    outcome: outcomeFor(sourceAdmission, capabilityAudit, liveClassification, hostileMatrix),
    collector: {
      node: process.version,
      repository: REPOSITORY,
      baseCommit: PROTECTED_MAIN_COMMIT,
      sources: sourcesBefore,
      sourceStable: finalAdmission.sourceStable,
      governance: {
        changeId: 'CHG-0017',
        changeSha256: governance.changes['CHG-0017'],
        planHash: governance.planHash,
        manifestContentHash: governance.manifestContentHash,
      },
    },
    input: {
      h043ArchivePath: H043_REPLAY_ARCHIVE_RELATIVE_PATH,
      h043ArchiveSha256: H043_REPLAY_ARCHIVE_SHA256,
      h043RunId: H043_RUN_ID,
      h043RunSha256: H043_RUN_SHA256,
      h043VerificationSha256: H043_VERIFICATION_SHA256,
      h043EvidenceSha256: H043_EVIDENCE_SHA256,
      h043CandidateTokenSha256: H043_CANDIDATE_TOKEN_SHA256,
    },
    sourceAdmission,
    historicalCandidate: historical.candidate,
    frames,
    capabilityAudit,
    liveClassification,
    hostileMatrix,
    claimBoundary: clone(H044_CLAIM_BOUNDARY),
  };
  const run = { ...body, evidenceSha256: sha256Canonical(body) };
  if (!validateSchema(run)) {
    throw new Error(
      `H-044 produced schema-invalid evidence: ${JSON.stringify(validateSchema.errors)}`
    );
  }
  const runDirectory = path.join(outputRoot, run.runId);
  await mkdir(runDirectory, { recursive: true });
  const runPath = path.join(runDirectory, 'run.json');
  await writeFile(runPath, `${JSON.stringify(run, null, 2)}\n`, { flag: 'wx' });
  return { run, runPath };
}

function isDirectInvocation() {
  return process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

if (isDirectInvocation()) {
  try {
    const { run, runPath } = await runH044();
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
