#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import {
  H042_REPLAY_ARCHIVE_PATH,
  H042_RUN_MEMBER_PATH,
  H042_VERIFICATION_MEMBER_PATH,
  readTarGzipMembers,
} from './archive-lib.mjs';

const REPOSITORY_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SCHEMA_PATH = fileURLToPath(
  new URL('./schemas/offline-worker-eligibility-run.schema.json', import.meta.url)
);
const ARCHIVE_SHA256 = '15b2589976cb3a4cff95af807d52728fee83a2f5b9983969f61e0663bfcc3b36';
const H042_RUN_ID = 'h042-2026-07-26T16-19-05-858Z-efaf85fa';
const H042_EVIDENCE_SHA256 = 'f4996a0d46c54fd337601e43ae7e0afa5e44d911c72c4888c0d1ae067fe0dc88';
const H042_RUN_SHA256 = 'be39e69140f733e7f56e371f144b6e7b0cd43c05b7be6bfea9850c440679a7b6';
const H042_VERIFICATION_SHA256 = '0fc4f3cd7f78fe1184331a40f97874521d97d6f5c677a4829588a6dc676e6919';
const PREFIX_SHA256 = 'aee82f2da74cee96a7ac10ea21946d1e668913e1bb2e2210398b4a362eff3959';
const RUNTIME_PREFIX_SHA256 = 'ec7f7041a505524d2ba058b3185373633135cab0765f46a2d4ddab9f260d725f';
const HOST_PREFIX_SHA256 = '53b91505477301d9a1a554f6a15dc41b138158df702339daa48139b810a3a4b4';
const AUDIT_PREFIX_SHA256 = 'bfc457e62f58cc581b3ad653cc9b45ee397ef6fc8a2be0d96f3cb003e0d7a8ef';
const LOG_INITIAL_SHA256 = '27534063c7d53c75a8b20f8b0a50c4b0ca01bd09763baab7716fc062e50263e6';
const LOG_ABSENT_SHA256 = '0b62162131e526aa07efc175a626623e885e9965362f833936d2e494391a4abb';
const LOG_PRE_SIGNAL_SHA256 = 'f5375408668603381d24b9289b307636b86db462022fd5fedfd1726fbc9e5d8b';
const CUTOFF_MONOTONIC_NS = '78174124595205';
const REPOSITORY = 'https://github.com/OverlayKit/companion-module-overlaykit-server.git';
const H042_MEMBER_ROOT = H042_RUN_MEMBER_PATH.slice(0, -'run.json'.length);

export const INDEPENDENT_REQUIRED_SOURCES = Object.freeze(
  [
    '.overlaykit/governance/changes/CHG-0014.json',
    '.overlaykit/governance/changes/CHG-0015.json',
    '.overlaykit/governance/decisions/ADR-0006.json',
    'lab/h043/adversarial-regression.test.mjs',
    'lab/h043/archive-lib.mjs',
    'lab/h043/archive-lib.test.mjs',
    'lab/h043/eligibility-lib.mjs',
    'lab/h043/eligibility-lib.test.mjs',
    'lab/h043/prefix-lib.mjs',
    'lab/h043/prefix-lib.test.mjs',
    'lab/h043/run.mjs',
    'lab/h043/run.test.mjs',
    'lab/h043/schema.test.mjs',
    'lab/h043/schemas/offline-worker-eligibility-run.schema.json',
    'lab/h043/verify.mjs',
    'lab/h043/verify.test.mjs',
    'package-lock.json',
    'package.json',
  ].sort()
);

const BASE_COMMIT = 'dce2cd8bb454a264f8f9738f9748dc1c70b5dcd0';
const CHANGE_SHA256 = 'b2cd667fad87b366163549cdb3b0ffaac95ffd591fc53d6158c229a516ae7e25';
const PLAN_HASH = 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4';
const MANIFEST_CONTENT_HASH = 'b29bde1b9f24a5c0ddaaa6b18cb577de859d6d9577b6636148c4ebeb021b8917';

export const INDEPENDENT_PREDICATE_KEYS = Object.freeze([
  'sourceAdmissionExact',
  'prefixBoundaryExact',
  'usbEpochExact',
  'returnedDeviceExact',
  'negativeWindowComplete',
  'topLevelLifecycleUnchanged',
  'workerUniqueThroughout',
  'workerTupleUnchanged',
  'currentDescriptorAbsentThroughout',
  'markersStable',
  'finalReceiptsCoherent',
  'historicalAuditExact',
]);

export const INDEPENDENT_CASE_IDS = Object.freeze([
  'canonical-golden',
  'healthy-baseline',
  'device-absent',
  'negative-window-open',
  'current-descriptor-reacquired',
  'ordered-markers-changed',
  'partial-marker-change',
  'worker-missing',
  'multiple-workers',
  'container-lifecycle-drift',
  'pid1-identity-drift',
  'worker-pid-changed',
  'worker-startticks-changed',
  'worker-ppid-changed',
  'worker-parent-startticks-changed',
  'worker-pid-namespace-changed',
  'worker-full-tuple-drift',
  'exact-absence-missing',
  'usb-epoch-identity-mismatch',
  'returned-node-mismatch',
  'negative-window-boundary-missing',
  'late-positive',
  'prefix-tail-contamination',
  'duplicate-candidates',
  'unapproved-command',
]);

export const INDEPENDENT_CLAIM_BOUNDARY = Object.freeze({
  proves: Object.freeze([
    'offline deterministic eligibility classification of the byte-exact canonical H-042 pre-signal prefix',
    'exact conjunction of one already-recorded USB epoch, a complete thirty-second negative automatic-reacquisition control, and one current-at-cutoff SurfaceThread, container, PID 1, and device tuple',
    'at most one historical revalidation-required candidate binding the exact observed volatile identities designated for separate live revalidation',
    'fail-closed withholding for complete non-eligible prefixes and inconclusive classification for missing, malformed, contradictory, stale, or ambiguous inputs',
    'classifier execution with no signal, process, container, host, configuration, or device mutation and no dependency on signal or post-signal evidence',
  ]),
  excludes: Object.freeze([
    'live eligibility after the recorded cutoff, successful physical revalidation, race freedom, PID-reuse safety, or atomic check-action behavior',
    'authorization or safety of SIGTERM or any other action; a candidate is not a command, supervisor, or production policy',
    'a live watcher, controller, supervisor, systemd or udev unit, restart or recreate policy, device bind, cgroup rule, or configuration change',
    'a new physical USB epoch, device I/O, new worker replacement or reacquisition, or repeated recovery',
    'button delivery, OverlayKit configuration continuity, rendered pixels, operator perception, OBS truth, or product acceptance',
    'security, acceptable downtime, multiple devices, pre-login, reboot, long-outage behavior, or support beyond the exact archived identities',
  ]),
});

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

function assertion(condition, message) {
  if (!condition) throw new Error(`H-043 verification failed: ${message}`);
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

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function sha256Canonical(value) {
  return sha256(canonicalJson(value));
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function clone(value) {
  return structuredClone(value);
}

function validUtcTimestamp(value) {
  if (typeof value !== 'string') return false;
  const match =
    /^(?<year>[0-9]{4})-(?<month>0[1-9]|1[0-2])-(?<day>0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?Z$/u.exec(
      value
    );
  if (!match) return false;
  const year = Number(match.groups.year);
  const month = Number(match.groups.month);
  const day = Number(match.groups.day);
  const leapYear = year % 400 === 0 || (year % 4 === 0 && year % 100 !== 0);
  const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day <= daysInMonth[month - 1] && Number.isFinite(Date.parse(value));
}

function parseJsonLines(text, label) {
  assertion(typeof text === 'string' && text.endsWith('\n'), `${label} is not JSONL`);
  return text
    .slice(0, -1)
    .split('\n')
    .map((line, index) => {
      try {
        const value = JSON.parse(line);
        assertion(
          value !== null && typeof value === 'object' && !Array.isArray(value),
          `${label} line ${index + 1} is not an object`
        );
        return value;
      } catch (error) {
        throw new Error(`${label} line ${index + 1} is invalid`, { cause: error });
      }
    });
}

function serializeJsonLines(entries) {
  return `${entries.map((entry) => JSON.stringify(entry)).join('\n')}\n`;
}

function monotonic(value, label) {
  assertion(
    typeof value === 'string' && /^[0-9]+$/u.test(value),
    `${label} is not monotonic nanoseconds`
  );
  return BigInt(value);
}

function memberBytes(members, name) {
  const value = members.get(`${H042_MEMBER_ROOT}${name}`);
  assertion(value, `archive member ${name} is missing`);
  return value;
}

function memberText(members, name) {
  return memberBytes(members, name).toString('utf8');
}

function selectedCompanion(companion) {
  return {
    name: companion.name,
    containerId: companion.containerId,
    imageReference: companion.imageReference,
    imageId: companion.imageId,
    repoDigests: clone(companion.repoDigests),
    version: companion.version,
    revision: companion.revision,
    dynamicRoot: companion.dynamicRoot,
    dynamicPath: companion.dynamicPath,
    compatibilityPath: companion.compatibilityPath,
    deviceCgroupRule: companion.deviceCgroupRule,
    deviceGid: companion.deviceGid,
    staticDevices: clone(companion.staticDevices),
    initialLifecycle: clone(companion.initialLifecycle),
    absentLifecycle: clone(companion.absentLifecycle),
    preSignalLifecycle: clone(companion.preSignalLifecycle),
    workerLifecycle: {
      initial: clone(companion.workerLifecycle.initial),
      absent: clone(companion.workerLifecycle.absent),
      preSignal: clone(companion.workerLifecycle.preSignal),
    },
  };
}

function independentPrefix(input) {
  const cutoff = monotonic(input.run.observations.preSignal.host.monotonicNs, 'pre-signal cutoff');
  const runtimeEntries = parseJsonLines(input.runtimePollText, 'runtime-poll.jsonl').filter(
    (entry) => monotonic(entry.monotonicNs, 'runtime monotonicNs') <= cutoff
  );
  const hostEntries = parseJsonLines(input.hostPollText, 'host-poll.jsonl').filter(
    (entry) => monotonic(entry.monotonicNs, 'host monotonicNs') <= cutoff
  );
  const audit = input.run.invocationAudit.entries.filter(
    (entry) => monotonic(entry.monotonicNs, 'audit monotonicNs') <= cutoff
  );
  const runtimeText = serializeJsonLines(runtimeEntries);
  const hostText = serializeJsonLines(hostEntries);
  return {
    schemaVersion: 'overlaykit-h043-h042-prefix/v1',
    source: {
      archiveSha256: ARCHIVE_SHA256,
      h042RunId: H042_RUN_ID,
      h042EvidenceSha256: H042_EVIDENCE_SHA256,
      h042RunSha256: H042_RUN_SHA256,
      h042VerificationSha256: H042_VERIFICATION_SHA256,
    },
    cutoffMonotonicNs: input.run.observations.preSignal.host.monotonicNs,
    context: {
      schemaVersion: input.run.schemaVersion,
      runId: input.run.runId,
      hypothesis: input.run.hypothesis,
      startedAt: input.run.startedAt,
      collector: clone(input.run.collector),
      host: clone(input.run.host),
      inputs: clone(input.run.inputs),
      device: clone(input.run.device),
      companion: selectedCompanion(input.run.companion),
      windows: {
        disconnect: clone(input.run.windows.disconnect),
        reconnect: clone(input.run.windows.reconnect),
        preSignal: clone(input.run.windows.preSignal),
      },
      observations: {
        preflight: clone(input.run.observations.preflight),
        initial: clone(input.run.observations.initial),
        absent: clone(input.run.observations.absent),
        returned: clone(input.run.observations.returned),
        preSignal: clone(input.run.observations.preSignal),
      },
      invocationAuditPrefix: clone(audit),
    },
    raw: {
      runtimePoll: {
        lineCount: runtimeEntries.length,
        sha256: sha256(runtimeText),
        text: runtimeText,
      },
      hostPoll: {
        lineCount: hostEntries.length,
        sha256: sha256(hostText),
        text: hostText,
      },
      invocationAudit: {
        entryCount: audit.length,
        sha256: sha256(`${canonicalJson(audit)}\n`),
      },
      logs: {
        initial: {
          sha256: sha256(input.logsInitialText),
          text: input.logsInitialText,
        },
        absent: {
          sha256: sha256(input.logsAbsentText),
          text: input.logsAbsentText,
        },
        preSignal: {
          sha256: sha256(input.logsPreSignalText),
          text: input.logsPreSignalText,
        },
      },
    },
  };
}

function prefixReceipt(prefix) {
  return {
    schemaVersion: 'overlaykit-h043-h042-prefix/v1',
    prefixSha256: sha256Canonical(prefix),
    cutoffMonotonicNs: prefix.cutoffMonotonicNs,
    runtimePoll: {
      lineCount: prefix.raw.runtimePoll.lineCount,
      sha256: prefix.raw.runtimePoll.sha256,
    },
    hostPoll: {
      lineCount: prefix.raw.hostPoll.lineCount,
      sha256: prefix.raw.hostPoll.sha256,
    },
    invocationAudit: clone(prefix.raw.invocationAudit),
    logs: {
      initialSha256: prefix.raw.logs.initial.sha256,
      absentSha256: prefix.raw.logs.absent.sha256,
      preSignalSha256: prefix.raw.logs.preSignal.sha256,
    },
  };
}

function fullWorker(worker) {
  return Object.fromEntries(WORKER_KEYS.map((key) => [key, clone(worker?.[key])]));
}

function lifecycle(lifecycleValue) {
  return Object.fromEntries(LIFECYCLE_KEYS.map((key) => [key, clone(lifecycleValue?.[key])]));
}

function statIdentity(value) {
  return {
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
}

function exactTarget(snapshot, serial) {
  const usb = snapshot.usb.filter(
    (entry) =>
      entry.serial === serial &&
      entry.vendorId === '0fd9' &&
      entry.productId === '0080' &&
      entry.serialMatches === true
  );
  const hidraw = snapshot.hidraw.filter(
    (entry) =>
      entry.serialMatches === true &&
      entry.hid?.unique === serial &&
      entry.hid?.id === '0003:00000FD9:00000080' &&
      entry.usbAncestor?.serial === serial &&
      entry.usbAncestor?.vendorId === '0fd9' &&
      entry.usbAncestor?.productId === '0080'
  );
  return usb.length === 1 && hidraw.length === 1 ? { usb: usb[0], hidraw: hidraw[0] } : null;
}

function epoch(target) {
  if (!target) return null;
  return {
    serial: target.usb.serial,
    busNumber: target.usb.busNumber,
    deviceNumber: target.usb.deviceNumber,
    usbDevicePath: target.usb.devicePath,
    usbDev: target.usb.dev,
    hidDevicePath: target.hidraw.hidDevicePath,
    devicePath: target.hidraw.devicePath,
    stat: statIdentity(target.hidraw.stat),
  };
}

function descriptorMatches(descriptor, stat) {
  return (
    descriptor?.stat?.inode === stat?.inode &&
    descriptor?.stat?.rdev === stat?.rdev &&
    descriptor?.stat?.major === stat?.major &&
    descriptor?.stat?.minor === stat?.minor &&
    descriptor?.stat?.isCharacterDevice === true
  );
}

function markersEqual(left, right) {
  return (
    left.opening === right.opening &&
    left.ready === right.ready &&
    left.openFailed === right.openFailed &&
    same(left.relevantLines, right.relevantLines)
  );
}

function auditExact(entries, observationCount) {
  const allowed = new Set([
    'docker-run',
    'physical-disconnect-window',
    'physical-reconnect-window',
    'docker-exec-observer',
    'docker-logs',
    'docker-inspect',
  ]);
  const counts = entries.reduce((result, entry) => {
    result[entry.kind] = (result[entry.kind] ?? 0) + 1;
    return result;
  }, {});
  return (
    Number.isInteger(observationCount) &&
    observationCount > 0 &&
    entries.every((entry) => allowed.has(entry.kind)) &&
    counts['docker-run'] === 1 &&
    counts['physical-disconnect-window'] === 1 &&
    counts['physical-reconnect-window'] === 1 &&
    counts['docker-exec-observer'] === observationCount &&
    counts['docker-logs'] === observationCount &&
    counts['docker-inspect'] === observationCount * 2
  );
}

function recomputePredicates(prefix) {
  const runtime = parseJsonLines(prefix.raw.runtimePoll.text, 'runtime prefix');
  const host = parseJsonLines(prefix.raw.hostPoll.text, 'host prefix');
  const observations = prefix.context.observations;
  const serial = prefix.context.device.serial;
  const initialTarget = exactTarget(observations.initial.host, serial);
  const returnedTarget = exactTarget(observations.returned.host, serial);
  const finalTarget = exactTarget(observations.preSignal.host, serial);
  const initialEpoch = epoch(initialTarget);
  const returnedEpoch = epoch(returnedTarget);
  const finalEpoch = epoch(finalTarget);
  const cutoff = monotonic(prefix.cutoffMonotonicNs, 'cutoff');
  const runtimeTimes = runtime.map((entry) => monotonic(entry.monotonicNs, 'runtime'));
  const hostTimes = host.map((entry) => monotonic(entry.monotonicNs, 'host'));
  const auditTimes = prefix.context.invocationAuditPrefix.map((entry) =>
    monotonic(entry.monotonicNs, 'audit')
  );
  const prefixBoundaryExact =
    runtime.length === 55 &&
    host.length === 476 &&
    prefix.context.invocationAuditPrefix.length === 223 &&
    runtimeTimes.every((value, index) => index === 0 || value > runtimeTimes[index - 1]) &&
    hostTimes.every((value, index) => index === 0 || value > hostTimes[index - 1]) &&
    auditTimes.every((value, index) => index === 0 || value > auditTimes[index - 1]) &&
    runtimeTimes.at(-1) < cutoff &&
    hostTimes.at(-1) === cutoff &&
    auditTimes.every((value) => value <= cutoff);
  const absentExact =
    observations.absent.host.state === 'absent' &&
    observations.absent.host.usb.filter((entry) => entry.serial === serial).length === 0 &&
    observations.absent.host.hidraw.filter(
      (entry) => entry.hid?.unique === serial || entry.usbAncestor?.serial === serial
    ).length === 0;
  const usbEpochExact =
    initialEpoch !== null &&
    returnedEpoch !== null &&
    absentExact &&
    initialEpoch.serial === returnedEpoch.serial &&
    initialEpoch.deviceNumber !== returnedEpoch.deviceNumber &&
    initialEpoch.hidDevicePath !== returnedEpoch.hidDevicePath &&
    initialEpoch.stat.inode !== returnedEpoch.stat.inode &&
    initialEpoch.stat.rdev === returnedEpoch.stat.rdev;
  const returnedDeviceExact =
    finalEpoch !== null &&
    same(returnedEpoch, finalEpoch) &&
    observations.returned.host.state === 'present' &&
    observations.preSignal.host.state === 'present';
  const started = monotonic(prefix.context.windows.preSignal.startedMonotonicNs, 'start');
  const deadline = started + 30_000_000_000n;
  const completed = monotonic(prefix.context.windows.preSignal.completedMonotonicNs, 'completed');
  const afterReturn = runtime.filter((entry) => monotonic(entry.monotonicNs, 'runtime') >= started);
  const before = afterReturn.filter((entry) => monotonic(entry.monotonicNs, 'runtime') < deadline);
  const boundary = afterReturn.find((entry) => monotonic(entry.monotonicNs, 'runtime') >= deadline);
  const baselineAt = monotonic(observations.initial.runtime.monotonicNs, 'baseline');
  const admitted = runtime.filter((entry) => monotonic(entry.monotonicNs, 'runtime') >= baselineAt);
  const workers = admitted.map((entry) => entry.observer.surfaceWorkers);
  const workerUniqueThroughout = workers.every((entries) => entries.length === 1);
  const expectedWorker = workerUniqueThroughout ? fullWorker(workers[0][0]) : null;
  const workerTupleUnchanged =
    expectedWorker !== null &&
    workers.every((entries) => same(fullWorker(entries[0]), expectedWorker));
  const expectedLifecycle = lifecycle(prefix.context.companion.initialLifecycle);
  const topLevelLifecycleUnchanged =
    same(lifecycle(prefix.context.companion.absentLifecycle), expectedLifecycle) &&
    same(lifecycle(prefix.context.companion.preSignalLifecycle), expectedLifecycle) &&
    runtime.every((entry) => same(lifecycle(entry.lifecycle), expectedLifecycle));
  const currentDescriptorAbsentThroughout =
    afterReturn.length > 0 &&
    afterReturn.every((entry) =>
      entry.observer.surfaceWorkers[0].fileDescriptors.every(
        (descriptor) => !descriptorMatches(descriptor, returnedEpoch.stat)
      )
    );
  const markersStable = admitted.every((entry) =>
    markersEqual(entry.markers, observations.initial.runtime.markers)
  );
  const negativeWindowComplete =
    prefix.context.windows.preSignal.timeoutSeconds === 30 &&
    prefix.context.windows.preSignal.deadlineExpired === true &&
    prefix.context.windows.preSignal.boundaryNegative === true &&
    completed >= deadline &&
    before.length > 0 &&
    boundary !== undefined &&
    boundary.observer.surfaceWorkers.length === 1 &&
    boundary.observer.surfaceWorkers[0].fileDescriptors.every(
      (descriptor) => !descriptorMatches(descriptor, returnedEpoch.stat)
    ) &&
    markersEqual(boundary.markers, observations.initial.runtime.markers);
  const finalRuntime = runtime.at(-1);
  const finalWorker = finalRuntime.observer.surfaceWorkers[0];
  const initialDescriptor =
    observations.initial.runtime.observer.surfaceWorkers[0].fileDescriptors.find((descriptor) =>
      descriptorMatches(descriptor, initialEpoch.stat)
    );
  const owner = finalTarget.hidraw.owner;
  const finalReceiptsCoherent =
    initialDescriptor !== undefined &&
    observations.initial.runtime.markers.opening >= 1 &&
    observations.initial.runtime.markers.ready >= 1 &&
    finalRuntime.phase === 'signal-target-revalidate' &&
    monotonic(finalRuntime.monotonicNs, 'final runtime') < cutoff &&
    same(fullWorker(finalWorker), expectedWorker) &&
    finalWorker.fileDescriptors.every(
      (descriptor) => !descriptorMatches(descriptor, returnedEpoch.stat)
    ) &&
    owner.observed === true &&
    owner.usageError === false &&
    owner.pids.length === 0 &&
    finalTarget.hidraw.nodeStable === true &&
    finalTarget.hidraw.nodeMatchesClass === true;
  return {
    sourceAdmissionExact:
      sha256Canonical(prefix) === PREFIX_SHA256 && prefix.context.collector.sourceStable === true,
    prefixBoundaryExact,
    usbEpochExact,
    returnedDeviceExact,
    negativeWindowComplete,
    topLevelLifecycleUnchanged,
    workerUniqueThroughout,
    workerTupleUnchanged,
    currentDescriptorAbsentThroughout,
    markersStable,
    finalReceiptsCoherent,
    historicalAuditExact: auditExact(prefix.context.invocationAuditPrefix, runtime.length),
  };
}

function expectedCandidate(prefix, predicates) {
  assertion(Object.values(predicates).every(Boolean), 'independent predicates are not all true');
  const observations = prefix.context.observations;
  const serial = prefix.context.device.serial;
  const initialEpoch = epoch(exactTarget(observations.initial.host, serial));
  const returnedEpoch = epoch(exactTarget(observations.returned.host, serial));
  const finalEpoch = epoch(exactTarget(observations.preSignal.host, serial));
  const runtime = parseJsonLines(prefix.raw.runtimePoll.text, 'runtime prefix');
  const started = monotonic(prefix.context.windows.preSignal.startedMonotonicNs, 'start');
  const deadline = started + 30_000_000_000n;
  const boundary = runtime.find((entry) => monotonic(entry.monotonicNs, 'runtime') >= deadline);
  const finalRuntime = runtime.at(-1);
  const identity = {
    device: {
      serial,
      vendorId: prefix.context.device.vendorId,
      productId: prefix.context.device.productId,
      initialEpoch,
      returnedEpoch,
      revalidationEpoch: finalEpoch,
    },
    lifecycle: lifecycle(prefix.context.companion.preSignalLifecycle),
    worker: fullWorker(finalRuntime.observer.surfaceWorkers[0]),
  };
  const window = {
    startedMonotonicNs: prefix.context.windows.preSignal.startedMonotonicNs,
    deadlineMonotonicNs: deadline.toString(),
    completedMonotonicNs: prefix.context.windows.preSignal.completedMonotonicNs,
    boundaryPollMonotonicNs: boundary.monotonicNs,
    revalidationMonotonicNs: finalRuntime.monotonicNs,
    cutoffMonotonicNs: prefix.cutoffMonotonicNs,
  };
  const tokenSha256 = sha256Canonical({
    schemaVersion: 'overlaykit-h043-candidate-token/v1',
    sourceEvidenceSha256: H042_EVIDENCE_SHA256,
    prefixSha256: PREFIX_SHA256,
    device: identity.device,
    lifecycle: identity.lifecycle,
    worker: identity.worker,
    window,
  });
  return {
    kind: 'revalidation-required',
    historical: true,
    requiresRevalidation: true,
    authority: 'none',
    action: null,
    observedCutoff: {
      at: observations.preSignal.host.capturedAt,
      monotonicNs: prefix.cutoffMonotonicNs,
    },
    sourceEvidenceSha256: H042_EVIDENCE_SHA256,
    prefixSha256: PREFIX_SHA256,
    identity,
    window,
    tokenSha256,
  };
}

function allFalsePredicates() {
  return Object.fromEntries(INDEPENDENT_PREDICATE_KEYS.map((key) => [key, false]));
}

function independentPrefixShapeExact(prefix) {
  return (
    exactKeys(prefix, ['schemaVersion', 'source', 'cutoffMonotonicNs', 'context', 'raw']) &&
    prefix.schemaVersion === 'overlaykit-h043-h042-prefix/v1' &&
    exactKeys(prefix.source, [
      'archiveSha256',
      'h042RunId',
      'h042EvidenceSha256',
      'h042RunSha256',
      'h042VerificationSha256',
    ]) &&
    exactKeys(prefix.context, [
      'schemaVersion',
      'runId',
      'hypothesis',
      'startedAt',
      'collector',
      'host',
      'inputs',
      'device',
      'companion',
      'windows',
      'observations',
      'invocationAuditPrefix',
    ]) &&
    exactKeys(prefix.raw, ['runtimePoll', 'hostPoll', 'invocationAudit', 'logs'])
  );
}

function independentRawExact(prefix) {
  const runtime = prefix.raw.runtimePoll;
  const host = prefix.raw.hostPoll;
  const audit = prefix.raw.invocationAudit;
  const logs = prefix.raw.logs;
  return (
    typeof runtime?.text === 'string' &&
    parseJsonLines(runtime.text, 'independent hostile runtime').length === runtime.lineCount &&
    sha256(runtime.text) === runtime.sha256 &&
    typeof host?.text === 'string' &&
    parseJsonLines(host.text, 'independent hostile host').length === host.lineCount &&
    sha256(host.text) === host.sha256 &&
    Array.isArray(prefix.context.invocationAuditPrefix) &&
    prefix.context.invocationAuditPrefix.length === audit?.entryCount &&
    sha256(`${canonicalJson(prefix.context.invocationAuditPrefix)}\n`) === audit?.sha256 &&
    typeof logs?.initial?.text === 'string' &&
    sha256(logs.initial.text) === logs.initial.sha256 &&
    typeof logs?.absent?.text === 'string' &&
    sha256(logs.absent.text) === logs.absent.sha256 &&
    typeof logs?.preSignal?.text === 'string' &&
    sha256(logs.preSignal.text) === logs.preSignal.sha256
  );
}

function independentSourceDescriptorExact(prefix) {
  return (
    prefix.source.archiveSha256 === ARCHIVE_SHA256 &&
    prefix.source.h042RunId === H042_RUN_ID &&
    prefix.source.h042EvidenceSha256 === H042_EVIDENCE_SHA256 &&
    prefix.source.h042RunSha256 === H042_RUN_SHA256 &&
    prefix.source.h042VerificationSha256 === H042_VERIFICATION_SHA256 &&
    prefix.context.runId === H042_RUN_ID &&
    prefix.context.hypothesis === 'H-042' &&
    prefix.context.schemaVersion === 'overlaykit-h042-surface-worker-recycle-run/v1'
  );
}

function observationAnchorExact(entries, snapshot) {
  if (!snapshot || typeof snapshot.monotonicNs !== 'string') return false;
  const matches = entries.filter((entry) => entry.monotonicNs === snapshot.monotonicNs);
  return matches.length === 1 && same(matches[0], snapshot);
}

function independentPrefixBoundaryExact(prefix, runtime, host) {
  const cutoff = monotonic(prefix.cutoffMonotonicNs, 'hostile cutoff');
  const runtimeTimes = runtime.map((entry) =>
    monotonic(entry.monotonicNs, 'hostile runtime monotonicNs')
  );
  const hostTimes = host.map((entry) => monotonic(entry.monotonicNs, 'hostile host monotonicNs'));
  const auditTimes = prefix.context.invocationAuditPrefix.map((entry) =>
    monotonic(entry.monotonicNs, 'hostile audit monotonicNs')
  );
  return (
    runtimeTimes.length > 0 &&
    hostTimes.length > 0 &&
    runtimeTimes.every((value, index) => index === 0 || value > runtimeTimes[index - 1]) &&
    hostTimes.every((value, index) => index === 0 || value > hostTimes[index - 1]) &&
    auditTimes.every((value, index) => index === 0 || value > auditTimes[index - 1]) &&
    runtimeTimes.at(-1) < cutoff &&
    hostTimes.at(-1) === cutoff &&
    auditTimes.every((value) => value <= cutoff) &&
    prefix.context.observations.preSignal.host.monotonicNs === prefix.cutoffMonotonicNs
  );
}

function independentLifecycleUnchanged(prefix, runtime) {
  const expected = lifecycle(prefix.context.companion.initialLifecycle);
  return (
    same(lifecycle(prefix.context.companion.absentLifecycle), expected) &&
    same(lifecycle(prefix.context.companion.preSignalLifecycle), expected) &&
    runtime.every((entry) => same(lifecycle(entry.lifecycle), expected))
  );
}

function deriveIndependentClassification(prefix) {
  const runtime = parseJsonLines(prefix.raw.runtimePoll.text, 'independent hostile runtime');
  const host = parseJsonLines(prefix.raw.hostPoll.text, 'independent hostile host');
  const observations = prefix.context.observations;
  const serial = prefix.context.device.serial;
  const initialTarget = exactTarget(observations.initial.host, serial);
  const returnedTarget = exactTarget(observations.returned.host, serial);
  const finalTarget = exactTarget(observations.preSignal.host, serial);
  const initialEpoch = epoch(initialTarget);
  const returnedEpoch = epoch(returnedTarget);
  const finalEpoch = epoch(finalTarget);
  const absentExact =
    observations.absent.host?.state === 'absent' &&
    observations.absent.host.usb?.filter((entry) => entry.serial === serial).length === 0 &&
    observations.absent.host.hidraw?.filter(
      (entry) => entry.hid?.unique === serial || entry.usbAncestor?.serial === serial
    ).length === 0;
  const usbEpochExact =
    initialEpoch !== null &&
    returnedEpoch !== null &&
    absentExact &&
    initialEpoch.serial === returnedEpoch.serial &&
    initialEpoch.deviceNumber !== returnedEpoch.deviceNumber &&
    initialEpoch.hidDevicePath !== returnedEpoch.hidDevicePath &&
    initialEpoch.stat.inode !== returnedEpoch.stat.inode &&
    initialEpoch.stat.rdev === returnedEpoch.stat.rdev;
  const returnedDeviceExact =
    finalEpoch !== null &&
    same(returnedEpoch, finalEpoch) &&
    observations.returned.host.state === 'present' &&
    observations.preSignal.host.state === 'present' &&
    observations.returned.host.scope?.bootId === observations.preSignal.host.scope?.bootId &&
    observations.returned.host.scope?.mountNamespace ===
      observations.preSignal.host.scope?.mountNamespace;

  const window = prefix.context.windows.preSignal;
  const started = monotonic(window.startedMonotonicNs, 'hostile window start');
  const deadline = started + 30_000_000_000n;
  const completed = monotonic(window.completedMonotonicNs, 'hostile window completion');
  const baselineAt = monotonic(
    observations.initial.runtime.monotonicNs,
    'hostile baseline acquisition'
  );
  const admitted = runtime.filter(
    (entry) => monotonic(entry.monotonicNs, 'hostile runtime') >= baselineAt
  );
  const afterReturn = runtime.filter(
    (entry) => monotonic(entry.monotonicNs, 'hostile runtime') >= started
  );
  const beforeDeadline = afterReturn.filter(
    (entry) => monotonic(entry.monotonicNs, 'hostile runtime') < deadline
  );
  const boundary = afterReturn.find(
    (entry) => monotonic(entry.monotonicNs, 'hostile runtime') >= deadline
  );
  const negativeWindowComplete =
    window.timeoutSeconds === 30 &&
    window.deadlineExpired === true &&
    window.boundaryNegative === true &&
    completed >= deadline &&
    beforeDeadline.length > 0 &&
    boundary !== undefined &&
    boundary.observer?.surfaceWorkers?.length === 1 &&
    boundary.observer.surfaceWorkers[0].fileDescriptors?.every(
      (descriptor) => !descriptorMatches(descriptor, returnedEpoch?.stat)
    ) &&
    markersEqual(boundary.markers, observations.initial.runtime.markers);

  const workers = admitted.map((entry) => entry.observer?.surfaceWorkers);
  const workerUniqueThroughout = workers.every(
    (entries) => Array.isArray(entries) && entries.length === 1
  );
  const initialWorker = workerUniqueThroughout ? fullWorker(workers[0][0]) : null;
  const workerTupleUnchanged =
    initialWorker !== null &&
    workers.every((entries) => same(fullWorker(entries[0]), initialWorker));
  const currentDescriptorAbsentThroughout =
    afterReturn.length > 0 &&
    afterReturn.every(
      (entry) =>
        entry.observer.surfaceWorkers.length === 1 &&
        entry.observer.surfaceWorkers[0].fileDescriptors.every(
          (descriptor) => !descriptorMatches(descriptor, returnedEpoch?.stat)
        )
    );
  const initialMarkers = observations.initial.runtime.markers;
  const finalMarkers = observations.preSignal.runtime.markers;
  const markersStable = admitted.every((entry) => markersEqual(entry.markers, initialMarkers));
  const topLevelLifecycleUnchanged = independentLifecycleUnchanged(prefix, runtime);
  const finalRuntime = runtime.at(-1);
  const finalWorker = finalRuntime?.observer?.surfaceWorkers?.[0];
  const descriptorObserved = finalWorker?.fileDescriptors?.some((descriptor) =>
    descriptorMatches(descriptor, returnedEpoch?.stat)
  );
  const openingDelta = (finalMarkers?.opening ?? 0) - (initialMarkers?.opening ?? 0);
  const readyDelta = (finalMarkers?.ready ?? 0) - (initialMarkers?.ready ?? 0);
  const control = observations.preSignal.control;
  const declaredMarkers = observations.preSignal.markers;
  const negativeAtBoundary = descriptorObserved !== true && openingDelta === 0 && readyDelta === 0;
  const preSignalSummaryCoherent =
    same(declaredMarkers?.baseline, initialMarkers) &&
    same(declaredMarkers?.final, finalMarkers) &&
    control?.descriptorObserved === (descriptorObserved === true) &&
    control?.openingObserved === openingDelta > 0 &&
    control?.readyObserved === readyDelta > 0 &&
    control?.boundaryNegative === (window.deadlineExpired === true && negativeAtBoundary);
  const initialDescriptor =
    observations.initial.runtime?.observer?.surfaceWorkers?.[0]?.fileDescriptors?.find(
      (descriptor) => descriptorMatches(descriptor, initialEpoch?.stat)
    );
  const finalOwner = finalTarget?.hidraw?.owner;
  const finalReceiptsCoherent =
    initialDescriptor !== undefined &&
    observations.initial.runtime?.markers?.opening >= 1 &&
    observations.initial.runtime?.markers?.ready >= 1 &&
    absentExact &&
    finalRuntime?.phase === 'signal-target-revalidate' &&
    monotonic(finalRuntime.monotonicNs, 'hostile final runtime') <
      monotonic(observations.preSignal.host.monotonicNs, 'hostile final host') &&
    same(fullWorker(finalWorker), initialWorker) &&
    finalWorker?.fileDescriptors?.every(
      (descriptor) => !descriptorMatches(descriptor, returnedEpoch?.stat)
    ) &&
    finalOwner?.observed === true &&
    finalOwner?.usageError === false &&
    Array.isArray(finalOwner?.pids) &&
    finalOwner.pids.length === 0 &&
    finalTarget?.hidraw?.nodeStable === true &&
    finalTarget?.hidraw?.nodeMatchesClass === true;

  const historicalAuditExact = auditExact(prefix.context.invocationAuditPrefix, runtime.length);
  const observationReceiptsExact =
    observationAnchorExact(runtime, observations.preSignal.runtime) &&
    observationAnchorExact(host, observations.preSignal.host);
  const sourceLineageExact =
    independentSourceDescriptorExact(prefix) && prefix.context.collector?.sourceStable === true;
  const prefixBoundaryExact =
    independentPrefixShapeExact(prefix) &&
    independentRawExact(prefix) &&
    independentPrefixBoundaryExact(prefix, runtime, host) &&
    observationReceiptsExact &&
    preSignalSummaryCoherent;
  const sourceAdmissionExact = sourceLineageExact && sha256Canonical(prefix) === PREFIX_SHA256;
  const structuralAdmissionExact =
    sourceLineageExact && prefixBoundaryExact && historicalAuditExact;
  const exactFinalAbsence =
    observations.preSignal.host?.state === 'absent' &&
    observations.preSignal.host?.lsusb?.observed === true &&
    observations.preSignal.host?.lsusb?.exitCode === 0 &&
    observations.preSignal.host?.lsusb?.matches?.length === 0 &&
    observations.preSignal.host.usb?.filter((entry) => entry.serial === serial).length === 0 &&
    observations.preSignal.host.hidraw?.filter(
      (entry) => entry.hid?.unique === serial || entry.usbAncestor?.serial === serial
    ).length === 0 &&
    observations.preSignal.host?.errors?.length === 0;
  const windowOpenCoherent =
    completed >= started &&
    completed < deadline &&
    monotonic(prefix.cutoffMonotonicNs, 'hostile cutoff') < deadline &&
    completed <= monotonic(prefix.cutoffMonotonicNs, 'hostile cutoff') &&
    window.deadlineExpired === false &&
    window.boundaryNegative === false;
  const predicates = {
    sourceAdmissionExact,
    prefixBoundaryExact,
    usbEpochExact,
    returnedDeviceExact,
    negativeWindowComplete,
    topLevelLifecycleUnchanged,
    workerUniqueThroughout,
    workerTupleUnchanged,
    currentDescriptorAbsentThroughout,
    markersStable,
    finalReceiptsCoherent,
    historicalAuditExact,
  };

  return {
    structuralAdmissionExact,
    exactFinalAbsence,
    windowOpenCoherent,
    descriptorObserved: descriptorObserved === true,
    openingDelta,
    readyDelta,
    predicates,
  };
}

function classificationResult(disposition, stage, reasonCode, predicates, candidates = []) {
  return { disposition, stage, reasonCode, predicates, candidates };
}

function classifyIndependentPrefix(prefix) {
  try {
    if (!independentPrefixShapeExact(prefix) || !independentRawExact(prefix)) {
      return classificationResult(
        'inconclusive',
        'source-admission',
        'malformed-prefix',
        allFalsePredicates()
      );
    }

    const derived = deriveIndependentClassification(prefix);
    const { predicates } = derived;
    if (!derived.structuralAdmissionExact) {
      return classificationResult(
        'inconclusive',
        'source-admission',
        'untrusted-or-contradictory-prefix',
        predicates
      );
    }
    if (
      !predicates.workerUniqueThroughout ||
      !predicates.workerTupleUnchanged ||
      !predicates.topLevelLifecycleUnchanged
    ) {
      return classificationResult(
        'inconclusive',
        'identity',
        'identity-ambiguity-or-drift',
        predicates
      );
    }
    if (!predicates.usbEpochExact) {
      return classificationResult(
        'inconclusive',
        'contradictory-evidence',
        'device-epoch-or-node-mismatch',
        predicates
      );
    }
    if (derived.exactFinalAbsence) {
      return classificationResult(
        'withheld',
        'not-eligible',
        'device-absent-at-cutoff',
        predicates
      );
    }
    if (!predicates.returnedDeviceExact) {
      return classificationResult(
        'inconclusive',
        'contradictory-evidence',
        'device-epoch-or-node-mismatch',
        predicates
      );
    }

    const elapsed =
      monotonic(
        prefix.context.windows.preSignal.completedMonotonicNs,
        'hostile window completion'
      ) - monotonic(prefix.context.windows.preSignal.startedMonotonicNs, 'hostile window start');
    if (elapsed < 0n) {
      return classificationResult(
        'inconclusive',
        'prefix-boundary',
        'incomplete-or-contradictory-boundary',
        predicates
      );
    }
    if (elapsed < 30_000_000_000n) {
      return derived.windowOpenCoherent
        ? classificationResult('withheld', 'not-eligible', 'negative-window-open', predicates)
        : classificationResult(
            'inconclusive',
            'prefix-boundary',
            'incomplete-or-contradictory-boundary',
            predicates
          );
    }
    if (derived.descriptorObserved || (derived.openingDelta > 0 && derived.readyDelta > 0)) {
      return classificationResult(
        'withheld',
        'not-eligible',
        'automatic-reacquisition-observed',
        predicates
      );
    }
    if (derived.openingDelta !== 0 || derived.readyDelta !== 0) {
      return classificationResult(
        'inconclusive',
        'contradictory-evidence',
        'partial-or-mixed-reacquisition',
        predicates
      );
    }
    if (!predicates.negativeWindowComplete || !predicates.prefixBoundaryExact) {
      return classificationResult(
        'inconclusive',
        'prefix-boundary',
        'incomplete-or-contradictory-boundary',
        predicates
      );
    }
    if (
      !predicates.sourceAdmissionExact ||
      !predicates.historicalAuditExact ||
      !predicates.currentDescriptorAbsentThroughout ||
      !predicates.markersStable ||
      !predicates.finalReceiptsCoherent
    ) {
      return classificationResult(
        'inconclusive',
        'source-admission',
        'untrusted-or-contradictory-prefix',
        predicates
      );
    }
    if (!Object.values(predicates).every((value) => value === true)) {
      return classificationResult('inconclusive', 'classification', 'predicate-gap', predicates);
    }
    return classificationResult(
      'candidate',
      'historical-worker-candidate',
      'revalidation-required-worker-candidate',
      predicates,
      [expectedCandidate(prefix, predicates)]
    );
  } catch {
    return classificationResult(
      'inconclusive',
      'source-admission',
      'malformed-prefix',
      allFalsePredicates()
    );
  }
}

function independentClassificationExactShape(classification) {
  return (
    exactKeys(classification, ['disposition', 'stage', 'reasonCode', 'predicates', 'candidates']) &&
    ['candidate', 'withheld', 'inconclusive'].includes(classification.disposition) &&
    exactKeys(classification.predicates, INDEPENDENT_PREDICATE_KEYS) &&
    Array.isArray(classification.candidates) &&
    classification.candidates.length <= 1 &&
    (classification.disposition === 'candidate'
      ? classification.candidates.length === 1 &&
        classification.candidates[0].requiresRevalidation === true &&
        classification.candidates[0].authority === 'none' &&
        classification.candidates[0].action === null
      : classification.candidates.length === 0)
  );
}

function rebuildIndependentRaw(prefix, { runtimeEntries, hostEntries, auditEntries } = {}) {
  const candidate = clone(prefix);
  if (runtimeEntries) {
    const text = serializeJsonLines(runtimeEntries);
    candidate.raw.runtimePoll = {
      lineCount: runtimeEntries.length,
      sha256: sha256(text),
      text,
    };
  }
  if (hostEntries) {
    const text = serializeJsonLines(hostEntries);
    candidate.raw.hostPoll = {
      lineCount: hostEntries.length,
      sha256: sha256(text),
      text,
    };
  }
  if (auditEntries) {
    candidate.context.invocationAuditPrefix = clone(auditEntries);
    candidate.raw.invocationAudit = {
      entryCount: auditEntries.length,
      sha256: sha256(`${canonicalJson(auditEntries)}\n`),
    };
  }
  return candidate;
}

function independentCurrentNodeDescriptor(prefix) {
  const stat = prefix.context.observations.preSignal.host.hidraw.find(
    (entry) => entry.serialMatches
  ).stat;
  return {
    descriptor: '20',
    target: '/host-dev/hidraw0',
    stat: clone(stat),
    fdinfoSha256: 'a'.repeat(64),
  };
}

function synchronizeIndependentPreSignalSummary(prefix) {
  const observation = prefix.context.observations.preSignal;
  const initialMarkers = prefix.context.observations.initial.runtime.markers;
  const finalMarkers = observation.runtime.markers;
  const currentStat = observation.host.hidraw.find((entry) => entry.serialMatches)?.stat;
  const descriptorObserved = observation.runtime.observer.surfaceWorkers.some((worker) =>
    worker.fileDescriptors.some((descriptor) => descriptorMatches(descriptor, currentStat))
  );
  const openingObserved = finalMarkers.opening > initialMarkers.opening;
  const readyObserved = finalMarkers.ready > initialMarkers.ready;
  observation.markers = {
    baseline: clone(initialMarkers),
    final: clone(finalMarkers),
  };
  observation.control = {
    descriptorObserved,
    openingObserved,
    readyObserved,
    boundaryNegative:
      prefix.context.windows.preSignal.deadlineExpired === true &&
      !descriptorObserved &&
      !openingObserved &&
      !readyObserved,
  };
}

function mutateIndependentFinalRuntime(prefix, mutateWorker, mutateRuntime) {
  const entries = parseJsonLines(prefix.raw.runtimePoll.text, 'independent hostile runtime');
  const final = entries.at(-1);
  mutateWorker?.(final.observer.surfaceWorkers, final);
  mutateRuntime?.(final);
  const candidate = rebuildIndependentRaw(prefix, { runtimeEntries: entries });
  candidate.context.observations.preSignal.runtime = clone(final);
  synchronizeIndependentPreSignalSummary(candidate);
  return candidate;
}

function mutateIndependentFinalHost(prefix, mutateHost) {
  const entries = parseJsonLines(prefix.raw.hostPoll.text, 'independent hostile host');
  const final = entries.at(-1);
  mutateHost(final);
  const candidate = rebuildIndependentRaw(prefix, { hostEntries: entries });
  candidate.context.observations.preSignal.host = clone(final);
  synchronizeIndependentPreSignalSummary(candidate);
  return candidate;
}

function openIndependentNegativeWindow(prefix) {
  const started = monotonic(
    prefix.context.windows.preSignal.startedMonotonicNs,
    'independent open-window start'
  );
  const runtime = parseJsonLines(prefix.raw.runtimePoll.text, 'independent open-window runtime');
  const finalRuntime = runtime.find(
    (entry) => monotonic(entry.monotonicNs, 'independent open-window runtime') >= started
  );
  assertion(finalRuntime, 'independent hostile open window has no post-return runtime');
  const cutoff = monotonic(finalRuntime.monotonicNs, 'independent open-window final runtime') + 1n;
  const runtimeEntries = runtime.filter(
    (entry) => monotonic(entry.monotonicNs, 'independent open-window runtime') < cutoff
  );
  const hostEntries = parseJsonLines(
    prefix.raw.hostPoll.text,
    'independent open-window host'
  ).filter((entry) => monotonic(entry.monotonicNs, 'independent open-window host') < cutoff);
  const finalHost = clone(prefix.context.observations.returned.host);
  finalHost.capturedAt = finalRuntime.capturedAt;
  finalHost.monotonicNs = cutoff.toString();
  hostEntries.push(finalHost);
  const auditEntries = prefix.context.invocationAuditPrefix.filter(
    (entry) => monotonic(entry.monotonicNs, 'independent open-window audit') <= cutoff
  );

  const candidate = rebuildIndependentRaw(prefix, {
    runtimeEntries,
    hostEntries,
    auditEntries,
  });
  candidate.cutoffMonotonicNs = cutoff.toString();
  candidate.context.observations.preSignal.host = clone(finalHost);
  candidate.context.observations.preSignal.runtime = clone(finalRuntime);
  candidate.context.companion.preSignalLifecycle = clone(finalRuntime.lifecycle);
  candidate.context.companion.workerLifecycle.preSignal = clone(
    finalRuntime.observer.surfaceWorkers
  );
  candidate.context.windows.preSignal.completedAt = finalHost.capturedAt;
  candidate.context.windows.preSignal.completedMonotonicNs = cutoff.toString();
  candidate.context.windows.preSignal.deadlineExpired = false;
  candidate.context.windows.preSignal.boundaryNegative = false;
  synchronizeIndependentPreSignalSummary(candidate);
  return candidate;
}

function independentHostileDefinitions() {
  return [
    {
      id: 'canonical-golden',
      expectedDisposition: 'candidate',
      expectedCandidateCount: 1,
      mutate: (value) => value,
    },
    {
      id: 'healthy-baseline',
      expectedDisposition: 'withheld',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateIndependentFinalRuntime(value, (workers, runtime) => {
          workers[0].fileDescriptors = [independentCurrentNodeDescriptor(value)];
          runtime.markers.opening += 1;
          runtime.markers.ready += 1;
        });
      },
    },
    {
      id: 'device-absent',
      expectedDisposition: 'withheld',
      expectedCandidateCount: 0,
      mutate(value) {
        const absent = value.context.observations.absent.host;
        return mutateIndependentFinalHost(value, (host) => {
          for (const key of ['lsusb', 'usb', 'hidraw', 'priorPath', 'errors', 'state']) {
            host[key] = clone(absent[key]);
          }
        });
      },
    },
    {
      id: 'negative-window-open',
      expectedDisposition: 'withheld',
      expectedCandidateCount: 0,
      mutate: openIndependentNegativeWindow,
    },
    {
      id: 'current-descriptor-reacquired',
      expectedDisposition: 'withheld',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateIndependentFinalRuntime(value, (workers) => {
          workers[0].fileDescriptors = [independentCurrentNodeDescriptor(value)];
        });
      },
    },
    {
      id: 'ordered-markers-changed',
      expectedDisposition: 'withheld',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateIndependentFinalRuntime(value, null, (runtime) => {
          runtime.markers.opening += 1;
          runtime.markers.ready += 1;
        });
      },
    },
    {
      id: 'partial-marker-change',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateIndependentFinalRuntime(value, null, (runtime) => {
          runtime.markers.opening += 1;
        });
      },
    },
    {
      id: 'worker-missing',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateIndependentFinalRuntime(value, (workers) => workers.splice(0));
      },
    },
    {
      id: 'multiple-workers',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateIndependentFinalRuntime(value, (workers) => {
          workers.push({ ...clone(workers[0]), pid: 999, startTicks: 999 });
        });
      },
    },
    {
      id: 'container-lifecycle-drift',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        const candidate = mutateIndependentFinalRuntime(value, null, (runtime) => {
          runtime.lifecycle.restartCount = 1;
        });
        candidate.context.companion.preSignalLifecycle.restartCount = 1;
        return candidate;
      },
    },
    {
      id: 'pid1-identity-drift',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        const candidate = mutateIndependentFinalRuntime(value, null, (runtime) => {
          runtime.lifecycle.pid1StartTicks += 1;
        });
        candidate.context.companion.preSignalLifecycle.pid1StartTicks += 1;
        return candidate;
      },
    },
    {
      id: 'worker-pid-changed',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateIndependentFinalRuntime(value, (workers) => {
          workers[0].pid += 1;
        });
      },
    },
    {
      id: 'worker-startticks-changed',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateIndependentFinalRuntime(value, (workers) => {
          workers[0].startTicks += 1;
        });
      },
    },
    {
      id: 'worker-ppid-changed',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateIndependentFinalRuntime(value, (workers) => {
          workers[0].ppid += 1;
        });
      },
    },
    {
      id: 'worker-parent-startticks-changed',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateIndependentFinalRuntime(value, (workers) => {
          workers[0].parentStartTicks += 1;
        });
      },
    },
    {
      id: 'worker-pid-namespace-changed',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateIndependentFinalRuntime(value, (workers) => {
          workers[0].pidNamespace = 'pid:[999]';
        });
      },
    },
    {
      id: 'worker-full-tuple-drift',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        return mutateIndependentFinalRuntime(value, (workers) => {
          workers[0].mountNamespace = 'mnt:[999]';
        });
      },
    },
    {
      id: 'exact-absence-missing',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        value.context.observations.absent.host.state = 'present';
        value.context.observations.absent.host.usb = clone(
          value.context.observations.initial.host.usb
        );
        return value;
      },
    },
    {
      id: 'usb-epoch-identity-mismatch',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        value.context.observations.returned.host.usb[0].deviceNumber =
          value.context.observations.initial.host.usb[0].deviceNumber;
        return value;
      },
    },
    {
      id: 'returned-node-mismatch',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        value.context.observations.preSignal.host.hidraw[0].stat.inode = '9999';
        return value;
      },
    },
    {
      id: 'negative-window-boundary-missing',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        const deadline =
          monotonic(
            value.context.windows.preSignal.startedMonotonicNs,
            'independent hostile window start'
          ) + 30_000_000_000n;
        const entries = parseJsonLines(
          value.raw.runtimePoll.text,
          'independent hostile runtime'
        ).filter(
          (entry) =>
            entry.phase === 'signal-target-revalidate' ||
            monotonic(entry.monotonicNs, 'independent hostile runtime') < deadline
        );
        return rebuildIndependentRaw(value, { runtimeEntries: entries });
      },
    },
    {
      id: 'late-positive',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        const deadline =
          monotonic(
            value.context.windows.preSignal.startedMonotonicNs,
            'independent hostile window start'
          ) + 30_000_000_000n;
        const entries = parseJsonLines(value.raw.runtimePoll.text, 'independent hostile runtime');
        const boundary = entries.find(
          (entry) => monotonic(entry.monotonicNs, 'independent hostile runtime') >= deadline
        );
        assertion(boundary, 'independent hostile late-positive has no boundary poll');
        boundary.markers.opening += 1;
        return rebuildIndependentRaw(value, { runtimeEntries: entries });
      },
    },
    {
      id: 'prefix-tail-contamination',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        value.futureSignal = { signal: 'SIGTERM' };
        return value;
      },
    },
    {
      id: 'duplicate-candidates',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      duplicateOutput: true,
      mutate: (value) => value,
    },
    {
      id: 'unapproved-command',
      expectedDisposition: 'inconclusive',
      expectedCandidateCount: 0,
      mutate(value) {
        const audit = clone(value.context.invocationAuditPrefix);
        const last = audit.at(-1);
        audit.push({
          at: last.at,
          monotonicNs: (
            monotonic(last.monotonicNs, 'independent hostile final audit') + 1n
          ).toString(),
          kind: 'docker-exec-signal',
          phase: 'fault-injection',
        });
        return rebuildIndependentRaw(value, { auditEntries: audit });
      },
    },
  ];
}

function independentTailCheck(input, prefix) {
  const mutated = clone(input);
  mutated.run.windows.signal = { arbitrary: true };
  mutated.run.windows.postSignal = { arbitrary: true };
  mutated.run.observations.postSignal = { arbitrary: true };
  mutated.run.predicates = { arbitrary: false };
  mutated.run.outcome = { status: 'refuted' };
  mutated.run.cleanup = { arbitrary: true };
  mutated.run.completedAt = '2099-01-01T00:00:00.000Z';
  mutated.run.invocationAudit.entries = mutated.run.invocationAudit.entries.map((entry) =>
    BigInt(entry.monotonicNs) > BigInt(prefix.cutoffMonotonicNs)
      ? { ...entry, kind: 'independent-tail-mutation' }
      : entry
  );
  mutated.runtimePollText = serializeJsonLines(
    parseJsonLines(mutated.runtimePollText, 'runtime tail').map((entry) =>
      BigInt(entry.monotonicNs) > BigInt(prefix.cutoffMonotonicNs)
        ? { ...entry, phase: 'independent-tail-mutation' }
        : entry
    )
  );
  mutated.hostPollText = serializeJsonLines(
    parseJsonLines(mutated.hostPollText, 'host tail').map((entry) =>
      BigInt(entry.monotonicNs) > BigInt(prefix.cutoffMonotonicNs)
        ? { ...entry, state: 'independent-tail-mutation' }
        : entry
    )
  );
  return same(independentPrefix(mutated), prefix);
}

function independentCausalBoundary(h042Run, prefix) {
  const faultEntries = h042Run.invocationAudit.entries
    .map((entry, sourceAuditIndex) => ({ entry, sourceAuditIndex }))
    .filter(
      ({ entry }) => entry.kind === 'docker-exec-signal' || entry.phase === 'fault-injection'
    );
  assertion(faultEntries.length > 0, 'source has no fault-injection boundary');
  const first = faultEntries[0];
  const cutoff = monotonic(prefix.cutoffMonotonicNs, 'causal cutoff');
  const fault = monotonic(first.entry.monotonicNs, 'first fault injection');
  assertion(cutoff < fault, 'causal cutoff does not precede first fault injection');
  return {
    cutoffMonotonicNs: prefix.cutoffMonotonicNs,
    firstFaultInjection: {
      sourceAuditIndex: first.sourceAuditIndex,
      at: first.entry.at,
      monotonicNs: first.entry.monotonicNs,
      kind: first.entry.kind,
      phase: first.entry.phase,
      entrySha256: sha256Canonical(first.entry),
    },
    gapNs: (fault - cutoff).toString(),
    precedesFirstFaultInjection: true,
  };
}

async function collectSourceReceipts() {
  return Promise.all(
    INDEPENDENT_REQUIRED_SOURCES.map(async (relativePath) => ({
      path: relativePath,
      sha256: sha256(await readFile(path.join(REPOSITORY_ROOT, relativePath))),
    }))
  );
}

function verifyMatrix(matrix, prefix) {
  const definitions = independentHostileDefinitions();
  const caseIds = definitions.map((definition) => definition.id);
  assertion(same(caseIds, INDEPENDENT_CASE_IDS), 'independent matrix definitions drifted');

  const cases = definitions.map((definition) => {
    const input = definition.mutate(clone(prefix));
    let classification = classifyIndependentPrefix(input);
    if (definition.duplicateOutput) {
      const duplicated = {
        ...classification,
        candidates: [classification.candidates[0], clone(classification.candidates[0])],
      };
      if (!independentClassificationExactShape(duplicated)) {
        classification = classificationResult(
          'inconclusive',
          'source-admission',
          'duplicate-candidate-output',
          clone(classification.predicates)
        );
      }
    }
    assertion(
      independentClassificationExactShape(classification),
      `${definition.id} independent classification shape drifted`
    );
    const actualCandidateCount = classification.candidates.length;
    const passed =
      classification.disposition === definition.expectedDisposition &&
      actualCandidateCount === definition.expectedCandidateCount;
    return {
      id: definition.id,
      inputSha256: sha256Canonical(input),
      expectedDisposition: definition.expectedDisposition,
      actualDisposition: classification.disposition,
      expectedCandidateCount: definition.expectedCandidateCount,
      actualCandidateCount,
      stage: classification.stage,
      reasonCode: classification.reasonCode,
      passed,
    };
  });
  const passedCount = cases.filter((entry) => entry.passed).length;
  const allPassed = passedCount === cases.length;

  assertion(matrix.schemaVersion === 'overlaykit-h043-hostile-matrix/v1', 'matrix schema drifted');
  assertion(same(matrix.requiredCaseIds, caseIds), 'matrix case IDs drifted');
  assertion(
    matrix.caseCount === cases.length && matrix.cases.length === cases.length,
    'matrix count drifted'
  );
  cases.forEach((expected, index) => {
    assertion(
      same(matrix.cases[index], expected),
      `${expected.id} independently reconstructed hostile receipt drifted`
    );
  });
  assertion(matrix.passedCount === passedCount, 'matrix passed count drifted');
  assertion(matrix.allPassed === allPassed, 'matrix aggregate outcome drifted');
  return {
    allPassed,
  };
}

function verifySideEffects(audit) {
  const countKeys = [
    'commandCount',
    'hostObservationCount',
    'dockerCount',
    'networkCount',
    'processCount',
    'sysfsCount',
    'deviceOpenCount',
    'deviceReadCount',
    'deviceWriteCount',
    'signalCount',
    'mutationCount',
  ];
  assertion(audit.mode === 'offline-archived-evidence-only', 'side-effect audit mode drifted');
  assertion(audit.commandCount === audit.commands.length, 'side-effect command count drifted');
  const passed = countKeys.every((key) => audit[key] === 0);
  assertion(audit.passed === passed, 'side-effect aggregate outcome drifted');
  return {
    passed,
  };
}

function independentOutcomeFor(classification, matrix, sideEffectAudit, sourceStable) {
  if (!sideEffectAudit.passed) {
    return {
      status: 'refuted',
      stage: 'side-effect-boundary',
      reasonCode: 'side-effect-observed',
    };
  }
  if (!matrix.allPassed || !matrix.tailIndependent) {
    return {
      status: 'refuted',
      stage: 'hostile-matrix',
      reasonCode: 'hostile-case-or-tail-independence-failed',
    };
  }
  if (!sourceStable) {
    return {
      status: 'inconclusive',
      stage: 'source-admission',
      reasonCode: 'source-set-unstable',
    };
  }
  if (classification.disposition === 'withheld') {
    return {
      status: 'refuted',
      stage: 'canonical-classification',
      reasonCode: 'canonical-prefix-not-eligible',
    };
  }
  if (classification.disposition === 'inconclusive') {
    return {
      status: 'inconclusive',
      stage: 'prefix-boundary',
      reasonCode: 'canonical-prefix-inconclusive',
    };
  }
  if (classification.disposition === 'candidate' && classification.candidates.length === 1) {
    return {
      status: 'supported',
      stage: 'offline-worker-eligibility',
      reasonCode: 'canonical-candidate-and-hostile-matrix-exact',
    };
  }
  return {
    status: 'inconclusive',
    stage: 'prefix-boundary',
    reasonCode: 'canonical-prefix-inconclusive',
  };
}

export async function verifyRun(runPath) {
  const [runBytes, schemaBytes, archiveBytes] = await Promise.all([
    readFile(runPath),
    readFile(SCHEMA_PATH),
    readFile(H042_REPLAY_ARCHIVE_PATH),
  ]);
  const run = JSON.parse(runBytes.toString('utf8'));
  const schema = JSON.parse(schemaBytes.toString('utf8'));
  const ajv = new Ajv2020({
    allErrors: true,
    strict: false,
    validateFormats: false,
  });
  const validate = ajv.compile(schema);
  assertion(validate(run), `schema invalid: ${ajv.errorsText(validate.errors)}`);

  const { evidenceSha256, ...record } = run;
  assertion(sha256Canonical(record) === evidenceSha256, 'evidence hash mismatch');
  assertion(
    validUtcTimestamp(run.startedAt) &&
      validUtcTimestamp(run.completedAt) &&
      Date.parse(run.completedAt) >= Date.parse(run.startedAt),
    'run timestamps are invalid or reversed'
  );
  assertion(
    run.runId ===
      `h043-${run.startedAt.replace(/[:.]/gu, '-')}-${sha256(
        `${run.startedAt}:${PREFIX_SHA256}`
      ).slice(0, 8)}`,
    'run ID does not bind the start timestamp and canonical prefix'
  );
  assertion(sha256(archiveBytes) === ARCHIVE_SHA256, 'archive hash mismatch');
  const members = readTarGzipMembers(archiveBytes);
  const h042RunBytes = members.get(H042_RUN_MEMBER_PATH);
  const h042VerificationBytes = members.get(H042_VERIFICATION_MEMBER_PATH);
  assertion(sha256(h042RunBytes) === H042_RUN_SHA256, 'H-042 run hash mismatch');
  assertion(
    sha256(h042VerificationBytes) === H042_VERIFICATION_SHA256,
    'H-042 verification hash mismatch'
  );
  const h042Run = JSON.parse(h042RunBytes.toString('utf8'));
  const h042Verification = JSON.parse(h042VerificationBytes.toString('utf8'));
  assertion(
    h042Run.runId === H042_RUN_ID &&
      h042Run.evidenceSha256 === H042_EVIDENCE_SHA256 &&
      h042Verification.runId === H042_RUN_ID &&
      h042Verification.evidenceSha256 === H042_EVIDENCE_SHA256 &&
      h042Verification.verified === true &&
      h042Verification.outcome === 'supported',
    'accepted H-042 lineage mismatch'
  );

  const input = {
    run: h042Run,
    runtimePollText: memberText(members, 'runtime-poll.jsonl'),
    hostPollText: memberText(members, 'host-poll.jsonl'),
    logsInitialText: memberText(members, 'logs-initial.txt'),
    logsAbsentText: memberText(members, 'logs-absent.txt'),
    logsPreSignalText: memberText(members, 'logs-pre-signal.txt'),
  };
  const prefix = independentPrefix(input);
  const receipt = prefixReceipt(prefix);
  assertion(receipt.prefixSha256 === PREFIX_SHA256, 'independent prefix hash mismatch');
  assertion(receipt.runtimePoll.sha256 === RUNTIME_PREFIX_SHA256, 'runtime prefix mismatch');
  assertion(receipt.hostPoll.sha256 === HOST_PREFIX_SHA256, 'host prefix mismatch');
  assertion(receipt.invocationAudit.sha256 === AUDIT_PREFIX_SHA256, 'audit prefix mismatch');
  assertion(receipt.logs.initialSha256 === LOG_INITIAL_SHA256, 'initial log hash mismatch');
  assertion(receipt.logs.absentSha256 === LOG_ABSENT_SHA256, 'absent log hash mismatch');
  assertion(receipt.logs.preSignalSha256 === LOG_PRE_SIGNAL_SHA256, 'pre-signal log hash mismatch');
  assertion(receipt.cutoffMonotonicNs === CUTOFF_MONOTONIC_NS, 'cutoff mismatch');
  assertion(same(run.prefix, receipt), 'declared prefix receipt mismatch');
  const causalBoundary = independentCausalBoundary(h042Run, prefix);
  assertion(
    same(run.causalBoundary, causalBoundary),
    'first fault-injection causal boundary mismatch'
  );

  const predicates = recomputePredicates(prefix);
  assertion(
    same(Object.keys(predicates), INDEPENDENT_PREDICATE_KEYS),
    'independent predicate keys drifted'
  );
  assertion(Object.values(predicates).every(Boolean), 'independent predicates are not exact');
  assertion(
    same(run.canonicalClassification.predicates, predicates),
    'declared predicates mismatch'
  );
  assertion(
    run.canonicalClassification.disposition === 'candidate' &&
      run.canonicalClassification.stage === 'historical-worker-candidate' &&
      run.canonicalClassification.reasonCode === 'revalidation-required-worker-candidate' &&
      run.canonicalClassification.candidates.length === 1,
    'canonical classification is not one candidate'
  );
  const candidate = expectedCandidate(prefix, predicates);
  assertion(
    same(run.canonicalClassification.candidates[0], candidate),
    'candidate receipt mismatch'
  );

  const matrix = verifyMatrix(run.hostileMatrix, prefix);
  const tailIndependent = independentTailCheck(input, prefix);
  assertion(
    run.hostileMatrix.tailIndependent === tailIndependent,
    'declared tail independence does not match independent reconstruction'
  );
  const sideEffectAudit = verifySideEffects(run.sideEffectAudit);
  assertion(same(run.claimBoundary, INDEPENDENT_CLAIM_BOUNDARY), 'claim boundary drifted');
  assertion(run.collector.node === 'v22.20.0', 'collector Node identity mismatch');
  assertion(run.collector.repository === REPOSITORY, 'collector repository mismatch');
  assertion(run.collector.baseCommit === BASE_COMMIT, 'collector base commit mismatch');
  const currentSources = await collectSourceReceipts();
  assertion(same(run.collector.sources, currentSources), 'collector source hashes mismatch');
  assertion(
    same(
      run.collector.sources.map((entry) => entry.path),
      INDEPENDENT_REQUIRED_SOURCES
    ),
    'collector source closure drifted'
  );
  const changeBytes = await readFile(
    path.join(REPOSITORY_ROOT, '.overlaykit/governance/changes/CHG-0015.json')
  );
  assertion(
    run.collector.governance.changeId === 'CHG-0015' &&
      sha256(changeBytes) === CHANGE_SHA256 &&
      run.collector.governance.changeSha256 === CHANGE_SHA256 &&
      run.collector.governance.planHash === PLAN_HASH &&
      run.collector.governance.manifestContentHash === MANIFEST_CONTENT_HASH,
    'governance receipt mismatch'
  );
  const expectedOutcome = independentOutcomeFor(
    run.canonicalClassification,
    {
      allPassed: matrix.allPassed,
      tailIndependent,
    },
    sideEffectAudit,
    run.collector.sourceStable
  );
  assertion(
    same(run.outcome, expectedOutcome),
    'run outcome does not match independently recomputed evidence'
  );

  return {
    schemaVersion: 'overlaykit-h043-verification/v1',
    hypothesis: 'H-043',
    runId: run.runId,
    outcome: run.outcome.status,
    stage: run.outcome.stage,
    evidenceSha256,
    sourceSetExact: true,
    archiveExact: true,
    prefixExact: true,
    predicatesExact: true,
    candidateExact: true,
    hostileMatrixExact: true,
    tailIndependent,
    sideEffectAuditExact: true,
    claimBoundaryExact: true,
    verified: true,
  };
}

async function latestRunPath() {
  const root = path.join(REPOSITORY_ROOT, 'artifacts', 'h043');
  const entries = (await readdir(root, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory() && entry.name.startsWith('h043-'))
    .map((entry) => entry.name)
    .sort();
  assertion(entries.length > 0, 'no H-043 run artifact exists');
  return path.join(root, entries.at(-1), 'run.json');
}

function requestedRunPath() {
  const index = process.argv.indexOf('--run');
  if (index === -1) return null;
  assertion(process.argv[index + 1], '--run requires a path');
  return path.resolve(REPOSITORY_ROOT, process.argv[index + 1]);
}

function isDirectInvocation() {
  return process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

if (isDirectInvocation()) {
  try {
    const runPath = requestedRunPath() ?? (await latestRunPath());
    const verification = await verifyRun(runPath);
    const outputPath = path.join(path.dirname(runPath), 'verification.json');
    await writeFile(outputPath, `${JSON.stringify(verification, null, 2)}\n`, {
      flag: 'wx',
    });
    process.stdout.write(
      `${JSON.stringify({
        runId: verification.runId,
        verified: verification.verified,
        outcome: verification.outcome,
        evidenceSha256: verification.evidenceSha256,
        verificationPath: path.relative(REPOSITORY_ROOT, outputPath),
      })}\n`
    );
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}
