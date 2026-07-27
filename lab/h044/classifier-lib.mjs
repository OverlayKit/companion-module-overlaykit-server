import { createHash } from 'node:crypto';

export const H044_PREDICATE_KEYS = Object.freeze([
  'sourceAdmissionExact',
  'auditExact',
  'framesComplete',
  'frameOrderExact',
  'exposureBounded',
  'hostStable',
  'deviceExact',
  'lifecycleExact',
  'pid1Exact',
  'workerUnique',
  'workerExact',
  'descriptorAbsent',
  'markersStable',
]);

export const H044_PROHIBITED_COUNT_KEYS = Object.freeze([
  'externalNetwork',
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

export const H044_ALLOWED_PROCESS_KEYS = Object.freeze([
  'git',
  'lsusb',
  'dockerVersion',
  'dockerPs',
  'dockerInspect',
  'dockerLogs',
]);

const HISTORICAL_CANDIDATE_KEYS = Object.freeze([
  'kind',
  'historical',
  'requiresRevalidation',
  'authority',
  'action',
  'observedCutoff',
  'sourceEvidenceSha256',
  'prefixSha256',
  'identity',
  'window',
  'tokenSha256',
]);

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
  'containerObservation',
  'lifecycle',
  'pid1',
  'workers',
  'descriptors',
  'markers',
  'absence',
  'auditBinding',
  'digestSha256',
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

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const MONOTONIC_PATTERN = /^(?:0|[1-9][0-9]*)$/u;
const DATE_TIME_PATTERN =
  /^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?Z$/u;
const MAX_EXPOSURE_NS = 5_000_000_000n;

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

function monotonic(value) {
  if (typeof value !== 'string' || !MONOTONIC_PATTERN.test(value)) {
    throw new TypeError('invalid monotonic nanosecond value');
  }
  return BigInt(value);
}

function dateTime(value) {
  return (
    typeof value === 'string' && DATE_TIME_PATTERN.test(value) && Number.isFinite(Date.parse(value))
  );
}

function nonNegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function strictlyIncreasingIndexes(value) {
  return (
    Array.isArray(value) &&
    value.every(
      (entry, index) => nonNegativeInteger(entry) && (index === 0 || entry > value[index - 1])
    )
  );
}

function scalarString(value) {
  return typeof value === 'string' && value.length > 0;
}

function allFalsePredicates() {
  return Object.fromEntries(H044_PREDICATE_KEYS.map((key) => [key, false]));
}

function classification(disposition, stage, reasonCode, predicates, receipts = []) {
  return { disposition, stage, reasonCode, predicates, receipts };
}

function exactStat(value) {
  return (
    exactKeys(value, STAT_KEYS) &&
    scalarString(value.stDev) &&
    scalarString(value.inode) &&
    scalarString(value.ctimeNs) &&
    scalarString(value.mode) &&
    nonNegativeInteger(value.uid) &&
    nonNegativeInteger(value.gid) &&
    scalarString(value.rdev) &&
    scalarString(value.rdevHex) &&
    nonNegativeInteger(value.major) &&
    nonNegativeInteger(value.minor) &&
    typeof value.isCharacterDevice === 'boolean'
  );
}

function exactEpoch(value) {
  return (
    exactKeys(value, EPOCH_KEYS) &&
    scalarString(value.serial) &&
    scalarString(value.busNumber) &&
    scalarString(value.deviceNumber) &&
    scalarString(value.usbDevicePath) &&
    scalarString(value.usbDev) &&
    scalarString(value.hidDevicePath) &&
    scalarString(value.devicePath) &&
    exactStat(value.stat)
  );
}

function exactLifecycle(value) {
  return (
    exactKeys(value, LIFECYCLE_KEYS) &&
    sha256(value.containerId) &&
    /^sha256:[0-9a-f]{64}$/u.test(value.imageId) &&
    dateTime(value.startedAt) &&
    nonNegativeInteger(value.restartCount) &&
    nonNegativeInteger(value.hostPid) &&
    nonNegativeInteger(value.pid1StartTicks) &&
    scalarString(value.pidNamespace) &&
    scalarString(value.mountNamespace) &&
    scalarString(value.cgroup) &&
    scalarString(value.hostCgroup) &&
    scalarString(value.cgroupNamespaceMode)
  );
}

function exactWorker(value) {
  return (
    exactKeys(value, WORKER_KEYS) &&
    nonNegativeInteger(value.pid) &&
    nonNegativeInteger(value.startTicks) &&
    nonNegativeInteger(value.ppid) &&
    nonNegativeInteger(value.parentStartTicks) &&
    nonNegativeInteger(value.uid) &&
    nonNegativeInteger(value.gid) &&
    Array.isArray(value.groups) &&
    value.groups.every(nonNegativeInteger) &&
    Array.isArray(value.cmdline) &&
    value.cmdline.length > 0 &&
    value.cmdline.every((entry) => typeof entry === 'string') &&
    scalarString(value.cgroup) &&
    scalarString(value.pidNamespace) &&
    scalarString(value.mountNamespace)
  );
}

export function deviceIdentityFromHistoricalCandidate(historicalCandidate) {
  return {
    serial: historicalCandidate.identity.device.serial,
    vendorId: historicalCandidate.identity.device.vendorId,
    productId: historicalCandidate.identity.device.productId,
    epoch: clone(historicalCandidate.identity.device.revalidationEpoch),
  };
}

export function pid1IdentityFromHistoricalCandidate(historicalCandidate) {
  const lifecycle = historicalCandidate.identity.lifecycle;
  return {
    hostPid: lifecycle.hostPid,
    startTicks: lifecycle.pid1StartTicks,
    pidNamespace: lifecycle.pidNamespace,
    mountNamespace: lifecycle.mountNamespace,
    cgroup: lifecycle.cgroup,
  };
}

function exactHistoricalCandidate(candidate) {
  if (
    !exactKeys(candidate, HISTORICAL_CANDIDATE_KEYS) ||
    candidate.kind !== 'revalidation-required' ||
    candidate.historical !== true ||
    candidate.requiresRevalidation !== true ||
    candidate.authority !== 'none' ||
    candidate.action !== null ||
    !exactKeys(candidate.observedCutoff, ['at', 'monotonicNs']) ||
    !dateTime(candidate.observedCutoff.at) ||
    !MONOTONIC_PATTERN.test(candidate.observedCutoff.monotonicNs) ||
    !sha256(candidate.sourceEvidenceSha256) ||
    !sha256(candidate.prefixSha256) ||
    !exactKeys(candidate.identity, ['device', 'lifecycle', 'worker']) ||
    !exactKeys(candidate.identity.device, [
      'serial',
      'vendorId',
      'productId',
      'initialEpoch',
      'returnedEpoch',
      'revalidationEpoch',
    ]) ||
    !scalarString(candidate.identity.device.serial) ||
    candidate.identity.device.vendorId !== '0fd9' ||
    candidate.identity.device.productId !== '0080' ||
    !exactEpoch(candidate.identity.device.initialEpoch) ||
    !exactEpoch(candidate.identity.device.returnedEpoch) ||
    !exactEpoch(candidate.identity.device.revalidationEpoch) ||
    !exactLifecycle(candidate.identity.lifecycle) ||
    !exactWorker(candidate.identity.worker) ||
    !plainObject(candidate.window) ||
    !Object.values(candidate.window).every(
      (value) => typeof value === 'string' && MONOTONIC_PATTERN.test(value)
    ) ||
    !sha256(candidate.tokenSha256)
  ) {
    return false;
  }

  const expectedToken = sha256Canonical({
    schemaVersion: 'overlaykit-h043-candidate-token/v1',
    sourceEvidenceSha256: candidate.sourceEvidenceSha256,
    prefixSha256: candidate.prefixSha256,
    device: candidate.identity.device,
    lifecycle: candidate.identity.lifecycle,
    worker: candidate.identity.worker,
    window: candidate.window,
  });
  return candidate.tokenSha256 === expectedToken;
}

function exactHost(value) {
  return (
    exactKeys(value, ['hostname', 'bootId', 'osRelease']) &&
    scalarString(value.hostname) &&
    scalarString(value.bootId) &&
    scalarString(value.osRelease)
  );
}

function exactDevice(value) {
  if (
    !exactKeys(value, ['complete', 'present', 'identity']) ||
    typeof value.complete !== 'boolean' ||
    typeof value.present !== 'boolean'
  ) {
    return false;
  }
  if (!value.present) return value.identity === null;
  return (
    exactKeys(value.identity, ['serial', 'vendorId', 'productId', 'epoch']) &&
    scalarString(value.identity.serial) &&
    value.identity.vendorId === '0fd9' &&
    value.identity.productId === '0080' &&
    exactEpoch(value.identity.epoch)
  );
}

function exactContainerObservation(value) {
  if (
    !exactKeys(value, ['present', 'state', 'exact']) ||
    typeof value.present !== 'boolean' ||
    typeof value.exact !== 'boolean'
  ) {
    return false;
  }
  return value.present
    ? typeof value.state === 'string' && /^[a-z][a-z0-9_-]*$/u.test(value.state)
    : value.state === null;
}

function exactPid1(value) {
  return (
    exactKeys(value, ['hostPid', 'startTicks', 'pidNamespace', 'mountNamespace', 'cgroup']) &&
    nonNegativeInteger(value.hostPid) &&
    nonNegativeInteger(value.startTicks) &&
    scalarString(value.pidNamespace) &&
    scalarString(value.mountNamespace) &&
    scalarString(value.cgroup)
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
    !exactDevice(frame.device) ||
    !exactContainerObservation(frame.containerObservation) ||
    !(frame.lifecycle === null || exactLifecycle(frame.lifecycle)) ||
    !(frame.pid1 === null || exactPid1(frame.pid1)) ||
    !Array.isArray(frame.workers) ||
    !frame.workers.every(exactWorker) ||
    !Array.isArray(frame.descriptors) ||
    !frame.descriptors.every(plainObject) ||
    !exactMarkers(frame.markers) ||
    !exactKeys(frame.absence, ['historicalContainerAbsent', 'exact']) ||
    typeof frame.absence.historicalContainerAbsent !== 'boolean' ||
    typeof frame.absence.exact !== 'boolean' ||
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

function auditBindingsExact(audit, frames) {
  return frames.every(
    (frame) =>
      frame.auditBinding.commandReceiptIndexes.every(
        (index) => index < audit.commandReceipts.length
      ) &&
      frame.auditBinding.filesystemReceiptIndexes.every(
        (index) => index < audit.filesystemReceipts.length
      )
  );
}

function capabilityAuditExact(audit, frames) {
  if (
    !exactKeys(audit, [
      'mode',
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
    ]) ||
    audit.mode !== 'live-readonly-capability-bounded' ||
    !Array.isArray(audit.commandReceipts) ||
    !audit.commandReceipts.every(
      (receipt) => plainObject(receipt) && H044_ALLOWED_PROCESS_KEYS.includes(receipt.kind)
    ) ||
    !Array.isArray(audit.filesystemReceipts) ||
    !audit.filesystemReceipts.every(
      (receipt) => plainObject(receipt) && Object.keys(receipt).length > 0
    ) ||
    !exactKeys(audit.allowedProcessCounts, H044_ALLOWED_PROCESS_KEYS) ||
    !H044_ALLOWED_PROCESS_KEYS.every((key) =>
      nonNegativeInteger(audit.allowedProcessCounts[key])
    ) ||
    !nonNegativeInteger(audit.commandCount) ||
    !nonNegativeInteger(audit.filesystemReceiptCount)
  ) {
    return false;
  }

  const receiptCounts = Object.fromEntries(H044_ALLOWED_PROCESS_KEYS.map((key) => [key, 0]));
  for (const receipt of audit.commandReceipts) receiptCounts[receipt.kind] += 1;
  const declaredCommandCount = H044_ALLOWED_PROCESS_KEYS.reduce(
    (total, key) => total + audit.allowedProcessCounts[key],
    0
  );

  return (
    audit.commandReceipts.length === audit.commandCount &&
    audit.filesystemReceipts.length === audit.filesystemReceiptCount &&
    declaredCommandCount === audit.commandCount &&
    H044_ALLOWED_PROCESS_KEYS.every(
      (key) => receiptCounts[key] === audit.allowedProcessCounts[key]
    ) &&
    auditBindingsExact(audit, frames) &&
    audit.complete === true &&
    audit.exact === true &&
    audit.frameCount === 2 &&
    audit.lsusbCount === 1 &&
    audit.unrecordedObservationCount === 0 &&
    exactKeys(audit.prohibitedCounts, H044_PROHIBITED_COUNT_KEYS) &&
    H044_PROHIBITED_COUNT_KEYS.every(
      (key) => nonNegativeInteger(audit.prohibitedCounts[key]) && audit.prohibitedCounts[key] === 0
    )
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

function receiptFor({ historicalCandidate, frames, capabilityAudit, exposureNs }) {
  const [first, second] = frames;
  const body = {
    schemaVersion: 'overlaykit-h044-live-revalidation-receipt/v1',
    kind: 'cutoff-bound-live-readonly-revalidation',
    authority: 'none',
    action: null,
    authorizesAction: false,
    validAtCutoffOnly: true,
    revalidatedAtCutoff: true,
    requiresRevalidation: true,
    historicalCandidateTokenSha256: historicalCandidate.tokenSha256,
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
      containerObservation: clone(second.containerObservation),
      lifecycle: clone(second.lifecycle),
      pid1: clone(second.pid1),
      worker: clone(second.workers[0]),
    },
    markers: clone(second.markers),
    sources: {
      h043EvidenceSha256: historicalCandidate.sourceEvidenceSha256,
      h043PrefixSha256: historicalCandidate.prefixSha256,
      frameDigests: frames.map((frame) => frame.digestSha256),
      capabilityAuditSha256: sha256Canonical(capabilityAudit),
    },
  };
  return { ...body, receiptSha256: sha256Canonical(body) };
}

export function classifyLiveFrames({
  historicalCandidate,
  frames,
  capabilityAudit,
  sourceAdmissionExact,
} = {}) {
  const predicates = allFalsePredicates();

  try {
    predicates.sourceAdmissionExact =
      sourceAdmissionExact === true && exactHistoricalCandidate(historicalCandidate);
    if (!predicates.sourceAdmissionExact) {
      return classification(
        'inconclusive',
        'source-admission',
        'source-admission-inexact',
        predicates
      );
    }

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
          frame.containerObservation.exact === true &&
          frame.absence.exact === true
      ) && new Set(frames.map((frame) => frame.digestSha256)).size === 2;
    if (!predicates.framesComplete) {
      return classification(
        'inconclusive',
        'frame-admission',
        'incomplete-or-invalid-live-frame',
        predicates
      );
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

    if (!same(first.absence, second.absence)) {
      return classification('inconclusive', 'live-drift', 'absence-state-drift', predicates);
    }

    const deviceStable =
      first.device.present === second.device.present &&
      same(first.device.identity, second.device.identity);
    if (!deviceStable) {
      return classification('inconclusive', 'live-drift', 'device-identity-drift', predicates);
    }

    if (!same(first.containerObservation, second.containerObservation)) {
      return classification(
        'inconclusive',
        'live-drift',
        'container-or-pid1-identity-drift',
        predicates
      );
    }

    const lifecycleStable = same(first.lifecycle, second.lifecycle);
    const pid1Stable = same(first.pid1, second.pid1);
    if (!lifecycleStable || !pid1Stable) {
      return classification(
        'inconclusive',
        'live-drift',
        'container-or-pid1-identity-drift',
        predicates
      );
    }

    if (frames.some((frame) => frame.workers.length > 1)) {
      return classification('inconclusive', 'identity', 'worker-ambiguity', predicates);
    }
    if (first.workers.length !== second.workers.length) {
      return classification('inconclusive', 'identity', 'worker-presence-drift', predicates);
    }
    const workerStable = first.workers.length === 0 || same(first.workers[0], second.workers[0]);
    if (!workerStable) {
      return classification('inconclusive', 'identity', 'worker-identity-drift', predicates);
    }

    if (!same(first.descriptors, second.descriptors)) {
      return classification('inconclusive', 'live-drift', 'descriptor-state-drift', predicates);
    }

    predicates.markersStable = same(first.markers, second.markers);
    if (!predicates.markersStable) {
      return classification('inconclusive', 'live-drift', 'marker-drift', predicates);
    }

    const expectedDevice = deviceIdentityFromHistoricalCandidate(historicalCandidate);
    const expectedPid1 = pid1IdentityFromHistoricalCandidate(historicalCandidate);
    predicates.deviceExact =
      first.device.present === true &&
      second.device.present === true &&
      same(first.device.identity, expectedDevice) &&
      same(second.device.identity, expectedDevice);
    predicates.lifecycleExact =
      first.lifecycle !== null &&
      second.lifecycle !== null &&
      same(first.lifecycle, historicalCandidate.identity.lifecycle) &&
      same(second.lifecycle, historicalCandidate.identity.lifecycle);
    predicates.pid1Exact =
      first.pid1 !== null &&
      second.pid1 !== null &&
      same(first.pid1, expectedPid1) &&
      same(second.pid1, expectedPid1);
    predicates.workerUnique = first.workers.length === 1 && second.workers.length === 1;
    predicates.workerExact =
      predicates.workerUnique &&
      same(first.workers[0], historicalCandidate.identity.worker) &&
      same(second.workers[0], historicalCandidate.identity.worker);
    predicates.descriptorAbsent = first.descriptors.length === 0 && second.descriptors.length === 0;

    if (first.containerObservation.present !== !first.absence.historicalContainerAbsent) {
      return classification(
        'inconclusive',
        'contradictory-evidence',
        'container-observation-contradiction',
        predicates
      );
    }

    if (
      first.absence.historicalContainerAbsent === true ||
      first.containerObservation.present === false ||
      first.containerObservation.state !== 'running' ||
      first.device.present === false ||
      first.lifecycle === null ||
      first.pid1 === null ||
      first.workers.length === 0
    ) {
      return classification(
        'withheld',
        'not-eligible',
        first.absence.historicalContainerAbsent === true
          ? 'historical-container-absent'
          : first.containerObservation.present === false
            ? 'historical-container-absent'
            : first.containerObservation.state !== 'running'
              ? 'container-not-running'
              : first.device.present === false
                ? 'device-absent'
                : first.workers.length === 0
                  ? 'surface-worker-absent'
                  : 'container-or-pid1-absent',
        predicates
      );
    }

    if (
      !predicates.deviceExact ||
      !predicates.lifecycleExact ||
      !predicates.pid1Exact ||
      !predicates.workerExact
    ) {
      return classification(
        'withheld',
        'not-eligible',
        'historical-identity-not-current',
        predicates
      );
    }

    if (!predicates.descriptorAbsent) {
      return classification('withheld', 'not-eligible', 'current-descriptor-present', predicates);
    }

    if (!Object.values(predicates).every((value) => value === true)) {
      return classification('inconclusive', 'classification', 'predicate-gap', predicates);
    }

    return classification(
      'candidate',
      'live-readonly-revalidation',
      'cutoff-bound-candidate-revalidated',
      predicates,
      [receiptFor({ historicalCandidate, frames, capabilityAudit, exposureNs })]
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

export function classificationExactShape(value) {
  return (
    exactKeys(value, ['disposition', 'stage', 'reasonCode', 'predicates', 'receipts']) &&
    ['candidate', 'withheld', 'inconclusive'].includes(value.disposition) &&
    scalarString(value.stage) &&
    scalarString(value.reasonCode) &&
    exactKeys(value.predicates, H044_PREDICATE_KEYS) &&
    H044_PREDICATE_KEYS.every((key) => typeof value.predicates[key] === 'boolean') &&
    Array.isArray(value.receipts) &&
    value.receipts.length <= 1 &&
    (value.disposition === 'candidate'
      ? value.receipts.length === 1 &&
        value.receipts[0].authority === 'none' &&
        value.receipts[0].action === null &&
        value.receipts[0].authorizesAction === false &&
        value.receipts[0].validAtCutoffOnly === true &&
        value.receipts[0].revalidatedAtCutoff === true &&
        value.receipts[0].requiresRevalidation === true
      : value.receipts.length === 0)
  );
}
