import {
  canonicalJson,
  canonicalPrefixReceiptsExact,
  exactKeys,
  parseJsonLines,
  prefixManifest,
  prefixShapeExact,
  sha256,
  sha256Canonical,
  sourceDescriptorExact,
} from './prefix-lib.mjs';

export const H043_PREDICATE_KEYS = Object.freeze([
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

export const H043_CLAIM_BOUNDARY = Object.freeze({
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

export const H043_SIDE_EFFECT_AUDIT = Object.freeze({
  mode: 'offline-archived-evidence-only',
  commands: Object.freeze([]),
  commandCount: 0,
  hostObservationCount: 0,
  dockerCount: 0,
  networkCount: 0,
  processCount: 0,
  sysfsCount: 0,
  deviceOpenCount: 0,
  deviceReadCount: 0,
  deviceWriteCount: 0,
  signalCount: 0,
  mutationCount: 0,
  passed: true,
});

const FULL_WORKER_KEYS = Object.freeze([
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

function clone(value) {
  return structuredClone(value);
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function monotonic(value) {
  if (typeof value !== 'string' || !/^[0-9]+$/u.test(value)) {
    throw new TypeError('invalid monotonic nanosecond value');
  }
  return BigInt(value);
}

function allFalsePredicates() {
  return Object.fromEntries(H043_PREDICATE_KEYS.map((key) => [key, false]));
}

function fullWorker(worker) {
  return Object.fromEntries(FULL_WORKER_KEYS.map((key) => [key, clone(worker?.[key])]));
}

function lifecycleIdentity(lifecycle) {
  return Object.fromEntries(LIFECYCLE_KEYS.map((key) => [key, clone(lifecycle?.[key])]));
}

function statIdentity(value) {
  if (!value) return null;
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
  const usb = snapshot?.usb?.filter(
    (entry) =>
      entry.serial === serial &&
      entry.vendorId === '0fd9' &&
      entry.productId === '0080' &&
      entry.serialMatches === true
  );
  const hidraw = snapshot?.hidraw?.filter(
    (entry) =>
      entry.serialMatches === true &&
      entry.hid?.unique === serial &&
      entry.hid?.id === '0003:00000FD9:00000080' &&
      entry.usbAncestor?.serial === serial &&
      entry.usbAncestor?.vendorId === '0fd9' &&
      entry.usbAncestor?.productId === '0080'
  );
  if (usb?.length !== 1 || hidraw?.length !== 1) return null;
  return { usb: usb[0], hidraw: hidraw[0] };
}

function epochIdentity(target) {
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
    descriptor?.stat &&
    stat &&
    descriptor.stat.inode === stat.inode &&
    descriptor.stat.rdev === stat.rdev &&
    descriptor.stat.major === stat.major &&
    descriptor.stat.minor === stat.minor &&
    descriptor.stat.isCharacterDevice === true
  );
}

function markersEqual(left, right) {
  return (
    left?.opening === right?.opening &&
    left?.ready === right?.ready &&
    left?.openFailed === right?.openFailed &&
    same(left?.relevantLines, right?.relevantLines)
  );
}

function observationAnchorExact(entries, snapshot) {
  if (!snapshot || typeof snapshot.monotonicNs !== 'string') return false;
  const matches = entries.filter((entry) => entry.monotonicNs === snapshot.monotonicNs);
  return matches.length === 1 && same(matches[0], snapshot);
}

function observationAnchorsExact(observations, runtimeEntries, hostEntries) {
  return (
    observationAnchorExact(hostEntries, observations.preSignal?.host) &&
    observationAnchorExact(runtimeEntries, observations.preSignal?.runtime)
  );
}

function internalRawExact(prefix) {
  const runtime = prefix.raw?.runtimePoll;
  const host = prefix.raw?.hostPoll;
  const audit = prefix.raw?.invocationAudit;
  const logs = prefix.raw?.logs;
  return (
    typeof runtime?.text === 'string' &&
    parseJsonLines(runtime.text, 'H-043 runtime prefix').length === runtime.lineCount &&
    sha256(runtime.text) === runtime.sha256 &&
    typeof host?.text === 'string' &&
    parseJsonLines(host.text, 'H-043 host prefix').length === host.lineCount &&
    sha256(host.text) === host.sha256 &&
    Array.isArray(prefix.context?.invocationAuditPrefix) &&
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

function auditSafe(entries) {
  const allowed = new Set([
    'docker-run',
    'physical-disconnect-window',
    'physical-reconnect-window',
    'docker-exec-observer',
    'docker-logs',
    'docker-inspect',
  ]);
  return (
    entries.every((entry) => allowed.has(entry.kind)) &&
    entries.every(
      (entry) =>
        entry.kind !== 'docker-exec-signal' &&
        entry.kind !== 'docker-stop' &&
        !/restart|recreate|rescan|fault-injection/u.test(`${entry.kind}:${entry.phase}`)
    )
  );
}

function prefixBoundary(prefix, runtimeEntries, hostEntries) {
  const cutoff = monotonic(prefix.cutoffMonotonicNs);
  const runtimeTimes = runtimeEntries.map((entry) => monotonic(entry.monotonicNs));
  const hostTimes = hostEntries.map((entry) => monotonic(entry.monotonicNs));
  const auditTimes = prefix.context.invocationAuditPrefix.map((entry) =>
    monotonic(entry.monotonicNs)
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

function lifecycleUnchanged(prefix, runtimeEntries) {
  const expected = lifecycleIdentity(prefix.context.companion.initialLifecycle);
  const declared = [
    prefix.context.companion.absentLifecycle,
    prefix.context.companion.preSignalLifecycle,
  ];
  return (
    exactKeys(expected, LIFECYCLE_KEYS) &&
    declared.every((entry) => same(lifecycleIdentity(entry), expected)) &&
    runtimeEntries.every((entry) => same(lifecycleIdentity(entry.lifecycle), expected))
  );
}

function auditExact(entries, runtimeEntries) {
  const counts = entries.reduce((result, entry) => {
    result[entry.kind] = (result[entry.kind] ?? 0) + 1;
    return result;
  }, {});
  const observationCount = runtimeEntries.length;
  return (
    auditSafe(entries) &&
    counts['docker-run'] === 1 &&
    counts['physical-disconnect-window'] === 1 &&
    counts['physical-reconnect-window'] === 1 &&
    counts['docker-exec-observer'] === observationCount &&
    counts['docker-logs'] === observationCount &&
    counts['docker-inspect'] === observationCount * 2
  );
}

function derive(prefix) {
  const runtimeEntries = parseJsonLines(prefix.raw.runtimePoll.text, 'H-043 runtime prefix');
  const hostEntries = parseJsonLines(prefix.raw.hostPoll.text, 'H-043 host prefix');
  const observations = prefix.context.observations;
  const serial = prefix.context.device.serial;
  const initialTarget = exactTarget(observations.initial.host, serial);
  const returnedTarget = exactTarget(observations.returned.host, serial);
  const finalTarget = exactTarget(observations.preSignal.host, serial);
  const initialEpoch = epochIdentity(initialTarget);
  const returnedEpoch = epochIdentity(returnedTarget);
  const finalEpoch = epochIdentity(finalTarget);
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
    initialEpoch.stat?.inode !== returnedEpoch.stat?.inode &&
    initialEpoch.stat?.rdev === returnedEpoch.stat?.rdev;

  const returnedDeviceExact =
    finalEpoch !== null &&
    same(returnedEpoch, finalEpoch) &&
    observations.returned.host.state === 'present' &&
    observations.preSignal.host.state === 'present' &&
    observations.returned.host.scope?.bootId === observations.preSignal.host.scope?.bootId &&
    observations.returned.host.scope?.mountNamespace ===
      observations.preSignal.host.scope?.mountNamespace;

  const window = prefix.context.windows.preSignal;
  const started = monotonic(window.startedMonotonicNs);
  const deadline = started + 30_000_000_000n;
  const completed = monotonic(window.completedMonotonicNs);
  const baselineAcquiredAt = monotonic(observations.initial.runtime.monotonicNs);
  const admittedRuntimeEntries = runtimeEntries.filter(
    (entry) => monotonic(entry.monotonicNs) >= baselineAcquiredAt
  );
  const afterReturn = runtimeEntries.filter((entry) => monotonic(entry.monotonicNs) >= started);
  const beforeDeadline = afterReturn.filter((entry) => monotonic(entry.monotonicNs) < deadline);
  const atOrAfterDeadline = afterReturn.filter((entry) => monotonic(entry.monotonicNs) >= deadline);
  const boundaryRuntime = atOrAfterDeadline[0] ?? null;
  const negativeWindowComplete =
    window.timeoutSeconds === 30 &&
    window.deadlineExpired === true &&
    window.boundaryNegative === true &&
    completed >= deadline &&
    beforeDeadline.length > 0 &&
    boundaryRuntime !== null &&
    boundaryRuntime.observer?.surfaceWorkers?.length === 1 &&
    boundaryRuntime.observer.surfaceWorkers[0].fileDescriptors?.every(
      (descriptor) => !descriptorMatches(descriptor, returnedEpoch?.stat)
    ) &&
    markersEqual(boundaryRuntime.markers, observations.initial.runtime.markers);

  const workers = admittedRuntimeEntries.map((entry) => entry.observer?.surfaceWorkers);
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
  const markersStable = admittedRuntimeEntries.every((entry) =>
    markersEqual(entry.markers, initialMarkers)
  );
  const topLevelLifecycleUnchanged = lifecycleUnchanged(prefix, runtimeEntries);
  const finalRuntime = runtimeEntries.at(-1);
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
    monotonic(finalRuntime.monotonicNs) < monotonic(observations.preSignal.host.monotonicNs) &&
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

  const historicalAuditExact = auditExact(prefix.context.invocationAuditPrefix, runtimeEntries);
  const observationReceiptsExact = observationAnchorsExact(
    observations,
    runtimeEntries,
    hostEntries
  );
  const sourceAdmissionExact =
    sourceDescriptorExact(prefix) &&
    canonicalPrefixReceiptsExact(prefix) &&
    prefix.context.collector?.sourceStable === true;
  const prefixBoundaryExact =
    prefixShapeExact(prefix) &&
    internalRawExact(prefix) &&
    prefixBoundary(prefix, runtimeEntries, hostEntries) &&
    observationReceiptsExact &&
    preSignalSummaryCoherent;
  const sourceLineageExact =
    sourceDescriptorExact(prefix) && prefix.context.collector?.sourceStable === true;
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
    monotonic(prefix.cutoffMonotonicNs) < deadline &&
    completed <= monotonic(prefix.cutoffMonotonicNs) &&
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
    runtimeEntries,
    hostEntries,
    observations,
    serial,
    initialEpoch,
    returnedEpoch,
    finalEpoch,
    window: {
      startedMonotonicNs: window.startedMonotonicNs,
      deadlineMonotonicNs: deadline.toString(),
      completedMonotonicNs: window.completedMonotonicNs,
      boundaryPollMonotonicNs: boundaryRuntime?.monotonicNs ?? null,
      revalidationMonotonicNs: finalRuntime?.monotonicNs ?? null,
      cutoffMonotonicNs: prefix.cutoffMonotonicNs,
    },
    initialWorker,
    lifecycle: lifecycleIdentity(prefix.context.companion.preSignalLifecycle),
    structuralAdmissionExact,
    exactFinalAbsence,
    windowOpenCoherent,
    descriptorObserved: descriptorObserved === true,
    openingDelta,
    readyDelta,
    predicates,
  };
}

export function buildCandidateToken({
  sourceEvidenceSha256,
  prefixSha256,
  device,
  lifecycle,
  worker,
  window,
}) {
  return sha256Canonical({
    schemaVersion: 'overlaykit-h043-candidate-token/v1',
    sourceEvidenceSha256,
    prefixSha256,
    device,
    lifecycle,
    worker,
    window,
  });
}

function candidateFor(prefix, derived) {
  const manifest = prefixManifest(prefix);
  const identity = {
    device: {
      serial: derived.serial,
      vendorId: prefix.context.device.vendorId,
      productId: prefix.context.device.productId,
      initialEpoch: derived.initialEpoch,
      returnedEpoch: derived.returnedEpoch,
      revalidationEpoch: derived.finalEpoch,
    },
    lifecycle: derived.lifecycle,
    worker: derived.initialWorker,
  };
  const tokenSha256 = buildCandidateToken({
    sourceEvidenceSha256: prefix.source.h042EvidenceSha256,
    prefixSha256: manifest.prefixSha256,
    device: identity.device,
    lifecycle: identity.lifecycle,
    worker: identity.worker,
    window: derived.window,
  });
  return {
    kind: 'revalidation-required',
    historical: true,
    requiresRevalidation: true,
    authority: 'none',
    action: null,
    observedCutoff: {
      at: prefix.context.observations.preSignal.host.capturedAt,
      monotonicNs: prefix.cutoffMonotonicNs,
    },
    sourceEvidenceSha256: prefix.source.h042EvidenceSha256,
    prefixSha256: manifest.prefixSha256,
    identity,
    window: clone(derived.window),
    tokenSha256,
  };
}

function result(disposition, stage, reasonCode, predicates, candidates = []) {
  return { disposition, stage, reasonCode, predicates, candidates };
}

export function classifyPrefix(prefix) {
  try {
    if (!prefixShapeExact(prefix) || !internalRawExact(prefix)) {
      return result('inconclusive', 'source-admission', 'malformed-prefix', allFalsePredicates());
    }

    const derived = derive(prefix);
    const { predicates } = derived;
    if (!derived.structuralAdmissionExact) {
      return result(
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
      return result('inconclusive', 'identity', 'identity-ambiguity-or-drift', predicates);
    }

    if (!predicates.usbEpochExact) {
      return result(
        'inconclusive',
        'contradictory-evidence',
        'device-epoch-or-node-mismatch',
        predicates
      );
    }

    if (derived.exactFinalAbsence) {
      return result('withheld', 'not-eligible', 'device-absent-at-cutoff', predicates);
    }

    if (!predicates.returnedDeviceExact) {
      return result(
        'inconclusive',
        'contradictory-evidence',
        'device-epoch-or-node-mismatch',
        predicates
      );
    }

    const elapsed =
      monotonic(prefix.context.windows.preSignal.completedMonotonicNs) -
      monotonic(prefix.context.windows.preSignal.startedMonotonicNs);
    if (elapsed < 0n) {
      return result(
        'inconclusive',
        'prefix-boundary',
        'incomplete-or-contradictory-boundary',
        predicates
      );
    }
    if (elapsed < 30_000_000_000n) {
      return derived.windowOpenCoherent
        ? result('withheld', 'not-eligible', 'negative-window-open', predicates)
        : result(
            'inconclusive',
            'prefix-boundary',
            'incomplete-or-contradictory-boundary',
            predicates
          );
    }

    if (derived.descriptorObserved || (derived.openingDelta > 0 && derived.readyDelta > 0)) {
      return result('withheld', 'not-eligible', 'automatic-reacquisition-observed', predicates);
    }
    if (derived.openingDelta !== 0 || derived.readyDelta !== 0) {
      return result(
        'inconclusive',
        'contradictory-evidence',
        'partial-or-mixed-reacquisition',
        predicates
      );
    }
    if (!predicates.negativeWindowComplete || !predicates.prefixBoundaryExact) {
      return result(
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
      return result(
        'inconclusive',
        'source-admission',
        'untrusted-or-contradictory-prefix',
        predicates
      );
    }

    if (!Object.values(predicates).every((value) => value === true)) {
      return result('inconclusive', 'classification', 'predicate-gap', predicates);
    }

    return result(
      'candidate',
      'historical-worker-candidate',
      'revalidation-required-worker-candidate',
      predicates,
      [candidateFor(prefix, derived)]
    );
  } catch {
    return result('inconclusive', 'source-admission', 'malformed-prefix', allFalsePredicates());
  }
}

export function classificationExactShape(classification) {
  return (
    exactKeys(classification, ['disposition', 'stage', 'reasonCode', 'predicates', 'candidates']) &&
    ['candidate', 'withheld', 'inconclusive'].includes(classification.disposition) &&
    exactKeys(classification.predicates, H043_PREDICATE_KEYS) &&
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
