import { randomBytes } from 'node:crypto';

export const PRE_SIGNAL_SECONDS = 30;
export const POST_SIGNAL_SECONDS = 30;

export const EXACT_SURFACE_THREAD_CMDLINE = Object.freeze([
  '/app/node-runtimes/node22/bin/node',
  '--enable-source-maps',
  '/app/SurfaceThread.js',
]);

export const H042_CLAIM_BOUNDARY = Object.freeze({
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

export const H042_PREDICATE_KEYS = Object.freeze([
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

const PRECONDITION_KEYS = Object.freeze([
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
]);

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

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, keys) {
  return (
    isPlainRecord(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function exactArray(left, right) {
  return (
    Array.isArray(left) &&
    Array.isArray(right) &&
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

export function runId() {
  return `h042-${new Date().toISOString().replaceAll(/[:.]/gu, '-')}-${randomBytes(4).toString('hex')}`;
}

export function exactWorkerIdentity(worker) {
  if (!isPlainRecord(worker)) return null;
  const identity = Object.fromEntries(WORKER_IDENTITY_KEYS.map((key) => [key, worker[key]]));
  if (
    !Number.isSafeInteger(identity.pid) ||
    identity.pid <= 1 ||
    !Number.isSafeInteger(identity.startTicks) ||
    identity.startTicks <= 0 ||
    !Number.isSafeInteger(identity.ppid) ||
    identity.ppid !== 1 ||
    !Number.isSafeInteger(identity.parentStartTicks) ||
    identity.parentStartTicks <= 0 ||
    !Number.isSafeInteger(identity.uid) ||
    !Number.isSafeInteger(identity.gid) ||
    !Array.isArray(identity.groups) ||
    identity.groups.some((group) => !Number.isSafeInteger(group) || group < 0) ||
    !exactArray(identity.cmdline, EXACT_SURFACE_THREAD_CMDLINE) ||
    typeof identity.cgroup !== 'string' ||
    typeof identity.pidNamespace !== 'string' ||
    typeof identity.mountNamespace !== 'string'
  ) {
    return null;
  }
  return identity;
}

export function workerMatchesBoundary(worker, { lifecycle, deviceGid }) {
  const identity = exactWorkerIdentity(worker);
  return (
    identity !== null &&
    isPlainRecord(lifecycle) &&
    Number.isSafeInteger(deviceGid) &&
    deviceGid > 0 &&
    identity.parentStartTicks === lifecycle.pid1StartTicks &&
    identity.uid === 1000 &&
    identity.gid === 1000 &&
    exactArray(
      [...identity.groups].sort((left, right) => left - right),
      [1000, deviceGid]
    ) &&
    identity.cgroup === lifecycle.cgroup &&
    identity.pidNamespace === lifecycle.pidNamespace &&
    identity.mountNamespace === lifecycle.mountNamespace
  );
}

export function sameWorker(left, right) {
  const first = exactWorkerIdentity(left);
  const second = exactWorkerIdentity(right);
  return (
    first !== null &&
    second !== null &&
    first.pid === second.pid &&
    first.startTicks === second.startTicks &&
    WORKER_IDENTITY_KEYS.every((key) => {
      if (key === 'groups' || key === 'cmdline') return exactArray(first[key], second[key]);
      return first[key] === second[key];
    })
  );
}

export function selectUniqueWorker(runtime, boundary) {
  const workers = runtime?.observer?.surfaceWorkers;
  if (!Array.isArray(workers) || workers.length !== 1) return null;
  return workerMatchesBoundary(workers[0], {
    lifecycle: runtime.lifecycle,
    deviceGid: boundary.deviceGid,
  })
    ? workers[0]
    : null;
}

export function replacementObservation(oldWorker, runtime, boundary) {
  const oldIdentity = exactWorkerIdentity(oldWorker);
  const replacement = selectUniqueWorker(runtime, boundary);
  const processes = runtime?.observer?.processes;
  if (oldIdentity === null || !Array.isArray(processes)) {
    return {
      oldWorkerExited: false,
      replacementWorkerUnique: false,
      replacementWorkerChanged: false,
      replacement: null,
    };
  }
  const oldWorkerExited = !processes.some(
    (process_) =>
      process_?.pid === oldIdentity.pid && process_?.startTicks === oldIdentity.startTicks
  );
  return {
    oldWorkerExited,
    replacementWorkerUnique: replacement !== null,
    replacementWorkerChanged:
      replacement !== null &&
      oldWorkerExited &&
      (replacement.pid !== oldIdentity.pid || replacement.startTicks !== oldIdentity.startTicks),
    replacement,
  };
}

export function replacementTimeline(oldWorker, runtimes, boundary) {
  const oldIdentity = exactWorkerIdentity(oldWorker);
  if (oldIdentity === null || !Array.isArray(runtimes) || runtimes.length === 0) {
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
  let ambiguousPoll = false;
  const replacements = new Map();
  for (const runtime of runtimes) {
    const processes = runtime?.observer?.processes;
    const workers = runtime?.observer?.surfaceWorkers;
    if (!Array.isArray(processes) || !Array.isArray(workers)) {
      ambiguousPoll = true;
      continue;
    }
    const oldPresent = processes.some(
      (process_) =>
        process_?.pid === oldIdentity.pid && process_?.startTicks === oldIdentity.startTicks
    );
    if (!oldPresent) oldWorkerExited = true;
    else if (oldWorkerExited) oldReappeared = true;
    for (const candidate of workers) {
      if (sameWorker(oldIdentity, candidate)) continue;
      if (
        !workerMatchesBoundary(candidate, {
          lifecycle: runtime.lifecycle,
          deviceGid: boundary.deviceGid,
        })
      ) {
        ambiguousPoll = true;
        continue;
      }
      const identity = exactWorkerIdentity(candidate);
      replacements.set(`${identity.pid}:${identity.startTicks}`, candidate);
    }
  }
  const finalRuntime = runtimes.at(-1);
  const finalWorkers = finalRuntime?.observer?.surfaceWorkers;
  const finalReplacement =
    Array.isArray(finalWorkers) &&
    finalWorkers.length === 1 &&
    !sameWorker(oldIdentity, finalWorkers[0]) &&
    workerMatchesBoundary(finalWorkers[0], {
      lifecycle: finalRuntime.lifecycle,
      deviceGid: boundary.deviceGid,
    })
      ? finalWorkers[0]
      : null;
  const singleReplacementGeneration = !ambiguousPoll && !oldReappeared && replacements.size <= 1;
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
      !sameWorker(oldIdentity, replacement),
    replacement,
  };
}

export function rfc3339NanoToEpochNs(value) {
  if (typeof value !== 'string') return null;
  const match =
    /^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z$/u.exec(value);
  if (!match || Number(match[2]) > 59) return null;
  const wholeSeconds = `${match[1]}:${match[2]}`;
  const epochMilliseconds = Date.parse(`${wholeSeconds}Z`);
  if (!Number.isFinite(epochMilliseconds)) return null;
  if (new Date(epochMilliseconds).toISOString().slice(0, 19) !== wholeSeconds) return null;
  const fraction = (match[3] ?? '').padEnd(9, '0');
  return BigInt(epochMilliseconds) * 1_000_000n + BigInt(fraction || '0');
}

function dockerTimestamp(line) {
  if (typeof line !== 'string') return null;
  const separator = line.indexOf(' ');
  if (separator <= 0) return null;
  const value = line.slice(0, separator);
  const nanoseconds = rfc3339NanoToEpochNs(value);
  return nanoseconds === null ? null : { value, nanoseconds };
}

export function markerDelta(before, after, signalReceivedAt) {
  const beforeLines = before?.relevantLines;
  const afterLines = after?.relevantLines;
  const receivedNs = rfc3339NanoToEpochNs(signalReceivedAt);
  if (
    !Array.isArray(beforeLines) ||
    !Array.isArray(afterLines) ||
    receivedNs === null ||
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
    timestamp: dockerTimestamp(line),
    opening: line.includes('Opening surface panel:'),
    ready: line.includes('Surface panel ready:'),
  }));
  const opening = events.find((entry) => entry.opening);
  const ready = events.find(
    (entry) => entry.ready && opening !== undefined && entry.index > opening.index
  );
  const relevant = events.filter((entry) => entry.opening || entry.ready);
  const allAfterSignal =
    relevant.length > 0 &&
    relevant.every((entry) => entry.timestamp !== null && entry.timestamp.nanoseconds > receivedNs);
  return {
    prefixValid: true,
    openingObserved: opening !== undefined,
    readyObserved: ready !== undefined,
    ordered:
      opening !== undefined &&
      ready !== undefined &&
      opening.index < ready.index &&
      opening.timestamp !== null &&
      ready.timestamp !== null &&
      opening.timestamp.nanoseconds < ready.timestamp.nanoseconds,
    allAfterSignal,
    lines,
  };
}

export function classifyH042Outcome(predicates) {
  if (
    !exactKeys(predicates, H042_PREDICATE_KEYS) ||
    H042_PREDICATE_KEYS.some((key) => typeof predicates[key] !== 'boolean')
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
