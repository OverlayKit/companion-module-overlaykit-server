import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  EXACT_SURFACE_THREAD_CMDLINE,
  H042_PREDICATE_KEYS,
  classifyH042Outcome,
  markerDelta,
  replacementTimeline,
  rfc3339NanoToEpochNs,
  selectUniqueWorker,
} from './signal-lib.mjs';

function lifecycle() {
  return {
    pid1StartTicks: 100,
    cgroup: '0::/',
    pidNamespace: 'pid:[1]',
    mountNamespace: 'mnt:[2]',
  };
}

function worker(overrides = {}) {
  return {
    pid: 73,
    startTicks: 130,
    ppid: 1,
    parentStartTicks: 100,
    uid: 1000,
    gid: 1000,
    groups: [1000, 1002],
    command: 'node',
    cmdline: [...EXACT_SURFACE_THREAD_CMDLINE],
    cgroup: '0::/',
    pidNamespace: 'pid:[1]',
    mountNamespace: 'mnt:[2]',
    fileDescriptors: [],
    ...overrides,
  };
}

function runtime(workers, processes = workers) {
  return { lifecycle: lifecycle(), observer: { surfaceWorkers: workers, processes } };
}

function supported(overrides = {}) {
  return {
    complete: true,
    permissionBoundaryExact: true,
    hostEpochChanged: true,
    dynamicViewTracksHost: true,
    baselineAcquired: true,
    preSignalWindowComplete: true,
    preSignalNegative: true,
    signalTargetUnique: true,
    signalTargetRevalidated: true,
    exactlyOneSigterm: true,
    signalSucceeded: true,
    invocationAuditExact: true,
    topLevelLifecycleUnchanged: true,
    oldWorkerExited: true,
    replacementWorkerUnique: true,
    singleReplacementGeneration: true,
    replacementWorkerChanged: true,
    postSignalObservationComplete: true,
    postSignalDescriptorObserved: true,
    postSignalOpeningObserved: true,
    postSignalReadyObserved: true,
    postSignalMarkersOrdered: true,
    postSignalWithinDeadline: true,
    deadlineBoundaryConsistent: true,
    latePositiveObserved: false,
    ...overrides,
  };
}

test('selects only one exact SurfaceThread lineage', () => {
  const exact = worker();
  assert.equal(selectUniqueWorker(runtime([exact]), { deviceGid: 1002 }), exact);
  assert.equal(
    selectUniqueWorker(runtime([exact, worker({ pid: 74 })]), { deviceGid: 1002 }),
    null
  );
  assert.equal(
    selectUniqueWorker(runtime([worker({ cmdline: ['/app/SurfaceThread.js'] })]), {
      deviceGid: 1002,
    }),
    null
  );
});

test('tracks one replacement generation, permits A+B transition, and rejects B to C', () => {
  const old = worker();
  const b = worker({ pid: 160, startTicks: 500 });
  const c = worker({ pid: 170, startTicks: 600 });
  const transition = replacementTimeline(old, [runtime([old, b], [old, b]), runtime([b], [b])], {
    deviceGid: 1002,
  });
  assert.equal(transition.oldWorkerExited, true);
  assert.equal(transition.replacementWorkerUnique, true);
  assert.equal(transition.singleReplacementGeneration, true);
  assert.equal(transition.replacement, b);
  assert.equal(
    replacementTimeline(old, [runtime([b], [b]), runtime([c], [c])], {
      deviceGid: 1002,
    }).singleReplacementGeneration,
    false
  );
  assert.equal(
    replacementTimeline(old, [runtime([b], [b]), runtime([], [])], { deviceGid: 1002 })
      .replacementWorkerUnique,
    false
  );
});

test('compares RFC3339Nano strictly and requires ordered post-signal markers', () => {
  assert.equal(
    rfc3339NanoToEpochNs('2026-07-26T00:00:30.000000001Z') >
      rfc3339NanoToEpochNs('2026-07-26T00:00:30.000Z'),
    true
  );
  assert.equal(rfc3339NanoToEpochNs('2026-02-31T00:00:00.000000001Z'), null);
  const before = {
    relevantLines: [
      '2026-07-26T00:00:00.000000000Z old Opening surface panel: serial',
      '2026-07-26T00:00:00.010000000Z old Surface panel ready: serial',
    ],
  };
  const after = {
    relevantLines: [
      ...before.relevantLines,
      '2026-07-26T00:00:30.000000001Z new Opening surface panel: serial',
      '2026-07-26T00:00:30.000000002Z new Surface panel ready: serial',
    ],
  };
  const delta = markerDelta(before, after, '2026-07-26T00:00:30.000Z');
  assert.equal(delta.openingObserved, true);
  assert.equal(delta.readyObserved, true);
  assert.equal(delta.ordered, true);
  assert.equal(delta.allAfterSignal, true);
  const equalTimestamp = {
    relevantLines: [
      ...before.relevantLines,
      '2026-07-26T00:00:30.000000001Z new Opening surface panel: serial',
      '2026-07-26T00:00:30.000000001Z new Surface panel ready: serial',
    ],
  };
  assert.equal(markerDelta(before, equalTimestamp, '2026-07-26T00:00:30.000Z').ordered, false);
});

test('classifies each conjunctive failure stage and fails mixed evidence closed', () => {
  assert.equal(classifyH042Outcome(supported()).status, 'supported');
  assert.deepEqual(classifyH042Outcome(supported({ oldWorkerExited: false })), {
    status: 'refuted',
    stage: 'worker-termination',
    reason:
      'One exact successful SIGTERM was followed by a complete observation in which the original SurfaceThread tuple did not terminate.',
  });
  assert.equal(
    classifyH042Outcome(
      supported({ replacementWorkerUnique: false, replacementWorkerChanged: false })
    ).stage,
    'worker-respawn'
  );
  assert.equal(
    classifyH042Outcome(
      supported({
        postSignalDescriptorObserved: false,
        postSignalOpeningObserved: false,
        postSignalReadyObserved: false,
        postSignalMarkersOrdered: false,
        postSignalWithinDeadline: false,
      })
    ).status,
    'refuted'
  );
  assert.equal(
    classifyH042Outcome(supported({ postSignalReadyObserved: false })).status,
    'inconclusive'
  );
  assert.equal(
    classifyH042Outcome(supported({ latePositiveObserved: true })).status,
    'inconclusive'
  );
});

test('rejects every malformed or failed-precondition envelope', () => {
  assert.equal(classifyH042Outcome({ ...supported(), extra: true }).status, 'inconclusive');
  assert.equal(
    classifyH042Outcome(
      Object.fromEntries(
        H042_PREDICATE_KEYS.filter((key) => key !== 'signalSucceeded').map((key) => [key, true])
      )
    ).status,
    'inconclusive'
  );
  for (const key of [
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
  ]) {
    assert.equal(classifyH042Outcome(supported({ [key]: false })).status, 'inconclusive');
  }
});
