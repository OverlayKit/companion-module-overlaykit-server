import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { H042_CLAIM_BOUNDARY } from './signal-lib.mjs';
import {
  INDEPENDENT_CLAIM_BOUNDARY,
  PREDICATE_KEYS,
  REQUIRED_SOURCE_PATHS,
  analyzeCleanupDockerEvents,
  analyzeExperimentDockerEvents,
  classifyOutcomeIndependent,
  exactPresentHostTuple,
  parseDockerEventLines,
  recomputeMarkerDelta,
  reconstructReplacementTimeline,
  rfc3339NanoToEpochNs,
  verifySignalReceipt,
} from './verify.mjs';

const CONTAINER_ID = 'a'.repeat(64);
const HEALTHCHECK = 'sh -c curl -fSsq http://localhost:${COMPANION_ADMIN_PORT:-8000}/';
const OBSERVER = '/app/node-runtimes/main/bin/node /h041-container-observer.mjs';
const HELPER = '/app/node-runtimes/main/bin/node /h042-signal-helper.mjs';
const BASE = rfc3339NanoToEpochNs('2026-07-26T01:00:00.000Z');
const H041 = JSON.parse(
  readFileSync(
    new URL('../../artifacts/h041/h041-2026-07-26T00-56-42-118Z-0423725f/run.json', import.meta.url)
  )
);
const H042_SCHEMA = JSON.parse(
  readFileSync(new URL('./schemas/surface-worker-recycle-run.schema.json', import.meta.url), 'utf8')
);

function rawEvent(action, offsetNs, attributes = {}, id = CONTAINER_ID) {
  const timeNano = (BASE + BigInt(offsetNs)).toString();
  const encoded = JSON.stringify({
    Type: 'container',
    Action: action,
    status: action,
    id,
    time: Number(BigInt(timeNano) / 1_000_000_000n),
    timeNano: '__TIME_NANO__',
    Actor: { ID: id, Attributes: attributes },
  });
  return encoded.replace('"__TIME_NANO__"', timeNano);
}

function execTriplet(command, execId, offsetMs) {
  return [
    rawEvent(`exec_create: ${command}`, BigInt(offsetMs) * 1_000_000n, { execID: execId }),
    rawEvent(`exec_start: ${command}`, BigInt(offsetMs) * 1_000_000n + 100_000n, {
      execID: execId,
    }),
    rawEvent('exec_die', BigInt(offsetMs) * 1_000_000n + 200_000n, {
      execID: execId,
      exitCode: '0',
    }),
  ];
}

function experimentText() {
  return (
    [
      rawEvent('create', 1_000_000n),
      rawEvent('start', 2_000_000n),
      ...execTriplet(OBSERVER, 'observer-1', 3),
      ...execTriplet(HEALTHCHECK, 'health-1', 6),
      rawEvent(`exec_create: ${HELPER}`, 9_000_000n, { execID: 'helper-1' }),
      rawEvent(`exec_start: ${HELPER}`, 9_500_000n, { execID: 'helper-1' }),
      rawEvent('exec_die', 12_000_000n, {
        execID: 'helper-1',
        exitCode: '0',
      }),
      rawEvent('health_status: healthy', 13_000_000n),
    ].join('\n') + '\n'
  );
}

function cleanupText() {
  return (
    [
      ...execTriplet(HEALTHCHECK, 'health-gap', 21),
      rawEvent('health_status: healthy', 24_000_000n),
      rawEvent('kill', 40_000_000n, { signal: '15' }),
      rawEvent('kill', 5_040_000_000n, { signal: '9' }),
      rawEvent('stop', 5_041_000_000n),
      rawEvent('die', 5_042_000_000n, { exitCode: '137' }),
      rawEvent('destroy', 5_043_000_000n),
    ].join('\n') + '\n'
  );
}

function worker(pid, startTicks, lifecycle) {
  return {
    pid,
    startTicks,
    ppid: 1,
    parentStartTicks: lifecycle.pid1StartTicks,
    uid: 1000,
    gid: 1000,
    groups: [1000, 1002],
    command: 'node',
    cmdline: [
      '/app/node-runtimes/node22/bin/node',
      '--enable-source-maps',
      '/app/SurfaceThread.js',
    ],
    cgroup: lifecycle.cgroup,
    pidNamespace: lifecycle.pidNamespace,
    mountNamespace: lifecycle.mountNamespace,
    fileDescriptors: [],
  };
}

function runtime(workers, processes, lifecycle) {
  return {
    lifecycle,
    observer: {
      surfaceWorkers: workers,
      processes,
    },
  };
}

function signalFixture() {
  const lifecycle = {
    pid1StartTicks: 50,
    cgroup: '0::/',
    pidNamespace: 'pid:[1]',
    mountNamespace: 'mnt:[2]',
  };
  const oldWorker = worker(73, 100, lifecycle);
  const target = Object.fromEntries(
    [
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
    ].map((key) => [key, oldWorker[key]])
  );
  const tuple = {
    pid: target.pid,
    startTicks: target.startTicks,
    ppid: target.ppid,
    parentStartTicks: target.parentStartTicks,
  };
  const receipt = {
    schemaVersion: 'overlaykit-h042-signal-receipt/v1',
    signal: 'SIGTERM',
    processKillCallCount: 99,
    startedAt: '2026-07-26T01:00:00.010Z',
    startedMonotonicNs: '110',
    receivedAt: '2026-07-26T01:00:00.010Z',
    receivedMonotonicNs: '120',
    expected: structuredClone(target),
    observed: {
      ...structuredClone(target),
      targetHidrawDescriptors: [],
      revalidation: {
        initial: structuredClone(tuple),
        final: structuredClone(tuple),
      },
    },
  };
  const signal = {
    command: ['/app/node-runtimes/main/bin/node', '/h042-signal-helper.mjs'],
    user: '1000:1000',
    target: structuredClone(target),
    startedAt: receipt.startedAt,
    startedMonotonicNs: receipt.startedMonotonicNs,
    receivedAt: receipt.receivedAt,
    receivedMonotonicNs: receipt.receivedMonotonicNs,
    exitCode: 0,
    receipt,
  };
  const receiptText = `${JSON.stringify(receipt)}\n`;
  const signalAudit = {
    signal: 'SIGTERM',
    user: '1000:1000',
    exitCode: 0,
    command: structuredClone(signal.command),
    processTarget: structuredClone(target),
    receiptSha256: null,
  };
  return { lifecycle, oldWorker, target, receipt, signal, receiptText, signalAudit };
}

test('freezes an independent exact source closure including both change contracts', () => {
  assert.equal(
    REQUIRED_SOURCE_PATHS.includes('.overlaykit/governance/changes/CHG-0012.json'),
    true
  );
  assert.equal(
    REQUIRED_SOURCE_PATHS.includes('.overlaykit/governance/changes/CHG-0013.json'),
    true
  );
  assert.deepEqual(REQUIRED_SOURCE_PATHS, [...REQUIRED_SOURCE_PATHS].sort());
  assert.equal(new Set(REQUIRED_SOURCE_PATHS).size, REQUIRED_SOURCE_PATHS.length);
});

test('triple-locks the producer, independent verifier, and schema claim boundaries', () => {
  const schemaDefinition = H042_SCHEMA.properties.claimBoundary;
  const schemaBoundary = Object.fromEntries(
    ['proves', 'excludes'].map((key) => [
      key,
      schemaDefinition.properties[key].prefixItems.map((entry) => entry.const),
    ])
  );

  assert.notStrictEqual(INDEPENDENT_CLAIM_BOUNDARY, H042_CLAIM_BOUNDARY);
  assert.notStrictEqual(INDEPENDENT_CLAIM_BOUNDARY.proves, H042_CLAIM_BOUNDARY.proves);
  assert.notStrictEqual(INDEPENDENT_CLAIM_BOUNDARY.excludes, H042_CLAIM_BOUNDARY.excludes);
  assert.deepEqual(H042_CLAIM_BOUNDARY, schemaBoundary);
  assert.deepEqual(INDEPENDENT_CLAIM_BOUNDARY, schemaBoundary);
});

test('accepts the real H-041 host HID shape and rejects identity drift', () => {
  const snapshot = structuredClone(H041.observations.preflight.host);
  const serial = H041.device.serial;
  const node = snapshot.hidraw.find((entry) => entry.serialMatches);
  const inventoryNode = H041.device.initialInventory.find((entry) => entry.hid?.unique === serial);

  assert.equal(Object.hasOwn(node.hid, 'vendorId'), false);
  assert.equal(Object.hasOwn(node.hid, 'productId'), false);
  assert.equal(inventoryNode.hid.vendorId, '0fd9');
  assert.equal(inventoryNode.hid.productId, '0080');
  assert.equal(exactPresentHostTuple(snapshot, serial, 'real H-041 host').node, node);

  for (const mutate of [
    (candidate) => {
      candidate.hidraw[0].hid.id = '0003:00000FD9:00000081';
    },
    (candidate) => {
      candidate.hidraw[0].hid.unique = 'ANOTHER-SERIAL';
    },
    (candidate) => {
      candidate.hidraw[0].usbAncestor.vendorId = 'ffff';
    },
    (candidate) => {
      candidate.hidraw[0].usbAncestor.productId = 'ffff';
    },
    (candidate) => {
      candidate.hidraw[0].usbAncestor.serial = 'ANOTHER-SERIAL';
    },
  ]) {
    const candidate = structuredClone(snapshot);
    mutate(candidate);
    assert.throws(
      () => exactPresentHostTuple(candidate, serial, 'mutated H-041 host'),
      /lacks one exact MK\.2 tuple/u
    );
  }
});

test('preserves raw timeNano above Number.MAX_SAFE_INTEGER and binds known exec triples', () => {
  const events = parseDockerEventLines(experimentText());
  assert.equal(events[0].timeNano, (BASE + 1_000_000n).toString());
  const analysis = analyzeExperimentDockerEvents(events, {
    containerId: CONTAINER_ID,
    expectedObserverExecCount: 1,
    signalStartedAt: '2026-07-26T01:00:00.010Z',
    signalReceivedAt: '2026-07-26T01:00:00.011Z',
    experimentStartedAt: '2026-07-26T01:00:00.000Z',
    experimentBoundaryAt: '2026-07-26T01:00:00.020Z',
  });
  assert.equal(analysis.passed, true);
  assert.equal(analysis.healthcheckExecCount, 1);
  assert.equal(analysis.execId, 'helper-1');
});

test('rejects quoted timeNano, unknown exec commands, wrong IDs, and incomplete healthchecks', () => {
  const quoted = experimentText().replace(/"timeNano":([0-9]+)/u, '"timeNano":"$1"');
  assert.throws(() => parseDockerEventLines(quoted), /raw numeric timeNano/u);

  const unknown = experimentText().replace(OBSERVER, '/bin/sh -c surprise');
  assert.throws(
    () =>
      analyzeExperimentDockerEvents(parseDockerEventLines(unknown), {
        containerId: CONTAINER_ID,
        expectedObserverExecCount: 1,
        signalStartedAt: '2026-07-26T01:00:00.010Z',
        signalReceivedAt: '2026-07-26T01:00:00.011Z',
        experimentStartedAt: '2026-07-26T01:00:00.000Z',
        experimentBoundaryAt: '2026-07-26T01:00:00.020Z',
      }),
    /unknown or duplicate exec_create/u
  );

  const wrongId = experimentText().replace(
    '"execID":"helper-1","exitCode":"0"',
    '"execID":"helper-2","exitCode":"0"'
  );
  assert.throws(
    () =>
      analyzeExperimentDockerEvents(parseDockerEventLines(wrongId), {
        containerId: CONTAINER_ID,
        expectedObserverExecCount: 1,
        signalStartedAt: '2026-07-26T01:00:00.010Z',
        signalReceivedAt: '2026-07-26T01:00:00.011Z',
        experimentStartedAt: '2026-07-26T01:00:00.000Z',
        experimentBoundaryAt: '2026-07-26T01:00:00.020Z',
      }),
    /incomplete|orphan/u
  );

  const incomplete = experimentText()
    .split('\n')
    .filter((line) => !(line.includes('"Action":"exec_die"') && line.includes('health-1')))
    .join('\n');
  assert.throws(
    () =>
      analyzeExperimentDockerEvents(parseDockerEventLines(incomplete), {
        containerId: CONTAINER_ID,
        expectedObserverExecCount: 1,
        signalStartedAt: '2026-07-26T01:00:00.010Z',
        signalReceivedAt: '2026-07-26T01:00:00.011Z',
        experimentStartedAt: '2026-07-26T01:00:00.000Z',
        experimentBoundaryAt: '2026-07-26T01:00:00.020Z',
      }),
    /incomplete|orphan/u
  );
});

test('requires exact cleanup partition, kill order, exit 137, and scope', () => {
  const options = {
    containerId: CONTAINER_ID,
    experimentBoundaryAt: '2026-07-26T01:00:00.020Z',
    classificationCompletedAt: '2026-07-26T01:00:00.030Z',
    eventsUntilAt: '2026-07-26T01:00:06.000Z',
  };
  assert.equal(
    analyzeCleanupDockerEvents(parseDockerEventLines(cleanupText()), options).passed,
    true
  );
  assert.throws(
    () =>
      analyzeCleanupDockerEvents(
        parseDockerEventLines(cleanupText().replace('"exitCode":"137"', '"exitCode":"0"')),
        options
      ),
    /lifecycle/u
  );
  assert.throws(
    () =>
      analyzeCleanupDockerEvents(
        parseDockerEventLines(cleanupText().replace('"signal":"9"', '"signal":"15"')),
        options
      ),
    /lifecycle/u
  );
  const unscoped = cleanupText().replaceAll(CONTAINER_ID, 'b'.repeat(64));
  assert.throws(
    () => analyzeCleanupDockerEvents(parseDockerEventLines(unscoped), options),
    /exact container/u
  );
});

test('signal proof binds both tuples and FD[] but does not trust self-declared callCount', async () => {
  const fixture = signalFixture();
  const { sha256 } = await import('./verify.mjs');
  fixture.signalAudit.receiptSha256 = sha256(fixture.receiptText);
  assert.doesNotThrow(() =>
    verifySignalReceipt({
      signal: fixture.signal,
      receiptText: fixture.receiptText,
      signalTargetRuntime: { monotonicNs: '100' },
      oldWorker: fixture.oldWorker,
      signalAudit: fixture.signalAudit,
    })
  );
  const mutated = structuredClone(fixture);
  mutated.receipt.observed.revalidation.final.startTicks += 1;
  mutated.signal.receipt = mutated.receipt;
  mutated.receiptText = `${JSON.stringify(mutated.receipt)}\n`;
  mutated.signalAudit.receiptSha256 = sha256(mutated.receiptText);
  assert.throws(
    () =>
      verifySignalReceipt({
        signal: mutated.signal,
        receiptText: mutated.receiptText,
        signalTargetRuntime: { monotonicNs: '100' },
        oldWorker: mutated.oldWorker,
        signalAudit: mutated.signalAudit,
      }),
    /both revalidation tuples/u
  );
  const regained = signalFixture();
  regained.receipt.observed.targetHidrawDescriptors = [{ descriptor: '20' }];
  regained.signal.receipt = regained.receipt;
  regained.receiptText = `${JSON.stringify(regained.receipt)}\n`;
  regained.signalAudit.receiptSha256 = sha256(regained.receiptText);
  assert.throws(
    () =>
      verifySignalReceipt({
        signal: regained.signal,
        receiptText: regained.receiptText,
        signalTargetRuntime: { monotonicNs: '100' },
        oldWorker: regained.oldWorker,
        signalAudit: regained.signalAudit,
      }),
    /both revalidation tuples/u
  );
});

test('millisecond-truncated signal timestamps reject ambiguous same-ms markers', () => {
  const before = { relevantLines: [] };
  const ambiguous = {
    relevantLines: [
      '2026-07-26T01:00:00.010500000Z Opening surface panel: streamdeck:serial',
      '2026-07-26T01:00:00.010600000Z Surface panel ready: streamdeck:serial',
    ],
  };
  const proven = {
    relevantLines: [
      '2026-07-26T01:00:00.011000000Z Opening surface panel: streamdeck:serial',
      '2026-07-26T01:00:00.011100000Z Surface panel ready: streamdeck:serial',
    ],
  };
  assert.equal(
    recomputeMarkerDelta(before, ambiguous, '2026-07-26T01:00:00.010Z').allAfterSignal,
    false
  );
  assert.equal(
    recomputeMarkerDelta(before, proven, '2026-07-26T01:00:00.010Z').allAfterSignal,
    true
  );
});

test('B-to-C reconstruction rejects multiple replacement generations and old-worker reappearance', () => {
  const lifecycle = {
    pid1StartTicks: 50,
    cgroup: '0::/',
    pidNamespace: 'pid:[1]',
    mountNamespace: 'mnt:[2]',
  };
  const old = worker(73, 100, lifecycle);
  const replacementB = worker(80, 200, lifecycle);
  const replacementC = worker(90, 300, lifecycle);
  const multiple = reconstructReplacementTimeline(
    old,
    [
      runtime([], [], lifecycle),
      runtime([replacementB], [replacementB], lifecycle),
      runtime([replacementC], [replacementC], lifecycle),
    ],
    1002
  );
  assert.equal(multiple.singleReplacementGeneration, false);
  assert.equal(multiple.replacementWorkerUnique, false);

  const reappeared = reconstructReplacementTimeline(
    old,
    [runtime([], [], lifecycle), runtime([old], [old], lifecycle)],
    1002
  );
  assert.equal(reappeared.singleReplacementGeneration, false);
});

test('independent outcome classifier refuses late and multi-generation positives', () => {
  const predicates = Object.fromEntries(PREDICATE_KEYS.map((key) => [key, true]));
  predicates.latePositiveObserved = false;
  assert.equal(classifyOutcomeIndependent(predicates).status, 'supported');
  predicates.latePositiveObserved = true;
  assert.equal(classifyOutcomeIndependent(predicates).stage, 'deadline-boundary');
  predicates.latePositiveObserved = false;
  predicates.singleReplacementGeneration = false;
  assert.equal(classifyOutcomeIndependent(predicates).stage, 'worker-replacement');
});
