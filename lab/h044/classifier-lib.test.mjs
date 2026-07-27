import assert from 'node:assert/strict';
import test from 'node:test';
import {
  H044_PREDICATE_KEYS,
  classifyLiveFrames,
  classificationExactShape,
  deviceIdentityFromHistoricalCandidate,
  pid1IdentityFromHistoricalCandidate,
  sha256Canonical,
} from './classifier-lib.mjs';

const SHA256 = 'a'.repeat(64);
const CONTAINER_ID = 'c'.repeat(64);
const IMAGE_ID = `sha256:${'d'.repeat(64)}`;

function stat({ inode = '1480', ctimeNs = '1785082803368821699' } = {}) {
  return {
    stDev: '7',
    inode,
    ctimeNs,
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

function epoch({
  deviceNumber = '18',
  hidGeneration = '0016',
  inode = '1480',
  ctimeNs = '1785082803368821699',
} = {}) {
  return {
    serial: 'A00SA5492OQMLF',
    busNumber: '1',
    deviceNumber,
    usbDevicePath: '2',
    usbDev: `189:${Number(deviceNumber) - 1}`,
    hidDevicePath:
      `/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0/` + `0003:0FD9:0080.${hidGeneration}`,
    devicePath: '/dev/hidraw0',
    stat: stat({ inode, ctimeNs }),
  };
}

function lifecycle() {
  return {
    containerId: CONTAINER_ID,
    imageId: IMAGE_ID,
    startedAt: '2026-07-26T16:19:06.805378786Z',
    restartCount: 0,
    hostPid: 1238461,
    pid1StartTicks: 7808679,
    pidNamespace: 'pid:[4026533784]',
    mountNamespace: 'mnt:[4026533781]',
    cgroup: '0::/',
    hostCgroup: `0::/system.slice/docker-${CONTAINER_ID}.scope`,
    cgroupNamespaceMode: 'private',
  };
}

function worker() {
  return {
    pid: 73,
    startTicks: 7808716,
    ppid: 1,
    parentStartTicks: 7808679,
    uid: 1000,
    gid: 1000,
    groups: [1000, 1002],
    cmdline: [
      '/app/node-runtimes/node22/bin/node',
      '--enable-source-maps',
      '/app/SurfaceThread.js',
    ],
    cgroup: '0::/',
    pidNamespace: 'pid:[4026533784]',
    mountNamespace: 'mnt:[4026533781]',
  };
}

function historicalCandidate() {
  const initialEpoch = epoch({
    deviceNumber: '17',
    hidGeneration: '0015',
    inode: '1465',
    ctimeNs: '1785082165309201027',
  });
  const revalidationEpoch = epoch();
  const candidate = {
    kind: 'revalidation-required',
    historical: true,
    requiresRevalidation: true,
    authority: 'none',
    action: null,
    observedCutoff: {
      at: '2026-07-26T16:20:34.184Z',
      monotonicNs: '78174124595205',
    },
    sourceEvidenceSha256: 'f4996a0d46c54fd337601e43ae7e0afa5e44d911c72c4888c0d1ae067fe0dc88',
    prefixSha256: 'aee82f2da74cee96a7ac10ea21946d1e668913e1bb2e2210398b4a362eff3959',
    identity: {
      device: {
        serial: 'A00SA5492OQMLF',
        vendorId: '0fd9',
        productId: '0080',
        initialEpoch,
        returnedEpoch: structuredClone(revalidationEpoch),
        revalidationEpoch,
      },
      lifecycle: lifecycle(),
      worker: worker(),
    },
    window: {
      startedMonotonicNs: '78143547973113',
      deadlineMonotonicNs: '78173547973113',
      completedMonotonicNs: '78174031954528',
      boundaryPollMonotonicNs: '78174031765124',
      revalidationMonotonicNs: '78174119635040',
      cutoffMonotonicNs: '78174124595205',
    },
    tokenSha256: '',
  };
  candidate.tokenSha256 = sha256Canonical({
    schemaVersion: 'overlaykit-h043-candidate-token/v1',
    sourceEvidenceSha256: candidate.sourceEvidenceSha256,
    prefixSha256: candidate.prefixSha256,
    device: candidate.identity.device,
    lifecycle: candidate.identity.lifecycle,
    worker: candidate.identity.worker,
    window: candidate.window,
  });
  return candidate;
}

function sealFrame(frame) {
  const candidate = structuredClone(frame);
  delete candidate.digestSha256;
  return { ...candidate, digestSha256: sha256Canonical(candidate) };
}

function framesFor(candidate) {
  const common = {
    complete: true,
    host: {
      hostname: 'llama',
      bootId: 'e4d12b9a-9f19-4a41-a621-c3e4e4ec003d',
      osRelease: 'Ubuntu 24.04.2 LTS',
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
    lifecycle: structuredClone(candidate.identity.lifecycle),
    pid1: pid1IdentityFromHistoricalCandidate(candidate),
    workers: [structuredClone(candidate.identity.worker)],
    descriptors: [],
    markers: {
      opening: 4,
      ready: 4,
      relevantLinesSha256: SHA256,
    },
    absence: {
      historicalContainerAbsent: false,
      exact: true,
    },
  };
  return [
    sealFrame({
      id: 'frame-1',
      startedAt: '2026-07-26T18:00:00.000Z',
      endedAt: '2026-07-26T18:00:00.900Z',
      startedMonotonicNs: '100000000000',
      endedMonotonicNs: '100900000000',
      observationCutoff: {
        at: '2026-07-26T18:00:00.800Z',
        monotonicNs: '100800000000',
      },
      ...structuredClone(common),
      auditBinding: {
        commandReceiptIndexes: [2, 3, 4, 6, 7, 10],
        filesystemReceiptIndexes: [0],
      },
    }),
    sealFrame({
      id: 'frame-2',
      startedAt: '2026-07-26T18:00:00.900Z',
      endedAt: '2026-07-26T18:00:01.800Z',
      startedMonotonicNs: '100900000000',
      endedMonotonicNs: '101800000000',
      observationCutoff: {
        at: '2026-07-26T18:00:01.700Z',
        monotonicNs: '101700000000',
      },
      ...structuredClone(common),
      auditBinding: {
        commandReceiptIndexes: [5, 8, 9, 11],
        filesystemReceiptIndexes: [1],
      },
    }),
  ];
}

function capabilityAudit() {
  const allowedProcessCounts = {
    git: 2,
    lsusb: 1,
    dockerVersion: 1,
    dockerPs: 2,
    dockerInspect: 4,
    dockerLogs: 2,
  };
  const commandReceipts = Object.entries(allowedProcessCounts).flatMap(([kind, count]) =>
    Array.from({ length: count }, (_, index) => ({ kind, receiptIndex: index }))
  );
  const filesystemReceipts = [
    { kind: 'readFile', path: '/proc/sys/kernel/random/boot_id' },
    { kind: 'lstat', path: '/dev/hidraw0' },
  ];
  return {
    mode: 'live-readonly-capability-bounded',
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

function canonicalInput() {
  const candidate = historicalCandidate();
  return {
    historicalCandidate: candidate,
    frames: framesFor(candidate),
    capabilityAudit: capabilityAudit(),
    sourceAdmissionExact: true,
  };
}

function classifyMutation(mutate) {
  const input = canonicalInput();
  mutate(input);
  return classifyLiveFrames(input);
}

function reseal(frame) {
  const next = sealFrame(frame);
  Object.assign(frame, next);
}

test('emits one cutoff-bound authority-void receipt for two exact adjacent frames', () => {
  const result = classifyLiveFrames(canonicalInput());
  assert.equal(classificationExactShape(result), true);
  assert.equal(result.disposition, 'candidate');
  assert.equal(result.stage, 'live-readonly-revalidation');
  assert.equal(result.reasonCode, 'cutoff-bound-candidate-revalidated');
  assert.deepEqual(Object.keys(result.predicates), H044_PREDICATE_KEYS);
  assert.equal(Object.values(result.predicates).every(Boolean), true);
  assert.equal(result.receipts.length, 1);

  const receipt = result.receipts[0];
  assert.equal(receipt.authority, 'none');
  assert.equal(receipt.action, null);
  assert.equal(receipt.authorizesAction, false);
  assert.equal(receipt.validAtCutoffOnly, true);
  assert.equal(receipt.revalidatedAtCutoff, true);
  assert.equal(receipt.requiresRevalidation, true);
  assert.equal(receipt.cutoff.monotonicNs, '101700000000');
  assert.equal(receipt.cutoff.at, '2026-07-26T18:00:01.700Z');
  assert.equal(receipt.exposure.endedMonotonicNs, receipt.cutoff.monotonicNs);
  assert.equal(receipt.exposure.endedAt, receipt.cutoff.at);
  assert.equal(receipt.exposure.milliseconds, 1700);
  const { receiptSha256, ...body } = receipt;
  assert.equal(receiptSha256, sha256Canonical(body));
  assert.equal(
    /signalTarget|executableAction|retry|futureValidity/u.test(JSON.stringify(receipt)),
    false
  );
});

test('is deterministic and does not mutate admitted input', () => {
  const input = canonicalInput();
  const before = sha256Canonical(input);
  const first = classifyLiveFrames(input);
  const second = classifyLiveFrames(input);
  assert.deepEqual(second, first);
  assert.equal(sha256Canonical(input), before);
});

for (const [label, mutate, reasonCode] of [
  [
    'historical container absence',
    (input) => {
      for (const frame of input.frames) {
        frame.absence.historicalContainerAbsent = true;
        frame.lifecycle = null;
        frame.pid1 = null;
        frame.workers = [];
        frame.containerObservation = {
          present: false,
          state: null,
          exact: true,
        };
        reseal(frame);
      }
    },
    'historical-container-absent',
  ],
  [
    'stable non-running container state',
    (input) => {
      for (const frame of input.frames) {
        frame.containerObservation.state = 'exited';
        frame.lifecycle = null;
        frame.pid1 = null;
        frame.workers = [];
        reseal(frame);
      }
    },
    'container-not-running',
  ],
  [
    'device absence',
    (input) => {
      for (const frame of input.frames) {
        frame.device.present = false;
        frame.device.identity = null;
        reseal(frame);
      }
    },
    'device-absent',
  ],
  [
    'stable worker absence',
    (input) => {
      for (const frame of input.frames) {
        frame.workers = [];
        reseal(frame);
      }
    },
    'surface-worker-absent',
  ],
  [
    'stable historical identity mismatch',
    (input) => {
      for (const frame of input.frames) {
        frame.workers[0].pid += 1;
        reseal(frame);
      }
    },
    'historical-identity-not-current',
  ],
  [
    'stable current descriptor presence',
    (input) => {
      for (const frame of input.frames) {
        frame.descriptors = [{ descriptor: '20', inode: '1480', rdev: '61696' }];
        reseal(frame);
      }
    },
    'current-descriptor-present',
  ],
]) {
  test(`withholds complete non-eligible evidence: ${label}`, () => {
    const result = classifyMutation(mutate);
    assert.equal(classificationExactShape(result), true);
    assert.equal(result.disposition, 'withheld');
    assert.equal(result.reasonCode, reasonCode);
    assert.deepEqual(result.receipts, []);
  });
}

for (const [label, mutate, stage, reasonCode] of [
  [
    'source admission false',
    (input) => {
      input.sourceAdmissionExact = false;
    },
    'source-admission',
    'source-admission-inexact',
  ],
  [
    'historical token tampering',
    (input) => {
      input.historicalCandidate.tokenSha256 = 'b'.repeat(64);
    },
    'source-admission',
    'source-admission-inexact',
  ],
  [
    'only one frame',
    (input) => {
      input.frames.pop();
    },
    'frame-admission',
    'two-complete-frames-required',
  ],
  [
    'incomplete frame',
    (input) => {
      input.frames[1].complete = false;
      reseal(input.frames[1]);
    },
    'frame-admission',
    'incomplete-or-invalid-live-frame',
  ],
  [
    'frame digest tampering',
    (input) => {
      input.frames[1].digestSha256 = 'b'.repeat(64);
    },
    'frame-admission',
    'incomplete-or-invalid-live-frame',
  ],
  [
    'missing frame audit binding',
    (input) => {
      delete input.frames[1].auditBinding;
      reseal(input.frames[1]);
    },
    'frame-admission',
    'incomplete-or-invalid-live-frame',
  ],
  [
    'duplicate command receipt binding',
    (input) => {
      input.frames[1].auditBinding.commandReceiptIndexes = [5, 5];
      reseal(input.frames[1]);
    },
    'frame-admission',
    'incomplete-or-invalid-live-frame',
  ],
  [
    'unordered filesystem receipt binding',
    (input) => {
      input.frames[1].auditBinding.filesystemReceiptIndexes = [1, 0];
      reseal(input.frames[1]);
    },
    'frame-admission',
    'incomplete-or-invalid-live-frame',
  ],
  [
    'out-of-range command receipt binding',
    (input) => {
      input.frames[1].auditBinding.commandReceiptIndexes = [99];
      reseal(input.frames[1]);
    },
    'capability-audit',
    'capability-audit-incomplete-or-inexact',
  ],
  [
    'missing audit field',
    (input) => {
      delete input.capabilityAudit.unrecordedObservationCount;
    },
    'capability-audit',
    'capability-audit-incomplete-or-inexact',
  ],
  [
    'command receipt cardinality mismatch',
    (input) => {
      input.capabilityAudit.commandReceipts.pop();
    },
    'capability-audit',
    'capability-audit-incomplete-or-inexact',
  ],
  [
    'prohibited signal capability',
    (input) => {
      input.capabilityAudit.prohibitedCounts.signal = 1;
    },
    'capability-audit',
    'prohibited-capability-observed',
  ],
  [
    'reordered frame boundary',
    (input) => {
      input.frames[1].startedMonotonicNs = '100800000000';
      input.frames[1].startedAt = '2026-07-26T18:00:00.800Z';
      reseal(input.frames[1]);
    },
    'temporal-boundary',
    'frame-order-invalid',
  ],
  [
    'exposure over five seconds',
    (input) => {
      input.frames[1].startedAt = '2026-07-26T18:00:05.000Z';
      input.frames[1].endedAt = '2026-07-26T18:00:05.100Z';
      input.frames[1].startedMonotonicNs = '105000000000';
      input.frames[1].endedMonotonicNs = '105100000000';
      input.frames[1].observationCutoff = {
        at: '2026-07-26T18:00:05.050Z',
        monotonicNs: '105050000000',
      };
      reseal(input.frames[1]);
    },
    'temporal-boundary',
    'exposure-window-exceeded',
  ],
  [
    'observation cutoff after collection end',
    (input) => {
      input.frames[1].observationCutoff = {
        at: '2026-07-26T18:00:01.900Z',
        monotonicNs: '101900000000',
      };
      reseal(input.frames[1]);
    },
    'temporal-boundary',
    'frame-order-invalid',
  ],
  [
    'host drift',
    (input) => {
      input.frames[1].host.bootId = 'different-boot';
      reseal(input.frames[1]);
    },
    'live-drift',
    'host-identity-drift',
  ],
  [
    'device epoch drift',
    (input) => {
      input.frames[1].device.identity.epoch.deviceNumber = '19';
      reseal(input.frames[1]);
    },
    'live-drift',
    'device-identity-drift',
  ],
  [
    'container lifecycle drift',
    (input) => {
      input.frames[1].lifecycle.restartCount = 1;
      reseal(input.frames[1]);
    },
    'live-drift',
    'container-or-pid1-identity-drift',
  ],
  [
    'container state drift from exited to paused',
    (input) => {
      input.frames[0].containerObservation.state = 'exited';
      input.frames[1].containerObservation.state = 'paused';
      for (const frame of input.frames) reseal(frame);
    },
    'live-drift',
    'container-or-pid1-identity-drift',
  ],
  [
    'PID 1 drift',
    (input) => {
      input.frames[1].pid1.startTicks += 1;
      reseal(input.frames[1]);
    },
    'live-drift',
    'container-or-pid1-identity-drift',
  ],
  [
    'worker ambiguity',
    (input) => {
      input.frames[1].workers.push(structuredClone(input.frames[1].workers[0]));
      reseal(input.frames[1]);
    },
    'identity',
    'worker-ambiguity',
  ],
  [
    'worker presence drift',
    (input) => {
      input.frames[1].workers = [];
      reseal(input.frames[1]);
    },
    'identity',
    'worker-presence-drift',
  ],
  [
    'worker PID reuse or tuple drift',
    (input) => {
      input.frames[1].workers[0].startTicks += 1;
      reseal(input.frames[1]);
    },
    'identity',
    'worker-identity-drift',
  ],
  [
    'descriptor drift',
    (input) => {
      input.frames[1].descriptors = [{ descriptor: '20' }];
      reseal(input.frames[1]);
    },
    'live-drift',
    'descriptor-state-drift',
  ],
  [
    'marker drift',
    (input) => {
      input.frames[1].markers.ready += 1;
      reseal(input.frames[1]);
    },
    'live-drift',
    'marker-drift',
  ],
  [
    'contradictory absence state',
    (input) => {
      input.frames[1].absence.historicalContainerAbsent = true;
      reseal(input.frames[1]);
    },
    'live-drift',
    'absence-state-drift',
  ],
]) {
  test(`fails closed without a receipt: ${label}`, () => {
    const result = classifyMutation(mutate);
    assert.equal(classificationExactShape(result), true);
    assert.equal(result.disposition, 'inconclusive');
    assert.equal(result.stage, stage);
    assert.equal(result.reasonCode, reasonCode);
    assert.deepEqual(result.receipts, []);
  });
}
