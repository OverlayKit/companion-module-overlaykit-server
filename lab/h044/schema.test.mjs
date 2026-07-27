import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import {
  H044_PREDICATE_KEYS,
  classifyLiveFrames,
  deviceIdentityFromHistoricalCandidate,
  pid1IdentityFromHistoricalCandidate,
  sha256Canonical,
} from './classifier-lib.mjs';

const SHA256 = 'a'.repeat(64);
const CONTAINER_ID = 'c'.repeat(64);
const IMAGE_ID = `sha256:${'d'.repeat(64)}`;

function deviceStat(inode) {
  return {
    stDev: '7',
    inode,
    ctimeNs: inode === '1465' ? '1785082165309201027' : '1785082803368821699',
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

function epoch(deviceNumber, generation, inode) {
  return {
    serial: 'A00SA5492OQMLF',
    busNumber: '1',
    deviceNumber,
    usbDevicePath: '2',
    usbDev: `189:${Number(deviceNumber) - 1}`,
    hidDevicePath:
      `/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0/` + `0003:0FD9:0080.${generation}`,
    devicePath: '/dev/hidraw0',
    stat: deviceStat(inode),
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
  const returnedEpoch = epoch('18', '0016', '1480');
  const value = {
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
        initialEpoch: epoch('17', '0015', '1465'),
        returnedEpoch: structuredClone(returnedEpoch),
        revalidationEpoch: returnedEpoch,
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
  value.tokenSha256 = sha256Canonical({
    schemaVersion: 'overlaykit-h043-candidate-token/v1',
    sourceEvidenceSha256: value.sourceEvidenceSha256,
    prefixSha256: value.prefixSha256,
    device: value.identity.device,
    lifecycle: value.identity.lifecycle,
    worker: value.identity.worker,
    window: value.window,
  });
  return value;
}

function sealFrame(frame) {
  const value = structuredClone(frame);
  delete value.digestSha256;
  return { ...value, digestSha256: sha256Canonical(value) };
}

function liveFrames(candidate) {
  const observation = {
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
      ...structuredClone(observation),
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
      ...structuredClone(observation),
      auditBinding: {
        commandReceiptIndexes: [5, 8, 9, 11],
        filesystemReceiptIndexes: [1],
      },
    }),
  ];
}

function audit() {
  const allowedProcessCounts = {
    git: 2,
    lsusb: 1,
    dockerVersion: 1,
    dockerPs: 2,
    dockerInspect: 4,
    dockerLogs: 2,
  };
  const commandReceipts = Object.entries(allowedProcessCounts).flatMap(([kind, count]) =>
    Array.from({ length: count }, (_, receiptIndex) => ({ kind, receiptIndex }))
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

function sourceAdmission(value = true) {
  return {
    h043ArchiveExact: value,
    h043RunExact: value,
    h043VerificationExact: value,
    h043EvidenceExact: value,
    h043CandidateTokenExact: value,
    chg0016Exact: value,
    adr0006Exact: value,
    protectedMainAncestryExact: value,
    governanceExact: value,
    sourceSetExact: value,
    allExact: value,
  };
}

function supportedRun() {
  const candidate = historicalCandidate();
  const frames = liveFrames(candidate);
  const capabilityAudit = audit();
  const liveClassification = classifyLiveFrames({
    historicalCandidate: candidate,
    frames,
    capabilityAudit,
    sourceAdmissionExact: true,
  });
  return {
    schemaVersion: 'overlaykit-h044-live-readonly-revalidation-run/v1',
    hypothesis: 'H-044',
    runId: 'h044-2026-07-26T18-00-00-000Z-dd391090',
    startedAt: '2026-07-26T18:00:00.000Z',
    completedAt: '2026-07-26T18:00:02.000Z',
    outcome: {
      status: 'supported',
      stage: 'live-readonly-revalidation',
      reasonCode: 'complete-live-classification-and-hostile-matrix-exact',
    },
    collector: {
      node: 'v22.20.0',
      repository: 'https://github.com/OverlayKit/companion-module-overlaykit-server.git',
      baseCommit: '9e2156e5a4343766715c3014264404bcfc89c1be',
      sources: [
        {
          path: 'lab/h044/classifier-lib.mjs',
          sha256: SHA256,
        },
        {
          path: 'lab/h044/schemas/live-run.schema.json',
          sha256: SHA256,
        },
      ],
      sourceStable: true,
      governance: {
        changeId: 'CHG-0017',
        changeSha256: SHA256,
        planHash: 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4',
        manifestContentHash: SHA256,
      },
    },
    input: {
      h043ArchivePath: `evidence/h043/${'6'.repeat(64)}/replay.tar.gz`,
      h043ArchiveSha256: '6'.repeat(64),
      h043RunId: 'h043-2026-07-26T22-13-38-193Z-b4158eab',
      h043RunSha256: '4a5754eddcd5672072d1ce0dc68c7a42694eafdc3eab5cddc4bf3e9ce5a57328',
      h043VerificationSha256: 'f75726992c88d45b9d43bab3443005cdaed05464d303f05a8356e0ccecc81023',
      h043EvidenceSha256: '64bf41f30dc2d51a2475e6f2e9b79ddebc225c076a87b83c384b3848b1bbecb8',
      h043CandidateTokenSha256: candidate.tokenSha256,
    },
    sourceAdmission: sourceAdmission(),
    historicalCandidate: candidate,
    frames,
    capabilityAudit,
    liveClassification,
    hostileMatrix: {
      schemaVersion: 'overlaykit-h044-hostile-matrix/v1',
      requiredCaseIds: ['canonical-candidate'],
      caseCount: 1,
      passedCount: 1,
      allPassed: true,
      cases: [
        {
          id: 'canonical-candidate',
          inputSha256: SHA256,
          expectedDisposition: 'candidate',
          actualDisposition: 'candidate',
          expectedReceiptCount: 1,
          actualReceiptCount: 1,
          stage: liveClassification.stage,
          reasonCode: liveClassification.reasonCode,
          passed: true,
        },
      ],
    },
    claimBoundary: {
      proves: ['two exact adjacent read-only frames at one bounded cutoff'],
      excludes: ['action authority after the cutoff'],
    },
    evidenceSha256: SHA256,
  };
}

const schema = JSON.parse(
  await readFile(new URL('./schemas/live-run.schema.json', import.meta.url), 'utf8')
);
const validate = new Ajv2020({
  strict: true,
  allErrors: true,
  validateFormats: false,
}).compile(schema);

function assertAccepted(value, message) {
  assert.equal(validate(value), true, `${message}: ${JSON.stringify(validate.errors)}`);
}

function assertRejected(value, message) {
  assert.equal(validate(value), false, message);
}

test('accepts supported H-044 with one non-authorizing candidate receipt', () => {
  const run = supportedRun();
  assertAccepted(run, 'candidate-supported run');
  assert.equal(run.liveClassification.disposition, 'candidate');
  assert.equal(run.liveClassification.receipts.length, 1);
});

test('accepts supported H-044 with complete stable non-eligible evidence withheld', () => {
  const run = supportedRun();
  for (const frame of run.frames) {
    frame.workers[0].pid += 1;
    Object.assign(frame, sealFrame(frame));
  }
  run.liveClassification = classifyLiveFrames({
    historicalCandidate: run.historicalCandidate,
    frames: run.frames,
    capabilityAudit: run.capabilityAudit,
    sourceAdmissionExact: true,
  });
  run.hostileMatrix.cases[0].expectedDisposition = 'withheld';
  run.hostileMatrix.cases[0].actualDisposition = 'withheld';
  run.hostileMatrix.cases[0].expectedReceiptCount = 0;
  run.hostileMatrix.cases[0].actualReceiptCount = 0;
  run.hostileMatrix.cases[0].stage = run.liveClassification.stage;
  run.hostileMatrix.cases[0].reasonCode = run.liveClassification.reasonCode;

  assert.equal(run.liveClassification.disposition, 'withheld');
  assertAccepted(run, 'withheld-supported run');
});

test('accepts an inconclusive hypothesis separately from an inconclusive live classification', () => {
  const run = supportedRun();
  run.sourceAdmission = sourceAdmission(false);
  run.liveClassification = classifyLiveFrames({
    historicalCandidate: run.historicalCandidate,
    frames: run.frames,
    capabilityAudit: run.capabilityAudit,
    sourceAdmissionExact: false,
  });
  run.outcome = {
    status: 'inconclusive',
    stage: 'source-admission',
    reasonCode: 'source-admission-incomplete',
  };
  assertAccepted(run, 'inconclusive run');
});

test('accepts a refuted hypothesis with prohibited capability and no unsafe receipt', () => {
  const run = supportedRun();
  run.capabilityAudit.prohibitedCounts.signal = 1;
  run.liveClassification = classifyLiveFrames({
    historicalCandidate: run.historicalCandidate,
    frames: run.frames,
    capabilityAudit: run.capabilityAudit,
    sourceAdmissionExact: true,
  });
  run.outcome = {
    status: 'refuted',
    stage: 'capability-boundary',
    reasonCode: 'prohibited-capability-observed',
  };
  assert.equal(run.liveClassification.disposition, 'inconclusive');
  assert.deepEqual(run.liveClassification.receipts, []);
  assertAccepted(run, 'refuted prohibited-capability run');
});

test('schema predicate set remains exactly aligned with the classifier', () => {
  assert.deepEqual(schema.$defs.predicates.required, H044_PREDICATE_KEYS);
});

for (const [label, mutate] of [
  [
    'supported outcome with inconclusive live classification',
    (run) => {
      run.liveClassification.disposition = 'inconclusive';
      run.liveClassification.receipts = [];
    },
  ],
  [
    'supported outcome with incomplete audit',
    (run) => {
      run.capabilityAudit.complete = false;
    },
  ],
  [
    'candidate authority expansion',
    (run) => {
      run.liveClassification.receipts[0].authority = 'live';
    },
  ],
  [
    'candidate executable action',
    (run) => {
      run.liveClassification.receipts[0].action = { signal: 'SIGTERM' };
    },
  ],
  [
    'candidate receipt with a non-running container',
    (run) => {
      run.liveClassification.receipts[0].identity.containerObservation.state = 'paused';
    },
  ],
  [
    'candidate duplicate receipt',
    (run) => {
      run.liveClassification.receipts.push(structuredClone(run.liveClassification.receipts[0]));
    },
  ],
  [
    'withheld classification carrying a receipt',
    (run) => {
      run.liveClassification.disposition = 'withheld';
    },
  ],
  [
    'unknown top-level authority field',
    (run) => {
      run.authority = 'none';
    },
  ],
  [
    'frame missing audit binding',
    (run) => {
      delete run.frames[0].auditBinding;
    },
  ],
  [
    'duplicate command receipt indexes',
    (run) => {
      run.frames[0].auditBinding.commandReceiptIndexes = [2, 2];
    },
  ],
  [
    'negative filesystem receipt index',
    (run) => {
      run.frames[0].auditBinding.filesystemReceiptIndexes = [-1];
    },
  ],
  [
    'frame missing observation cutoff',
    (run) => {
      delete run.frames[0].observationCutoff;
    },
  ],
  [
    'uppercase container state',
    (run) => {
      run.frames[0].containerObservation.state = 'Running';
    },
  ],
  [
    'absent container with a non-null state',
    (run) => {
      run.frames[0].containerObservation = {
        present: false,
        state: 'exited',
        exact: true,
      };
    },
  ],
]) {
  test(`rejects ${label}`, () => {
    const run = supportedRun();
    mutate(run);
    assertRejected(run, label);
  });
}

test('classifier rejects an unordered audit binding even though JSON Schema cannot compare items', () => {
  const run = supportedRun();
  run.frames[1].auditBinding.commandReceiptIndexes = [8, 5];
  Object.assign(run.frames[1], sealFrame(run.frames[1]));
  const classification = classifyLiveFrames({
    historicalCandidate: run.historicalCandidate,
    frames: run.frames,
    capabilityAudit: run.capabilityAudit,
    sourceAdmissionExact: true,
  });
  assert.equal(classification.disposition, 'inconclusive');
  assert.equal(classification.stage, 'frame-admission');
  assert.equal(classification.reasonCode, 'incomplete-or-invalid-live-frame');
  assert.deepEqual(classification.receipts, []);
});
