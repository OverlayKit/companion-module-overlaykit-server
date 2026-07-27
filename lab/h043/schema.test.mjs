import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import {
  H043_CLAIM_BOUNDARY,
  H043_PREDICATE_KEYS,
  H043_SIDE_EFFECT_AUDIT,
} from './eligibility-lib.mjs';
import { H043_CANONICAL_PREFIX_RECEIPTS, H043_PREFIX_SCHEMA } from './prefix-lib.mjs';

const SHA256 = 'a'.repeat(64);
const PREFIX_SHA256 = 'aee82f2da74cee96a7ac10ea21946d1e668913e1bb2e2210398b4a362eff3959';
const GIT_COMMIT = 'dce2cd8bb454a264f8f9738f9748dc1c70b5dcd0';
const CONTAINER_ID = 'c'.repeat(64);
const IMAGE_ID = `sha256:${'d'.repeat(64)}`;

const CASES = Object.freeze([
  ['canonical-golden', 'candidate', 1],
  ['healthy-baseline', 'withheld', 0],
  ['device-absent', 'withheld', 0],
  ['negative-window-open', 'withheld', 0],
  ['current-descriptor-reacquired', 'withheld', 0],
  ['ordered-markers-changed', 'withheld', 0],
  ['partial-marker-change', 'inconclusive', 0],
  ['worker-missing', 'inconclusive', 0],
  ['multiple-workers', 'inconclusive', 0],
  ['container-lifecycle-drift', 'inconclusive', 0],
  ['pid1-identity-drift', 'inconclusive', 0],
  ['worker-pid-changed', 'inconclusive', 0],
  ['worker-startticks-changed', 'inconclusive', 0],
  ['worker-ppid-changed', 'inconclusive', 0],
  ['worker-parent-startticks-changed', 'inconclusive', 0],
  ['worker-pid-namespace-changed', 'inconclusive', 0],
  ['worker-full-tuple-drift', 'inconclusive', 0],
  ['exact-absence-missing', 'inconclusive', 0],
  ['usb-epoch-identity-mismatch', 'inconclusive', 0],
  ['returned-node-mismatch', 'inconclusive', 0],
  ['negative-window-boundary-missing', 'inconclusive', 0],
  ['late-positive', 'inconclusive', 0],
  ['prefix-tail-contamination', 'inconclusive', 0],
  ['duplicate-candidates', 'inconclusive', 0],
  ['unapproved-command', 'inconclusive', 0],
]);

function allPredicates(value = true) {
  return Object.fromEntries(H043_PREDICATE_KEYS.map((key) => [key, value]));
}

function stat(inode, ctimeNs) {
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

function epoch({ deviceNumber, hidGeneration, inode, ctimeNs }) {
  return {
    serial: 'A00SA5492OQMLF',
    busNumber: '1',
    deviceNumber,
    usbDevicePath: '2',
    usbDev: `189:${Number(deviceNumber) - 1}`,
    hidDevicePath:
      `/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0/` + `0003:0FD9:0080.${hidGeneration}`,
    devicePath: '/dev/hidraw0',
    stat: stat(inode, ctimeNs),
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

function candidate() {
  const initialEpoch = epoch({
    deviceNumber: '17',
    hidGeneration: '0015',
    inode: '1465',
    ctimeNs: '1785082165309201027',
  });
  const returnedEpoch = epoch({
    deviceNumber: '18',
    hidGeneration: '0016',
    inode: '1480',
    ctimeNs: '1785082803368821699',
  });
  return {
    kind: 'revalidation-required',
    historical: true,
    requiresRevalidation: true,
    authority: 'none',
    action: null,
    observedCutoff: {
      at: '2026-07-26T16:20:34.184Z',
      monotonicNs: H043_CANONICAL_PREFIX_RECEIPTS.cutoffMonotonicNs,
    },
    sourceEvidenceSha256: 'f4996a0d46c54fd337601e43ae7e0afa5e44d911c72c4888c0d1ae067fe0dc88',
    prefixSha256: PREFIX_SHA256,
    identity: {
      device: {
        serial: 'A00SA5492OQMLF',
        vendorId: '0fd9',
        productId: '0080',
        initialEpoch,
        returnedEpoch,
        revalidationEpoch: structuredClone(returnedEpoch),
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
      cutoffMonotonicNs: H043_CANONICAL_PREFIX_RECEIPTS.cutoffMonotonicNs,
    },
    tokenSha256: SHA256,
  };
}

function classification() {
  return {
    disposition: 'candidate',
    stage: 'historical-worker-candidate',
    reasonCode: 'revalidation-required-worker-candidate',
    predicates: allPredicates(),
    candidates: [candidate()],
  };
}

function matrixCase([id, disposition, candidateCount]) {
  const stage =
    disposition === 'candidate'
      ? 'historical-worker-candidate'
      : disposition === 'withheld'
        ? 'not-eligible'
        : 'source-admission';
  const reasonCode =
    disposition === 'candidate'
      ? 'revalidation-required-worker-candidate'
      : disposition === 'withheld'
        ? 'non-eligible-hostile-case'
        : 'fail-closed-hostile-case';
  return {
    id,
    inputSha256: SHA256,
    expectedDisposition: disposition,
    actualDisposition: disposition,
    expectedCandidateCount: candidateCount,
    actualCandidateCount: candidateCount,
    stage,
    reasonCode,
    passed: true,
  };
}

function supportedRun() {
  return {
    schemaVersion: 'overlaykit-h043-offline-worker-eligibility-run/v1',
    hypothesis: 'H-043',
    runId: 'h043-2026-07-26T17-00-00-000Z-dd391090',
    startedAt: '2026-07-26T17:00:00.000Z',
    completedAt: '2026-07-26T17:00:01.000Z',
    outcome: {
      status: 'supported',
      stage: 'offline-worker-eligibility',
      reasonCode: 'canonical-candidate-and-hostile-matrix-exact',
    },
    collector: {
      node: 'v22.20.0',
      repository: 'https://github.com/OverlayKit/companion-module-overlaykit-server.git',
      baseCommit: GIT_COMMIT,
      sources: [
        {
          path: 'lab/h043/eligibility-lib.mjs',
          sha256: SHA256,
        },
        {
          path: 'lab/h043/schemas/offline-worker-eligibility-run.schema.json',
          sha256: SHA256,
        },
      ],
      sourceStable: true,
      governance: {
        changeId: 'CHG-0015',
        changeSha256: 'b2cd667fad87b366163549cdb3b0ffaac95ffd591fc53d6158c229a516ae7e25',
        planHash: 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4',
        manifestContentHash: 'b29bde1b9f24a5c0ddaaa6b18cb577de859d6d9577b6636148c4ebeb021b8917',
      },
    },
    input: {
      archivePath:
        'evidence/h042/f4996a0d46c54fd337601e43ae7e0afa5e44d911c72c4888c0d1ae067fe0dc88/' +
        'replay-15b2589976cb3a4cff95af807d52728fee83a2f5b9983969f61e0663bfcc3b36.tar.gz',
      archiveSha256: '15b2589976cb3a4cff95af807d52728fee83a2f5b9983969f61e0663bfcc3b36',
      h042RunId: 'h042-2026-07-26T16-19-05-858Z-efaf85fa',
      h042EvidenceSha256: 'f4996a0d46c54fd337601e43ae7e0afa5e44d911c72c4888c0d1ae067fe0dc88',
      h042RunSha256: 'be39e69140f733e7f56e371f144b6e7b0cd43c05b7be6bfea9850c440679a7b6',
      h042VerificationSha256: '0fc4f3cd7f78fe1184331a40f97874521d97d6f5c677a4829588a6dc676e6919',
    },
    prefix: {
      schemaVersion: H043_PREFIX_SCHEMA,
      prefixSha256: PREFIX_SHA256,
      cutoffMonotonicNs: H043_CANONICAL_PREFIX_RECEIPTS.cutoffMonotonicNs,
      runtimePoll: structuredClone(H043_CANONICAL_PREFIX_RECEIPTS.runtimePoll),
      hostPoll: structuredClone(H043_CANONICAL_PREFIX_RECEIPTS.hostPoll),
      invocationAudit: structuredClone(H043_CANONICAL_PREFIX_RECEIPTS.invocationAudit),
      logs: {
        initialSha256: H043_CANONICAL_PREFIX_RECEIPTS.logsInitial,
        absentSha256: H043_CANONICAL_PREFIX_RECEIPTS.logsAbsent,
        preSignalSha256: H043_CANONICAL_PREFIX_RECEIPTS.logsPreSignal,
      },
    },
    causalBoundary: {
      cutoffMonotonicNs: H043_CANONICAL_PREFIX_RECEIPTS.cutoffMonotonicNs,
      firstFaultInjection: {
        sourceAuditIndex: 223,
        at: '2026-07-26T16:20:34.271Z',
        monotonicNs: '78174210861519',
        kind: 'docker-exec-signal',
        phase: 'fault-injection',
        entrySha256: 'a52472766a103a8b1b7348b1a5d1305c79022b063697ffefc5af3538f8a64658',
      },
      gapNs: '86266314',
      precedesFirstFaultInjection: true,
    },
    canonicalClassification: classification(),
    hostileMatrix: {
      schemaVersion: 'overlaykit-h043-hostile-matrix/v1',
      requiredCaseIds: CASES.map(([id]) => id),
      caseCount: CASES.length,
      passedCount: CASES.length,
      allPassed: true,
      tailIndependent: true,
      cases: CASES.map(matrixCase),
    },
    sideEffectAudit: structuredClone(H043_SIDE_EFFECT_AUDIT),
    claimBoundary: structuredClone(H043_CLAIM_BOUNDARY),
    evidenceSha256: SHA256,
  };
}

const schema = JSON.parse(
  await readFile(
    new URL('./schemas/offline-worker-eligibility-run.schema.json', import.meta.url),
    'utf8'
  )
);
const validate = new Ajv2020({
  strict: false,
  allErrors: true,
  validateFormats: false,
}).compile(schema);

function assertAccepted(value, message) {
  assert.equal(validate(value), true, `${message}: ${JSON.stringify(validate.errors)}`);
}

function assertRejected(value, message) {
  assert.equal(validate(value), false, message);
}

test('schema accepts the complete supported envelope and triple-locks model boundaries', () => {
  assertAccepted(supportedRun(), 'supported H-043 fixture was rejected');

  const predicateKeys = schema.$defs.predicates.required;
  assert.deepEqual(predicateKeys, [...H043_PREDICATE_KEYS]);
  const schemaBoundary = Object.fromEntries(
    ['proves', 'excludes'].map((key) => [
      key,
      schema.$defs.claimBoundary.properties[key].prefixItems.map((entry) => entry.const),
    ])
  );
  assert.deepEqual(schemaBoundary, H043_CLAIM_BOUNDARY);
});

test('candidate branch requires every predicate and one non-authorizing full receipt', () => {
  for (const key of H043_PREDICATE_KEYS) {
    const run = supportedRun();
    run.canonicalClassification.predicates[key] = false;
    assertRejected(run, `candidate with false ${key} was accepted`);
  }

  for (const candidates of [[], [candidate(), candidate()]]) {
    const run = supportedRun();
    run.canonicalClassification.candidates = candidates;
    assertRejected(run, `candidate cardinality ${candidates.length} was accepted`);
  }

  for (const mutate of [
    (receipt) => {
      receipt.requiresRevalidation = false;
    },
    (receipt) => {
      receipt.authority = 'agent';
    },
    (receipt) => {
      receipt.action = { signal: 'SIGTERM' };
    },
    (receipt) => {
      receipt.historical = false;
    },
    (receipt) => {
      receipt.kind = 'safe-trigger';
    },
    (receipt) => {
      receipt.identity.worker.startTicks = 0;
    },
    (receipt) => {
      receipt.identity.worker.extra = true;
    },
  ]) {
    const run = supportedRun();
    mutate(run.canonicalClassification.candidates[0]);
    assertRejected(run, 'weakened or expanded candidate receipt was accepted');
  }

  const wrongStage = supportedRun();
  wrongStage.canonicalClassification.stage = 'not-eligible';
  assertRejected(wrongStage, 'candidate with withheld stage was accepted');
});

test('withheld and inconclusive branches carry zero candidates and remain distinguishable', () => {
  const withheld = supportedRun();
  withheld.outcome = {
    status: 'refuted',
    stage: 'canonical-classification',
    reasonCode: 'canonical-prefix-not-eligible',
  };
  withheld.canonicalClassification = {
    disposition: 'withheld',
    stage: 'not-eligible',
    reasonCode: 'negative-window-open',
    predicates: allPredicates(),
    candidates: [],
  };
  withheld.canonicalClassification.predicates.negativeWindowComplete = false;
  assertAccepted(withheld, 'well-formed withheld evidence was rejected');

  const withheldCandidate = structuredClone(withheld);
  withheldCandidate.canonicalClassification.candidates = [candidate()];
  assertRejected(withheldCandidate, 'withheld classification carrying a candidate was accepted');

  const unjustifiedWithheld = structuredClone(withheld);
  unjustifiedWithheld.canonicalClassification.predicates = allPredicates();
  assertRejected(
    unjustifiedWithheld,
    'withheld classification with no negative predicate was accepted'
  );

  const inconclusive = supportedRun();
  inconclusive.outcome = {
    status: 'inconclusive',
    stage: 'prefix-boundary',
    reasonCode: 'canonical-prefix-inconclusive',
  };
  inconclusive.canonicalClassification = {
    disposition: 'inconclusive',
    stage: 'source-admission',
    reasonCode: 'malformed-prefix',
    predicates: allPredicates(),
    candidates: [],
  };
  inconclusive.canonicalClassification.predicates.sourceAdmissionExact = false;
  assertAccepted(inconclusive, 'well-formed inconclusive evidence was rejected');

  const inconclusiveCandidate = structuredClone(inconclusive);
  inconclusiveCandidate.canonicalClassification.candidates = [candidate()];
  assertRejected(
    inconclusiveCandidate,
    'inconclusive classification carrying a candidate was accepted'
  );

  const unjustifiedInconclusive = structuredClone(inconclusive);
  unjustifiedInconclusive.canonicalClassification.predicates = allPredicates();
  assertRejected(
    unjustifiedInconclusive,
    'inconclusive classification with every predicate true was accepted'
  );

  const unstableSource = supportedRun();
  unstableSource.outcome = {
    status: 'inconclusive',
    stage: 'source-admission',
    reasonCode: 'source-set-unstable',
  };
  unstableSource.collector.sourceStable = false;
  assertAccepted(unstableSource, 'source-instability inconclusive evidence was rejected');

  const wrongSourceStage = structuredClone(unstableSource);
  wrongSourceStage.outcome = {
    status: 'inconclusive',
    stage: 'prefix-boundary',
    reasonCode: 'canonical-prefix-inconclusive',
  };
  assertRejected(wrongSourceStage, 'source instability was accepted under a classification stage');
});

test('strict envelope rejects drift, invalid provenance, and malformed timestamps', () => {
  for (const mutate of [
    (run) => {
      run.extra = true;
    },
    (run) => {
      run.collector.extra = true;
    },
    (run) => {
      run.collector.baseCommit = SHA256;
    },
    (run) => {
      run.collector.baseCommit = '0'.repeat(40);
    },
    (run) => {
      run.startedAt = '2026-13-26T17:00:00.000Z';
    },
    (run) => {
      run.completedAt = '2026-07-26T17:00:01.000';
    },
    (run) => {
      run.runId = 'h043-Z---0123abcd';
    },
    (run) => {
      run.runId = 'h043-2026-07-26T17-99-00-000Z-0123abcd';
    },
    (run) => {
      run.input.archiveSha256 = SHA256;
    },
    (run) => {
      run.prefix.runtimePoll.lineCount = 56;
    },
    (run) => {
      run.prefix.cutoffMonotonicNs = '78174275543442';
    },
    (run) => {
      run.hostileMatrix.passedCount = 21;
    },
    (run) => {
      run.hostileMatrix.tailIndependent = false;
    },
    (run) => {
      run.sideEffectAudit.commands = ['docker restart companion'];
      run.sideEffectAudit.commandCount = 1;
      run.sideEffectAudit.passed = false;
    },
    (run) => {
      run.claimBoundary.proves.push('a production-safe trigger');
    },
    (run) => {
      run.claimBoundary.excludes.reverse();
    },
  ]) {
    const run = supportedRun();
    mutate(run);
    assertRejected(run, 'supported evidence with a weakened boundary was accepted');
  }
});

test('refuted lattice preserves side effects, hostile failures, and tail dependence', () => {
  const refuted = supportedRun();
  refuted.outcome = {
    status: 'refuted',
    stage: 'side-effect-boundary',
    reasonCode: 'side-effect-observed',
  };
  refuted.sideEffectAudit.commands = ['docker restart companion'];
  refuted.sideEffectAudit.commandCount = 1;
  refuted.sideEffectAudit.dockerCount = 1;
  refuted.sideEffectAudit.mutationCount = 1;
  refuted.sideEffectAudit.passed = false;
  assertAccepted(refuted, 'side-effect refutation could not be represented');

  const emptySideEffectRefutation = supportedRun();
  emptySideEffectRefutation.outcome = {
    status: 'refuted',
    stage: 'side-effect-boundary',
    reasonCode: 'side-effect-observed',
  };
  emptySideEffectRefutation.sideEffectAudit.passed = false;
  assertRejected(
    emptySideEffectRefutation,
    'side-effect refutation without a non-zero observation was accepted'
  );

  const hostileCase = supportedRun();
  hostileCase.outcome = {
    status: 'refuted',
    stage: 'hostile-matrix',
    reasonCode: 'hostile-case-or-tail-independence-failed',
  };
  hostileCase.hostileMatrix.allPassed = false;
  hostileCase.hostileMatrix.passedCount = 24;
  hostileCase.hostileMatrix.cases.at(-1).passed = false;
  assertAccepted(hostileCase, 'failed hostile case could not be represented as refuted');

  const inconsistentHostileCase = structuredClone(hostileCase);
  inconsistentHostileCase.hostileMatrix.passedCount = 25;
  assertRejected(
    inconsistentHostileCase,
    'failed hostile matrix with a passing aggregate count was accepted'
  );

  const tailDependent = supportedRun();
  tailDependent.outcome = {
    status: 'refuted',
    stage: 'hostile-matrix',
    reasonCode: 'hostile-case-or-tail-independence-failed',
  };
  tailDependent.hostileMatrix.tailIndependent = false;
  assertAccepted(tailDependent, 'tail-dependence refutation could not be represented');

  const wrongTailStage = structuredClone(tailDependent);
  wrongTailStage.outcome = {
    status: 'refuted',
    stage: 'canonical-classification',
    reasonCode: 'canonical-prefix-not-eligible',
  };
  assertRejected(
    wrongTailStage,
    'tail dependence was accepted under a canonical-classification stage'
  );
});
