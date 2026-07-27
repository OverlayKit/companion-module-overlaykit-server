import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { H043_CLAIM_BOUNDARY } from './eligibility-lib.mjs';
import { sha256, sha256Canonical } from './prefix-lib.mjs';
import { H043_REQUIRED_SOURCES, buildRun } from './run.mjs';
import { INDEPENDENT_CLAIM_BOUNDARY, INDEPENDENT_REQUIRED_SOURCES, verifyRun } from './verify.mjs';

const temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'overlaykit-h043-verify-'));
after(async () => {
  await rm(temporaryDirectory, { recursive: true, force: true });
});

const canonicalRun = await buildRun({ startedAt: '2026-07-26T18:10:00.000Z' });

async function writeFixture(name, mutate = () => {}) {
  const candidate = structuredClone(canonicalRun);
  mutate(candidate);
  const { evidenceSha256: ignored, ...record } = candidate;
  candidate.evidenceSha256 = sha256Canonical(record);
  const file = path.join(temporaryDirectory, `${name}.json`);
  await writeFile(file, `${JSON.stringify(candidate, null, 2)}\n`);
  return file;
}

function bindRunId(run) {
  run.runId =
    `h043-${run.startedAt.replace(/[:.]/gu, '-')}-` +
    sha256(`${run.startedAt}:${run.prefix.prefixSha256}`).slice(0, 8);
}

function recordObservedSideEffect(run) {
  run.sideEffectAudit.commands = ['process.kill(SIGTERM)'];
  run.sideEffectAudit.commandCount = 1;
  run.sideEffectAudit.processCount = 1;
  run.sideEffectAudit.signalCount = 1;
  run.sideEffectAudit.mutationCount = 1;
  run.sideEffectAudit.passed = false;
}

test('independently verifies the complete canonical H-043 run', async () => {
  const runPath = await writeFixture('canonical');
  const verification = await verifyRun(runPath);
  assert.deepEqual(verification, {
    schemaVersion: 'overlaykit-h043-verification/v1',
    hypothesis: 'H-043',
    runId: canonicalRun.runId,
    outcome: 'supported',
    stage: 'offline-worker-eligibility',
    evidenceSha256: canonicalRun.evidenceSha256,
    sourceSetExact: true,
    archiveExact: true,
    prefixExact: true,
    predicatesExact: true,
    candidateExact: true,
    hostileMatrixExact: true,
    tailIndependent: true,
    sideEffectAuditExact: true,
    claimBoundaryExact: true,
    verified: true,
  });
});

test('keeps verifier literals independent while triple-locking the claim boundary', async () => {
  const schema = JSON.parse(
    await readFile(
      new URL('./schemas/offline-worker-eligibility-run.schema.json', import.meta.url),
      'utf8'
    )
  );
  const schemaBoundary = Object.fromEntries(
    ['proves', 'excludes'].map((key) => [
      key,
      schema.$defs.claimBoundary.properties[key].prefixItems.map((entry) => entry.const),
    ])
  );
  assert.notStrictEqual(INDEPENDENT_CLAIM_BOUNDARY, H043_CLAIM_BOUNDARY);
  assert.notStrictEqual(INDEPENDENT_CLAIM_BOUNDARY.proves, H043_CLAIM_BOUNDARY.proves);
  assert.deepEqual(INDEPENDENT_CLAIM_BOUNDARY, H043_CLAIM_BOUNDARY);
  assert.deepEqual(schemaBoundary, H043_CLAIM_BOUNDARY);
  assert.deepEqual(INDEPENDENT_REQUIRED_SOURCES, H043_REQUIRED_SOURCES);
});

test('rejects a candidate that claims authority even with a recomputed outer hash', async () => {
  const runPath = await writeFixture('authority', (run) => {
    run.canonicalClassification.candidates[0].authority = 'signal';
  });
  await assert.rejects(() => verifyRun(runPath), /schema invalid/u);
});

test('rejects source hash and hostile-oracle drift independently', async () => {
  const sourcePath = await writeFixture('source-drift', (run) => {
    run.collector.sources[0].sha256 = '0'.repeat(64);
  });
  await assert.rejects(() => verifyRun(sourcePath), /source hashes mismatch/u);

  const matrixPath = await writeFixture('matrix-drift', (run) => {
    const entry = run.hostileMatrix.cases.find(
      (candidate) => candidate.id === 'worker-startticks-changed'
    );
    entry.expectedDisposition = 'withheld';
    entry.actualDisposition = 'withheld';
  });
  await assert.rejects(() => verifyRun(matrixPath), /(?:oracle|hostile receipt) drifted/u);
});

test('rejects evidence-hash tampering before semantic admission', async () => {
  const file = path.join(temporaryDirectory, 'hash-drift.json');
  const candidate = structuredClone(canonicalRun);
  candidate.evidenceSha256 = '0'.repeat(64);
  await writeFile(file, `${JSON.stringify(candidate, null, 2)}\n`);
  await assert.rejects(() => verifyRun(file), /evidence hash mismatch/u);
});

test('verifies an internally consistent refuted side-effect envelope', async () => {
  const runPath = await writeFixture('refuted-side-effect', (run) => {
    recordObservedSideEffect(run);
    run.outcome = {
      status: 'refuted',
      stage: 'side-effect-boundary',
      reasonCode: 'side-effect-observed',
    };
  });

  const verification = await verifyRun(runPath);
  assert.equal(verification.outcome, 'refuted');
  assert.equal(verification.stage, 'side-effect-boundary');
  assert.equal(verification.verified, true);
});

test('verifies an internally consistent inconclusive source-admission envelope', async () => {
  const runPath = await writeFixture('inconclusive-source-set', (run) => {
    run.collector.sourceStable = false;
    run.outcome = {
      status: 'inconclusive',
      stage: 'source-admission',
      reasonCode: 'source-set-unstable',
    };
  });

  const verification = await verifyRun(runPath);
  assert.equal(verification.outcome, 'inconclusive');
  assert.equal(verification.stage, 'source-admission');
  assert.equal(verification.verified, true);
});

test('rejects evidence and outcome combinations that contradict each other', async () => {
  const hiddenSideEffect = await writeFixture('hidden-side-effect', (run) => {
    recordObservedSideEffect(run);
  });
  await assert.rejects(() => verifyRun(hiddenSideEffect));

  const inventedRefutation = await writeFixture('invented-refutation', (run) => {
    run.outcome = {
      status: 'refuted',
      stage: 'side-effect-boundary',
      reasonCode: 'side-effect-observed',
    };
  });
  await assert.rejects(() => verifyRun(inventedRefutation));

  const inventedInconclusive = await writeFixture('invented-inconclusive', (run) => {
    run.outcome = {
      status: 'inconclusive',
      stage: 'source-admission',
      reasonCode: 'source-set-unstable',
    };
  });
  await assert.rejects(() => verifyRun(inventedInconclusive));
});

test('rejects invalid or reversed dates even when runId and the outer hash are rebound', async () => {
  const impossibleDate = await writeFixture('impossible-date', (run) => {
    run.startedAt = '2026-02-31T18:10:00.000Z';
    run.completedAt = '2026-03-04T18:10:00.000Z';
    bindRunId(run);
  });
  await assert.rejects(() => verifyRun(impossibleDate), /timestamp/u);

  const reversedDates = await writeFixture('reversed-dates', (run) => {
    run.completedAt = '2026-07-26T18:09:59.999Z';
  });
  await assert.rejects(() => verifyRun(reversedDates), /timestamps are invalid or reversed/u);
});

test('rejects false run and base-commit identities with a recomputed outer hash', async () => {
  const runIdPath = await writeFixture('run-id-drift', (run) => {
    run.runId = `${run.runId.slice(0, -8)}${'0'.repeat(8)}`;
  });
  await assert.rejects(() => verifyRun(runIdPath), /run ID/u);

  const baseCommitPath = await writeFixture('base-commit-drift', (run) => {
    run.collector.baseCommit = '0'.repeat(40);
  });
  await assert.rejects(() => verifyRun(baseCommitPath), /(?:baseCommit|base commit)/u);
});

test('rejects forged matrix aggregates after rebinding the outer evidence hash', async () => {
  const runPath = await writeFixture('matrix-aggregate-drift', (run) => {
    run.hostileMatrix.passedCount = 24;
    run.hostileMatrix.allPassed = false;
    run.outcome = {
      status: 'refuted',
      stage: 'hostile-matrix',
      reasonCode: 'hostile-case-or-tail-independence-failed',
    };
  });

  await assert.rejects(() => verifyRun(runPath), /[Mm]atrix/u);
});
