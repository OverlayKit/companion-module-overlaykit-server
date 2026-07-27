import assert from 'node:assert/strict';
import test from 'node:test';
import { buildH042Prefix, sha256Canonical } from './prefix-lib.mjs';
import {
  H043_REQUIRED_CASE_IDS,
  H043_REQUIRED_SOURCES,
  buildRun,
  evaluateHostileMatrix,
  evaluateTailIndependence,
  loadCanonicalH042Archive,
  outcomeFor,
} from './run.mjs';

test('loads only the exact accepted H-042 lineage from the tracked replay', async () => {
  const input = await loadCanonicalH042Archive();
  assert.equal(input.run.runId, 'h042-2026-07-26T16-19-05-858Z-efaf85fa');
  assert.equal(
    input.run.evidenceSha256,
    'f4996a0d46c54fd337601e43ae7e0afa5e44d911c72c4888c0d1ae067fe0dc88'
  );
  assert.equal(input.verification.verified, true);
  assert.equal(input.verification.outcome, 'supported');
});

test('executes the exact 25-case hostile matrix without an unsafe positive', async () => {
  const input = await loadCanonicalH042Archive();
  const prefix = buildH042Prefix(input);
  const tailIndependent = evaluateTailIndependence(input, prefix);
  const matrix = evaluateHostileMatrix(prefix, { tailIndependent });

  assert.deepEqual(matrix.requiredCaseIds, H043_REQUIRED_CASE_IDS);
  assert.equal(matrix.caseCount, 25);
  assert.equal(matrix.passedCount, 25);
  assert.equal(matrix.allPassed, true);
  assert.equal(matrix.tailIndependent, true);
  assert.equal(
    matrix.cases.filter(
      (entry) => entry.actualDisposition === 'candidate' || entry.actualCandidateCount > 0
    ).length,
    1
  );
  assert.equal(matrix.cases[0].id, 'canonical-golden');
});

test('proves that arbitrary post-cutoff tail changes cannot alter candidate bytes', async () => {
  const input = await loadCanonicalH042Archive();
  const prefix = buildH042Prefix(input);
  assert.equal(evaluateTailIndependence(input, prefix), true);
});

test('builds a source-bound supported run with a zero side-effect receipt', async () => {
  const run = await buildRun({ startedAt: '2026-07-26T18:00:00.000Z' });
  const { evidenceSha256, ...record } = run;

  assert.equal(sha256Canonical(record), evidenceSha256);
  assert.equal(run.outcome.status, 'supported');
  assert.equal(run.canonicalClassification.disposition, 'candidate');
  assert.equal(run.canonicalClassification.candidates.length, 1);
  assert.equal(run.hostileMatrix.allPassed, true);
  assert.equal(run.hostileMatrix.tailIndependent, true);
  assert.equal(run.sideEffectAudit.passed, true);
  assert.equal(
    Object.entries(run.sideEffectAudit)
      .filter(([key]) => key.endsWith('Count'))
      .every(([, value]) => value === 0),
    true
  );
  assert.deepEqual(
    run.collector.sources.map((entry) => entry.path),
    H043_REQUIRED_SOURCES
  );
  assert.equal(run.collector.sourceStable, true);
});

test('recomputes the three-way outcome with safety failures taking precedence', () => {
  const candidate = {
    disposition: 'candidate',
    candidates: [{}],
  };
  const matrix = {
    allPassed: true,
    tailIndependent: true,
  };
  const sideEffects = { passed: true };

  assert.deepEqual(outcomeFor(candidate, matrix, sideEffects, true), {
    status: 'supported',
    stage: 'offline-worker-eligibility',
    reasonCode: 'canonical-candidate-and-hostile-matrix-exact',
  });
  assert.deepEqual(outcomeFor(candidate, matrix, { passed: false }, true), {
    status: 'refuted',
    stage: 'side-effect-boundary',
    reasonCode: 'side-effect-observed',
  });
  assert.deepEqual(
    outcomeFor(candidate, { ...matrix, tailIndependent: false }, sideEffects, true),
    {
      status: 'refuted',
      stage: 'hostile-matrix',
      reasonCode: 'hostile-case-or-tail-independence-failed',
    }
  );
  assert.deepEqual(outcomeFor(candidate, matrix, sideEffects, false), {
    status: 'inconclusive',
    stage: 'source-admission',
    reasonCode: 'source-set-unstable',
  });
  assert.deepEqual(
    outcomeFor({ disposition: 'withheld', candidates: [] }, matrix, sideEffects, true),
    {
      status: 'refuted',
      stage: 'canonical-classification',
      reasonCode: 'canonical-prefix-not-eligible',
    }
  );
  assert.deepEqual(
    outcomeFor({ disposition: 'inconclusive', candidates: [] }, matrix, sideEffects, true),
    {
      status: 'inconclusive',
      stage: 'prefix-boundary',
      reasonCode: 'canonical-prefix-inconclusive',
    }
  );
});

test('rejects syntactically shaped but impossible UTC calendar dates', async () => {
  await assert.rejects(
    () => buildRun({ startedAt: '2026-02-31T18:00:00.000Z' }),
    /not a valid UTC timestamp/u
  );
});
