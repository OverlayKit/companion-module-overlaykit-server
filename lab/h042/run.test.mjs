import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { POST_SIGNAL_SECONDS, PRE_SIGNAL_SECONDS } from './signal-lib.mjs';
import {
  canonicalH041Path,
  compileEvidenceSchema,
  createFailureContext,
  markersUnchanged,
  parseArgs,
  runStartPrecedesReceipt,
} from './run.mjs';

test('starts the run no later than every contributing host receipt', () => {
  const startedAt = '2026-07-26T02:10:37.615Z';
  assert.equal(runStartPrecedesReceipt(startedAt, '2026-07-26T02:10:37.615Z'), true);
  assert.equal(runStartPrecedesReceipt(startedAt, '2026-07-26T02:10:37.616Z'), true);
  assert.equal(runStartPrecedesReceipt(startedAt, '2026-07-26T02:10:37.614Z'), false);
  assert.equal(runStartPrecedesReceipt(startedAt, 'invalid'), false);
});

test('keeps both causal recovery windows fixed at thirty seconds', () => {
  assert.equal(PRE_SIGNAL_SECONDS, 30);
  assert.equal(POST_SIGNAL_SECONDS, 30);
  assert.deepEqual(parseArgs([]), {
    h041: 'artifacts/h041/h041-2026-07-26T00-56-42-118Z-0423725f/run.json',
    evidenceDirectory: null,
    transitionWindowSeconds: 120,
    baselineWindowSeconds: 30,
    absentDescriptorWindowSeconds: 5,
  });
  assert.throws(() => parseArgs(['--pre-signal-seconds', '31']));
  assert.throws(() => parseArgs(['--post-signal-seconds', '31']));
});

test('negative control requires exact cumulative marker stability', () => {
  const baseline = {
    opening: 1,
    ready: 1,
    openFailed: 0,
    relevantLines: ['opening', 'ready'],
  };
  assert.equal(markersUnchanged(baseline, structuredClone(baseline)), true);
  assert.equal(markersUnchanged(baseline, { ...baseline, opening: 2 }), false);
  assert.equal(
    markersUnchanged(baseline, { ...baseline, relevantLines: ['opening', 'other'] }),
    false
  );
});

test('binds the H-041 input to its canonical artifact tree before physical work', () => {
  assert.match(
    canonicalH041Path('artifacts/h041/h041-2026-07-26T00-56-42-118Z-0423725f/run.json'),
    /\/artifacts\/h041\/h041-2026-07-26T00-56-42-118Z-0423725f\/run\.json$/u
  );
  assert.throws(() => canonicalH041Path('lab/h041/run.json'));
  assert.throws(() => canonicalH041Path('artifacts/h041/../h040/copied-run.json'));
  assert.throws(() => canonicalH041Path('artifacts/h041/copied-run.txt'));
});

test('preserves provisional classification and cleanup when independent verification fails', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'overlaykit-h042-failure-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const failurePath = path.join(directory, 'failure.json');
  const draft = {
    outcome: {
      status: 'supported',
      stage: 'surface-worker-reacquisition',
      reason: 'provisional only',
    },
    predicates: { complete: true, signalSucceeded: true },
  };
  const cleanup = {
    successful: true,
    containerRemoved: true,
    error: null,
  };
  const context = createFailureContext();
  context.preserve(draft, cleanup);
  await context.write(failurePath, 'h042-test', 'independent verification failed');

  const failure = JSON.parse(await readFile(failurePath, 'utf8'));
  assert.deepEqual(failure.provisional, {
    outcome: draft.outcome,
    predicates: draft.predicates,
  });
  assert.deepEqual(failure.cleanup, cleanup);
  assert.equal(failure.classification, 'inconclusive');
});

test('registers the producer date-time format and rejects invalid calendar receipts', () => {
  const validate = compileEvidenceSchema({
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    type: 'object',
    required: ['at'],
    properties: {
      at: { type: 'string', format: 'date-time' },
    },
    additionalProperties: false,
  });

  assert.equal(validate({ at: '2026-07-26T02:10:37.615000001Z' }), true);
  assert.equal(validate({ at: '2026-02-31T02:10:37.615Z' }), false);
  assert.equal(validate({ at: '2026-07-26T02:10:37+00:00' }), false);
  assert.equal(validate({ at: '2026-07-26T02:10:37.1234567890Z' }), false);
  assert.equal(validate.errors?.[0]?.keyword, 'format');
});
