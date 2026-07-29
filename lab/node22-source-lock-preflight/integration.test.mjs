import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  makeCandidateExpectation,
  makeObservationSnapshot,
} from './fixtures/synthetic-boundary.mjs';
import { produceSourceLock } from './producer.mjs';
import { verifySourceLock } from './verify.mjs';

test('producer output is independently admitted without creating a real-source claim', () => {
  const evidence = produceSourceLock(makeObservationSnapshot());
  const receipt = verifySourceLock(makeCandidateExpectation(), evidence);

  assert.equal(receipt.verification, 'synthetic-closure-matches-precontract');
  assert.equal(receipt.hypothesisOutcome, 'not-executed');
  assert.equal(receipt.realSourceClosureClaim, false);
  assert.equal(receipt.authority, 'none');
  assert.equal(receipt.action, null);
});
