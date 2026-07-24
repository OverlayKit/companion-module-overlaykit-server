import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  assertStoragePreflight,
  CANONICAL_MINIMUM_FREE_GIB,
  minimumFreeGiB,
  SUPPLEMENTAL_MINIMUM_FREE_GIB,
} from './runtime.mjs';

test('uses separate canonical and supplemental storage floors', () => {
  assert.equal(minimumFreeGiB(true), CANONICAL_MINIMUM_FREE_GIB);
  assert.equal(minimumFreeGiB(false), SUPPLEMENTAL_MINIMUM_FREE_GIB);
});

test('does not permit canonical callers to lower the storage floor', () => {
  assert.throws(
    () => minimumFreeGiB(true, '49'),
    /Canonical H-034 runs require at least 50 GiB free/u
  );
  assert.equal(minimumFreeGiB(true, '64'), 64);
});

test('rejects invalid configured storage values', () => {
  for (const value of ['0', '-1', 'not-a-number']) {
    assert.throws(() => minimumFreeGiB(false, value), /must be a positive number/u);
  }
});

test('fails closed when the measured storage reserve is insufficient', () => {
  assert.doesNotThrow(() =>
    assertStoragePreflight({ availableGiB: 16, requiredGiB: 16, sufficient: true })
  );
  assert.throws(
    () =>
      assertStoragePreflight({
        availableGiB: 15.999,
        requiredGiB: 16,
        sufficient: false,
      }),
    /15\.999 GiB is available/u
  );
});
