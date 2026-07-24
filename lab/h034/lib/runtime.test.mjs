import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  assertStoragePreflight,
  CANONICAL_MINIMUM_FREE_GIB,
  lockedOverlayKitBuildEnvironment,
  minimumFreeGiB,
  SUPPLEMENTAL_MINIMUM_FREE_GIB,
} from './runtime.mjs';

test('binds the locked OverlayKit source identity to the image build environment', () => {
  assert.deepEqual(
    lockedOverlayKitBuildEnvironment({
      overlaykit: {
        commit: 'a'.repeat(40),
        archiveSha256: 'b'.repeat(64),
      },
    }),
    {
      H034_OVERLAYKIT_COMMIT: 'a'.repeat(40),
      H034_OVERLAYKIT_ARCHIVE_SHA256: 'b'.repeat(64),
    }
  );
});

test('rejects incomplete or malformed locked OverlayKit source identities', () => {
  assert.throws(
    () => lockedOverlayKitBuildEnvironment({ overlaykit: { archiveSha256: 'b'.repeat(64) } }),
    /commit must be a lowercase 40-character Git identity/u
  );
  assert.throws(
    () =>
      lockedOverlayKitBuildEnvironment({
        overlaykit: { commit: 'a'.repeat(40), archiveSha256: 'not-a-digest' },
      }),
    /archive must have a lowercase SHA-256 digest/u
  );
});

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
