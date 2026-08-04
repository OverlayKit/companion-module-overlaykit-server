import assert from 'node:assert/strict';
import { chmodSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  PreAttemptBindingStage0Error,
  buildReservationBytes,
  materializePreAttemptBinding,
} from './stage0.mjs';
import { syntheticGrant, syntheticPrecontractBytes } from './fixtures/synthetic-precontract.mjs';
import { verifyPartialWriteControl } from './verify.mjs';

function privateRoot() {
  const root = mkdtempSync(path.join(tmpdir(), 'overlaykit-pre-attempt-binding-'));
  chmodSync(root, 0o700);
  return root;
}

function cleanup(root) {
  assert.ok(root.startsWith(path.join(tmpdir(), 'overlaykit-pre-attempt-binding-')));
  rmSync(root, { force: true, recursive: true });
}

test('reservation is durable before the sole stage-1 launch-failure callback', async () => {
  const root = privateRoot();
  const events = [];
  try {
    const result = await materializePreAttemptBinding({
      evidenceRoot: root,
      grant: syntheticGrant(),
      loadStage1: async () => ({
        launchSyntheticStage1() {
          events.push('launch-failure');
          const error = new Error('synthetic');
          error.code = 'SYNTHETIC_STAGE1_LAUNCH_FAILED';
          error.syscall = 'synthetic-stage1-launch';
          throw error;
        },
      }),
      precontractBytes: syntheticPrecontractBytes(),
    });
    assert.deepEqual(result.events, ['reservation-durable', 'stage1-load', 'stage1-invoke']);
    assert.deepEqual(events, ['launch-failure']);
    assert.equal(result.branchId, 'launch-failure');
    assert.equal(result.terminal.attempts.length, 0);
    assert.equal((lstatSync(result.reservationDirectory).mode & 0o7777).toString(8), '700');
    for (const filePath of [result.reservationPath, result.terminalPath]) {
      const metadata = lstatSync(filePath);
      assert.equal((metadata.mode & 0o7777).toString(8), '600');
      assert.equal(metadata.nlink, 1);
    }
  } finally {
    cleanup(root);
  }
});

test('partial reservation write consumes the slot with zero stage-1 loads', async () => {
  const root = privateRoot();
  let stage1LoadCount = 0;
  let firstWriteError;
  let retryError;
  const expected = buildReservationBytes({
    grant: syntheticGrant(),
    precontractBytes: syntheticPrecontractBytes(),
  }).bytes;
  try {
    await assert.rejects(
      () =>
        materializePreAttemptBinding({
          evidenceRoot: root,
          grant: syntheticGrant(),
          injectPartialByteLength: 31,
          loadStage1: async () => {
            stage1LoadCount += 1;
            return {};
          },
          precontractBytes: syntheticPrecontractBytes(),
        }),
      (error) => (
        (firstWriteError = error),
        error instanceof PreAttemptBindingStage0Error &&
          error.code === 'synthetic-partial-write-injected'
      )
    );
    assert.equal(stage1LoadCount, 0);
    const [reservationDirectoryName] = readdirSync(root);
    const reservationDirectory = path.join(root, reservationDirectoryName);
    const partial = readFileSync(path.join(reservationDirectory, 'reservation.json'));
    assert.ok(partial.length > 0 && partial.length < expected.length);
    assert.deepEqual(partial, expected.subarray(0, partial.length));

    await assert.rejects(
      () =>
        materializePreAttemptBinding({
          evidenceRoot: root,
          grant: syntheticGrant(),
          loadStage1: async () => {
            stage1LoadCount += 1;
            return {};
          },
          precontractBytes: syntheticPrecontractBytes(),
        }),
      (error) => (
        (retryError = error),
        error instanceof PreAttemptBindingStage0Error &&
          error.code === 'reservation-already-consumed'
      )
    );
    assert.equal(stage1LoadCount, 0);
    const verification = verifyPartialWriteControl({
      firstWriteReceipt: {
        errorCode: firstWriteError.code,
        expectedByteLength: firstWriteError.details.expectedByteLength,
        observedByteLength: firstWriteError.details.observedByteLength,
        observedRawSha256: firstWriteError.details.observedRawSha256,
      },
      grant: syntheticGrant(),
      partialReservationBytes: partial,
      precontractBytes: syntheticPrecontractBytes(),
      retryReceipt: { errorCode: retryError.code },
      stage1Events: [],
    });
    assert.equal(verification.controlId, 'partial-write');
  } finally {
    cleanup(root);
  }
});
