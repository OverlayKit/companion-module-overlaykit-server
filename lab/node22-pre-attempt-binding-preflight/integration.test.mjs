import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { syntheticGrant, syntheticPrecontractBytes } from './fixtures/synthetic-precontract.mjs';
import { materializePreAttemptBinding } from './stage0.mjs';
import { verifyLaunchFailure } from './verify.mjs';

test('the dynamic stage-1 launch failure follows a durable candidate reservation', async () => {
  const root = mkdtempSync(path.join(tmpdir(), 'overlaykit-pre-attempt-binding-integration-'));
  chmodSync(root, 0o700);
  const events = [];
  try {
    const materialized = await materializePreAttemptBinding({
      evidenceRoot: root,
      grant: syntheticGrant(),
      loadStage1: async () => {
        events.push('stage1-load');
        return {
          launchSyntheticStage1() {
            events.push('stage1-invoke');
            const error = new Error('synthetic stage-1 launch failure');
            error.code = 'SYNTHETIC_STAGE1_LAUNCH_FAILED';
            error.syscall = 'synthetic-stage1-launch';
            throw error;
          },
        };
      },
      precontractBytes: syntheticPrecontractBytes(),
    });
    assert.deepEqual(materialized.events, ['reservation-durable', 'stage1-load', 'stage1-invoke']);
    assert.deepEqual(events, ['stage1-load', 'stage1-invoke']);
    const receipt = verifyLaunchFailure({
      grant: syntheticGrant(),
      precontractBytes: syntheticPrecontractBytes(),
      reservationBytes: materialized.reservationBytes,
      terminalBytes: materialized.terminalBytes,
    });
    assert.equal(receipt.status, 'candidate-launch-failure-reconstructed');
    assert.equal(receipt.attempts, 0);
  } finally {
    assert.ok(root.startsWith(path.join(tmpdir(), 'overlaykit-pre-attempt-binding-integration-')));
    rmSync(root, { force: true, recursive: true });
  }
});
