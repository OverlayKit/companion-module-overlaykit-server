import assert from 'node:assert/strict';
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

import { BRANCHES, executeSyntheticCase } from './fixtures/synthetic-terminal-cases.mjs';
import {
  REPOSITORY_ROOT,
  FailurePreservationRunError,
  buildReplayArchive,
  materializeTerminalCase,
  runAuthorizedControls,
} from './run.mjs';

const ARTIFACTS_ROOT = path.join(REPOSITORY_ROOT, 'artifacts');

function privateTestRoot() {
  mkdirSync(ARTIFACTS_ROOT, { mode: 0o700, recursive: true });
  const root = mkdtempSync(path.join(ARTIFACTS_ROOT, 'node22-failure-preservation-test-'));
  chmodSync(root, 0o700);
  return root;
}

function cleanup(root) {
  assert.ok(root.startsWith(`${ARTIFACTS_ROOT}${path.sep}`));
  rmSync(root, { force: true, recursive: true });
}

test('reservation is durable before every synthetic attempt and every branch reconstructs', () => {
  const root = privateTestRoot();
  try {
    const materialized = BRANCHES.map((branchId, index) => {
      const events = [];
      const result = materializeTerminalCase({
        branchId,
        evidenceRoot: root,
        executeCase(selected) {
          events.push('attempt');
          return executeSyntheticCase(selected);
        },
        hooks: {
          onAttemptStart() {
            events.push('attempt-start');
          },
          onReservationDurable() {
            events.push('reservation-durable');
          },
        },
        ordinal: index + 1,
      });
      assert.deepEqual(events, ['reservation-durable', 'attempt-start', 'attempt']);
      assert.equal(result.verification.branchId, branchId);
      assert.equal(result.verification.status, 'independently-reconstructed');
      return result;
    });

    assert.deepEqual(
      materialized.map(({ branchId }) => branchId),
      BRANCHES
    );
    for (const entry of materialized) {
      assert.equal((lstatSync(entry.reservationDirectory).mode & 0o7777).toString(8), '700');
      for (const filePath of [entry.reservationPath, entry.terminalPath, entry.archivePath]) {
        const metadata = lstatSync(filePath);
        assert.equal((metadata.mode & 0o7777).toString(8), '600');
        assert.equal(metadata.nlink, 1);
      }
    }
  } finally {
    cleanup(root);
  }
});

test('a consumed reservation rejects before the callback and preserves first bytes', () => {
  const root = privateTestRoot();
  try {
    const first = materializeTerminalCase({
      branchId: BRANCHES[0],
      evidenceRoot: root,
      ordinal: 1,
    });
    let launches = 0;
    assert.throws(
      () =>
        materializeTerminalCase({
          branchId: BRANCHES[0],
          evidenceRoot: root,
          executeCase() {
            launches += 1;
            return executeSyntheticCase(BRANCHES[0]);
          },
          ordinal: 1,
        }),
      (error) =>
        error instanceof FailurePreservationRunError &&
        error.code === 'reservation-already-consumed'
    );
    assert.equal(launches, 0);
    assert.equal(lstatSync(first.reservationPath).size, first.reservationBytes.length);
  } finally {
    cleanup(root);
  }
});

test('replay builder is order-independent and emits byte-identical POSIX-ustar', () => {
  const reservation = Buffer.from('reservation\n', 'utf8');
  const terminal = Buffer.from('terminal\n', 'utf8');
  const first = buildReplayArchive([
    { bytes: terminal, name: 'terminal.json' },
    { bytes: reservation, name: 'reservation.json' },
  ]);
  const second = buildReplayArchive([
    { bytes: reservation, name: 'reservation.json' },
    { bytes: terminal, name: 'terminal.json' },
  ]);
  assert.deepEqual(first, second);
  assert.equal(first.subarray(-1024).equals(Buffer.alloc(1024)), true);
  assert.equal(first.subarray(257, 263).toString('ascii'), 'ustar\0');
});

test('the authorized control roster rejects exact hostile cases', () => {
  const root = privateTestRoot();
  try {
    const materializedCases = BRANCHES.map((branchId, index) =>
      materializeTerminalCase({
        branchId,
        evidenceRoot: root,
        ordinal: index + 1,
      })
    );
    const controls = runAuthorizedControls({ evidenceRoot: root, materializedCases });
    assert.deepEqual(
      controls.map(({ id }) => id),
      [
        'partial-write',
        'duplicate-reservation',
        'staleness',
        'collision',
        'symlink',
        'hardlink',
        'containment',
        'directory-permission',
        'file-mode',
        'determinism',
      ]
    );
    assert.ok(controls.every(({ passed }) => passed));
  } finally {
    cleanup(root);
  }
});
