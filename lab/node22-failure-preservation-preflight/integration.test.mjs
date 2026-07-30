import assert from 'node:assert/strict';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

import { BRANCHES } from './fixtures/synthetic-terminal-cases.mjs';
import { REPOSITORY_ROOT, materializeTerminalCase } from './run.mjs';
import { verifyReplay, verifyTerminal } from './verify.mjs';

const ARTIFACTS_ROOT = path.join(REPOSITORY_ROOT, 'artifacts');

test('producer bytes pass the independent verifier for exactly five terminal branches', () => {
  mkdirSync(ARTIFACTS_ROOT, { mode: 0o700, recursive: true });
  const root = mkdtempSync(path.join(ARTIFACTS_ROOT, 'node22-failure-preservation-integration-'));
  chmodSync(root, 0o700);
  try {
    const receipts = BRANCHES.map((branchId, index) => {
      const materialized = materializeTerminalCase({
        branchId,
        evidenceRoot: root,
        ordinal: index + 1,
      });
      const subjectBytes = Buffer.from(
        JSON.stringify(
          JSON.parse(
            readFileSync(
              path.join(
                REPOSITORY_ROOT,
                'lab/node22-failure-preservation-preflight/subject-lock.json'
              ),
              'utf8'
            )
          ),
          null,
          2
        ) + '\n',
        'utf8'
      );
      const terminal = verifyTerminal({
        reservationBytes: materialized.reservationBytes,
        subjectBytes,
        terminalBytes: materialized.terminalBytes,
      });
      const replay = verifyReplay({
        archiveBytes: materialized.archiveBytes,
        reservationBytes: materialized.reservationBytes,
        subjectBytes,
        terminalBytes: materialized.terminalBytes,
      });
      return { branchId: terminal.branchId, replay: replay.status };
    });
    assert.deepEqual(
      receipts.map(({ branchId }) => branchId),
      BRANCHES
    );
    assert.ok(receipts.every(({ replay }) => replay === 'replay-reconstructed'));
  } finally {
    assert.ok(root.startsWith(`${ARTIFACTS_ROOT}${path.sep}`));
    rmSync(root, { force: true, recursive: true });
  }
});
