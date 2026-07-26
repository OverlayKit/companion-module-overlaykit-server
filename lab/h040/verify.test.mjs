import assert from 'node:assert/strict';
import { test } from 'node:test';
import { verifyChronology } from './verify.mjs';

function chronology() {
  return {
    startedAt: '2026-07-25T22:00:00.000Z',
    windows: {
      disconnect: {
        openedAt: '2026-07-25T22:00:00.000Z',
        openedMonotonicNs: '120',
        closedAt: '2026-07-25T22:00:00.001Z',
        closedMonotonicNs: '150',
      },
      reconnect: {
        openedAt: '2026-07-25T22:00:00.001Z',
        openedMonotonicNs: '160',
        closedAt: '2026-07-25T22:00:00.002Z',
        closedMonotonicNs: '190',
      },
    },
    observations: {
      initial: {
        capturedAt: '2026-07-25T22:00:00.000Z',
        monotonicNs: '110',
        host: {
          capturedAt: '2026-07-25T22:00:00.000Z',
          monotonicNs: '100',
        },
      },
      absent: {
        capturedAt: '2026-07-25T22:00:00.001Z',
        monotonicNs: '140',
        host: {
          capturedAt: '2026-07-25T22:00:00.001Z',
          monotonicNs: '130',
        },
      },
      returned: {
        capturedAt: '2026-07-25T22:00:00.002Z',
        monotonicNs: '180',
        host: {
          capturedAt: '2026-07-25T22:00:00.002Z',
          monotonicNs: '170',
        },
      },
    },
  };
}

test('uses monotonic order when adjacent wall-clock observations share a millisecond', () => {
  assert.doesNotThrow(() => verifyChronology(chronology()));
});

test('rejects an adjacent transition without strict monotonic order', () => {
  const run = chronology();
  run.windows.reconnect.openedMonotonicNs = run.windows.disconnect.closedMonotonicNs;
  assert.throws(() => verifyChronology(run), /chronology is invalid/u);
});
