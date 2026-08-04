import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  makeSyntheticLaunchFailureTerminal,
  makeSyntheticPrecontract,
  syntheticGrant,
  syntheticLaunchFailureTerminalBytes,
  syntheticPrecontractBytes,
  syntheticReservationBytes,
} from './fixtures/synthetic-precontract.mjs';
import {
  PreAttemptBindingVerificationError,
  verifyLaunchFailure,
  verifyPartialWriteControl,
  verifyPreAttemptReservation,
} from './verify.mjs';

function pretty(value) {
  const compare = (left, right) =>
    Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
  const canonicalize = (candidate) => {
    if (Array.isArray(candidate)) return candidate.map(canonicalize);
    if (candidate !== null && typeof candidate === 'object') {
      return Object.fromEntries(
        Object.keys(candidate)
          .sort(compare)
          .map((key) => [key, canonicalize(candidate[key])])
      );
    }
    return candidate;
  };
  return Buffer.from(`${JSON.stringify(canonicalize(value), null, 2)}\n`, 'utf8');
}

function rejects(code, operation) {
  assert.throws(
    operation,
    (error) => error instanceof PreAttemptBindingVerificationError && error.code === code
  );
}

test('independent verifier reconstructs the candidate reservation and launch failure', () => {
  const reservation = verifyPreAttemptReservation({
    grant: syntheticGrant(),
    precontractBytes: syntheticPrecontractBytes(),
    reservationBytes: syntheticReservationBytes(),
  });
  assert.equal(reservation.status, 'candidate-reservation-binding-reconstructed');
  const terminal = verifyLaunchFailure({
    grant: syntheticGrant(),
    precontractBytes: syntheticPrecontractBytes(),
    reservationBytes: syntheticReservationBytes(),
    terminalBytes: syntheticLaunchFailureTerminalBytes(),
  });
  assert.equal(terminal.branchId, 'launch-failure');
  assert.equal(terminal.attempts, 0);
});

test('governance omission, predecessor staleness and source-set rebinding fail closed', () => {
  const omitted = makeSyntheticPrecontract();
  delete omitted.governanceBindings.chg0042RawSha256;
  rejects('precontract-shape-invalid', () =>
    verifyPreAttemptReservation({
      grant: syntheticGrant(),
      precontractBytes: pretty(omitted),
      reservationBytes: syntheticReservationBytes(),
    })
  );

  const stale = makeSyntheticPrecontract();
  stale.predecessorAnchor.commit = '0'.repeat(40);
  rejects('precontract-policy-invalid', () =>
    verifyPreAttemptReservation({
      grant: syntheticGrant(),
      precontractBytes: pretty(stale),
      reservationBytes: syntheticReservationBytes(),
    })
  );

  const rebound = makeSyntheticPrecontract();
  rebound.sourceSet.descriptors[0].rawSha256 = 'f'.repeat(64);
  rejects('precontract-source-set-invalid', () =>
    verifyPreAttemptReservation({
      grant: syntheticGrant(),
      precontractBytes: pretty(rebound),
      reservationBytes: syntheticReservationBytes(),
    })
  );
});

test('terminal binding drift and any nonzero attempt fail closed', () => {
  const terminal = makeSyntheticLaunchFailureTerminal();
  terminal.attempts.push({
    exitCode: 0,
    ordinal: 1,
    signal: null,
    stderr: '',
    stdout: '',
  });
  rejects('terminal-binding-invalid', () =>
    verifyLaunchFailure({
      grant: syntheticGrant(),
      precontractBytes: syntheticPrecontractBytes(),
      reservationBytes: syntheticReservationBytes(),
      terminalBytes: pretty(terminal),
    })
  );
});

test('partial-write verification requires a strict prefix, consumption and zero stage-1 loads', () => {
  const expected = syntheticReservationBytes();
  const partial = expected.subarray(0, 31);
  const firstWriteReceipt = {
    errorCode: 'synthetic-partial-write-injected',
    expectedByteLength: expected.length,
    observedByteLength: partial.length,
    observedRawSha256: createHash('sha256').update(partial).digest('hex'),
  };
  const receipt = verifyPartialWriteControl({
    firstWriteReceipt,
    grant: syntheticGrant(),
    partialReservationBytes: partial,
    precontractBytes: syntheticPrecontractBytes(),
    retryReceipt: { errorCode: 'reservation-already-consumed' },
    stage1Events: [],
  });
  assert.equal(receipt.controlId, 'partial-write');
  assert.equal(receipt.assessed, false);
  assert.equal(receipt.status, 'candidate-control-envelope-consistent');

  rejects('partial-write-stage1-loaded', () =>
    verifyPartialWriteControl({
      firstWriteReceipt,
      grant: syntheticGrant(),
      partialReservationBytes: partial,
      precontractBytes: syntheticPrecontractBytes(),
      retryReceipt: { errorCode: 'reservation-already-consumed' },
      stage1Events: ['stage1-load'],
    })
  );
});
