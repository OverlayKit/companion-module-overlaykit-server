import assert from 'node:assert/strict';
import { test } from 'node:test';
import { acceptedServerEvidence, acceptedTargetConfirmation } from './evidence.mjs';

function frame(eventSequence, sequence, value, observations) {
  return {
    eventSequence,
    kind: 'frame.forwarded',
    direction: 'server-to-companion',
    messageType: 'device.state.delta',
    target: 'preview',
    issuerKeyId: 'issuer-1',
    sequence,
    evidenceSha256: String(sequence).repeat(64),
    confirmedAt: 1_000,
    observations: observations ?? [
      { controlId: 'lower-third.visibility', value, revision: sequence },
    ],
  };
}

function acknowledgement(eventSequence, sequence) {
  return {
    eventSequence,
    kind: 'frame.observed',
    direction: 'companion-to-server',
    messageType: 'device.state.ack',
    target: 'preview',
    issuerKeyId: 'issuer-1',
    sequence,
    evidenceSha256: String(sequence).repeat(64),
    status: 'applied',
  };
}

test('selects accepted server evidence strictly after an experiment boundary', () => {
  const events = [
    frame(1, 1, 'inactive'),
    acknowledgement(2, 1),
    frame(3, 2, 'inactive'),
    acknowledgement(4, 2),
  ];

  const selected = acceptedServerEvidence(events, {
    controlId: 'lower-third.visibility',
    value: 'inactive',
    afterEventSequence: 2,
  });

  assert.equal(selected.serverEvent.eventSequence, 3);
  assert.equal(selected.acknowledgement.eventSequence, 4);
  assert.throws(
    () =>
      acceptedServerEvidence(events, {
        controlId: 'lower-third.visibility',
        value: 'inactive',
        afterEventSequence: 4,
      }),
    /No matching authoritative server frame/u
  );
});

test('selects the latest acknowledged target confirmation even without observations', () => {
  const events = [
    frame(1, 7, 'inactive'),
    acknowledgement(2, 7),
    frame(3, 8, 'active', []),
    acknowledgement(4, 8),
    frame(5, 9, 'active', []),
  ];

  const selected = acceptedTargetConfirmation(events, { target: 'preview' });

  assert.equal(selected.serverEvent.eventSequence, 3);
  assert.equal(selected.serverEvent.confirmedAt, 1_000);
  assert.equal(selected.acknowledgement.eventSequence, 4);
});
