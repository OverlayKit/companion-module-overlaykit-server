import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  parseProcessStatus,
  selectCausalReceipt,
  selectGraphicalSession,
  virtualInvocationAudit,
} from './physical-lib.mjs';

test('accepts only an active local graphical user session', () => {
  const session = {
    Name: 'rod',
    Active: 'yes',
    State: 'active',
    Class: 'user',
    Remote: 'no',
    Type: 'wayland',
    Seat: 'seat0',
  };
  assert.equal(selectGraphicalSession([session], 'rod'), session);
  assert.equal(selectGraphicalSession([{ ...session, Type: 'tty' }], 'rod'), null);
  assert.equal(selectGraphicalSession([{ ...session, Active: 'no' }], 'rod'), null);
});

test('reads effective surface-process identity and supplementary groups', () => {
  assert.deepEqual(
    parseProcessStatus(
      'Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\nGroups:\t1000 1002\n'
    ),
    { uid: 1000, gid: 1000, groups: [1000, 1002] }
  );
});

test('fails virtual invocation audit closed', () => {
  assert.equal(
    virtualInvocationAudit([{ kind: 'trpc-configuration', procedure: 'controls.resetControl' }])
      .passed,
    true
  );
  const audit = virtualInvocationAudit([
    { kind: 'companion-http', path: '/api/location/1/0/0/press' },
  ]);
  assert.equal(audit.passed, false);
  assert.equal(audit.virtualInvocationCount, 1);
});

test('selects one ordered command-result-state-ack chain', () => {
  const common = { wallClock: '2026-07-25T00:00:00.000Z', monotonicNs: '1' };
  const events = [
    {
      ...common,
      eventSequence: 11,
      kind: 'frame.observed',
      direction: 'companion-to-server',
      messageType: 'device.command.execute',
      operationId: 'op-1',
    },
    {
      ...common,
      eventSequence: 12,
      kind: 'frame.observed',
      direction: 'server-to-companion',
      messageType: 'device.command.result',
      operationId: 'op-1',
      correlationMatches: true,
    },
    {
      ...common,
      eventSequence: 13,
      kind: 'frame.forwarded',
      direction: 'server-to-companion',
      messageType: 'device.state.delta',
      issuerKeyId: 'key',
      sequence: 4,
      evidenceSha256: 'a'.repeat(64),
      target: 'preview',
      observations: [{ controlId: 'lower-third.visibility', value: 'active' }],
    },
    {
      ...common,
      eventSequence: 14,
      kind: 'frame.observed',
      direction: 'companion-to-server',
      messageType: 'device.state.ack',
      issuerKeyId: 'key',
      sequence: 4,
      evidenceSha256: 'a'.repeat(64),
      status: 'applied',
    },
  ];
  const receipt = selectCausalReceipt(events, {
    afterEventSequence: 10,
    controlId: 'lower-third.visibility',
    expectedValue: 'active',
  });
  assert.equal(receipt.command.operationId, 'op-1');
  assert.equal(receipt.acknowledgement.eventSequence, 14);
});
