import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { test } from 'node:test';

const require = createRequire(import.meta.url);
const { commandCorrelation, responseCorrelation } = require('./proxy-evidence.cjs');

test('binds a command result to the public canonical command intent', () => {
  const command = {
    schemaVersion: 'overlaykit-device-command-execute/v1',
    type: 'device.command.execute',
    operationId: 'operation-1',
    target: 'preview',
    basedOn: {
      issuerKeyId: 'issuer-1',
      sequence: 7,
      sha256: 'a'.repeat(64),
      productionRevision: 1,
      catalogGeneration: 1,
    },
    intent: {
      kind: 'component.visibility',
      componentId: 'lower-third',
      visible: true,
      expectedRevision: 1,
    },
  };
  const bytes = Buffer.from(JSON.stringify(command), 'utf8');
  const pending = commandCorrelation(command, bytes);
  const matching = responseCorrelation(
    { intentSha256: pending.expectedIntentSha256 },
    pending
  );
  const mismatched = responseCorrelation({ intentSha256: 'b'.repeat(64) }, pending);

  assert.equal(matching.correlationMatches, true);
  assert.equal(mismatched.correlationMatches, false);
  assert.equal(mismatched.expectedIntentSha256, pending.expectedIntentSha256);
  assert.equal(mismatched.responseIntentSha256, 'b'.repeat(64));
});

test('binds a refusal to the exact command request bytes', () => {
  const command = {
    type: 'device.command.execute',
    operationId: 'operation-2',
    target: 'preview',
    intent: {
      kind: 'component.visibility',
      componentId: 'lower-third',
      visible: false,
      expectedRevision: 2,
    },
  };
  const bytes = Buffer.from(JSON.stringify(command), 'utf8');
  const pending = commandCorrelation(command, bytes);
  const observed = responseCorrelation({ requestSha256: pending.requestSha256 }, pending);

  assert.equal(observed.correlationMatches, true);
  assert.equal(observed.expectedRequestSha256, pending.requestSha256);
});
