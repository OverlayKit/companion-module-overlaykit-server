'use strict';

const { createHash } = require('node:crypto');

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function parsedMessage(data) {
  if (!Buffer.isBuffer(data) && typeof data !== 'string') return null;
  try {
    const value = JSON.parse(Buffer.from(data).toString('utf8'));
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    let payload = null;
    if (typeof value.payloadBase64 === 'string') {
      try {
        payload = JSON.parse(Buffer.from(value.payloadBase64, 'base64').toString('utf8'));
      } catch {
        payload = null;
      }
    }
    return { value, payload };
  } catch {
    return null;
  }
}

function commandCorrelation(value, wireBytes) {
  if (value?.type !== 'device.command.execute' || typeof value.operationId !== 'string') {
    return null;
  }
  const intent = value.intent;
  if (!intent || typeof intent !== 'object' || Array.isArray(intent)) return null;
  const canonicalIntent = {
    schemaVersion: 'overlaykit-device-command-intent/v1',
    target: value.target,
    kind: intent.kind,
    componentId: intent.componentId,
    visible: intent.visible,
    expectedRevision: intent.expectedRevision,
  };
  return {
    operationId: value.operationId,
    requestSha256: sha256(wireBytes),
    expectedIntentSha256: sha256(Buffer.from(JSON.stringify(canonicalIntent), 'utf8')),
  };
}

function responseCorrelation(payload, pending) {
  const responseIntentSha256 =
    typeof payload?.intentSha256 === 'string' ? payload.intentSha256 : null;
  const responseRequestSha256 =
    typeof payload?.requestSha256 === 'string' ? payload.requestSha256 : null;
  const expectedIntentSha256 = pending?.expectedIntentSha256 ?? null;
  const expectedRequestSha256 = pending?.requestSha256 ?? null;
  const correlationMatches =
    responseIntentSha256 !== null && expectedIntentSha256 !== null
      ? responseIntentSha256 === expectedIntentSha256
      : responseRequestSha256 !== null && expectedRequestSha256 !== null
        ? responseRequestSha256 === expectedRequestSha256
        : null;
  return {
    expectedIntentSha256,
    expectedRequestSha256,
    responseIntentSha256,
    responseRequestSha256,
    correlationMatches,
  };
}

module.exports = {
  commandCorrelation,
  parsedMessage,
  responseCorrelation,
  sha256,
};
