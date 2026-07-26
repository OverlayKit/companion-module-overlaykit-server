import { createHash, randomBytes } from 'node:crypto';

export const H038_CLAIM_BOUNDARY = Object.freeze({
  proves: [
    'post-login execution on the exact Fedora 43 host and physical MK.2 identity',
    'official Companion acquisition with the exact hidraw node and effective supplementary group',
    'one physical-window command correlated to an acknowledged authoritative OverlayKit state',
    'zero virtual-press invocations by the bounded H-038 runner',
    'release of temporary containers, configuration, and the hidraw node after the run',
  ],
  excludes: [
    'pre-login startup or availability',
    'rendered hardware pixels or operator perception',
    'USB disconnect, reconnect, reboot, or recovery',
    'native Fedora packaging or production container architecture',
    'OBS output truth or complete production support',
  ],
});

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value === null || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, canonicalize(value[key])])
  );
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function sha256Canonical(value) {
  return sha256(canonicalJson(value));
}

export function runId() {
  return `h038-${new Date().toISOString().replaceAll(/[:.]/gu, '-')}-${randomBytes(4).toString('hex')}`;
}

export function parseProperties(text) {
  return Object.fromEntries(
    text
      .split(/\r?\n/u)
      .filter((line) => line.includes('='))
      .map((line) => {
        const separator = line.indexOf('=');
        return [line.slice(0, separator), line.slice(separator + 1)];
      })
  );
}

export function selectGraphicalSession(sessions, principal) {
  return (
    sessions.find(
      (session) =>
        session.Name === principal &&
        session.Active === 'yes' &&
        session.State === 'active' &&
        session.Class === 'user' &&
        session.Remote === 'no' &&
        ['wayland', 'x11'].includes(session.Type) &&
        session.Seat.length > 0
    ) ?? null
  );
}

export function parseProcessStatus(text) {
  const properties = Object.fromEntries(
    text.split(/\r?\n/u).flatMap((line) => {
      const separator = line.indexOf(':');
      return separator === -1 ? [] : [[line.slice(0, separator), line.slice(separator + 1).trim()]];
    })
  );
  const numbers = (key) => (properties[key] ?? '').split(/\s+/u).filter(Boolean).map(Number);
  return {
    uid: numbers('Uid')[0] ?? null,
    gid: numbers('Gid')[0] ?? null,
    groups: numbers('Groups'),
  };
}

export function virtualInvocationAudit(entries) {
  const forbidden = entries.filter(
    (entry) =>
      entry.kind === 'virtual-press' ||
      (entry.kind === 'companion-http' &&
        /^\/api\/location\/[^/]+\/[^/]+\/[^/]+\/press$/u.test(entry.path ?? ''))
  );
  return {
    entries,
    forbidden,
    virtualInvocationCount: forbidden.length,
    passed: forbidden.length === 0,
  };
}

function isStateMessage(event) {
  return (
    event.messageType === 'device.bootstrap.snapshot' || event.messageType === 'device.state.delta'
  );
}

export function selectCausalReceipt(events, options) {
  const command = events.find(
    (event) =>
      event.eventSequence > options.afterEventSequence &&
      event.kind === 'frame.observed' &&
      event.direction === 'companion-to-server' &&
      event.messageType === 'device.command.execute' &&
      typeof event.operationId === 'string'
  );
  if (!command) throw new Error('No physical-window Companion command was observed');
  const result = events.find(
    (event) =>
      event.eventSequence > command.eventSequence &&
      event.direction === 'server-to-companion' &&
      event.operationId === command.operationId &&
      event.correlationMatches === true
  );
  if (!result) throw new Error('Companion command lacks a correlated server result');
  const serverEvent = events.find(
    (event) =>
      event.eventSequence > command.eventSequence &&
      event.kind === 'frame.forwarded' &&
      event.direction === 'server-to-companion' &&
      isStateMessage(event) &&
      event.target === 'preview' &&
      event.observations?.some(
        (observation) =>
          observation.controlId === options.controlId && observation.value === options.expectedValue
      )
  );
  if (!serverEvent) throw new Error('Command lacks the expected authoritative state');
  const acknowledgement = events.find(
    (event) =>
      event.eventSequence > serverEvent.eventSequence &&
      event.kind === 'frame.observed' &&
      event.direction === 'companion-to-server' &&
      event.messageType === 'device.state.ack' &&
      event.issuerKeyId === serverEvent.issuerKeyId &&
      event.sequence === serverEvent.sequence &&
      event.evidenceSha256 === serverEvent.evidenceSha256 &&
      event.status === 'applied'
  );
  if (!acknowledgement) throw new Error('Authoritative state lacks a matching applied ACK');
  return { command, result, serverEvent, acknowledgement };
}
