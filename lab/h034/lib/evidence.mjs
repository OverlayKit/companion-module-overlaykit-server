import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { sha256File, writeJson } from './util.mjs';

export const STATE_STYLE = Object.freeze({
  active: { text: 'ACTIVE', color: '#147d3f' },
  inactive: { text: 'INACTIVE', color: '#30343b' },
  unknown: { text: 'UNKNOWN', color: '#f0b429' },
  disconnected: { text: 'DISCONNECTED', color: '#35546f' },
  failed: { text: 'FAILED', color: '#b42318' },
  unavailable: { text: 'UNAVAILABLE', color: '#6b7280' },
});

export async function proxyEvents(evidenceDirectory) {
  const raw = await readFile(path.join(evidenceDirectory, 'proxy-events.jsonl'), 'utf8');
  return raw
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

export function acceptedServerEvidence(events, options = {}) {
  const afterEventSequence = options.afterEventSequence ?? 0;
  const beforeOrAt = options.beforeOrAt ?? Number.MAX_SAFE_INTEGER;
  const candidates = events.filter(
    (event) =>
      event.kind === 'frame.forwarded' &&
      event.direction === 'server-to-companion' &&
      (event.messageType === 'device.bootstrap.snapshot' ||
        event.messageType === 'device.state.delta') &&
      event.eventSequence > afterEventSequence &&
      event.eventSequence <= beforeOrAt &&
      event.target === 'preview' &&
      event.observations?.some(
        (observation) =>
          observation.controlId === options.controlId &&
          (options.value === undefined || observation.value === options.value)
      )
  );
  const serverEvent = candidates.at(-1);
  if (!serverEvent) throw new Error('No matching authoritative server frame was forwarded');
  const acknowledgement = events.find(
    (event) =>
      event.kind === 'frame.observed' &&
      event.direction === 'companion-to-server' &&
      event.messageType === 'device.state.ack' &&
      event.issuerKeyId === serverEvent.issuerKeyId &&
      event.sequence === serverEvent.sequence &&
      event.evidenceSha256 === serverEvent.evidenceSha256 &&
      event.status === 'applied' &&
      event.eventSequence > serverEvent.eventSequence &&
      event.eventSequence <= beforeOrAt
  );
  if (!acknowledgement) throw new Error('Authoritative server frame lacks a matching applied ACK');
  const observation = serverEvent.observations.find((item) => item.controlId === options.controlId);
  return { serverEvent, acknowledgement, observation };
}

export function acceptedTargetConfirmation(events, options = {}) {
  const afterEventSequence = options.afterEventSequence ?? 0;
  const beforeOrAt = options.beforeOrAt ?? Number.MAX_SAFE_INTEGER;
  const candidates = events.filter(
    (event) =>
      event.kind === 'frame.forwarded' &&
      event.direction === 'server-to-companion' &&
      (event.messageType === 'device.bootstrap.snapshot' ||
        event.messageType === 'device.state.delta') &&
      event.eventSequence > afterEventSequence &&
      event.eventSequence <= beforeOrAt &&
      event.target === options.target &&
      Number.isSafeInteger(event.confirmedAt)
  );
  for (const serverEvent of candidates.reverse()) {
    const acknowledgement = events.find(
      (event) =>
        event.kind === 'frame.observed' &&
        event.direction === 'companion-to-server' &&
        event.messageType === 'device.state.ack' &&
        event.issuerKeyId === serverEvent.issuerKeyId &&
        event.sequence === serverEvent.sequence &&
        event.evidenceSha256 === serverEvent.evidenceSha256 &&
        event.status === 'applied' &&
        event.eventSequence > serverEvent.eventSequence &&
        event.eventSequence <= beforeOrAt
    );
    if (acknowledgement) return { serverEvent, acknowledgement };
  }
  throw new Error('No acknowledged authoritative target confirmation was forwarded');
}

export async function createReceipt(options) {
  const style = STATE_STYLE[options.observedState];
  if (!style) throw new Error(`Unsupported UI state ${options.observedState}`);
  const captureSha256 = await sha256File(options.captureAbsolutePath);
  const receipt = {
    schemaVersion: 'overlaykit-h034-causal-receipt/v1',
    runId: options.runId,
    scenarioId: options.scenarioId,
    expectedState: options.expectedState,
    observedState: options.observedState,
    invocation: options.invocation,
    justification: {
      kind: options.justificationKind,
      proxyEventSequence: options.evidence.serverEvent.eventSequence,
      serverMessageType: options.evidence.serverEvent.messageType,
      controlId: options.controlId,
      revision: options.evidence.observation.revision,
      value: options.evidence.observation.value,
      wallClock: options.evidence.serverEvent.wallClock,
      monotonicNs: options.evidence.serverEvent.monotonicNs,
    },
    acceptedEvidence: {
      issuerKeyId: options.evidence.serverEvent.issuerKeyId,
      sequence: options.evidence.serverEvent.sequence,
      sha256: options.evidence.serverEvent.evidenceSha256,
      ackProxyEventSequence: options.evidence.acknowledgement.eventSequence,
      status: 'applied',
    },
    observation: {
      source: 'companion-satellite-sub-state',
      text: options.satellite.values.TEXT,
      color: options.satellite.values.COLOR,
      wallClock: options.satellite.wallClock,
      monotonicNs: options.satellite.monotonicNs,
    },
    capture: {
      path: `captures/${path.basename(options.captureAbsolutePath)}`,
      sha256: captureSha256,
    },
    timing: options.timing,
    versions: options.versions,
  };
  if (receipt.expectedState !== receipt.observedState) {
    throw new Error(`Expected ${receipt.expectedState}, observed ${receipt.observedState}`);
  }
  if (receipt.observation.text !== style.text || receipt.observation.color !== style.color) {
    throw new Error(
      `Companion rendered ${receipt.observation.text}/${receipt.observation.color}, expected ${style.text}/${style.color}`
    );
  }
  const relativePath = `receipts/${options.scenarioId}.json`;
  await writeJson(path.join(options.evidenceDirectory, relativePath), receipt);
  return { relativePath, receipt };
}
