import { readFile } from 'node:fs/promises';
import path from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import { proxyEvents, STATE_STYLE } from './lib/evidence.mjs';
import { readJson, sha256File } from './lib/util.mjs';

const LAB_DIRECTORY = path.dirname(new URL(import.meta.url).pathname);
const INPUT_LOCK_PATH = path.join(LAB_DIRECTORY, 'inputs.lock.json');
const RECEIPT_SCHEMA_PATH = path.join(LAB_DIRECTORY, 'schemas/receipt.schema.json');
const RUN_SCHEMA_PATH = path.join(LAB_DIRECTORY, 'schemas/run.schema.json');
const REQUIRED_STATES = new Set([
  'active',
  'inactive',
  'unknown',
  'disconnected',
  'failed',
  'unavailable',
]);
const REQUIRED_ACTIONS = new Set(['visibility.show', 'visibility.hide', 'visibility.toggle']);

function assertion(condition, message) {
  if (!condition) throw new Error(message);
}

function dateTime(value) {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

async function validators(overlaykitCommit) {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  ajv.addFormat('date-time', dateTime);
  const receiptSchema = await readJson(RECEIPT_SCHEMA_PATH);
  receiptSchema.properties.versions.properties.overlaykitCommit.const = overlaykitCommit;
  const receipt = ajv.compile(receiptSchema);
  const run = ajv.compile(await readJson(RUN_SCHEMA_PATH));
  return { receipt, run };
}

function schemaError(name, validator) {
  return `${name} schema failed: ${ajvErrors(validator.errors)}`;
}

function ajvErrors(errors) {
  return (errors ?? []).map((error) => `${error.instancePath || '/'} ${error.message}`).join('; ');
}

function eventBySequence(events, sequence) {
  const matches = events.filter((event) => event.eventSequence === sequence);
  assertion(matches.length === 1, `Proxy event sequence ${sequence} is missing or ambiguous`);
  return matches[0];
}

async function verifyReceipt(receipt, context) {
  const valid = context.validateReceipt(receipt);
  assertion(valid, schemaError(receipt.scenarioId ?? 'receipt', context.validateReceipt));
  assertion(receipt.runId === context.run.runId, `${receipt.scenarioId} belongs to another run`);
  assertion(
    receipt.versions.companion === context.run.inputs.companion.version,
    `${receipt.scenarioId} Companion version mismatch`
  );
  assertion(
    receipt.versions.overlaykitCommit === context.run.inputs.overlaykit.commit,
    `${receipt.scenarioId} OverlayKit version mismatch`
  );
  assertion(
    receipt.versions.moduleArchiveSha256 === context.run.moduleArchiveSha256,
    `${receipt.scenarioId} module archive mismatch`
  );
  assertion(
    receipt.versions.labDefinitionSha256 === context.run.labDefinitionSha256,
    `${receipt.scenarioId} lab definition mismatch`
  );
  assertion(
    receipt.expectedState === receipt.observedState,
    `${receipt.scenarioId} expected and observed states differ`
  );
  const expectedStyle = STATE_STYLE[receipt.observedState];
  assertion(
    receipt.observation.text === expectedStyle.text &&
      receipt.observation.color === expectedStyle.color,
    `${receipt.scenarioId} Companion UI style does not identify ${receipt.observedState}`
  );

  const capturePath = path.join(context.directory, receipt.capture.path);
  assertion(
    path.dirname(capturePath) === path.join(context.directory, 'captures'),
    `${receipt.scenarioId} capture escaped the evidence directory`
  );
  const capture = await readFile(capturePath);
  assertion(
    capture.length >= 10_000 && capture.subarray(1, 4).toString('ascii') === 'PNG',
    `${receipt.scenarioId} capture is not a substantial PNG`
  );
  assertion(
    (await sha256File(capturePath)) === receipt.capture.sha256,
    `${receipt.scenarioId} capture hash mismatch`
  );

  const serverEvent = eventBySequence(context.events, receipt.justification.proxyEventSequence);
  assertion(
    serverEvent.kind === 'frame.forwarded' && serverEvent.direction === 'server-to-companion',
    `${receipt.scenarioId} justification is not a forwarded server frame`
  );
  assertion(
    serverEvent.messageType === receipt.justification.serverMessageType,
    `${receipt.scenarioId} server event type mismatch`
  );
  assertion(
    serverEvent.issuerKeyId === receipt.acceptedEvidence.issuerKeyId &&
      serverEvent.sequence === receipt.acceptedEvidence.sequence &&
      serverEvent.evidenceSha256 === receipt.acceptedEvidence.sha256,
    `${receipt.scenarioId} accepted evidence does not identify its server frame`
  );
  const observation = serverEvent.observations?.find(
    (item) => item.controlId === receipt.justification.controlId
  );
  assertion(observation, `${receipt.scenarioId} server frame lacks its justifying control`);
  assertion(
    observation.revision === receipt.justification.revision &&
      observation.value === receipt.justification.value,
    `${receipt.scenarioId} justifying observation mismatch`
  );

  const acknowledgement = eventBySequence(
    context.events,
    receipt.acceptedEvidence.ackProxyEventSequence
  );
  assertion(
    acknowledgement.kind === 'frame.observed' &&
      acknowledgement.direction === 'companion-to-server' &&
      acknowledgement.messageType === 'device.state.ack' &&
      acknowledgement.status === 'applied',
    `${receipt.scenarioId} accepted evidence lacks an applied Companion ACK`
  );
  assertion(
    acknowledgement.issuerKeyId === receipt.acceptedEvidence.issuerKeyId &&
      acknowledgement.sequence === receipt.acceptedEvidence.sequence &&
      acknowledgement.evidenceSha256 === receipt.acceptedEvidence.sha256,
    `${receipt.scenarioId} applied ACK hash mismatch`
  );
  assertion(
    acknowledgement.eventSequence > serverEvent.eventSequence,
    `${receipt.scenarioId} ACK predates its server frame`
  );

  if (receipt.invocation && receipt.timing.authoritativeWithinDeadline) {
    assertion(
      receipt.timing.durationMs <= receipt.timing.deadlineMs &&
        receipt.timing.deadlineExpired === false,
      `${receipt.scenarioId} claims a late authoritative state as timely`
    );
  }
  if (receipt.timing.deadlineExpired) {
    assertion(
      receipt.timing.authoritativeWithinDeadline === false &&
        receipt.timing.lateEvidenceCannotPass === true,
      `${receipt.scenarioId} permits late evidence to pass`
    );
  }
  if (receipt.observedState === 'unknown') {
    assertion(
      receipt.justification.kind === 'accepted-evidence-expired' && receipt.timing.deadlineExpired,
      `${receipt.scenarioId} unknown state lacks expired accepted evidence`
    );
  }
  if (receipt.observedState === 'disconnected') {
    assertion(
      receipt.justification.kind === 'transport-closed',
      `${receipt.scenarioId} disconnected state lacks transport evidence`
    );
    assertion(
      context.events.some(
        (event) =>
          event.kind === 'transport.closed' && event.eventSequence > serverEvent.eventSequence
      ),
      `${receipt.scenarioId} has no observed transport closure`
    );
  }
  if (receipt.observedState === 'failed') {
    assertion(
      receipt.justification.kind === 'protocol-violation',
      `${receipt.scenarioId} failed state lacks protocol evidence`
    );
    assertion(
      context.events.some(
        (event) =>
          event.kind === 'fault.protocol_failure_injected' &&
          event.eventSequence > serverEvent.eventSequence
      ),
      `${receipt.scenarioId} has no controlled protocol failure`
    );
  }
  if (receipt.observedState === 'unavailable') {
    assertion(
      receipt.justification.kind === 'authorized-catalog-absence',
      `${receipt.scenarioId} unavailable state lacks catalog evidence`
    );
  }
}

function verifyRunPolicy(run, lockedInputs) {
  assertion(
    run.network.endpoint === 'ws://172.31.34.10:8081/device' && run.network.loopback === false,
    'Product traffic did not cross the locked non-loopback boundary'
  );
  assertion(run.network.tailscale === false, 'Tailscale is not canonical H-034 evidence');
  assertion(run.network.cloud === false, 'Cloud dependencies are not canonical H-034 evidence');
  if (run.classification === 'canonical') {
    assertion(
      run.inputs.overlaykit.repository === 'https://github.com/OverlayKit/overlaykit',
      'Canonical OverlayKit input is not the public repository'
    );
  } else {
    assertion(
      ['https://github.com/OverlayKit/overlaykit', 'local-supplemental-source'].includes(
        run.inputs.overlaykit.repository
      ),
      'Supplemental OverlayKit input has an unsupported source'
    );
  }
  assertion(
    /^[0-9a-f]{40}$/u.test(run.inputs.overlaykit.commit),
    'OverlayKit input lacks an exact Git commit'
  );
  if (run.classification === 'canonical') {
    assertion(
      run.inputs.overlaykit.commit === lockedInputs.overlaykit.commit,
      'Canonical evidence does not use the locked OverlayKit commit'
    );
  }
  assertion(
    run.inputs.companion.image.startsWith('ghcr.io/bitfocus/companion/'),
    'Companion input is not the public official image'
  );
  assertion(
    run.nodes.every(
      (node) =>
        node.os === 'ubuntu' && node.osVersion === '24.04' && !node.address.startsWith('127.')
    ),
    'H-034 nodes are not two non-loopback Ubuntu 24.04 systems'
  );
  assertion(
    run.provisioning.ephemeral && !run.provisioning.secretPersisted,
    'Provisioning persisted a bearer or used non-ephemeral authority'
  );
  assertion(
    Object.values(run.semanticAssertions).every((value) => value === true),
    'Run contains a failed semantic assertion'
  );
}

export async function verifyEvidence(runPath) {
  const absoluteRunPath = path.resolve(runPath);
  const directory = path.dirname(absoluteRunPath);
  const run = await readJson(absoluteRunPath);
  const lockedInputs = await readJson(INPUT_LOCK_PATH);
  assertion(
    /^[0-9a-f]{40}$/u.test(run.inputs?.overlaykit?.commit ?? ''),
    'Run lacks an exact OverlayKit Git commit'
  );
  const validate = await validators(run.inputs?.overlaykit?.commit);
  assertion(validate.run(run), schemaError('run', validate.run));
  verifyRunPolicy(run, lockedInputs);
  const events = await proxyEvents(directory);
  const eventSequences = events.map((event) => event.eventSequence);
  assertion(
    new Set(eventSequences).size === eventSequences.length,
    'Proxy event sequence is not globally unique within the run'
  );
  assertion(
    eventSequences.every((value, index) => index === 0 || value > eventSequences[index - 1]),
    'Proxy event sequence is not globally monotonic'
  );
  assertion(
    events.some((event) => event.kind === 'transport.open'),
    'No actual Companion-to-OverlayKit transport was observed'
  );

  const states = new Set();
  const actions = new Set();
  const receipts = [];
  for (const relativePath of run.receipts) {
    const receiptPath = path.join(directory, relativePath);
    assertion(
      path.dirname(receiptPath) === path.join(directory, 'receipts'),
      `Receipt ${relativePath} escaped the evidence directory`
    );
    const receipt = await readJson(receiptPath);
    await verifyReceipt(receipt, {
      run,
      directory,
      events,
      validateReceipt: validate.receipt,
    });
    states.add(receipt.observedState);
    if (receipt.invocation) actions.add(receipt.invocation.action);
    receipts.push(receipt);
  }
  assertion(
    [...REQUIRED_STATES].every((state) => states.has(state)),
    'Run does not visibly prove all six Companion states'
  );
  assertion(
    [...REQUIRED_ACTIONS].every((action) => actions.has(action)),
    'Run does not invoke show, hide, and toggle through real Companion buttons'
  );
  const timeout = receipts.find((receipt) => receipt.scenarioId === 'ack-result-only-timeout');
  const lateRejected = receipts.find(
    (receipt) => receipt.scenarioId === 'late-evidence-remains-unknown'
  );
  const late = receipts.find((receipt) => receipt.scenarioId === 'late-authoritative-recovery');
  assertion(
    timeout?.observedState === 'unknown',
    'Ack/result-only timeout did not project unknown'
  );
  assertion(
    lateRejected?.observedState === 'unknown' &&
      lateRejected.timing.durationMs > 3000 &&
      lateRejected.timing.deadlineExpired &&
      !lateRejected.timing.authoritativeWithinDeadline,
    'Late authoritative evidence changed the unknown state'
  );
  assertion(
    late?.timing.durationMs > 3000 &&
      late.timing.deadlineExpired &&
      !late.timing.authoritativeWithinDeadline &&
      late.observedState === 'inactive' &&
      late.acceptedEvidence.sequence > lateRejected.acceptedEvidence.sequence &&
      events.some(
        (event) =>
          event.kind === 'transport.closed' &&
          event.eventSequence > lateRejected.justification.proxyEventSequence &&
          event.eventSequence < late.justification.proxyEventSequence
      ),
    'Recovery did not require fresh post-timeout authority'
  );

  const serializedEvidence = await Promise.all(
    run.receipts.map((relativePath) => readFile(path.join(directory, relativePath), 'utf8'))
  );
  assertion(
    !serializedEvidence.some((value) => /Bearer\s+|okd_[A-Za-z0-9_-]+/u.test(value)),
    'Persisted evidence contains a bearer secret'
  );
  return {
    runId: run.runId,
    classification: run.classification,
    receiptCount: receipts.length,
    states: [...states].sort(),
    actions: [...actions].sort(),
    semanticAssertions: run.semanticAssertions,
  };
}
