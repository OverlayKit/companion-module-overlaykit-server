import { createHash } from 'node:crypto';

const STUDY = 'NODE22-PRE-ATTEMPT-BINDING-PREFLIGHT-001';
const PRECONTRACT_SCHEMA = 'overlaykit-node22-pre-attempt-binding-preflight-precontract/v1';
const RESERVATION_SCHEMA = 'overlaykit-node22-pre-attempt-binding-preflight-reservation/v1';
const TERMINAL_SCHEMA = 'overlaykit-node22-pre-attempt-binding-preflight-terminal/v1';
const PREDECESSOR_COMMIT = '1121f1dd86114da8560f31122743ae20f8d53b03';
const PREDECESSOR_TREE = '52bf8023a628d85683417bf67c42d7b7effcd912';
const PLAN_RAW_SHA256 = '2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243';
const PLAN_HASH = 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4';
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const GIT_OBJECT_PATTERN = /^[0-9a-f]{40}$/u;
const SOURCE_ROSTER = Object.freeze([
  'lab/node22-pre-attempt-binding-preflight/contract.test.mjs',
  'lab/node22-pre-attempt-binding-preflight/fixtures/synthetic-precontract.mjs',
  'lab/node22-pre-attempt-binding-preflight/integration.test.mjs',
  'lab/node22-pre-attempt-binding-preflight/package.json',
  'lab/node22-pre-attempt-binding-preflight/stage0.mjs',
  'lab/node22-pre-attempt-binding-preflight/stage0.test.mjs',
  'lab/node22-pre-attempt-binding-preflight/stage1.mjs',
  'lab/node22-pre-attempt-binding-preflight/subject-lock.json',
  'lab/node22-pre-attempt-binding-preflight/verify.mjs',
  'lab/node22-pre-attempt-binding-preflight/verify.test.mjs',
]);

export class PreAttemptBindingVerificationError extends Error {
  constructor(code) {
    super(code);
    this.name = 'PreAttemptBindingVerificationError';
    this.code = code;
  }
}

function reject(code) {
  throw new PreAttemptBindingVerificationError(code);
}

function assertion(condition, code) {
  if (!condition) reject(code);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, expected, code) {
  assertion(isPlainObject(value), code);
  const actual = Object.keys(value).sort(compareUtf8);
  const wanted = [...expected].sort(compareUtf8);
  assertion(
    actual.length === wanted.length && actual.every((key, index) => key === wanted[index]),
    code
  );
}

function canonicalize(value, seen = new Set()) {
  if (Array.isArray(value)) {
    assertion(!seen.has(value), 'canonical-value-invalid');
    seen.add(value);
    const result = value.map((entry) => canonicalize(entry, seen));
    seen.delete(value);
    return result;
  }
  if (isPlainObject(value)) {
    assertion(!seen.has(value), 'canonical-value-invalid');
    seen.add(value);
    const result = Object.fromEntries(
      Object.keys(value)
        .sort(compareUtf8)
        .map((key) => [key, canonicalize(value[key], seen)])
    );
    seen.delete(value);
    return result;
  }
  assertion(
    value === null ||
      typeof value === 'string' ||
      typeof value === 'boolean' ||
      (typeof value === 'number' && Number.isSafeInteger(value)),
    'canonical-value-invalid'
  );
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function canonicalPrettyJson(value) {
  return `${JSON.stringify(canonicalize(value), null, 2)}\n`;
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonicalHash(value) {
  return sha256(Buffer.from(canonicalJson(value), 'utf8'));
}

function validateSourceSet(sourceSet) {
  exactKeys(
    sourceSet,
    ['descriptorCount', 'descriptors', 'sha256'],
    'precontract-source-set-invalid'
  );
  assertion(
    sourceSet.descriptorCount === SOURCE_ROSTER.length &&
      Array.isArray(sourceSet.descriptors) &&
      sourceSet.descriptors.length === SOURCE_ROSTER.length,
    'precontract-source-set-invalid'
  );
  const seenPaths = new Set();
  for (const [index, descriptor] of sourceSet.descriptors.entries()) {
    exactKeys(
      descriptor,
      ['byteLength', 'gitMode', 'gitOid', 'path', 'rawSha256'],
      'precontract-source-descriptor-invalid'
    );
    assertion(
      descriptor.path === SOURCE_ROSTER[index] &&
        !seenPaths.has(descriptor.path) &&
        descriptor.gitMode === '100644' &&
        GIT_OBJECT_PATTERN.test(descriptor.gitOid) &&
        SHA256_PATTERN.test(descriptor.rawSha256) &&
        Number.isSafeInteger(descriptor.byteLength) &&
        descriptor.byteLength > 0,
      'precontract-source-descriptor-invalid'
    );
    seenPaths.add(descriptor.path);
  }
  assertion(
    SHA256_PATTERN.test(sourceSet.sha256) &&
      canonicalHash(sourceSet.descriptors) === sourceSet.sha256,
    'precontract-source-set-invalid'
  );
  return sourceSet.descriptors;
}

function parseCanonicalBytes(value, label) {
  assertion(Buffer.isBuffer(value) || value instanceof Uint8Array, `${label}-bytes-invalid`);
  const bytes = Buffer.from(value);
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    reject(`${label}-utf8-invalid`);
  }
  let document;
  try {
    document = JSON.parse(text);
  } catch {
    reject(`${label}-json-invalid`);
  }
  assertion(text === canonicalPrettyJson(document), `${label}-noncanonical`);
  return { bytes, document, rawSha256: sha256(bytes) };
}

function validatePrecontract(precontractBytes, grant) {
  const parsed = parseCanonicalBytes(precontractBytes, 'precontract');
  const value = parsed.document;
  exactKeys(
    value,
    [
      'action',
      'apparatusAnchor',
      'authority',
      'branchId',
      'governanceBindings',
      'normative',
      'predecessorAnchor',
      'schemaVersion',
      'sourceSet',
      'study',
      'subjectRawSha256',
      'synthetic',
    ],
    'precontract-shape-invalid'
  );
  exactKeys(value.apparatusAnchor, ['commit', 'tree'], 'precontract-shape-invalid');
  exactKeys(
    value.governanceBindings,
    ['chg0042RawSha256', 'manifestContentHash', 'manifestRawSha256', 'planHash', 'planRawSha256'],
    'precontract-shape-invalid'
  );
  exactKeys(value.predecessorAnchor, ['commit', 'tree'], 'precontract-shape-invalid');
  const sourceDescriptors = validateSourceSet(value.sourceSet);
  assertion(
    value.schemaVersion === PRECONTRACT_SCHEMA &&
      value.study === STUDY &&
      value.synthetic === true &&
      value.normative === false &&
      value.authority === 'none' &&
      value.action === null &&
      value.branchId === 'launch-failure' &&
      value.predecessorAnchor.commit === PREDECESSOR_COMMIT &&
      value.predecessorAnchor.tree === PREDECESSOR_TREE &&
      value.governanceBindings.planRawSha256 === PLAN_RAW_SHA256 &&
      value.governanceBindings.planHash === PLAN_HASH,
    'precontract-policy-invalid'
  );
  assertion(
    GIT_OBJECT_PATTERN.test(value.apparatusAnchor.commit) &&
      GIT_OBJECT_PATTERN.test(value.apparatusAnchor.tree),
    'precontract-git-anchor-invalid'
  );
  for (const candidate of [
    value.governanceBindings.chg0042RawSha256,
    value.governanceBindings.manifestContentHash,
    value.governanceBindings.manifestRawSha256,
    value.sourceSet.sha256,
    value.subjectRawSha256,
  ]) {
    assertion(SHA256_PATTERN.test(candidate), 'precontract-digest-invalid');
  }
  const subjectDescriptor = sourceDescriptors.find(
    (descriptor) => descriptor.path === 'lab/node22-pre-attempt-binding-preflight/subject-lock.json'
  );
  assertion(
    subjectDescriptor?.rawSha256 === value.subjectRawSha256,
    'precontract-subject-binding-invalid'
  );
  assertion(
    grant === `${STUDY}:one-synthetic-attempt:sha256:${parsed.rawSha256}`,
    'precontract-grant-invalid'
  );
  return parsed;
}

function validateReservation(precontractReceipt, grant, reservationBytes) {
  const parsed = parseCanonicalBytes(reservationBytes, 'reservation');
  const value = parsed.document;
  exactKeys(
    value,
    [
      'action',
      'authority',
      'branchId',
      'grant',
      'normative',
      'precontract',
      'precontractRawSha256',
      'schemaVersion',
      'stage',
      'study',
      'synthetic',
    ],
    'reservation-shape-invalid'
  );
  assertion(
    value.schemaVersion === RESERVATION_SCHEMA &&
      value.study === STUDY &&
      value.synthetic === true &&
      value.normative === false &&
      value.authority === 'none' &&
      value.action === null &&
      value.branchId === 'launch-failure' &&
      value.stage === 'stage-0-durable-before-stage-1' &&
      value.grant === grant &&
      value.precontractRawSha256 === precontractReceipt.rawSha256 &&
      canonicalJson(value.precontract) === canonicalJson(precontractReceipt.document),
    'reservation-binding-invalid'
  );
  return parsed;
}

function expectedReservation(precontractReceipt, grant) {
  return {
    action: null,
    authority: 'none',
    branchId: 'launch-failure',
    grant,
    normative: false,
    precontract: canonicalize(precontractReceipt.document),
    precontractRawSha256: precontractReceipt.rawSha256,
    schemaVersion: RESERVATION_SCHEMA,
    stage: 'stage-0-durable-before-stage-1',
    study: STUDY,
    synthetic: true,
  };
}

export function verifyPreAttemptReservation({ grant, precontractBytes, reservationBytes } = {}) {
  const precontract = validatePrecontract(precontractBytes, grant);
  const reservation = validateReservation(precontract, grant, reservationBytes);
  return {
    action: null,
    authority: 'none',
    branchId: 'launch-failure',
    precontractRawSha256: precontract.rawSha256,
    reservationRawSha256: reservation.rawSha256,
    sourceSetSha256: precontract.document.sourceSet.sha256,
    status: 'candidate-reservation-binding-reconstructed',
    study: STUDY,
    synthetic: true,
  };
}

export function verifyLaunchFailure({
  grant,
  precontractBytes,
  reservationBytes,
  terminalBytes,
} = {}) {
  const reservationReceipt = verifyPreAttemptReservation({
    grant,
    precontractBytes,
    reservationBytes,
  });
  const parsed = parseCanonicalBytes(terminalBytes, 'terminal');
  const value = parsed.document;
  exactKeys(
    value,
    [
      'action',
      'attempts',
      'authority',
      'branchId',
      'launchError',
      'normative',
      'precontractRawSha256',
      'reservationRawSha256',
      'schemaVersion',
      'semanticSha256',
      'study',
      'synthetic',
    ],
    'terminal-shape-invalid'
  );
  exactKeys(value.launchError, ['code', 'syscall'], 'terminal-shape-invalid');
  const { semanticSha256, ...body } = value;
  assertion(
    value.schemaVersion === TERMINAL_SCHEMA &&
      value.study === STUDY &&
      value.synthetic === true &&
      value.normative === false &&
      value.authority === 'none' &&
      value.action === null &&
      value.branchId === 'launch-failure' &&
      Array.isArray(value.attempts) &&
      value.attempts.length === 0 &&
      value.launchError.code === 'SYNTHETIC_STAGE1_LAUNCH_FAILED' &&
      value.launchError.syscall === 'synthetic-stage1-launch' &&
      value.precontractRawSha256 === reservationReceipt.precontractRawSha256 &&
      value.reservationRawSha256 === reservationReceipt.reservationRawSha256 &&
      semanticSha256 === canonicalHash(body),
    'terminal-binding-invalid'
  );
  return {
    action: null,
    attempts: 0,
    authority: 'none',
    branchId: 'launch-failure',
    status: 'candidate-launch-failure-reconstructed',
    study: STUDY,
    terminalRawSha256: parsed.rawSha256,
    terminalSemanticSha256: semanticSha256,
  };
}

export function verifyPartialWriteControl({
  firstWriteReceipt,
  grant,
  partialReservationBytes,
  precontractBytes,
  retryReceipt,
  stage1Events,
} = {}) {
  const precontract = validatePrecontract(precontractBytes, grant);
  const expected = Buffer.from(
    canonicalPrettyJson(expectedReservation(precontract, grant)),
    'utf8'
  );
  assertion(
    Buffer.isBuffer(partialReservationBytes) || partialReservationBytes instanceof Uint8Array,
    'partial-write-observed-bytes-invalid'
  );
  const partial = Buffer.from(partialReservationBytes);
  exactKeys(
    firstWriteReceipt,
    ['errorCode', 'expectedByteLength', 'observedByteLength', 'observedRawSha256'],
    'partial-write-receipt-invalid'
  );
  exactKeys(retryReceipt, ['errorCode'], 'partial-write-retry-receipt-invalid');
  assertion(
    partial.length > 0 &&
      partial.length < expected.length &&
      expected.subarray(0, partial.length).equals(partial),
    'partial-write-not-strict-prefix'
  );
  assertion(
    firstWriteReceipt.errorCode === 'synthetic-partial-write-injected' &&
      firstWriteReceipt.expectedByteLength === expected.length &&
      firstWriteReceipt.observedByteLength === partial.length &&
      firstWriteReceipt.observedRawSha256 === sha256(partial),
    'partial-write-receipt-invalid'
  );
  assertion(
    retryReceipt.errorCode === 'reservation-already-consumed',
    'partial-write-reservation-not-consumed'
  );
  assertion(
    Array.isArray(stage1Events) && stage1Events.length === 0,
    'partial-write-stage1-loaded'
  );
  return {
    action: null,
    assessed: false,
    authority: 'none',
    controlId: 'partial-write',
    expectedByteLength: expected.length,
    expectedRawSha256: sha256(expected),
    observedByteLength: partial.length,
    observedRawSha256: sha256(partial),
    precontractRawSha256: precontract.rawSha256,
    reason: 'candidate-receipts-are-internally-consistent',
    status: 'candidate-control-envelope-consistent',
    study: STUDY,
    synthetic: true,
  };
}

export const verifierConstants = Object.freeze({
  branchId: 'launch-failure',
  controlId: 'partial-write',
  predecessorCommit: PREDECESSOR_COMMIT,
  predecessorTree: PREDECESSOR_TREE,
  sourceDescriptorCount: SOURCE_ROSTER.length,
  sourceRoster: SOURCE_ROSTER,
  study: STUDY,
});
