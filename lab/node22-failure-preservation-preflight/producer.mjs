import { createHash } from 'node:crypto';

const STUDY = 'NODE22-FAILURE-PRESERVATION-PREFLIGHT-001';
const RESERVATION_SCHEMA = 'overlaykit-node22-failure-preservation-preflight-reservation/v1';
const TERMINAL_SCHEMA = 'overlaykit-node22-failure-preservation-preflight-terminal/v1';
const PINNED_SUBJECT_RAW_SHA256 =
  '32faedd0bf9202190ee9fdbae0c84baff05764dd637dcf4b2dfd6d4487aca144';

export const BRANCHES = Object.freeze([
  'launch-failure',
  'malformed-output',
  'divergent-attempts',
  'exact-incompatibility',
  'success',
]);

const EXPECTED_ATTEMPT_COUNTS = Object.freeze({
  'launch-failure': 0,
  'malformed-output': 1,
  'divergent-attempts': 2,
  'exact-incompatibility': 2,
  success: 2,
});

const SOURCE_ANCHOR = Object.freeze({
  blockingRunnerRawSha256: '5c5bd2b73500c98779e8b0fea8b9d149f7d66815ef601a2bd5944b54f8bf457b',
  chg0036RawSha256: '2ff88d94d8768b23548e64d066922aec3e1d0b8ba7aaab27907f8af0432bf492',
  chg0038RawSha256: '3b0a2fb3dfbfa08d59df881df5f097bf66758eb6563e223012f790aaa8c8d77e',
  chg0039RawSha256: '6d062d4a1aa236d441481845549bea65d3a2b3b11498b34361b9a18c4a6d5a85',
  mainCommit: 'd1caa3bff1b47b61c661e4ec4582add4f9c795c3',
  mainTree: 'd83fa14a3c25189260921a0c08862e6540a52baf',
  planHash: 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4',
  planRawSha256: '2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243',
  predecessorManifestContentHash:
    'efa010a5c268dca8b364d0efe669f8315d415ad19ead95b75e8b155d664d92a1',
  predecessorManifestRawSha256: 'dc2666418b273d752f3f9d06ebe354515dad5eb06ec5d1aa597732806bf2b465',
  profileHash: '9b55c034c16a653d497672374c12d94f6f609c77f23aecd0f0d437e230cb4ebd',
});

export class FailurePreservationProducerError extends Error {
  constructor(code) {
    super(code);
    this.name = 'FailurePreservationProducerError';
    this.code = code;
  }
}

function reject(code) {
  throw new FailurePreservationProducerError(code);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function canonicalize(value, seen = new Set()) {
  if (Array.isArray(value)) {
    if (seen.has(value)) reject('canonical-value-cyclic');
    seen.add(value);
    const result = value.map((entry) => canonicalize(entry, seen));
    seen.delete(value);
    return result;
  }

  if (isPlainObject(value)) {
    if (seen.has(value)) reject('canonical-value-cyclic');
    seen.add(value);
    const result = Object.fromEntries(
      Object.keys(value)
        .sort(compareUtf8)
        .map((key) => [key, canonicalize(value[key], seen)])
    );
    seen.delete(value);
    return result;
  }

  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value))
  ) {
    return value;
  }

  reject('canonical-value-invalid');
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function canonicalPrettyJson(value) {
  return `${JSON.stringify(canonicalize(value), null, 2)}\n`;
}

export function sha256(bytes) {
  if (typeof bytes !== 'string' && !Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
    reject('sha256-input-invalid');
  }
  return createHash('sha256').update(bytes).digest('hex');
}

export function canonicalHash(value) {
  return sha256(Buffer.from(canonicalJson(value), 'utf8'));
}

function hasExactKeys(value, expectedKeys) {
  if (!isPlainObject(value)) return false;
  const actual = Object.keys(value).sort(compareUtf8);
  const expected = [...expectedKeys].sort(compareUtf8);
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isSha256(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value);
}

function validateBranchOrdinal(branchId, ordinal) {
  const index = BRANCHES.indexOf(branchId);
  if (index === -1) reject('branch-id-invalid');
  if (ordinal !== index + 1) reject('branch-ordinal-invalid');
}

function validateSourceAnchor(sourceAnchor) {
  const keys = Object.keys(SOURCE_ANCHOR);
  if (!hasExactKeys(sourceAnchor, keys)) reject('source-anchor-shape-invalid');
  if (canonicalJson(sourceAnchor) !== canonicalJson(SOURCE_ANCHOR)) {
    reject('source-anchor-drift');
  }
  return canonicalize(sourceAnchor);
}

function validateLaunchError(launchError) {
  if (launchError === null) return null;
  if (
    !hasExactKeys(launchError, ['code', 'syscall']) ||
    typeof launchError.code !== 'string' ||
    launchError.code.length === 0 ||
    typeof launchError.syscall !== 'string' ||
    launchError.syscall.length === 0
  ) {
    reject('launch-error-shape-invalid');
  }
  return {
    code: launchError.code,
    syscall: launchError.syscall,
  };
}

function encodeBinary(bytes) {
  if (!Buffer.isBuffer(bytes)) reject('attempt-bytes-invalid');
  const detached = Buffer.from(bytes);
  return {
    base64: detached.toString('base64'),
    byteLength: detached.length,
    sha256: sha256(detached),
  };
}

function encodeAttempt(attempt, expectedOrdinal) {
  if (
    !hasExactKeys(attempt, ['exitCode', 'ordinal', 'signal', 'stderr', 'stdout']) ||
    attempt.ordinal !== expectedOrdinal ||
    !(
      attempt.exitCode === null ||
      (Number.isSafeInteger(attempt.exitCode) && attempt.exitCode >= 0)
    ) ||
    !(attempt.signal === null || (typeof attempt.signal === 'string' && attempt.signal.length > 0))
  ) {
    reject('attempt-shape-invalid');
  }

  return {
    exitCode: attempt.exitCode,
    ordinal: attempt.ordinal,
    signal: attempt.signal,
    stderr: encodeBinary(attempt.stderr),
    stdout: encodeBinary(attempt.stdout),
  };
}

export function makeReservation(input) {
  if (!hasExactKeys(input, ['branchId', 'ordinal', 'sourceAnchor', 'subjectRawSha256'])) {
    reject('reservation-input-shape-invalid');
  }

  validateBranchOrdinal(input.branchId, input.ordinal);
  if (!isSha256(input.subjectRawSha256) || input.subjectRawSha256 !== PINNED_SUBJECT_RAW_SHA256) {
    reject('subject-anchor-drift');
  }

  return {
    action: null,
    authority: 'none',
    branchId: input.branchId,
    normative: false,
    ordinal: input.ordinal,
    schemaVersion: RESERVATION_SCHEMA,
    sourceAnchor: validateSourceAnchor(input.sourceAnchor),
    study: STUDY,
    subjectRawSha256: input.subjectRawSha256,
    synthetic: true,
  };
}

export function produceTerminalEnvelope(input) {
  if (!hasExactKeys(input, ['branchId', 'ordinal', 'reservationRawSha256', 'transport'])) {
    reject('terminal-input-shape-invalid');
  }

  validateBranchOrdinal(input.branchId, input.ordinal);
  if (!isSha256(input.reservationRawSha256)) reject('reservation-anchor-invalid');
  if (!hasExactKeys(input.transport, ['attempts', 'launchError'])) {
    reject('transport-shape-invalid');
  }

  const launchError = validateLaunchError(input.transport.launchError);
  if (!Array.isArray(input.transport.attempts)) reject('attempt-roster-invalid');
  const expectedAttemptCount = EXPECTED_ATTEMPT_COUNTS[input.branchId];
  if (input.transport.attempts.length !== expectedAttemptCount) {
    reject('attempt-roster-invalid');
  }
  if (
    (input.branchId === 'launch-failure' && launchError === null) ||
    (input.branchId !== 'launch-failure' && launchError !== null)
  ) {
    reject('launch-error-branch-invalid');
  }

  const attempts = input.transport.attempts.map((attempt, index) =>
    encodeAttempt(attempt, index + 1)
  );
  const body = {
    action: null,
    attempts,
    authority: 'none',
    branchId: input.branchId,
    launchError,
    normative: false,
    ordinal: input.ordinal,
    reservationRawSha256: input.reservationRawSha256,
    schemaVersion: TERMINAL_SCHEMA,
    study: STUDY,
    synthetic: true,
  };

  return {
    ...body,
    semanticSha256: canonicalHash(body),
  };
}
