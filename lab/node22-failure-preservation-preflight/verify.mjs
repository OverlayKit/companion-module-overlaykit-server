import { createHash } from 'node:crypto';

const STUDY = 'NODE22-FAILURE-PRESERVATION-PREFLIGHT-001';
const SUBJECT_RAW_SHA256 = '32faedd0bf9202190ee9fdbae0c84baff05764dd637dcf4b2dfd6d4487aca144';
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const USTAR_BLOCK_BYTES = 512;
const USTAR_END_BYTES = USTAR_BLOCK_BYTES * 2;

const BRANCHES = Object.freeze([
  'launch-failure',
  'malformed-output',
  'divergent-attempts',
  'exact-incompatibility',
  'success',
]);

const REASON_CODES = Object.freeze({
  'launch-failure': 'synthetic-launch-failed',
  'malformed-output': 'synthetic-output-malformed',
  'divergent-attempts': 'synthetic-attempts-diverged',
  'exact-incompatibility': 'synthetic-exact-expectation-mismatch',
  success: 'synthetic-exact-expectation-satisfied',
});

const EXPECTED_PROTOCOL = Object.freeze({
  compatibility: 'compatible',
  marker: 'node22-failure-preservation-v1',
});

const RESERVATION_KEYS = Object.freeze([
  'action',
  'authority',
  'branchId',
  'normative',
  'ordinal',
  'schemaVersion',
  'sourceAnchor',
  'study',
  'subjectRawSha256',
  'synthetic',
]);

const TERMINAL_KEYS = Object.freeze([
  'action',
  'attempts',
  'authority',
  'branchId',
  'launchError',
  'normative',
  'ordinal',
  'reservationRawSha256',
  'schemaVersion',
  'semanticSha256',
  'study',
  'synthetic',
]);

const ATTEMPT_KEYS = Object.freeze(['exitCode', 'ordinal', 'signal', 'stderr', 'stdout']);
const BINARY_KEYS = Object.freeze(['base64', 'byteLength', 'sha256']);
const SOURCE_ANCHOR_KEYS = Object.freeze([
  'blockingRunnerRawSha256',
  'chg0036RawSha256',
  'chg0038RawSha256',
  'chg0039RawSha256',
  'mainCommit',
  'mainTree',
  'planHash',
  'planRawSha256',
  'predecessorManifestContentHash',
  'predecessorManifestRawSha256',
  'profileHash',
]);

const EXPECTED_ATTEMPT_COUNTS = Object.freeze({
  'launch-failure': 0,
  'malformed-output': 1,
  'divergent-attempts': 2,
  'exact-incompatibility': 2,
  success: 2,
});

export class FailurePreservationVerificationError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = 'FailurePreservationVerificationError';
    this.code = code;
  }
}

function reject(code, message = code) {
  throw new FailurePreservationVerificationError(code, message);
}

function assertion(condition, code, message = code) {
  if (!condition) reject(code, message);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
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

function canonicalValue(value, seen = new Set()) {
  if (Array.isArray(value)) {
    assertion(!seen.has(value), 'canonical-value-invalid');
    seen.add(value);
    const result = value.map((entry) => canonicalValue(entry, seen));
    seen.delete(value);
    return result;
  }

  if (isPlainObject(value)) {
    assertion(!seen.has(value), 'canonical-value-invalid');
    seen.add(value);
    const result = Object.fromEntries(
      Object.keys(value)
        .sort(compareUtf8)
        .map((key) => [key, canonicalValue(value[key], seen)])
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
  return JSON.stringify(canonicalValue(value));
}

function canonicalPrettyJson(value) {
  return `${JSON.stringify(canonicalValue(value), null, 2)}\n`;
}

function canonicalHash(value) {
  return sha256(Buffer.from(canonicalJson(value), 'utf8'));
}

function toBytes(value, label) {
  assertion(
    Buffer.isBuffer(value) || value instanceof Uint8Array,
    'evidence-bytes-invalid',
    `${label} must be bytes`
  );
  return Buffer.from(value);
}

function parseUtf8Json(bytes, label, { canonical = true } = {}) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    reject('evidence-utf8-invalid', `${label} is not valid UTF-8`);
  }

  let value;
  try {
    value = JSON.parse(text);
  } catch {
    reject('evidence-json-invalid', `${label} is not valid JSON`);
  }

  const expected = canonical ? canonicalPrettyJson(value) : `${JSON.stringify(value, null, 2)}\n`;
  assertion(text === expected, 'evidence-json-noncanonical', `${label} bytes are not canonical`);
  return value;
}

function validateAuthority(value, code) {
  assertion(
    value.synthetic === true &&
      value.normative === false &&
      value.authority === 'none' &&
      value.action === null,
    code
  );
}

function validateSubject(subjectBytes) {
  const bytes = toBytes(subjectBytes, 'subject');
  assertion(sha256(bytes) === SUBJECT_RAW_SHA256, 'subject-raw-sha256-mismatch');
  const subject = parseUtf8Json(bytes, 'subject', { canonical: false });
  assertion(
    subject?.schemaVersion === 'overlaykit-node22-failure-preservation-preflight-subject/v1' &&
      subject.study === STUDY &&
      subject.syntheticOnly === true &&
      subject.normative === false &&
      subject.authority === 'none' &&
      subject.action === null &&
      subject.terminalPartition?.expectedCaseCount === BRANCHES.length &&
      Array.isArray(subject.terminalPartition?.precedence) &&
      subject.terminalPartition.precedence.length === BRANCHES.length &&
      subject.terminalPartition.precedence.every(
        (branchId, ordinal) => branchId === BRANCHES[ordinal]
      ),
    'subject-shape-invalid'
  );
  return { bytes, subject };
}

function validateSourceAnchor(sourceAnchor) {
  exactKeys(sourceAnchor, SOURCE_ANCHOR_KEYS, 'reservation-shape-invalid');
  for (const [key, value] of Object.entries(sourceAnchor)) {
    const pattern = key === 'mainCommit' || key === 'mainTree' ? /^[0-9a-f]{40}$/u : SHA256_PATTERN;
    assertion(typeof value === 'string' && pattern.test(value), 'reservation-shape-invalid');
  }
}

function validateReservation(reservationBytes, subjectReceipt) {
  const bytes = toBytes(reservationBytes, 'reservation');
  const reservation = parseUtf8Json(bytes, 'reservation');
  exactKeys(reservation, RESERVATION_KEYS, 'reservation-shape-invalid');
  validateAuthority(reservation, 'authority-overclaim');
  assertion(
    reservation.schemaVersion ===
      'overlaykit-node22-failure-preservation-preflight-reservation/v1' &&
      reservation.study === STUDY &&
      reservation.subjectRawSha256 === SUBJECT_RAW_SHA256 &&
      BRANCHES[reservation.ordinal - 1] === reservation.branchId,
    'reservation-shape-invalid'
  );
  validateSourceAnchor(reservation.sourceAnchor);
  assertion(
    canonicalJson(reservation.sourceAnchor) === canonicalJson(subjectReceipt.subject.sourceAnchor),
    'reservation-source-anchor-mismatch'
  );
  return { bytes, reservation, rawSha256: sha256(bytes) };
}

function decodeBinary(binary, label) {
  exactKeys(binary, BINARY_KEYS, 'terminal-shape-invalid');
  assertion(
    typeof binary.base64 === 'string' &&
      Number.isSafeInteger(binary.byteLength) &&
      binary.byteLength >= 0 &&
      typeof binary.sha256 === 'string' &&
      SHA256_PATTERN.test(binary.sha256),
    'terminal-shape-invalid'
  );
  assertion(BASE64_PATTERN.test(binary.base64), 'binary-base64-invalid', label);
  const bytes = Buffer.from(binary.base64, 'base64');
  assertion(bytes.toString('base64') === binary.base64, 'binary-base64-invalid', label);
  assertion(bytes.byteLength === binary.byteLength, 'binary-byte-length-mismatch', label);
  assertion(sha256(bytes) === binary.sha256, 'binary-sha256-mismatch', label);
  return bytes;
}

function validateAttempt(attempt, index) {
  exactKeys(attempt, ATTEMPT_KEYS, 'terminal-shape-invalid');
  assertion(
    attempt.ordinal === index + 1 &&
      (attempt.exitCode === null || Number.isSafeInteger(attempt.exitCode)) &&
      (attempt.signal === null ||
        (typeof attempt.signal === 'string' && attempt.signal.length > 0)),
    'terminal-shape-invalid'
  );
  return {
    exitCode: attempt.exitCode,
    ordinal: attempt.ordinal,
    signal: attempt.signal,
    stderr: decodeBinary(attempt.stderr, `attempt ${index} stderr`),
    stdout: decodeBinary(attempt.stdout, `attempt ${index} stdout`),
  };
}

function parseCanonicalProcessOutput(bytes) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return { valid: false };
  }

  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return { valid: false };
  }

  try {
    const canonical = canonicalJson(value);
    if (text !== `${canonical}\n`) return { valid: false };
    return {
      canonical,
      canonicalSha256: sha256(Buffer.from(canonical, 'utf8')),
      valid: true,
      value,
    };
  } catch {
    return { valid: false };
  }
}

function processReceiptValid(attempts) {
  return (
    attempts.length === 2 &&
    attempts.every(
      (attempt) =>
        attempt.exitCode === 0 && attempt.signal === null && attempt.stderr.byteLength === 0
    )
  );
}

function deriveBranch(launchError, attempts) {
  if (launchError !== null) return 'launch-failure';
  if (!processReceiptValid(attempts)) return 'malformed-output';

  const parsed = attempts.map((attempt) => parseCanonicalProcessOutput(attempt.stdout));
  if (parsed.some((result) => result.valid === false)) return 'malformed-output';
  if (parsed[0].canonicalSha256 !== parsed[1].canonicalSha256) return 'divergent-attempts';
  if (parsed[0].canonical !== canonicalJson(EXPECTED_PROTOCOL)) return 'exact-incompatibility';
  return 'success';
}

function validateLaunchError(launchError) {
  if (launchError === null) return;
  exactKeys(launchError, ['code', 'syscall'], 'terminal-shape-invalid');
  assertion(
    typeof launchError.code === 'string' &&
      launchError.code.length > 0 &&
      typeof launchError.syscall === 'string' &&
      launchError.syscall.length > 0,
    'terminal-shape-invalid'
  );
}

function validateTerminal(terminalBytes, reservationReceipt) {
  const bytes = toBytes(terminalBytes, 'terminal');
  const terminal = parseUtf8Json(bytes, 'terminal');
  exactKeys(terminal, TERMINAL_KEYS, 'terminal-shape-invalid');
  validateAuthority(terminal, 'authority-overclaim');
  assertion(
    terminal.schemaVersion === 'overlaykit-node22-failure-preservation-preflight-terminal/v1' &&
      terminal.study === STUDY &&
      BRANCHES[terminal.ordinal - 1] === terminal.branchId &&
      terminal.branchId === reservationReceipt.reservation.branchId &&
      terminal.ordinal === reservationReceipt.reservation.ordinal,
    'terminal-shape-invalid'
  );
  assertion(
    terminal.reservationRawSha256 === reservationReceipt.rawSha256,
    'reservation-raw-sha256-mismatch'
  );
  assertion(
    typeof terminal.semanticSha256 === 'string' && SHA256_PATTERN.test(terminal.semanticSha256),
    'terminal-shape-invalid'
  );
  const { semanticSha256: _semanticSha256, ...semanticBody } = terminal;
  assertion(
    canonicalHash(semanticBody) === terminal.semanticSha256,
    'terminal-semantic-sha256-mismatch'
  );

  validateLaunchError(terminal.launchError);
  assertion(Array.isArray(terminal.attempts), 'terminal-shape-invalid');
  assertion(
    terminal.attempts.length === EXPECTED_ATTEMPT_COUNTS[terminal.branchId],
    'terminal-attempt-cardinality-invalid'
  );
  const attempts = terminal.attempts.map((attempt, index) => validateAttempt(attempt, index));
  const derivedBranch = deriveBranch(terminal.launchError, attempts);
  assertion(derivedBranch === terminal.branchId, 'declared-branch-mismatch');

  return {
    attempts,
    bytes,
    derivedBranch,
    rawSha256: sha256(bytes),
    terminal,
  };
}

export function verifyTerminal({ subjectBytes, reservationBytes, terminalBytes } = {}) {
  const subjectReceipt = validateSubject(subjectBytes);
  const reservationReceipt = validateReservation(reservationBytes, subjectReceipt);
  const terminalReceipt = validateTerminal(terminalBytes, reservationReceipt);
  return {
    action: null,
    attemptCount: terminalReceipt.attempts.length,
    authority: 'none',
    branchId: terminalReceipt.derivedBranch,
    reasonCode: REASON_CODES[terminalReceipt.derivedBranch],
    reservationRawSha256: reservationReceipt.rawSha256,
    study: STUDY,
    subjectRawSha256: SUBJECT_RAW_SHA256,
    synthetic: true,
    terminalRawSha256: terminalReceipt.rawSha256,
    terminalSemanticSha256: terminalReceipt.terminal.semanticSha256,
    verification: 'independently-reconstructed-terminal',
  };
}

function validateArchivePath(archivePath) {
  assertion(
    typeof archivePath === 'string' &&
      archivePath.length > 0 &&
      Buffer.byteLength(archivePath, 'utf8') <= 100 &&
      /^[\x20-\x7e]+$/u.test(archivePath) &&
      !archivePath.includes('\\') &&
      !/^[A-Za-z]:/u.test(archivePath) &&
      !archivePath.startsWith('/') &&
      archivePath
        .split('/')
        .every((component) => component !== '' && component !== '.' && component !== '..'),
    'replay-path-invalid'
  );
}

function writeAscii(buffer, offset, length, text, code = 'replay-path-invalid') {
  const bytes = Buffer.from(text, 'ascii');
  assertion(bytes.length <= length, code);
  bytes.copy(buffer, offset);
}

function octalText(value, digits, code = 'replay-metadata-invalid') {
  assertion(Number.isSafeInteger(value) && value >= 0, code);
  const text = value.toString(8);
  assertion(text.length <= digits, code);
  return text.padStart(digits, '0');
}

function writeOctal(buffer, offset, length, value) {
  writeAscii(
    buffer,
    offset,
    length,
    `${octalText(value, length - 1)}\0`,
    'replay-metadata-invalid'
  );
}

function buildHeader(member) {
  const header = Buffer.alloc(USTAR_BLOCK_BYTES);
  writeAscii(header, 0, 100, member.archivePath);
  writeOctal(header, 100, 8, 0o600);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, member.bytes.byteLength);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  writeAscii(header, 257, 6, 'ustar\0');
  writeAscii(header, 263, 2, '00');
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  writeAscii(header, 148, 8, `${octalText(checksum, 6)}\0 `, 'replay-metadata-invalid');
  return header;
}

export function buildReplayArchive(members) {
  assertion(Array.isArray(members), 'replay-shape-invalid');
  const normalized = members
    .map((member) => {
      exactKeys(member, ['archivePath', 'bytes'], 'replay-shape-invalid');
      validateArchivePath(member.archivePath);
      return {
        archivePath: member.archivePath,
        bytes: toBytes(member.bytes, `archive member ${member.archivePath}`),
      };
    })
    .sort((left, right) => compareUtf8(left.archivePath, right.archivePath));

  const paths = normalized.map((member) => member.archivePath);
  assertion(new Set(paths).size === paths.length, 'replay-member-collision');

  const chunks = [];
  for (const member of normalized) {
    chunks.push(buildHeader(member), member.bytes);
    const padding =
      (USTAR_BLOCK_BYTES - (member.bytes.byteLength % USTAR_BLOCK_BYTES)) % USTAR_BLOCK_BYTES;
    if (padding > 0) chunks.push(Buffer.alloc(padding));
  }
  chunks.push(Buffer.alloc(USTAR_END_BYTES));
  return Buffer.concat(chunks);
}

function readString(buffer, offset, length) {
  const field = buffer.subarray(offset, offset + length);
  const end = field.indexOf(0);
  return field.subarray(0, end === -1 ? field.length : end).toString('ascii');
}

function readOctal(buffer, offset, length, code = 'replay-metadata-invalid') {
  const field = buffer.subarray(offset, offset + length).toString('ascii');
  const trimmed = field.replace(/\0.*$/u, '').trim();
  assertion(/^[0-7]+$/u.test(trimmed), code);
  const value = Number.parseInt(trimmed, 8);
  assertion(Number.isSafeInteger(value), code);
  return value;
}

function parseReplayArchive(archiveBytes) {
  const bytes = toBytes(archiveBytes, 'replay archive');
  assertion(
    bytes.length >= USTAR_END_BYTES && bytes.length % USTAR_BLOCK_BYTES === 0,
    'replay-truncated'
  );

  const members = [];
  const seen = new Set();
  let offset = 0;
  while (offset < bytes.length) {
    const header = bytes.subarray(offset, offset + USTAR_BLOCK_BYTES);
    if (header.every((byte) => byte === 0)) {
      const remainder = bytes.subarray(offset);
      assertion(
        remainder.length === USTAR_END_BYTES && remainder.every((byte) => byte === 0),
        'replay-terminator-invalid'
      );
      offset = bytes.length;
      break;
    }

    assertion(header.length === USTAR_BLOCK_BYTES, 'replay-truncated');
    const storedChecksum = readOctal(header, 148, 8);
    const checksumHeader = Buffer.from(header);
    checksumHeader.fill(0x20, 148, 156);
    const computedChecksum = checksumHeader.reduce((sum, byte) => sum + byte, 0);
    assertion(storedChecksum === computedChecksum, 'replay-checksum-invalid');

    const archivePath = readString(header, 0, 100);
    validateArchivePath(archivePath);
    assertion(!seen.has(archivePath), 'replay-member-collision');
    seen.add(archivePath);

    const mode = readOctal(header, 100, 8);
    const uid = readOctal(header, 108, 8);
    const gid = readOctal(header, 116, 8);
    const byteLength = readOctal(header, 124, 12);
    const mtime = readOctal(header, 136, 12);
    assertion(
      mode === 0o600 &&
        uid === 0 &&
        gid === 0 &&
        mtime === 0 &&
        header[156] === 0x30 &&
        readString(header, 257, 6) === 'ustar' &&
        readString(header, 263, 2) === '00' &&
        readString(header, 265, 32) === '' &&
        readString(header, 297, 32) === '',
      'replay-metadata-invalid'
    );

    const dataStart = offset + USTAR_BLOCK_BYTES;
    const dataEnd = dataStart + byteLength;
    const paddedEnd = dataStart + Math.ceil(byteLength / USTAR_BLOCK_BYTES) * USTAR_BLOCK_BYTES;
    assertion(dataEnd <= bytes.length && paddedEnd <= bytes.length, 'replay-truncated');
    assertion(
      bytes.subarray(dataEnd, paddedEnd).every((byte) => byte === 0),
      'replay-padding-invalid'
    );
    members.push({
      archivePath,
      bytes: Buffer.from(bytes.subarray(dataStart, dataEnd)),
    });
    offset = paddedEnd;
  }
  assertion(offset === bytes.length, 'replay-truncated');
  return { bytes, members };
}

export function verifyReplay({ subjectBytes, reservationBytes, terminalBytes, archiveBytes } = {}) {
  const parsed = parseReplayArchive(archiveBytes);
  const expectedPaths = ['reservation.json', 'terminal.json'];
  assertion(
    parsed.members.length === expectedPaths.length &&
      parsed.members.every((member, index) => member.archivePath === expectedPaths[index]),
    'replay-member-roster-invalid'
  );
  assertion(
    parsed.members[0].bytes.equals(toBytes(reservationBytes, 'reservation')) &&
      parsed.members[1].bytes.equals(toBytes(terminalBytes, 'terminal')),
    'replay-member-bytes-mismatch'
  );
  const reconstructed = buildReplayArchive(parsed.members);
  assertion(reconstructed.equals(parsed.bytes), 'replay-nondeterministic');

  const terminalReceipt = verifyTerminal({ subjectBytes, reservationBytes, terminalBytes });
  const archiveSha256 = sha256(parsed.bytes);
  return {
    ...terminalReceipt,
    archiveRawSha256: archiveSha256,
    archiveSha256,
    archiveMemberCount: parsed.members.length,
    replayVerification: 'byte-identical-posix-ustar-reconstruction',
    status: 'replay-reconstructed',
  };
}

export const verifierConstants = Object.freeze({
  branches: BRANCHES,
  expectedProtocol: EXPECTED_PROTOCOL,
  reasonCodes: REASON_CODES,
  study: STUDY,
  subjectRawSha256: SUBJECT_RAW_SHA256,
});
