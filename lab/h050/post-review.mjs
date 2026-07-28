import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const LAB_DIRECTORY = realpathSync(path.dirname(fileURLToPath(import.meta.url)));
const REPOSITORY_ROOT = realpathSync(path.resolve(LAB_DIRECTORY, '../..'));

const FILES = Object.freeze({
  subjectLock: path.join(LAB_DIRECTORY, 'subject-lock.json'),
  docket: path.join(LAB_DIRECTORY, 'product-intent-docket.json'),
  candidateMotion: path.join(LAB_DIRECTORY, 'canonical-candidate-motion.json'),
  humanAcceptance: path.join(LAB_DIRECTORY, 'human-acceptance.json'),
  assessment: path.join(LAB_DIRECTORY, 'post-review-assessment.json'),
});

const RAW_HASHES = Object.freeze({
  subjectLock: '6588b1d31321ecf77616a9952a68620383de4a3b336829074ec632980a68239e',
  docket: '7a145c440af25f5bbbb71c111381f886dccba387e6a0880853e666ceabea6684',
  candidateMotion: '20aa95c65dd0fb05bc21d7d98e7ba839895de5ded959b781db9d32893e1e1e28',
  humanAcceptance: 'd392ec651f80cdd715ef7482a829b823631fc94ceb8abf926e957c7f7f690602',
  assessment: 'a324a4fbce441c32ceba2d92aebba4323b747151a1f2b845de4601a9db40ca23',
});

const SUBJECT_COMMIT = '2810e63defe37025f575ebea37be7e1c5e97c18e';
const SUBJECT_SOURCE_SET_SHA256 =
  'a9b0c3a354fbdea6867f4343d69a051763395a882ae2dea8c76ff8ff6c20732b';
const CANDIDATE_BYTE_LENGTH = 4139;

const PRE_REVIEW_SOURCES = Object.freeze([
  Object.freeze({
    path: '.gitignore',
    mode: '0644',
    byteLength: 139,
    sha256: '2c42503834e61def3bf5840b5c553a73b2d569cee732c69e7420f75ce5e6f1fc',
  }),
  Object.freeze({
    path: '.overlaykit/governance/changes/CHG-0029.json',
    mode: '0644',
    byteLength: 13751,
    sha256: '36c74c9c45104f28cd0a019a4e5433c7e836f61daaac26d8de6be3987be92f05',
  }),
  Object.freeze({
    path: '.overlaykit/governance/manifest.json',
    mode: '0644',
    byteLength: 4272,
    sha256: 'f14bb6b9de145ad9acf292f6b4ccaa00c86ba2af9528a4894d91c0883f41f0ed',
  }),
  Object.freeze({
    path: 'lab/h050/subject-lock.json',
    mode: '0644',
    byteLength: 5584,
    sha256: RAW_HASHES.subjectLock,
  }),
  Object.freeze({
    path: 'lab/h050/product-intent-docket.json',
    mode: '0644',
    byteLength: 3880,
    sha256: RAW_HASHES.docket,
  }),
  Object.freeze({
    path: 'lab/h050/schemas/product-intent-docket.schema.json',
    mode: '0644',
    byteLength: 11207,
    sha256: '730a7a5b8fb35ace3704916dae4ff3408af84f86a5d6a8cf4ca4cbb53af223ed',
  }),
  Object.freeze({
    path: 'lab/h050/verify.mjs',
    mode: '0644',
    byteLength: 32974,
    sha256: '35938cf8a47cffd98e2c266508465ddb4a1a20221ae06deb0e71a2b12ab7439c',
  }),
  Object.freeze({
    path: 'lab/h050/verify.test.mjs',
    mode: '0644',
    byteLength: 11844,
    sha256: 'bdb2cf6f318067bc7554a9638001befacbf95c96741060d2e6fc1667a37757dc',
  }),
]);

const POST_REVIEW_SOURCE_PATHS = Object.freeze([
  'lab/h050/canonical-candidate-motion.json',
  'lab/h050/human-acceptance.json',
  'lab/h050/post-review-assessment.json',
  'lab/h050/post-review.mjs',
  'lab/h050/post-review.test.mjs',
]);

export const H050_POST_REVIEW_CLOSURE_ROOT = path.join(
  REPOSITORY_ROOT,
  'artifacts/h050/post-review-closures',
  RAW_HASHES.candidateMotion
);

const DISPLAYED_MARKDOWN =
  '> Acepto como intención humana canónica de H‑050 la moción candidata SHA‑256 20aa95c65dd0fb05bc21d7d98e7ba839895de5ded959b781db9d32893e1e1e28, vinculada al docket SHA‑256 7a145c440af25f5bbbb71c111381f886dccba387e6a0880853e666ceabea6684, incluyendo\n  > sus nueve decisiones y límites. Autorizo únicamente su cierre post-review local. No autorizo SPEC, ADR, implementación, observación live, commit, push ni merge.';
const DISPLAYED_MARKDOWN_BYTE_LENGTH = 425;
const DISPLAYED_MARKDOWN_SHA256 =
  '613d3dae98b5e028a784c27706a29e6be5bcf437496964566e869e847b1c37f8';
const SEMANTIC_FOLDED =
  'Acepto como intención humana canónica de H‑050 la moción candidata SHA‑256 20aa95c65dd0fb05bc21d7d98e7ba839895de5ded959b781db9d32893e1e1e28, vinculada al docket SHA‑256 7a145c440af25f5bbbb71c111381f886dccba387e6a0880853e666ceabea6684, incluyendo sus nueve decisiones y límites. Autorizo únicamente su cierre post-review local. No autorizo SPEC, ADR, implementación, observación live, commit, push ni merge.';
const SEMANTIC_FOLDED_BYTE_LENGTH = 419;
const SEMANTIC_FOLDED_SHA256 = 'da18adfb60bb11bb8237b0772ae3d16e2e52a3784c0ca06199eda6acf5eafa84';

export const H050_POST_REVIEW_PREDICATE_DECISIONS = Object.freeze([
  Object.freeze({
    id: 'automaticRecoveryObligation',
    decision: 'selected',
    value:
      'Mandatory unattended recovery: every governed instance SHALL restore delivery without operator action after the nominated trigger; optional, best-effort, investigatory, and manual-only behavior do not satisfy the obligation.',
  }),
  Object.freeze({
    id: 'linuxRoleAndPhysicalMk2Scope',
    decision: 'selected',
    value:
      'Scope is the active SPEC-0001 Linux production-host role and exactly one Stream Deck MK.2 nominated to its Companion instance by configured device serial; other models and non-nominated devices remain outside the obligation and must not be affected.',
  }),
  Object.freeze({
    id: 'triggerAndIdentityContinuity',
    decision: 'selected',
    value:
      'The trigger is a post-login exact absence of every current-epoch descriptor for the nominated serial followed by its return or re-enumeration; continuity requires the same serial, and bus number, device number, port proximity, or model alone cannot substitute a different device.',
  }),
  Object.freeze({
    id: 'restoredPhysicalCommandDelivery',
    decision: 'selected',
    value:
      'Recovery is proven only when one physical press of a nominated idempotent key traverses the preserved Companion configuration, invokes exactly one authorized OverlayKit command, and produces its authoritative server-state effect; descriptor ownership and Opening or Ready markers alone are insufficient.',
  }),
  Object.freeze({
    id: 'recoveryDeadlineAndClock',
    decision: 'selected',
    value:
      'A monotonic clock starts at the first operating-system observation of a new current-epoch descriptor for the same nominated serial after exact absence; a controlled physical press occurs from t0+5.000s through t0+5.250s; the clock stops at the authoritative server-state effect and the maximum is t0+8.250s.',
  }),
  Object.freeze({
    id: 'degradedFailureAndManualFallback',
    decision: 'selected',
    value:
      'If the authoritative effect is absent by t0+8.250s or identity is ambiguous, the role exposes a degraded state within one additional second; no more than three automatic recovery interventions may occur in one USB epoch or thirty-second window, after which intervention stops until a new epoch or explicit operator reset; manual fallback is diagnosis under a separately approved runbook, never an implicit restart or configuration change.',
  }),
  Object.freeze({
    id: 'safetySecurityAndAuthorityBoundary',
    decision: 'selected',
    value:
      'Recovery preserves the nominated serial, current device epoch, Companion instance, configuration identity, credentials, and OverlayKit server authority; work is single-flight per device, any process target is revalidated immediately before action, stale or different devices cannot command, duplicate commands are forbidden, and no top-level restart or configuration mutation is implied.',
  }),
  Object.freeze({
    id: 'acceptanceEvidenceAndScenarioCoverage',
    decision: 'selected',
    value:
      'Acceptance covers a fresh post-login baseline, one disconnect and re-enumeration, ten consecutive recovery cycles, a thirty-minute absence, removal during recovery, and a second non-nominated MK.2 on the same host; evidence includes monotonic timing, serial and epoch identity, configuration digest, process identity when applicable, a physical-actuation receipt, Companion action evidence, and authoritative OverlayKit state, with zero duplicates, wrong-device effects, or configuration loss.',
  }),
  Object.freeze({
    id: 'specificationRelationship',
    decision: 'selected',
    value:
      'A later new specification extends SPEC-0001 for this physical-recovery scope and references SPEC-0002 for the virtual command segment without editing or deleting either accepted record; drafting, acceptance, ADR creation, and implementation each require a separate human-authorized transition.',
  }),
]);

const EXPECTED_MOTION = Object.freeze({
  schemaVersion: 'overlaykit-h050-human-product-intent-motion/v1',
  hypothesis: 'H-050',
  principal: '@rodrigoteamx',
  subjectCommit: SUBJECT_COMMIT,
  docketRawSha256: RAW_HASHES.docket,
  productIntent: 'require-automatic',
  predicateDecisions: H050_POST_REVIEW_PREDICATE_DECISIONS,
  decisionsExplicitUnambiguousConflictFree: true,
  mechanismSelected: false,
  specificationAuthorized: false,
  adrAuthorized: false,
  implementationAuthorized: false,
  authority: 'none',
  action: null,
});

const EXPECTED_ACCEPTANCE_CANDIDATE = Object.freeze({
  path: 'lab/h050/canonical-candidate-motion.json',
  rawSha256: RAW_HASHES.candidateMotion,
  byteLength: CANDIDATE_BYTE_LENGTH,
  encoding: 'canonical-json-minified-with-one-trailing-lf',
});

const EXPECTED_ACCEPTANCE_DOCKET = Object.freeze({
  path: 'lab/h050/product-intent-docket.json',
  rawSha256: RAW_HASHES.docket,
});

const EXPECTED_ACCEPTANCE_TEMPORAL_SEQUENCE = Object.freeze({
  candidateProposal: 'exact-content-and-digest-presented-before-human-acceptance',
  humanAcceptance: 'subsequent-to-candidate-proposal',
  localMaterialization: 'candidate-file-and-acceptance-record-materialized-after-human-acceptance',
  postReviewAssessment: 'materialized-after-this-acceptance-record',
});

const EXPECTED_ACCEPTANCE_DECISION = Object.freeze({
  decision: 'accept-canonical-candidate-including-nine-decisions-and-limits',
  acceptedCandidateMotionSha256: RAW_HASHES.candidateMotion,
  acceptedDocketRawSha256: RAW_HASHES.docket,
  authorizes: Object.freeze(['local-post-review-closure']),
  authorizationExhaustive: true,
  outsideAuthorizedSet: 'unauthorized',
  doesNotAuthorize: Object.freeze([
    'SPEC',
    'ADR',
    'implementation',
    'live-observation',
    'commit',
    'push',
    'merge',
  ]),
});

const EXPECTED_ACCEPTANCE_BOUNDARY = Object.freeze({
  conclusion:
    'the human principal accepts the previously proposed exact candidate as canonical H-050 product intent, including all nine decisions and their existing non-authorizing limits; the candidate file and this record are later local materializations',
  nonAuthority:
    'this acceptance supports only the non-normative H-050 product-intent question and does not itself create a SPEC, ADR, implementation, live-observation, Git, or production authority',
  transport:
    'the record preserves two labeled review representations but makes no claim about inaccessible raw transport bytes',
});

const EXPECTED_ASSESSMENT_SOURCES = Object.freeze({
  subjectLock: Object.freeze({
    path: 'lab/h050/subject-lock.json',
    rawSha256: RAW_HASHES.subjectLock,
  }),
  docket: Object.freeze({
    path: 'lab/h050/product-intent-docket.json',
    rawSha256: RAW_HASHES.docket,
  }),
  candidateMotion: Object.freeze({
    path: 'lab/h050/canonical-candidate-motion.json',
    rawSha256: RAW_HASHES.candidateMotion,
    byteLength: CANDIDATE_BYTE_LENGTH,
  }),
  humanAcceptance: Object.freeze({
    path: 'lab/h050/human-acceptance.json',
    rawSha256: RAW_HASHES.humanAcceptance,
  }),
});

const EXPECTED_MOTION_RECEIPT = Object.freeze({
  productIntent: 'require-automatic',
  predicateCount: 9,
  selectedPredicateCount: 9,
  decisionsExplicitUnambiguousConflictFree: true,
  mechanismSelected: false,
  specificationAuthorized: false,
  adrAuthorized: false,
  implementationAuthorized: false,
});

const EXPECTED_HUMAN_ACCEPTANCE_RECEIPT = Object.freeze({
  principal: '@rodrigoteamx',
  candidateAndDocketHashesAccepted: true,
  allNineDecisionsAndLimitsAccepted: true,
  localPostReviewClosureAuthorized: true,
  authorizationExhaustive: true,
  transportBytesClaimed: false,
});

const EXPECTED_OUTCOME = Object.freeze({
  status: 'supported',
  stage: 'closed-human-product-intent',
  reasonCode: 'human-require-automatic-nine-of-nine-accepted',
  claimBoundary:
    'the exact human-accepted candidate resolves all nine non-normative H-050 product-intent decisions for the nominated docket; it does not create product law or authorize any later transition',
});

const EXPECTED_TEMPORAL_ORDER = Object.freeze({
  candidateProposal: 'exact-content-and-digest-presented-before-human-acceptance',
  humanAcceptance: 'subsequent-to-candidate-proposal',
  localMaterialization: 'candidate-file-and-acceptance-record-created-after-human-acceptance',
  assessment: 'created-after-local-materialization',
});

const EXPECTED_CAPABILITY_AUDIT = Object.freeze({
  mode: 'offline-local-post-review-closure',
  network: false,
  liveHost: false,
  usb: false,
  hidraw: false,
  docker: false,
  signals: false,
  worktreeGovernanceEvidenceWrites: true,
  worktreeWrittenPaths: POST_REVIEW_SOURCE_PATHS,
  ignoredArtifactClosureWrites: true,
  ignoredArtifactRoot:
    'artifacts/h050/post-review-closures/20aa95c65dd0fb05bc21d7d98e7ba839895de5ded959b781db9d32893e1e1e28',
  configurationMutation: false,
  productMutation: false,
  gitHistoryMutation: false,
});

class InvalidPostReviewEvidenceError extends Error {
  constructor(message, reasonCode = 'post-review-evidence-drift') {
    super(message);
    this.name = 'InvalidPostReviewEvidenceError';
    this.reasonCode = reasonCode;
  }
}

function assertion(condition, message, reasonCode) {
  if (!condition) throw new InvalidPostReviewEvidenceError(message, reasonCode);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, expected, label, reasonCode) {
  assertion(isObject(value), `${label} must be an object`, reasonCode);
  assertion(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort()),
    `${label} keys differ`,
    reasonCode
  );
}

function canonicalize(value, seen = new Set()) {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value))
  ) {
    return value;
  }
  assertion(value !== undefined && typeof value !== 'function', 'unsupported canonical value');
  assertion(!seen.has(value), 'canonical cycle');
  seen.add(value);
  if (Array.isArray(value)) {
    const result = value.map((item) => canonicalize(item, seen));
    seen.delete(value);
    return result;
  }
  assertion(isObject(value), 'canonical value must be a plain object');
  const result = {};
  for (const key of Object.keys(value).sort()) result[key] = canonicalize(value[key], seen);
  seen.delete(value);
  return result;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function canonicalArtifact(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
}

export function sha256(value) {
  return createHash('sha256')
    .update(Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8'))
    .digest('hex');
}

function validateArchivePath(archivePath) {
  assertion(typeof archivePath === 'string' && archivePath.length > 0, 'empty archive path');
  assertion(
    /^[\x20-\x7e]+$/u.test(archivePath) &&
      !archivePath.includes('\\') &&
      !/^[A-Za-z]:/u.test(archivePath),
    `non-canonical archive path: ${archivePath}`
  );
  assertion(!archivePath.startsWith('/'), `absolute archive path: ${archivePath}`);
  assertion(
    path.posix.normalize(archivePath) === archivePath &&
      archivePath.split('/').every((segment) => !['', '.', '..'].includes(segment)),
    `unsafe archive path: ${archivePath}`
  );
  assertion(Buffer.byteLength(archivePath, 'utf8') <= 100, `ustar path too long: ${archivePath}`);
}

function compareArchivePath(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function writeAscii(buffer, offset, length, value, label) {
  const bytes = Buffer.from(value, 'ascii');
  assertion(bytes.length <= length, `${label} does not fit ustar field`);
  bytes.copy(buffer, offset);
}

function writeOctal(buffer, offset, length, value, label) {
  assertion(Number.isSafeInteger(value) && value >= 0, `${label} is not a safe integer`);
  const encoded = `${value.toString(8).padStart(length - 1, '0')}\0`;
  assertion(encoded.length === length, `${label} does not fit ustar octal field`);
  writeAscii(buffer, offset, length, encoded, label);
}

function readOctal(buffer, offset, length, label) {
  const value = buffer
    .subarray(offset, offset + length)
    .toString('ascii')
    .replace(/\0.*$/u, '')
    .trim();
  assertion(/^[0-7]+$/u.test(value), `${label} is not canonical octal`);
  return Number.parseInt(value, 8);
}

function ustarHeader(member) {
  const header = Buffer.alloc(512);
  writeAscii(header, 0, 100, member.archivePath, 'name');
  writeOctal(header, 100, 8, 0o600, 'mode');
  writeOctal(header, 108, 8, 0, 'uid');
  writeOctal(header, 116, 8, 0, 'gid');
  writeOctal(header, 124, 12, member.bytes.length, 'size');
  writeOctal(header, 136, 12, 0, 'mtime');
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  writeAscii(header, 257, 6, 'ustar\0', 'magic');
  writeAscii(header, 263, 2, '00', 'version');
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  writeAscii(header, 148, 8, `${checksum.toString(8).padStart(6, '0')}\0 `, 'checksum');
  return header;
}

export function buildUstar(inputMembers) {
  assertion(Array.isArray(inputMembers) && inputMembers.length > 0, 'ustar requires members');
  const members = inputMembers
    .map((member) => {
      assertion(Buffer.isBuffer(member.bytes), 'ustar member bytes missing');
      validateArchivePath(member.archivePath);
      return { archivePath: member.archivePath, bytes: member.bytes };
    })
    .sort((left, right) => compareArchivePath(left.archivePath, right.archivePath));
  assertion(
    new Set(members.map(({ archivePath }) => archivePath)).size === members.length,
    'duplicate ustar member'
  );
  const chunks = [];
  for (const member of members) {
    chunks.push(ustarHeader(member), member.bytes);
    const remainder = member.bytes.length % 512;
    if (remainder !== 0) chunks.push(Buffer.alloc(512 - remainder));
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

export function parseUstar(archiveBytes) {
  assertion(Buffer.isBuffer(archiveBytes), 'archive must be bytes');
  assertion(
    archiveBytes.length >= 1024 && archiveBytes.length % 512 === 0,
    'archive length is not valid block alignment'
  );
  const members = [];
  let offset = 0;
  let zeroBlocks = 0;
  while (offset < archiveBytes.length) {
    const header = archiveBytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      zeroBlocks += 1;
      offset += 512;
      continue;
    }
    assertion(zeroBlocks === 0, 'non-zero data follows ustar terminator');
    assertion(header.subarray(257, 263).equals(Buffer.from('ustar\0')), 'ustar magic differs');
    assertion(header.subarray(263, 265).equals(Buffer.from('00')), 'ustar version differs');
    const expectedChecksum = readOctal(header, 148, 8, 'checksum');
    const checksumHeader = Buffer.from(header);
    checksumHeader.fill(0x20, 148, 156);
    assertion(
      checksumHeader.reduce((sum, byte) => sum + byte, 0) === expectedChecksum,
      'ustar checksum differs'
    );
    const archivePath = header.subarray(0, 100).toString('utf8').replace(/\0.*$/u, '');
    validateArchivePath(archivePath);
    assertion(
      header[156] === 0x30 || header[156] === 0,
      `non-regular archive member: ${archivePath}`
    );
    const mode = readOctal(header, 100, 8, 'mode');
    const uid = readOctal(header, 108, 8, 'uid');
    const gid = readOctal(header, 116, 8, 'gid');
    const byteLength = readOctal(header, 124, 12, 'size');
    const mtime = readOctal(header, 136, 12, 'mtime');
    const dataStart = offset + 512;
    const dataEnd = dataStart + byteLength;
    assertion(dataEnd <= archiveBytes.length, `truncated archive member: ${archivePath}`);
    const bytes = Buffer.from(archiveBytes.subarray(dataStart, dataEnd));
    const paddedEnd = dataStart + Math.ceil(byteLength / 512) * 512;
    assertion(
      archiveBytes.subarray(dataEnd, paddedEnd).every((byte) => byte === 0),
      `non-zero archive padding: ${archivePath}`
    );
    members.push({ archivePath, bytes, mode, uid, gid, mtime });
    offset = paddedEnd;
  }
  assertion(zeroBlocks >= 2, 'ustar terminator is incomplete');
  assertion(
    new Set(members.map(({ archivePath }) => archivePath)).size === members.length,
    'duplicate parsed archive member'
  );
  return members;
}

function parseJsonBytes(bytes, label, reasonCode) {
  assertion(Buffer.isBuffer(bytes), `${label} must be bytes`, reasonCode);
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch (error) {
    throw new InvalidPostReviewEvidenceError(
      `${label} is not exact UTF-8 JSON: ${error.message}`,
      reasonCode
    );
  }
}

function readLocalRegularFile(filePath, label) {
  const stat = lstatSync(filePath);
  assertion(
    stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1,
    `${label} is not a single-link regular file`,
    'unsafe-local-post-review-file'
  );
  return readFileSync(filePath);
}

function assertRawHash(bytes, expected, label, reasonCode) {
  assertion(sha256(bytes) === expected, `${label} raw bytes drift`, reasonCode);
}

function validatePreReviewSources(subjectLockBytes, docketBytes) {
  assertRawHash(subjectLockBytes, RAW_HASHES.subjectLock, 'subject lock', 'subject-lock-raw-drift');
  assertRawHash(docketBytes, RAW_HASHES.docket, 'docket', 'docket-raw-drift');
  const subjectLock = parseJsonBytes(
    subjectLockBytes,
    'subject lock',
    'subject-lock-structure-drift'
  );
  const docket = parseJsonBytes(docketBytes, 'docket', 'docket-structure-drift');
  assertion(
    subjectLock.schemaVersion === 'overlaykit-h050-subject-lock/v1' &&
      subjectLock.hypothesis === 'H-050' &&
      subjectLock.subject?.commit === SUBJECT_COMMIT &&
      subjectLock.subject?.sourceCount === 13 &&
      subjectLock.subject?.sourceSetSha256 === SUBJECT_SOURCE_SET_SHA256 &&
      subjectLock.authority === 'none' &&
      subjectLock.action === null,
    'subject lock meaning drift',
    'subject-lock-structure-drift'
  );
  assertion(
    docket.schemaVersion === 'overlaykit-h050-product-intent-docket/v1' &&
      docket.hypothesis === 'H-050' &&
      docket.status === 'pending-human-decision' &&
      docket.normative === false &&
      docket.humanDecision === null &&
      docket.subject?.commit === SUBJECT_COMMIT &&
      docket.subject?.sourceSetSha256 === SUBJECT_SOURCE_SET_SHA256 &&
      Array.isArray(docket.predicates) &&
      docket.predicates.length === 9 &&
      docket.predicates.every(({ decision }) => decision === null) &&
      docket.authority === 'none' &&
      docket.action === null,
    'docket meaning drift',
    'docket-structure-drift'
  );
}

function validateCandidateMotion(candidateMotionBytes) {
  assertRawHash(
    candidateMotionBytes,
    RAW_HASHES.candidateMotion,
    'candidate motion',
    'candidate-motion-raw-drift'
  );
  assertion(
    candidateMotionBytes.length === CANDIDATE_BYTE_LENGTH,
    'candidate motion byte length drift',
    'candidate-motion-byte-length-drift'
  );
  const motion = parseJsonBytes(
    candidateMotionBytes,
    'candidate motion',
    'candidate-motion-structure-drift'
  );
  assertion(
    candidateMotionBytes.equals(canonicalArtifact(motion)),
    'candidate motion is not canonical JSON plus one LF',
    'candidate-motion-noncanonical'
  );
  exactKeys(
    motion,
    Object.keys(EXPECTED_MOTION),
    'candidate motion',
    'candidate-motion-shape-drift'
  );
  assertion(
    canonicalJson(motion) === canonicalJson(EXPECTED_MOTION),
    'candidate motion meaning drift',
    'candidate-motion-meaning-drift'
  );
  assertion(
    new Set(motion.predicateDecisions.map(({ id }) => id)).size === 9,
    'candidate motion predicate IDs are not unique',
    'candidate-motion-predicate-cardinality-drift'
  );
  return motion;
}

function validateRepresentation(representation, expected, label) {
  exactKeys(representation, ['status', 'value', 'utf8ByteLength', 'sha256'], label);
  assertion(representation.status === expected.status, `${label} status drift`);
  assertion(representation.value === expected.value, `${label} value drift`);
  const valueBytes = Buffer.from(representation.value, 'utf8');
  assertion(
    valueBytes.length === expected.byteLength &&
      representation.utf8ByteLength === expected.byteLength,
    `${label} byte length drift`
  );
  assertion(
    sha256(valueBytes) === expected.sha256 && representation.sha256 === expected.sha256,
    `${label} digest drift`
  );
}

function validateHumanAcceptance(humanAcceptanceBytes) {
  assertRawHash(
    humanAcceptanceBytes,
    RAW_HASHES.humanAcceptance,
    'human acceptance',
    'human-acceptance-raw-drift'
  );
  const acceptance = parseJsonBytes(
    humanAcceptanceBytes,
    'human acceptance',
    'human-acceptance-structure-drift'
  );
  exactKeys(
    acceptance,
    [
      'schemaVersion',
      'hypothesis',
      'principal',
      'normative',
      'temporalSequence',
      'candidateMotion',
      'docket',
      'representations',
      'acceptance',
      'claimBoundary',
      'authority',
      'action',
    ],
    'human acceptance',
    'human-acceptance-shape-drift'
  );
  assertion(
    acceptance.schemaVersion === 'overlaykit-h050-human-acceptance/v1' &&
      acceptance.hypothesis === 'H-050' &&
      acceptance.principal === '@rodrigoteamx' &&
      acceptance.normative === false,
    'human acceptance identity drift',
    'human-acceptance-identity-drift'
  );
  assertion(
    canonicalJson(acceptance.temporalSequence) ===
      canonicalJson(EXPECTED_ACCEPTANCE_TEMPORAL_SEQUENCE),
    'human acceptance temporal sequence drift',
    'human-acceptance-temporal-drift'
  );
  assertion(
    canonicalJson(acceptance.candidateMotion) === canonicalJson(EXPECTED_ACCEPTANCE_CANDIDATE) &&
      canonicalJson(acceptance.docket) === canonicalJson(EXPECTED_ACCEPTANCE_DOCKET),
    'human acceptance source binding drift',
    'human-acceptance-source-binding-drift'
  );
  exactKeys(
    acceptance.representations,
    ['displayedMarkdown', 'semanticFolded', 'transportBytes'],
    'human acceptance representations'
  );
  validateRepresentation(
    acceptance.representations.displayedMarkdown,
    {
      status: 'model-visible-transcription-not-transport-bytes',
      value: DISPLAYED_MARKDOWN,
      byteLength: DISPLAYED_MARKDOWN_BYTE_LENGTH,
      sha256: DISPLAYED_MARKDOWN_SHA256,
    },
    'displayed Markdown representation'
  );
  validateRepresentation(
    acceptance.representations.semanticFolded,
    {
      status: 'unquoted-folded-semantic-text-not-transport-bytes',
      value: SEMANTIC_FOLDED,
      byteLength: SEMANTIC_FOLDED_BYTE_LENGTH,
      sha256: SEMANTIC_FOLDED_SHA256,
    },
    'semantic folded representation'
  );
  exactKeys(
    acceptance.representations.transportBytes,
    ['claimed', 'byteLength', 'sha256'],
    'transport-byte non-claim'
  );
  assertion(
    acceptance.representations.transportBytes.claimed === false &&
      acceptance.representations.transportBytes.byteLength === null &&
      acceptance.representations.transportBytes.sha256 === null,
    'raw transport bytes were overclaimed',
    'raw-transport-bytes-overclaim'
  );
  assertion(
    canonicalJson(acceptance.acceptance) === canonicalJson(EXPECTED_ACCEPTANCE_DECISION),
    'human acceptance decision drift',
    'human-acceptance-decision-drift'
  );
  assertion(
    canonicalJson(acceptance.claimBoundary) === canonicalJson(EXPECTED_ACCEPTANCE_BOUNDARY),
    'human acceptance claim boundary drift',
    'human-acceptance-boundary-drift'
  );
  assertion(
    acceptance.authority === 'none' && acceptance.action === null,
    'human acceptance authority or action overclaim',
    'human-acceptance-authority-overclaim'
  );
  return acceptance;
}

function validateAssessment(assessmentBytes) {
  assertRawHash(
    assessmentBytes,
    RAW_HASHES.assessment,
    'post-review assessment',
    'post-review-assessment-raw-drift'
  );
  const assessment = parseJsonBytes(
    assessmentBytes,
    'post-review assessment',
    'post-review-assessment-structure-drift'
  );
  exactKeys(
    assessment,
    [
      'schemaVersion',
      'hypothesis',
      'temporalOrder',
      'sources',
      'motionReceipt',
      'humanAcceptanceReceipt',
      'outcome',
      'epistemicClaims',
      'adrAssessment',
      'specificationAssessment',
      'capabilityAudit',
      'closureAuthorization',
      'authority',
      'action',
    ],
    'post-review assessment',
    'post-review-assessment-shape-drift'
  );
  assertion(
    assessment.schemaVersion === 'overlaykit-h050-post-review-assessment/v1' &&
      assessment.hypothesis === 'H-050',
    'post-review assessment identity drift',
    'post-review-assessment-identity-drift'
  );
  assertion(
    canonicalJson(assessment.temporalOrder) === canonicalJson(EXPECTED_TEMPORAL_ORDER) &&
      canonicalJson(assessment.sources) === canonicalJson(EXPECTED_ASSESSMENT_SOURCES),
    'post-review assessment temporal or source chain drift',
    'post-review-assessment-source-chain-drift'
  );
  assertion(
    canonicalJson(assessment.motionReceipt) === canonicalJson(EXPECTED_MOTION_RECEIPT) &&
      canonicalJson(assessment.humanAcceptanceReceipt) ===
        canonicalJson(EXPECTED_HUMAN_ACCEPTANCE_RECEIPT),
    'post-review receipts drift',
    'post-review-assessment-receipt-drift'
  );
  assertion(
    canonicalJson(assessment.outcome) === canonicalJson(EXPECTED_OUTCOME),
    'post-review outcome drift',
    'post-review-assessment-outcome-drift'
  );
  assertion(
    Array.isArray(assessment.epistemicClaims) &&
      assessment.epistemicClaims.length === 5 &&
      canonicalJson(assessment.epistemicClaims.map(({ kind }) => kind)) ===
        canonicalJson(['fact', 'fact', 'inference', 'unknown', 'assumption']) &&
      assessment.epistemicClaims.every(
        (claim) =>
          isObject(claim) &&
          Object.keys(claim).length === 3 &&
          typeof claim.statement === 'string' &&
          claim.statement.length > 20 &&
          typeof claim.evidence === 'string' &&
          claim.evidence.length > 20
      ),
    'post-review epistemic claims drift',
    'post-review-assessment-epistemic-drift'
  );
  assertion(
    assessment.adrAssessment?.candidateActivated === false &&
      assessment.specificationAssessment?.successorSpecificationIndicatedByIntent === true &&
      assessment.specificationAssessment?.draftingAuthorized === false &&
      assessment.specificationAssessment?.acceptanceAuthorized === false,
    'ADR or SPEC authority overclaim',
    'post-review-assessment-normative-overclaim'
  );
  assertion(
    canonicalJson(assessment.capabilityAudit) === canonicalJson(EXPECTED_CAPABILITY_AUDIT),
    'capability audit drift',
    'post-review-assessment-capability-overclaim'
  );
  assertion(
    assessment.closureAuthorization === 'local-post-review-only' &&
      assessment.authority === 'none' &&
      assessment.action === null,
    'post-review closure authority overclaim',
    'post-review-assessment-authority-overclaim'
  );
  return assessment;
}

function resolveRepositoryPath(repositoryRoot, relativePath) {
  assertion(
    typeof relativePath === 'string' &&
      relativePath.length > 0 &&
      !relativePath.startsWith('/') &&
      !relativePath.includes('\\') &&
      relativePath.split('/').every((segment) => !['', '.', '..'].includes(segment)),
    `unsafe repository-relative path: ${relativePath}`
  );
  const root = realpathSync(repositoryRoot);
  const absolutePath = path.resolve(root, relativePath);
  assertion(
    absolutePath.startsWith(`${root}${path.sep}`),
    `repository path escapes root: ${relativePath}`
  );
  return { root, absolutePath };
}

function readRepositoryRegularFile(repositoryRoot, relativePath) {
  const { root, absolutePath } = resolveRepositoryPath(repositoryRoot, relativePath);
  const stat = lstatSync(absolutePath);
  assertion(
    stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1,
    `repository source is unsafe: ${relativePath}`
  );
  assertion(
    realpathSync(absolutePath).startsWith(`${root}${path.sep}`),
    `repository source realpath escapes root: ${relativePath}`
  );
  return {
    bytes: readFileSync(absolutePath),
    mode: (stat.mode & 0o777).toString(8).padStart(4, '0'),
  };
}

function assertRepositoryPathAbsent(repositoryRoot, relativePath) {
  const { absolutePath } = resolveRepositoryPath(repositoryRoot, relativePath);
  try {
    lstatSync(absolutePath);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  throw new InvalidPostReviewEvidenceError(
    `path must be absent from the pre-successor closure: ${relativePath}`,
    'successor-entered-pre-review-closure'
  );
}

function sourceEntry(relativePath, bytes, mode) {
  return {
    path: relativePath,
    mode,
    byteLength: bytes.length,
    sha256: sha256(bytes),
  };
}

function inspectClosureSources(repositoryRoot) {
  assertRepositoryPathAbsent(repositoryRoot, '.overlaykit/governance/changes/CHG-0030.json');
  const sourceBytes = new Map();
  const preReviewSources = PRE_REVIEW_SOURCES.map((expected) => {
    const observed = readRepositoryRegularFile(repositoryRoot, expected.path);
    const entry = sourceEntry(expected.path, observed.bytes, observed.mode);
    assertion(
      canonicalJson(entry) === canonicalJson(expected),
      `pre-review source drift: ${expected.path}`,
      'pre-review-source-drift'
    );
    sourceBytes.set(expected.path, observed.bytes);
    return entry;
  });
  assertion(
    sourceBytes.get('.gitignore').toString('utf8').split(/\r?\n/u).includes('artifacts/'),
    'the local artifact closure is not ignored',
    'artifact-closure-ignore-rule-absent'
  );

  const postReviewSources = POST_REVIEW_SOURCE_PATHS.map((relativePath) => {
    const observed = readRepositoryRegularFile(repositoryRoot, relativePath);
    const entry = sourceEntry(relativePath, observed.bytes, observed.mode);
    assertion(entry.mode === '0644', `post-review source mode drift: ${relativePath}`);
    sourceBytes.set(relativePath, observed.bytes);
    return entry;
  });

  validateCandidateMotion(sourceBytes.get('lab/h050/canonical-candidate-motion.json'));
  validateHumanAcceptance(sourceBytes.get('lab/h050/human-acceptance.json'));
  validateAssessment(sourceBytes.get('lab/h050/post-review-assessment.json'));
  return { preReviewSources, postReviewSources, sourceBytes };
}

export function assertBuildInputsStable(repositoryRoot, snapshot) {
  assertRepositoryPathAbsent(repositoryRoot, '.overlaykit/governance/changes/CHG-0030.json');
  assertion(snapshot?.sourceBytes instanceof Map, 'source stability snapshot is invalid');
  for (const entry of [...snapshot.preReviewSources, ...snapshot.postReviewSources]) {
    const observed = readRepositoryRegularFile(repositoryRoot, entry.path);
    assertion(
      observed.mode === entry.mode && observed.bytes.equals(snapshot.sourceBytes.get(entry.path)),
      `postflight source bytes differ: ${entry.path}`,
      'closure-source-postflight-drift'
    );
  }
}

function createSourceAnchor(preReviewSources, postReviewSources) {
  return {
    schemaVersion: 'overlaykit-h050-local-source-anchor/v1',
    hypothesis: 'H-050',
    admission: 'local-content-addressed-unsigned',
    signatureStatus: 'absent-not-authorized',
    signedCommit: null,
    subject: {
      commit: SUBJECT_COMMIT,
      sourceSetSha256: SUBJECT_SOURCE_SET_SHA256,
      docketRawSha256: RAW_HASHES.docket,
      candidateMotionRawSha256: RAW_HASHES.candidateMotion,
    },
    temporalBoundary: {
      candidateProposal: 'exact-content-and-digest-presented-before-human-acceptance',
      humanAcceptance: 'subsequent-to-candidate-proposal',
      localMaterialization: 'all-post-review-files-created-after-human-acceptance',
      archive: 'created-after-post-review-files-and-before-any-successor-change',
    },
    preReviewSourceCount: preReviewSources.length,
    preReviewSourceSetSha256: sha256(canonicalJson(preReviewSources)),
    preReviewSources,
    postReviewSourceCount: postReviewSources.length,
    postReviewSourceSetSha256: sha256(canonicalJson(postReviewSources)),
    postReviewSources,
    successorBoundary: {
      expectedSuccessorChange: 'CHG-0030',
      successorChangeIncluded: false,
      successorManifestIncluded: false,
      reason:
        'the evidence closure precedes and cannot self-authorize any successor lifecycle record',
    },
    provenance:
      'local content address only; no signed Git anchor, transport-byte identity, remote durability, publication, or independent timestamp is claimed',
    authority: 'none',
    action: null,
  };
}

function payloadMember(role, sourcePath, archivePath, bytes) {
  validateArchivePath(archivePath);
  return {
    descriptor: {
      role,
      sourcePath,
      archivePath,
      byteLength: bytes.length,
      sha256: sha256(bytes),
    },
    bytes,
  };
}

function expectedDirectoryFiles(archiveFileName) {
  return [
    'candidate-motion.json',
    'closure.json',
    'human-acceptance.json',
    'manifest.json',
    'post-review-assessment.json',
    archiveFileName,
    'source-anchor.json',
  ].sort(compareArchivePath);
}

function createExternalClosure({
  sourceAnchorBytes,
  candidateMotionBytes,
  humanAcceptanceBytes,
  assessmentBytes,
  manifestBytes,
  archiveBytes,
  archiveFileName,
  archiveMemberCount,
}) {
  const archiveSha256 = sha256(archiveBytes);
  return {
    schemaVersion: 'overlaykit-h050-post-review-closure/v1',
    hypothesis: 'H-050',
    temporalBoundary: {
      candidateProposal: 'exact-content-and-digest-presented-before-human-acceptance',
      humanAcceptance: 'subsequent-to-candidate-proposal',
      localMaterialization: 'candidate-and-review-records-created-after-human-acceptance',
      archive: 'created-after-local-materialization-and-before-any-successor-change',
    },
    subject: {
      commit: SUBJECT_COMMIT,
      sourceSetSha256: SUBJECT_SOURCE_SET_SHA256,
      docketRawSha256: RAW_HASHES.docket,
    },
    sourceAnchor: {
      admission: 'local-content-addressed-unsigned',
      signatureStatus: 'absent-not-authorized',
      signedCommit: null,
      recordSha256: sha256(sourceAnchorBytes),
    },
    candidateMotion: {
      rawSha256: sha256(candidateMotionBytes),
      byteLength: candidateMotionBytes.length,
      proposalPrecededAcceptance: true,
      fileMaterializedAfterAcceptance: true,
    },
    humanAcceptance: {
      rawSha256: sha256(humanAcceptanceBytes),
      displayedMarkdownSha256: DISPLAYED_MARKDOWN_SHA256,
      semanticFoldedSha256: SEMANTIC_FOLDED_SHA256,
      transportBytesClaimed: false,
      authorization: 'local-post-review-closure-only',
      anythingElseAuthorized: false,
    },
    postReviewAssessment: {
      rawSha256: sha256(assessmentBytes),
      status: 'supported',
      reasonCode: 'human-require-automatic-nine-of-nine-accepted',
      authority: 'none',
      action: null,
    },
    preSuccessorBoundary: {
      changeId: 'CHG-0029',
      changeRawSha256: '36c74c9c45104f28cd0a019a4e5433c7e836f61daaac26d8de6be3987be92f05',
      manifestRawSha256: 'f14bb6b9de145ad9acf292f6b4ccaa00c86ba2af9528a4894d91c0883f41f0ed',
      successorChange: 'CHG-0030',
      successorChangeIncluded: false,
      successorManifestIncluded: false,
    },
    manifestSha256: sha256(manifestBytes),
    bundle: {
      path: `artifacts/h050/post-review-closures/${RAW_HASHES.candidateMotion}/${archiveFileName}`,
      sha256: archiveSha256,
      byteLength: archiveBytes.length,
      memberCount: archiveMemberCount,
    },
    determinism: {
      format: 'POSIX-ustar',
      order: 'unsigned-bytewise-archive-path',
      fileMode: '0600',
      uid: 0,
      gid: 0,
      mtime: 0,
      buildASha256: archiveSha256,
      buildBSha256: archiveSha256,
      byteIdentical: true,
    },
    directoryFiles: expectedDirectoryFiles(archiveFileName),
    adrAssessment: {
      candidateActivated: false,
      authority: 'none',
      action: null,
    },
    specificationAssessment: {
      successorSpecificationIndicatedByIntent: true,
      draftingAuthorized: false,
      acceptanceAuthorized: false,
    },
    lifecycleAssumption:
      'implementation denied here means product or mechanism implementation; any later separately authorized implemented successor change would classify evidence-closure lifecycle only',
    publication: 'not-authorized',
    authority: 'none',
    action: null,
  };
}

export function buildPostReviewClosure({ repositoryRoot = REPOSITORY_ROOT } = {}) {
  const snapshot = inspectClosureSources(repositoryRoot);
  const candidateMotionBytes = snapshot.sourceBytes.get('lab/h050/canonical-candidate-motion.json');
  const humanAcceptanceBytes = snapshot.sourceBytes.get('lab/h050/human-acceptance.json');
  const assessmentBytes = snapshot.sourceBytes.get('lab/h050/post-review-assessment.json');
  const sourceAnchor = createSourceAnchor(snapshot.preReviewSources, snapshot.postReviewSources);
  const sourceAnchorBytes = canonicalArtifact(sourceAnchor);

  const payloads = [];
  for (const source of snapshot.preReviewSources) {
    payloads.push(
      payloadMember(
        'pre-review-source',
        source.path,
        `sources/pre-review/${source.path}`,
        snapshot.sourceBytes.get(source.path)
      )
    );
  }
  for (const sourcePath of ['lab/h050/post-review.mjs', 'lab/h050/post-review.test.mjs']) {
    payloads.push(
      payloadMember(
        'post-review-replay-source',
        sourcePath,
        `sources/post-review/${sourcePath}`,
        snapshot.sourceBytes.get(sourcePath)
      )
    );
  }
  for (const [role, sourcePath, archivePath, bytes] of [
    [
      'local-unsigned-source-anchor',
      'artifacts/h050/post-review-closures/<candidate-sha256>/source-anchor.json',
      'metadata/source-anchor.json',
      sourceAnchorBytes,
    ],
    [
      'canonical-candidate-motion',
      'lab/h050/canonical-candidate-motion.json',
      'metadata/candidate-motion.json',
      candidateMotionBytes,
    ],
    [
      'human-acceptance',
      'lab/h050/human-acceptance.json',
      'metadata/human-acceptance.json',
      humanAcceptanceBytes,
    ],
    [
      'post-review-assessment',
      'lab/h050/post-review-assessment.json',
      'metadata/post-review-assessment.json',
      assessmentBytes,
    ],
  ]) {
    payloads.push(payloadMember(role, sourcePath, archivePath, bytes));
  }
  payloads.sort((left, right) =>
    compareArchivePath(left.descriptor.archivePath, right.descriptor.archivePath)
  );

  const manifest = {
    schemaVersion: 'overlaykit-h050-post-review-manifest/v1',
    hypothesis: 'H-050',
    closurePurpose:
      'exclusive local post-review closure for the human-accepted H-050 product-intent decision',
    temporalSemantics:
      'candidate content and digest were proposed before human acceptance; files and archive were materialized only afterward',
    outcome: {
      status: 'supported',
      stage: 'closed-human-product-intent',
      reasonCode: 'human-require-automatic-nine-of-nine-accepted',
      normative: false,
    },
    sourceSets: {
      preReview: {
        count: snapshot.preReviewSources.length,
        sha256: sourceAnchor.preReviewSourceSetSha256,
      },
      postReview: {
        count: snapshot.postReviewSources.length,
        sha256: sourceAnchor.postReviewSourceSetSha256,
      },
    },
    payloadMemberCount: payloads.length,
    members: payloads.map(({ descriptor }) => descriptor),
    provenance:
      'local content address only; the successor change and successor manifest remain outside this archive',
    disclosure: 'restricted-local',
    publication: 'not-authorized',
    authority: 'none',
    action: null,
  };
  const manifestBytes = canonicalArtifact(manifest);
  const archiveMembers = [
    ...payloads.map(({ descriptor, bytes }) => ({
      archivePath: descriptor.archivePath,
      bytes,
    })),
    { archivePath: 'metadata/manifest.json', bytes: manifestBytes },
  ];
  const buildA = buildUstar(archiveMembers);
  const buildB = buildUstar([...archiveMembers].reverse());
  assertion(buildA.equals(buildB), 'independent deterministic archive builds differ');
  const archiveFileName = `replay-${sha256(buildA)}.tar`;
  const closure = createExternalClosure({
    sourceAnchorBytes,
    candidateMotionBytes,
    humanAcceptanceBytes,
    assessmentBytes,
    manifestBytes,
    archiveBytes: buildA,
    archiveFileName,
    archiveMemberCount: archiveMembers.length,
  });
  const closureBytes = canonicalArtifact(closure);
  assertBuildInputsStable(repositoryRoot, snapshot);
  return {
    sourceAnchor,
    sourceAnchorBytes,
    manifest,
    manifestBytes,
    closure,
    closureBytes,
    archiveBytes: buildA,
    archiveFileName,
    metadata: {
      'source-anchor.json': sourceAnchorBytes,
      'candidate-motion.json': candidateMotionBytes,
      'human-acceptance.json': humanAcceptanceBytes,
      'post-review-assessment.json': assessmentBytes,
      'manifest.json': manifestBytes,
    },
    snapshot,
  };
}

function assertSafeDirectory(directoryPath, expectedMode = null) {
  const stat = lstatSync(directoryPath);
  assertion(
    stat.isDirectory() && !stat.isSymbolicLink(),
    `directory component is unsafe: ${directoryPath}`
  );
  if (expectedMode !== null) {
    assertion((stat.mode & 0o777) === expectedMode, `directory mode differs: ${directoryPath}`);
  }
  return realpathSync(directoryPath);
}

function ensureSafeDirectoryChain(allowedRoot, targetDirectory) {
  const allowedAbsolute = path.resolve(allowedRoot);
  const allowedReal = assertSafeDirectory(allowedAbsolute);
  const targetAbsolute = path.resolve(targetDirectory);
  assertion(
    targetAbsolute.startsWith(`${allowedAbsolute}${path.sep}`),
    'output directory escapes allowed root'
  );
  const relative = path.relative(allowedAbsolute, targetAbsolute);
  let current = allowedAbsolute;
  for (const segment of relative.split(path.sep)) {
    assertion(segment !== '' && segment !== '.' && segment !== '..', 'unsafe output segment');
    current = path.join(current, segment);
    if (!existsSync(current)) mkdirSync(current, { mode: 0o700 });
    const currentReal = assertSafeDirectory(current);
    assertion(
      currentReal.startsWith(`${allowedReal}${path.sep}`),
      `directory component escapes allowed root: ${current}`
    );
  }
  chmodSync(targetAbsolute, 0o700);
  return realpathSync(targetAbsolute);
}

function writeExclusiveRegularFile(outputDirectory, fileName, bytes) {
  assertion(
    /^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(fileName) && !fileName.includes('..'),
    `unsafe output file name: ${fileName}`
  );
  const filePath = path.join(outputDirectory, fileName);
  if (existsSync(filePath)) {
    const existing = lstatSync(filePath);
    assertion(existing.nlink === 1, `refusing output with multiple links: ${fileName}`);
    throw new InvalidPostReviewEvidenceError(`refusing to overwrite existing file: ${fileName}`);
  }
  writeFileSync(filePath, bytes, { flag: 'wx', mode: 0o600 });
  chmodSync(filePath, 0o600);
  const stat = lstatSync(filePath);
  assertion(
    stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && (stat.mode & 0o777) === 0o600,
    `written output file is unsafe: ${fileName}`
  );
  assertion(
    path.dirname(realpathSync(filePath)) === outputDirectory,
    `written output escapes closure directory: ${fileName}`
  );
}

export function writePostReviewClosure(
  result,
  {
    allowedRoot = path.dirname(H050_POST_REVIEW_CLOSURE_ROOT),
    outputDirectory = H050_POST_REVIEW_CLOSURE_ROOT,
  } = {}
) {
  assertion(
    result?.archiveBytes && result?.closureBytes && result?.metadata,
    'invalid closure build'
  );
  const outputReal = ensureSafeDirectoryChain(allowedRoot, outputDirectory);
  const expectedFiles = expectedDirectoryFiles(result.archiveFileName);
  const writes = {
    ...result.metadata,
    [result.archiveFileName]: result.archiveBytes,
    'closure.json': result.closureBytes,
  };
  assertion(
    canonicalJson(Object.keys(writes).sort(compareArchivePath)) === canonicalJson(expectedFiles),
    'closure write roster differs'
  );
  for (const fileName of expectedFiles) {
    writeExclusiveRegularFile(outputReal, fileName, writes[fileName]);
  }
  return outputReal;
}

function readClosureFile(closureDirectory, fileName) {
  const filePath = path.join(closureDirectory, fileName);
  const stat = lstatSync(filePath);
  assertion(
    stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && (stat.mode & 0o777) === 0o600,
    `closure file is unsafe: ${fileName}`
  );
  assertion(
    path.dirname(realpathSync(filePath)) === closureDirectory,
    `closure file escapes directory: ${fileName}`
  );
  return readFileSync(filePath);
}

function validateSourceAnchor(sourceAnchorBytes) {
  const sourceAnchor = parseJsonBytes(
    sourceAnchorBytes,
    'source anchor',
    'source-anchor-structure-drift'
  );
  assertion(
    sourceAnchorBytes.equals(canonicalArtifact(sourceAnchor)),
    'source anchor is not canonical JSON plus LF'
  );
  exactKeys(
    sourceAnchor,
    [
      'schemaVersion',
      'hypothesis',
      'admission',
      'signatureStatus',
      'signedCommit',
      'subject',
      'temporalBoundary',
      'preReviewSourceCount',
      'preReviewSourceSetSha256',
      'preReviewSources',
      'postReviewSourceCount',
      'postReviewSourceSetSha256',
      'postReviewSources',
      'successorBoundary',
      'provenance',
      'authority',
      'action',
    ],
    'source anchor'
  );
  assertion(
    sourceAnchor.schemaVersion === 'overlaykit-h050-local-source-anchor/v1' &&
      sourceAnchor.hypothesis === 'H-050' &&
      sourceAnchor.admission === 'local-content-addressed-unsigned' &&
      sourceAnchor.signatureStatus === 'absent-not-authorized' &&
      sourceAnchor.signedCommit === null &&
      sourceAnchor.authority === 'none' &&
      sourceAnchor.action === null,
    'source anchor authority or identity drift'
  );
  assertion(
    canonicalJson(sourceAnchor.preReviewSources) === canonicalJson(PRE_REVIEW_SOURCES) &&
      sourceAnchor.preReviewSourceCount === PRE_REVIEW_SOURCES.length &&
      sourceAnchor.preReviewSourceSetSha256 === sha256(canonicalJson(PRE_REVIEW_SOURCES)),
    'source anchor pre-review roster drift'
  );
  assertion(
    Array.isArray(sourceAnchor.postReviewSources) &&
      sourceAnchor.postReviewSources.length === POST_REVIEW_SOURCE_PATHS.length &&
      canonicalJson(sourceAnchor.postReviewSources.map(({ path: value }) => value)) ===
        canonicalJson(POST_REVIEW_SOURCE_PATHS) &&
      sourceAnchor.postReviewSourceSetSha256 ===
        sha256(canonicalJson(sourceAnchor.postReviewSources)),
    'source anchor post-review roster drift'
  );
  for (const entry of sourceAnchor.postReviewSources) {
    exactKeys(
      entry,
      ['path', 'mode', 'byteLength', 'sha256'],
      `source anchor post-review source ${entry.path}`
    );
    assertion(
      entry.mode === '0644' &&
        Number.isSafeInteger(entry.byteLength) &&
        entry.byteLength > 0 &&
        /^[0-9a-f]{64}$/u.test(entry.sha256),
      `source anchor post-review receipt drift: ${entry.path}`
    );
  }
  assertion(
    sourceAnchor.successorBoundary?.expectedSuccessorChange === 'CHG-0030' &&
      sourceAnchor.successorBoundary?.successorChangeIncluded === false &&
      sourceAnchor.successorBoundary?.successorManifestIncluded === false,
    'source anchor includes or authorizes a successor'
  );
  const expectedSourceAnchor = createSourceAnchor(
    PRE_REVIEW_SOURCES,
    sourceAnchor.postReviewSources
  );
  assertion(
    canonicalJson(sourceAnchor) === canonicalJson(expectedSourceAnchor),
    'source anchor envelope differs from exact reconstruction'
  );
  return sourceAnchor;
}

export function verifyPostReviewClosure({ closureDirectory = H050_POST_REVIEW_CLOSURE_ROOT } = {}) {
  const closureReal = assertSafeDirectory(path.resolve(closureDirectory), 0o700);
  const names = readdirSync(closureReal).sort(compareArchivePath);
  const archiveNames = names.filter((name) => /^replay-[0-9a-f]{64}\.tar$/u.test(name));
  assertion(archiveNames.length === 1, 'closure must contain exactly one replay archive');
  const archiveFileName = archiveNames[0];
  assertion(
    canonicalJson(names) === canonicalJson(expectedDirectoryFiles(archiveFileName)),
    'closure directory roster differs'
  );
  const byName = new Map(names.map((name) => [name, readClosureFile(closureReal, name)]));
  const candidateMotionBytes = byName.get('candidate-motion.json');
  const humanAcceptanceBytes = byName.get('human-acceptance.json');
  const assessmentBytes = byName.get('post-review-assessment.json');
  validateCandidateMotion(candidateMotionBytes);
  validateHumanAcceptance(humanAcceptanceBytes);
  validateAssessment(assessmentBytes);
  const sourceAnchorBytes = byName.get('source-anchor.json');
  const sourceAnchor = validateSourceAnchor(sourceAnchorBytes);
  const manifestBytes = byName.get('manifest.json');
  const manifest = parseJsonBytes(manifestBytes, 'manifest', 'manifest-structure-drift');
  assertion(
    manifestBytes.equals(canonicalArtifact(manifest)),
    'manifest is not canonical JSON plus LF'
  );
  exactKeys(
    manifest,
    [
      'schemaVersion',
      'hypothesis',
      'closurePurpose',
      'temporalSemantics',
      'outcome',
      'sourceSets',
      'payloadMemberCount',
      'members',
      'provenance',
      'disclosure',
      'publication',
      'authority',
      'action',
    ],
    'manifest'
  );
  exactKeys(manifest.outcome, ['status', 'stage', 'reasonCode', 'normative'], 'manifest outcome');
  exactKeys(manifest.sourceSets, ['preReview', 'postReview'], 'manifest source sets');
  exactKeys(manifest.sourceSets.preReview, ['count', 'sha256'], 'manifest pre-review source set');
  exactKeys(manifest.sourceSets.postReview, ['count', 'sha256'], 'manifest post-review source set');
  assertion(
    manifest.schemaVersion === 'overlaykit-h050-post-review-manifest/v1' &&
      manifest.hypothesis === 'H-050' &&
      manifest.closurePurpose ===
        'exclusive local post-review closure for the human-accepted H-050 product-intent decision' &&
      manifest.temporalSemantics ===
        'candidate content and digest were proposed before human acceptance; files and archive were materialized only afterward' &&
      canonicalJson(manifest.outcome) ===
        canonicalJson({
          status: 'supported',
          stage: 'closed-human-product-intent',
          reasonCode: 'human-require-automatic-nine-of-nine-accepted',
          normative: false,
        }) &&
      manifest.provenance ===
        'local content address only; the successor change and successor manifest remain outside this archive' &&
      manifest.disclosure === 'restricted-local' &&
      manifest.publication === 'not-authorized' &&
      manifest.authority === 'none' &&
      manifest.action === null,
    'manifest outcome or authority drift'
  );
  assertion(
    manifest.sourceSets?.preReview?.count === PRE_REVIEW_SOURCES.length &&
      manifest.sourceSets?.preReview?.sha256 === sourceAnchor.preReviewSourceSetSha256 &&
      manifest.sourceSets?.postReview?.count === POST_REVIEW_SOURCE_PATHS.length &&
      manifest.sourceSets?.postReview?.sha256 === sourceAnchor.postReviewSourceSetSha256,
    'manifest source sets drift'
  );
  assertion(
    Array.isArray(manifest.members) &&
      manifest.payloadMemberCount === manifest.members.length &&
      new Set(manifest.members.map(({ archivePath }) => archivePath)).size ===
        manifest.members.length,
    'manifest member cardinality or uniqueness differs'
  );
  const sortedManifestMembers = [...manifest.members].sort((left, right) =>
    compareArchivePath(left.archivePath, right.archivePath)
  );
  assertion(
    canonicalJson(manifest.members) === canonicalJson(sortedManifestMembers),
    'manifest members are not sorted'
  );
  for (const member of manifest.members) {
    exactKeys(
      member,
      ['role', 'sourcePath', 'archivePath', 'byteLength', 'sha256'],
      `manifest member ${member.archivePath}`
    );
    validateArchivePath(member.archivePath);
    assertion(
      Number.isSafeInteger(member.byteLength) &&
        member.byteLength >= 0 &&
        /^[0-9a-f]{64}$/u.test(member.sha256),
      `manifest member receipt invalid: ${member.archivePath}`
    );
  }

  const archiveBytes = byName.get(archiveFileName);
  const archiveSha256 = sha256(archiveBytes);
  assertion(
    archiveFileName === `replay-${archiveSha256}.tar`,
    'archive file name does not bind its digest'
  );
  const parsedMembers = parseUstar(archiveBytes);
  assertion(
    parsedMembers.every(
      ({ mode, uid, gid, mtime }) => mode === 0o600 && uid === 0 && gid === 0 && mtime === 0
    ),
    'archive metadata is not normalized'
  );
  const rebuiltArchive = buildUstar(
    parsedMembers.map(({ archivePath, bytes }) => ({ archivePath, bytes }))
  );
  assertion(rebuiltArchive.equals(archiveBytes), 'archive is not the exact deterministic rebuild');
  const archiveByPath = new Map(parsedMembers.map((member) => [member.archivePath, member.bytes]));
  assertion(
    archiveByPath.size === manifest.members.length + 1 &&
      archiveByPath.has('metadata/manifest.json'),
    'archive and manifest member cardinality differ'
  );
  assertion(
    archiveByPath.get('metadata/manifest.json').equals(manifestBytes),
    'archive manifest differs from external manifest'
  );
  for (const member of manifest.members) {
    const bytes = archiveByPath.get(member.archivePath);
    assertion(bytes !== undefined, `archive member missing: ${member.archivePath}`);
    assertion(
      bytes.length === member.byteLength && sha256(bytes) === member.sha256,
      `archive member receipt differs: ${member.archivePath}`
    );
  }
  for (const [archivePath, bytes] of [
    ['metadata/source-anchor.json', sourceAnchorBytes],
    ['metadata/candidate-motion.json', candidateMotionBytes],
    ['metadata/human-acceptance.json', humanAcceptanceBytes],
    ['metadata/post-review-assessment.json', assessmentBytes],
  ]) {
    assertion(
      archiveByPath.get(archivePath)?.equals(bytes),
      `${archivePath} external copy differs`
    );
  }
  for (const entry of [...sourceAnchor.preReviewSources, ...sourceAnchor.postReviewSources]) {
    const archivePath =
      entry.path === 'lab/h050/canonical-candidate-motion.json'
        ? 'metadata/candidate-motion.json'
        : entry.path === 'lab/h050/human-acceptance.json'
          ? 'metadata/human-acceptance.json'
          : entry.path === 'lab/h050/post-review-assessment.json'
            ? 'metadata/post-review-assessment.json'
            : entry.path.startsWith('lab/h050/post-review.')
              ? `sources/post-review/${entry.path}`
              : `sources/pre-review/${entry.path}`;
    const bytes = archiveByPath.get(archivePath);
    assertion(
      bytes !== undefined && bytes.length === entry.byteLength && sha256(bytes) === entry.sha256,
      `source-anchor payload differs: ${entry.path}`
    );
  }

  const closureBytes = byName.get('closure.json');
  const closure = parseJsonBytes(closureBytes, 'closure', 'closure-structure-drift');
  assertion(
    closureBytes.equals(canonicalArtifact(closure)),
    'closure is not canonical JSON plus LF'
  );
  const expectedClosure = createExternalClosure({
    sourceAnchorBytes,
    candidateMotionBytes,
    humanAcceptanceBytes,
    assessmentBytes,
    manifestBytes,
    archiveBytes,
    archiveFileName,
    archiveMemberCount: parsedMembers.length,
  });
  assertion(
    canonicalJson(closure) === canonicalJson(expectedClosure),
    'closure envelope differs from independent reconstruction'
  );
  return {
    schemaVersion: 'overlaykit-h050-post-review-closure-verification/v1',
    verified: true,
    closureDirectory: closureReal,
    candidateMotionSha256: RAW_HASHES.candidateMotion,
    humanAcceptanceSha256: RAW_HASHES.humanAcceptance,
    assessmentSha256: RAW_HASHES.assessment,
    sourceAnchorSha256: sha256(sourceAnchorBytes),
    manifestSha256: sha256(manifestBytes),
    archiveSha256,
    archiveByteLength: archiveBytes.length,
    archiveMemberCount: parsedMembers.length,
    preReviewSourceCount: PRE_REVIEW_SOURCES.length,
    postReviewSourceCount: POST_REVIEW_SOURCE_PATHS.length,
    outcome: 'supported',
    authority: 'none',
    action: null,
  };
}

export function materializePostReviewClosure() {
  const allowedRoot = path.dirname(H050_POST_REVIEW_CLOSURE_ROOT);
  ensureSafeDirectoryChain(REPOSITORY_ROOT, allowedRoot);
  const result = buildPostReviewClosure();
  writePostReviewClosure(result, {
    allowedRoot,
    outputDirectory: H050_POST_REVIEW_CLOSURE_ROOT,
  });
  return verifyPostReviewClosure();
}

function invalidOutcome(reasonCode, detail) {
  return {
    status: 'invalid',
    stage: 'evidence-admission',
    reasonCode,
    detail,
  };
}

export function verifyH050PostReview(options = {}) {
  const subjectLockBytes =
    options.subjectLockBytes ?? readLocalRegularFile(FILES.subjectLock, 'subject lock');
  const docketBytes = options.docketBytes ?? readLocalRegularFile(FILES.docket, 'docket');
  const candidateMotionBytes =
    options.candidateMotionBytes ?? readLocalRegularFile(FILES.candidateMotion, 'candidate motion');
  const humanAcceptanceBytes =
    options.humanAcceptanceBytes ?? readLocalRegularFile(FILES.humanAcceptance, 'human acceptance');
  const assessmentBytes =
    options.assessmentBytes ?? readLocalRegularFile(FILES.assessment, 'post-review assessment');

  validatePreReviewSources(subjectLockBytes, docketBytes);
  const motion = validateCandidateMotion(candidateMotionBytes);
  validateHumanAcceptance(humanAcceptanceBytes);
  const assessment = validateAssessment(assessmentBytes);

  return {
    schemaVersion: 'overlaykit-h050-post-review-verification/v1',
    verified: true,
    temporalClosure: {
      candidateMotion: {
        rawSha256: sha256(candidateMotionBytes),
        byteLength: candidateMotionBytes.length,
        productIntent: motion.productIntent,
        selectedPredicateCount: motion.predicateDecisions.length,
      },
      humanAcceptance: {
        rawSha256: sha256(humanAcceptanceBytes),
        acceptedCandidateMotionSha256: RAW_HASHES.candidateMotion,
        acceptedDocketRawSha256: RAW_HASHES.docket,
        transportBytesClaimed: false,
      },
      assessment: {
        rawSha256: sha256(assessmentBytes),
        temporallyAfterAcceptance:
          assessment.temporalOrder.assessment === 'created-after-local-materialization',
      },
    },
    outcome: { ...EXPECTED_OUTCOME },
    checks: {
      preReviewSubjectAndDocketByteIdentical: true,
      candidateMotionCanonicalAndByteExact: true,
      nineOfNineDecisionsExact: true,
      humanAcceptanceBindsCandidateAndDocket: true,
      displayedAndSemanticRepresentationsExact: true,
      rawTransportBytesNotClaimed: true,
      temporalSeparationPreserved: true,
      noSpecificationAdrOrImplementationAuthority: true,
      localPostReviewOnly: true,
    },
    capabilityAudit: {
      mode: 'offline-local-post-review-closure-verification',
      filesRead: 5,
      network: false,
      liveHost: false,
      usb: false,
      hidraw: false,
      docker: false,
      signals: false,
      writes: false,
      worktreeGovernanceEvidenceWritesObserved: true,
      ignoredArtifactClosureWritesAuthorized: true,
      gitHistoryMutation: false,
    },
    authority: 'none',
    action: null,
  };
}

export function verifyH050PostReviewSafe(options = {}) {
  try {
    return verifyH050PostReview(options);
  } catch (error) {
    if (!(error instanceof InvalidPostReviewEvidenceError)) throw error;
    return {
      schemaVersion: 'overlaykit-h050-post-review-verification/v1',
      verified: false,
      outcome: invalidOutcome(error.reasonCode, error.message),
      authority: 'none',
      action: null,
    };
  }
}

function isMain() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMain()) {
  const [command, ...rest] = process.argv.slice(2);
  if (command === '--materialize-closure' && rest.length === 0) {
    process.stdout.write(`${canonicalJson(materializePostReviewClosure())}\n`);
  } else if (command === '--verify-closure' && rest.length === 0) {
    process.stdout.write(`${canonicalJson(verifyPostReviewClosure())}\n`);
  } else if (command === undefined) {
    const result = verifyH050PostReviewSafe();
    process.stdout.write(`${canonicalJson(result)}\n`);
    if (!result.verified) process.exitCode = 1;
  } else {
    process.stderr.write(
      'usage: node lab/h050/post-review.mjs [--materialize-closure|--verify-closure]\n'
    );
    process.exitCode = 2;
  }
}
