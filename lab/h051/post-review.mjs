import { createHash } from 'node:crypto';
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalJson, inspectH051Sources, verifyH051 } from './verify.mjs';

const LAB_DIRECTORY = realpathSync(path.dirname(fileURLToPath(import.meta.url)));
const REPOSITORY_ROOT = realpathSync(path.resolve(LAB_DIRECTORY, '../..'));

export const H051_MAP_RAW_SHA256 =
  'dfb1156e6c16721c01d008cb5d760b05f10dc2328cfb871a3a80a29a4447c7ce';
export const H051_MAP_CANONICAL_SHA256 =
  '0a2ec483a1d4f3d6c3603b20a51c1abbcc2ef098e78306feee205c8409dd72a6';
const H051_ACCEPTANCE_RAW_SHA256 =
  '69f2918fdc0f816ef2b70438d7b2731d94242eb3db191dff7d4b8e5c6b95ff23';
const H051_ASSESSMENT_RAW_SHA256 =
  '7512c59bb1d5ef1f858a25d2e1d9c65c4be2656e488bf1265a63fe30881df2e2';
const H051_PRECONTRACT_RAW_SHA256 =
  '6cdc124c9707cd4a743cfdd68a1706534418ad5163da720aefe8e0c2ded7adf5';
const H051_MANIFEST_RAW_SHA256 = '902275239fcbfcaef3c9f6d0a12f754af866b63822fdf6a7294b94b677c02f0b';
const H051_SOURCE_LOCK_RAW_SHA256 =
  'e95b3c806c512fd116e169be3bd02c8673e8fc39c72f28b245e8ab28fabe0a0a';
const H051_DOCKET_RAW_SHA256 = 'adcd317603eb8678ab970f8dd0bcf63a3444d0bc6af669fa60b134b5d89237bc';
const H051_COMBINED_SOURCE_SET_SHA256 =
  '6d54e3ca53b02dc31495f3d1e2cdd965f48f04b24f1460e7a5149267c8921317';
const H051_DISPLAYED_ACCEPTANCE_SHA256 =
  'b0409b174310dbde980668f7a9a6acfac3e0f0b08b55c93380a60276fcd5f516';
const H051_FOLDED_ACCEPTANCE_SHA256 =
  'c7ba5e7b2003a010ebe8d410b39f10ad0edb5b9c842a05f694b79d2f9ec95ba8';
const H051_DISPLAYED_GRANT_SHA256 =
  '91dc487b6364bf1944254bbe2378b62393a1464a884f8cd9b0c9dc5c47a8fe44';
const H051_FOLDED_GRANT_SHA256 = '8b4b5d0d25bc246e703ffbf8d5cf18632e8519d72a2f1bcacb11faa177f1b367';

const PRE_REVIEW_ENVELOPE = Object.freeze([
  Object.freeze({
    path: '.gitignore',
    sha256: '2c42503834e61def3bf5840b5c553a73b2d569cee732c69e7420f75ce5e6f1fc',
  }),
  Object.freeze({
    path: '.overlaykit/governance/changes/CHG-0031.json',
    sha256: H051_PRECONTRACT_RAW_SHA256,
  }),
  Object.freeze({
    path: '.overlaykit/governance/manifest.json',
    sha256: H051_MANIFEST_RAW_SHA256,
  }),
  Object.freeze({
    path: 'lab/h051/subject-lock.json',
    sha256: H051_SOURCE_LOCK_RAW_SHA256,
  }),
  Object.freeze({
    path: 'lab/h051/specification-readiness-docket.json',
    sha256: H051_DOCKET_RAW_SHA256,
  }),
  Object.freeze({
    path: 'lab/h051/readiness-map.json',
    sha256: H051_MAP_RAW_SHA256,
  }),
  Object.freeze({
    path: 'lab/h051/schemas/subject-lock.schema.json',
    sha256: '96f781cfae12b89efeeb59fec55f159f54df7afd07a7774b222b4da0aad3bd5b',
  }),
  Object.freeze({
    path: 'lab/h051/schemas/specification-readiness-docket.schema.json',
    sha256: '68beb26521a95eb945958a30a01a90bb7507dd1fdfccd1d2a57f95c995bbfd9c',
  }),
  Object.freeze({
    path: 'lab/h051/schemas/readiness-map.schema.json',
    sha256: 'bb1f4aff225fd00004ae411d8cd55464a89b4eb125b89f3bc6b68ef427725384',
  }),
  Object.freeze({
    path: 'lab/h051/verify.mjs',
    sha256: '02dd9ff4b4d16472acbd9fadd2fb1adbb4bf473b53f53813263de759024058b2',
  }),
  Object.freeze({
    path: 'lab/h051/verify.test.mjs',
    sha256: '8589b784591c1fa60f2c3a620d2e4ce0075a1cd9d46cd9e69c47190873ddb556',
  }),
]);

const POST_REVIEW_PATHS = Object.freeze([
  'lab/h051/human-acceptance.json',
  'lab/h051/post-review-assessment.json',
  'lab/h051/post-review.mjs',
  'lab/h051/post-review.test.mjs',
]);

const ABSENT_SUCCESSORS = Object.freeze([
  '.overlaykit/governance/changes/CHG-0032.json',
  'lab/h052',
  'artifacts/h052',
]);

export const H051_POST_REVIEW_ALLOWED_ROOT = path.join(
  REPOSITORY_ROOT,
  'artifacts/h051/post-review-closures'
);
export const H051_POST_REVIEW_CLOSURE_ROOT = path.join(
  H051_POST_REVIEW_ALLOWED_ROOT,
  H051_MAP_RAW_SHA256
);

export class InvalidH051PostReviewEvidenceError extends Error {
  constructor(reasonCode, message) {
    super(message);
    this.name = 'InvalidH051PostReviewEvidenceError';
    this.reasonCode = reasonCode;
  }
}

function assertion(condition, reasonCode, message) {
  if (!condition) throw new InvalidH051PostReviewEvidenceError(reasonCode, message);
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function canonicalArtifact(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw new InvalidH051PostReviewEvidenceError(
      'json-invalid',
      `${label} is not valid JSON: ${error.message}`
    );
  }
}

function canonicalJsonBytesHash(value) {
  return sha256(Buffer.from(canonicalJson(value), 'utf8'));
}

function compareBytewise(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function assertCanonicalRelativePath(value, reasonCode = 'path-invalid') {
  assertion(typeof value === 'string' && value.length > 0, reasonCode, 'path is empty');
  assertion(!path.posix.isAbsolute(value), reasonCode, `absolute path: ${value}`);
  assertion(!value.includes('\\'), reasonCode, `alternate separator: ${value}`);
  assertion(path.posix.normalize(value) === value, reasonCode, `non-canonical path: ${value}`);
  assertion(
    !value.split('/').some((part) => part === '' || part === '.' || part === '..'),
    reasonCode,
    `unsafe path: ${value}`
  );
}

function repositoryPath(relativePath) {
  assertCanonicalRelativePath(relativePath);
  const absolutePath = path.resolve(REPOSITORY_ROOT, relativePath);
  assertion(
    absolutePath.startsWith(`${REPOSITORY_ROOT}${path.sep}`),
    'path-escape',
    `repository path escapes: ${relativePath}`
  );
  return absolutePath;
}

function assertNoSymlinkAncestors(absolutePath) {
  const relative = path.relative(REPOSITORY_ROOT, absolutePath);
  assertion(
    relative !== '' && !relative.startsWith('..') && !path.isAbsolute(relative),
    'path-escape',
    `path escapes repository: ${absolutePath}`
  );
  let cursor = REPOSITORY_ROOT;
  for (const part of relative.split(path.sep)) {
    cursor = path.join(cursor, part);
    const metadata = lstatSync(cursor);
    assertion(!metadata.isSymbolicLink(), 'symlink-source', `symlink source: ${cursor}`);
  }
}

function readRegularSource(relativePath, expectedSha256 = null) {
  const absolutePath = repositoryPath(relativePath);
  assertNoSymlinkAncestors(absolutePath);
  const metadata = lstatSync(absolutePath);
  assertion(metadata.isFile(), 'source-type-invalid', `not a regular file: ${relativePath}`);
  assertion(metadata.nlink === 1, 'source-hardlink', `hard-linked source: ${relativePath}`);
  const mode = (metadata.mode & 0o777).toString(8).padStart(4, '0');
  assertion(mode === '0644', 'source-mode-drift', `source mode differs: ${relativePath}`);
  const bytes = readFileSync(absolutePath);
  if (expectedSha256 !== null) {
    assertion(
      sha256(bytes) === expectedSha256,
      'source-byte-drift',
      `source bytes differ: ${relativePath}`
    );
  }
  return { bytes, mode };
}

function assertPathAbsent(relativePath) {
  const absolutePath = repositoryPath(relativePath);
  try {
    lstatSync(absolutePath);
  } catch (error) {
    if (error?.code === 'ENOENT') return;
    throw error;
  }
  throw new InvalidH051PostReviewEvidenceError(
    'successor-present',
    `unauthorized successor exists: ${relativePath}`
  );
}

function assertExactKeys(value, expected, label) {
  assertion(
    value !== null && typeof value === 'object' && !Array.isArray(value),
    'shape-drift',
    `${label} is not an object`
  );
  assertion(
    canonicalJson(Object.keys(value).sort()) === canonicalJson([...expected].sort()),
    'shape-drift',
    `${label} keys differ`
  );
}

function assertExactArray(actual, expected, reasonCode, label) {
  assertion(canonicalJson(actual) === canonicalJson(expected), reasonCode, `${label} differs`);
}

function verifyRepresentation(representation, expected) {
  assertExactKeys(representation, ['status', 'value', 'utf8ByteLength', 'sha256'], expected.label);
  const bytes = Buffer.from(representation.value, 'utf8');
  assertion(
    representation.status === expected.status &&
      representation.utf8ByteLength === bytes.length &&
      representation.sha256 === sha256(bytes) &&
      representation.utf8ByteLength === expected.byteLength &&
      representation.sha256 === expected.sha256,
    'review-representation-drift',
    `${expected.label} differs`
  );
}

export function validateHumanAcceptance(value) {
  assertion(
    value.schemaVersion === 'overlaykit-h051-human-acceptance/v1' &&
      value.hypothesis === 'H-051' &&
      value.principal === '@rodrigoteamx' &&
      value.normative === false &&
      value.authority === 'none' &&
      value.action === null,
    'acceptance-envelope-drift',
    'human acceptance envelope differs'
  );
  const subject = value.subject;
  assertion(
    subject.precontractRawSha256 === H051_PRECONTRACT_RAW_SHA256 &&
      subject.sourceLockRawSha256 === H051_SOURCE_LOCK_RAW_SHA256 &&
      subject.docketRawSha256 === H051_DOCKET_RAW_SHA256 &&
      subject.readinessMapRawSha256 === H051_MAP_RAW_SHA256 &&
      subject.readinessMapCanonicalJsonSha256 === H051_MAP_CANONICAL_SHA256,
    'acceptance-subject-drift',
    'human acceptance subject differs'
  );
  verifyRepresentation(value.representations.humanAcceptance.displayedMarkdown, {
    label: 'displayed human acceptance',
    status: 'model-visible-transcription-not-transport-bytes',
    byteLength: 846,
    sha256: H051_DISPLAYED_ACCEPTANCE_SHA256,
  });
  verifyRepresentation(value.representations.humanAcceptance.semanticFolded, {
    label: 'folded human acceptance',
    status: 'unquoted-folded-semantic-text-not-transport-bytes',
    byteLength: 811,
    sha256: H051_FOLDED_ACCEPTANCE_SHA256,
  });
  verifyRepresentation(value.representations.closureGrant.displayedMarkdown, {
    label: 'displayed closure grant',
    status: 'model-visible-transcription-not-transport-bytes',
    byteLength: 273,
    sha256: H051_DISPLAYED_GRANT_SHA256,
  });
  verifyRepresentation(value.representations.closureGrant.semanticFolded, {
    label: 'folded closure grant',
    status: 'unquoted-folded-semantic-text-not-transport-bytes',
    byteLength: 267,
    sha256: H051_FOLDED_GRANT_SHA256,
  });
  for (const event of ['humanAcceptance', 'closureGrant']) {
    const transport = value.representations[event].transportBytes;
    assertion(
      transport.claimed === false && transport.byteLength === null && transport.sha256 === null,
      'transport-byte-overclaim',
      `${event} claims inaccessible transport bytes`
    );
  }
  const acceptance = value.acceptance;
  assertion(
    acceptance.decision ===
      'accept-exact-readiness-map-and-eleven-classifications-as-inconclusive' &&
      acceptance.mappingCount === 9 &&
      acceptance.abstractSlotCount === 41 &&
      acceptance.citationCount === 19 &&
      acceptance.predicateReceiptCount === 11 &&
      acceptance.satisfiedPredicateCount === 9 &&
      acceptance.outcome.status === 'inconclusive' &&
      acceptance.outcome.reasonCode ===
        'relationship-carrier-ambiguous-and-schema-compiler-pending',
    'acceptance-decision-drift',
    'human acceptance decision differs'
  );
  assertExactArray(
    acceptance.ambiguousPredicates,
    ['mapsSpecificationRelationship'],
    'acceptance-decision-drift',
    'ambiguous predicates'
  );
  assertExactArray(
    acceptance.unresolvedPredicates,
    ['schemaCompilerAdmitsAdditiveLifecycle'],
    'acceptance-decision-drift',
    'unresolved predicates'
  );
  const authorization = value.closureAuthorization;
  assertExactArray(
    authorization.authorizes,
    ['local-content-addressed-post-review-closure'],
    'closure-authority-drift',
    'authorized actions'
  );
  assertion(
    authorization.requiresPreReviewByteIdentity === true &&
      authorization.authorizationExhaustive === true &&
      authorization.outsideAuthorizedSet === 'unauthorized',
    'closure-authority-drift',
    'closure authority boundary differs'
  );
  assertExactArray(
    authorization.doesNotAuthorize,
    [
      'CHG-successor',
      'commit',
      'push',
      'merge',
      'publication',
      'SPEC',
      'ADR',
      'live-observation',
      'live-host-mutation',
      'H-052',
    ],
    'closure-authority-drift',
    'denied actions'
  );
  return true;
}

export function validatePostReviewAssessment(value) {
  assertion(
    value.schemaVersion === 'overlaykit-h051-post-review-assessment/v1' &&
      value.hypothesis === 'H-051' &&
      value.normative === false &&
      value.authority === 'none' &&
      value.action === null,
    'assessment-envelope-drift',
    'post-review assessment envelope differs'
  );
  assertion(
    value.sources.precontract.rawSha256 === H051_PRECONTRACT_RAW_SHA256 &&
      value.sources.manifest.rawSha256 === H051_MANIFEST_RAW_SHA256 &&
      value.sources.subjectLock.rawSha256 === H051_SOURCE_LOCK_RAW_SHA256 &&
      value.sources.docket.rawSha256 === H051_DOCKET_RAW_SHA256 &&
      value.sources.readinessMap.rawSha256 === H051_MAP_RAW_SHA256 &&
      value.sources.readinessMap.canonicalJsonSha256 === H051_MAP_CANONICAL_SHA256 &&
      value.sources.humanAcceptance.rawSha256 === H051_ACCEPTANCE_RAW_SHA256,
    'assessment-source-drift',
    'post-review assessment source binding differs'
  );
  const review = value.humanReviewReceipt;
  assertion(
    review.principal === '@rodrigoteamx' &&
      review.exactMapHashesAccepted === true &&
      review.mappingCount === 9 &&
      review.abstractSlotCount === 41 &&
      review.citationCount === 19 &&
      review.predicateReceiptCount === 11 &&
      review.satisfiedPredicateCount === 9 &&
      review.semanticClassificationsAccepted === true &&
      review.transportBytesClaimed === false,
    'assessment-review-drift',
    'human review receipt differs'
  );
  assertExactArray(
    review.ambiguousPredicatesAccepted,
    ['mapsSpecificationRelationship'],
    'assessment-review-drift',
    'accepted ambiguous predicates'
  );
  assertExactArray(
    review.unresolvedPredicatesAccepted,
    ['schemaCompilerAdmitsAdditiveLifecycle'],
    'assessment-review-drift',
    'accepted unresolved predicates'
  );
  assertion(
    value.mechanicalRecord.sourceStatus === 'agent-proposed-pending-human-acceptance' &&
      value.mechanicalRecord.sourceHumanAcceptanceRequired === true &&
      value.mechanicalRecord.sourceBytesMutated === false,
    'mechanical-record-rewrite',
    'pre-review mechanical record was reinterpreted'
  );
  assertion(
    value.outcome.status === 'inconclusive' &&
      value.outcome.stage === 'closed-human-review-specification-readiness' &&
      value.outcome.reasonCode === 'relationship-carrier-ambiguous-and-schema-compiler-pending',
    'post-review-outcome-drift',
    'post-review outcome differs'
  );
  assertion(
    value.adrAssessment.candidateActivated === false &&
      value.specificationAssessment.draftingAuthorized === false &&
      value.specificationAssessment.acceptanceAuthorized === false,
    'normative-authority-overclaim',
    'assessment activates ADR or SPEC authority'
  );
  const capabilities = value.capabilityAudit;
  assertion(
    capabilities.network === false &&
      capabilities.liveObservation === false &&
      capabilities.usb === false &&
      capabilities.hidraw === false &&
      capabilities.docker === false &&
      capabilities.signals === false &&
      capabilities.installation === false &&
      capabilities.configurationMutation === false &&
      capabilities.serviceOrProcessMutation === false &&
      capabilities.localEvidenceWrites === true &&
      capabilities.preReviewSourceMutation === false &&
      capabilities.governanceMutation === false &&
      capabilities.productMutation === false &&
      capabilities.gitHistoryMutation === false,
    'capability-overclaim',
    'assessment capability boundary differs'
  );
  assertion(
    value.closureAuthorization === 'local-content-addressed-post-review-only' &&
      value.durability === 'local-unsigned-not-published',
    'closure-authority-drift',
    'assessment closure boundary differs'
  );
  return true;
}

function archivePathFor(kind, index, relativePath) {
  if (kind === 'post-review') {
    if (relativePath.endsWith('/human-acceptance.json')) return 'metadata/human-acceptance.json';
    if (relativePath.endsWith('/post-review-assessment.json')) {
      return 'metadata/post-review-assessment.json';
    }
  }
  return `sources/${kind}/${String(index).padStart(3, '0')}`;
}

function sourceDescriptor({ sourcePath, archivePath, role, bytes, mode = '0644' }) {
  return {
    sourcePath,
    archivePath,
    role,
    mode,
    byteLength: bytes.length,
    sha256: sha256(bytes),
  };
}

function descriptorSetSha256(descriptors) {
  return sha256(
    Buffer.from(
      canonicalJson(
        descriptors.map(({ sourcePath, archivePath, role, mode, byteLength, sha256: digest }) => ({
          sourcePath,
          archivePath,
          role,
          mode,
          byteLength,
          sha256: digest,
        }))
      ),
      'utf8'
    )
  );
}

export function captureH051PostReviewInputs() {
  for (const relativePath of ABSENT_SUCCESSORS) assertPathAbsent(relativePath);
  const preReviewVerification = verifyH051();
  assertion(
    preReviewVerification.structuralIntegrityVerified === true &&
      preReviewVerification.semanticClassificationsAccepted === false &&
      preReviewVerification.outcome.status === 'inconclusive' &&
      preReviewVerification.authority === 'none' &&
      preReviewVerification.action === null,
    'pre-review-verification-drift',
    'pre-review H-051 verification differs'
  );

  const envelope = new Map();
  const envelopeDescriptors = PRE_REVIEW_ENVELOPE.map((expected, index) => {
    const source = readRegularSource(expected.path, expected.sha256);
    envelope.set(expected.path, source.bytes);
    return sourceDescriptor({
      sourcePath: expected.path,
      archivePath: archivePathFor('h051-pre-review', index, expected.path),
      role: 'h051-pre-review-envelope',
      bytes: source.bytes,
      mode: source.mode,
    });
  });
  const subjectLock = parseJson(envelope.get('lab/h051/subject-lock.json'), 'subject lock');
  assertion(
    subjectLock.combinedSourceSetSha256 === H051_COMBINED_SOURCE_SET_SHA256 &&
      subjectLock.gitSources.length === 18 &&
      subjectLock.localSources.length === 8,
    'subject-lock-drift',
    'subject lock source closure differs'
  );
  const inspected = inspectH051Sources(subjectLock);
  const gitDescriptors = subjectLock.gitSources.map((entry, index) => {
    const bytes = inspected.sourceBytesByPath.get(entry.path);
    assertion(
      bytes !== undefined && bytes.length === entry.byteLength && sha256(bytes) === entry.sha256,
      'locked-git-source-drift',
      `locked Git source differs: ${entry.path}`
    );
    return sourceDescriptor({
      sourcePath: entry.path,
      archivePath: archivePathFor('normative-git', index, entry.path),
      role: 'locked-normative-git-source',
      bytes,
      mode: entry.mode === '100644' ? '0644' : entry.mode,
    });
  });
  const localDescriptors = subjectLock.localSources.map((entry, index) => {
    const bytes = inspected.sourceBytesByPath.get(entry.path);
    assertion(
      bytes !== undefined && bytes.length === entry.byteLength && sha256(bytes) === entry.sha256,
      'locked-local-source-drift',
      `locked local source differs: ${entry.path}`
    );
    return sourceDescriptor({
      sourcePath: entry.path,
      archivePath: archivePathFor('local-predecessor', index, entry.path),
      role: 'locked-local-predecessor-source',
      bytes,
      mode: entry.mode,
    });
  });

  const postReview = new Map();
  const postReviewDescriptors = POST_REVIEW_PATHS.map((relativePath, index) => {
    const expectedSha256 =
      relativePath === 'lab/h051/human-acceptance.json'
        ? H051_ACCEPTANCE_RAW_SHA256
        : relativePath === 'lab/h051/post-review-assessment.json'
          ? H051_ASSESSMENT_RAW_SHA256
          : null;
    const source = readRegularSource(relativePath, expectedSha256);
    postReview.set(relativePath, source.bytes);
    return sourceDescriptor({
      sourcePath: relativePath,
      archivePath: archivePathFor('post-review', index, relativePath),
      role: relativePath.endsWith('human-acceptance.json')
        ? 'human-acceptance'
        : relativePath.endsWith('post-review-assessment.json')
          ? 'post-review-assessment'
          : 'post-review-replay-source',
      bytes: source.bytes,
      mode: source.mode,
    });
  });

  const map = parseJson(envelope.get('lab/h051/readiness-map.json'), 'readiness map');
  assertion(
    sha256(envelope.get('lab/h051/readiness-map.json')) === H051_MAP_RAW_SHA256 &&
      canonicalJsonBytesHash(map) === H051_MAP_CANONICAL_SHA256,
    'readiness-map-drift',
    'readiness map identity differs'
  );
  const acceptance = parseJson(
    postReview.get('lab/h051/human-acceptance.json'),
    'human acceptance'
  );
  const assessment = parseJson(
    postReview.get('lab/h051/post-review-assessment.json'),
    'post-review assessment'
  );
  validateHumanAcceptance(acceptance);
  validatePostReviewAssessment(assessment);

  const precontract = parseJson(
    envelope.get('.overlaykit/governance/changes/CHG-0031.json'),
    'CHG-0031'
  );
  assertion(
    precontract.id === 'CHG-0031' && precontract.status === 'proposed',
    'precontract-lifecycle-drift',
    'CHG-0031 lifecycle differs'
  );

  const bytesByArchivePath = new Map();
  for (const descriptor of [...gitDescriptors, ...localDescriptors, ...envelopeDescriptors]) {
    const bytes =
      descriptor.role === 'locked-normative-git-source' ||
      descriptor.role === 'locked-local-predecessor-source'
        ? inspected.sourceBytesByPath.get(descriptor.sourcePath)
        : envelope.get(descriptor.sourcePath);
    bytesByArchivePath.set(descriptor.archivePath, bytes);
  }
  for (const descriptor of postReviewDescriptors) {
    bytesByArchivePath.set(descriptor.archivePath, postReview.get(descriptor.sourcePath));
  }

  return {
    subjectLock,
    gitDescriptors,
    localDescriptors,
    envelopeDescriptors,
    postReviewDescriptors,
    bytesByArchivePath,
    preReviewVerification,
  };
}

export function assertH051PostReviewInputsStable(snapshot) {
  const current = captureH051PostReviewInputs();
  for (const key of [
    'gitDescriptors',
    'localDescriptors',
    'envelopeDescriptors',
    'postReviewDescriptors',
  ]) {
    assertion(
      canonicalJson(current[key]) === canonicalJson(snapshot[key]),
      'postflight-source-drift',
      `${key} changed during closure build`
    );
  }
  for (const [archivePath, bytes] of snapshot.bytesByArchivePath) {
    assertion(
      current.bytesByArchivePath.has(archivePath) &&
        current.bytesByArchivePath.get(archivePath).equals(bytes),
      'postflight-source-drift',
      `source bytes changed during closure build: ${archivePath}`
    );
  }
  return true;
}

function validateArchivePath(archivePath) {
  assertCanonicalRelativePath(archivePath, 'archive-path-invalid');
  assertion(
    /^[\x20-\x7e]+$/u.test(archivePath) && Buffer.byteLength(archivePath, 'utf8') <= 100,
    'archive-path-invalid',
    `archive path is not portable ustar: ${archivePath}`
  );
}

function writeAscii(buffer, offset, length, value, label) {
  const bytes = Buffer.from(value, 'ascii');
  assertion(bytes.length <= length, 'ustar-field-overflow', `${label} does not fit`);
  bytes.copy(buffer, offset);
}

function writeOctal(buffer, offset, length, value, label) {
  assertion(Number.isSafeInteger(value) && value >= 0, 'ustar-value-invalid', `${label} invalid`);
  const encoded = `${value.toString(8).padStart(length - 1, '0')}\0`;
  assertion(encoded.length === length, 'ustar-field-overflow', `${label} does not fit`);
  writeAscii(buffer, offset, length, encoded, label);
}

function readString(buffer, offset, length) {
  const field = buffer.subarray(offset, offset + length);
  const nul = field.indexOf(0);
  return field.subarray(0, nul === -1 ? field.length : nul).toString('ascii');
}

function readOctal(buffer, offset, length, label) {
  const text = readString(buffer, offset, length).trim();
  assertion(/^[0-7]+$/u.test(text), 'ustar-field-invalid', `${label} is not octal`);
  return Number.parseInt(text, 8);
}

function ustarHeader(archivePath, bytes) {
  const header = Buffer.alloc(512);
  writeAscii(header, 0, 100, archivePath, 'name');
  writeOctal(header, 100, 8, 0o600, 'mode');
  writeOctal(header, 108, 8, 0, 'uid');
  writeOctal(header, 116, 8, 0, 'gid');
  writeOctal(header, 124, 12, bytes.length, 'size');
  writeOctal(header, 136, 12, 0, 'mtime');
  header.fill(0x20, 148, 156);
  header[156] = 0x30;
  writeAscii(header, 257, 6, 'ustar\0', 'magic');
  writeAscii(header, 263, 2, '00', 'version');
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  const checksumText = `${checksum.toString(8).padStart(6, '0')}\0 `;
  writeAscii(header, 148, 8, checksumText, 'checksum');
  return header;
}

export function buildUstar(inputMembers) {
  const members = [...inputMembers].sort((left, right) =>
    compareBytewise(left.archivePath, right.archivePath)
  );
  const names = members.map(({ archivePath }) => archivePath);
  assertion(new Set(names).size === names.length, 'archive-member-duplicate', 'duplicate member');
  const chunks = [];
  for (const member of members) {
    validateArchivePath(member.archivePath);
    assertion(Buffer.isBuffer(member.bytes), 'archive-member-invalid', 'member bytes missing');
    chunks.push(ustarHeader(member.archivePath, member.bytes), member.bytes);
    const padding = (512 - (member.bytes.length % 512)) % 512;
    if (padding > 0) chunks.push(Buffer.alloc(padding));
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

function isZeroBlock(block) {
  return block.every((byte) => byte === 0);
}

export function parseUstar(archiveBytes) {
  assertion(
    Buffer.isBuffer(archiveBytes) && archiveBytes.length % 512 === 0,
    'archive-size-invalid',
    'archive size is not block-aligned'
  );
  const members = [];
  let offset = 0;
  let terminated = false;
  while (offset < archiveBytes.length) {
    const header = archiveBytes.subarray(offset, offset + 512);
    assertion(header.length === 512, 'archive-truncated', 'truncated header');
    if (isZeroBlock(header)) {
      const second = archiveBytes.subarray(offset + 512, offset + 1024);
      assertion(
        second.length === 512 && isZeroBlock(second) && offset + 1024 === archiveBytes.length,
        'archive-terminator-invalid',
        'archive terminator differs'
      );
      terminated = true;
      break;
    }
    const storedChecksum = readOctal(header, 148, 8, 'checksum');
    const checksumHeader = Buffer.from(header);
    checksumHeader.fill(0x20, 148, 156);
    assertion(
      checksumHeader.reduce((sum, byte) => sum + byte, 0) === storedChecksum,
      'archive-checksum-invalid',
      'ustar checksum differs'
    );
    assertion(
      readString(header, 257, 6) === 'ustar' &&
        readString(header, 263, 2) === '00' &&
        header[156] === 0x30,
      'archive-header-invalid',
      'ustar identity differs'
    );
    const archivePath = readString(header, 0, 100);
    validateArchivePath(archivePath);
    assertion(
      readOctal(header, 100, 8, 'mode') === 0o600 &&
        readOctal(header, 108, 8, 'uid') === 0 &&
        readOctal(header, 116, 8, 'gid') === 0 &&
        readOctal(header, 136, 12, 'mtime') === 0,
      'archive-metadata-drift',
      `archive metadata differs: ${archivePath}`
    );
    const size = readOctal(header, 124, 12, 'size');
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    assertion(
      dataEnd <= archiveBytes.length,
      'archive-truncated',
      `member truncated: ${archivePath}`
    );
    const bytes = Buffer.from(archiveBytes.subarray(dataStart, dataEnd));
    const paddedEnd = dataStart + Math.ceil(size / 512) * 512;
    assertion(
      archiveBytes.subarray(dataEnd, paddedEnd).every((byte) => byte === 0),
      'archive-padding-invalid',
      `member padding differs: ${archivePath}`
    );
    members.push({ archivePath, bytes });
    offset = paddedEnd;
  }
  assertion(
    terminated &&
      members.length > 0 &&
      new Set(members.map(({ archivePath }) => archivePath)).size === members.length,
    'archive-roster-invalid',
    'archive terminator or member roster invalid'
  );
  const sorted = [...members].sort((left, right) =>
    compareBytewise(left.archivePath, right.archivePath)
  );
  assertion(
    canonicalJson(members.map(({ archivePath }) => archivePath)) ===
      canonicalJson(sorted.map(({ archivePath }) => archivePath)),
    'archive-order-invalid',
    'archive members are not bytewise sorted'
  );
  return members;
}

function buildSourceAnchor(snapshot) {
  const preReviewDescriptors = [
    ...snapshot.gitDescriptors,
    ...snapshot.localDescriptors,
    ...snapshot.envelopeDescriptors,
  ];
  return {
    schemaVersion: 'overlaykit-h051-local-source-anchor/v1',
    hypothesis: 'H-051',
    admission: 'local-content-addressed-unsigned',
    signatureStatus: 'absent-not-authorized',
    signedCommit: null,
    subject: {
      mapRawSha256: H051_MAP_RAW_SHA256,
      mapCanonicalJsonSha256: H051_MAP_CANONICAL_SHA256,
      precontractRawSha256: H051_PRECONTRACT_RAW_SHA256,
      manifestRawSha256: H051_MANIFEST_RAW_SHA256,
      sourceLockRawSha256: H051_SOURCE_LOCK_RAW_SHA256,
      docketRawSha256: H051_DOCKET_RAW_SHA256,
      combinedLockedSourceSetSha256: H051_COMBINED_SOURCE_SET_SHA256,
    },
    preReviewSourceCount: preReviewDescriptors.length,
    preReviewSourceSetSha256: descriptorSetSha256(preReviewDescriptors),
    preReviewSources: preReviewDescriptors,
    postReviewSourceCount: snapshot.postReviewDescriptors.length,
    postReviewSourceSetSha256: descriptorSetSha256(snapshot.postReviewDescriptors),
    postReviewSources: snapshot.postReviewDescriptors,
    temporalBoundary: {
      mapProposal: 'before-human-acceptance',
      humanAcceptance: 'after-map-proposal-and-before-closure-grant',
      closureGrant: 'after-human-acceptance-and-before-local-materialization',
      localMaterialization: 'after-explicit-closure-grant',
      archive: 'after-post-review-records-and-before-any-successor',
    },
    successorBoundary: {
      successorChange: 'CHG-0032',
      successorChangeIncluded: false,
      successorManifestIncluded: false,
      h052Included: false,
    },
    provenance:
      'local content address only; no transport-byte identity, cryptographic signature, independent timestamp, remote durability, or publication is claimed',
    authority: 'none',
    action: null,
  };
}

function manifestMember(descriptor) {
  return {
    archivePath: descriptor.archivePath,
    sourcePath: descriptor.sourcePath,
    role: descriptor.role,
    mode: '0600',
    byteLength: descriptor.byteLength,
    sha256: descriptor.sha256,
  };
}

export function buildPostReviewClosure() {
  const snapshot = captureH051PostReviewInputs();
  const sourceAnchor = buildSourceAnchor(snapshot);
  const sourceAnchorBytes = canonicalArtifact(sourceAnchor);
  const sourceAnchorDescriptor = sourceDescriptor({
    sourcePath: 'generated:source-anchor.json',
    archivePath: 'metadata/source-anchor.json',
    role: 'local-unsigned-source-anchor',
    bytes: sourceAnchorBytes,
  });
  const descriptors = [
    ...snapshot.gitDescriptors,
    ...snapshot.localDescriptors,
    ...snapshot.envelopeDescriptors,
    ...snapshot.postReviewDescriptors,
    sourceAnchorDescriptor,
  ];
  const members = descriptors
    .map(manifestMember)
    .sort((left, right) => compareBytewise(left.archivePath, right.archivePath));
  const manifest = {
    schemaVersion: 'overlaykit-h051-post-review-manifest/v1',
    hypothesis: 'H-051',
    closurePurpose:
      'exclusive local content-addressed closure of the human-accepted inconclusive H-051 review',
    disclosure: 'restricted-local-not-published',
    subject: {
      mapRawSha256: H051_MAP_RAW_SHA256,
      mapCanonicalJsonSha256: H051_MAP_CANONICAL_SHA256,
      humanAcceptanceRawSha256: H051_ACCEPTANCE_RAW_SHA256,
      postReviewAssessmentRawSha256: H051_ASSESSMENT_RAW_SHA256,
    },
    memberCount: members.length,
    members,
    authority: 'none',
    action: null,
  };
  const manifestBytes = canonicalArtifact(manifest);
  const archiveMembers = descriptors.map((descriptor) => ({
    archivePath: descriptor.archivePath,
    bytes:
      descriptor.archivePath === 'metadata/source-anchor.json'
        ? sourceAnchorBytes
        : snapshot.bytesByArchivePath.get(descriptor.archivePath),
  }));
  archiveMembers.push({ archivePath: 'manifest.json', bytes: manifestBytes });
  const archiveBytesA = buildUstar(archiveMembers);
  const archiveBytesB = buildUstar([...archiveMembers].reverse());
  assertion(
    archiveBytesA.equals(archiveBytesB),
    'archive-nondeterministic',
    'independent archive builds differ'
  );
  const archiveSha256 = sha256(archiveBytesA);
  const archiveFileName = `replay-${archiveSha256}.tar`;
  const closure = {
    schemaVersion: 'overlaykit-h051-post-review-closure/v1',
    hypothesis: 'H-051',
    subject: {
      mapRawSha256: H051_MAP_RAW_SHA256,
      mapCanonicalJsonSha256: H051_MAP_CANONICAL_SHA256,
      precontractRawSha256: H051_PRECONTRACT_RAW_SHA256,
      manifestRawSha256: H051_MANIFEST_RAW_SHA256,
    },
    temporalBoundary: {
      mapProposal: 'before-human-acceptance',
      humanAcceptance: 'after-map-proposal-and-before-closure-grant',
      closureGrant: 'after-human-acceptance-and-before-local-materialization',
      localMaterialization: 'after-explicit-closure-grant',
      archive: 'after-local-materialization-and-before-any-successor',
    },
    humanAcceptance: {
      rawSha256: H051_ACCEPTANCE_RAW_SHA256,
      displayedMarkdownSha256: H051_DISPLAYED_ACCEPTANCE_SHA256,
      semanticFoldedSha256: H051_FOLDED_ACCEPTANCE_SHA256,
      closureGrantDisplayedMarkdownSha256: H051_DISPLAYED_GRANT_SHA256,
      closureGrantSemanticFoldedSha256: H051_FOLDED_GRANT_SHA256,
      transportBytesClaimed: false,
      authorization: 'local-content-addressed-post-review-closure-only',
      anythingElseAuthorized: false,
    },
    postReviewAssessment: {
      rawSha256: H051_ASSESSMENT_RAW_SHA256,
      status: 'inconclusive',
      reasonCode: 'relationship-carrier-ambiguous-and-schema-compiler-pending',
      semanticClassificationsAccepted: true,
      satisfiedPredicateCount: 9,
      ambiguousPredicateCount: 1,
      unresolvedPredicateCount: 1,
    },
    sourceAnchor: {
      rawSha256: sha256(sourceAnchorBytes),
      signatureStatus: 'absent-not-authorized',
      signedCommit: null,
    },
    manifest: {
      rawSha256: sha256(manifestBytes),
      payloadMemberCount: members.length,
    },
    bundle: {
      fileName: archiveFileName,
      sha256: archiveSha256,
      byteLength: archiveBytesA.length,
      memberCount: archiveMembers.length,
    },
    determinism: {
      format: 'POSIX-ustar',
      order: 'unsigned-bytewise-archive-path',
      fileMode: '0600',
      uid: 0,
      gid: 0,
      mtime: 0,
      buildASha256: archiveSha256,
      buildBSha256: sha256(archiveBytesB),
      byteIdentical: true,
    },
    directoryFiles: [
      'closure.json',
      'human-acceptance.json',
      'manifest.json',
      'post-review-assessment.json',
      archiveFileName,
      'source-anchor.json',
    ].sort(compareBytewise),
    adrAssessment: {
      candidateActivated: false,
      authority: 'none',
      action: null,
    },
    specificationAssessment: {
      draftingAuthorized: false,
      acceptanceAuthorized: false,
    },
    publication: 'not-authorized',
    durability: 'local-unsigned-not-published',
    capabilityAudit: {
      localEvidenceWrites: true,
      liveOrOperationalHostMutation: false,
      network: false,
      gitHistoryMutation: false,
      productMutation: false,
      governanceMutation: false,
    },
    successor: {
      changeId: 'CHG-0032',
      included: false,
      authorized: false,
      h052Included: false,
      h052Authorized: false,
    },
    authority: 'none',
    action: null,
  };
  const closureBytes = canonicalArtifact(closure);
  assertH051PostReviewInputsStable(snapshot);
  return {
    snapshot,
    sourceAnchor,
    sourceAnchorBytes,
    manifest,
    manifestBytes,
    archiveMembers,
    archiveBytes: archiveBytesA,
    archiveFileName,
    closure,
    closureBytes,
  };
}

export function assertClosureParentMetadata(metadata, cursor) {
  assertion(
    metadata.isDirectory() && !metadata.isSymbolicLink(),
    'output-root-invalid',
    `closure parent is unsafe: ${cursor}`
  );
  assertion(
    (metadata.mode & 0o777) === 0o700,
    'output-root-mode-drift',
    `existing closure parent mode is not 0700: ${cursor}`
  );
  return true;
}

function ensureClosureParents() {
  const artifactsRoot = path.join(REPOSITORY_ROOT, 'artifacts');
  const artifactsMetadata = lstatSync(artifactsRoot);
  assertion(
    artifactsMetadata.isDirectory() && !artifactsMetadata.isSymbolicLink(),
    'output-root-invalid',
    'artifacts root is unsafe'
  );
  let cursor = artifactsRoot;
  for (const component of ['h051', 'post-review-closures']) {
    cursor = path.join(cursor, component);
    try {
      mkdirSync(cursor, { mode: 0o700 });
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
    }
    assertClosureParentMetadata(lstatSync(cursor), cursor);
  }
  assertion(
    realpathSync(H051_POST_REVIEW_ALLOWED_ROOT).startsWith(
      `${realpathSync(artifactsRoot)}${path.sep}`
    ),
    'output-root-invalid',
    'closure root escapes artifacts'
  );
}

function writeExclusiveFile(filePath, bytes) {
  writeFileSync(filePath, bytes, { flag: 'wx', mode: 0o600 });
  const metadata = lstatSync(filePath);
  assertion(
    metadata.isFile() &&
      !metadata.isSymbolicLink() &&
      metadata.nlink === 1 &&
      (metadata.mode & 0o777) === 0o600,
    'output-file-invalid',
    `written output is unsafe: ${filePath}`
  );
}

export function buildClosureOutputFiles(expected) {
  const postReviewBytes = (sourcePath) => {
    const descriptor = expected.snapshot.postReviewDescriptors.find(
      (entry) => entry.sourcePath === sourcePath
    );
    const bytes = descriptor
      ? expected.snapshot.bytesByArchivePath.get(descriptor.archivePath)
      : undefined;
    assertion(
      Buffer.isBuffer(bytes),
      'writer-snapshot-incomplete',
      `writer snapshot is missing ${sourcePath}`
    );
    return bytes;
  };
  const files = new Map([
    ['human-acceptance.json', postReviewBytes('lab/h051/human-acceptance.json')],
    ['post-review-assessment.json', postReviewBytes('lab/h051/post-review-assessment.json')],
    ['source-anchor.json', expected.sourceAnchorBytes],
    ['manifest.json', expected.manifestBytes],
    [expected.archiveFileName, expected.archiveBytes],
    ['closure.json', expected.closureBytes],
  ]);
  assertion(
    canonicalJson([...files.keys()].sort(compareBytewise)) ===
      canonicalJson(expected.closure.directoryFiles),
    'output-roster-drift',
    'output file roster differs'
  );
  return files;
}

export function writePostReviewClosure(result) {
  const expected = buildPostReviewClosure();
  assertion(
    result.sourceAnchorBytes?.equals(expected.sourceAnchorBytes) &&
      result.manifestBytes?.equals(expected.manifestBytes) &&
      result.archiveBytes?.equals(expected.archiveBytes) &&
      result.closureBytes?.equals(expected.closureBytes) &&
      result.archiveFileName === expected.archiveFileName,
    'writer-input-drift',
    'writer input does not match an exact current closure build'
  );
  ensureClosureParents();
  try {
    mkdirSync(H051_POST_REVIEW_CLOSURE_ROOT, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
    const verified = verifyPostReviewClosure({
      closureDirectory: H051_POST_REVIEW_CLOSURE_ROOT,
    });
    return { outputDirectory: H051_POST_REVIEW_CLOSURE_ROOT, verified, existing: true };
  }
  assertClosureParentMetadata(
    lstatSync(H051_POST_REVIEW_CLOSURE_ROOT),
    H051_POST_REVIEW_CLOSURE_ROOT
  );
  const files = buildClosureOutputFiles(expected);
  for (const [fileName, bytes] of files) {
    writeExclusiveFile(path.join(H051_POST_REVIEW_CLOSURE_ROOT, fileName), bytes);
  }
  const verified = verifyPostReviewClosure({
    closureDirectory: H051_POST_REVIEW_CLOSURE_ROOT,
  });
  return { outputDirectory: H051_POST_REVIEW_CLOSURE_ROOT, verified, existing: false };
}

function readClosureDirectory(closureDirectory) {
  const requestedDirectory = path.resolve(closureDirectory);
  let cursor = path.parse(requestedDirectory).root;
  for (const component of requestedDirectory.slice(cursor.length).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, component);
    const componentMetadata = lstatSync(cursor);
    assertion(
      !componentMetadata.isSymbolicLink(),
      'closure-directory-invalid',
      `closure directory ancestor is a symlink: ${cursor}`
    );
  }
  const absoluteDirectory = realpathSync(requestedDirectory);
  assertion(
    absoluteDirectory === requestedDirectory,
    'closure-directory-invalid',
    'closure directory realpath differs'
  );
  const metadata = lstatSync(requestedDirectory);
  assertion(
    metadata.isDirectory() && !metadata.isSymbolicLink() && (metadata.mode & 0o777) === 0o700,
    'closure-directory-invalid',
    'closure directory is unsafe'
  );
  const names = readdirSync(absoluteDirectory).sort(compareBytewise);
  const byName = new Map();
  for (const name of names) {
    assertCanonicalRelativePath(name, 'closure-file-name-invalid');
    assertion(!name.includes('/'), 'closure-file-name-invalid', `nested closure file: ${name}`);
    const filePath = path.join(absoluteDirectory, name);
    const fileMetadata = lstatSync(filePath);
    assertion(
      fileMetadata.isFile() &&
        !fileMetadata.isSymbolicLink() &&
        fileMetadata.nlink === 1 &&
        (fileMetadata.mode & 0o777) === 0o600,
      'closure-file-invalid',
      `unsafe closure file: ${name}`
    );
    byName.set(name, readFileSync(filePath));
  }
  return { absoluteDirectory, names, byName };
}

function validateExternalClosure(closure) {
  assertion(
    closure.schemaVersion === 'overlaykit-h051-post-review-closure/v1' &&
      closure.hypothesis === 'H-051' &&
      closure.authority === 'none' &&
      closure.action === null,
    'closure-envelope-drift',
    'external closure envelope differs'
  );
  assertion(
    closure.subject.mapRawSha256 === H051_MAP_RAW_SHA256 &&
      closure.subject.mapCanonicalJsonSha256 === H051_MAP_CANONICAL_SHA256 &&
      closure.humanAcceptance.rawSha256 === H051_ACCEPTANCE_RAW_SHA256 &&
      closure.humanAcceptance.transportBytesClaimed === false &&
      closure.humanAcceptance.anythingElseAuthorized === false,
    'closure-subject-drift',
    'external closure subject differs'
  );
  assertion(
    closure.postReviewAssessment.status === 'inconclusive' &&
      closure.postReviewAssessment.reasonCode ===
        'relationship-carrier-ambiguous-and-schema-compiler-pending' &&
      closure.postReviewAssessment.semanticClassificationsAccepted === true &&
      closure.postReviewAssessment.satisfiedPredicateCount === 9 &&
      closure.postReviewAssessment.ambiguousPredicateCount === 1 &&
      closure.postReviewAssessment.unresolvedPredicateCount === 1,
    'closure-outcome-drift',
    'external closure outcome differs'
  );
  assertion(
    closure.adrAssessment.candidateActivated === false &&
      closure.specificationAssessment.draftingAuthorized === false &&
      closure.specificationAssessment.acceptanceAuthorized === false &&
      closure.publication === 'not-authorized' &&
      closure.durability === 'local-unsigned-not-published' &&
      closure.successor.included === false &&
      closure.successor.authorized === false &&
      closure.successor.h052Included === false &&
      closure.successor.h052Authorized === false,
    'closure-authority-overclaim',
    'external closure expands authority'
  );
  assertion(
    closure.capabilityAudit.localEvidenceWrites === true &&
      closure.capabilityAudit.liveOrOperationalHostMutation === false &&
      closure.capabilityAudit.network === false &&
      closure.capabilityAudit.gitHistoryMutation === false &&
      closure.capabilityAudit.productMutation === false &&
      closure.capabilityAudit.governanceMutation === false,
    'closure-capability-overclaim',
    'external closure capability boundary differs'
  );
  return true;
}

export function verifyPostReviewClosure({ closureDirectory = H051_POST_REVIEW_CLOSURE_ROOT } = {}) {
  const { names, byName } = readClosureDirectory(closureDirectory);
  const closureBytes = byName.get('closure.json');
  assertion(closureBytes !== undefined, 'closure-file-missing', 'closure.json is absent');
  const closure = parseJson(closureBytes, 'external closure');
  assertion(
    closureBytes.equals(canonicalArtifact(closure)),
    'closure-canonical-drift',
    'external closure is not canonical JSON plus LF'
  );
  validateExternalClosure(closure);
  assertExactArray(
    names,
    closure.directoryFiles,
    'closure-directory-roster-drift',
    'closure directory files'
  );
  const archiveBytes = byName.get(closure.bundle.fileName);
  assertion(
    archiveBytes !== undefined &&
      sha256(archiveBytes) === closure.bundle.sha256 &&
      archiveBytes.length === closure.bundle.byteLength,
    'archive-external-drift',
    'external archive identity differs'
  );
  const archiveMembers = parseUstar(archiveBytes);
  assertion(
    archiveMembers.length === closure.bundle.memberCount,
    'archive-cardinality-drift',
    'archive member count differs'
  );
  const archiveByPath = new Map(
    archiveMembers.map(({ archivePath, bytes }) => [archivePath, bytes])
  );
  const manifestBytes = byName.get('manifest.json');
  assertion(
    manifestBytes !== undefined &&
      sha256(manifestBytes) === closure.manifest.rawSha256 &&
      archiveByPath.get('manifest.json')?.equals(manifestBytes),
    'manifest-external-drift',
    'manifest copies differ'
  );
  const manifest = parseJson(manifestBytes, 'manifest');
  assertion(
    manifestBytes.equals(canonicalArtifact(manifest)) &&
      manifest.schemaVersion === 'overlaykit-h051-post-review-manifest/v1' &&
      manifest.hypothesis === 'H-051' &&
      manifest.authority === 'none' &&
      manifest.action === null &&
      manifest.memberCount === manifest.members.length &&
      manifest.memberCount === closure.manifest.payloadMemberCount,
    'manifest-structure-drift',
    'manifest structure differs'
  );
  const expectedArchivePaths = [
    ...manifest.members.map(({ archivePath }) => archivePath),
    'manifest.json',
  ].sort(compareBytewise);
  assertExactArray(
    archiveMembers.map(({ archivePath }) => archivePath),
    expectedArchivePaths,
    'manifest-archive-bijection-drift',
    'manifest/archive paths'
  );
  for (const member of manifest.members) {
    const bytes = archiveByPath.get(member.archivePath);
    assertion(
      bytes !== undefined &&
        bytes.length === member.byteLength &&
        sha256(bytes) === member.sha256 &&
        member.mode === '0600',
      'manifest-member-drift',
      `manifest member differs: ${member.archivePath}`
    );
  }
  assertion(
    archiveByPath
      .get('metadata/human-acceptance.json')
      ?.equals(byName.get('human-acceptance.json')) &&
      archiveByPath
        .get('metadata/post-review-assessment.json')
        ?.equals(byName.get('post-review-assessment.json')) &&
      archiveByPath.get('metadata/source-anchor.json')?.equals(byName.get('source-anchor.json')),
    'metadata-copy-drift',
    'external metadata copies differ'
  );
  const acceptance = parseJson(byName.get('human-acceptance.json'), 'human acceptance');
  const assessment = parseJson(byName.get('post-review-assessment.json'), 'post-review assessment');
  validateHumanAcceptance(acceptance);
  validatePostReviewAssessment(assessment);
  const sourceAnchorBytes = byName.get('source-anchor.json');
  const sourceAnchor = parseJson(sourceAnchorBytes, 'source anchor');
  assertion(
    sourceAnchorBytes.equals(canonicalArtifact(sourceAnchor)) &&
      sha256(sourceAnchorBytes) === closure.sourceAnchor.rawSha256 &&
      sourceAnchor.signatureStatus === 'absent-not-authorized' &&
      sourceAnchor.signedCommit === null &&
      sourceAnchor.preReviewSourceCount === 37 &&
      sourceAnchor.postReviewSourceCount === 4 &&
      sourceAnchor.authority === 'none' &&
      sourceAnchor.action === null,
    'source-anchor-drift',
    'source anchor differs'
  );
  const rebuiltArchive = buildUstar(archiveMembers);
  assertion(
    rebuiltArchive.equals(archiveBytes),
    'archive-reconstruction-drift',
    'archive does not reconstruct byte-identically'
  );
  const expected = buildPostReviewClosure();
  assertion(
    expected.sourceAnchorBytes.equals(sourceAnchorBytes) &&
      expected.manifestBytes.equals(manifestBytes) &&
      expected.archiveBytes.equals(archiveBytes) &&
      expected.closureBytes.equals(closureBytes),
    'closure-reconstruction-drift',
    'closure envelope does not reconstruct from current exact inputs'
  );
  return {
    schemaVersion: 'overlaykit-h051-post-review-verification/v1',
    verified: true,
    hypothesis: 'H-051',
    sourceClosure: {
      preReviewSourceCount: sourceAnchor.preReviewSourceCount,
      postReviewSourceCount: sourceAnchor.postReviewSourceCount,
      sourceAnchorRawSha256: sha256(sourceAnchorBytes),
      manifestRawSha256: sha256(manifestBytes),
      archiveSha256: sha256(archiveBytes),
      archiveByteLength: archiveBytes.length,
      archiveMemberCount: archiveMembers.length,
      externalClosureRawSha256: sha256(closureBytes),
    },
    humanReview: {
      semanticClassificationsAccepted: true,
      outcome: 'inconclusive',
      reasonCode: 'relationship-carrier-ambiguous-and-schema-compiler-pending',
      satisfiedPredicateCount: 9,
      ambiguousPredicateCount: 1,
      unresolvedPredicateCount: 1,
    },
    adrAssessment: { candidateActivated: false },
    publication: 'not-authorized',
    durability: 'local-unsigned-not-published',
    authority: 'none',
    action: null,
  };
}

export function verifyH051PostReviewSafe(options = {}) {
  try {
    return verifyPostReviewClosure(options);
  } catch (error) {
    return {
      schemaVersion: 'overlaykit-h051-post-review-verification/v1',
      verified: false,
      hypothesis: 'H-051',
      outcome: {
        status: 'invalid',
        reasonCode:
          error instanceof InvalidH051PostReviewEvidenceError
            ? error.reasonCode
            : 'verification-error',
        message: error instanceof Error ? error.message : String(error),
      },
      authority: 'none',
      action: null,
    };
  }
}

export function materializePostReviewClosure() {
  const first = buildPostReviewClosure();
  const second = buildPostReviewClosure();
  assertion(
    first.archiveBytes.equals(second.archiveBytes) &&
      first.sourceAnchorBytes.equals(second.sourceAnchorBytes) &&
      first.manifestBytes.equals(second.manifestBytes) &&
      first.closureBytes.equals(second.closureBytes),
    'closure-nondeterministic',
    'independent closure builds differ'
  );
  return writePostReviewClosure(first);
}

function isMain() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMain()) {
  const materialized = materializePostReviewClosure();
  process.stdout.write(`${canonicalJson(materialized.verified)}\n`);
}
