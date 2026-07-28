import assert from 'node:assert/strict';
import {
  chmodSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  H051_MAP_CANONICAL_SHA256,
  H051_MAP_RAW_SHA256,
  H051_POST_REVIEW_CLOSURE_ROOT,
  InvalidH051PostReviewEvidenceError,
  assertH051PostReviewInputsStable,
  assertClosureParentMetadata,
  buildClosureOutputFiles,
  buildPostReviewClosure,
  buildUstar,
  canonicalArtifact,
  captureH051PostReviewInputs,
  parseUstar,
  sha256,
  validateHumanAcceptance,
  validatePostReviewAssessment,
  verifyH051PostReviewSafe,
  verifyPostReviewClosure,
  writePostReviewClosure,
} from './post-review.mjs';

const acceptanceBytes = readFileSync(new URL('./human-acceptance.json', import.meta.url));
const assessmentBytes = readFileSync(new URL('./post-review-assessment.json', import.meta.url));
const acceptance = JSON.parse(acceptanceBytes);
const assessment = JSON.parse(assessmentBytes);

function clone(value) {
  return structuredClone(value);
}

function assertReason(reasonCode) {
  return (error) => {
    assert.ok(error instanceof InvalidH051PostReviewEvidenceError);
    assert.equal(error.reasonCode, reasonCode);
    return true;
  };
}

function writeFixture(result, outputDirectory) {
  mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });
  chmodSync(outputDirectory, 0o700);
  const files = new Map([
    ['human-acceptance.json', acceptanceBytes],
    ['post-review-assessment.json', assessmentBytes],
    ['source-anchor.json', result.sourceAnchorBytes],
    ['manifest.json', result.manifestBytes],
    [result.archiveFileName, result.archiveBytes],
    ['closure.json', result.closureBytes],
  ]);
  for (const [name, bytes] of files) {
    writeFileSync(path.join(outputDirectory, name), bytes, { flag: 'wx', mode: 0o600 });
    chmodSync(path.join(outputDirectory, name), 0o600);
  }
}

test('human acceptance preserves two ordered non-transport review events', () => {
  assert.equal(validateHumanAcceptance(acceptance), true);
  assert.equal(
    sha256(acceptanceBytes),
    '69f2918fdc0f816ef2b70438d7b2731d94242eb3db191dff7d4b8e5c6b95ff23'
  );
  assert.equal(acceptance.subject.readinessMapRawSha256, H051_MAP_RAW_SHA256);
  assert.equal(acceptance.subject.readinessMapCanonicalJsonSha256, H051_MAP_CANONICAL_SHA256);
  assert.equal(acceptance.representations.humanAcceptance.transportBytes.claimed, false);
  assert.equal(acceptance.representations.closureGrant.transportBytes.claimed, false);
  assert.deepEqual(acceptance.closureAuthorization.authorizes, [
    'local-content-addressed-post-review-closure',
  ]);
});

test('post-review assessment accepts semantics while preserving inconclusive source bytes', () => {
  assert.equal(validatePostReviewAssessment(assessment), true);
  assert.equal(
    sha256(assessmentBytes),
    '7512c59bb1d5ef1f858a25d2e1d9c65c4be2656e488bf1265a63fe30881df2e2'
  );
  assert.equal(assessment.humanReviewReceipt.semanticClassificationsAccepted, true);
  assert.equal(assessment.mechanicalRecord.sourceStatus, 'agent-proposed-pending-human-acceptance');
  assert.equal(assessment.mechanicalRecord.sourceBytesMutated, false);
  assert.equal(assessment.outcome.status, 'inconclusive');
  assert.equal(assessment.adrAssessment.candidateActivated, false);
  assert.equal(assessment.authority, 'none');
  assert.equal(assessment.action, null);
});

test('exact input capture closes 26 locked, 11 envelope, and 4 post-review sources', () => {
  const snapshot = captureH051PostReviewInputs();
  assert.equal(snapshot.gitDescriptors.length, 18);
  assert.equal(snapshot.localDescriptors.length, 8);
  assert.equal(snapshot.envelopeDescriptors.length, 11);
  assert.equal(snapshot.postReviewDescriptors.length, 4);
  assert.equal(snapshot.bytesByArchivePath.size, 41);
  assert.equal(snapshot.preReviewVerification.outcome.status, 'inconclusive');
  assert.equal(snapshot.preReviewVerification.semanticClassificationsAccepted, false);
  assert.equal(assertH051PostReviewInputsStable(snapshot), true);
});

test('two independent closure builds are byte-identical and form a 43-member archive', () => {
  const first = buildPostReviewClosure();
  const second = buildPostReviewClosure();
  assert.deepEqual(first.sourceAnchorBytes, second.sourceAnchorBytes);
  assert.deepEqual(first.manifestBytes, second.manifestBytes);
  assert.deepEqual(first.archiveBytes, second.archiveBytes);
  assert.deepEqual(first.closureBytes, second.closureBytes);
  assert.equal(first.sourceAnchor.preReviewSourceCount, 37);
  assert.equal(first.sourceAnchor.postReviewSourceCount, 4);
  assert.equal(first.manifest.memberCount, 42);
  assert.equal(first.archiveMembers.length, 43);
  assert.equal(parseUstar(first.archiveBytes).length, 43);
  assert.equal(first.closure.postReviewAssessment.status, 'inconclusive');
  assert.equal(first.closure.adrAssessment.candidateActivated, false);
  assert.equal(first.closure.authority, 'none');
  assert.equal(first.closure.action, null);
});

test('ustar is bytewise deterministic and normalizes all metadata', () => {
  const first = buildUstar([
    { archivePath: 'z', bytes: Buffer.from('last') },
    { archivePath: 'a', bytes: Buffer.from('first') },
  ]);
  const second = buildUstar([
    { archivePath: 'a', bytes: Buffer.from('first') },
    { archivePath: 'z', bytes: Buffer.from('last') },
  ]);
  assert.deepEqual(first, second);
  assert.deepEqual(
    parseUstar(first).map(({ archivePath, bytes }) => [archivePath, bytes.toString('utf8')]),
    [
      ['a', 'first'],
      ['z', 'last'],
    ]
  );
});

test('ustar rejects traversal, alternate separators, duplicates, checksum, and padding drift', () => {
  for (const hostilePath of ['../escape', '/absolute', 'safe\\hidden', 'a/./b']) {
    assert.throws(
      () => buildUstar([{ archivePath: hostilePath, bytes: Buffer.alloc(0) }]),
      InvalidH051PostReviewEvidenceError
    );
  }
  assert.throws(
    () =>
      buildUstar([
        { archivePath: 'same', bytes: Buffer.alloc(0) },
        { archivePath: 'same', bytes: Buffer.alloc(0) },
      ]),
    assertReason('archive-member-duplicate')
  );
  const checksumDrift = buildUstar([{ archivePath: 'safe', bytes: Buffer.from('value') }]);
  checksumDrift[0] ^= 1;
  assert.throws(() => parseUstar(checksumDrift), assertReason('archive-checksum-invalid'));
  const paddingDrift = buildUstar([{ archivePath: 'safe', bytes: Buffer.from('value') }]);
  paddingDrift[512 + 5] = 1;
  assert.throws(() => parseUstar(paddingDrift), assertReason('archive-padding-invalid'));
  const missingTerminator = buildUstar([
    { archivePath: 'safe', bytes: Buffer.from('value') },
  ]).subarray(0, -1024);
  assert.throws(() => parseUstar(missingTerminator), assertReason('archive-roster-invalid'));
});

test('review rebound, artificial resolution, ADR activation, and action lift fail closed', () => {
  const rebound = clone(acceptance);
  rebound.subject.readinessMapRawSha256 = '0'.repeat(64);
  assert.throws(() => validateHumanAcceptance(rebound), assertReason('acceptance-subject-drift'));

  const resolved = clone(assessment);
  resolved.outcome.status = 'supported';
  assert.throws(
    () => validatePostReviewAssessment(resolved),
    assertReason('post-review-outcome-drift')
  );

  const adr = clone(assessment);
  adr.adrAssessment.candidateActivated = true;
  assert.throws(
    () => validatePostReviewAssessment(adr),
    assertReason('normative-authority-overclaim')
  );

  const action = clone(acceptance);
  action.action = { type: 'open-h052' };
  assert.throws(() => validateHumanAcceptance(action), assertReason('acceptance-envelope-drift'));
});

test('a changed source snapshot is rejected without mutating the workspace', () => {
  const snapshot = captureH051PostReviewInputs();
  const changed = {
    ...snapshot,
    envelopeDescriptors: clone(snapshot.envelopeDescriptors),
  };
  changed.envelopeDescriptors[0].sha256 = '0'.repeat(64);
  assert.throws(
    () => assertH051PostReviewInputsStable(changed),
    assertReason('postflight-source-drift')
  );
});

test('a temporary exact closure verifies and reconstructs byte-for-byte', () => {
  const temporaryRoot = mkdtempSync(path.join(tmpdir(), 'overlaykit-h051-post-review-'));
  try {
    const outputDirectory = path.join(temporaryRoot, H051_MAP_RAW_SHA256);
    const result = buildPostReviewClosure();
    writeFixture(result, outputDirectory);
    const verification = verifyPostReviewClosure({ closureDirectory: outputDirectory });
    assert.equal(verification.verified, true);
    assert.equal(verification.sourceClosure.preReviewSourceCount, 37);
    assert.equal(verification.sourceClosure.postReviewSourceCount, 4);
    assert.equal(verification.sourceClosure.archiveMemberCount, 43);
    assert.equal(verification.humanReview.semanticClassificationsAccepted, true);
    assert.equal(verification.humanReview.outcome, 'inconclusive');
    assert.equal(verification.adrAssessment.candidateActivated, false);
    assert.equal(verification.publication, 'not-authorized');
    assert.equal(verification.authority, 'none');
    assert.equal(verification.action, null);
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('archive tampering and a missing or extra external file fail closed', () => {
  for (const mutation of ['archive', 'missing', 'extra']) {
    const temporaryRoot = mkdtempSync(path.join(tmpdir(), `overlaykit-h051-${mutation}-`));
    try {
      const outputDirectory = path.join(temporaryRoot, H051_MAP_RAW_SHA256);
      const result = buildPostReviewClosure();
      writeFixture(result, outputDirectory);
      if (mutation === 'archive') {
        const archivePath = path.join(outputDirectory, result.archiveFileName);
        const archive = readFileSync(archivePath);
        archive[512] ^= 1;
        writeFileSync(archivePath, archive);
        chmodSync(archivePath, 0o600);
      } else if (mutation === 'missing') {
        rmSync(path.join(outputDirectory, 'source-anchor.json'));
      } else {
        writeFileSync(path.join(outputDirectory, 'extra.json'), '{}\n', { mode: 0o600 });
      }
      const verification = verifyH051PostReviewSafe({ closureDirectory: outputDirectory });
      assert.equal(verification.verified, false);
    } finally {
      rmSync(temporaryRoot, { recursive: true, force: true });
    }
  }
});

test('publication, successor, H-052, and capability overclaims fail closed', () => {
  const temporaryRoot = mkdtempSync(path.join(tmpdir(), 'overlaykit-h051-overclaim-'));
  try {
    const outputDirectory = path.join(temporaryRoot, H051_MAP_RAW_SHA256);
    const result = buildPostReviewClosure();
    writeFixture(result, outputDirectory);
    const closurePath = path.join(outputDirectory, 'closure.json');
    const closure = JSON.parse(readFileSync(closurePath, 'utf8'));
    closure.publication = 'authorized';
    closure.adrAssessment.candidateActivated = true;
    closure.successor.included = true;
    closure.successor.h052Authorized = true;
    closure.capabilityAudit.liveOrOperationalHostMutation = true;
    writeFileSync(closurePath, canonicalArtifact(closure));
    chmodSync(closurePath, 0o600);
    const verification = verifyH051PostReviewSafe({ closureDirectory: outputDirectory });
    assert.equal(verification.verified, false);
    assert.equal(verification.outcome.reasonCode, 'closure-authority-overclaim');
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('symlink and hardlink external closure members are rejected', () => {
  for (const kind of ['symlink', 'hardlink']) {
    const temporaryRoot = mkdtempSync(path.join(tmpdir(), `overlaykit-h051-${kind}-`));
    try {
      const outputDirectory = path.join(temporaryRoot, H051_MAP_RAW_SHA256);
      const result = buildPostReviewClosure();
      writeFixture(result, outputDirectory);
      const target = path.join(outputDirectory, 'source-anchor.json');
      const outside = path.join(temporaryRoot, 'outside.json');
      writeFileSync(outside, result.sourceAnchorBytes, { mode: 0o600 });
      rmSync(target);
      if (kind === 'symlink') symlinkSync(outside, target);
      else linkSync(outside, target);
      const verification = verifyH051PostReviewSafe({ closureDirectory: outputDirectory });
      assert.equal(verification.verified, false);
    } finally {
      rmSync(temporaryRoot, { recursive: true, force: true });
    }
  }
});

test('the production writer is fixed to one ignored canonical directory', () => {
  const source = readFileSync(new URL('./post-review.mjs', import.meta.url), 'utf8');
  assert.match(source, /artifacts\/h051\/post-review-closures/u);
  assert.equal(
    H051_POST_REVIEW_CLOSURE_ROOT.endsWith(
      `artifacts/h051/post-review-closures/${H051_MAP_RAW_SHA256}`
    ),
    true
  );
  assert.doesNotMatch(source, /node:(?:http|https|net|tls|dgram)/u);
  assert.doesNotMatch(source, /\b(?:fetch|WebSocket)\s*\(/u);
  assert.doesNotMatch(source, /\/dev\/(?:hidraw|bus\/usb)/u);
  assert.doesNotMatch(source, /\b(?:kill|spawn|execSync)\s*\(/u);
  assert.doesNotMatch(source, /shell\s*:\s*true/u);
  assert.doesNotMatch(source, /\brenameSync\s*\(/u);
  assert.match(source, /mkdirSync\(H051_POST_REVIEW_CLOSURE_ROOT,\s*\{\s*mode:\s*0o700\s*\}\)/u);
});

test('output receipts come only from the validated build snapshot', () => {
  const result = buildPostReviewClosure();
  const files = buildClosureOutputFiles(result);
  for (const [sourcePath, fileName] of [
    ['lab/h051/human-acceptance.json', 'human-acceptance.json'],
    ['lab/h051/post-review-assessment.json', 'post-review-assessment.json'],
  ]) {
    const descriptor = result.snapshot.postReviewDescriptors.find(
      (entry) => entry.sourcePath === sourcePath
    );
    assert.ok(descriptor);
    assert.equal(
      files.get(fileName),
      result.snapshot.bytesByArchivePath.get(descriptor.archivePath)
    );
  }
});

test('the production writer rejects a caller-supplied rebound closure before writing', () => {
  const result = buildPostReviewClosure();
  const rebound = { ...result, closureBytes: Buffer.from(result.closureBytes) };
  rebound.closureBytes[0] ^= 1;
  assert.throws(() => writePostReviewClosure(rebound), assertReason('writer-input-drift'));
});

test('an existing parent with mode drift is rejected without metadata mutation', () => {
  const temporaryRoot = mkdtempSync(path.join(tmpdir(), 'overlaykit-h051-parent-mode-'));
  try {
    const existingParent = path.join(temporaryRoot, 'h051');
    mkdirSync(existingParent, { recursive: true, mode: 0o755 });
    chmodSync(existingParent, 0o755);
    assert.throws(
      () => assertClosureParentMetadata(lstatSync(existingParent), existingParent),
      assertReason('output-root-mode-drift')
    );
    assert.equal(lstatSync(existingParent).mode & 0o777, 0o755);
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('safe verification fails closed on an absent directory', () => {
  const missing = path.join(tmpdir(), `overlaykit-h051-absent-${process.pid}-${Date.now()}`);
  const verification = verifyH051PostReviewSafe({ closureDirectory: missing });
  assert.equal(verification.verified, false);
  assert.equal(verification.outcome.status, 'invalid');
  assert.equal(verification.outcome.reasonCode, 'verification-error');
});
