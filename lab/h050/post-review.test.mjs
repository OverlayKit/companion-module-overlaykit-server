import assert from 'node:assert/strict';
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  H050_POST_REVIEW_PREDICATE_DECISIONS,
  assertBuildInputsStable,
  buildPostReviewClosure,
  buildUstar,
  canonicalArtifact,
  canonicalJson,
  parseUstar,
  sha256,
  verifyH050PostReview,
  verifyH050PostReviewSafe,
  verifyPostReviewClosure,
  writePostReviewClosure,
} from './post-review.mjs';

const CANDIDATE_SHA256 = '20aa95c65dd0fb05bc21d7d98e7ba839895de5ded959b781db9d32893e1e1e28';
const DOCKET_SHA256 = '7a145c440af25f5bbbb71c111381f886dccba387e6a0880853e666ceabea6684';
const ACCEPTANCE_SHA256 = 'd392ec651f80cdd715ef7482a829b823631fc94ceb8abf926e957c7f7f690602';
const ASSESSMENT_SHA256 = 'a324a4fbce441c32ceba2d92aebba4323b747151a1f2b845de4601a9db40ca23';

const candidateBytes = readFileSync(new URL('./canonical-candidate-motion.json', import.meta.url));
const acceptanceBytes = readFileSync(new URL('./human-acceptance.json', import.meta.url));
const assessmentBytes = readFileSync(new URL('./post-review-assessment.json', import.meta.url));

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function temporaryDirectory(prefix) {
  return mkdtempSync(path.join(tmpdir(), prefix));
}

function materializeTemporaryClosure(temporaryRoot) {
  const allowedRoot = path.join(temporaryRoot, 'allowed');
  const outputDirectory = path.join(allowedRoot, CANDIDATE_SHA256);
  mkdirSync(allowedRoot, { mode: 0o700 });
  const result = buildPostReviewClosure();
  writePostReviewClosure(result, { allowedRoot, outputDirectory });
  return { result, outputDirectory };
}

test('canonical candidate bytes match the accepted 4,139-byte nomination', () => {
  assert.equal(candidateBytes.length, 4139);
  assert.equal(sha256(candidateBytes), CANDIDATE_SHA256);
  const candidate = JSON.parse(candidateBytes);
  assert.deepEqual(candidateBytes, canonicalArtifact(candidate));
  assert.equal(candidate.productIntent, 'require-automatic');
  assert.deepEqual(candidate.predicateDecisions, H050_POST_REVIEW_PREDICATE_DECISIONS);
  assert.equal(candidate.predicateDecisions.length, 9);
  assert.equal(candidate.authority, 'none');
  assert.equal(candidate.action, null);
});

test('human acceptance separates proposal, acceptance, and later local materialization', () => {
  assert.equal(sha256(acceptanceBytes), ACCEPTANCE_SHA256);
  const acceptance = JSON.parse(acceptanceBytes);
  assert.deepEqual(acceptance.temporalSequence, {
    candidateProposal: 'exact-content-and-digest-presented-before-human-acceptance',
    humanAcceptance: 'subsequent-to-candidate-proposal',
    localMaterialization:
      'candidate-file-and-acceptance-record-materialized-after-human-acceptance',
    postReviewAssessment: 'materialized-after-this-acceptance-record',
  });
  assert.equal(acceptance.acceptance.acceptedCandidateMotionSha256, CANDIDATE_SHA256);
  assert.equal(acceptance.acceptance.acceptedDocketRawSha256, DOCKET_SHA256);
  assert.deepEqual(acceptance.acceptance.authorizes, ['local-post-review-closure']);
  assert.equal(acceptance.acceptance.authorizationExhaustive, true);
  assert.equal(acceptance.acceptance.outsideAuthorizedSet, 'unauthorized');
  assert.equal(acceptance.representations.transportBytes.claimed, false);
  assert.equal(acceptance.representations.transportBytes.sha256, null);
  for (const representation of [
    acceptance.representations.displayedMarkdown,
    acceptance.representations.semanticFolded,
  ]) {
    const bytes = Buffer.from(representation.value, 'utf8');
    assert.equal(bytes.length, representation.utf8ByteLength);
    assert.equal(sha256(bytes), representation.sha256);
  }
});

test('post-review classification is supported only inside the non-authorizing docket boundary', () => {
  const result = verifyH050PostReview();
  assert.equal(result.verified, true);
  assert.deepEqual(result.outcome, {
    status: 'supported',
    stage: 'closed-human-product-intent',
    reasonCode: 'human-require-automatic-nine-of-nine-accepted',
    claimBoundary:
      'the exact human-accepted candidate resolves all nine non-normative H-050 product-intent decisions for the nominated docket; it does not create product law or authorize any later transition',
  });
  assert.equal(result.temporalClosure.candidateMotion.rawSha256, CANDIDATE_SHA256);
  assert.equal(result.temporalClosure.humanAcceptance.rawSha256, ACCEPTANCE_SHA256);
  assert.equal(result.temporalClosure.assessment.rawSha256, ASSESSMENT_SHA256);
  assert.equal(result.temporalClosure.humanAcceptance.transportBytesClaimed, false);
  assert.equal(result.authority, 'none');
  assert.equal(result.action, null);

  const assessment = JSON.parse(assessmentBytes);
  assert.equal(sha256(assessmentBytes), ASSESSMENT_SHA256);
  assert.equal(assessment.adrAssessment.candidateActivated, false);
  assert.equal(assessment.specificationAssessment.draftingAuthorized, false);
  assert.equal(assessment.specificationAssessment.acceptanceAuthorized, false);
  assert.equal(assessment.capabilityAudit.worktreeGovernanceEvidenceWrites, true);
  assert.equal(assessment.capabilityAudit.gitHistoryMutation, false);
  assert.equal(assessment.epistemicClaims.at(-1).kind, 'assumption');
  assert.match(assessment.epistemicClaims.at(-1).statement, /evidence only/u);
});

test('candidate, acceptance, and assessment drift fail closed', () => {
  const candidate = JSON.parse(candidateBytes);
  candidate.predicateDecisions[0].value = 'weakened';
  const candidateResult = verifyH050PostReviewSafe({
    candidateMotionBytes: canonicalArtifact(candidate),
  });
  assert.equal(candidateResult.verified, false);
  assert.equal(candidateResult.outcome.status, 'invalid');
  assert.equal(candidateResult.outcome.reasonCode, 'candidate-motion-raw-drift');

  const acceptance = JSON.parse(acceptanceBytes);
  acceptance.representations.transportBytes = {
    claimed: true,
    byteLength: 419,
    sha256: acceptance.representations.semanticFolded.sha256,
  };
  const acceptanceResult = verifyH050PostReviewSafe({
    humanAcceptanceBytes: jsonBytes(acceptance),
  });
  assert.equal(acceptanceResult.verified, false);
  assert.equal(acceptanceResult.outcome.status, 'invalid');
  assert.equal(acceptanceResult.outcome.reasonCode, 'human-acceptance-raw-drift');

  const assessment = JSON.parse(assessmentBytes);
  assessment.specificationAssessment.draftingAuthorized = true;
  assessment.adrAssessment.candidateActivated = true;
  const assessmentResult = verifyH050PostReviewSafe({
    assessmentBytes: jsonBytes(assessment),
  });
  assert.equal(assessmentResult.verified, false);
  assert.equal(assessmentResult.outcome.status, 'invalid');
  assert.equal(assessmentResult.outcome.reasonCode, 'post-review-assessment-raw-drift');
});

test('canonical JSON and POSIX ustar output are deterministic and metadata-normalized', () => {
  assert.equal(
    canonicalJson({ z: 1, a: [{ y: true, x: null }] }),
    '{"a":[{"x":null,"y":true}],"z":1}'
  );
  const left = buildUstar([
    { archivePath: 'z/last.txt', bytes: Buffer.from('last') },
    { archivePath: 'a/first.txt', bytes: Buffer.from('first') },
  ]);
  const right = buildUstar([
    { archivePath: 'a/first.txt', bytes: Buffer.from('first') },
    { archivePath: 'z/last.txt', bytes: Buffer.from('last') },
  ]);
  assert.deepEqual(left, right);
  assert.deepEqual(
    parseUstar(left).map(({ archivePath, mode, uid, gid, mtime }) => ({
      archivePath,
      mode,
      uid,
      gid,
      mtime,
    })),
    [
      { archivePath: 'a/first.txt', mode: 0o600, uid: 0, gid: 0, mtime: 0 },
      { archivePath: 'z/last.txt', mode: 0o600, uid: 0, gid: 0, mtime: 0 },
    ]
  );
});

test('ustar rejects traversal, alternate separators, duplicates, and corruption', () => {
  for (const hostilePath of ['../escape', 'safe\\hidden', 'C:/escape', '/absolute']) {
    assert.throws(
      () => buildUstar([{ archivePath: hostilePath, bytes: Buffer.alloc(0) }]),
      /archive path/u
    );
  }
  assert.throws(
    () =>
      buildUstar([
        { archivePath: 'same', bytes: Buffer.alloc(0) },
        { archivePath: 'same', bytes: Buffer.alloc(0) },
      ]),
    /duplicate ustar member/u
  );
  const corrupt = buildUstar([{ archivePath: 'safe', bytes: Buffer.from('value') }]);
  corrupt[0] ^= 1;
  assert.throws(() => parseUstar(corrupt), /ustar checksum differs/u);
});

test('closure build preserves eight pre-review sources, five post-review sources, and no successor', () => {
  const first = buildPostReviewClosure();
  const second = buildPostReviewClosure();
  assert.deepEqual(first.archiveBytes, second.archiveBytes);
  assert.equal(first.sourceAnchor.preReviewSourceCount, 8);
  assert.equal(first.sourceAnchor.postReviewSourceCount, 5);
  assert.equal(first.sourceAnchor.successorBoundary.successorChangeIncluded, false);
  assert.equal(first.sourceAnchor.successorBoundary.successorManifestIncluded, false);
  assert.equal(first.manifest.payloadMemberCount, 14);
  assert.equal(parseUstar(first.archiveBytes).length, 15);
  assert.equal(first.closure.candidateMotion.proposalPrecededAcceptance, true);
  assert.equal(first.closure.candidateMotion.fileMaterializedAfterAcceptance, true);
  assert.equal(first.closure.humanAcceptance.anythingElseAuthorized, false);
  assert.equal(first.closure.preSuccessorBoundary.successorChangeIncluded, false);
  assert.equal(first.closure.authority, 'none');
  assert.equal(first.closure.action, null);
});

test('source stability check rejects changed postflight bytes', () => {
  const temporaryRoot = temporaryDirectory('overlaykit-h050-source-stability-');
  try {
    const sourcePath = path.join(temporaryRoot, 'source.txt');
    writeFileSync(sourcePath, 'changed', { mode: 0o644 });
    const snapshot = {
      preReviewSources: [
        {
          path: 'source.txt',
          mode: '0644',
          byteLength: 8,
          sha256: sha256('original'),
        },
      ],
      postReviewSources: [],
      sourceBytes: new Map([['source.txt', Buffer.from('original')]]),
    };
    assert.throws(
      () => assertBuildInputsStable(temporaryRoot, snapshot),
      /postflight source bytes differ/u
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('written closure has exact roster and verifies by independent reconstruction', () => {
  const temporaryRoot = temporaryDirectory('overlaykit-h050-closure-');
  try {
    const { result, outputDirectory } = materializeTemporaryClosure(temporaryRoot);
    const verified = verifyPostReviewClosure({ closureDirectory: outputDirectory });
    assert.equal(verified.verified, true);
    assert.equal(verified.outcome, 'supported');
    assert.equal(verified.candidateMotionSha256, CANDIDATE_SHA256);
    assert.equal(verified.humanAcceptanceSha256, ACCEPTANCE_SHA256);
    assert.equal(verified.assessmentSha256, ASSESSMENT_SHA256);
    assert.equal(verified.preReviewSourceCount, 8);
    assert.equal(verified.postReviewSourceCount, 5);
    assert.equal(verified.authority, 'none');
    assert.equal(verified.action, null);
    assert.deepEqual(readdirSync(outputDirectory).sort(), result.closure.directoryFiles.sort());
    assert.equal(lstatSync(outputDirectory).mode & 0o777, 0o700);
    for (const fileName of readdirSync(outputDirectory)) {
      const stat = lstatSync(path.join(outputDirectory, fileName));
      assert.equal(stat.isFile(), true);
      assert.equal(stat.isSymbolicLink(), false);
      assert.equal(stat.nlink, 1);
      assert.equal(stat.mode & 0o777, 0o600);
    }
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('closure writer refuses overwrite, symlink ancestors, and hard-linked targets', () => {
  const temporaryRoot = temporaryDirectory('overlaykit-h050-writer-hostile-');
  try {
    const { result, outputDirectory } = materializeTemporaryClosure(temporaryRoot);
    const allowedRoot = path.dirname(outputDirectory);
    assert.throws(
      () => writePostReviewClosure(result, { allowedRoot, outputDirectory }),
      /refusing to overwrite existing file/u
    );
    assert.throws(
      () =>
        writePostReviewClosure(result, {
          allowedRoot,
          outputDirectory: path.join(temporaryRoot, 'escape'),
        }),
      /output directory escapes allowed root/u
    );

    const outside = path.join(temporaryRoot, 'outside');
    mkdirSync(outside, { mode: 0o700 });
    symlinkSync(outside, path.join(allowedRoot, 'linked-parent'));
    assert.throws(
      () =>
        writePostReviewClosure(result, {
          allowedRoot,
          outputDirectory: path.join(allowedRoot, 'linked-parent', 'closure'),
        }),
      /directory component is unsafe/u
    );
    assert.equal(existsSync(path.join(outside, 'closure')), false);

    const hardlinkDirectory = path.join(allowedRoot, 'hardlink');
    mkdirSync(hardlinkDirectory, { mode: 0o700 });
    const outsideFile = path.join(temporaryRoot, 'outside-candidate.json');
    writeFileSync(outsideFile, candidateBytes, { mode: 0o600 });
    linkSync(outsideFile, path.join(hardlinkDirectory, 'candidate-motion.json'));
    assert.throws(
      () =>
        writePostReviewClosure(result, {
          allowedRoot,
          outputDirectory: hardlinkDirectory,
        }),
      /multiple links/u
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('closure verification rejects archive tampering', () => {
  const temporaryRoot = temporaryDirectory('overlaykit-h050-archive-tamper-');
  try {
    const { result, outputDirectory } = materializeTemporaryClosure(temporaryRoot);
    const archivePath = path.join(outputDirectory, result.archiveFileName);
    const archive = readFileSync(archivePath);
    archive[512] ^= 1;
    writeFileSync(archivePath, archive, { mode: 0o600 });
    chmodSync(archivePath, 0o600);
    assert.throws(
      () => verifyPostReviewClosure({ closureDirectory: outputDirectory }),
      /archive file name does not bind its digest/u
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('closure verification rejects an unmanifested deterministic archive member', () => {
  const temporaryRoot = temporaryDirectory('overlaykit-h050-extra-member-');
  try {
    const { result, outputDirectory } = materializeTemporaryClosure(temporaryRoot);
    const originalArchivePath = path.join(outputDirectory, result.archiveFileName);
    const expandedArchive = buildUstar([
      ...parseUstar(readFileSync(originalArchivePath)).map(({ archivePath, bytes }) => ({
        archivePath,
        bytes,
      })),
      { archivePath: 'zzzz/unmanifested.bin', bytes: Buffer.from('hostile') },
    ]);
    const expandedSha256 = sha256(expandedArchive);
    const expandedFileName = `replay-${expandedSha256}.tar`;
    unlinkSync(originalArchivePath);
    writeFileSync(path.join(outputDirectory, expandedFileName), expandedArchive, { mode: 0o600 });

    const closurePath = path.join(outputDirectory, 'closure.json');
    const closure = JSON.parse(readFileSync(closurePath, 'utf8'));
    closure.bundle.path = `artifacts/h050/post-review-closures/${CANDIDATE_SHA256}/${expandedFileName}`;
    closure.bundle.sha256 = expandedSha256;
    closure.bundle.byteLength = expandedArchive.length;
    closure.bundle.memberCount += 1;
    closure.determinism.buildASha256 = expandedSha256;
    closure.determinism.buildBSha256 = expandedSha256;
    closure.directoryFiles = closure.directoryFiles.map((name) =>
      name === result.archiveFileName ? expandedFileName : name
    );
    writeFileSync(closurePath, canonicalArtifact(closure), { mode: 0o600 });
    assert.throws(
      () => verifyPostReviewClosure({ closureDirectory: outputDirectory }),
      /archive and manifest member cardinality differ/u
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('closure verification rejects publication, ADR, or SPEC overclaim', () => {
  const temporaryRoot = temporaryDirectory('overlaykit-h050-overclaim-');
  try {
    const { outputDirectory } = materializeTemporaryClosure(temporaryRoot);
    const closurePath = path.join(outputDirectory, 'closure.json');
    const closure = JSON.parse(readFileSync(closurePath, 'utf8'));
    closure.publication = 'authorized';
    closure.adrAssessment.candidateActivated = true;
    closure.specificationAssessment.draftingAuthorized = true;
    writeFileSync(closurePath, canonicalArtifact(closure), { mode: 0o600 });
    assert.throws(
      () => verifyPostReviewClosure({ closureDirectory: outputDirectory }),
      /closure envelope differs/u
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('closure verification rejects source-anchor subject, temporal, and provenance drift', () => {
  const mutations = [
    (sourceAnchor) => {
      sourceAnchor.subject.commit = '0'.repeat(40);
    },
    (sourceAnchor) => {
      sourceAnchor.temporalBoundary.localMaterialization = 'before-human-acceptance';
    },
    (sourceAnchor) => {
      sourceAnchor.provenance = 'signed-and-published';
    },
  ];
  for (const mutate of mutations) {
    const temporaryRoot = temporaryDirectory('overlaykit-h050-anchor-drift-');
    try {
      const { outputDirectory } = materializeTemporaryClosure(temporaryRoot);
      const sourceAnchorPath = path.join(outputDirectory, 'source-anchor.json');
      const sourceAnchor = JSON.parse(readFileSync(sourceAnchorPath, 'utf8'));
      mutate(sourceAnchor);
      writeFileSync(sourceAnchorPath, canonicalArtifact(sourceAnchor), { mode: 0o600 });
      assert.throws(
        () => verifyPostReviewClosure({ closureDirectory: outputDirectory }),
        /source anchor envelope differs/u
      );
    } finally {
      rmSync(temporaryRoot, { recursive: true, force: true });
    }
  }
});

test('closure verification rejects manifest boundary and outcome drift', () => {
  const mutations = [
    (manifest) => {
      manifest.closurePurpose = 'authorize implementation';
    },
    (manifest) => {
      manifest.temporalSemantics = 'candidate file existed before acceptance';
    },
    (manifest) => {
      manifest.outcome.reasonCode = 'agent-self-approved';
    },
    (manifest) => {
      manifest.provenance = 'remote-durable';
    },
    (manifest) => {
      manifest.disclosure = 'public';
    },
  ];
  for (const mutate of mutations) {
    const temporaryRoot = temporaryDirectory('overlaykit-h050-manifest-drift-');
    try {
      const { outputDirectory } = materializeTemporaryClosure(temporaryRoot);
      const manifestPath = path.join(outputDirectory, 'manifest.json');
      const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
      mutate(manifest);
      writeFileSync(manifestPath, canonicalArtifact(manifest), { mode: 0o600 });
      assert.throws(
        () => verifyPostReviewClosure({ closureDirectory: outputDirectory }),
        /manifest outcome or authority drift/u
      );
    } finally {
      rmSync(temporaryRoot, { recursive: true, force: true });
    }
  }
});

test('post-review verifier is independent of the pre-review verifier and external capabilities', () => {
  const source = readFileSync(new URL('./post-review.mjs', import.meta.url), 'utf8');
  assert.equal(/from ['"]\.\/verify\.mjs['"]/u.test(source), false);
  assert.equal(/node:(?:child_process|http|https|net|tls|dgram)/u.test(source), false);
  assert.equal(/\b(?:spawn|exec|fetch)\s*\(/u.test(source), false);
  assert.match(source, /gitHistoryMutation: false/u);
  assert.match(source, /worktreeGovernanceEvidenceWrites: true/u);
});
