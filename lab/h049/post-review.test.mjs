import assert from 'node:assert/strict';
import {
  chmodSync,
  copyFileSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  H049,
  H049_CANONICAL_MOTION,
  assertBuildInputsStable,
  buildPostReviewClosure,
  buildUstar,
  canonicalArtifact,
  canonicalJson,
  parseUstar,
  sha256,
  verifyPostReviewClosure,
  writePostReviewClosure,
} from './post-review.mjs';

const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const CANONICAL_CLOSURE_DIRECTORY = path.join(
  REPOSITORY_ROOT,
  'artifacts/h049/post-review-closures',
  H049.semanticEvidenceSha256
);

function materializeTestClosure(outputDirectory) {
  if (!existsSync(CANONICAL_CLOSURE_DIRECTORY)) {
    const result = buildPostReviewClosure();
    writePostReviewClosure(result, {
      outputDirectory,
      allowedRoot: path.dirname(outputDirectory),
    });
    return result.archiveFileName;
  }
  mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });
  chmodSync(outputDirectory, 0o700);
  for (const fileName of readdirSync(CANONICAL_CLOSURE_DIRECTORY)) {
    copyFileSync(
      path.join(CANONICAL_CLOSURE_DIRECTORY, fileName),
      path.join(outputDirectory, fileName)
    );
    chmodSync(path.join(outputDirectory, fileName), 0o600);
  }
  const archiveFileName = readdirSync(outputDirectory).find(
    (fileName) => fileName.startsWith('replay-') && fileName.endsWith('.tar')
  );
  assert.ok(archiveFileName);
  return archiveFileName;
}

test('canonical JSON sorts object keys while preserving array order', () => {
  assert.equal(
    canonicalJson({ z: 1, a: [{ y: true, x: null }] }),
    '{"a":[{"x":null,"y":true}],"z":1}'
  );
  assert.equal(canonicalArtifact({ b: 2, a: 1 }).toString('utf8'), '{"a":1,"b":2}\n');
});

test('the contextual successor reply has the exact nominated digest', () => {
  assert.equal(sha256(H049.transitionReply), H049.transitionReplySha256);
  assert.match(H049_CANONICAL_MOTION, /No activa ADR; authority: none, action: null/u);
});

test('the POSIX ustar writer is deterministic, sorted, and metadata-normalized', () => {
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

test('the ustar boundary rejects traversal, duplicates, and header corruption', () => {
  assert.throws(
    () => buildUstar([{ archivePath: '../escape', bytes: Buffer.alloc(0) }]),
    /unsafe archive path/u
  );
  for (const hostilePath of ['safe\\hidden', 'C:/escape', 'safe\0hidden']) {
    assert.throws(
      () => buildUstar([{ archivePath: hostilePath, bytes: Buffer.alloc(0) }]),
      /non-canonical archive path/u
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

test('the source boundary rejects a premature successor and changed postflight bytes', () => {
  const temporaryRoot = mkdtempSync(path.join(tmpdir(), 'overlaykit-h049-source-boundary-'));
  try {
    const successorPath = path.join(temporaryRoot, '.overlaykit/governance/changes/CHG-0027.json');
    mkdirSync(path.dirname(successorPath), { recursive: true });
    writeFileSync(successorPath, '{}\n');
    const emptySnapshot = {
      harnessSourceMap: { sources: [] },
      sourceBytes: new Map(),
      postReviewSourceBytes: new Map(),
    };
    assert.throws(
      () => assertBuildInputsStable(temporaryRoot, emptySnapshot),
      /must be absent at the pre-review boundary/u
    );
    rmSync(successorPath);

    const sourcePath = path.join(temporaryRoot, 'source.txt');
    writeFileSync(sourcePath, 'changed', { mode: 0o644 });
    const changedSnapshot = {
      harnessSourceMap: {
        sources: [{ path: 'source.txt', mode: '0644' }],
      },
      sourceBytes: new Map([['source.txt', Buffer.from('original')]]),
      postReviewSourceBytes: new Map(),
    };
    assert.throws(
      () => assertBuildInputsStable(temporaryRoot, changedSnapshot),
      /postflight source bytes differ/u
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('the closure writer rejects a symlink in an output ancestor', () => {
  const temporaryRoot = mkdtempSync(path.join(tmpdir(), 'overlaykit-h049-writer-boundary-'));
  try {
    const allowedRoot = path.join(temporaryRoot, 'allowed');
    const outsideRoot = path.join(temporaryRoot, 'outside');
    mkdirSync(allowedRoot, { mode: 0o700 });
    mkdirSync(outsideRoot, { mode: 0o700 });
    symlinkSync(outsideRoot, path.join(allowedRoot, 'linked-parent'));
    const result = buildPostReviewClosure();
    assert.throws(
      () =>
        writePostReviewClosure(result, {
          allowedRoot,
          outputDirectory: path.join(allowedRoot, 'linked-parent', 'closure'),
        }),
      /directory component is unsafe/u
    );
    assert.equal(existsSync(path.join(outsideRoot, 'closure')), false);
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('the closure writer rejects a pre-existing hard-linked output file', () => {
  const temporaryRoot = mkdtempSync(path.join(tmpdir(), 'overlaykit-h049-hardlink-boundary-'));
  try {
    const allowedRoot = path.join(temporaryRoot, 'allowed');
    const outputDirectory = path.join(allowedRoot, 'closure');
    mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });
    const result = buildPostReviewClosure();
    const outsideFile = path.join(temporaryRoot, 'outside-source-anchor.json');
    writeFileSync(outsideFile, result.metadata['source-anchor.json'], { mode: 0o600 });
    linkSync(outsideFile, path.join(outputDirectory, 'source-anchor.json'));
    assert.throws(
      () => writePostReviewClosure(result, { allowedRoot, outputDirectory }),
      /multiple links/u
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('the H-049 post-review closure preserves pre-review temporal semantics', () => {
  if (existsSync(CANONICAL_CLOSURE_DIRECTORY)) {
    const verified = verifyPostReviewClosure({
      closureDirectory: CANONICAL_CLOSURE_DIRECTORY,
    });
    assert.equal(verified.mechanicalOutcome, 'inconclusive');
    assert.equal(verified.postReviewOutcome, 'refuted');
    assert.equal(verified.sourceSignatureStatus, 'absent-not-authorized');
    assert.equal(verified.authority, 'none');
    assert.equal(verified.action, null);
    return;
  }
  const result = buildPostReviewClosure();
  assert.equal(result.closure.mechanicalEvidence.outcome.status, 'inconclusive');
  assert.equal(result.closure.postReviewAdjudication.status, 'refuted');
  assert.equal(result.closure.reviewMap.sourceStatus, 'agent-proposed-pending-human-acceptance');
  assert.equal(result.closure.reviewMap.sourceHumanAcceptanceRef, null);
  assert.equal(result.closure.sourceAnchor.signatureStatus, 'absent-not-authorized');
  assert.equal(result.closure.sourceAnchor.signedCommit, null);
  assert.equal(result.closure.authority, 'none');
  assert.equal(result.closure.action, null);
});

test('a written closure verifies by exact reconstruction and fails closed after archive tampering', () => {
  const temporaryRoot = mkdtempSync(path.join(tmpdir(), 'overlaykit-h049-post-review-'));
  try {
    const outputDirectory = path.join(temporaryRoot, H049.semanticEvidenceSha256);
    const archiveFileName = materializeTestClosure(outputDirectory);
    const verified = verifyPostReviewClosure({ closureDirectory: outputDirectory });
    assert.equal(verified.verified, true);
    assert.equal(verified.postReviewOutcome, 'refuted');
    assert.equal(verified.signedGitAnchor, false);

    const archivePath = path.join(outputDirectory, archiveFileName);
    const archive = readFileSync(archivePath);
    archive[512] ^= 1;
    writeFileSync(archivePath, archive);
    assert.throws(
      () => verifyPostReviewClosure({ closureDirectory: outputDirectory }),
      /archive digest differs/u
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('the verifier rejects rebound publication and ADR overclaims', () => {
  const temporaryRoot = mkdtempSync(path.join(tmpdir(), 'overlaykit-h049-overclaim-'));
  try {
    const outputDirectory = path.join(temporaryRoot, H049.semanticEvidenceSha256);
    materializeTestClosure(outputDirectory);
    const closurePath = path.join(outputDirectory, 'closure.json');
    const closure = JSON.parse(readFileSync(closurePath, 'utf8'));
    closure.publication = 'authorized';
    closure.adrAssessment.status = 'decision-candidate-activated';
    writeFileSync(closurePath, canonicalArtifact(closure), { mode: 0o600 });
    assert.throws(
      () => verifyPostReviewClosure({ closureDirectory: outputDirectory }),
      /closure envelope differs/u
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});

test('the verifier rejects an unmanifested deterministic archive member', () => {
  const temporaryRoot = mkdtempSync(path.join(tmpdir(), 'overlaykit-h049-extra-member-'));
  try {
    const outputDirectory = path.join(temporaryRoot, H049.semanticEvidenceSha256);
    const archiveFileName = materializeTestClosure(outputDirectory);
    const archivePath = path.join(outputDirectory, archiveFileName);
    const expandedArchive = buildUstar([
      ...parseUstar(readFileSync(archivePath)).map(({ archivePath: memberPath, bytes }) => ({
        archivePath: memberPath,
        bytes,
      })),
      { archivePath: 'zzzz/unmanifested.bin', bytes: Buffer.from('hostile') },
    ]);
    const expandedSha256 = sha256(expandedArchive);
    const expandedFileName = `replay-${expandedSha256}.tar`;
    rmSync(archivePath);
    writeFileSync(path.join(outputDirectory, expandedFileName), expandedArchive, { mode: 0o600 });

    const closurePath = path.join(outputDirectory, 'closure.json');
    const closure = JSON.parse(readFileSync(closurePath, 'utf8'));
    closure.bundle.path = `${path.posix.dirname(closure.bundle.path)}/${expandedFileName}`;
    closure.bundle.sha256 = expandedSha256;
    closure.bundle.byteLength = expandedArchive.length;
    closure.bundle.memberCount += 1;
    closure.determinism.buildASha256 = expandedSha256;
    closure.determinism.buildBSha256 = expandedSha256;
    writeFileSync(closurePath, canonicalArtifact(closure), { mode: 0o600 });
    assert.throws(
      () => verifyPostReviewClosure({ closureDirectory: outputDirectory }),
      /archive and manifest member cardinality differ/u
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
});
