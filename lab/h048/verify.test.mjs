import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, lstatSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildH048Bundle, writeBundle } from './run.mjs';
import {
  assembleH048VerifierChainsForTest,
  assertH048VerifierGitBlobIdentityForTest,
  classifyH048VerifierOutcomeForTest,
  deriveH048VerifierIndirectionsForTest,
  validateH048VerifierAcceptanceForTest,
  verifyH048Directory,
} from './verify.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const H048_ARTIFACT_ROOT = path.join(REPOSITORY_ROOT, 'artifacts', 'h048');
const VERIFY_PREDICATES = Object.freeze([
  'effectiveAcceptedProductionAuthority',
  'exactImageReferenceAndId',
  'spec0001LinuxHostBinding',
  'deploymentPresenceAndCardinality',
  'repositoryDeclaredLifecycleOwner',
  'reconcilerMechanism',
  'absenceToConvergenceRule',
  'explicitLinkClosure',
]);
const SYNTHETIC_SUBJECTS = Object.freeze([
  Object.freeze({
    key: 'OverlayKit/companion-module-overlaykit-server',
    commit: 'a'.repeat(40),
  }),
  Object.freeze({
    key: 'OverlayKit/overlaykit',
    commit: 'b'.repeat(40),
  }),
]);
const SYNTHETIC_TARGET = Object.freeze({
  imageReference: 'synthetic-image:v1',
  imageId: `sha256:${'c'.repeat(64)}`,
  hostRole: 'synthetic-linux-host',
});

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function binding(deploymentKey) {
  return {
    deploymentKey,
    imageReference: SYNTHETIC_TARGET.imageReference,
    imageId: SYNTHETIC_TARGET.imageId,
    hostRole: SYNTHETIC_TARGET.hostRole,
  };
}

function contributionFixture(
  chainBinding,
  predicate,
  { disposition = 'supports', suffix = 'support' } = {}
) {
  const repository = SYNTHETIC_SUBJECTS[0];
  const deploymentKeyBytes = Buffer.from(chainBinding.deploymentKey, 'utf8');
  const repositoryPath = `${chainBinding.deploymentKey}/${predicate}-${suffix}.json`;
  const digest = sha256(Buffer.from(`${repositoryPath}\0${disposition}`, 'utf8'));
  const candidate = {
    repository: repository.key,
    commit: repository.commit,
    path: repositoryPath,
    sourceKind: 'git-blob',
    sha256: digest,
    classification: `synthetic-${disposition}`,
    predicateContributions: [predicate],
    eligibleForChain: true,
  };
  return {
    candidate,
    contribution: {
      repository: candidate.repository,
      commit: candidate.commit,
      path: candidate.path,
      sourceKind: candidate.sourceKind,
      sha256: candidate.sha256,
      predicate,
      disposition,
      binding: chainBinding,
      bindingEvidence: {
        kind: 'exact-utf8-byte-span/v1',
        byteOffset: 0,
        byteLength: deploymentKeyBytes.length,
        sha256: sha256(deploymentKeyBytes),
      },
    },
  };
}

function exactLinkReceipt(candidate) {
  const target = SYNTHETIC_SUBJECTS[1];
  const body = {
    ownerRepository: candidate.repository,
    ownerCommit: candidate.commit,
    ownerPath: candidate.path,
    ownerSourceKind: candidate.sourceKind,
    ownerSha256: candidate.sha256,
    kind: 'subject-atomic-url',
    value: `${target.key}@${target.commit}`,
    targetRepository: target.key,
    targetCommit: target.commit,
    status: 'resolved-exact-subject',
  };
  return {
    id: sha256(Buffer.from(canonicalJson(body), 'utf8')),
    ...body,
  };
}

function completeChainFixture(deploymentKey) {
  const chainBinding = binding(deploymentKey);
  const parts = VERIFY_PREDICATES.map((predicate) => contributionFixture(chainBinding, predicate));
  const linkCandidate = parts.find(
    ({ contribution }) => contribution.predicate === 'explicitLinkClosure'
  ).candidate;
  return {
    binding: chainBinding,
    candidates: parts.map(({ candidate }) => candidate),
    chainContributions: parts.map(({ contribution }) => contribution),
    indirections: [exactLinkReceipt(linkCandidate)],
  };
}

function assembleSynthetic({ candidates, chainContributions, indirections }) {
  return assembleH048VerifierChainsForTest({
    candidates,
    chainContributions,
    indirections,
    subjectRepositories: SYNTHETIC_SUBJECTS,
    target: SYNTHETIC_TARGET,
    reviewAccepted: true,
  });
}

function testRunId(suffix) {
  return `test-${process.pid}-${suffix}`;
}

function cleanup(runId) {
  const target = path.join(H048_ARTIFACT_ROOT, runId);
  rmSync(target, { recursive: true, force: true });
}

test('verifier remains independent from H-048 producer and classifier modules', () => {
  const source = readFileSync(new URL('./verify.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /from ['"]\.\/run\.mjs['"]/u);
  assert.doesNotMatch(source, /from ['"]\.\/inventory-lib\.mjs['"]/u);
  assert.doesNotMatch(source, /buildH048Bundle|buildInventory|deriveOutcome/u);
  assert.doesNotMatch(source, /from ['"]\.\.\/h047\//u);
  assert.doesNotMatch(source, /\bAjv(?:2020)?\b|from ['"]ajv/u);
  assert.match(source, /from ['"]\.\/archive-lib\.mjs['"]/u);
  assert.doesNotMatch(source, /https?:\/\//u);
  assert.doesNotMatch(source, /process\.env/u);
});

test('Git blob bytes must independently reproduce the exact ls-tree object ID', () => {
  const bytes = Buffer.from('canonical H-048 verifier blob', 'utf8');
  const oid = createHash('sha1')
    .update(Buffer.from(`blob ${bytes.length}\0`, 'utf8'))
    .update(bytes)
    .digest('hex');

  assert.doesNotThrow(() => assertH048VerifierGitBlobIdentityForTest(oid, bytes));
  assert.throws(
    () =>
      assertH048VerifierGitBlobIdentityForTest(
        oid,
        Buffer.from('substituted H-048 verifier blob', 'utf8')
      ),
    /do not reproduce ls-tree OID/u
  );
});

test('independent classifier supports one complete exactly linked chain', () => {
  const fixture = completeChainFixture('show-a');
  const result = assembleSynthetic(fixture);

  assert.equal(result.eligibleChains.length, 1);
  assert.equal(result.chainAssessments.length, 1);
  assert.equal(result.chainAssessments[0].eligible, true);
  assert.deepEqual(result.chainAssessments[0].missingPredicates, []);
  assert.deepEqual(result.chainAssessments[0].ambiguousPredicates, []);
  assert.deepEqual(result.chainAssessments[0].contradictedPredicates, []);
  assert.deepEqual(result.missingPredicates, []);
  assert.deepEqual(result.unknowns, []);
  assert.deepEqual(
    result.eligibleChains[0].components.map(({ predicate }) => predicate),
    VERIFY_PREDICATES
  );
  assert.deepEqual(result.eligibleChains[0].binding, fixture.binding);
});

test('independent classifier never Cartesian-mixes partial bindings', () => {
  const leftBinding = binding('show-left');
  const rightBinding = binding('show-right');
  const left = VERIFY_PREDICATES.slice(0, 4).map((predicate) =>
    contributionFixture(leftBinding, predicate)
  );
  const right = VERIFY_PREDICATES.slice(4).map((predicate) =>
    contributionFixture(rightBinding, predicate)
  );
  const parts = [...left, ...right];
  const result = assembleSynthetic({
    candidates: parts.map(({ candidate }) => candidate),
    chainContributions: parts.map(({ contribution }) => contribution),
    indirections: [],
  });

  assert.deepEqual(result.missingPredicates, []);
  assert.equal(result.chainAssessments.length, 2);
  assert.ok(
    result.chainAssessments.every(({ missingPredicates }) => missingPredicates.length === 4)
  );
  assert.equal(result.eligibleChains.length, 0);
});

test('independent classifier fails closed on contradiction and a borrowed exact link', () => {
  const contradicted = completeChainFixture('show-contradicted');
  const conflict = contributionFixture(contradicted.binding, VERIFY_PREDICATES[0], {
    disposition: 'contradicts',
    suffix: 'conflict',
  });
  const contradictionResult = assembleSynthetic({
    candidates: [...contradicted.candidates, conflict.candidate],
    chainContributions: [...contradicted.chainContributions, conflict.contribution],
    indirections: contradicted.indirections,
  });
  assert.equal(contradictionResult.eligibleChains.length, 0);
  assert.deepEqual(contradictionResult.chainAssessments[0].contradictedPredicates, [
    VERIFY_PREDICATES[0],
  ]);
  assert.ok(
    contradictionResult.unknowns.some(({ code }) => code === 'contradictory-chain-component')
  );

  const borrowed = completeChainFixture('show-borrowed');
  const nonLinkCandidate = borrowed.candidates.find(
    ({ predicateContributions }) => !predicateContributions.includes('explicitLinkClosure')
  );
  const borrowedResult = assembleSynthetic({
    ...borrowed,
    indirections: [exactLinkReceipt(nonLinkCandidate)],
  });
  assert.equal(borrowedResult.eligibleChains.length, 0);
  assert.equal(borrowedResult.chainAssessments[0].exactLinkReceiptIds.length, 0);
  assert.ok(borrowedResult.unknowns.some(({ code }) => code === 'explicit-link-not-exact'));
});

test('independent classifier preserves multiple complete chains without aliasing', () => {
  const left = completeChainFixture('show-multiple-left');
  const right = completeChainFixture('show-multiple-right');
  const result = assembleSynthetic({
    candidates: [...left.candidates, ...right.candidates],
    chainContributions: [...left.chainContributions, ...right.chainContributions],
    indirections: [...left.indirections, ...right.indirections],
  });

  assert.equal(result.eligibleChains.length, 2);
  assert.deepEqual(
    result.eligibleChains.map(({ binding: chainBinding }) => chainBinding.deploymentKey).sort(),
    ['show-multiple-left', 'show-multiple-right']
  );
  assert.equal(new Set(result.eligibleChains.map(({ id }) => id)).size, 2);
});

test('independent outcome classifier derives supported, refuted, and inconclusive', () => {
  assert.deepEqual(
    classifyH048VerifierOutcomeForTest({
      coverageComplete: true,
      unknowns: [],
      eligibleChains: [{ id: 'synthetic-chain' }],
    }),
    {
      status: 'supported',
      stage: 'desired-state-chain',
      reasonCode: 'eligible-chain-present',
    }
  );
  assert.deepEqual(
    classifyH048VerifierOutcomeForTest({
      coverageComplete: true,
      unknowns: [],
      eligibleChains: [],
    }),
    {
      status: 'refuted',
      stage: 'complete-nominated-git-boundary',
      reasonCode: 'complete-zero-eligible-chain-coverage',
    }
  );
  assert.deepEqual(
    classifyH048VerifierOutcomeForTest({
      coverageComplete: false,
      unknowns: [{ code: 'synthetic-ambiguity' }],
      eligibleChains: [],
    }),
    {
      status: 'inconclusive',
      stage: 'semantic-coverage',
      reasonCode: 'incomplete-ambiguous-or-unreviewed-coverage',
    }
  );
  assert.deepEqual(
    classifyH048VerifierOutcomeForTest({
      coverageComplete: false,
      unknowns: [{ code: 'accepted-source-anchor-opaque' }],
      eligibleChains: [],
    }),
    {
      status: 'inconclusive',
      stage: 'source-admission',
      reasonCode: 'accepted-source-anchor-opaque',
    }
  );
});

test('self-consistent human acceptance is rejected without an external SHA nomination', () => {
  const subjectLock = {
    schemaVersion: 'synthetic-subject-lock/v1',
    claimBoundary: {
      includes: ['synthetic'],
      excludes: [],
      authority: 'none',
      action: null,
    },
    repoSet: {
      sha256: 'e'.repeat(64),
    },
  };
  const subjectLockBytes = Buffer.from(`${canonicalJson(subjectLock)}\n`, 'utf8');
  const reviewUniverse = {
    schemaVersion: 'synthetic-review-universe-ref/v1',
    sha256: 'f'.repeat(64),
  };
  const payload = {
    schemaVersion: 'overlaykit-h048-semantic-review/v1',
    hypothesis: 'H-048',
    reviewUniverse,
    defaultDisposition: {
      classification: 'no-eligible-predicate-contribution',
      rationale: 'synthetic',
      authority: 'none',
      action: null,
    },
    defaultIndirectionDisposition: {
      classification: 'no-eligible-semantic-indirection',
      rationale: 'synthetic',
      authority: 'none',
      action: null,
    },
    sources: [],
    chainContributions: [],
    pendingHumanJudgments: [],
    authority: 'none',
    action: null,
  };
  const reviewPayloadSha256 = sha256(Buffer.from(canonicalJson(payload), 'utf8'));
  const acceptance = {
    schemaVersion: 'overlaykit-h048-human-acceptance/v1',
    hypothesis: 'H-048',
    principal: '@rodrigoteamx',
    reviewPayloadSha256,
    subjectLockRawSha256: sha256(subjectLockBytes),
    subjectLockCanonicalSha256: sha256(Buffer.from(canonicalJson(subjectLock), 'utf8')),
    claimBoundaryCanonicalSha256: sha256(
      Buffer.from(canonicalJson(subjectLock.claimBoundary), 'utf8')
    ),
    repoSetSha256: subjectLock.repoSet.sha256,
    reviewUniverseSha256: reviewUniverse.sha256,
    authority: 'none',
    action: null,
  };
  const acceptanceBytes = Buffer.from(`${canonicalJson(acceptance)}\n`, 'utf8');
  const reviewMap = {
    ...payload,
    status: 'human-accepted',
    humanAcceptanceRef: {
      kind: 'embedded-content-addressed-json',
      canonicalization: 'exact-base64-decoded-bytes/v1',
      byteLength: acceptanceBytes.length,
      sha256: sha256(acceptanceBytes),
      preimageBase64: acceptanceBytes.toString('base64'),
    },
  };

  assert.throws(
    () =>
      validateH048VerifierAcceptanceForTest({
        reviewMap,
        subjectLock,
        subjectLockBytes,
        expectedReviewUniverse: reviewUniverse,
      }),
    /lacks an externally nominated digest/u
  );
});

test('GitHub pull requests remain unresolved while excluded surfaces stay terminal', () => {
  const pull = 'https://github.com/OverlayKit/overlaykit/pull/17';
  const pulls = 'https://github.com/OverlayKit/overlaykit/pulls/17';
  const issue = 'https://github.com/OverlayKit/overlaykit/issues/17';
  const project = 'https://github.com/OverlayKit/overlaykit/projects/17';
  const wiki = 'https://github.com/OverlayKit/overlaykit/wiki/Runbook';
  const receipts = deriveH048VerifierIndirectionsForTest({
    repository: SYNTHETIC_SUBJECTS[0].key,
    ownerCommit: SYNTHETIC_SUBJECTS[0].commit,
    repositoryPath: 'synthetic-links.md',
    sourceKind: 'git-blob',
    sourceSha256: 'd'.repeat(64),
    bytes: Buffer.from([pull, pulls, issue, project, wiki].join('\n'), 'utf8'),
    subjectRepositories: SYNTHETIC_SUBJECTS,
  });
  const byValue = new Map(receipts.map((receipt) => [receipt.value, receipt]));

  for (const value of [pull, pulls]) {
    assert.equal(byValue.get(value).kind, 'subject-github-pull-request');
    assert.equal(byValue.get(value).status, 'unresolved-github-pull-request');
    assert.equal(byValue.get(value).targetRepository, SYNTHETIC_SUBJECTS[1].key);
    assert.equal(byValue.get(value).targetCommit, null);
  }
  for (const value of [issue, project, wiki]) {
    assert.equal(byValue.get(value).kind, 'subject-github-excluded-surface');
    assert.equal(byValue.get(value).status, 'excluded-github-surface');
  }
  for (const receipt of receipts) {
    const { id, ...body } = receipt;
    assert.equal(id, sha256(Buffer.from(canonicalJson(body), 'utf8')));
  }
});

test('independent verifier keeps noncanonical nominated-repository URLs unresolved', () => {
  const exactCommit = SYNTHETIC_SUBJECTS[1].commit;
  const values = [
    `http://github.com/OverlayKit/overlaykit/commit/${exactCommit}`,
    `https://github.com/overlaykit/overlaykit/commit/${exactCommit}`,
    'https://github.com/OverlayKit/overlaykit.git',
    'https://github.com/OverlayKit/overlaykit#readme',
  ];
  const receipts = deriveH048VerifierIndirectionsForTest({
    repository: SYNTHETIC_SUBJECTS[0].key,
    ownerCommit: SYNTHETIC_SUBJECTS[0].commit,
    repositoryPath: 'synthetic-noncanonical-links.md',
    sourceKind: 'git-blob',
    sourceSha256: 'e'.repeat(64),
    bytes: Buffer.from(values.join('\n'), 'utf8'),
    subjectRepositories: SYNTHETIC_SUBJECTS,
  });
  assert.equal(receipts.length, values.length);
  for (const receipt of receipts) {
    assert.equal(receipt.kind, 'subject-noncanonical-url');
    assert.equal(receipt.status, 'unversioned-subject-reference');
    assert.equal(receipt.targetRepository, SYNTHETIC_SUBJECTS[1].key);
    assert.equal(receipt.targetCommit, null);
  }
});

test('independent verifier reconstructs a real producer bundle and writes once', () => {
  const runId = testRunId('verified');
  cleanup(runId);
  try {
    const output = writeBundle(runId, buildH048Bundle());
    const first = verifyH048Directory(output);
    assert.equal(first.verification.verified, true);
    assert.equal(first.verification.outcome.status, 'inconclusive');
    assert.equal(first.verification.outcome.reasonCode, 'accepted-source-anchor-opaque');
    assert.equal(first.verification.checks.acceptedSetPreimagesAvailable, false);
    assert.equal(first.verification.checks.strictRunSchemaSourceExact, true);
    assert.equal(first.verification.checks.runEnvelopeExact, true);
    assert.equal(first.verification.checks.nodeVersionExact, true);
    assert.equal(first.verification.checks.reviewUniverseIndependentlyReconstructed, true);
    assert.equal('strictRunSchema' in first.verification.checks, false);
    assert.equal(first.verification.authority, 'none');
    assert.equal(first.verification.action, null);

    const written = verifyH048Directory(output, { write: true });
    assert.deepEqual(written.verification, first.verification);
    const verificationPath = path.join(output, 'verification.json');
    assert.equal(lstatSync(verificationPath).mode & 0o777, 0o600);
    const replayed = verifyH048Directory(output);
    assert.ok(replayed.bytes.equals(written.bytes));
    assert.throws(() => verifyH048Directory(output, { write: true }), /already exists/u);
  } finally {
    cleanup(runId);
  }
});

test('preexisting verification receipt rejects tamper, weak mode, and symlink substitution', () => {
  const runId = testRunId('receipt-hostile');
  cleanup(runId);
  try {
    const output = writeBundle(runId, buildH048Bundle());
    const receipt = verifyH048Directory(output, { write: true });
    const verificationPath = path.join(output, 'verification.json');

    writeFileSync(verificationPath, Buffer.from('{}\n', 'utf8'));
    chmodSync(verificationPath, 0o600);
    assert.throws(() => verifyH048Directory(output), /existing verification receipt differs/u);

    writeFileSync(verificationPath, receipt.bytes);
    chmodSync(verificationPath, 0o644);
    assert.throws(() => verifyH048Directory(output), /artifact mode differs/u);

    chmodSync(verificationPath, 0o600);
    rmSync(verificationPath);
    symlinkSync('run.json', verificationPath);
    assert.throws(() => verifyH048Directory(output), /unsafe artifact/u);
  } finally {
    cleanup(runId);
  }
});

test('two producer runs have byte-identical semantic artifacts and verification', () => {
  const leftId = testRunId('left');
  const rightId = testRunId('right');
  cleanup(leftId);
  cleanup(rightId);
  try {
    const left = writeBundle(leftId, buildH048Bundle());
    const right = writeBundle(rightId, buildH048Bundle());
    for (const name of [
      'source-closure.json',
      'source-map.json',
      'review-universe.json',
      'candidate-index.json',
      'run.json',
    ]) {
      assert.ok(readFileSync(path.join(left, name)).equals(readFileSync(path.join(right, name))));
    }
    const leftVerification = verifyH048Directory(left);
    const rightVerification = verifyH048Directory(right);
    assert.ok(leftVerification.bytes.equals(rightVerification.bytes));
    assert.deepEqual(leftVerification.verification, rightVerification.verification);
    assert.equal('runId' in leftVerification.verification, false);
  } finally {
    cleanup(leftId);
    cleanup(rightId);
  }
});

test('verifier rejects candidate mutation before trusting the producer outcome', () => {
  const runId = testRunId('candidate');
  cleanup(runId);
  try {
    const output = writeBundle(runId, buildH048Bundle());
    const candidatePath = path.join(output, 'candidate-index.json');
    const candidate = JSON.parse(readFileSync(candidatePath, 'utf8'));
    candidate.eligibleChains.push({ forged: true });
    writeFileSync(candidatePath, `${JSON.stringify(candidate)}\n`, { mode: 0o600 });
    chmodSync(candidatePath, 0o600);
    assert.throws(() => verifyH048Directory(output), /candidate digest/u);
  } finally {
    cleanup(runId);
  }
});

test('verifier rejects a coherently rehashed candidate classification tamper', () => {
  const runId = testRunId('candidate-semantic');
  cleanup(runId);
  try {
    const output = writeBundle(runId, buildH048Bundle());
    const candidatePath = path.join(output, 'candidate-index.json');
    const candidateIndex = JSON.parse(readFileSync(candidatePath, 'utf8'));
    assert.ok(candidateIndex.candidates.length > 0);
    candidateIndex.candidates[0].classification = `${candidateIndex.candidates[0].classification}-forged`;
    const candidateBytes = Buffer.from(`${canonicalJson(candidateIndex)}\n`, 'utf8');
    writeFileSync(candidatePath, candidateBytes);
    chmodSync(candidatePath, 0o600);

    const runPath = path.join(output, 'run.json');
    const run = JSON.parse(readFileSync(runPath, 'utf8'));
    run.artifacts.candidateIndex.byteLength = candidateBytes.length;
    run.artifacts.candidateIndex.sha256 = sha256(candidateBytes);
    delete run.semanticEvidenceSha256;
    run.semanticEvidenceSha256 = sha256(Buffer.from(canonicalJson(run), 'utf8'));
    writeFileSync(runPath, Buffer.from(`${canonicalJson(run)}\n`, 'utf8'));
    chmodSync(runPath, 0o600);

    assert.throws(
      () => verifyH048Directory(output),
      /independent candidate reconstruction differs/u
    );
  } finally {
    cleanup(runId);
  }
});

test('verifier rejects a coherently rehashed review-universe tamper', () => {
  const runId = testRunId('review-universe');
  cleanup(runId);
  try {
    const output = writeBundle(runId, buildH048Bundle());
    const universePath = path.join(output, 'review-universe.json');
    const universe = JSON.parse(readFileSync(universePath, 'utf8'));
    universe.policy.sourceCoverage = `${universe.policy.sourceCoverage}-forged`;
    const universeBytes = Buffer.from(`${canonicalJson(universe)}\n`, 'utf8');
    writeFileSync(universePath, universeBytes);
    chmodSync(universePath, 0o600);

    const runPath = path.join(output, 'run.json');
    const run = JSON.parse(readFileSync(runPath, 'utf8'));
    run.artifacts.reviewUniverse.byteLength = universeBytes.length;
    run.artifacts.reviewUniverse.sha256 = sha256(universeBytes);
    delete run.semanticEvidenceSha256;
    run.semanticEvidenceSha256 = sha256(Buffer.from(canonicalJson(run), 'utf8'));
    writeFileSync(runPath, Buffer.from(`${canonicalJson(run)}\n`, 'utf8'));
    chmodSync(runPath, 0o600);

    assert.throws(
      () => verifyH048Directory(output),
      /independent review-universe reconstruction differs/u
    );
  } finally {
    cleanup(runId);
  }
});

test('verifier rejects coherent artifact reformat with recomputed descriptors', () => {
  const runId = testRunId('canonical-bytes');
  cleanup(runId);
  try {
    const output = writeBundle(runId, buildH048Bundle());
    const sourceMapPath = path.join(output, 'source-map.json');
    const sourceMap = JSON.parse(readFileSync(sourceMapPath, 'utf8'));
    const reformattedSourceMap = Buffer.from(`${JSON.stringify(sourceMap, null, 2)}\n`, 'utf8');
    writeFileSync(sourceMapPath, reformattedSourceMap);
    chmodSync(sourceMapPath, 0o600);

    const runPath = path.join(output, 'run.json');
    const run = JSON.parse(readFileSync(runPath, 'utf8'));
    run.artifacts.sourceMap.byteLength = reformattedSourceMap.length;
    run.artifacts.sourceMap.sha256 = sha256(reformattedSourceMap);
    delete run.semanticEvidenceSha256;
    run.semanticEvidenceSha256 = sha256(Buffer.from(canonicalJson(run), 'utf8'));
    writeFileSync(runPath, Buffer.from(`${canonicalJson(run)}\n`, 'utf8'));
    chmodSync(runPath, 0o600);

    assert.throws(
      () => verifyH048Directory(output),
      /source map artifact is not exact canonical JSON bytes/u
    );
  } finally {
    cleanup(runId);
  }
});

test('verifier rejects captured source mutation and mode weakening', () => {
  const sourceMutationId = testRunId('source');
  const modeMutationId = testRunId('mode');
  cleanup(sourceMutationId);
  cleanup(modeMutationId);
  try {
    const sourceOutput = writeBundle(sourceMutationId, buildH048Bundle());
    const sourceClosure = JSON.parse(
      readFileSync(path.join(sourceOutput, 'source-closure.json'), 'utf8')
    );
    const blobPath = path.join(sourceOutput, sourceClosure.sources[0].blobFile);
    writeFileSync(blobPath, Buffer.from('forged'), { mode: 0o600 });
    chmodSync(blobPath, 0o600);
    assert.throws(
      () => verifyH048Directory(sourceOutput),
      /source length differs|source digest differs/u
    );

    const modeOutput = writeBundle(modeMutationId, buildH048Bundle());
    chmodSync(path.join(modeOutput, 'run.json'), 0o644);
    assert.throws(() => verifyH048Directory(modeOutput), /artifact mode differs/u);
  } finally {
    cleanup(sourceMutationId);
    cleanup(modeMutationId);
  }
});
