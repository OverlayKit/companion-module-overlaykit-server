import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import {
  H043_CANDIDATE_TOKEN_SHA256,
  H043_EVIDENCE_SHA256,
  H043_REPLAY_ARCHIVE_PATH,
  H043_REPLAY_ARCHIVE_SHA256,
  H043_RUN_ID,
  H043_RUN_SHA256,
  H043_VERIFICATION_SHA256,
  H044_REQUIRED_SOURCE_PATHS,
  buildSourceAdmission,
  readHistoricalEvidence,
} from './admission-lib.mjs';

const GOVERNANCE = Object.freeze({
  verified: true,
  planHash: 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4',
  manifestContentHash: 'b36032589f0d652ceffd6aafee502e551b4f86779149be4b9ac1c38636a17013',
  changes: Object.freeze({
    'CHG-0016': 'b8ea5a54c666047c7c44e322b21bc5f24836d172b4712c7483507bc2d4739ae6',
    'CHG-0017': '858fcc7fde8bf6abd73e58f56224c3eae238ecf46ae70e92aca92f886937e576',
  }),
  decisions: Object.freeze({
    'ADR-0006': '619fbfe60cc8c4c298c6c1eaaa25825b514b1d36bc0b8ec6588d4c3718b9f360',
  }),
  requiredSourcePaths: H044_REQUIRED_SOURCE_PATHS,
});

const GIT = Object.freeze({
  protectedMainCommit: '6c329234caddf9e34126be04149f768673bdb8bf',
  sourceContractCommit: '9e2156e7ddc38ebe223824a07f682421b7ee0589',
  protectedMainAncestor: true,
});

function sourceMap(suffix = '') {
  return H044_REQUIRED_SOURCE_PATHS.map((path) => ({
    path,
    sha256: createHash('sha256').update(`${path}${suffix}`).digest('hex'),
  }));
}

function clone(value) {
  return structuredClone(value);
}

test('admits the byte-exact accepted H-043 run, verification, and capability-free candidate', async () => {
  const bytes = await readFile(H043_REPLAY_ARCHIVE_PATH);
  const historical = readHistoricalEvidence(bytes);

  assert.equal(historical.exact, true);
  assert.equal(historical.archiveReceipt.sha256, H043_REPLAY_ARCHIVE_SHA256);
  assert.equal(historical.archiveReceipt.byteLength, 389_084);
  assert.equal(historical.archiveReceipt.memberCount, 21);
  assert.equal(historical.runReceipt.sha256, H043_RUN_SHA256);
  assert.equal(historical.runReceipt.runId, H043_RUN_ID);
  assert.equal(historical.runReceipt.evidenceSha256, H043_EVIDENCE_SHA256);
  assert.equal(historical.runReceipt.outcome, 'supported');
  assert.equal(historical.verificationReceipt.sha256, H043_VERIFICATION_SHA256);
  assert.equal(historical.verificationReceipt.verified, true);
  assert.equal(historical.verificationReceipt.outcome, 'supported');
  assert.equal(historical.candidateReceipt.tokenSha256, H043_CANDIDATE_TOKEN_SHA256);
  assert.equal(historical.candidateReceipt.requiresRevalidation, true);
  assert.equal(historical.candidateReceipt.authority, 'none');
  assert.equal(historical.candidateReceipt.action, null);
  assert.equal(historical.run.canonicalClassification.candidates.length, 1);

  historical.candidate.authority = 'tampered';
  assert.equal(
    historical.run.canonicalClassification.candidates[0].authority,
    'none',
    'returned candidate must not alias the returned run'
  );
  historical.run.canonicalClassification.candidates[0].authority = 'tampered';
  assert.equal(
    historical.candidateReceipt.authority,
    'none',
    'receipts must not alias returned historical data'
  );
});

test('rejects archive byte tampering and unsupported inputs before admission', async () => {
  const bytes = await readFile(H043_REPLAY_ARCHIVE_PATH);
  const tampered = Buffer.from(bytes);
  tampered[tampered.length - 1] ^= 0x01;

  assert.throws(() => readHistoricalEvidence(tampered), /archive SHA-256/u);
  assert.throws(() => readHistoricalEvidence(bytes.subarray(0, -1)), /archive SHA-256/u);
  assert.throws(() => readHistoricalEvidence('not bytes'), /Buffer or Uint8Array/u);
});

test('builds an exact fail-closed source admission from independent receipts', async () => {
  const historical = readHistoricalEvidence(await readFile(H043_REPLAY_ARCHIVE_PATH));
  const before = sourceMap();
  const after = clone(before);
  const admission = buildSourceAdmission({
    historical,
    governance: clone(GOVERNANCE),
    git: clone(GIT),
    sourcesBefore: before,
    sourcesAfter: after,
  });

  assert.deepEqual(admission, {
    historicalExact: true,
    governanceExact: true,
    gitExact: true,
    sourceSetExact: true,
    sourceStable: true,
    exact: true,
    checks: {
      historicalArchiveExact: true,
      historicalRunExact: true,
      historicalVerificationExact: true,
      historicalCandidateExact: true,
      governanceVerified: true,
      governancePlanExact: true,
      governanceManifestExact: true,
      governanceChangesExact: true,
      governanceDecisionExact: true,
      governanceSourcePathsExact: true,
      protectedMainExact: true,
      sourceContractExact: true,
      protectedMainAncestor: true,
      sourcesBeforeExact: true,
      sourcesAfterExact: true,
    },
  });
});

test('returns explicit false booleans for missing or malformed admission inputs', () => {
  const admission = buildSourceAdmission();
  assert.equal(admission.exact, false);
  assert.equal(admission.historicalExact, false);
  assert.equal(admission.governanceExact, false);
  assert.equal(admission.gitExact, false);
  assert.equal(admission.sourceSetExact, false);
  assert.equal(admission.sourceStable, false);
  assert.equal(
    Object.values(admission.checks).every((value) => typeof value === 'boolean'),
    true
  );
});

test('withholds exact admission for lineage, governance, ancestry, source-set, or stability drift', async () => {
  const canonicalHistorical = readHistoricalEvidence(await readFile(H043_REPLAY_ARCHIVE_PATH));
  const canonicalBefore = sourceMap();

  const cases = [
    {
      id: 'candidate-authority',
      mutate(input) {
        input.historical.candidateReceipt.authority = 'signal';
      },
      field: 'historicalExact',
    },
    {
      id: 'candidate-token',
      mutate(input) {
        input.historical.candidate.tokenSha256 = '0'.repeat(64);
      },
      field: 'historicalExact',
    },
    {
      id: 'manifest',
      mutate(input) {
        input.governance.manifestContentHash = '0'.repeat(64);
      },
      field: 'governanceExact',
    },
    {
      id: 'extra-governance-change',
      mutate(input) {
        input.governance.changes['CHG-9999'] = '0'.repeat(64);
      },
      field: 'governanceExact',
    },
    {
      id: 'ancestry',
      mutate(input) {
        input.git.protectedMainAncestor = false;
      },
      field: 'gitExact',
    },
    {
      id: 'missing-source',
      mutate(input) {
        input.sourcesAfter.pop();
      },
      field: 'sourceSetExact',
    },
    {
      id: 'reordered-source',
      mutate(input) {
        [input.sourcesAfter[0], input.sourcesAfter[1]] = [
          input.sourcesAfter[1],
          input.sourcesAfter[0],
        ];
      },
      field: 'sourceSetExact',
    },
    {
      id: 'duplicate-source',
      mutate(input) {
        input.sourcesAfter[1] = clone(input.sourcesAfter[0]);
      },
      field: 'sourceSetExact',
    },
    {
      id: 'source-hash-drift',
      mutate(input) {
        input.sourcesAfter[0].sha256 = '0'.repeat(64);
      },
      field: 'sourceStable',
    },
  ];

  for (const entry of cases) {
    const input = {
      historical: clone(canonicalHistorical),
      governance: clone(GOVERNANCE),
      git: clone(GIT),
      sourcesBefore: clone(canonicalBefore),
      sourcesAfter: clone(canonicalBefore),
    };
    entry.mutate(input);
    const admission = buildSourceAdmission(input);
    assert.equal(admission.exact, false, entry.id);
    assert.equal(admission[entry.field], false, `${entry.id}:${entry.field}`);
  }
});
