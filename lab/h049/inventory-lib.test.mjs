import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  H049_PREDICATES,
  buildCandidateIndex,
  buildNormativeInventory,
  canonicalArtifact,
  canonicalJson,
  deriveH049Outcome,
  evaluateReviewMap,
  semanticEvidenceSha256,
  sha256,
} from './inventory-lib.mjs';

const REPOSITORY_ROOT = new URL('../..', import.meta.url);
const GIT_ENV = {
  GIT_ALTERNATE_OBJECT_DIRECTORIES: '',
  GIT_ATTR_NOSYSTEM: '1',
  GIT_CONFIG_COUNT: '0',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_SYSTEM: '/dev/null',
  GIT_NO_LAZY_FETCH: '1',
  GIT_NO_REPLACE_OBJECTS: '1',
  GIT_OPTIONAL_LOCKS: '0',
  GIT_TERMINAL_PROMPT: '0',
  LANG: 'C',
  LC_ALL: 'C',
  PATH: '/usr/bin:/bin',
};

let lock;
let review;
let fixture;

function git(args) {
  return execFileSync('/usr/bin/git', args, {
    cwd: REPOSITORY_ROOT,
    encoding: null,
    env: GIT_ENV,
  });
}

function freshReview() {
  return structuredClone(review);
}

before(() => {
  lock = JSON.parse(readFileSync(new URL('./subject-lock.json', import.meta.url), 'utf8'));
  review = JSON.parse(readFileSync(new URL('./review-map.json', import.meta.url), 'utf8'));
  const restrictedTreeBytes = git([
    'ls-tree',
    '-rz',
    '--full-tree',
    lock.subject.commit,
    '--',
    ...lock.sources.map(({ path }) => path),
  ]);
  const sourceBytesByPath = new Map(
    lock.sources.map((source) => [source.path, git(['cat-file', 'blob', source.oid])])
  );
  fixture = { restrictedTreeBytes, sourceBytesByPath };
});

describe('H-049 exact normative inventory', () => {
  test('canonical JSON sorts object keys and preserves array order', () => {
    assert.equal(canonicalJson({ z: 1, a: [{ y: 2, x: 3 }, 4] }), '{"a":[{"x":3,"y":2},4],"z":1}');
  });

  test('closes nine sources and every one of 901 string clauses', () => {
    const inventory = buildNormativeInventory({ subjectLock: lock, ...fixture });
    assert.equal(inventory.sourceMap.sourceCount, 9);
    assert.equal(
      inventory.sourceMap.sourceSetSha256,
      '3136aa776e1d15dcc2f3fc3597a6e7011f2b9601492936c5e1da65920a67e218'
    );
    assert.equal(inventory.clauseUniverse.clauseCount, 901);
    assert.equal(
      sha256(canonicalArtifact(inventory.clauseUniverse)),
      '637671ba036157351305e3bf023645bcebb9f8ab0ec19d37e4988799754e7c79'
    );
  });

  test('rejects a changed normative blob', () => {
    const bytes = new Map(fixture.sourceBytesByPath);
    const target = lock.sources[0].path;
    bytes.set(target, Buffer.concat([bytes.get(target), Buffer.from(' ')]));
    assert.throws(
      () =>
        buildNormativeInventory({
          subjectLock: lock,
          restrictedTreeBytes: fixture.restrictedTreeBytes,
          sourceBytesByPath: bytes,
        }),
      /source identity differs/u
    );
  });

  test('rejects an omitted source', () => {
    const bytes = new Map(fixture.sourceBytesByPath);
    bytes.delete(lock.sources[0].path);
    assert.throws(
      () =>
        buildNormativeInventory({
          subjectLock: lock,
          restrictedTreeBytes: fixture.restrictedTreeBytes,
          sourceBytesByPath: bytes,
        }),
      /missing source bytes/u
    );
  });

  test('rejects a changed restricted tree stream', () => {
    const tree = Buffer.from(fixture.restrictedTreeBytes);
    tree[0] ^= 1;
    assert.throws(
      () =>
        buildNormativeInventory({
          subjectLock: lock,
          restrictedTreeBytes: tree,
          sourceBytesByPath: fixture.sourceBytesByPath,
        }),
      /restricted ls-tree SHA-256 differs/u
    );
  });
});

describe('H-049 semantic review and outcome precedence', () => {
  function evaluated(reviewMap = freshReview()) {
    const inventory = buildNormativeInventory({ subjectLock: lock, ...fixture });
    return {
      inventory,
      result: evaluateReviewMap({
        reviewMap,
        clauseUniverse: inventory.clauseUniverse,
        parsedByPath: inventory.parsedByPath,
      }),
    };
  }

  test('keeps the canonical pre-review result inconclusive', () => {
    const { inventory } = evaluated();
    const candidateIndex = buildCandidateIndex({
      reviewMap: review,
      clauseUniverse: inventory.clauseUniverse,
      parsedByPath: inventory.parsedByPath,
    });
    assert.equal(candidateIndex.candidates.length, 5);
    assert.equal(candidateIndex.eligibleChains.length, 0);
    assert.equal(candidateIndex.unknowns.length, 9);
    assert.deepEqual(candidateIndex.outcome, {
      status: 'inconclusive',
      stage: 'semantic-review',
      reasonCode: 'human-review-pending-or-semantic-coverage-incomplete',
    });
    assert.deepEqual(candidateIndex.projectedOutcomeIfExactMapAccepted, {
      status: 'refuted',
      stage: 'closed-accepted-law-boundary',
      reasonCode: 'complete-zero-chain-coverage',
      condition:
        'only-after-exact-map-content-addressed-human-acceptance-and-zero-pending-judgments',
    });
  });

  test('the strongest cross-domain stitch is not eligible', () => {
    const { result } = evaluated();
    const candidate = result.candidates.find(({ id }) => id === 'strongest-cross-domain-composite');
    assert.equal(candidate.eligible, false);
    assert.equal(candidate.explicitLinkClosure, false);
    assert.equal(candidate.exclusionOrContradiction, true);
    assert.equal(candidate.predicates.physicalCommandDeliveryRestored, false);
    assert.equal(candidate.predicates.observableRecoveryDeadline, false);
  });

  test('rejects retargeted clause-universe admission', () => {
    const altered = freshReview();
    altered.clauseUniverse.sha256 = '0'.repeat(64);
    assert.throws(() => evaluated(altered), /clause universe hash differs/u);
  });

  test('rejects a changed citation digest', () => {
    const altered = freshReview();
    altered.candidates[0].citations[0].valueSha256 = '0'.repeat(64);
    assert.throws(() => evaluated(altered), /citation value hash differs/u);
  });

  test('rejects a retargeted citation pointer', () => {
    const altered = freshReview();
    altered.candidates[0].citations[0].pointer = '/title';
    assert.throws(() => evaluated(altered), /citation value hash differs/u);
  });

  test('rejects any in-place acceptance transition, even with a reference', () => {
    const altered = freshReview();
    altered.status = 'human-accepted';
    altered.humanAcceptanceRef = 'self-certification-is-not-authority';
    assert.throws(() => evaluated(altered), /cannot admit human acceptance/u);
  });

  test('unknown plus an eligible chain remains inconclusive', () => {
    assert.deepEqual(
      deriveH049Outcome({
        coverageComplete: false,
        unknowns: [{ id: 'pending' }],
        eligibleChains: [{ id: 'synthetic-positive' }],
      }),
      {
        status: 'inconclusive',
        stage: 'semantic-review',
        reasonCode: 'human-review-pending-or-semantic-coverage-incomplete',
      }
    );
  });

  test('complete accepted zero-chain coverage refutes', () => {
    assert.deepEqual(
      deriveH049Outcome({ coverageComplete: true, unknowns: [], eligibleChains: [] }),
      {
        status: 'refuted',
        stage: 'closed-accepted-law-boundary',
        reasonCode: 'complete-zero-chain-coverage',
      }
    );
  });

  test('one fully accepted chain supports', () => {
    const predicates = Object.fromEntries(H049_PREDICATES.map((predicate) => [predicate, true]));
    assert.equal(Object.values(predicates).every(Boolean), true);
    assert.deepEqual(
      deriveH049Outcome({
        coverageComplete: true,
        unknowns: [],
        eligibleChains: [{ id: 'synthetic-positive' }],
      }),
      {
        status: 'supported',
        stage: 'normative-obligation-chain',
        reasonCode: 'complete-seven-predicate-chain-present',
      }
    );
  });

  test('semantic digest binds the harness source map', () => {
    const artifact = { file: 'x.json', byteLength: 2, sha256: sha256('{}') };
    const first = semanticEvidenceSha256({
      harnessSourceMapArtifact: artifact,
      sourceMapArtifact: artifact,
      clauseUniverseArtifact: artifact,
      candidateIndexArtifact: artifact,
      outcome: { status: 'inconclusive' },
    });
    const second = semanticEvidenceSha256({
      harnessSourceMapArtifact: { ...artifact, sha256: '1'.repeat(64) },
      sourceMapArtifact: artifact,
      clauseUniverseArtifact: artifact,
      candidateIndexArtifact: artifact,
      outcome: { status: 'inconclusive' },
    });
    assert.notEqual(first, second);
  });
});
