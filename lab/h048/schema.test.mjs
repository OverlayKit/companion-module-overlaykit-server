import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import { buildH048Bundle } from './run.mjs';

const schema = JSON.parse(
  await readFile(
    new URL('./schemas/external-desired-state-run.schema.json', import.meta.url),
    'utf8'
  )
);
const ajv = new Ajv2020({ allErrors: true, strict: true });
const validate = ajv.compile(schema);

function clone(value) {
  return structuredClone(value);
}

function accepted(value) {
  assert.equal(validate(value), true, JSON.stringify(validate.errors));
}

function rejected(value) {
  assert.equal(validate(value), false, 'schema unexpectedly accepted hostile H-048 evidence');
}

const canonicalRun = buildH048Bundle().run;

test('strict schema compiles and accepts the real bounded H-048 run', () => {
  accepted(canonicalRun);
});

test('schema rejects changed repository, tree, ref-set, or repo-set anchors', () => {
  for (const mutate of [
    (value) => {
      value.boundary.repoSet.sha256 = 'a'.repeat(64);
    },
    (value) => {
      value.boundary.repositories[0].commit = '1'.repeat(40);
    },
    (value) => {
      value.boundary.repositories[0].tree = '2'.repeat(40);
    },
    (value) => {
      value.boundary.repositories[0].entryCount = 249;
    },
    (value) => {
      value.boundary.repositories[1].lsTreeSha256 = 'b'.repeat(64);
    },
    (value) => {
      value.boundary.repositories[1].refSet.sha256 = 'c'.repeat(64);
    },
    (value) => {
      value.boundary.repositories.reverse();
    },
  ]) {
    const hostile = clone(canonicalRun);
    mutate(hostile);
    rejected(hostile);
  }
});

test('schema preserves the honest unsigned local source admission', () => {
  for (const mutate of [
    (value) => {
      value.localSourceClosure.signatureStatus = 'verified';
    },
    (value) => {
      value.localSourceClosure.commit = '1'.repeat(40);
    },
    (value) => {
      value.localSourceClosure.sourceCount = 12;
    },
    (value) => {
      value.localSourceClosure.sourceSetSha256 = 'not-a-digest';
    },
  ]) {
    const hostile = clone(canonicalRun);
    mutate(hostile);
    rejected(hostile);
  }
});

test('schema binds every artifact role to its exact filename', () => {
  const hostile = clone(canonicalRun);
  hostile.artifacts.sourceClosure.file = 'candidate-index.json';
  hostile.artifacts.candidateIndex.file = 'source-closure.json';
  rejected(hostile);

  const hostileUniverse = clone(canonicalRun);
  hostileUniverse.artifacts.reviewUniverse.file = 'source-map.json';
  rejected(hostileUniverse);
});

test('schema locks the fail-closed opaque-anchor outcome', () => {
  for (const outcome of [
    {
      status: 'refuted',
      stage: 'complete-nominated-git-boundary',
      reasonCode: 'complete-zero-eligible-chain-coverage',
    },
    {
      status: 'supported',
      stage: 'desired-state-chain',
      reasonCode: 'eligible-chain-present',
    },
    {
      status: 'inconclusive',
      stage: 'semantic-coverage',
      reasonCode: 'incomplete-ambiguous-or-unreviewed-coverage',
    },
  ]) {
    const hostile = clone(canonicalRun);
    hostile.outcome = outcome;
    rejected(hostile);
  }
  for (const mutate of [
    (value) => {
      value.summary.coverageComplete = true;
    },
    (value) => {
      value.summary.unknowns = 0;
    },
  ]) {
    const hostile = clone(canonicalRun);
    mutate(hostile);
    rejected(hostile);
  }
});

test('schema supports all outcome envelopes but preserves their cross-field invariants', () => {
  const withAvailableAnchors = clone(canonicalRun);
  for (const anchor of [
    withAvailableAnchors.boundary.repoSet,
    ...withAvailableAnchors.boundary.repositories.map((repository) => repository.refSet),
  ]) {
    anchor.preimageStatus = 'available';
    anchor.canonicalization = 'exact-base64-decoded-bytes/v1';
    anchor.preimage = 'YQ==';
  }
  rejected(withAvailableAnchors);

  withAvailableAnchors.summary.coverageComplete = true;
  withAvailableAnchors.summary.unknowns = 0;
  withAvailableAnchors.summary.unresolvedIndirections = 0;
  withAvailableAnchors.summary.eligibleChains = 1;
  withAvailableAnchors.summary.missingPredicates = [];
  withAvailableAnchors.outcome = {
    status: 'supported',
    stage: 'desired-state-chain',
    reasonCode: 'eligible-chain-present',
  };
  accepted(withAvailableAnchors);

  const hostileSupported = clone(withAvailableAnchors);
  hostileSupported.summary.unknowns = 1;
  rejected(hostileSupported);

  const hostileUnresolved = clone(withAvailableAnchors);
  hostileUnresolved.summary.unresolvedIndirections = 1;
  rejected(hostileUnresolved);

  const refuted = clone(withAvailableAnchors);
  refuted.summary.eligibleChains = 0;
  refuted.outcome = {
    status: 'refuted',
    stage: 'complete-nominated-git-boundary',
    reasonCode: 'complete-zero-eligible-chain-coverage',
  };
  accepted(refuted);
  refuted.summary.eligibleChains = 1;
  rejected(refuted);

  const falseCoverageWithoutUnknown = clone(canonicalRun);
  falseCoverageWithoutUnknown.summary.unknowns = 0;
  rejected(falseCoverageWithoutUnknown);
});

test('schema seals the exact claim boundary and its canonical digest', () => {
  for (const mutate of [
    (value) => {
      value.claimBoundary.includes[0] = 'forged boundary';
    },
    (value) => {
      value.claimBoundary.includes.reverse();
    },
    (value) => {
      value.claimBoundary.excludes.pop();
    },
    (value) => {
      value.claimBoundary.excludes.push('extra exclusion');
    },
    (value) => {
      value.claimBoundaryCanonicalSha256 = 'a'.repeat(64);
    },
  ]) {
    const hostile = clone(canonicalRun);
    mutate(hostile);
    rejected(hostile);
  }
});

test('schema cannot grant authority or action', () => {
  for (const mutate of [
    (value) => {
      value.authority = 'operator';
    },
    (value) => {
      value.action = { kind: 'restart' };
    },
    (value) => {
      value.adrAssessment.status = 'candidate';
    },
    (value) => {
      value.capabilityAudit.networkObserved = true;
    },
    (value) => {
      value.capabilityAudit.productionMutationObserved = true;
    },
  ]) {
    const hostile = clone(canonicalRun);
    mutate(hostile);
    rejected(hostile);
  }
});

test('schema rejects additional undeclared fields at every critical envelope', () => {
  for (const mutate of [
    (value) => {
      value.extra = true;
    },
    (value) => {
      value.boundary.extra = true;
    },
    (value) => {
      value.localSourceClosure.extra = true;
    },
    (value) => {
      value.summary.extra = true;
    },
    (value) => {
      value.capabilityAudit.extra = true;
    },
  ]) {
    const hostile = clone(canonicalRun);
    mutate(hostile);
    rejected(hostile);
  }
});
