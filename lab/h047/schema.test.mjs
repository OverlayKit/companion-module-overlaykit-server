import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import { H047_CLAIM_BOUNDARY, H047_SUBJECT } from './inventory-lib.mjs';
import { H047_SOURCE_PATHS } from './run.mjs';

const schema = JSON.parse(
  await readFile(
    new URL('./schemas/repository-desired-state-run.schema.json', import.meta.url),
    'utf8'
  )
);
const ajv = new Ajv2020({ allErrors: true, strict: true });
const validate = ajv.compile(schema);

function fixture() {
  const oid = '1'.repeat(40);
  const digest = 'a'.repeat(64);
  return {
    schemaVersion: 'overlaykit-h047-repository-desired-state-run/v1',
    hypothesis: 'H-047',
    subject: {
      ...H047_SUBJECT,
      manifestContentHash: 'a31de506836ffd12f9b1a2849bdb0c353e886481800a2ab01a3dd293ebb7c87e',
    },
    sourceAnchor: {
      commit: '2'.repeat(40),
      parent: H047_SUBJECT.commit,
      parentCount: 1,
      tree: '3'.repeat(40),
      signatureVerified: true,
      deltaPaths: H047_SOURCE_PATHS,
      sourceSetSha256: digest,
      sources: H047_SOURCE_PATHS.map((path) => ({
        path,
        mode: '100644',
        oid,
        byteLength: 1,
        sha256: digest,
      })),
    },
    target: {
      imageReference: 'ghcr.io/bitfocus/companion/companion:v4.3.3',
      imageId: 'sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e',
      hostRole: 'spec-0001-linux-production-host',
      hostRoleSpecification: 'SPEC-0001',
      hostRoleSpecificationContentHash:
        '917f1ca2febe17f8901ab71f91a0b0135402f9be972a876f233fcd5c789b8179',
      imageInterpretation: 'historical-evidence-selector',
    },
    artifacts: {
      sourceMap: { file: 'source-map.json', byteLength: 1, sha256: digest },
      candidateIndex: { file: 'candidate-index.json', byteLength: 1, sha256: digest },
    },
    summary: {
      acceptedDecisions: 6,
      acceptedSpecifications: 2,
      implementedChanges: 9,
      proposedChanges: 12,
      identityPaths: 26,
      deploymentSurfaces: 8,
      candidates: 101,
      unknowns: 7,
      eligibleChains: 0,
      coverageComplete: false,
    },
    outcome: {
      status: 'inconclusive',
      stage: 'source-admission',
      reasonCode: 'incomplete-ambiguous-or-unknown-coverage',
    },
    adrAssessment: {
      status: 'no-decision-candidate-activated',
      rationaleCode: 'repository-inventory-selects-no-new-architecture',
      futureDecisionQuestion:
        'which accepted source of truth, lifecycle-owner role, reconciler, and convergence policy should govern a persistent Companion deployment if one is desired',
      authority: 'none',
      action: null,
    },
    capabilityAudit: {
      mode: 'repository-only-read-only',
      gitExecutable: '/usr/bin/git',
      commandPolicy: [
        'git cat-file blob <oid>',
        'git cat-file commit <source-anchor>',
        'git diff-tree --no-commit-id --name-only -r -z <subject> <source-anchor>',
        'git ls-tree -rz --full-tree <commit>',
        'git rev-parse <revision>',
        'git status --porcelain=v1 --untracked-files=all',
        'git verify-commit <source-anchor>',
      ],
      observedInvocationCounts: {
        'cat-file-blob': 248,
        'cat-file-commit': 1,
        'diff-tree': 1,
        'ls-tree': 2,
        'rev-parse': 4,
        status: 1,
        'verify-commit': 1,
      },
      gitNoLazyFetch: true,
      gitOptionalLocks: false,
      sourceAnchorSignatureVerified: true,
      sourceAnchorParentCount: 1,
      repositoryReadsOnly: true,
      localIgnoredEvidenceWriteOnly: true,
      networkObserved: false,
      dockerObserved: false,
      usbObserved: false,
      procfsObserved: false,
      sysfsObserved: false,
      devfsObserved: false,
      systemdObserved: false,
      hidrawObserved: false,
      signalObserved: false,
      productionMutationObserved: false,
    },
    authority: 'none',
    action: null,
    claimBoundary: H047_CLAIM_BOUNDARY,
    semanticEvidenceSha256: digest,
  };
}

function withOutcome(status, { unknowns, eligibleChains, coverageComplete }) {
  const value = fixture();
  value.summary.unknowns = unknowns;
  value.summary.eligibleChains = eligibleChains;
  value.summary.coverageComplete = coverageComplete;
  if (status === 'supported') {
    value.outcome = {
      status,
      stage: 'desired-state-chain',
      reasonCode: 'eligible-chain-present',
    };
  } else if (status === 'refuted') {
    value.outcome = {
      status,
      stage: 'complete-repository-inventory',
      reasonCode: 'complete-zero-eligible-chain-coverage',
    };
  } else {
    value.outcome = {
      status,
      stage: 'source-admission',
      reasonCode: 'incomplete-ambiguous-or-unknown-coverage',
    };
  }
  return value;
}

function accepted(value) {
  assert.equal(validate(value), true, JSON.stringify(validate.errors));
}

function rejected(value) {
  assert.equal(validate(value), false, 'schema unexpectedly accepted hostile evidence');
}

test('strict schema compiles and accepts the exact bounded run shape', () => {
  accepted(fixture());
});

test('schema accepts exactly the three fail-closed cross-field outcome states', () => {
  for (const value of [
    withOutcome('refuted', {
      unknowns: 0,
      eligibleChains: 0,
      coverageComplete: true,
    }),
    withOutcome('supported', {
      unknowns: 0,
      eligibleChains: 2,
      coverageComplete: true,
    }),
    withOutcome('inconclusive', {
      unknowns: 1,
      eligibleChains: 1,
      coverageComplete: false,
    }),
    withOutcome('inconclusive', {
      unknowns: 0,
      eligibleChains: 0,
      coverageComplete: false,
    }),
  ]) {
    accepted(value);
  }
});

test('schema rejects every impossible outcome/unknown/eligible/coverage combination', () => {
  for (const value of [
    withOutcome('refuted', {
      unknowns: 1,
      eligibleChains: 0,
      coverageComplete: true,
    }),
    withOutcome('refuted', {
      unknowns: 0,
      eligibleChains: 1,
      coverageComplete: true,
    }),
    withOutcome('refuted', {
      unknowns: 0,
      eligibleChains: 0,
      coverageComplete: false,
    }),
    withOutcome('supported', {
      unknowns: 1,
      eligibleChains: 1,
      coverageComplete: true,
    }),
    withOutcome('supported', {
      unknowns: 0,
      eligibleChains: 0,
      coverageComplete: true,
    }),
    withOutcome('supported', {
      unknowns: 0,
      eligibleChains: 1,
      coverageComplete: false,
    }),
    withOutcome('inconclusive', {
      unknowns: 0,
      eligibleChains: 0,
      coverageComplete: true,
    }),
    withOutcome('inconclusive', {
      unknowns: 1,
      eligibleChains: 1,
      coverageComplete: true,
    }),
  ]) {
    rejected(value);
  }
});

test('schema rejects authority, action, target, and claim-boundary broadening', () => {
  for (const mutate of [
    (value) => {
      value.authority = 'operator';
    },
    (value) => {
      value.action = { type: 'restart' };
    },
    (value) => {
      value.target.hostRole = 'some-other-host';
    },
    (value) => {
      value.claimBoundary.excludes.pop();
    },
  ]) {
    const value = structuredClone(fixture());
    mutate(value);
    rejected(value);
  }
});

test('schema rejects artifact swaps, outcome drift, capability expansion, and extra fields', () => {
  for (const mutate of [
    (value) => {
      value.artifacts.sourceMap.file = 'candidate-index.json';
    },
    (value) => {
      value.outcome = {
        status: 'supported',
        stage: 'complete-repository-inventory',
        reasonCode: 'complete-zero-eligible-chain-coverage',
      };
    },
    (value) => {
      value.capabilityAudit.networkObserved = true;
    },
    (value) => {
      value.capabilityAudit.gitNoLazyFetch = false;
    },
    (value) => {
      value.capabilityAudit.gitOptionalLocks = true;
    },
    (value) => {
      value.capabilityAudit.sourceAnchorSignatureVerified = false;
    },
    (value) => {
      value.capabilityAudit.sourceAnchorParentCount = 2;
    },
    (value) => {
      value.sourceAnchor.signatureVerified = false;
    },
    (value) => {
      value.sourceAnchor.parentCount = 2;
    },
    (value) => {
      value.adrAssessment.status = 'adr-candidate';
    },
    (value) => {
      value.adrAssessment.authority = 'agent';
    },
    (value) => {
      value.adrAssessment.action = { type: 'create-adr' };
    },
    (value) => {
      value.summary.coverageComplete = true;
    },
    (value) => {
      value.unreviewed = true;
    },
  ]) {
    const value = structuredClone(fixture());
    mutate(value);
    rejected(value);
  }
});

test('schema rejects an incomplete or expanded source closure', () => {
  const missing = structuredClone(fixture());
  missing.sourceAnchor.sources.pop();
  rejected(missing);

  const expandedSources = structuredClone(fixture());
  expandedSources.sourceAnchor.sources.push({
    path: 'lab/h047/extra.mjs',
    mode: '100644',
    oid: '2'.repeat(40),
    byteLength: 1,
    sha256: 'b'.repeat(64),
  });
  rejected(expandedSources);

  const expanded = structuredClone(fixture());
  expanded.sourceAnchor.deltaPaths = [...expanded.sourceAnchor.deltaPaths, 'ops/companion.service'];
  rejected(expanded);
});

test('schema binds every source position to one exact unique H-047 path', () => {
  const reordered = structuredClone(fixture());
  [reordered.sourceAnchor.sources[0], reordered.sourceAnchor.sources[1]] = [
    reordered.sourceAnchor.sources[1],
    reordered.sourceAnchor.sources[0],
  ];
  rejected(reordered);

  const duplicatePath = structuredClone(fixture());
  duplicatePath.sourceAnchor.sources[1] = {
    ...duplicatePath.sourceAnchor.sources[1],
    path: duplicatePath.sourceAnchor.sources[0].path,
    oid: '2'.repeat(40),
    sha256: 'b'.repeat(64),
  };
  rejected(duplicatePath);

  const substituted = structuredClone(fixture());
  substituted.sourceAnchor.sources[4].path = 'lab/h047/not-review-map.json';
  rejected(substituted);

  const duplicateObject = structuredClone(fixture());
  duplicateObject.sourceAnchor.sources[1] = structuredClone(
    duplicateObject.sourceAnchor.sources[0]
  );
  rejected(duplicateObject);
});
