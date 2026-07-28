import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  BASE_SPECIFICATION_IDS,
  CONTROL_IDS,
  EXPECTED_ACTIVE_SPECIFICATION_IDS,
  FIXTURE_SPECIFICATION_ID,
  PREDICATE_IDS,
  classifyH053Outcome,
  runH053Experiment,
} from './experiment-lib.mjs';
import { inspectH053Sources } from './source-lock.mjs';

const EXPECTED_PREDICATE_IDS = [
  'exactSourceBoundaryClosed',
  'candidateConformsProductSpecificationV1',
  'candidateUsesProseCarrierAndSupersedesNull',
  'candidateInternalReferencesAreClosed',
  'transitionIsAtomicAcceptedAddition',
  'profileRetainsExactlyThreeSpecifications',
  'allThreeAreAcceptedAndUnsuperceded',
  'predecessorBytesRemainIdentical',
  'compiledPlanContainsThreeEffectiveAcceptedSpecifications',
  'profileAndCorpusPermutationIsDeterministic',
  'manifestDeltaIsAdditionOnlyAndContentBound',
  'priorEvidenceBecomesStale',
  'noSpecificationOrImplementationAuthorityIsInferred',
];

const EXPECTED_CONTROL_IDS = [
  'proposedToAcceptedRejectedByImmutability',
  'activeSetRemovalAdmittedByHost',
  'supersessionBreaksIndependentActiveSet',
  'typedRelationshipFieldsRejectedBySchema',
];

const sources = inspectH053Sources();
const temporalSourceBytesByPath = new Map([
  ...sources.gitSourceBytesByPath,
  ...sources.localSourceBytesByPath,
]);

function experiment(overrides = {}) {
  return runH053Experiment({
    sourceBytesByPath: temporalSourceBytesByPath,
    exactSourceBoundaryClosed: true,
    sourceExecutionClosed: false,
    authority: 'none',
    action: null,
    ...overrides,
  });
}

const result = experiment();

test('freezes the exact H-053 predicate and control vocabulary', () => {
  assert.deepEqual(PREDICATE_IDS, EXPECTED_PREDICATE_IDS);
  assert.deepEqual(CONTROL_IDS, EXPECTED_CONTROL_IDS);
  assert.deepEqual(BASE_SPECIFICATION_IDS, ['SPEC-0001', 'SPEC-0002']);
  assert.equal(FIXTURE_SPECIFICATION_ID, 'SPEC-9998');
  assert.deepEqual(EXPECTED_ACTIVE_SPECIFICATION_IDS, ['SPEC-0001', 'SPEC-0002', 'SPEC-9998']);
  assert.deepEqual(Object.keys(result.predicates), EXPECTED_PREDICATE_IDS);
  assert.deepEqual(Object.keys(result.controls), EXPECTED_CONTROL_IDS);
});

test('preserves the atomic additive subresult without claiming H-053 support', () => {
  assert.equal(result.outcome.status, 'inconclusive');
  assert.equal(result.outcome.reason, 'source-execution-closure-incomplete');
  assert.equal(result.outcome.authority, 'none');
  assert.equal(result.outcome.action, null);

  assert.equal(result.predicates.exactSourceBoundaryClosed, false);
  for (const id of EXPECTED_PREDICATE_IDS.slice(1)) {
    assert.equal(result.predicates[id], true, `${id} must pass`);
  }

  assert.equal(result.fixture.specification.status, 'accepted');
  assert.equal(result.fixture.specification.supersedes, null);
  assert.equal(result.fixture.nonNormative, true);
  assert.equal(result.fixture.persisted, false);
  const carrierProse = `${result.fixture.specification.scope} ${result.fixture.specification.summary}`;
  assert.match(carrierProse, /extends SPEC-0001/);
  assert.match(carrierProse, /references SPEC-0002/);
});

test('retains both predecessor bytes and compiles three independent accepted specifications', () => {
  assert.equal(
    result.evidence.base.predecessorManifestRawSha256,
    '888e02e5605c6387c83644bacb049761451605d2c27b501b14f0b8d826af2666'
  );
  assert.equal(
    result.evidence.base.predecessorManifestCarrier,
    'recovered-local-pre-h053-manifest'
  );
  assert.equal(result.evidence.base.predecessorManifestChangeCount, 33);
  assert.deepEqual(Object.keys(result.evidence.predecessorBytes).sort(), [
    ...BASE_SPECIFICATION_IDS,
  ]);
  assert.deepEqual(
    result.evidence.accepted.planSpecifications.map(({ id }) => id),
    EXPECTED_ACTIVE_SPECIFICATION_IDS
  );

  for (const specification of result.evidence.accepted.planSpecifications) {
    assert.equal(specification.declaredStatus, 'accepted');
    assert.equal(specification.effectiveStatus, 'accepted');
    assert.equal(specification.supersededBy, null);
  }

  assert.equal(
    result.evidence.accepted.specificationEntries.find(
      ([id]) => id === FIXTURE_SPECIFICATION_ID
    )?.[1],
    result.fixture.contentHash
  );
});

test('binds equal plans and manifests under corpus and profile permutation', () => {
  assert.equal(result.evidence.accepted.profileHash, result.evidence.permutation.profileHash);
  assert.equal(result.evidence.accepted.planHash, result.evidence.permutation.planHash);
  assert.equal(result.evidence.accepted.manifestHash, result.evidence.permutation.manifestHash);
  assert.notEqual(result.evidence.base.profileHash, result.evidence.accepted.profileHash);
  assert.notEqual(result.evidence.base.planHash, result.evidence.accepted.planHash);
  assert.notEqual(result.evidence.base.manifestHash, result.evidence.accepted.manifestHash);
});

test('reports the four negative controls without concealing the active-set gap', () => {
  for (const id of EXPECTED_CONTROL_IDS) {
    assert.equal(result.controls[id], true, `${id} must expose the expected behavior`);
  }

  assert.deepEqual(result.evidence.controls.proposedTransitionViolations, [
    'specification:SPEC-9998',
  ]);
  assert.equal(
    result.evidence.controls.activeProposedCompilationError.code,
    'SPECIFICATION_INACTIVE'
  );
  assert.deepEqual(result.evidence.controls.activeSetRemoval.planSpecificationIds, ['SPEC-9998']);
  assert.deepEqual(result.evidence.controls.activeSetRemoval.immutabilityViolations, []);
  assert.equal(
    result.evidence.controls.supersessionCompilationError.code,
    'SPECIFICATION_INACTIVE'
  );
  assert.deepEqual(
    result.evidence.controls.typedRelationshipErrors
      .filter(({ keyword }) => keyword === 'additionalProperties')
      .map(({ params }) => params.additionalProperty)
      .sort(),
    ['extends', 'references']
  );
});

test('marks prior evidence stale and leaves the guarded real surface unchanged', () => {
  assert.equal(result.evidence.priorEvidence.baselineState, 'current');
  assert.equal(result.evidence.priorEvidence.changedState, 'stale');
  assert.equal(
    result.evidence.priorEvidence.changedReason,
    'The run observed a different profileHash, planHash, or manifestHash.'
  );
  assert.equal(result.evidence.guardedSurface.unchanged, true);
  assert.equal(result.evidence.guardedSurface.beforeHash, result.evidence.guardedSurface.afterHash);
});

test('fails closed when the external exact-source predicate is not supplied', () => {
  const unbound = experiment({
    exactSourceBoundaryClosed: false,
    sourceExecutionClosed: true,
  });

  assert.equal(unbound.predicates.exactSourceBoundaryClosed, false);
  assert.equal(unbound.outcome.status, 'inconclusive');
  assert.equal(unbound.outcome.reason, 'exact-source-boundary-not-supplied');
});

test('rejects an incomplete supplied temporal source map without worktree fallback', () => {
  const incomplete = new Map(temporalSourceBytesByPath);
  incomplete.delete('.overlaykit/governance/manifest.json');
  assert.throws(
    () => experiment({ sourceBytesByPath: incomplete }),
    /H053_SOURCE_INVALID: supplied temporal source map omits \.overlaykit\/governance\/manifest\.json/u
  );
});

test('implements the exact fail-closed invalid, refuted, inconclusive, and supported policy', () => {
  const closedAdmission = {
    descriptorBoundaryClosed: true,
    sourceExecutionClosed: true,
    authority: 'none',
    action: null,
    realSurfaceUnchanged: true,
    witnessPreconditionsClosed: true,
    acceptedCompilationRejected: false,
    exactThreeAcceptedProduced: true,
    allPredicatesPass: true,
    allControlsPass: true,
  };

  assert.deepEqual(classifyH053Outcome(closedAdmission), {
    status: 'supported',
    reason: 'additive-current-carrier-lifecycle-admitted-with-explicit-gaps',
  });
  assert.deepEqual(
    classifyH053Outcome({
      ...closedAdmission,
      acceptedCompilationRejected: true,
      exactThreeAcceptedProduced: false,
    }),
    { status: 'refuted', reason: 'atomic-accepted-addition-rejected' }
  );
  assert.deepEqual(classifyH053Outcome({ ...closedAdmission, exactThreeAcceptedProduced: false }), {
    status: 'refuted',
    reason: 'three-effective-accepted-specifications-not-produced',
  });
  assert.deepEqual(classifyH053Outcome({ ...closedAdmission, allControlsPass: false }), {
    status: 'inconclusive',
    reason: 'required-negative-control-incomplete',
  });
  assert.deepEqual(
    classifyH053Outcome({
      ...closedAdmission,
      sourceExecutionClosed: false,
      acceptedCompilationRejected: true,
    }),
    { status: 'inconclusive', reason: 'source-execution-closure-incomplete' }
  );
  assert.deepEqual(classifyH053Outcome({ ...closedAdmission, authority: 'self-approved' }), {
    status: 'invalid',
    reason: 'unauthorized-authority-or-action',
  });
  assert.deepEqual(classifyH053Outcome({ ...closedAdmission, realSurfaceUnchanged: false }), {
    status: 'invalid',
    reason: 'unauthorized-real-surface-mutation',
  });
});
