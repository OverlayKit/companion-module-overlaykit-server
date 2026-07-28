import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalHash, canonicalJson, sha256 } from '../../tools/governance/src/canonical.ts';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');

const PREDICATE_IDS = Object.freeze([
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
]);

const CONTROL_IDS = Object.freeze([
  'proposedToAcceptedRejectedByImmutability',
  'activeSetRemovalAdmittedByHost',
  'supersessionBreaksIndependentActiveSet',
  'typedRelationshipFieldsRejectedBySchema',
]);

const APPARATUS_PATHS = Object.freeze([
  'lab/h053/evidence-lib.mjs',
  'lab/h053/experiment-lib.mjs',
  'lab/h053/experiment-lib.test.mjs',
  'lab/h053/fixtures/SPEC-9998.synthetic.json',
  'lab/h053/run.mjs',
  'lab/h053/source-lock.mjs',
  'lab/h053/source-lock.test.mjs',
  'lab/h053/subject-lock.json',
  'lab/h053/verify.mjs',
  'lab/h053/verify.test.mjs',
]);

const EXPECTED_SOURCE = Object.freeze({
  combinedSourceSetSha256: 'd257830144a01545cd4bdd11c3209481adc54dc6d47603eb8273f6884f17a54f',
  subjectLockRawSha256: '9ec0b7529d5e087018814871e6aa300641a19ffdf6d84aefa6bfa7ef7b83fe4c',
  gitSourceSetSha256: '6031fbc61fc8ccf1be86b712f8d718412a449fe3f393d8fca59fb820473169dd',
  localSourceSetSha256: '45f826086a17aaacdfc0b7dbd8ef2046cfe4044f34ef34c3d1536c783b632f8a',
  restrictedLsTreeSha256: '20e85f20358fe0b186281d3ff006074ccfcdd3de72c2e2fbe1255283326667ac',
  recoveredPreH053ManifestSha256:
    '888e02e5605c6387c83644bacb049761451605d2c27b501b14f0b8d826af2666',
});

const EXPECTED_EXECUTION_BINDINGS = Object.freeze([
  {
    path: '.overlaykit/governance/plan.json',
    byteLength: 22610,
    sha256: '2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243',
    admittedToNominatedBoundary: true,
  },
  {
    path: '.overlaykit/governance/profile.json',
    byteLength: 2547,
    sha256: 'e61fde755b80c66742df144d5e7bcb4309629542e3bdba666a347f65d3341787',
    admittedToNominatedBoundary: true,
  },
  {
    path: '.overlaykit/governance/schemas/profile.schema.json',
    byteLength: 6879,
    sha256: '82360a0c3d3f9e60cf8a5c00bc0d9b0d5eee6de149bba5485db140e3683f5dd2',
    admittedToNominatedBoundary: true,
  },
  {
    path: '.overlaykit/governance/schemas/specification.schema.json',
    byteLength: 5189,
    sha256: '056bc1460849ece13839cd635f0ce1e2e93cd7d00bf9c0e6622e0a2440f720fc',
    admittedToNominatedBoundary: true,
  },
  {
    path: '.overlaykit/governance/specifications/SPEC-0001.json',
    byteLength: 10127,
    sha256: '917f1ca2febe17f8901ab71f91a0b0135402f9be972a876f233fcd5c789b8179',
    admittedToNominatedBoundary: true,
  },
  {
    path: '.overlaykit/governance/specifications/SPEC-0002.json',
    byteLength: 10804,
    sha256: 'd15b1cbf7e97bd92aadf40342421161a0955e210b8566f7ae870dc78c05e89f6',
    admittedToNominatedBoundary: true,
  },
  {
    path: 'tools/governance/src/canonical.ts',
    byteLength: 1346,
    sha256: '104bbd70451af320a2a92e134fc2767208fe08ed1275c2d739b13c0f23ef432b',
    admittedToNominatedBoundary: true,
  },
  {
    path: 'tools/governance/src/compiler.ts',
    byteLength: 7028,
    sha256: 'd5b22afddb6e1611a2d29c5dffd082afcc21dae0c4d9d14078219c2b35368acb',
    admittedToNominatedBoundary: true,
  },
  {
    path: 'tools/governance/src/errors.ts',
    byteLength: 352,
    sha256: '23f0c8e843f655a61dae807709c75670a42ef4b851beb0d8cacd584d0e0578b4',
    admittedToNominatedBoundary: false,
  },
  {
    path: 'tools/governance/src/manifest.ts',
    byteLength: 2702,
    sha256: '95ca667e1596df740237267851a15403061cfa9126c3153634d10b1d9e0b9a9f',
    admittedToNominatedBoundary: true,
  },
  {
    path: 'tools/governance/src/projector.ts',
    byteLength: 6650,
    sha256: 'efaa5623f60211ba7c1ba5b47f1bf66049fbada7ea5de10ba1e5fd336492a7be',
    admittedToNominatedBoundary: true,
  },
  {
    path: 'tools/governance/src/types.ts',
    byteLength: 12487,
    sha256: 'b8b7508ac6b35d16409ab447d71b511263e61953ce56e9a14667becb8db07e14',
    admittedToNominatedBoundary: true,
  },
  {
    path: 'tools/governance/src/validator.ts',
    byteLength: 13226,
    sha256: '177330ac2915cab64953812ad01e8af162e50e7de0fd236b53669e323763a475',
    admittedToNominatedBoundary: true,
  },
]);

const EXPECTED_FIXTURE = Object.freeze({
  path: 'lab/h053/fixtures/SPEC-9998.synthetic.json',
  byteLength: 3709,
  rawSha256: 'b30a1cbeda06cd68853b2e0a022a335843bd301a667c2dace137403bc8cf0005',
  semanticSha256: 'cc590597ff3842ab1131fb65a3c916bf44e901ee797591834e5e899373454333',
});

const EXPECTED_ACTIVE_SPECIFICATION_IDS = Object.freeze(['SPEC-0001', 'SPEC-0002', 'SPEC-9998']);

const EXPECTED_BASE_SPECIFICATION_ENTRIES = Object.freeze([
  ['SPEC-0001', '917f1ca2febe17f8901ab71f91a0b0135402f9be972a876f233fcd5c789b8179'],
  ['SPEC-0002', 'd15b1cbf7e97bd92aadf40342421161a0955e210b8566f7ae870dc78c05e89f6'],
]);

const EXPECTED_ACCEPTED_SPECIFICATION_ENTRIES = Object.freeze([
  ...EXPECTED_BASE_SPECIFICATION_ENTRIES,
  ['SPEC-9998', EXPECTED_FIXTURE.rawSha256],
]);

const EXPECTED_CLAIM_BOUNDARY =
  'no H-053 support or refutation: the d257 descriptor reconstructs, but errors.ts executes outside that nominated boundary; dynamic subresults remain observations and inferences only';

const EXPECTED_DOES_NOT_DEMONSTRATE = Object.freeze([
  'normative specification content or a real specification identity',
  'a universal monotonic active-set guarantee',
  'implementation feasibility or product behavior',
  'live, USB, hidraw, Docker, process, service, network, security, compliance, drift, or production policy',
]);

const EXPECTED_CAPABILITY_UNKNOWNS = Object.freeze([
  'No syscall trace or sandbox-enforced capability allowlist closes process behavior.',
  'Absence fields are apparatus observations, not universal host-activity claims.',
]);

const EXPECTED_ENVIRONMENT_UNKNOWNS = Object.freeze([
  'Node executable bytes and transitive runtime dependencies are outside the nominated subject.',
  'No process-level capability allowlist or syscall trace was produced.',
  'Package-manifest hashes do not close installed package contents.',
]);

const EXPECTED_PRESERVATION = Object.freeze({
  chg0033: '7179de3ae940a9b959d441f42d04ece4158746f23362743dbe625dd9bbd92cc4',
  h052Closure: 'a59c69bc2607b0c4f8d6aab336761b48e0b6f19d251be151e6846c3daf71814f',
  plan: '2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243',
  spec0001: '917f1ca2febe17f8901ab71f91a0b0135402f9be972a876f233fcd5c789b8179',
  spec0002: 'd15b1cbf7e97bd92aadf40342421161a0955e210b8566f7ae870dc78c05e89f6',
});

const EXPECTED_PRESERVATION_PATHS = Object.freeze({
  chg0033: '.overlaykit/governance/changes/CHG-0033.json',
  h052Closure:
    'artifacts/h052/post-review-closures/7179de3ae940a9b959d441f42d04ece4158746f23362743dbe625dd9bbd92cc4/closure.json',
  plan: '.overlaykit/governance/plan.json',
  spec0001: '.overlaykit/governance/specifications/SPEC-0001.json',
  spec0002: '.overlaykit/governance/specifications/SPEC-0002.json',
});

const PROHIBITED_OBSERVATIONS = Object.freeze([
  'fixtureWritesOutsideLab',
  'networkActivity',
  'liveObservation',
  'usbOrHidrawActivity',
  'dockerActivity',
  'signalsOrServicesActivity',
  'realSpecificationMutation',
  'profileSchemaCompilerPlanOrProductMutation',
  'adrCreated',
  'gitIndexOrHistoryMutation',
  'publication',
]);

export const H053_OUTCOME_REASONS = Object.freeze({
  supported: 'additive-current-carrier-lifecycle-admitted-with-explicit-gaps',
  invalidAuthority: 'unauthorized-authority-or-action',
  invalidMutation: 'unauthorized-persistence-capability-or-source-mutation',
  invalidSelfApproval: 'unauthorized-self-approval-or-adr-activation',
  sourceDescriptor: 'exact-source-boundary-not-supplied',
  sourceExecution: 'source-execution-closure-incomplete',
  environment: 'apparatus-environment-closure-incomplete',
  capability: 'capability-closure-incomplete',
  witness: 'synthetic-witness-preconditions-incomplete',
  atomicRefutation: 'atomic-accepted-addition-rejected',
  threeSpecRefutation: 'three-effective-accepted-specifications-not-produced',
  control: 'required-negative-control-incomplete',
  positive: 'positive-result-unclassifiable',
});

export class InvalidH053EvidenceError extends Error {
  constructor(reasonCode, message) {
    super(message);
    this.name = 'InvalidH053EvidenceError';
    this.reasonCode = reasonCode;
  }
}

function assertion(condition, reasonCode, message) {
  if (!condition) {
    throw new InvalidH053EvidenceError(reasonCode, message);
  }
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseEvidence(bytes) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw new InvalidH053EvidenceError('run-json-invalid', error.message);
  }
}

function exactKeys(value, expected, label) {
  assertion(isRecord(value), 'run-shape-invalid', `${label} must be an object`);
  assertion(
    canonicalJson(Object.keys(value).sort()) === canonicalJson([...expected].sort()),
    'run-shape-invalid',
    `${label} keys differ`
  );
}

function exactRoster(receipts, expectedIds, label) {
  assertion(Array.isArray(receipts), 'run-shape-invalid', `${label} must be an array`);
  assertion(
    canonicalJson(receipts.map(({ id }) => id)) === canonicalJson(expectedIds),
    `${label}-roster-drift`,
    `${label} roster or order differs`
  );
}

function semanticBody(run) {
  const { runId: _runId, semanticSha256: _semanticSha256, ...body } = run;
  return body;
}

function sourceDescriptorClosed(subject) {
  return (
    subject.combinedSourceSetSha256 === EXPECTED_SOURCE.combinedSourceSetSha256 &&
    subject.subjectLockRawSha256 === EXPECTED_SOURCE.subjectLockRawSha256 &&
    subject.gitSourceSetSha256 === EXPECTED_SOURCE.gitSourceSetSha256 &&
    subject.localSourceSetSha256 === EXPECTED_SOURCE.localSourceSetSha256 &&
    subject.restrictedLsTreeSha256 === EXPECTED_SOURCE.restrictedLsTreeSha256 &&
    subject.recoveredPreH053ManifestSha256 === EXPECTED_SOURCE.recoveredPreH053ManifestSha256 &&
    subject.gitSourceCount === 21 &&
    subject.localSourceCount === 8 &&
    subject.totalTemporalSourceCount === 29
  );
}

function inspectSourceExecutionClosure(subject) {
  const closure = subject.sourceExecutionClosure;
  assertion(isRecord(closure), 'run-shape-invalid', 'source execution closure must be an object');
  assertion(
    Array.isArray(closure.bindings),
    'run-shape-invalid',
    'source bindings must be an array'
  );
  assertion(
    Array.isArray(closure.unadmittedDependencies),
    'run-shape-invalid',
    'unadmitted dependencies must be an array'
  );
  assertion(
    Array.isArray(closure.nominatedButNotExecutedSources),
    'run-shape-invalid',
    'nominated-but-not-executed sources must be an array'
  );
  const expectedUnadmitted = [EXPECTED_EXECUTION_BINDINGS[8]];
  assertion(
    closure.classification === 'incomplete' &&
      closure.closed === false &&
      closure.method === 'static-first-party-import-closure-plus-consumed-worktree-inputs' &&
      closure.dependencyCount === 13 &&
      closure.admittedDependencyCount === 12 &&
      closure.unadmittedDependencyCount === 1 &&
      closure.consumedInputCount === 6 &&
      closure.executedFirstPartySourceCount === 7 &&
      canonicalJson(closure.bindings) === canonicalJson(EXPECTED_EXECUTION_BINDINGS) &&
      closure.bindingsSha256 ===
        'bb699e42bcdd5c29cd2cde50bf2c19ce312253ca8b689e32871bfde3446d6bf2' &&
      closure.bindingsSha256 === canonicalHash(closure.bindings) &&
      canonicalJson(closure.unadmittedDependencies) === canonicalJson(expectedUnadmitted) &&
      canonicalJson(closure.nominatedButNotExecutedSources) ===
        canonicalJson(['tools/governance/src/repository.ts']) &&
      typeof closure.reason === 'string' &&
      closure.reason.includes('tools/governance/src/errors.ts') &&
      closure.reason.includes('absent from the nominated d257 source roster') &&
      subject.executedWorktreeSourceCount === 13 &&
      subject.executedWorktreeBindingsSha256 === closure.bindingsSha256,
    'source-execution-receipt-drift',
    'The immutable d257 execution closure or its errors.ts omission differs'
  );
  return false;
}

function inspectApparatus(apparatus) {
  assertion(isRecord(apparatus), 'run-shape-invalid', 'apparatus must be an object');
  assertion(
    Array.isArray(apparatus.files),
    'run-shape-invalid',
    'apparatus files must be an array'
  );
  const pathsMatch =
    canonicalJson(apparatus.files.map(({ path: sourcePath }) => sourcePath)) ===
    canonicalJson(APPARATUS_PATHS);
  const descriptorsValid = apparatus.files.every(
    ({ byteLength, sha256: contentHash }) =>
      Number.isSafeInteger(byteLength) &&
      byteLength > 0 &&
      typeof contentHash === 'string' &&
      /^[0-9a-f]{64}$/u.test(contentHash)
  );
  const fixtureDescriptor = apparatus.files.find(
    ({ path: sourcePath }) => sourcePath === EXPECTED_FIXTURE.path
  );
  return (
    apparatus.fileCount === APPARATUS_PATHS.length &&
    pathsMatch &&
    descriptorsValid &&
    fixtureDescriptor?.byteLength === EXPECTED_FIXTURE.byteLength &&
    fixtureDescriptor?.sha256 === EXPECTED_FIXTURE.rawSha256 &&
    apparatus.descriptorSetSha256 === canonicalHash(apparatus.files) &&
    apparatus.admittedAsSubjectSources === false
  );
}

function inspectEnvironment(environment) {
  assertion(isRecord(environment), 'run-shape-invalid', 'environment must be an object');
  assertion(
    environment.closed === false &&
      environment.classification === 'partially-content-addressed-apparatus-environment',
    'environment-closure-overclaim',
    'The H-053 apparatus environment is not independently closed'
  );
  assertion(
    isRecord(environment.node) &&
      typeof environment.node.version === 'string' &&
      typeof environment.node.platform === 'string' &&
      typeof environment.node.architecture === 'string' &&
      environment.node.executableContentSha256 === null,
    'environment-receipt-drift',
    'Node environment receipt differs'
  );
  assertion(
    Array.isArray(environment.packages) &&
      canonicalJson(environment.packages.map(({ name }) => name)) ===
        canonicalJson(['ajv', 'tsx']) &&
      environment.packages.every(
        ({ version, packageManifestByteLength, packageManifestSha256 }) =>
          typeof version === 'string' &&
          Number.isSafeInteger(packageManifestByteLength) &&
          packageManifestByteLength > 0 &&
          typeof packageManifestSha256 === 'string' &&
          /^[0-9a-f]{64}$/u.test(packageManifestSha256)
      ) &&
      environment.packageDescriptorSetSha256 === canonicalHash(environment.packages) &&
      canonicalJson(environment.unknowns) === canonicalJson(EXPECTED_ENVIRONMENT_UNKNOWNS),
    'environment-receipt-drift',
    'Package or environment unknown receipts differ'
  );
  return false;
}

function inspectPreservation(preservation) {
  if (!isRecord(preservation)) {
    return false;
  }
  return Object.entries(EXPECTED_PRESERVATION).every(
    ([id, expectedHash]) =>
      isRecord(preservation[id]) &&
      preservation[id].path === EXPECTED_PRESERVATION_PATHS[id] &&
      preservation[id].sha256 === expectedHash &&
      Number.isSafeInteger(preservation[id].byteLength) &&
      preservation[id].byteLength > 0
  );
}

function inspectRealManifestTransition(transition) {
  return (
    isRecord(transition) &&
    transition.additionOnly === true &&
    transition.predecessorRawSha256 === EXPECTED_SOURCE.recoveredPreH053ManifestSha256 &&
    transition.currentRawSha256 ===
      '69781c1d92fa9fc689270f42a837789dd14daaee4b16d2c813be99fbb579754d' &&
    transition.predecessorContentHash ===
      '0409867cbb9b33c240f88d2b66b93f348ba23d0f0ea1d0c6e5ac4ffea34694d4' &&
    transition.currentContentHash ===
      '22cd29f52d7e43d25049873e808c0112803c4e17d6033d82127c3b032267a42a' &&
    transition.addedChange?.id === 'CHG-0034' &&
    transition.addedChange?.rawSha256 ===
      '162074e3c306b77abe7dc1787d329d999d9955defbc94346a0def68392036458' &&
    transition.addedChange?.status === 'proposed' &&
    canonicalJson(transition.changedTopLevelKeys) === canonicalJson(['changes', 'contentHash']) &&
    transition.predecessorChangeCount === 33 &&
    transition.currentChangeCount === 34
  );
}

function inspectCapabilities(capabilityAudit) {
  assertion(isRecord(capabilityAudit), 'run-shape-invalid', 'capability audit must be an object');
  assertion(
    isRecord(capabilityAudit.observed),
    'run-shape-invalid',
    'capability observations must be an object'
  );
  assertion(
    Array.isArray(capabilityAudit.unknowns),
    'run-shape-invalid',
    'capability unknowns must be an array'
  );
  exactKeys(
    capabilityAudit.observed,
    ['rawEvidenceWriteAuthorized', ...PROHIBITED_OBSERVATIONS],
    'capability observations'
  );
  assertion(
    capabilityAudit.closed === false &&
      capabilityAudit.classification === 'static-apparatus-and-observed-delta-only' &&
      Object.values(capabilityAudit.observed).every((value) => typeof value === 'boolean') &&
      canonicalJson(capabilityAudit.unknowns) === canonicalJson(EXPECTED_CAPABILITY_UNKNOWNS),
    'capability-closure-overclaim',
    'H-053 capability observations do not prove a closed sandbox'
  );
  const prohibitedObserved = PROHIBITED_OBSERVATIONS.some(
    (field) => capabilityAudit.observed[field] === true
  );
  return {
    closed: false,
    rawWriteAuthorized: capabilityAudit.observed.rawEvidenceWriteAuthorized === true,
    prohibitedObserved,
    observedNonUseOnly: true,
  };
}

export function classifyH053Outcome({
  descriptorBoundaryClosed,
  sourceExecutionClosed,
  authority,
  action,
  realSurfaceUnchanged,
  witnessPreconditionsClosed,
  acceptedCompilationRejected,
  exactThreeAcceptedProduced,
  allPredicatesPass,
  allControlsPass,
}) {
  if (authority !== 'none' || action !== null) {
    return { status: 'invalid', reason: H053_OUTCOME_REASONS.invalidAuthority };
  }
  if (realSurfaceUnchanged !== true) {
    return { status: 'invalid', reason: H053_OUTCOME_REASONS.invalidMutation };
  }
  if (descriptorBoundaryClosed !== true) {
    return { status: 'inconclusive', reason: H053_OUTCOME_REASONS.sourceDescriptor };
  }
  if (sourceExecutionClosed !== true) {
    return { status: 'inconclusive', reason: H053_OUTCOME_REASONS.sourceExecution };
  }
  if (witnessPreconditionsClosed !== true) {
    return { status: 'inconclusive', reason: H053_OUTCOME_REASONS.witness };
  }
  if (acceptedCompilationRejected === true) {
    return { status: 'refuted', reason: H053_OUTCOME_REASONS.atomicRefutation };
  }
  if (exactThreeAcceptedProduced !== true) {
    return { status: 'refuted', reason: H053_OUTCOME_REASONS.threeSpecRefutation };
  }
  if (allControlsPass !== true) {
    return { status: 'inconclusive', reason: H053_OUTCOME_REASONS.control };
  }
  if (allPredicatesPass !== true) {
    return { status: 'inconclusive', reason: H053_OUTCOME_REASONS.positive };
  }
  return { status: 'supported', reason: H053_OUTCOME_REASONS.supported };
}

function deriveOutcome(run, predicates, controls, context) {
  const authorityInvalid =
    run.authority !== 'none' ||
    run.action !== null ||
    run.experiment.outcome?.authority !== 'none' ||
    run.experiment.outcome?.action !== null;
  if (authorityInvalid) {
    return { status: 'invalid', reason: H053_OUTCOME_REASONS.invalidAuthority };
  }

  const selfApprovalInvalid =
    run.interpretation.humanReview?.accepted !== null ||
    run.interpretation.adrAssessment?.candidateActivated === true ||
    run.interpretation.adrAssessment?.candidateRecordCreated === true;
  if (selfApprovalInvalid) {
    return { status: 'invalid', reason: H053_OUTCOME_REASONS.invalidSelfApproval };
  }

  const mutationInvalid =
    run.normative !== false ||
    context.capability.prohibitedObserved ||
    !context.capability.rawWriteAuthorized ||
    run.experiment.fixture?.persisted !== false ||
    run.experiment.fixture?.nonNormative !== true ||
    !context.realManifestSafe ||
    !context.preservationSafe ||
    context.guardedSurfaceUnchanged !== true;
  if (mutationInvalid) {
    return { status: 'invalid', reason: H053_OUTCOME_REASONS.invalidMutation };
  }

  const witnessPreconditionsClosed = [
    'candidateConformsProductSpecificationV1',
    'candidateUsesProseCarrierAndSupersedesNull',
    'candidateInternalReferencesAreClosed',
  ].every((id) => predicates[id] === true);
  return classifyH053Outcome({
    descriptorBoundaryClosed: context.sourceDescriptorClosed,
    sourceExecutionClosed:
      predicates.exactSourceBoundaryClosed === true && context.sourceExecutionClosed === true,
    authority: 'none',
    action: null,
    realSurfaceUnchanged: true,
    witnessPreconditionsClosed,
    acceptedCompilationRejected: predicates.transitionIsAtomicAcceptedAddition !== true,
    exactThreeAcceptedProduced:
      predicates.profileRetainsExactlyThreeSpecifications === true &&
      predicates.allThreeAreAcceptedAndUnsuperceded === true &&
      predicates.compiledPlanContainsThreeEffectiveAcceptedSpecifications === true,
    allPredicatesPass: PREDICATE_IDS.every((id) => predicates[id] === true),
    allControlsPass: CONTROL_IDS.every((id) => controls[id] === true),
  });
}

function manifestContentHashIsValid(manifest) {
  if (!isRecord(manifest) || typeof manifest.contentHash !== 'string') {
    return false;
  }
  const { contentHash: _contentHash, ...body } = manifest;
  return canonicalHash(body) === manifest.contentHash;
}

function sameJson(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function internalReferencesAreClosed(specification) {
  if (
    !Array.isArray(specification.actors) ||
    !Array.isArray(specification.terms) ||
    !Array.isArray(specification.requirements) ||
    !Array.isArray(specification.userStories) ||
    !Array.isArray(specification.workflows)
  ) {
    return false;
  }
  const actorIds = new Set(specification.actors.map(({ id }) => id));
  const requirementIds = new Set(specification.requirements.map(({ id }) => id));
  const acceptanceIds = specification.userStories.flatMap(({ acceptanceCriteria }) =>
    (acceptanceCriteria ?? []).map(({ id }) => id)
  );
  const unique = (values) => new Set(values).size === values.length;
  return (
    unique(specification.actors.map(({ id }) => id)) &&
    unique(specification.terms.map(({ id }) => id)) &&
    unique(specification.requirements.map(({ id }) => id)) &&
    unique(specification.userStories.map(({ id }) => id)) &&
    unique(specification.workflows.map(({ id }) => id)) &&
    unique(acceptanceIds) &&
    specification.userStories.every(({ actor }) => actorIds.has(actor)) &&
    specification.workflows.every(
      ({ actors, invariants }) =>
        Array.isArray(actors) &&
        Array.isArray(invariants) &&
        actors.every((actor) => actorIds.has(actor)) &&
        invariants.every((requirement) => requirementIds.has(requirement))
    )
  );
}

function reconstructExperimentResults(run) {
  const fixture = run.experiment.fixture;
  const candidate = fixture.specification;
  const evidence = run.experiment.evidence;
  assertion(
    isRecord(candidate) && isRecord(evidence),
    'experiment-evidence-shape-invalid',
    'Fixture or experiment evidence is absent'
  );

  const fixtureDescriptor = run.apparatus.files.find(
    ({ path: sourcePath }) => sourcePath === EXPECTED_FIXTURE.path
  );
  const fixtureBound =
    fixture.path === EXPECTED_FIXTURE.path &&
    fixture.contentHash === EXPECTED_FIXTURE.rawSha256 &&
    fixture.byteLength === EXPECTED_FIXTURE.byteLength &&
    fixture.nonNormative === true &&
    fixture.persisted === false &&
    fixtureDescriptor?.sha256 === EXPECTED_FIXTURE.rawSha256 &&
    fixtureDescriptor?.byteLength === EXPECTED_FIXTURE.byteLength &&
    canonicalHash(candidate) === EXPECTED_FIXTURE.semanticSha256;
  assertion(fixtureBound, 'fixture-content-drift', 'Synthetic fixture bytes or semantics differ');

  const validation = evidence.candidateValidation;
  const base = evidence.base;
  const accepted = evidence.accepted;
  const permutation = evidence.permutation;
  const manifestDelta = evidence.manifestDelta;
  const controlEvidence = evidence.controls;
  assertion(
    isRecord(validation) &&
      isRecord(base) &&
      isRecord(accepted) &&
      isRecord(permutation) &&
      isRecord(manifestDelta) &&
      isRecord(controlEvidence),
    'experiment-evidence-shape-invalid',
    'Required independent predicate receipts are absent'
  );

  assertion(
    base.predecessorManifestRawSha256 === EXPECTED_SOURCE.recoveredPreH053ManifestSha256 &&
      base.predecessorManifestContentHash ===
        '0409867cbb9b33c240f88d2b66b93f348ba23d0f0ea1d0c6e5ac4ffea34694d4' &&
      base.predecessorManifestChangeCount === 33 &&
      base.predecessorManifestCarrier === 'recovered-local-pre-h053-manifest' &&
      base.nominatedPlanRawSha256 === EXPECTED_PRESERVATION.plan &&
      base.predecessorPlanReconstructed === true &&
      base.descriptorBoundaryClosed === true &&
      base.sourceExecutionClosed === false &&
      base.planHash === 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4' &&
      base.manifestHash === base.predecessorManifestContentHash &&
      sameJson(base.specificationEntries, EXPECTED_BASE_SPECIFICATION_ENTRIES),
    'base-evidence-drift',
    'Predecessor experiment evidence differs from the nominated d257 boundary'
  );

  const planSpecifications = accepted.planSpecifications;
  assertion(
    Array.isArray(planSpecifications) &&
      Array.isArray(accepted.profileSpecificationIds) &&
      Array.isArray(accepted.specificationEntries),
    'experiment-evidence-shape-invalid',
    'Accepted plan or profile receipts are absent'
  );
  const planSpecificationIds = planSpecifications.map(({ id }) => id);
  const allThreeAccepted = planSpecifications.every(
    ({ declaredStatus, effectiveStatus, supersededBy }) =>
      declaredStatus === 'accepted' && effectiveStatus === 'accepted' && supersededBy === null
  );
  const compiledCandidate = planSpecifications.find(({ id }) => id === 'SPEC-9998');

  const baseManifest = manifestDelta.base;
  const acceptedManifest = manifestDelta.accepted;
  assertion(
    isRecord(baseManifest) && isRecord(acceptedManifest),
    'experiment-evidence-shape-invalid',
    'Manifest delta receipts are absent'
  );
  const manifestDeltaClosed =
    manifestContentHashIsValid(baseManifest) &&
    manifestContentHashIsValid(acceptedManifest) &&
    baseManifest.schemaVersion === 'overlaykit-governance-manifest/v2' &&
    acceptedManifest.schemaVersion === baseManifest.schemaVersion &&
    baseManifest.contentHash === base.predecessorManifestContentHash &&
    acceptedManifest.contentHash === accepted.manifestHash &&
    acceptedManifest.contentHash ===
      '329019e8179a59959f02d603688b8f8025d4290ab2829adc91a7d1e961e95e18' &&
    sameJson(
      baseManifest.specifications,
      Object.fromEntries(EXPECTED_BASE_SPECIFICATION_ENTRIES)
    ) &&
    sameJson(
      acceptedManifest.specifications,
      Object.fromEntries(EXPECTED_ACCEPTED_SPECIFICATION_ENTRIES)
    ) &&
    sameJson(baseManifest.decisions, acceptedManifest.decisions) &&
    sameJson(baseManifest.changes, acceptedManifest.changes) &&
    sameJson(baseManifest.schemas, acceptedManifest.schemas) &&
    baseManifest.mechanismsHash === acceptedManifest.mechanismsHash &&
    baseManifest.profileHash === base.profileHash &&
    baseManifest.planHash === base.planHash &&
    acceptedManifest.profileHash === accepted.profileHash &&
    acceptedManifest.planHash === accepted.planHash &&
    sameJson(manifestDelta.additionOnlyViolations, []) &&
    sameJson(manifestDelta.expectedAddition, {
      id: 'SPEC-9998',
      contentHash: EXPECTED_FIXTURE.rawSha256,
    });

  const candidateText = `${candidate.scope ?? ''} ${candidate.summary ?? ''}`;
  const candidateValidationClosed =
    validation.specificationSchemaValid === true &&
    sameJson(validation.specificationSchemaErrors, []) &&
    validation.acceptedProfileSchemaValid === true &&
    sameJson(validation.acceptedProfileSchemaErrors, []);
  const proseCarrierClosed =
    candidate.supersedes === null &&
    candidateText.includes('extends SPEC-0001') &&
    candidateText.includes('references SPEC-0002') &&
    !Object.hasOwn(candidate, 'extends') &&
    !Object.hasOwn(candidate, 'references') &&
    compiledCandidate?.contentHash === EXPECTED_FIXTURE.rawSha256;
  const predecessorBytesClosed =
    sameJson(evidence.predecessorBytes, {
      'SPEC-0001': {
        path: '.overlaykit/governance/specifications/SPEC-0001.json',
        byteLength: 10127,
        sha256: EXPECTED_PRESERVATION.spec0001,
      },
      'SPEC-0002': {
        path: '.overlaykit/governance/specifications/SPEC-0002.json',
        byteLength: 10804,
        sha256: EXPECTED_PRESERVATION.spec0002,
      },
    }) &&
    EXPECTED_BASE_SPECIFICATION_ENTRIES.every(
      ([id, contentHash]) => acceptedManifest.specifications[id] === contentHash
    );
  const guardedSurfaceUnchanged =
    isRecord(evidence.guardedSurface) &&
    canonicalHash(evidence.guardedSurface.paths) ===
      '887a150253c06299cae7b7afbd01de47a1e541341a168b4a3dd22bc1114011d3' &&
    evidence.guardedSurface.beforeHash === evidence.guardedSurface.afterHash &&
    evidence.guardedSurface.unchanged === true;

  const predicates = {
    exactSourceBoundaryClosed:
      base.descriptorBoundaryClosed === true &&
      base.sourceExecutionClosed === true &&
      base.predecessorPlanReconstructed === true,
    candidateConformsProductSpecificationV1:
      fixtureBound &&
      candidateValidationClosed &&
      candidate.schemaVersion === 'overlaykit-product-specification/v1' &&
      candidate.id === 'SPEC-9998',
    candidateUsesProseCarrierAndSupersedesNull: proseCarrierClosed,
    candidateInternalReferencesAreClosed:
      internalReferencesAreClosed(candidate) && accepted.compilationError === null,
    transitionIsAtomicAcceptedAddition:
      candidate.status === 'accepted' &&
      candidateValidationClosed &&
      accepted.compilationError === null &&
      !Object.hasOwn(baseManifest.specifications, 'SPEC-9998'),
    profileRetainsExactlyThreeSpecifications: sameJson(
      accepted.profileSpecificationIds,
      EXPECTED_ACTIVE_SPECIFICATION_IDS
    ),
    allThreeAreAcceptedAndUnsuperceded:
      sameJson(planSpecificationIds, EXPECTED_ACTIVE_SPECIFICATION_IDS) && allThreeAccepted,
    predecessorBytesRemainIdentical: predecessorBytesClosed && guardedSurfaceUnchanged,
    compiledPlanContainsThreeEffectiveAcceptedSpecifications:
      sameJson(planSpecificationIds, EXPECTED_ACTIVE_SPECIFICATION_IDS) && allThreeAccepted,
    profileAndCorpusPermutationIsDeterministic:
      accepted.compilationError === null &&
      permutation.compilationError === null &&
      accepted.profileHash === permutation.profileHash &&
      accepted.planHash === permutation.planHash &&
      accepted.manifestHash === permutation.manifestHash,
    manifestDeltaIsAdditionOnlyAndContentBound:
      manifestDeltaClosed &&
      sameJson(accepted.specificationEntries, EXPECTED_ACCEPTED_SPECIFICATION_ENTRIES) &&
      compiledCandidate?.contentHash === EXPECTED_FIXTURE.rawSha256,
    priorEvidenceBecomesStale:
      evidence.priorEvidence?.baselineState === 'current' &&
      evidence.priorEvidence?.changedState === 'stale' &&
      evidence.priorEvidence?.changedReason ===
        'The run observed a different profileHash, planHash, or manifestHash.' &&
      base.profileHash !== accepted.profileHash &&
      base.planHash !== accepted.planHash &&
      base.manifestHash !== accepted.manifestHash,
    noSpecificationOrImplementationAuthorityIsInferred:
      run.authority === 'none' &&
      run.action === null &&
      run.experiment.outcome?.authority === 'none' &&
      run.experiment.outcome?.action === null &&
      guardedSurfaceUnchanged,
  };

  const typedAdditionalProperties = (controlEvidence.typedRelationshipErrors ?? [])
    .filter(({ keyword }) => keyword === 'additionalProperties')
    .map(({ params }) => params?.additionalProperty)
    .sort();
  const controls = {
    proposedToAcceptedRejectedByImmutability:
      sameJson(controlEvidence.proposedTransitionViolations, ['specification:SPEC-9998']) &&
      controlEvidence.activeProposedCompilationError?.code === 'SPECIFICATION_INACTIVE',
    activeSetRemovalAdmittedByHost:
      controlEvidence.activeSetRemoval?.compilationError === null &&
      sameJson(controlEvidence.activeSetRemoval?.planSpecificationIds, ['SPEC-9998']) &&
      sameJson(controlEvidence.activeSetRemoval?.immutabilityViolations, []),
    supersessionBreaksIndependentActiveSet:
      controlEvidence.supersessionCompilationError?.code === 'SPECIFICATION_INACTIVE' &&
      controlEvidence.supersessionCompilationError?.message?.includes(
        'SPEC-0001 is superseded by SPEC-9998'
      ),
    typedRelationshipFieldsRejectedBySchema: sameJson(typedAdditionalProperties, [
      'extends',
      'references',
    ]),
  };

  return { predicates, controls, guardedSurfaceUnchanged };
}

function inspectCurrentApparatus(run, repositoryRoot) {
  const current = APPARATUS_PATHS.map((sourcePath) => {
    const absolutePath = path.join(repositoryRoot, sourcePath);
    const metadata = lstatSync(absolutePath);
    assertion(
      metadata.isFile() && !metadata.isSymbolicLink() && metadata.nlink === 1,
      'current-apparatus-unsafe',
      `Current apparatus path is unsafe: ${sourcePath}`
    );
    const bytes = readFileSync(absolutePath);
    return { path: sourcePath, byteLength: bytes.length, sha256: sha256(bytes) };
  });
  assertion(
    canonicalJson(current) === canonicalJson(run.apparatus.files),
    'current-apparatus-drift',
    'Current apparatus bytes differ from the evidence descriptors'
  );

  const executionBindings = EXPECTED_EXECUTION_BINDINGS.map((expected) => {
    const absolutePath = path.join(repositoryRoot, expected.path);
    const metadata = lstatSync(absolutePath);
    assertion(
      metadata.isFile() && !metadata.isSymbolicLink() && metadata.nlink === 1,
      'current-execution-source-unsafe',
      `Current execution source is unsafe: ${expected.path}`
    );
    const bytes = readFileSync(absolutePath);
    return {
      path: expected.path,
      byteLength: bytes.length,
      sha256: sha256(bytes),
      admittedToNominatedBoundary: expected.admittedToNominatedBoundary,
    };
  });
  assertion(
    sameJson(executionBindings, EXPECTED_EXECUTION_BINDINGS),
    'current-execution-source-drift',
    'Current execution source bytes differ from the immutable H-053 receipt'
  );

  const currentPackages = [
    ['node_modules/ajv/package.json', 'ajv'],
    ['node_modules/tsx/package.json', 'tsx'],
  ].map(([sourcePath, expectedName]) => {
    const bytes = readFileSync(path.join(repositoryRoot, sourcePath));
    const packageManifest = JSON.parse(bytes.toString('utf8'));
    assertion(
      packageManifest.name === expectedName,
      'current-environment-drift',
      `Current package identity differs: ${sourcePath}`
    );
    return {
      name: packageManifest.name,
      version: packageManifest.version,
      packageManifestByteLength: bytes.length,
      packageManifestSha256: sha256(bytes),
    };
  });
  assertion(
    process.version === run.environment.node.version &&
      process.platform === run.environment.node.platform &&
      process.arch === run.environment.node.architecture &&
      sameJson(currentPackages, run.environment.packages),
    'current-environment-drift',
    'Current Node or package-manifest environment differs from the evidence'
  );
}

export function verifyH053EvidenceStructure(run) {
  exactKeys(
    run,
    [
      'runId',
      'semanticSha256',
      'schemaVersion',
      'hypothesis',
      'normative',
      'subject',
      'realManifestTransition',
      'apparatus',
      'environment',
      'experiment',
      'predicateReceipts',
      'controlReceipts',
      'interpretation',
      'preservation',
      'capabilityAudit',
      'authority',
      'action',
    ],
    'run'
  );
  assertion(
    run.schemaVersion === 'overlaykit-h053-additive-admission-run/v1' && run.hypothesis === 'H-053',
    'run-envelope-drift',
    'Run is not an H-053 evidence envelope'
  );
  assertion(
    typeof run.semanticSha256 === 'string' &&
      /^[0-9a-f]{64}$/u.test(run.semanticSha256) &&
      run.runId === `h053-${run.semanticSha256.slice(0, 24)}` &&
      canonicalHash(semanticBody(run)) === run.semanticSha256,
    'semantic-hash-invalid',
    'Run semantic identity differs'
  );

  exactRoster(run.predicateReceipts, PREDICATE_IDS, 'predicate');
  exactRoster(run.controlReceipts, CONTROL_IDS, 'control');
  exactKeys(run.experiment.predicates, PREDICATE_IDS, 'experiment predicates');
  exactKeys(run.experiment.controls, CONTROL_IDS, 'experiment controls');

  for (const receipt of run.predicateReceipts) {
    exactKeys(receipt, ['id', 'passed'], `predicate receipt ${receipt.id}`);
    assertion(
      typeof receipt.passed === 'boolean' &&
        receipt.passed === run.experiment.predicates[receipt.id],
      'predicate-result-drift',
      `Predicate ${receipt.id} differs from its experiment result`
    );
  }
  for (const receipt of run.controlReceipts) {
    exactKeys(
      receipt,
      ['id', 'passed', 'classification', 'interpretation'],
      `control receipt ${receipt.id}`
    );
    assertion(
      typeof receipt.passed === 'boolean' &&
        receipt.passed === run.experiment.controls[receipt.id] &&
        typeof receipt.interpretation === 'string' &&
        receipt.interpretation.length > 0,
      'control-result-drift',
      `Control ${receipt.id} differs from its experiment result`
    );
    const expectedClassification =
      receipt.passed === false
        ? 'inconclusive'
        : receipt.id === 'activeSetRemovalAdmittedByHost'
          ? 'gap-observed'
          : 'expected-behavior-observed';
    assertion(
      receipt.classification === expectedClassification,
      'control-classification-drift',
      `Control ${receipt.id} classification differs`
    );
  }

  const apparatusClosed = inspectApparatus(run.apparatus);
  assertion(
    apparatusClosed,
    'apparatus-closure-drift',
    'Experimental apparatus descriptors are incomplete or drifted'
  );
  const environmentClosed = inspectEnvironment(run.environment);
  const descriptorClosed = sourceDescriptorClosed(run.subject);
  assertion(
    descriptorClosed,
    'source-boundary-drift',
    'The H-053 subject no longer matches the nominated d257 descriptor'
  );
  const sourceExecutionClosed = inspectSourceExecutionClosure(run.subject);
  const reconstructed = reconstructExperimentResults(run);
  const predicates = reconstructed.predicates;
  const controls = reconstructed.controls;
  for (const { id, passed } of run.predicateReceipts) {
    assertion(
      passed === predicates[id] && run.experiment.predicates[id] === predicates[id],
      'predicate-reconstruction-drift',
      `Predicate ${id} differs from independently reconstructed experiment evidence`
    );
  }
  for (const { id, passed } of run.controlReceipts) {
    assertion(
      passed === controls[id] && run.experiment.controls[id] === controls[id],
      'control-reconstruction-drift',
      `Control ${id} differs from independently reconstructed experiment evidence`
    );
  }

  const capability = inspectCapabilities(run.capabilityAudit);
  const context = {
    sourceDescriptorClosed: descriptorClosed,
    sourceExecutionClosed,
    apparatusClosed,
    environmentClosed,
    preservationSafe: inspectPreservation(run.preservation),
    realManifestSafe: inspectRealManifestTransition(run.realManifestTransition),
    guardedSurfaceUnchanged: reconstructed.guardedSurfaceUnchanged,
    capability,
  };
  const outcome = deriveOutcome(run, predicates, controls, context);

  assertion(
    run.experiment.outcome?.status === outcome.status &&
      run.experiment.outcome?.reason === outcome.reason &&
      run.interpretation.outcome?.status === outcome.status &&
      run.interpretation.outcome?.reasonCode === outcome.reason,
    'outcome-polarity-drift',
    `Declared outcome does not match independent oracle ${outcome.status}/${outcome.reason}`
  );
  assertion(
    run.interpretation.outcome?.stage === 'pre-review-offline-current-host-admission' &&
      run.interpretation.outcome.claimBoundary === EXPECTED_CLAIM_BOUNDARY &&
      run.interpretation.humanReview?.required === true &&
      sameJson(run.interpretation.doesNotDemonstrate, EXPECTED_DOES_NOT_DEMONSTRATE),
    'review-boundary-drift',
    'Claim boundary, non-demonstrations, or human-review boundary differs'
  );

  const passedPredicateCount = run.predicateReceipts.filter(({ passed }) => passed).length;
  const passedControlCount = run.controlReceipts.filter(({ passed }) => passed).length;
  const subresults = run.interpretation.subresults;
  assertion(
    isRecord(subresults) &&
      subresults.classification === 'observations-and-inferences-only' &&
      subresults.passedPredicateCount === passedPredicateCount &&
      subresults.totalPredicateCount === PREDICATE_IDS.length &&
      subresults.passedControlCount === passedControlCount &&
      subresults.totalControlCount === CONTROL_IDS.length &&
      subresults.supportClaimed === (outcome.status === 'supported') &&
      subresults.refutationClaimed === (outcome.status === 'refuted'),
    'subresult-polarity-drift',
    'Subresult counts or claims differ from the independent oracle'
  );

  const activeSetGap =
    run.controlReceipts.find(({ id }) => id === 'activeSetRemovalAdmittedByHost')
      ?.classification === 'gap-observed';
  const candidateMayBeNominated = outcome.status === 'supported' && activeSetGap;
  const adrAssessment = run.interpretation.adrAssessment;
  assertion(isRecord(adrAssessment), 'run-shape-invalid', 'ADR assessment must be an object');
  assertion(
    adrAssessment.candidateQuestion ===
      'Should active specification membership be monotonic so an additive activation cannot silently remove an unsuperseded predecessor?',
    'adr-assessment-overclaim',
    'ADR candidate question differs'
  );
  assertion(
    outcome.status === 'invalid' ||
      adrAssessment.candidateNominated !== true ||
      candidateMayBeNominated,
    'adr-assessment-overclaim',
    'ADR candidate was nominated without supported evidence and an observed active-set gap'
  );
  assertion(
    outcome.status === 'invalid' ||
      (adrAssessment.candidateActivated !== true && adrAssessment.candidateRecordCreated !== true),
    'adr-assessment-overclaim',
    'Evidence creates or activates an ADR'
  );

  return {
    runId: run.runId,
    semanticSha256: run.semanticSha256,
    predicateCount: PREDICATE_IDS.length,
    passedPredicateCount,
    controlCount: CONTROL_IDS.length,
    passedControlCount,
    outcome: run.interpretation.outcome,
    adrAssessment,
    sourceClosure: {
      descriptorClosed: context.sourceDescriptorClosed,
      executionClosed: context.sourceExecutionClosed,
    },
    environmentClosure: {
      declaredClosed: context.environmentClosed,
      independentlyReconstructed: false,
    },
    capabilityAssessment: {
      declaredClosed: capability.closed,
      observedNonUseOnly: capability.observedNonUseOnly,
      sandboxEnforcementProven: false,
    },
    authority: 'none',
    action: null,
  };
}

export function verifyH053EvidenceBytes(
  bytes,
  { rebuild = true, repositoryRoot = REPOSITORY_ROOT } = {}
) {
  const run = parseEvidence(bytes);
  const structural = verifyH053EvidenceStructure(run);
  if (rebuild) {
    inspectCurrentApparatus(run, realpathSync(repositoryRoot));
  }
  return {
    verified: true,
    rawSha256: sha256(bytes),
    byteLength: bytes.length,
    independentOracleVerified: true,
    producerReconstructionUsed: false,
    deterministicReconstructionVerified: false,
    currentApparatusVerified: rebuild,
    ...structural,
  };
}

function containedRelative(parent, target, reasonCode) {
  const relative = path.relative(parent, target);
  assertion(
    relative !== '' &&
      relative !== '..' &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative),
    reasonCode,
    `Path escapes fixed root: ${target}`
  );
  return relative;
}

function assertNoSymlinkComponents(parent, target) {
  const relative = containedRelative(parent, target, 'run-path-invalid');
  let current = parent;
  for (const [index, component] of relative.split(path.sep).entries()) {
    current = path.join(current, component);
    const metadata = lstatSync(current);
    assertion(
      !metadata.isSymbolicLink(),
      'run-path-symlink',
      `Run path contains symlink component ${current}`
    );
    if (index < relative.split(path.sep).length - 1) {
      assertion(metadata.isDirectory(), 'run-path-invalid', `${current} is not a directory`);
    }
  }
}

function readUniqueRegularFile(filePath, runsRoot) {
  assertNoSymlinkComponents(runsRoot, filePath);
  const realRunsRoot = realpathSync(runsRoot);
  const realFilePath = realpathSync(filePath);
  containedRelative(realRunsRoot, realFilePath, 'run-path-invalid');
  const descriptor = openSync(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const descriptorMetadata = fstatSync(descriptor);
    const pathnameMetadata = lstatSync(filePath);
    assertion(
      descriptorMetadata.isFile() &&
        pathnameMetadata.isFile() &&
        !pathnameMetadata.isSymbolicLink() &&
        descriptorMetadata.nlink === 1 &&
        pathnameMetadata.nlink === 1 &&
        descriptorMetadata.dev === pathnameMetadata.dev &&
        descriptorMetadata.ino === pathnameMetadata.ino,
      'run-file-unsafe',
      'Run file is not a unique regular file'
    );
    assertion(
      (descriptorMetadata.mode & 0o777) === 0o600,
      'run-mode-drift',
      'Run file mode differs'
    );
    assertNoSymlinkComponents(runsRoot, filePath);
    return readFileSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

export function verifyH053EvidenceFile(
  filePath,
  { repositoryRoot = REPOSITORY_ROOT, rebuild = true } = {}
) {
  assertion(
    typeof filePath === 'string' &&
      filePath.length > 0 &&
      !filePath.includes('\0') &&
      !filePath.split(/[\\/]/u).includes('..'),
    'run-path-traversal',
    'Run path contains traversal or invalid bytes'
  );
  const realRepositoryRoot = realpathSync(repositoryRoot);
  const runsRoot = path.join(realRepositoryRoot, 'artifacts', 'h053', 'runs');
  assertNoSymlinkComponents(realRepositoryRoot, runsRoot);
  const absolutePath = path.resolve(realRepositoryRoot, filePath);
  containedRelative(runsRoot, absolutePath, 'run-path-invalid');
  const bytes = readUniqueRegularFile(absolutePath, runsRoot);
  const receipt = verifyH053EvidenceBytes(bytes, {
    rebuild,
    repositoryRoot: realRepositoryRoot,
  });
  const relativeEvidencePath = path.relative(runsRoot, absolutePath);
  assertion(
    relativeEvidencePath === path.join(receipt.semanticSha256, 'run.json'),
    'run-content-address-mismatch',
    'Run path does not match its recomputed semantic SHA-256'
  );
  return receipt;
}

export function verifyH053EvidenceSafe(bytes, options) {
  try {
    return verifyH053EvidenceBytes(bytes, options);
  } catch (error) {
    return {
      verified: false,
      reasonCode:
        error instanceof InvalidH053EvidenceError ? error.reasonCode : 'unexpected-verifier-error',
      message: error instanceof Error ? error.message : String(error),
      authority: 'none',
      action: null,
    };
  }
}

function main() {
  assertion(process.argv.length === 3, 'cli-usage-invalid', 'usage: verify.mjs <run.json>');
  process.stdout.write(`${JSON.stringify(verifyH053EvidenceFile(process.argv[2]))}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
