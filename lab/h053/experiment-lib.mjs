import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Ajv } from 'ajv';
import {
  canonicalHash,
  canonicalJson,
  canonicalPrettyJson,
  sha256,
} from '../../tools/governance/src/canonical.ts';
import { compileGovernance } from '../../tools/governance/src/compiler.ts';
import { immutabilityViolations } from '../../tools/governance/src/manifest.ts';
import { observeRun } from '../../tools/governance/src/projector.ts';

export const BASE_SPECIFICATION_IDS = Object.freeze(['SPEC-0001', 'SPEC-0002']);
export const FIXTURE_SPECIFICATION_ID = 'SPEC-9998';
export const EXPECTED_ACTIVE_SPECIFICATION_IDS = Object.freeze([
  ...BASE_SPECIFICATION_IDS,
  FIXTURE_SPECIFICATION_ID,
]);

export const PREDICATE_IDS = Object.freeze([
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

export const CONTROL_IDS = Object.freeze([
  'proposedToAcceptedRejectedByImmutability',
  'activeSetRemovalAdmittedByHost',
  'supersessionBreaksIndependentActiveSet',
  'typedRelationshipFieldsRejectedBySchema',
]);

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const PRE_H053_MANIFEST_SHA256 = '888e02e5605c6387c83644bacb049761451605d2c27b501b14f0b8d826af2666';
const NOMINATED_INPUT_PATHS = Object.freeze({
  manifest: '.overlaykit/governance/manifest.json',
  plan: '.overlaykit/governance/plan.json',
  profile: '.overlaykit/governance/profile.json',
  profileSchema: '.overlaykit/governance/schemas/profile.schema.json',
  specificationSchema: '.overlaykit/governance/schemas/specification.schema.json',
  spec0001: '.overlaykit/governance/specifications/SPEC-0001.json',
  spec0002: '.overlaykit/governance/specifications/SPEC-0002.json',
});

const GUARDED_PATHS = Object.freeze([
  '.overlaykit/governance/decisions',
  '.overlaykit/governance/mechanisms.json',
  '.overlaykit/governance/plan.json',
  '.overlaykit/governance/profile.json',
  '.overlaykit/governance/schemas',
  '.overlaykit/governance/specifications',
  'package-lock.json',
  'package.json',
  'src',
  'tests',
  'tools/governance/src',
]);

function clone(value) {
  return structuredClone(value);
}

function assertCondition(condition, message) {
  if (!condition) {
    throw new Error(`H053_SOURCE_INVALID: ${message}`);
  }
}

function sameStringSet(actual, expected) {
  return (
    actual.length === expected.length &&
    [...actual].sort().every((value, index) => value === [...expected].sort()[index])
  );
}

function recordForSpecification(specification, suppliedBytes = null) {
  const bytes = suppliedBytes ?? Buffer.from(canonicalPrettyJson(specification), 'utf8');
  return {
    specification,
    contentHash: sha256(bytes),
    path: `counterfactual/specifications/${specification.id}.json`,
    byteLength: bytes.length,
  };
}

function parseJsonBytes(bytes, label) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw new Error(`H053_SOURCE_INVALID: ${label} JSON is invalid: ${error.message}`);
  }
}

export function loadNominatedExperimentInputs({
  repoRoot = REPO_ROOT,
  sourceBytesByPath = null,
} = {}) {
  const resolvedRoot = resolve(repoRoot);
  const read = (sourcePath) => {
    if (sourceBytesByPath === null) {
      return readFileSync(join(resolvedRoot, sourcePath));
    }
    assertCondition(
      sourceBytesByPath.has(sourcePath),
      `supplied temporal source map omits ${sourcePath}`
    );
    return sourceBytesByPath.get(sourcePath);
  };
  return Object.fromEntries(
    Object.entries(NOMINATED_INPUT_PATHS).map(([id, sourcePath]) => [
      id,
      {
        path: sourcePath,
        bytes: Buffer.from(read(sourcePath)),
      },
    ])
  );
}

function loadFixture(repoRoot) {
  const fixturePath = join(repoRoot, 'lab', 'h053', 'fixtures', 'SPEC-9998.synthetic.json');
  const bytes = readFileSync(fixturePath);
  let specification;
  try {
    specification = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw new Error(`H053_SOURCE_INVALID: fixture JSON is invalid: ${error.message}`);
  }
  return {
    specification,
    bytes,
    path: relative(repoRoot, fixturePath),
  };
}

function collectFiles(root, relativePath) {
  const absolutePath = join(root, relativePath);
  const metadata = statSync(absolutePath);

  if (metadata.isFile()) {
    return [relativePath];
  }

  assertCondition(metadata.isDirectory(), `${relativePath} is not a regular file or directory`);

  return readdirSync(absolutePath)
    .sort()
    .flatMap((entry) => collectFiles(root, join(relativePath, entry)));
}

function snapshotGuardedSurface(repoRoot) {
  const files = GUARDED_PATHS.flatMap((path) => collectFiles(repoRoot, path))
    .sort()
    .map((path) => {
      const bytes = readFileSync(join(repoRoot, path));
      return {
        path,
        byteLength: bytes.length,
        sha256: sha256(bytes),
      };
    });

  return {
    files,
    sha256: canonicalHash(files),
  };
}

function compileSchemaValidators(inputs) {
  const ajv = new Ajv({ allErrors: true, strict: true });
  const specificationSchema = parseJsonBytes(
    inputs.specificationSchema.bytes,
    inputs.specificationSchema.path
  );
  const profileSchema = parseJsonBytes(inputs.profileSchema.bytes, inputs.profileSchema.path);

  return {
    specification: ajv.compile(specificationSchema),
    profile: ajv.compile(profileSchema),
  };
}

function policiesForDecision(plan, decisionId) {
  const rules = plan.rules
    .filter(({ sourceDecision }) => sourceDecision === decisionId)
    .map(({ sourceDecision: _sourceDecision, ...rule }) => ({ kind: 'rule', ...rule }));
  const gates = plan.gates
    .filter(({ sourceDecision }) => sourceDecision === decisionId)
    .map(({ sourceDecision: _sourceDecision, outcome: _outcome, ...gate }) => ({
      kind: 'gate',
      ...gate,
    }));
  const artifacts = plan.artifacts
    .filter(({ sourceDecision }) => sourceDecision === decisionId)
    .map(({ sourceDecision: _sourceDecision, ...artifact }) => ({
      kind: 'artifact',
      ...artifact,
    }));
  return [...rules, ...gates, ...artifacts];
}

function decisionRecordFromPlan(plan, compiled) {
  assertCondition(
    compiled.declaredStatus === 'accepted' &&
      compiled.effectiveStatus === 'accepted' &&
      compiled.supersededBy === null,
    `${compiled.id} is not independently accepted in the nominated plan`
  );
  return {
    decision: {
      schemaVersion: 'overlaykit-governance-decision/v1',
      id: compiled.id,
      title: compiled.title,
      status: compiled.declaredStatus,
      date: '2026-07-28',
      supersedes: null,
      governs: ['h053-counterfactual-carrier'],
      context: 'Synthetic carrier reconstructed exclusively from the nominated compiled plan.',
      decision: 'Retain the nominated compiled projection without creating normative law.',
      consequences: ['Only fields consumed by the current compiler are reconstructed.'],
      policies: policiesForDecision(plan, compiled.id),
    },
    contentHash: compiled.contentHash,
    path: `counterfactual/decisions/${compiled.id}.json`,
  };
}

function specificationRecordFromInput(input) {
  const specification = parseJsonBytes(input.bytes, input.path);
  return {
    specification,
    contentHash: sha256(input.bytes),
    byteLength: input.bytes.length,
    path: input.path,
  };
}

function baseContract(inputs) {
  const plan = parseJsonBytes(inputs.plan.bytes, inputs.plan.path);
  const profile = parseJsonBytes(inputs.profile.bytes, inputs.profile.path);
  const records = [
    specificationRecordFromInput(inputs.spec0001),
    specificationRecordFromInput(inputs.spec0002),
  ];
  assertCondition(
    sameStringSet(
      records.map(({ specification }) => specification.id),
      BASE_SPECIFICATION_IDS
    ),
    'the two nominated predecessor specifications are absent'
  );
  assertCondition(
    sameStringSet(profile.specificationIds ?? [], BASE_SPECIFICATION_IDS),
    'the nominated active profile is not the exact two-specification predecessor set'
  );
  const contract = {
    decisions: plan.decisions.map((decision) => decisionRecordFromPlan(plan, decision)),
    specifications: clone(records),
    changes: [],
    profile: {
      ...clone(profile),
      specificationIds: [...BASE_SPECIFICATION_IDS],
    },
    mechanisms: {
      schemaVersion: 'overlaykit-governance-mechanisms/v1',
      mechanisms: clone(plan.mechanisms),
    },
    schemas: {
      'profile.schema.json': sha256(inputs.profileSchema.bytes),
      'specification.schema.json': sha256(inputs.specificationSchema.bytes),
    },
    schemasHash: plan.schemasHash,
    mechanismsHash: plan.mechanismsHash,
  };
  return { contract, nominatedPlan: plan };
}

function validatePredecessorManifest(input, basePlan, base) {
  const manifest = parseJsonBytes(input.bytes, input.path);
  const { contentHash, ...body } = manifest;
  assertCondition(
    sha256(input.bytes) === PRE_H053_MANIFEST_SHA256,
    'the local pre-H-053 manifest bytes are not the nominated predecessor'
  );
  assertCondition(
    contentHash === canonicalHash(body),
    'the local pre-H-053 manifest content hash is invalid'
  );
  assertCondition(
    manifest.schemaVersion === 'overlaykit-governance-manifest/v2' &&
      manifest.profileHash === basePlan.profileHash &&
      manifest.mechanismsHash === basePlan.mechanismsHash &&
      manifest.planHash === basePlan.planHash,
    'the local pre-H-053 manifest does not bind the reconstructed predecessor plan'
  );
  assertCondition(
    BASE_SPECIFICATION_IDS.every(
      (id) =>
        manifest.specifications[id] ===
        base.specifications.find(({ specification }) => specification.id === id)?.contentHash
    ) && Object.keys(manifest.specifications).length === BASE_SPECIFICATION_IDS.length,
    'the local pre-H-053 manifest does not bind exactly the two predecessor specifications'
  );
  return manifest;
}

function syntheticManifestFromPredecessor(predecessor, plan, addedSpecifications = []) {
  const { contentHash: _predecessorContentHash, ...predecessorBody } = clone(predecessor);
  const body = {
    ...predecessorBody,
    specifications: Object.fromEntries(
      [
        ...Object.entries(predecessor.specifications),
        ...addedSpecifications.map(({ specification, contentHash }) => [
          specification.id,
          contentHash,
        ]),
      ].sort(([left], [right]) => left.localeCompare(right))
    ),
    profileHash: plan.profileHash,
    mechanismsHash: plan.mechanismsHash,
    planHash: plan.planHash,
  };
  return {
    ...body,
    contentHash: canonicalHash(body),
  };
}

function manifestReceipt(manifest) {
  if (manifest === null) {
    return null;
  }
  return {
    schemaVersion: manifest.schemaVersion,
    decisions: clone(manifest.decisions),
    specifications: clone(manifest.specifications),
    changes: clone(manifest.changes),
    schemas: clone(manifest.schemas),
    profileHash: manifest.profileHash,
    mechanismsHash: manifest.mechanismsHash,
    planHash: manifest.planHash,
    contentHash: manifest.contentHash,
  };
}

function unchangedManifestChangeCarriers(manifest) {
  return Object.keys(manifest.changes).map((id) => ({
    change: {
      id,
      status: 'proposed',
    },
  }));
}

function withCandidate(contract, record, activeIds) {
  return {
    ...clone(contract),
    specifications: [...clone(contract.specifications), clone(record)],
    profile: {
      ...clone(contract.profile),
      specificationIds: [...activeIds],
    },
  };
}

function captureError(operation) {
  try {
    return { value: operation(), error: null };
  } catch (error) {
    return {
      value: null,
      error: {
        name: error instanceof Error ? error.name : 'UnknownError',
        code:
          error !== null && typeof error === 'object' && 'code' in error
            ? String(error.code)
            : null,
        message: error instanceof Error ? error.message : String(error),
      },
    };
  }
}

function internalReferencesAreClosed(specification) {
  const actorIds = new Set(specification.actors.map(({ id }) => id));
  const requirementIds = new Set(specification.requirements.map(({ id }) => id));
  const acceptanceIds = specification.userStories.flatMap(({ acceptanceCriteria }) =>
    acceptanceCriteria.map(({ id }) => id)
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
        actors.every((actor) => actorIds.has(actor)) &&
        invariants.every((requirement) => requirementIds.has(requirement))
    )
  );
}

function baselineRun(plan, manifest) {
  const target = {
    repository: 'OverlayKit/companion-module-overlaykit-server',
    commit: 'a'.repeat(40),
    ref: 'refs/heads/counterfactual',
    event: 'local',
    pullRequest: null,
  };

  return {
    target,
    run: {
      schemaVersion: 'overlaykit-governance-run/v1',
      runId: 'h053-baseline-counterfactual',
      profileHash: plan.profileHash,
      planHash: plan.planHash,
      manifestHash: manifest.contentHash,
      invokedBy: { kind: 'agent', id: 'codex', principal: '@rodrigoteamx' },
      producer: {
        kind: 'local-cli',
        id: 'lab/h053/experiment-lib.mjs',
        version: '1',
        commit: target.commit,
      },
      subject: target,
      source: 'local',
      startedAt: '2026-07-28T00:00:00.000Z',
      finishedAt: '2026-07-28T00:00:00.001Z',
      assumptions: clone(plan.assumptions),
      outcomes: [],
      artifacts: [],
    },
  };
}

function predecessorSnapshot(contract) {
  return Object.fromEntries(
    contract.specifications.map((record) => {
      return [
        record.specification.id,
        {
          path: record.path,
          byteLength: record.byteLength,
          sha256: record.contentHash,
        },
      ];
    })
  );
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
    return { status: 'invalid', reason: 'unauthorized-authority-or-action' };
  }
  if (realSurfaceUnchanged !== true) {
    return { status: 'invalid', reason: 'unauthorized-real-surface-mutation' };
  }
  if (descriptorBoundaryClosed !== true) {
    return { status: 'inconclusive', reason: 'exact-source-boundary-not-supplied' };
  }
  if (sourceExecutionClosed !== true) {
    return { status: 'inconclusive', reason: 'source-execution-closure-incomplete' };
  }
  if (witnessPreconditionsClosed !== true) {
    return { status: 'inconclusive', reason: 'synthetic-witness-preconditions-incomplete' };
  }
  if (acceptedCompilationRejected === true) {
    return { status: 'refuted', reason: 'atomic-accepted-addition-rejected' };
  }
  if (exactThreeAcceptedProduced !== true) {
    return {
      status: 'refuted',
      reason: 'three-effective-accepted-specifications-not-produced',
    };
  }
  if (allControlsPass !== true) {
    return { status: 'inconclusive', reason: 'required-negative-control-incomplete' };
  }
  if (allPredicatesPass !== true) {
    return { status: 'inconclusive', reason: 'positive-result-unclassifiable' };
  }
  return {
    status: 'supported',
    reason: 'additive-current-carrier-lifecycle-admitted-with-explicit-gaps',
  };
}

export function runH053Experiment({
  repoRoot = REPO_ROOT,
  sourceBytesByPath = null,
  exactSourceBoundaryClosed = false,
  sourceExecutionClosed = false,
  authority = 'none',
  action = null,
} = {}) {
  const resolvedRoot = resolve(repoRoot);
  const guardedBefore = snapshotGuardedSurface(resolvedRoot);
  const inputs = loadNominatedExperimentInputs({ repoRoot: resolvedRoot, sourceBytesByPath });
  const validators = compileSchemaValidators(inputs);
  const { contract: base, nominatedPlan } = baseContract(inputs);
  const predecessorsBefore = predecessorSnapshot(base);
  const basePlan = compileGovernance(base);
  const predecessorPlanReconstructed =
    canonicalJson(basePlan) === canonicalJson(nominatedPlan) &&
    sha256(inputs.plan.bytes) ===
      '2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243';
  const baseManifest = validatePredecessorManifest(inputs.manifest, basePlan, base);

  const fixture = loadFixture(resolvedRoot);
  const candidate = fixture.specification;
  const candidateRecord = recordForSpecification(candidate, fixture.bytes);
  const candidateSchemaValid = validators.specification(candidate);
  const candidateSchemaErrors = clone(validators.specification.errors ?? []);
  const accepted = withCandidate(base, candidateRecord, EXPECTED_ACTIVE_SPECIFICATION_IDS);
  const acceptedProfileSchemaValid = validators.profile(accepted.profile);
  const acceptedProfileSchemaErrors = clone(validators.profile.errors ?? []);
  const acceptedCompilation = captureError(() => compileGovernance(accepted));
  const acceptedPlan = acceptedCompilation.value;
  const acceptedManifest =
    acceptedPlan === null
      ? null
      : syntheticManifestFromPredecessor(baseManifest, acceptedPlan, [candidateRecord]);

  const permuted = {
    ...clone(accepted),
    specifications: [...clone(accepted.specifications)].reverse(),
    profile: {
      ...clone(accepted.profile),
      specificationIds: [...EXPECTED_ACTIVE_SPECIFICATION_IDS].reverse(),
    },
  };
  const permutedCompilation = captureError(() => compileGovernance(permuted));
  const permutedPlan = permutedCompilation.value;
  const permutedManifest =
    permutedPlan === null
      ? null
      : syntheticManifestFromPredecessor(baseManifest, permutedPlan, [candidateRecord]);

  const proposedCandidate = { ...clone(candidate), status: 'proposed' };
  const proposedRecord = recordForSpecification(proposedCandidate);
  const proposed = withCandidate(base, proposedRecord, BASE_SPECIFICATION_IDS);
  const proposedPlan = compileGovernance(proposed);
  const proposedManifest = syntheticManifestFromPredecessor(baseManifest, proposedPlan, [
    proposedRecord,
  ]);
  const proposedTransitionViolations =
    acceptedManifest === null
      ? []
      : immutabilityViolations(
          proposedManifest,
          acceptedManifest,
          unchangedManifestChangeCarriers(proposedManifest)
        );
  const activeProposedCompilation = captureError(() =>
    compileGovernance(withCandidate(base, proposedRecord, EXPECTED_ACTIVE_SPECIFICATION_IDS))
  );

  const removedActiveSetCompilation = captureError(() =>
    compileGovernance(withCandidate(base, candidateRecord, [FIXTURE_SPECIFICATION_ID]))
  );
  const removedActiveSetPlan = removedActiveSetCompilation.value;
  const removedActiveSetManifest =
    removedActiveSetPlan === null
      ? null
      : syntheticManifestFromPredecessor(baseManifest, removedActiveSetPlan, [candidateRecord]);
  const removalViolations =
    acceptedManifest === null || removedActiveSetManifest === null
      ? ['experiment-not-comparable']
      : immutabilityViolations(
          acceptedManifest,
          removedActiveSetManifest,
          unchangedManifestChangeCarriers(acceptedManifest)
        );

  const supersedingCandidate = {
    ...clone(candidate),
    supersedes: BASE_SPECIFICATION_IDS[0],
  };
  const supersedingCompilation = captureError(() =>
    compileGovernance(
      withCandidate(
        base,
        recordForSpecification(supersedingCandidate),
        EXPECTED_ACTIVE_SPECIFICATION_IDS
      )
    )
  );

  const typedCandidate = {
    ...clone(candidate),
    extends: BASE_SPECIFICATION_IDS[0],
    references: [BASE_SPECIFICATION_IDS[1]],
  };
  const typedRelationshipValid = validators.specification(typedCandidate);
  const typedRelationshipErrors = clone(validators.specification.errors ?? []);
  const typedAdditionalProperties = typedRelationshipErrors
    .filter(({ keyword }) => keyword === 'additionalProperties')
    .map(({ params }) => params.additionalProperty)
    .sort();

  const planSpecificationIds = acceptedPlan?.specifications.map(({ id }) => id) ?? [];
  const compiledCandidate = acceptedPlan?.specifications.find(
    ({ id }) => id === FIXTURE_SPECIFICATION_ID
  );
  const allThreeAccepted =
    acceptedPlan !== null &&
    acceptedPlan.specifications.every(
      ({ declaredStatus, effectiveStatus, supersededBy }) =>
        declaredStatus === 'accepted' && effectiveStatus === 'accepted' && supersededBy === null
    );
  const baseSpecificationEntries = Object.entries(baseManifest.specifications).sort();
  const acceptedSpecificationEntries = Object.entries(
    acceptedManifest?.specifications ?? {}
  ).sort();
  const expectedAcceptedSpecificationEntries = [
    ...baseSpecificationEntries,
    [FIXTURE_SPECIFICATION_ID, candidateRecord.contentHash],
  ].sort(([left], [right]) => left.localeCompare(right));
  const additionOnlyViolations =
    acceptedManifest === null
      ? ['experiment-not-comparable']
      : immutabilityViolations(
          baseManifest,
          acceptedManifest,
          unchangedManifestChangeCarriers(baseManifest)
        );

  const baseline = baselineRun(basePlan, baseManifest);
  const baselineObservation = observeRun(basePlan, baseManifest, baseline.run, baseline.target);
  const changedObservation =
    acceptedPlan === null || acceptedManifest === null
      ? null
      : observeRun(acceptedPlan, acceptedManifest, baseline.run, baseline.target);

  const predecessorsAfter = predecessorSnapshot(base);
  const guardedAfter = snapshotGuardedSurface(resolvedRoot);
  const realSurfaceUnchanged =
    guardedBefore.sha256 === guardedAfter.sha256 &&
    canonicalJson(guardedBefore.files) === canonicalJson(guardedAfter.files);

  const predicates = {
    exactSourceBoundaryClosed:
      exactSourceBoundaryClosed === true &&
      sourceExecutionClosed === true &&
      predecessorPlanReconstructed === true,
    candidateConformsProductSpecificationV1:
      candidateSchemaValid === true &&
      candidateSchemaErrors.length === 0 &&
      candidate.id === FIXTURE_SPECIFICATION_ID,
    candidateUsesProseCarrierAndSupersedesNull:
      candidate.supersedes === null &&
      `${candidate.scope} ${candidate.summary}`.includes('extends SPEC-0001') &&
      `${candidate.scope} ${candidate.summary}`.includes('references SPEC-0002') &&
      !Object.hasOwn(candidate, 'extends') &&
      !Object.hasOwn(candidate, 'references') &&
      compiledCandidate?.contentHash === candidateRecord.contentHash,
    candidateInternalReferencesAreClosed:
      internalReferencesAreClosed(candidate) && acceptedCompilation.error === null,
    transitionIsAtomicAcceptedAddition:
      candidate.status === 'accepted' &&
      acceptedProfileSchemaValid === true &&
      acceptedProfileSchemaErrors.length === 0 &&
      acceptedCompilation.error === null &&
      !baseManifest.specifications[FIXTURE_SPECIFICATION_ID],
    profileRetainsExactlyThreeSpecifications:
      sameStringSet(accepted.profile.specificationIds ?? [], EXPECTED_ACTIVE_SPECIFICATION_IDS) &&
      (accepted.profile.specificationIds ?? []).length === 3,
    allThreeAreAcceptedAndUnsuperceded: allThreeAccepted,
    predecessorBytesRemainIdentical:
      canonicalJson(predecessorsBefore) === canonicalJson(predecessorsAfter) &&
      BASE_SPECIFICATION_IDS.every(
        (id) => acceptedManifest?.specifications[id] === baseManifest.specifications[id]
      ),
    compiledPlanContainsThreeEffectiveAcceptedSpecifications:
      canonicalJson(planSpecificationIds) === canonicalJson(EXPECTED_ACTIVE_SPECIFICATION_IDS) &&
      allThreeAccepted,
    profileAndCorpusPermutationIsDeterministic:
      acceptedPlan !== null &&
      permutedPlan !== null &&
      acceptedManifest !== null &&
      permutedManifest !== null &&
      acceptedPlan.profileHash === permutedPlan.profileHash &&
      acceptedPlan.planHash === permutedPlan.planHash &&
      canonicalJson(acceptedPlan) === canonicalJson(permutedPlan) &&
      canonicalJson(acceptedManifest) === canonicalJson(permutedManifest),
    manifestDeltaIsAdditionOnlyAndContentBound:
      acceptedManifest !== null &&
      canonicalJson(acceptedSpecificationEntries) ===
        canonicalJson(expectedAcceptedSpecificationEntries) &&
      additionOnlyViolations.length === 0 &&
      canonicalJson(acceptedManifest.decisions) === canonicalJson(baseManifest.decisions) &&
      canonicalJson(acceptedManifest.changes) === canonicalJson(baseManifest.changes) &&
      canonicalJson(acceptedManifest.schemas) === canonicalJson(baseManifest.schemas) &&
      acceptedManifest.mechanismsHash === baseManifest.mechanismsHash &&
      acceptedManifest.specifications[FIXTURE_SPECIFICATION_ID] === candidateRecord.contentHash &&
      compiledCandidate?.contentHash === candidateRecord.contentHash &&
      acceptedManifest.profileHash === acceptedPlan?.profileHash &&
      acceptedManifest.planHash === acceptedPlan?.planHash,
    priorEvidenceBecomesStale:
      baselineObservation.state === 'current' &&
      changedObservation?.state === 'stale' &&
      changedObservation.reason ===
        'The run observed a different profileHash, planHash, or manifestHash.',
    noSpecificationOrImplementationAuthorityIsInferred:
      authority === 'none' && action === null && realSurfaceUnchanged,
  };

  const controls = {
    proposedToAcceptedRejectedByImmutability:
      canonicalJson(proposedTransitionViolations) ===
        canonicalJson([`specification:${FIXTURE_SPECIFICATION_ID}`]) &&
      activeProposedCompilation.error?.code === 'SPECIFICATION_INACTIVE',
    activeSetRemovalAdmittedByHost:
      removedActiveSetCompilation.error === null &&
      canonicalJson(removedActiveSetPlan?.specifications.map(({ id }) => id) ?? []) ===
        canonicalJson([FIXTURE_SPECIFICATION_ID]) &&
      removalViolations.length === 0,
    supersessionBreaksIndependentActiveSet:
      supersedingCompilation.error?.code === 'SPECIFICATION_INACTIVE' &&
      supersedingCompilation.error.message.includes(
        `${BASE_SPECIFICATION_IDS[0]} is superseded by ${FIXTURE_SPECIFICATION_ID}`
      ),
    typedRelationshipFieldsRejectedBySchema:
      typedRelationshipValid === false &&
      canonicalJson(typedAdditionalProperties) === canonicalJson(['extends', 'references']),
  };

  const predicateValues = PREDICATE_IDS.map((id) => predicates[id]);
  const controlValues = CONTROL_IDS.map((id) => controls[id]);
  const allPredicatesPass = predicateValues.every((value) => value === true);
  const allControlsPass = controlValues.every((value) => value === true);
  const witnessPreconditionsClosed =
    candidateSchemaValid === true &&
    candidateSchemaErrors.length === 0 &&
    acceptedProfileSchemaValid === true &&
    acceptedProfileSchemaErrors.length === 0 &&
    internalReferencesAreClosed(candidate) &&
    candidate.status === 'accepted' &&
    candidate.supersedes === null;
  const exactThreeAcceptedProduced =
    acceptedCompilation.error === null &&
    acceptedPlan !== null &&
    sameStringSet(planSpecificationIds, EXPECTED_ACTIVE_SPECIFICATION_IDS) &&
    planSpecificationIds.length === EXPECTED_ACTIVE_SPECIFICATION_IDS.length &&
    allThreeAccepted;
  const classification = classifyH053Outcome({
    descriptorBoundaryClosed: exactSourceBoundaryClosed,
    sourceExecutionClosed,
    authority,
    action,
    realSurfaceUnchanged,
    witnessPreconditionsClosed,
    acceptedCompilationRejected: acceptedCompilation.error !== null,
    exactThreeAcceptedProduced,
    allPredicatesPass,
    allControlsPass,
  });

  return {
    schemaVersion: 'overlaykit-h053-additive-specification-experiment/v1',
    hypothesis: 'H-053',
    fixture: {
      path: fixture.path,
      specification: candidate,
      contentHash: candidateRecord.contentHash,
      byteLength: candidateRecord.byteLength,
      nonNormative: true,
      persisted: false,
    },
    predicates,
    controls,
    evidence: {
      base: {
        predecessorManifestRawSha256: sha256(inputs.manifest.bytes),
        predecessorManifestContentHash: baseManifest.contentHash,
        predecessorManifestChangeCount: Object.keys(baseManifest.changes).length,
        predecessorManifestCarrier: 'recovered-local-pre-h053-manifest',
        nominatedPlanRawSha256: sha256(inputs.plan.bytes),
        predecessorPlanReconstructed,
        descriptorBoundaryClosed: exactSourceBoundaryClosed === true,
        sourceExecutionClosed: sourceExecutionClosed === true,
        profileHash: basePlan.profileHash,
        planHash: basePlan.planHash,
        manifestHash: baseManifest.contentHash,
        specificationEntries: baseSpecificationEntries,
      },
      candidateValidation: {
        specificationSchemaValid: candidateSchemaValid,
        specificationSchemaErrors: candidateSchemaErrors,
        acceptedProfileSchemaValid,
        acceptedProfileSchemaErrors,
      },
      accepted: {
        profileSpecificationIds: clone(accepted.profile.specificationIds),
        profileHash: acceptedPlan?.profileHash ?? null,
        planHash: acceptedPlan?.planHash ?? null,
        manifestHash: acceptedManifest?.contentHash ?? null,
        specificationEntries: acceptedSpecificationEntries,
        planSpecifications: acceptedPlan?.specifications ?? [],
        compilationError: acceptedCompilation.error,
      },
      permutation: {
        profileHash: permutedPlan?.profileHash ?? null,
        planHash: permutedPlan?.planHash ?? null,
        manifestHash: permutedManifest?.contentHash ?? null,
        compilationError: permutedCompilation.error,
      },
      manifestDelta: {
        base: manifestReceipt(baseManifest),
        accepted: manifestReceipt(acceptedManifest),
        additionOnlyViolations,
        expectedAddition: {
          id: FIXTURE_SPECIFICATION_ID,
          contentHash: candidateRecord.contentHash,
        },
      },
      controls: {
        proposedTransitionViolations,
        activeProposedCompilationError: activeProposedCompilation.error,
        activeSetRemoval: {
          compilationError: removedActiveSetCompilation.error,
          planSpecificationIds: removedActiveSetPlan?.specifications.map(({ id }) => id) ?? [],
          immutabilityViolations: removalViolations,
        },
        supersessionCompilationError: supersedingCompilation.error,
        typedRelationshipErrors,
      },
      predecessorBytes: predecessorsBefore,
      guardedSurface: {
        paths: [...GUARDED_PATHS],
        beforeHash: guardedBefore.sha256,
        afterHash: guardedAfter.sha256,
        unchanged: realSurfaceUnchanged,
      },
      priorEvidence: {
        baselineState: baselineObservation.state,
        changedState: changedObservation?.state ?? null,
        changedReason: changedObservation?.reason ?? null,
      },
    },
    outcome: {
      ...classification,
      authority,
      action,
    },
  };
}
