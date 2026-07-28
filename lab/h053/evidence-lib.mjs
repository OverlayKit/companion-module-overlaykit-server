import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  canonicalHash,
  canonicalJson,
  canonicalPrettyJson,
  sha256,
} from '../../tools/governance/src/canonical.ts';
import { CONTROL_IDS, PREDICATE_IDS, runH053Experiment } from './experiment-lib.mjs';
import { H053_SOURCE_CONSTANTS, inspectH053Sources } from './source-lock.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const CHG_0033_SHA256 = '7179de3ae940a9b959d441f42d04ece4158746f23362743dbe625dd9bbd92cc4';
const H052_CLOSURE_SHA256 = 'a59c69bc2607b0c4f8d6aab336761b48e0b6f19d251be151e6846c3daf71814f';
const PLAN_RAW_SHA256 = '2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243';
const PLAN_HASH = 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4';
const SPEC_0001_SHA256 = '917f1ca2febe17f8901ab71f91a0b0135402f9be972a876f233fcd5c789b8179';
const SPEC_0002_SHA256 = 'd15b1cbf7e97bd92aadf40342421161a0955e210b8566f7ae870dc78c05e89f6';
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

function assertion(condition, message) {
  if (!condition) {
    throw new Error(`H053_EVIDENCE_INVALID: ${message}`);
  }
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw new Error(`H053_EVIDENCE_INVALID: ${label} JSON is invalid: ${error.message}`);
  }
}

function fileBytes(relativePath) {
  return readFileSync(path.join(REPOSITORY_ROOT, relativePath));
}

function expectedSuccessorManifest(predecessor, changeId, changeHash) {
  const body = {
    schemaVersion: predecessor.schemaVersion,
    decisions: structuredClone(predecessor.decisions),
    specifications: structuredClone(predecessor.specifications),
    changes: {
      ...structuredClone(predecessor.changes),
      [changeId]: changeHash,
    },
    schemas: structuredClone(predecessor.schemas),
    profileHash: predecessor.profileHash,
    mechanismsHash: predecessor.mechanismsHash,
    planHash: predecessor.planHash,
  };
  return {
    ...body,
    contentHash: canonicalHash(body),
  };
}

export function verifyRealManifestAddition(sourceReceipt) {
  const predecessorBytes = sourceReceipt.localSourceBytesByPath.get(
    '.overlaykit/governance/manifest.json'
  );
  assertion(predecessorBytes !== undefined, 'pre-H-053 manifest is absent from source receipt');
  const predecessor = parseJson(predecessorBytes, 'pre-H-053 manifest');
  const changePath = '.overlaykit/governance/changes/CHG-0034.json';
  const changeBytes = fileBytes(changePath);
  const change = parseJson(changeBytes, 'CHG-0034');
  assertion(change.id === 'CHG-0034' && change.status === 'proposed', 'CHG-0034 lifecycle differs');
  const currentPath = '.overlaykit/governance/manifest.json';
  const currentBytes = fileBytes(currentPath);
  const current = parseJson(currentBytes, 'current manifest');
  const expected = expectedSuccessorManifest(predecessor, change.id, sha256(changeBytes));
  assertion(
    canonicalJson(current) === canonicalJson(expected),
    'real manifest transition is not CHG-0034 addition-only'
  );
  const changedTopLevelKeys = Object.keys(current)
    .filter((key) => canonicalJson(current[key]) !== canonicalJson(predecessor[key]))
    .sort();
  const predecessorChangeIds = Object.keys(predecessor.changes).sort();
  const currentChangeIds = Object.keys(current.changes).sort();
  assertion(
    canonicalJson(changedTopLevelKeys) === canonicalJson(['changes', 'contentHash']),
    'unexpected real manifest top-level delta'
  );
  assertion(
    canonicalJson(currentChangeIds) === canonicalJson([...predecessorChangeIds, 'CHG-0034'].sort()),
    'unexpected real manifest change roster'
  );
  return {
    predecessorRawSha256: sha256(predecessorBytes),
    currentRawSha256: sha256(currentBytes),
    predecessorContentHash: predecessor.contentHash,
    currentContentHash: current.contentHash,
    addedChange: {
      id: change.id,
      rawSha256: sha256(changeBytes),
      status: change.status,
    },
    changedTopLevelKeys,
    predecessorChangeCount: predecessorChangeIds.length,
    currentChangeCount: currentChangeIds.length,
    additionOnly: true,
  };
}

function preservationReceipt() {
  const paths = {
    chg0033: '.overlaykit/governance/changes/CHG-0033.json',
    h052Closure:
      'artifacts/h052/post-review-closures/7179de3ae940a9b959d441f42d04ece4158746f23362743dbe625dd9bbd92cc4/closure.json',
    plan: '.overlaykit/governance/plan.json',
    spec0001: '.overlaykit/governance/specifications/SPEC-0001.json',
    spec0002: '.overlaykit/governance/specifications/SPEC-0002.json',
  };
  const values = Object.fromEntries(
    Object.entries(paths).map(([id, sourcePath]) => {
      const bytes = fileBytes(sourcePath);
      return [id, { path: sourcePath, byteLength: bytes.length, sha256: sha256(bytes) }];
    })
  );
  assertion(values.chg0033.sha256 === CHG_0033_SHA256, 'CHG-0033 bytes drifted');
  assertion(values.h052Closure.sha256 === H052_CLOSURE_SHA256, 'H-052 closure bytes drifted');
  assertion(values.plan.sha256 === PLAN_RAW_SHA256, 'compiled plan bytes drifted');
  assertion(values.spec0001.sha256 === SPEC_0001_SHA256, 'SPEC-0001 bytes drifted');
  assertion(values.spec0002.sha256 === SPEC_0002_SHA256, 'SPEC-0002 bytes drifted');
  return values;
}

function apparatusReceipt() {
  const files = APPARATUS_PATHS.map((sourcePath) => {
    const bytes = fileBytes(sourcePath);
    return {
      path: sourcePath,
      byteLength: bytes.length,
      sha256: sha256(bytes),
    };
  });
  return {
    fileCount: files.length,
    files,
    descriptorSetSha256: canonicalHash(files),
    admittedAsSubjectSources: false,
    role: 'content-addressed experimental apparatus only',
  };
}

function environmentReceipt() {
  const packagePaths = ['node_modules/ajv/package.json', 'node_modules/tsx/package.json'];
  const packages = packagePaths.map((sourcePath) => {
    const bytes = fileBytes(sourcePath);
    const packageManifest = parseJson(bytes, sourcePath);
    return {
      name: packageManifest.name,
      version: packageManifest.version,
      packageManifestByteLength: bytes.length,
      packageManifestSha256: sha256(bytes),
    };
  });
  return {
    closed: false,
    classification: 'partially-content-addressed-apparatus-environment',
    node: {
      version: process.version,
      platform: process.platform,
      architecture: process.arch,
      executableContentSha256: null,
    },
    packages,
    packageDescriptorSetSha256: canonicalHash(packages),
    unknowns: [
      'Node executable bytes and transitive runtime dependencies are outside the nominated subject.',
      'No process-level capability allowlist or syscall trace was produced.',
      'Package-manifest hashes do not close installed package contents.',
    ],
  };
}

function controlClassifications(experiment) {
  return CONTROL_IDS.map((id) => {
    if (id === 'activeSetRemovalAdmittedByHost') {
      return {
        id,
        passed: experiment.controls[id] === true,
        classification: experiment.controls[id] === true ? 'gap-observed' : 'inconclusive',
        interpretation:
          'The current host admits a profile that removes unsuperseded predecessors; this does not refute the exact retained-set witness and does not prove a desired policy.',
      };
    }
    return {
      id,
      passed: experiment.controls[id] === true,
      classification:
        experiment.controls[id] === true ? 'expected-behavior-observed' : 'inconclusive',
      interpretation:
        id === 'proposedToAcceptedRejectedByImmutability'
          ? 'A persisted proposed specification cannot be mutated in place to accepted.'
          : id === 'supersessionBreaksIndependentActiveSet'
            ? 'Using supersedes cannot preserve all three specifications as independently active.'
            : 'ProductSpecification/v1 rejects undeclared typed extends and references fields.',
    };
  });
}

export function buildH053Evidence() {
  const sources = inspectH053Sources();
  const realManifestTransition = verifyRealManifestAddition(sources);
  const preservation = preservationReceipt();
  const apparatus = apparatusReceipt();
  const environment = environmentReceipt();
  const temporalSourceBytesByPath = new Map([
    ...sources.gitSourceBytesByPath,
    ...sources.localSourceBytesByPath,
  ]);
  const experiment = runH053Experiment({
    repoRoot: REPOSITORY_ROOT,
    sourceBytesByPath: temporalSourceBytesByPath,
    exactSourceBoundaryClosed:
      sources.combinedSourceSetSha256 === H053_SOURCE_CONSTANTS.combinedSourceSetSha256,
    sourceExecutionClosed: sources.sourceExecutionClosure.closed,
    authority: 'none',
    action: null,
  });
  assertion(
    experiment.evidence.base.planHash === PLAN_HASH,
    'the executed worktree does not compile the nominated predecessor plan'
  );
  const predicateReceipts = PREDICATE_IDS.map((id) => ({
    id,
    passed: experiment.predicates[id] === true,
  }));
  const controls = controlClassifications(experiment);
  const passedPredicateCount = predicateReceipts.filter(({ passed }) => passed).length;
  const passedControlCount = controls.filter(({ passed }) => passed).length;

  const body = {
    schemaVersion: 'overlaykit-h053-additive-admission-run/v1',
    hypothesis: 'H-053',
    normative: false,
    subject: {
      combinedSourceSetSha256: sources.combinedSourceSetSha256,
      subjectLockRawSha256: sources.subjectLockRawSha256,
      gitSourceCount: sources.gitSourceCount,
      localSourceCount: sources.localSourceCount,
      totalTemporalSourceCount: sources.totalSourceCount,
      gitSourceSetSha256: sources.gitSourceSetSha256,
      localSourceSetSha256: sources.localSourceSetSha256,
      restrictedLsTreeSha256: sources.restrictedLsTreeSha256,
      recoveredPreH053ManifestSha256: sources.recoveredPreH053ManifestSha256,
      executedWorktreeSourceCount: sources.executedWorktreeBindings.length,
      executedWorktreeBindingsSha256: sources.executedWorktreeBindingsSha256,
      sourceExecutionClosure: sources.sourceExecutionClosure,
    },
    realManifestTransition,
    apparatus,
    environment,
    experiment,
    predicateReceipts,
    controlReceipts: controls,
    interpretation: {
      outcome: {
        status: experiment.outcome.status,
        stage: 'pre-review-offline-current-host-admission',
        reasonCode: experiment.outcome.reason,
        claimBoundary:
          'no H-053 support or refutation: the d257 descriptor reconstructs, but errors.ts executes outside that nominated boundary; dynamic subresults remain observations and inferences only',
      },
      adrAssessment: {
        candidateNominated: false,
        candidateActivated: false,
        candidateRecordCreated: false,
        candidateQuestion:
          'Should active specification membership be monotonic so an additive activation cannot silently remove an unsuperseded predecessor?',
        basis:
          'The active-set-removal subresult is only an observation inside an inconclusive experiment and cannot nominate an ADR candidate.',
        requiredNextGate:
          'close and renominate the executed source boundary before any separate human ADR-candidacy review',
      },
      subresults: {
        classification: 'observations-and-inferences-only',
        passedPredicateCount,
        totalPredicateCount: predicateReceipts.length,
        passedControlCount,
        totalControlCount: controls.length,
        supportClaimed: false,
        refutationClaimed: false,
      },
      humanReview: {
        required: true,
        accepted: null,
      },
      doesNotDemonstrate: [
        'normative specification content or a real specification identity',
        'a universal monotonic active-set guarantee',
        'implementation feasibility or product behavior',
        'live, USB, hidraw, Docker, process, service, network, security, compliance, drift, or production policy',
      ],
    },
    preservation,
    capabilityAudit: {
      closed: false,
      classification: 'static-apparatus-and-observed-delta-only',
      observed: {
        fixtureWritesOutsideLab: false,
        rawEvidenceWriteAuthorized: true,
        networkActivity: false,
        liveObservation: false,
        usbOrHidrawActivity: false,
        dockerActivity: false,
        signalsOrServicesActivity: false,
        realSpecificationMutation: false,
        profileSchemaCompilerPlanOrProductMutation: false,
        adrCreated: false,
        gitIndexOrHistoryMutation: false,
        publication: false,
      },
      unknowns: [
        'No syscall trace or sandbox-enforced capability allowlist closes process behavior.',
        'Absence fields are apparatus observations, not universal host-activity claims.',
      ],
    },
    authority: 'none',
    action: null,
  };
  const semanticSha256 = canonicalHash(body);
  return {
    runId: `h053-${semanticSha256.slice(0, 24)}`,
    semanticSha256,
    ...body,
  };
}

export function encodeH053Evidence(run) {
  return Buffer.from(canonicalPrettyJson(run), 'utf8');
}

export const H053_EVIDENCE_PATHS = Object.freeze({
  repositoryRoot: REPOSITORY_ROOT,
  labDirectory: LAB_DIRECTORY,
});
