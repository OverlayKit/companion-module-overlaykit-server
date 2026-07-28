import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { canonicalHash, canonicalJson } from '../../tools/governance/src/canonical.ts';
import { buildH053Evidence, encodeH053Evidence } from './evidence-lib.mjs';
import { validateH053RunIdentity } from './run.mjs';
import {
  H053_OUTCOME_REASONS,
  InvalidH053EvidenceError,
  classifyH053Outcome,
  verifyH053EvidenceBytes,
  verifyH053EvidenceFile,
  verifyH053EvidenceSafe,
  verifyH053EvidenceStructure,
} from './verify.mjs';

function clone(value) {
  return structuredClone(value);
}

function assertReason(reasonCode) {
  return (error) => {
    assert.ok(error instanceof InvalidH053EvidenceError);
    assert.equal(error.reasonCode, reasonCode);
    return true;
  };
}

function rehash(run) {
  const { runId: _runId, semanticSha256: _semanticSha256, ...body } = run;
  run.semanticSha256 = canonicalHash(body);
  run.runId = `h053-${run.semanticSha256.slice(0, 24)}`;
  return run;
}

function setPredicate(run, id, passed) {
  run.experiment.predicates[id] = passed;
  run.predicateReceipts.find((receipt) => receipt.id === id).passed = passed;
}

function setOutcome(run, status, reason) {
  run.experiment.outcome.status = status;
  run.experiment.outcome.reason = reason;
  run.interpretation.outcome.status = status;
  run.interpretation.outcome.reasonCode = reason;
  run.interpretation.subresults.passedPredicateCount = run.predicateReceipts.filter(
    ({ passed }) => passed
  ).length;
  run.interpretation.subresults.totalPredicateCount = run.predicateReceipts.length;
  run.interpretation.subresults.passedControlCount = run.controlReceipts.filter(
    ({ passed }) => passed
  ).length;
  run.interpretation.subresults.totalControlCount = run.controlReceipts.length;
  run.interpretation.subresults.supportClaimed = status === 'supported';
  run.interpretation.subresults.refutationClaimed = status === 'refuted';
}

let cachedRun;
function canonicalRun() {
  cachedRun ??= buildH053Evidence();
  return cachedRun;
}

test('producer remains deterministic and canonical H-053 is inconclusive at 12/13 and 4/4', () => {
  const first = canonicalRun();
  const second = buildH053Evidence();
  assert.equal(canonicalJson(first), canonicalJson(second));
  assert.equal(first.interpretation.outcome.status, 'inconclusive');
  assert.equal(first.interpretation.outcome.reasonCode, H053_OUTCOME_REASONS.sourceExecution);
  assert.equal(first.interpretation.subresults.passedPredicateCount, 12);
  assert.equal(first.interpretation.subresults.passedControlCount, 4);
  assert.equal(first.interpretation.adrAssessment.candidateNominated, false);
  assert.equal(first.authority, 'none');
  assert.equal(first.action, null);
});

test('verifier is independent from the producer and classifies canonical evidence', () => {
  const verifierSource = readFileSync(new URL('./verify.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(verifierSource, /\bbuildH053Evidence\b/u);
  assert.doesNotMatch(verifierSource, /from\s+['"]\.\/evidence-lib\.mjs['"]/u);

  const receipt = verifyH053EvidenceBytes(encodeH053Evidence(canonicalRun()));
  assert.equal(receipt.verified, true);
  assert.equal(receipt.independentOracleVerified, true);
  assert.equal(receipt.producerReconstructionUsed, false);
  assert.equal(receipt.deterministicReconstructionVerified, false);
  assert.equal(receipt.currentApparatusVerified, true);
  assert.equal(receipt.passedPredicateCount, 12);
  assert.equal(receipt.passedControlCount, 4);
  assert.equal(receipt.outcome.status, 'inconclusive');
  assert.equal(receipt.sourceClosure.descriptorClosed, true);
  assert.equal(receipt.sourceClosure.executionClosed, false);
  assert.equal(receipt.capabilityAssessment.observedNonUseOnly, true);
  assert.equal(receipt.capabilityAssessment.sandboxEnforcementProven, false);
});

test('canonical source-execution omission prevents support and ADR nomination', () => {
  const run = canonicalRun();
  assert.equal(run.subject.sourceExecutionClosure.closed, false);
  assert.deepEqual(
    run.subject.sourceExecutionClosure.unadmittedDependencies.map(
      ({ path: sourcePath }) => sourcePath
    ),
    ['tools/governance/src/errors.ts']
  );
  assert.equal(run.experiment.predicates.exactSourceBoundaryClosed, false);
  assert.equal(run.interpretation.outcome.status, 'inconclusive');
  assert.equal(run.interpretation.adrAssessment.candidateNominated, false);
});

test('pure CHG-0034 polarity oracle implements invalid, refuted, inconclusive, and supported', () => {
  const supported = {
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
  assert.deepEqual(classifyH053Outcome(supported), {
    status: 'supported',
    reason: H053_OUTCOME_REASONS.supported,
  });
  assert.deepEqual(classifyH053Outcome({ ...supported, authority: 'specification' }), {
    status: 'invalid',
    reason: H053_OUTCOME_REASONS.invalidAuthority,
  });
  assert.deepEqual(classifyH053Outcome({ ...supported, realSurfaceUnchanged: false }), {
    status: 'invalid',
    reason: H053_OUTCOME_REASONS.invalidMutation,
  });
  assert.deepEqual(classifyH053Outcome({ ...supported, descriptorBoundaryClosed: false }), {
    status: 'inconclusive',
    reason: H053_OUTCOME_REASONS.sourceDescriptor,
  });
  assert.deepEqual(classifyH053Outcome({ ...supported, sourceExecutionClosed: false }), {
    status: 'inconclusive',
    reason: H053_OUTCOME_REASONS.sourceExecution,
  });
  assert.deepEqual(classifyH053Outcome({ ...supported, acceptedCompilationRejected: true }), {
    status: 'refuted',
    reason: H053_OUTCOME_REASONS.atomicRefutation,
  });
  assert.deepEqual(classifyH053Outcome({ ...supported, exactThreeAcceptedProduced: false }), {
    status: 'refuted',
    reason: H053_OUTCOME_REASONS.threeSpecRefutation,
  });
  assert.deepEqual(classifyH053Outcome({ ...supported, allControlsPass: false }), {
    status: 'inconclusive',
    reason: H053_OUTCOME_REASONS.control,
  });
});

test('d257 verifier rejects any rehashed attempt to hide known open closures', () => {
  const sourcePromotion = clone(canonicalRun());
  sourcePromotion.subject.sourceExecutionClosure.closed = true;
  sourcePromotion.subject.sourceExecutionClosure.classification = 'complete';
  sourcePromotion.experiment.evidence.base.sourceExecutionClosed = true;
  setPredicate(sourcePromotion, 'exactSourceBoundaryClosed', true);
  setOutcome(sourcePromotion, 'supported', H053_OUTCOME_REASONS.supported);
  assert.throws(
    () => verifyH053EvidenceStructure(rehash(sourcePromotion)),
    assertReason('source-execution-receipt-drift')
  );

  const environmentPromotion = clone(canonicalRun());
  environmentPromotion.environment.closed = true;
  assert.throws(
    () => verifyH053EvidenceStructure(rehash(environmentPromotion)),
    assertReason('environment-closure-overclaim')
  );

  const capabilityPromotion = clone(canonicalRun());
  capabilityPromotion.capabilityAudit.closed = true;
  assert.throws(
    () => verifyH053EvidenceStructure(rehash(capabilityPromotion)),
    assertReason('capability-closure-overclaim')
  );
});

test('predicate and control booleans cannot override independently reconstructed receipts', () => {
  const predicateLie = clone(canonicalRun());
  setPredicate(predicateLie, 'priorEvidenceBecomesStale', false);
  setOutcome(predicateLie, 'inconclusive', H053_OUTCOME_REASONS.sourceExecution);
  assert.throws(
    () => verifyH053EvidenceStructure(rehash(predicateLie)),
    assertReason('predicate-reconstruction-drift')
  );

  const predicateEvidenceDrift = clone(canonicalRun());
  predicateEvidenceDrift.experiment.evidence.priorEvidence.changedState = 'current';
  assert.throws(
    () => verifyH053EvidenceStructure(rehash(predicateEvidenceDrift)),
    assertReason('predicate-reconstruction-drift')
  );

  const controlEvidenceDrift = clone(canonicalRun());
  controlEvidenceDrift.experiment.evidence.controls.typedRelationshipErrors = [];
  assert.throws(
    () => verifyH053EvidenceStructure(rehash(controlEvidenceDrift)),
    assertReason('control-reconstruction-drift')
  );
});

test('fixture, manifest, claim boundary, and non-demonstrations are content-bound', () => {
  const fixtureDrift = clone(canonicalRun());
  fixtureDrift.experiment.fixture.specification.summary = 'Normative product requirement';
  assert.throws(
    () => verifyH053EvidenceStructure(rehash(fixtureDrift)),
    assertReason('fixture-content-drift')
  );

  const manifestDrift = clone(canonicalRun());
  manifestDrift.experiment.evidence.manifestDelta.accepted.decisions['ADR-0001'] = '0'.repeat(64);
  assert.throws(
    () => verifyH053EvidenceStructure(rehash(manifestDrift)),
    assertReason('predicate-reconstruction-drift')
  );

  const claimDrift = clone(canonicalRun());
  claimDrift.interpretation.outcome.claimBoundary = 'H-053 creates production policy.';
  assert.throws(
    () => verifyH053EvidenceStructure(rehash(claimDrift)),
    assertReason('review-boundary-drift')
  );

  const limitsDrift = clone(canonicalRun());
  limitsDrift.interpretation.doesNotDemonstrate = [];
  assert.throws(
    () => verifyH053EvidenceStructure(rehash(limitsDrift)),
    assertReason('review-boundary-drift')
  );
});

test('missing controls and predicates fail closed instead of changing polarity', () => {
  const missingControl = clone(canonicalRun());
  missingControl.controlReceipts.pop();
  delete missingControl.experiment.controls.typedRelationshipFieldsRejectedBySchema;
  assert.throws(
    () => verifyH053EvidenceStructure(rehash(missingControl)),
    assertReason('control-roster-drift')
  );

  const missingPredicate = clone(canonicalRun());
  missingPredicate.predicateReceipts.pop();
  delete missingPredicate.experiment.predicates.noSpecificationOrImplementationAuthorityIsInferred;
  assert.throws(
    () => verifyH053EvidenceStructure(rehash(missingPredicate)),
    assertReason('predicate-roster-drift')
  );
});

test('authority overclaim and prohibited activity are admitted only as invalid evidence', () => {
  const authorityOverclaim = clone(canonicalRun());
  authorityOverclaim.authority = 'specification';
  authorityOverclaim.experiment.outcome.authority = 'specification';
  setPredicate(authorityOverclaim, 'noSpecificationOrImplementationAuthorityIsInferred', false);
  setOutcome(authorityOverclaim, 'invalid', H053_OUTCOME_REASONS.invalidAuthority);
  const authorityReceipt = verifyH053EvidenceStructure(rehash(authorityOverclaim));
  assert.equal(authorityReceipt.outcome.status, 'invalid');
  assert.equal(authorityReceipt.authority, 'none');
  assert.equal(authorityReceipt.action, null);

  const networkActivity = clone(canonicalRun());
  networkActivity.capabilityAudit.observed.networkActivity = true;
  setOutcome(networkActivity, 'invalid', H053_OUTCOME_REASONS.invalidMutation);
  const activityReceipt = verifyH053EvidenceStructure(rehash(networkActivity));
  assert.equal(activityReceipt.outcome.status, 'invalid');
  assert.equal(activityReceipt.capabilityAssessment.sandboxEnforcementProven, false);
});

test('self-approval and ADR activation are admitted only with invalid polarity', () => {
  const run = clone(canonicalRun());
  run.interpretation.humanReview.accepted = 'self';
  run.interpretation.adrAssessment.candidateNominated = true;
  run.interpretation.adrAssessment.candidateActivated = true;
  setOutcome(run, 'invalid', H053_OUTCOME_REASONS.invalidSelfApproval);
  const receipt = verifyH053EvidenceStructure(rehash(run));
  assert.equal(receipt.outcome.status, 'invalid');
  assert.equal(receipt.authority, 'none');
  assert.equal(receipt.action, null);
});

test('semantic tampering and a concealed outcome polarity are rejected', () => {
  const tampered = clone(canonicalRun());
  tampered.interpretation.outcome.status = 'refuted';
  assert.throws(() => verifyH053EvidenceStructure(tampered), assertReason('semantic-hash-invalid'));

  const concealed = clone(canonicalRun());
  setOutcome(concealed, 'supported', H053_OUTCOME_REASONS.supported);
  assert.throws(
    () => verifyH053EvidenceStructure(rehash(concealed)),
    assertReason('outcome-polarity-drift')
  );
});

test('safe verification rejects malformed evidence without creating authority', () => {
  const result = verifyH053EvidenceSafe(Buffer.from('{"not":"a run"}\n'), { rebuild: false });
  assert.equal(result.verified, false);
  assert.equal(result.reasonCode, 'run-shape-invalid');
  assert.equal(result.authority, 'none');
  assert.equal(result.action, null);
});

test('writer validates semantic identity and safe envelope before path construction', () => {
  assert.equal(validateH053RunIdentity(canonicalRun()), canonicalRun().semanticSha256);

  const traversalHash = clone(canonicalRun());
  traversalHash.semanticSha256 = '../escape';
  assert.throws(() => validateH053RunIdentity(traversalHash), /semantic SHA-256 is malformed/u);

  const authorityOverclaim = clone(canonicalRun());
  authorityOverclaim.authority = 'specification';
  setOutcome(authorityOverclaim, 'invalid', H053_OUTCOME_REASONS.invalidAuthority);
  rehash(authorityOverclaim);
  assert.throws(() => validateH053RunIdentity(authorityOverclaim), /creates authority/u);

  const forgedSupport = clone(canonicalRun());
  forgedSupport.subject.sourceExecutionClosure.closed = true;
  forgedSupport.subject.sourceExecutionClosure.classification = 'complete';
  setOutcome(forgedSupport, 'supported', H053_OUTCOME_REASONS.supported);
  rehash(forgedSupport);
  assert.throws(() => validateH053RunIdentity(forgedSupport), /immutable d257/u);
});

test('file verifier accepts only the recomputed content-addressed path', (t) => {
  const repositoryRoot = mkdtempSync(path.join(tmpdir(), 'h053-verify-'));
  t.after(() => rmSync(repositoryRoot, { recursive: true, force: true }));
  const run = canonicalRun();
  const runsRoot = path.join(repositoryRoot, 'artifacts', 'h053', 'runs');
  const runDirectory = path.join(runsRoot, run.semanticSha256);
  mkdirSync(runDirectory, { recursive: true, mode: 0o700 });
  const runPath = path.join(runDirectory, 'run.json');
  writeFileSync(runPath, encodeH053Evidence(run), { mode: 0o600 });

  const receipt = verifyH053EvidenceFile(path.relative(repositoryRoot, runPath), {
    repositoryRoot,
    rebuild: false,
  });
  assert.equal(receipt.semanticSha256, run.semanticSha256);

  const wrongDirectory = path.join(runsRoot, '0'.repeat(64));
  mkdirSync(wrongDirectory, { mode: 0o700 });
  const wrongPath = path.join(wrongDirectory, 'run.json');
  writeFileSync(wrongPath, encodeH053Evidence(run), { mode: 0o600 });
  assert.throws(
    () =>
      verifyH053EvidenceFile(path.relative(repositoryRoot, wrongPath), {
        repositoryRoot,
        rebuild: false,
      }),
    assertReason('run-content-address-mismatch')
  );
});

test('file verifier rejects explicit traversal, lexical escape, and symlink ancestors', (t) => {
  const repositoryRoot = mkdtempSync(path.join(tmpdir(), 'h053-path-'));
  t.after(() => rmSync(repositoryRoot, { recursive: true, force: true }));
  const runsRoot = path.join(repositoryRoot, 'artifacts', 'h053', 'runs');
  const outsideRoot = path.join(repositoryRoot, 'outside');
  mkdirSync(runsRoot, { recursive: true, mode: 0o700 });
  mkdirSync(outsideRoot, { mode: 0o700 });

  assert.throws(
    () =>
      verifyH053EvidenceFile('artifacts/h053/runs/../escape/run.json', {
        repositoryRoot,
        rebuild: false,
      }),
    assertReason('run-path-traversal')
  );
  assert.throws(
    () =>
      verifyH053EvidenceFile(path.join(outsideRoot, 'run.json'), {
        repositoryRoot,
        rebuild: false,
      }),
    assertReason('run-path-invalid')
  );

  const run = canonicalRun();
  const outsideRunDirectory = path.join(outsideRoot, run.semanticSha256);
  mkdirSync(outsideRunDirectory, { mode: 0o700 });
  writeFileSync(path.join(outsideRunDirectory, 'run.json'), encodeH053Evidence(run), {
    mode: 0o600,
  });
  symlinkSync(outsideRunDirectory, path.join(runsRoot, run.semanticSha256), 'dir');
  assert.throws(
    () =>
      verifyH053EvidenceFile(
        path.join('artifacts', 'h053', 'runs', run.semanticSha256, 'run.json'),
        { repositoryRoot, rebuild: false }
      ),
    assertReason('run-path-symlink')
  );
});
