import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  H051_PREDICATES,
  InvalidH051EvidenceError,
  inspectH051Sources,
  resolveJsonPointer,
  sha256,
  validateH051Schemas,
  verifyDocketStructure,
  verifyH051,
  verifyH051Safe,
  verifyReadinessMapStructure,
  verifySubjectLockStructure,
} from './verify.mjs';

const subjectLockBytes = readFileSync(new URL('./subject-lock.json', import.meta.url));
const precontractBytes = readFileSync(
  new URL('../../.overlaykit/governance/changes/CHG-0031.json', import.meta.url)
);
const docketBytes = readFileSync(new URL('./specification-readiness-docket.json', import.meta.url));
const readinessMapBytes = readFileSync(new URL('./readiness-map.json', import.meta.url));
const subjectLock = JSON.parse(subjectLockBytes);
const docket = JSON.parse(docketBytes);
const readinessMap = JSON.parse(readinessMapBytes);

function clone(value) {
  return structuredClone(value);
}

function assertReason(reasonCode) {
  return (error) => {
    assert.ok(error instanceof InvalidH051EvidenceError);
    assert.equal(error.reasonCode, reasonCode);
    return true;
  };
}

let cachedSources;
function inspectedSources() {
  cachedSources ??= inspectH051Sources(subjectLock);
  return cachedSources;
}

test('exact H-051 evidence closes structurally and remains semantically inconclusive', () => {
  const result = verifyH051();
  assert.equal(result.structuralIntegrityVerified, true);
  assert.equal(result.structuralReconstructionVerified, true);
  assert.equal(result.semanticClassificationsAccepted, false);
  assert.deepEqual(result.outcome, {
    status: 'inconclusive',
    stage: 'pre-review-specification-readiness',
    reasonCode: 'relationship-carrier-ambiguous-and-schema-compiler-pending',
    claimBoundary:
      'exact source and abstract-slot structure only; semantic mappings remain agent-proposed pending human acceptance',
  });
  assert.equal(result.sourceClosure.gitSourceCount, 18);
  assert.equal(result.sourceClosure.localSourceCount, 8);
  assert.equal(result.sourceClosure.totalSourceCount, 26);
  assert.equal(result.traceability.mappingCount, 9);
  assert.equal(result.traceability.predicateReceiptCount, 11);
  assert.equal(result.traceability.abstractSlotCount, 41);
  assert.equal(result.traceability.citationCount, 19);
  assert.equal(result.traceability.structurallySatisfiedPredicateCount, 9);
  assert.equal(result.traceability.ambiguousPredicateCount, 1);
  assert.equal(result.traceability.unresolvedPredicateCount, 1);
  assert.equal(result.adrAssessment.candidateActivated, false);
  assert.equal(result.authority, 'none');
  assert.equal(result.action, null);
});

test('all three strict schemas admit only the current artifact shapes', () => {
  assert.equal(
    validateH051Schemas({
      subjectLock,
      docket,
      readinessMap,
    }),
    true
  );
  const overclaim = clone(readinessMap);
  overclaim.specificationDraft = {};
  assert.throws(
    () =>
      validateH051Schemas({
        subjectLock,
        docket,
        readinessMap: overclaim,
      }),
    assertReason('schema-validation-failed')
  );
});

test('the two-layer source lock is exact, non-circular, and role-complete', () => {
  const receipt = verifySubjectLockStructure(subjectLock);
  assert.deepEqual(receipt, {
    gitSourceCount: 18,
    localSourceCount: 8,
    totalSourceCount: 26,
    combinedSourceSetSha256: '6d54e3ca53b02dc31495f3d1e2cdd965f48f04b24f1460e7a5149267c8921317',
  });
  assert.equal(
    subjectLock.gitSources.some(({ path }) => path === '.overlaykit/governance/manifest.json'),
    true
  );
  assert.equal(
    [...subjectLock.gitSources, ...subjectLock.localSources].some(
      ({ path }) =>
        path === '.overlaykit/governance/changes/CHG-0031.json' || path.startsWith('lab/h051/')
    ),
    false
  );
});

test('Git blobs and unsigned local predecessor bytes reconstruct all 26 sources', () => {
  const receipt = inspectedSources();
  assert.equal(receipt.sourceCount, 26);
  assert.equal(
    receipt.restrictedLsTreeSha256,
    'ba367b8da57e42b985fc6a1bcfe41f2f947f4e33f253f6ef8621588f94d2b3bd'
  );
  assert.equal(
    sha256(receipt.sourceBytesByPath.get('lab/h050/canonical-candidate-motion.json')),
    '20aa95c65dd0fb05bc21d7d98e7ba839895de5ded959b781db9d32893e1e1e28'
  );
  assert.equal(
    sha256(
      receipt.sourceBytesByPath.get(
        'artifacts/h050/post-review-closures/20aa95c65dd0fb05bc21d7d98e7ba839895de5ded959b781db9d32893e1e1e28/closure.json'
      )
    ),
    '2fe8d261ac60594ca4700002758af23b2a8455bc2152bbc19475ce54611f7d1e'
  );
});

test('all mappings use admitted sources, resolvable pointers, and the finite slot universe', () => {
  const receipt = verifyReadinessMapStructure(readinessMap, {
    lock: subjectLock,
    sourceBytesByPath: inspectedSources().sourceBytesByPath,
  });
  assert.equal(receipt.mappingCount, 9);
  assert.equal(receipt.predicateReceiptCount, 11);
  assert.equal(receipt.citationCount, 19);
  assert.equal(receipt.abstractSlotCount, 41);
  assert.deepEqual(
    readinessMap.predicateReceipts.map(({ id }) => id),
    H051_PREDICATES
  );
  assert.equal(
    resolveJsonPointer(
      JSON.parse(
        inspectedSources().sourceBytesByPath.get('lab/h050/canonical-candidate-motion.json')
      ),
      '/predicateDecisions/8/id'
    ),
    'specificationRelationship'
  );
});

test('the docket binds the repeated short grant to H-050 then H-051 context', () => {
  assert.equal(
    verifyDocketStructure(docket, {
      precontractRawSha256: sha256(precontractBytes),
      predecessorChangeRawSha256: sha256(
        inspectedSources().sourceBytesByPath.get('.overlaykit/governance/changes/CHG-0030.json')
      ),
      sourceLockRawSha256: sha256(subjectLockBytes),
      readinessMapRawSha256: sha256(readinessMapBytes),
    }),
    true
  );
  assert.equal(docket.authorizationContext.modelVisibleReply.transportBytesClaimed, false);
  assert.equal(docket.authorizationContext.successorHypothesis, 'H-051');
  assert.equal(docket.authorizationContext.successorChange, 'CHG-0031');
  assert.equal(docket.subject.precontractRawSha256, sha256(precontractBytes));
  assert.equal(docket.preReviewResult.humanAcceptance, null);
});

test('precontract and predecessor-change substitutions fail closed', () => {
  const precontractResult = verifyH051Safe({
    artifactOverrides: {
      precontract: Buffer.concat([precontractBytes, Buffer.from('\n')]),
    },
  });
  assert.equal(precontractResult.structuralIntegrityVerified, false);
  assert.equal(precontractResult.outcome.reasonCode, 'precontract-raw-drift');

  const predecessorPath = '.overlaykit/governance/changes/CHG-0030.json';
  const predecessorBytes = inspectedSources().sourceBytesByPath.get(predecessorPath);
  const predecessorResult = verifyH051Safe({
    localOverrides: new Map([
      [predecessorPath, Buffer.concat([predecessorBytes, Buffer.from('\n')])],
    ]),
  });
  assert.equal(predecessorResult.structuralIntegrityVerified, false);
  assert.equal(predecessorResult.outcome.reasonCode, 'local-source-byte-drift');

  const reboundDocket = clone(docket);
  reboundDocket.authorizationContext.predecessorChangeRawSha256 = '0'.repeat(64);
  assert.throws(
    () =>
      verifyDocketStructure(reboundDocket, {
        precontractRawSha256: sha256(precontractBytes),
        predecessorChangeRawSha256: sha256(predecessorBytes),
        sourceLockRawSha256: sha256(subjectLockBytes),
        readinessMapRawSha256: sha256(readinessMapBytes),
      }),
    assertReason('predecessor-change-binding-drift')
  );
});

test('local predecessor byte drift fails closed without touching the workspace', () => {
  const sourcePath = 'lab/h050/canonical-candidate-motion.json';
  const original = readFileSync(
    new URL('../h050/canonical-candidate-motion.json', import.meta.url)
  );
  const localOverrides = new Map([[sourcePath, Buffer.concat([original, Buffer.from(' ')])]]);
  const result = verifyH051Safe({ localOverrides });
  assert.equal(result.structuralIntegrityVerified, false);
  assert.equal(result.outcome.status, 'invalid');
  assert.equal(result.outcome.reasonCode, 'local-source-byte-drift');
  assert.equal(result.semanticClassificationsAccepted, false);
  assert.equal(result.authority, 'none');
  assert.equal(result.action, null);
});

test('raw artifact or schema drift is invalid rather than a new semantic outcome', () => {
  const artifactResult = verifyH051Safe({
    artifactOverrides: {
      readinessMap: Buffer.concat([readinessMapBytes, Buffer.from('\n')]),
    },
  });
  assert.equal(artifactResult.outcome.reasonCode, 'readinessMap-raw-drift');

  const schemaResult = verifyH051Safe({
    schemaOverrides: {
      docket: Buffer.concat([
        readFileSync(
          new URL('./schemas/specification-readiness-docket.schema.json', import.meta.url)
        ),
        Buffer.from('\n'),
      ]),
    },
  });
  assert.equal(schemaResult.outcome.reasonCode, 'schema-raw-drift');
});

test('role overlap, source reordering, and successor self-admission are rejected', () => {
  const roleOverlap = clone(subjectLock);
  roleOverlap.sourceRoles.h050AcceptedIntent.push(roleOverlap.sourceRoles.h050PreReview[0]);
  assert.throws(() => verifySubjectLockStructure(roleOverlap), assertReason('source-role-overlap'));

  const reordered = clone(subjectLock);
  [reordered.localSources[0], reordered.localSources[1]] = [
    reordered.localSources[1],
    reordered.localSources[0],
  ];
  assert.throws(
    () => verifySubjectLockStructure(reordered),
    assertReason('local-source-set-drift')
  );

  const selfAdmission = clone(subjectLock);
  selfAdmission.excludedSources.successorChange = '.overlaykit/governance/changes/CHG-0032.json';
  assert.throws(
    () => verifySubjectLockStructure(selfAdmission),
    assertReason('temporal-boundary-drift')
  );
});

test('citation escape, missing pointers, and slot invention fail closed', () => {
  const escapedCitation = clone(readinessMap);
  escapedCitation.mappings[0].sourceCitations[0].path = '../outside.json';
  assert.throws(
    () =>
      verifyReadinessMapStructure(escapedCitation, {
        lock: subjectLock,
        sourceBytesByPath: inspectedSources().sourceBytesByPath,
      }),
    assertReason('citation-source-not-admitted')
  );

  const missingPointer = clone(readinessMap);
  missingPointer.mappings[0].sourceCitations[0].pointer = '/missing';
  assert.throws(
    () =>
      verifyReadinessMapStructure(missingPointer, {
        lock: subjectLock,
        sourceBytesByPath: inspectedSources().sourceBytesByPath,
      }),
    assertReason('citation-pointer-missing')
  );

  const inventedSlot = clone(readinessMap);
  inventedSlot.mappings[0].abstractSlots[0] = 'mechanism.signal-controller';
  assert.throws(
    () =>
      verifyReadinessMapStructure(inventedSlot, {
        lock: subjectLock,
        sourceBytesByPath: inspectedSources().sourceBytesByPath,
      }),
    assertReason('mapping-slot-not-admitted')
  );
});

test('predicate omission, classification drift, and SPEC-shaped projection are rejected', () => {
  const omittedReceipt = clone(readinessMap);
  omittedReceipt.predicateReceipts.pop();
  assert.throws(
    () =>
      verifyReadinessMapStructure(omittedReceipt, {
        lock: subjectLock,
        sourceBytesByPath: inspectedSources().sourceBytesByPath,
      }),
    assertReason('predicate-receipt-roster-drift')
  );

  const falseResolution = clone(readinessMap);
  falseResolution.mappings.at(-1).classification = 'mapped';
  falseResolution.mappings.at(-1).ambiguity = null;
  assert.throws(
    () =>
      verifyReadinessMapStructure(falseResolution, {
        lock: subjectLock,
        sourceBytesByPath: inspectedSources().sourceBytesByPath,
      }),
    assertReason('mapping-classification-drift')
  );

  const specFixture = clone(readinessMap);
  specFixture.mappingPolicy.specificationFixturePermitted = true;
  assert.throws(
    () =>
      verifyReadinessMapStructure(specFixture, {
        lock: subjectLock,
        sourceBytesByPath: inspectedSources().sourceBytesByPath,
      }),
    assertReason('mapping-policy-drift')
  );
});

test('authority, ADR, capability, and semantic self-approval overclaims are rejected', () => {
  const authority = clone(readinessMap);
  authority.authority = 'agent';
  assert.throws(
    () =>
      verifyReadinessMapStructure(authority, {
        lock: subjectLock,
        sourceBytesByPath: inspectedSources().sourceBytesByPath,
      }),
    assertReason('authority-overclaim')
  );

  const adr = clone(readinessMap);
  adr.adrAssessment.candidateActivated = true;
  assert.throws(
    () =>
      verifyReadinessMapStructure(adr, {
        lock: subjectLock,
        sourceBytesByPath: inspectedSources().sourceBytesByPath,
      }),
    assertReason('adr-overclaim')
  );

  const live = clone(docket);
  live.capabilityAudit.usb = true;
  assert.throws(
    () =>
      verifyDocketStructure(live, {
        precontractRawSha256: sha256(precontractBytes),
        predecessorChangeRawSha256: sha256(
          inspectedSources().sourceBytesByPath.get('.overlaykit/governance/changes/CHG-0030.json')
        ),
        sourceLockRawSha256: sha256(subjectLockBytes),
        readinessMapRawSha256: sha256(readinessMapBytes),
      }),
    assertReason('capability-overclaim')
  );

  const selfApproval = clone(docket);
  selfApproval.discoveryFrame.observableEvidence =
    'eleven independently recomputed semantic predicates';
  assert.throws(
    () =>
      verifyDocketStructure(selfApproval, {
        precontractRawSha256: sha256(precontractBytes),
        predecessorChangeRawSha256: sha256(
          inspectedSources().sourceBytesByPath.get('.overlaykit/governance/changes/CHG-0030.json')
        ),
        sourceLockRawSha256: sha256(subjectLockBytes),
        readinessMapRawSha256: sha256(readinessMapBytes),
      }),
    assertReason('semantic-self-approval')
  );
});

test('the verifier has no writer, network, live-host, signal, or alternate executable capability', () => {
  const source = readFileSync(new URL('./verify.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /node:(?:http|https|net|tls|dgram)/u);
  assert.doesNotMatch(
    source,
    /\b(?:writeFile|appendFile|mkdir|unlink|rename|truncate|chmod|chown|kill|spawn)\w*\s*\(/u
  );
  assert.doesNotMatch(source, /\b(?:fetch|WebSocket)\s*\(/u);
  assert.doesNotMatch(source, /shell\s*:\s*true/u);
  assert.match(source, /execFileSync\('\/usr\/bin\/git'/u);
  assert.match(source, /ALLOWED_GIT_OPERATIONS/u);
  assert.equal(/\/(?:proc|sys)\//u.test(source), false);
  assert.equal(/\/dev\//u.test(source.replaceAll('/dev/null', '')), false);
});
