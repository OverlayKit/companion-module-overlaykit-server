import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { canonicalJson as hostCanonicalJson } from '../../tools/governance/src/canonical.ts';
import {
  H053_SOURCE_CONSTANTS,
  InvalidH053SourceError,
  inspectH053Sources,
  nominatedCanonicalHash,
  parseSubjectLock,
  sha256,
  verifySubjectLockStructure,
} from './source-lock.mjs';

const subjectLockBytes = readFileSync(new URL('./subject-lock.json', import.meta.url));
const { lock: subjectLock } = parseSubjectLock(subjectLockBytes);

function clone(value) {
  return structuredClone(value);
}

function assertReason(reasonCode) {
  return (error) => {
    assert.ok(error instanceof InvalidH053SourceError);
    assert.equal(error.reasonCode, reasonCode);
    return true;
  };
}

let cachedInspection;
function inspected() {
  cachedInspection ??= inspectH053Sources();
  return cachedInspection;
}

test('reconstructs the exact nominated H-053 descriptor with its original canonicalizer', () => {
  const receipt = verifySubjectLockStructure(subjectLock);
  assert.deepEqual(receipt, {
    gitSourceCount: 21,
    localSourceCount: 8,
    totalSourceCount: 29,
    combinedSourceSetSha256: 'd257830144a01545cd4bdd11c3209481adc54dc6d47603eb8273f6884f17a54f',
  });
  assert.equal(
    nominatedCanonicalHash(subjectLock.sourceBoundary),
    H053_SOURCE_CONSTANTS.combinedSourceSetSha256
  );
});

test('documents and detects the canonicalization distinction from the governance host', () => {
  const hostDigest = createHash('sha256')
    .update(hostCanonicalJson(subjectLock.sourceBoundary))
    .digest('hex');
  assert.equal(hostDigest, 'b0c89615a63f58a2a30b8f62e4e683848786aa6bb4b30f8dfe5d084546461cea');
  assert.notEqual(hostDigest, H053_SOURCE_CONSTANTS.combinedSourceSetSha256);
});

test('resolves all 21 Git and 8 local temporal sources without network access', () => {
  const receipt = inspected();
  assert.equal(receipt.gitSourceBytesByPath.size, 21);
  assert.equal(receipt.localSourceBytesByPath.size, 8);
  assert.equal(receipt.totalSourceCount, 29);
  assert.equal(receipt.executedWorktreeBindings.length, 13);
  assert.match(receipt.executedWorktreeBindingsSha256, /^[0-9a-f]{64}$/u);
  assert.equal(
    receipt.gitSourceSetSha256,
    '6031fbc61fc8ccf1be86b712f8d718412a449fe3f393d8fca59fb820473169dd'
  );
  assert.equal(
    receipt.localSourceSetSha256,
    '45f826086a17aaacdfc0b7dbd8ef2046cfe4044f34ef34c3d1536c783b632f8a'
  );
  assert.equal(
    sha256(
      receipt.gitSourceBytesByPath.get('.overlaykit/governance/specifications/SPEC-0001.json')
    ),
    '917f1ca2febe17f8901ab71f91a0b0135402f9be972a876f233fcd5c789b8179'
  );
});

test('fails the source-execution closure on the exact transitive errors.ts omission', () => {
  const receipt = inspected();
  assert.equal(receipt.sourceExecutionClosure.closed, false);
  assert.equal(receipt.sourceExecutionClosure.classification, 'incomplete');
  assert.equal(receipt.sourceExecutionClosure.dependencyCount, 13);
  assert.equal(receipt.sourceExecutionClosure.admittedDependencyCount, 12);
  assert.equal(receipt.sourceExecutionClosure.unadmittedDependencyCount, 1);
  assert.equal(receipt.sourceExecutionClosure.consumedInputCount, 6);
  assert.equal(receipt.sourceExecutionClosure.executedFirstPartySourceCount, 7);
  assert.deepEqual(
    receipt.sourceExecutionClosure.unadmittedDependencies.map(
      ({ path: sourcePath, admittedToNominatedBoundary }) => ({
        path: sourcePath,
        admittedToNominatedBoundary,
      })
    ),
    [
      {
        path: 'tools/governance/src/errors.ts',
        admittedToNominatedBoundary: false,
      },
    ]
  );
  assert.deepEqual(receipt.sourceExecutionClosure.nominatedButNotExecutedSources, [
    'tools/governance/src/repository.ts',
  ]);
  assert.equal(
    receipt.sourceExecutionClosure.bindings.some(
      ({ path: sourcePath }) => sourcePath === 'tools/governance/src/repository.ts'
    ),
    false
  );
  assert.match(receipt.sourceExecutionClosure.bindingsSha256, /^[0-9a-f]{64}$/u);
});

test('recovers the pre-H-053 manifest from the byte-exact H-052 replay', () => {
  const receipt = inspected();
  const recovered = receipt.localSourceBytesByPath.get('.overlaykit/governance/manifest.json');
  const successor = readFileSync(
    new URL('../../.overlaykit/governance/manifest.json', import.meta.url)
  );
  assert.equal(sha256(recovered), H053_SOURCE_CONSTANTS.preH053ManifestSha256);
  assert.notEqual(sha256(successor), H053_SOURCE_CONSTANTS.preH053ManifestSha256);
  assert.equal(JSON.parse(recovered).changes['CHG-0034'], undefined);
  assert.match(JSON.parse(successor).changes['CHG-0034'], /^[0-9a-f]{64}$/u);
});

test('rejects descriptor drift and successor self-admission', () => {
  const drifted = clone(subjectLock);
  drifted.sourceBoundary.gitSubject.sources[0].byteLength += 1;
  assert.throws(
    () => verifySubjectLockStructure(drifted),
    assertReason('source-descriptor-hash-drift')
  );

  const selfAdmitted = clone(subjectLock);
  selfAdmitted.sourceBoundary.gitSubject.sources[0].path =
    '.overlaykit/governance/changes/CHG-0034.json';
  assert.throws(
    () => verifySubjectLockStructure(selfAdmitted),
    assertReason('source-descriptor-hash-drift')
  );
});

test('rejects local predecessor substitution rather than reclassifying the hypothesis', () => {
  const path =
    'artifacts/h052/post-review-closures/7179de3ae940a9b959d441f42d04ece4158746f23362743dbe625dd9bbd92cc4/closure.json';
  const original = readFileSync(new URL(`../../${path}`, import.meta.url));
  assert.throws(
    () =>
      inspectH053Sources({
        localOverrides: new Map([[path, Buffer.concat([original, Buffer.from('\n')])]]),
      }),
    assertReason('local-source-byte-drift')
  );
});

test('binds the subject-lock raw bytes independently from the nominated source hash', () => {
  assert.equal(inspected().subjectLockRawSha256, sha256(subjectLockBytes));
  assert.notEqual(inspected().subjectLockRawSha256, inspected().combinedSourceSetSha256);
});
