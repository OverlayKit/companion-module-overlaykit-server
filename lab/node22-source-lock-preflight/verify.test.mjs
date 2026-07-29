import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';

import {
  makeCandidateExpectation,
  makeExpectedEvidence,
  makeObservationSnapshot,
} from './fixtures/synthetic-boundary.mjs';
import { verifySourceLock } from './verify.mjs';

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort(compareUtf8)
        .map((key) => [key, canonicalize(value[key])])
    );
  }
  return value;
}

function canonicalHash(value) {
  return createHash('sha256')
    .update(JSON.stringify(canonicalize(value)))
    .digest('hex');
}

// This test-local refresh implementation deliberately imports neither producer
// nor verifier helpers. It lets controls remain internally coherent so each
// test reaches the intended semantic rejection rather than a generic hash error.
function refreshEvidence(evidence) {
  for (const layer of evidence.layers) {
    layer.entryCount = layer.entries.length;
    const body = {
      entries: layer.entries,
      entryCount: layer.entryCount,
      id: layer.id,
      kind: layer.kind,
      resolutionChain: layer.resolutionChain,
      sourceLocator: layer.sourceLocator,
      sourceRealPath: layer.sourceRealPath,
    };
    layer.contentSha256 = canonicalHash(body);
  }

  const layersById = new Map(evidence.layers.map((layer) => [layer.id, layer]));
  for (const mount of evidence.mounts) {
    const layer = layersById.get(mount.layerId);
    if (layer) {
      mount.sourceContentSha256 = layer.contentSha256;
    }
  }

  evidence.counts = {
    descriptors: evidence.layers.reduce((total, layer) => total + layer.entries.length, 0),
    directories: evidence.layers.reduce(
      (total, layer) => total + layer.entries.filter((entry) => entry.kind === 'directory').length,
      0
    ),
    indirections: evidence.layers.reduce((total, layer) => total + layer.resolutionChain.length, 0),
    layers: evidence.layers.length,
    mounts: evidence.mounts.length,
    regularFiles: evidence.layers.reduce(
      (total, layer) =>
        total + layer.entries.filter((entry) => entry.kind === 'regular-file').length,
      0
    ),
  };
  return refreshEvidenceEnvelope(evidence);
}

function refreshEvidenceEnvelope(evidence) {
  evidence.rootSha256 = canonicalHash({
    counts: evidence.counts,
    layers: evidence.layers,
    mounts: evidence.mounts,
  });
  const { semanticSha256: _semanticSha256, ...body } = evidence;
  evidence.semanticSha256 = canonicalHash(body);
  return evidence;
}

function refreshExpectation(expectation) {
  const closure = expectation.expectedClosure;
  for (const layer of closure.layers) {
    layer.entryCount = layer.entries.length;
    const { contentSha256: _contentSha256, ...body } = layer;
    layer.contentSha256 = canonicalHash(body);
  }
  const layersById = new Map(closure.layers.map((layer) => [layer.id, layer]));
  for (const mount of closure.mounts) {
    const layer = layersById.get(mount.layerId);
    if (layer) {
      mount.sourceContentSha256 = layer.contentSha256;
    }
  }
  closure.counts = {
    descriptors: closure.layers.reduce((total, layer) => total + layer.entries.length, 0),
    directories: closure.layers.reduce(
      (total, layer) => total + layer.entries.filter((entry) => entry.kind === 'directory').length,
      0
    ),
    indirections: closure.layers.reduce((total, layer) => total + layer.resolutionChain.length, 0),
    layers: closure.layers.length,
    mounts: closure.mounts.length,
    regularFiles: closure.layers.reduce(
      (total, layer) =>
        total + layer.entries.filter((entry) => entry.kind === 'regular-file').length,
      0
    ),
  };
  closure.rootSha256 = canonicalHash({
    counts: closure.counts,
    layers: closure.layers,
    mounts: closure.mounts,
  });
  return expectation;
}

function expectVerifierRejection(expectation, evidence, code) {
  assert.throws(
    () => verifySourceLock(expectation, evidence),
    (error) => error?.name === 'SourceLockVerificationError' && error?.code === code
  );
}

test('independent verifier matches the pinned candidate expectation and baseline evidence', () => {
  const result = verifySourceLock(makeCandidateExpectation(), makeExpectedEvidence());

  assert.equal(
    result.candidateExpectationSha256,
    '1605865d02f6d462e99038df2e1c1b776b3fc9bf8fb0581982b69f2a5f518df2'
  );
  assert.equal(
    result.evidenceSemanticSha256,
    'bdcb8d49f6b3b34605a868b4f12b07766bb612d536a716cbe6d14967ee28e983'
  );
  assert.equal(result.hypothesisOutcome, 'not-executed');
  assert.equal(result.realSourceClosureClaim, false);
  assert.equal(result.authority, 'none');
  assert.equal(result.action, null);
});

test('verifier rejects coherent omission without relying on count-only checks', () => {
  const expectation = makeCandidateExpectation();

  const layer = makeExpectedEvidence();
  layer.layers.pop();
  layer.mounts.pop();
  expectVerifierRejection(expectation, refreshEvidence(layer), 'layer-roster-incomplete');

  const mount = makeExpectedEvidence();
  mount.mounts.pop();
  expectVerifierRejection(expectation, refreshEvidence(mount), 'mount-roster-incomplete');

  const descriptor = makeExpectedEvidence();
  descriptor.layers[20].entries.pop();
  expectVerifierRejection(expectation, refreshEvidence(descriptor), 'descriptor-roster-incomplete');

  const indirection = makeExpectedEvidence();
  indirection.layers[3].resolutionChain.pop();
  expectVerifierRejection(
    expectation,
    refreshEvidence(indirection),
    'indirection-roster-incomplete'
  );
});

test('verifier rejects topology-preserving replacement with all cardinalities retained', () => {
  const expectation = makeCandidateExpectation();

  const layer = makeExpectedEvidence();
  layer.layers[24].id = 'synthetic-dummy-layer';
  layer.layers[24].sourceLocator =
    '/__overlaykit_source_lock_fixture__/locators/synthetic-dummy-layer';
  layer.layers[24].sourceRealPath =
    '/__overlaykit_source_lock_fixture__/sources/synthetic-dummy-layer';
  layer.mounts[24].layerId = layer.layers[24].id;
  layer.mounts[24].sourceLocator = layer.layers[24].sourceLocator;
  layer.mounts[24].sourceRealPath = layer.layers[24].sourceRealPath;
  layer.mounts[24].target = '/__overlaykit_source_lock_fixture__/mounts/synthetic-dummy-layer';
  expectVerifierRejection(expectation, refreshEvidence(layer), 'layer-roster-incomplete');

  const descriptor = makeExpectedEvidence();
  descriptor.layers[20].entries.at(-1).logicalPath = 'files/999.synthetic';
  expectVerifierRejection(expectation, refreshEvidence(descriptor), 'descriptor-roster-incomplete');

  const indirection = makeExpectedEvidence();
  indirection.layers[3].resolutionChain[1].requestedPath =
    '/__overlaykit_source_lock_fixture__/resolved/replacement';
  expectVerifierRejection(expectation, refreshEvidence(indirection), 'symlink-chain-drift');

  const mount = makeExpectedEvidence();
  mount.mounts[24].target = '/__overlaykit_source_lock_fixture__/mounts/replacement';
  expectVerifierRejection(
    expectation,
    refreshEvidenceEnvelope(mount),
    'mount-layer-bijection-invalid'
  );
});

test('verifier rejects a coherently rehashed stale descriptor', () => {
  const evidence = makeExpectedEvidence();
  const entry = evidence.layers[20].entries.find((candidate) => candidate.kind === 'regular-file');
  entry.sha256 = createHash('sha256').update('stale synthetic bytes').digest('hex');
  entry.byteLength += 1;

  expectVerifierRejection(
    makeCandidateExpectation(),
    refreshEvidence(evidence),
    'source-descriptor-stale'
  );
});

test('verifier rejects symlink drift and chain reorder', () => {
  const drift = makeExpectedEvidence();
  drift.layers[3].resolutionChain[0].linkTarget = 'drifted';
  expectVerifierRejection(
    makeCandidateExpectation(),
    refreshEvidence(drift),
    'symlink-chain-drift'
  );

  const reorder = makeExpectedEvidence();
  reorder.layers[3].resolutionChain.reverse();
  expectVerifierRejection(
    makeCandidateExpectation(),
    refreshEvidence(reorder),
    'canonical-order-invalid'
  );
});

test('verifier rejects collisions with cardinalities preserved', () => {
  const layer = makeExpectedEvidence();
  layer.layers[1].id = layer.layers[0].id;
  expectVerifierRejection(makeCandidateExpectation(), refreshEvidence(layer), 'layer-id-collision');

  const descriptor = makeExpectedEvidence();
  descriptor.layers[16].entries[1].logicalPath = descriptor.layers[16].entries[0].logicalPath;
  expectVerifierRejection(
    makeCandidateExpectation(),
    refreshEvidence(descriptor),
    'descriptor-key-collision'
  );

  const target = makeExpectedEvidence();
  target.mounts[1].target = target.mounts[0].target;
  expectVerifierRejection(
    makeCandidateExpectation(),
    refreshEvidence(target),
    'mount-target-collision'
  );
});

test('verifier rejects path and mount rebinding', () => {
  const source = makeExpectedEvidence();
  source.layers[0].sourceLocator = '/__overlaykit_source_lock_fixture__/locators/rebound';
  source.layers[0].sourceRealPath = '/__overlaykit_source_lock_fixture__/sources/rebound';
  source.mounts[0].sourceLocator = source.layers[0].sourceLocator;
  source.mounts[0].sourceRealPath = source.layers[0].sourceRealPath;
  expectVerifierRejection(
    makeCandidateExpectation(),
    refreshEvidence(source),
    'source-path-rebound'
  );

  const mount = makeExpectedEvidence();
  [mount.mounts[0].sourceContentSha256, mount.mounts[1].sourceContentSha256] = [
    mount.mounts[1].sourceContentSha256,
    mount.mounts[0].sourceContentSha256,
  ];
  expectVerifierRejection(
    makeCandidateExpectation(),
    refreshEvidenceEnvelope(mount),
    'mount-layer-bijection-invalid'
  );
});

test('verifier rejects expectation derived from the same coherently mutated state', () => {
  const expectation = makeCandidateExpectation();
  const evidence = makeExpectedEvidence();
  const replacement = createHash('sha256').update('coherent fraud').digest('hex');

  expectation.expectedClosure.layers[20].entries[1].sha256 = replacement;
  evidence.layers[20].entries[1].sha256 = replacement;
  refreshExpectation(expectation);
  refreshEvidence(evidence);

  expectVerifierRejection(expectation, evidence, 'precontract-expectation-drift');
});

test('verifier rejects observation-as-expectation, authority drift, and extra fields', () => {
  expectVerifierRejection(
    makeObservationSnapshot(),
    makeExpectedEvidence(),
    'precontract-expectation-unanchored'
  );

  const authority = makeExpectedEvidence();
  authority.authority = 'verifier';
  refreshEvidence(authority);
  expectVerifierRejection(makeCandidateExpectation(), authority, 'authority-overclaim');

  const unexpected = clone(makeExpectedEvidence());
  unexpected.verdict = 'supported';
  expectVerifierRejection(makeCandidateExpectation(), unexpected, 'evidence-shape-invalid');
});
