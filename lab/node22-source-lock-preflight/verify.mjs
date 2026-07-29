import { createHash } from 'node:crypto';

const STUDY = 'NODE22-SOURCE-LOCK-PREFLIGHT-001';
const SYNTHETIC_NAMESPACE = '/__overlaykit_source_lock_fixture__';
const PINNED_CANDIDATE_EXPECTATION_SHA256 =
  '1605865d02f6d462e99038df2e1c1b776b3fc9bf8fb0581982b69f2a5f518df2';

const EXPECTED_COUNTS = Object.freeze({
  descriptors: 687,
  directories: 74,
  indirections: 26,
  layers: 25,
  mounts: 25,
  regularFiles: 613,
});

export class SourceLockVerificationError extends Error {
  constructor(code) {
    super(code);
    this.name = 'SourceLockVerificationError';
    this.code = code;
  }
}

function reject(code) {
  throw new SourceLockVerificationError(code);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function normalize(value) {
  if (Array.isArray(value)) {
    return value.map((item) => normalize(item));
  }

  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort(compareUtf8)
        .map((key) => [key, normalize(value[key])])
    );
  }

  return value;
}

function digest(value) {
  return createHash('sha256')
    .update(JSON.stringify(normalize(value)))
    .digest('hex');
}

function same(left, right) {
  return JSON.stringify(normalize(left)) === JSON.stringify(normalize(right));
}

function exactKeys(value, keys) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }
  const actual = Object.keys(value).sort(compareUtf8);
  const expected = [...keys].sort(compareUtf8);
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function validateExpectationEnvelope(expectation) {
  if (
    !exactKeys(expectation, [
      'action',
      'authority',
      'expectedClosure',
      'normative',
      'provenance',
      'realSourceClosureClaim',
      'schemaVersion',
      'study',
      'synthetic',
      'temporalRole',
    ])
  ) {
    reject('precontract-expectation-unanchored');
  }

  if (
    expectation.schemaVersion !== 'overlaykit-node22-source-lock-expectation/v1' ||
    expectation.study !== STUDY ||
    expectation.temporalRole !== 'candidate-precontract-expectation' ||
    expectation.synthetic !== true ||
    expectation.normative !== false ||
    expectation.realSourceClosureClaim !== false
  ) {
    reject('precontract-expectation-unanchored');
  }

  if (expectation.authority !== 'none' || expectation.action !== null) {
    reject('authority-overclaim');
  }

  if (
    !exactKeys(expectation.provenance, [
      'anchorRequiredBeforeRealSourceUse',
      'derivation',
      'kind',
      'realSourceAuthority',
    ]) ||
    expectation.provenance.anchorRequiredBeforeRealSourceUse !== true ||
    expectation.provenance.derivation !== 'agent-authored-separate-roster-pending-human-review' ||
    expectation.provenance.kind !== 'synthetic-pinned-candidate-fixture' ||
    expectation.provenance.realSourceAuthority !== 'absent'
  ) {
    reject('precontract-expectation-unanchored');
  }

  if (digest(expectation) !== PINNED_CANDIDATE_EXPECTATION_SHA256) {
    reject('precontract-expectation-drift');
  }

  const closure = expectation.expectedClosure;
  if (
    !exactKeys(closure, ['counts', 'layers', 'mounts', 'rootSha256']) ||
    !same(closure.counts, EXPECTED_COUNTS) ||
    !Array.isArray(closure.layers) ||
    !Array.isArray(closure.mounts)
  ) {
    reject('precontract-expectation-invalid');
  }

  const rootBody = {
    counts: closure.counts,
    layers: closure.layers,
    mounts: closure.mounts,
  };
  if (digest(rootBody) !== closure.rootSha256) {
    reject('precontract-expectation-invalid');
  }
}

function validateEvidenceEnvelope(evidence) {
  if (
    !exactKeys(evidence, [
      'action',
      'authority',
      'captureId',
      'counts',
      'layers',
      'mounts',
      'normative',
      'realSourceClosureClaim',
      'rootSha256',
      'schemaVersion',
      'semanticSha256',
      'study',
      'synthetic',
      'temporalRole',
    ])
  ) {
    reject('evidence-shape-invalid');
  }

  if (
    evidence.schemaVersion !== 'overlaykit-node22-source-lock-evidence/v1' ||
    evidence.study !== STUDY ||
    evidence.temporalRole !== 'unassessed-source-lock-closure' ||
    evidence.synthetic !== true ||
    evidence.normative !== false ||
    evidence.realSourceClosureClaim !== false ||
    typeof evidence.captureId !== 'string' ||
    evidence.captureId.length === 0
  ) {
    reject('evidence-shape-invalid');
  }

  if (evidence.authority !== 'none' || evidence.action !== null) {
    reject('authority-overclaim');
  }
}

function validateEntryShape(entry) {
  if (entry?.kind === 'directory') {
    if (!exactKeys(entry, ['kind', 'logicalPath', 'mode'])) {
      reject('evidence-shape-invalid');
    }
    return;
  }

  if (entry?.kind === 'regular-file') {
    if (!exactKeys(entry, ['byteLength', 'kind', 'logicalPath', 'mode', 'sha256'])) {
      reject('evidence-shape-invalid');
    }
    if (
      !Number.isSafeInteger(entry.byteLength) ||
      entry.byteLength < 0 ||
      !/^[a-f0-9]{64}$/.test(entry.sha256)
    ) {
      reject('evidence-shape-invalid');
    }
    return;
  }

  reject('evidence-shape-invalid');
}

function validateInternalIntegrity(evidence) {
  if (!Array.isArray(evidence.layers) || !Array.isArray(evidence.mounts)) {
    reject('evidence-shape-invalid');
  }

  let descriptors = 0;
  let directories = 0;
  let indirections = 0;
  let regularFiles = 0;

  for (const layer of evidence.layers) {
    if (
      !exactKeys(layer, [
        'contentSha256',
        'entries',
        'entryCount',
        'id',
        'kind',
        'resolutionChain',
        'sourceLocator',
        'sourceRealPath',
      ]) ||
      !Array.isArray(layer.entries) ||
      !Array.isArray(layer.resolutionChain)
    ) {
      reject('evidence-shape-invalid');
    }

    layer.entries.forEach(validateEntryShape);
    const layerBody = {
      entries: layer.entries,
      entryCount: layer.entryCount,
      id: layer.id,
      kind: layer.kind,
      resolutionChain: layer.resolutionChain,
      sourceLocator: layer.sourceLocator,
      sourceRealPath: layer.sourceRealPath,
    };
    if (digest(layerBody) !== layer.contentSha256) {
      reject('evidence-integrity-drift');
    }
    if (layer.entryCount !== layer.entries.length) {
      reject('evidence-integrity-drift');
    }

    descriptors += layer.entries.length;
    directories += layer.entries.filter((entry) => entry.kind === 'directory').length;
    regularFiles += layer.entries.filter((entry) => entry.kind === 'regular-file').length;
    indirections += layer.resolutionChain.length;
  }

  for (const mount of evidence.mounts) {
    if (
      !exactKeys(mount, [
        'access',
        'kind',
        'layerId',
        'sourceContentSha256',
        'sourceLocator',
        'sourceRealPath',
        'target',
      ]) ||
      !/^[a-f0-9]{64}$/.test(mount.sourceContentSha256)
    ) {
      reject('evidence-shape-invalid');
    }
  }

  const computedCounts = {
    descriptors,
    directories,
    indirections,
    layers: evidence.layers.length,
    mounts: evidence.mounts.length,
    regularFiles,
  };
  if (!same(computedCounts, evidence.counts)) {
    reject('evidence-integrity-drift');
  }

  const rootBody = {
    counts: evidence.counts,
    layers: evidence.layers,
    mounts: evidence.mounts,
  };
  if (digest(rootBody) !== evidence.rootSha256) {
    reject('evidence-integrity-drift');
  }

  const semanticBody = {
    action: evidence.action,
    authority: evidence.authority,
    captureId: evidence.captureId,
    counts: evidence.counts,
    layers: evidence.layers,
    mounts: evidence.mounts,
    normative: evidence.normative,
    realSourceClosureClaim: evidence.realSourceClosureClaim,
    rootSha256: evidence.rootSha256,
    schemaVersion: evidence.schemaVersion,
    study: evidence.study,
    synthetic: evidence.synthetic,
    temporalRole: evidence.temporalRole,
  };
  if (digest(semanticBody) !== evidence.semanticSha256) {
    reject('evidence-integrity-drift');
  }
}

function assertNoCollisions(evidence) {
  const layerIds = evidence.layers.map((layer) => layer.id);
  if (new Set(layerIds).size !== layerIds.length) {
    reject('layer-id-collision');
  }

  for (const layer of evidence.layers) {
    const descriptorKeys = layer.entries.map((entry) => `${layer.id}\u0000${entry.logicalPath}`);
    if (new Set(descriptorKeys).size !== descriptorKeys.length) {
      reject('descriptor-key-collision');
    }

    const indirectionKeys = layer.resolutionChain.map(
      (entry) => `${layer.id}\u0000${String(entry?.ordinal)}`
    );
    if (new Set(indirectionKeys).size !== indirectionKeys.length) {
      reject('indirection-key-collision');
    }
  }

  const mountLayerIds = evidence.mounts.map((mount) => mount.layerId);
  if (new Set(mountLayerIds).size !== mountLayerIds.length) {
    reject('mount-layer-collision');
  }

  const mountTargets = evidence.mounts.map((mount) => mount.target);
  if (new Set(mountTargets).size !== mountTargets.length) {
    reject('mount-target-collision');
  }
}

function assertExactCardinalities(evidence) {
  if (evidence.layers.length !== EXPECTED_COUNTS.layers) {
    reject('layer-roster-incomplete');
  }
  if (evidence.mounts.length !== EXPECTED_COUNTS.mounts) {
    reject('mount-roster-incomplete');
  }
  if (evidence.counts.descriptors !== EXPECTED_COUNTS.descriptors) {
    reject('descriptor-roster-incomplete');
  }
  if (evidence.counts.indirections !== EXPECTED_COUNTS.indirections) {
    reject('indirection-roster-incomplete');
  }
  if (
    evidence.counts.directories !== EXPECTED_COUNTS.directories ||
    evidence.counts.regularFiles !== EXPECTED_COUNTS.regularFiles
  ) {
    reject('descriptor-roster-incomplete');
  }
}

function assertCanonicalOrdering(evidence, expected) {
  const layerIds = evidence.layers.map((layer) => layer.id);
  const expectedLayerIds = expected.layers.map((layer) => layer.id);
  if (
    same([...layerIds].sort(compareUtf8), [...expectedLayerIds].sort(compareUtf8)) &&
    !same(layerIds, expectedLayerIds)
  ) {
    reject('canonical-order-invalid');
  }

  const mountIds = evidence.mounts.map((mount) => mount.layerId);
  const expectedMountIds = expected.mounts.map((mount) => mount.layerId);
  if (
    same([...mountIds].sort(compareUtf8), [...expectedMountIds].sort(compareUtf8)) &&
    !same(mountIds, expectedMountIds)
  ) {
    reject('canonical-order-invalid');
  }

  for (const layer of evidence.layers) {
    const logicalPaths = layer.entries.map((entry) => entry.logicalPath);
    if (
      logicalPaths.some(
        (logicalPath, index) => index > 0 && compareUtf8(logicalPaths[index - 1], logicalPath) >= 0
      )
    ) {
      reject('canonical-order-invalid');
    }

    const ordinals = layer.resolutionChain.map((entry) => entry?.ordinal);
    if (ordinals.some((ordinal, index) => ordinal !== index)) {
      reject('canonical-order-invalid');
    }
  }
}

function assertLayerMatches(layer, expectedLayer) {
  if (layer.id !== expectedLayer.id || layer.kind !== expectedLayer.kind) {
    reject('layer-roster-incomplete');
  }

  if (
    layer.sourceLocator !== expectedLayer.sourceLocator ||
    layer.sourceRealPath !== expectedLayer.sourceRealPath ||
    !layer.sourceLocator.startsWith(`${SYNTHETIC_NAMESPACE}/`) ||
    !layer.sourceRealPath.startsWith(`${SYNTHETIC_NAMESPACE}/`)
  ) {
    reject('source-path-rebound');
  }

  if (!same(layer.resolutionChain, expectedLayer.resolutionChain)) {
    reject('symlink-chain-drift');
  }

  if (layer.entries.length !== expectedLayer.entries.length) {
    reject('descriptor-roster-incomplete');
  }

  for (let index = 0; index < expectedLayer.entries.length; index += 1) {
    const entry = layer.entries[index];
    const expectedEntry = expectedLayer.entries[index];
    if (entry.logicalPath !== expectedEntry.logicalPath || entry.kind !== expectedEntry.kind) {
      reject('descriptor-roster-incomplete');
    }
    if (!same(entry, expectedEntry)) {
      reject('source-descriptor-stale');
    }
  }

  if (layer.contentSha256 !== expectedLayer.contentSha256) {
    reject('source-lock-stale');
  }
}

function assertMountMatches(mount, expectedMount, layer) {
  if (
    mount.layerId !== expectedMount.layerId ||
    mount.kind !== expectedMount.kind ||
    mount.access !== 'read-only' ||
    mount.target !== expectedMount.target
  ) {
    reject('mount-layer-bijection-invalid');
  }

  if (
    mount.sourceLocator !== expectedMount.sourceLocator ||
    mount.sourceRealPath !== expectedMount.sourceRealPath
  ) {
    reject('source-path-rebound');
  }

  if (
    mount.sourceContentSha256 !== expectedMount.sourceContentSha256 ||
    mount.sourceContentSha256 !== layer.contentSha256
  ) {
    reject('mount-layer-bijection-invalid');
  }
}

function compareWithExpectation(expectation, evidence) {
  const expected = expectation.expectedClosure;
  assertNoCollisions(evidence);
  assertExactCardinalities(evidence);
  assertCanonicalOrdering(evidence, expected);

  for (let index = 0; index < expected.layers.length; index += 1) {
    assertLayerMatches(evidence.layers[index], expected.layers[index]);
  }
  for (let index = 0; index < expected.mounts.length; index += 1) {
    assertMountMatches(evidence.mounts[index], expected.mounts[index], evidence.layers[index]);
  }

  if (
    evidence.rootSha256 !== expected.rootSha256 ||
    !same(
      {
        counts: evidence.counts,
        layers: evidence.layers,
        mounts: evidence.mounts,
      },
      {
        counts: expected.counts,
        layers: expected.layers,
        mounts: expected.mounts,
      }
    )
  ) {
    reject('source-lock-stale');
  }
}

export function verifySourceLock(expectation, evidence) {
  validateExpectationEnvelope(expectation);
  validateEvidenceEnvelope(evidence);
  validateInternalIntegrity(evidence);
  compareWithExpectation(expectation, evidence);

  return {
    action: null,
    authority: 'none',
    counts: { ...evidence.counts },
    evidenceSemanticSha256: evidence.semanticSha256,
    candidateExpectationSha256: PINNED_CANDIDATE_EXPECTATION_SHA256,
    hypothesisOutcome: 'not-executed',
    realSourceClosureClaim: false,
    study: STUDY,
    synthetic: true,
    verification: 'synthetic-closure-matches-precontract',
  };
}

export const verifierConstants = Object.freeze({
  candidateExpectationSha256: PINNED_CANDIDATE_EXPECTATION_SHA256,
  namespace: SYNTHETIC_NAMESPACE,
  study: STUDY,
});
