import { createHash } from 'node:crypto';

const STUDY = 'NODE22-SOURCE-LOCK-PREFLIGHT-001';
const SYNTHETIC_NAMESPACE = '/__overlaykit_source_lock_fixture__';
const CAPTURE_ID = 'synthetic-source-lock-observation-001';

const PRECONTRACT_LAYER_BLUEPRINTS = Object.freeze([
  {
    id: 'synthetic-runtime-00',
    kind: 'runtime-file',
    regularCount: 1,
    directoryCount: 0,
    chainLength: 0,
  },
  {
    id: 'synthetic-runtime-01',
    kind: 'runtime-file',
    regularCount: 1,
    directoryCount: 0,
    chainLength: 1,
  },
  {
    id: 'synthetic-runtime-02',
    kind: 'runtime-file',
    regularCount: 1,
    directoryCount: 0,
    chainLength: 1,
  },
  {
    id: 'synthetic-runtime-03',
    kind: 'runtime-file',
    regularCount: 1,
    directoryCount: 0,
    chainLength: 2,
  },
  {
    id: 'synthetic-runtime-04',
    kind: 'runtime-file',
    regularCount: 1,
    directoryCount: 0,
    chainLength: 2,
  },
  {
    id: 'synthetic-runtime-05',
    kind: 'runtime-file',
    regularCount: 1,
    directoryCount: 0,
    chainLength: 2,
  },
  {
    id: 'synthetic-runtime-06',
    kind: 'runtime-file',
    regularCount: 1,
    directoryCount: 0,
    chainLength: 2,
  },
  {
    id: 'synthetic-runtime-07',
    kind: 'runtime-file',
    regularCount: 1,
    directoryCount: 0,
    chainLength: 2,
  },
  {
    id: 'synthetic-runtime-08',
    kind: 'runtime-file',
    regularCount: 1,
    directoryCount: 0,
    chainLength: 2,
  },
  {
    id: 'synthetic-runtime-09',
    kind: 'runtime-file',
    regularCount: 1,
    directoryCount: 0,
    chainLength: 2,
  },
  {
    id: 'synthetic-runtime-10',
    kind: 'runtime-file',
    regularCount: 1,
    directoryCount: 0,
    chainLength: 2,
  },
  {
    id: 'synthetic-runtime-11',
    kind: 'runtime-file',
    regularCount: 1,
    directoryCount: 0,
    chainLength: 2,
  },
  {
    id: 'synthetic-runtime-12',
    kind: 'runtime-file',
    regularCount: 1,
    directoryCount: 0,
    chainLength: 1,
  },
  {
    id: 'synthetic-runtime-13',
    kind: 'runtime-file',
    regularCount: 1,
    directoryCount: 0,
    chainLength: 2,
  },
  {
    id: 'synthetic-runtime-14',
    kind: 'runtime-file',
    regularCount: 1,
    directoryCount: 0,
    chainLength: 1,
  },
  {
    id: 'synthetic-runtime-15',
    kind: 'runtime-file',
    regularCount: 1,
    directoryCount: 0,
    chainLength: 2,
  },
  {
    id: 'synthetic-apparatus',
    kind: 'directory-tree',
    regularCount: 10,
    directoryCount: 2,
    chainLength: 0,
  },
  {
    id: 'synthetic-package-00',
    kind: 'directory-tree',
    regularCount: 50,
    directoryCount: 6,
    chainLength: 0,
  },
  {
    id: 'synthetic-package-01',
    kind: 'directory-tree',
    regularCount: 7,
    directoryCount: 3,
    chainLength: 0,
  },
  {
    id: 'synthetic-package-02',
    kind: 'directory-tree',
    regularCount: 3,
    directoryCount: 2,
    chainLength: 0,
  },
  {
    id: 'synthetic-package-03',
    kind: 'directory-tree',
    regularCount: 466,
    directoryCount: 45,
    chainLength: 0,
  },
  {
    id: 'synthetic-package-04',
    kind: 'directory-tree',
    regularCount: 11,
    directoryCount: 2,
    chainLength: 0,
  },
  {
    id: 'synthetic-package-05',
    kind: 'directory-tree',
    regularCount: 34,
    directoryCount: 8,
    chainLength: 0,
  },
  {
    id: 'synthetic-package-06',
    kind: 'directory-tree',
    regularCount: 12,
    directoryCount: 5,
    chainLength: 0,
  },
  {
    id: 'synthetic-package-07',
    kind: 'directory-tree',
    regularCount: 4,
    directoryCount: 1,
    chainLength: 0,
  },
]);

// This separately declared roster represents the mutable observation side of
// the fixture. It is intentionally not derived from the precontract array.
const OBSERVATION_LAYER_BLUEPRINTS = Object.freeze([
  ['synthetic-runtime-00', 'runtime-file', 1, 0, 0],
  ['synthetic-runtime-01', 'runtime-file', 1, 0, 1],
  ['synthetic-runtime-02', 'runtime-file', 1, 0, 1],
  ['synthetic-runtime-03', 'runtime-file', 1, 0, 2],
  ['synthetic-runtime-04', 'runtime-file', 1, 0, 2],
  ['synthetic-runtime-05', 'runtime-file', 1, 0, 2],
  ['synthetic-runtime-06', 'runtime-file', 1, 0, 2],
  ['synthetic-runtime-07', 'runtime-file', 1, 0, 2],
  ['synthetic-runtime-08', 'runtime-file', 1, 0, 2],
  ['synthetic-runtime-09', 'runtime-file', 1, 0, 2],
  ['synthetic-runtime-10', 'runtime-file', 1, 0, 2],
  ['synthetic-runtime-11', 'runtime-file', 1, 0, 2],
  ['synthetic-runtime-12', 'runtime-file', 1, 0, 1],
  ['synthetic-runtime-13', 'runtime-file', 1, 0, 2],
  ['synthetic-runtime-14', 'runtime-file', 1, 0, 1],
  ['synthetic-runtime-15', 'runtime-file', 1, 0, 2],
  ['synthetic-apparatus', 'directory-tree', 10, 2, 0],
  ['synthetic-package-00', 'directory-tree', 50, 6, 0],
  ['synthetic-package-01', 'directory-tree', 7, 3, 0],
  ['synthetic-package-02', 'directory-tree', 3, 2, 0],
  ['synthetic-package-03', 'directory-tree', 466, 45, 0],
  ['synthetic-package-04', 'directory-tree', 11, 2, 0],
  ['synthetic-package-05', 'directory-tree', 34, 8, 0],
  ['synthetic-package-06', 'directory-tree', 12, 5, 0],
  ['synthetic-package-07', 'directory-tree', 4, 1, 0],
]);

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function canonicalize(value) {
  if (Array.isArray(value)) {
    return value.map((item) => canonicalize(item));
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

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function pad(value) {
  return String(value).padStart(3, '0');
}

function sourceLocator(layerId) {
  return `${SYNTHETIC_NAMESPACE}/locators/${layerId}`;
}

function sourceRealPath(layerId) {
  return `${SYNTHETIC_NAMESPACE}/sources/${layerId}`;
}

function mountTarget(layerId) {
  return `${SYNTHETIC_NAMESPACE}/mounts/${layerId}`;
}

function makeResolutionChain(layerId, runtimeIndex, chainLength) {
  if (chainLength === 0) {
    return [];
  }

  const common = {
    kind: 'symbolic-link',
    linkTarget: 'resolved',
    mode: '0777',
    ordinal: 0,
    requestedPath: `${SYNTHETIC_NAMESPACE}/aliases`,
    resolvedPath: `${SYNTHETIC_NAMESPACE}/resolved`,
  };

  if (chainLength === 1) {
    return [common];
  }

  return [
    common,
    {
      kind: 'symbolic-link',
      linkTarget: `terminal-${pad(runtimeIndex)}`,
      mode: '0777',
      ordinal: 1,
      requestedPath: `${SYNTHETIC_NAMESPACE}/resolved/runtime-${pad(runtimeIndex)}`,
      resolvedPath: `${SYNTHETIC_NAMESPACE}/terminals/runtime-${pad(runtimeIndex)}`,
    },
  ];
}

function regularBytes(layerId, logicalPath) {
  return `overlaykit-source-lock-fixture/v1\n${layerId}\n${logicalPath}\n`;
}

function makeObservedEntries(layerId, regularCount, directoryCount) {
  const entries = [];

  for (let index = 0; index < directoryCount; index += 1) {
    entries.push({
      kind: 'directory',
      logicalPath: index === 0 ? '.' : `directories/${pad(index)}`,
      mode: '0555',
    });
  }

  for (let index = 0; index < regularCount; index += 1) {
    const logicalPath = `files/${pad(index)}.synthetic`;
    entries.push({
      bytesUtf8: regularBytes(layerId, logicalPath),
      kind: 'regular-file',
      logicalPath,
      mode: index % 11 === 0 ? '0555' : '0444',
    });
  }

  return entries.sort((left, right) => compareUtf8(left.logicalPath, right.logicalPath));
}

function expectedEntry(entry) {
  if (entry.kind === 'directory') {
    return {
      kind: entry.kind,
      logicalPath: entry.logicalPath,
      mode: entry.mode,
    };
  }

  return {
    byteLength: Buffer.byteLength(entry.bytesUtf8, 'utf8'),
    kind: entry.kind,
    logicalPath: entry.logicalPath,
    mode: entry.mode,
    sha256: sha256(entry.bytesUtf8),
  };
}

function makeExpectedLayer(blueprint, runtimeIndex) {
  const entries = makeObservedEntries(
    blueprint.id,
    blueprint.regularCount,
    blueprint.directoryCount
  ).map(expectedEntry);
  const resolutionChain = makeResolutionChain(blueprint.id, runtimeIndex, blueprint.chainLength);
  const body = {
    entries,
    entryCount: entries.length,
    id: blueprint.id,
    kind: blueprint.kind,
    resolutionChain,
    sourceLocator: sourceLocator(blueprint.id),
    sourceRealPath: sourceRealPath(blueprint.id),
  };

  return {
    ...body,
    contentSha256: canonicalHash(body),
  };
}

function makeExpectedClosure() {
  const layers = PRECONTRACT_LAYER_BLUEPRINTS.map((blueprint, index) =>
    makeExpectedLayer(blueprint, index)
  );
  const mounts = layers.map((layer) => ({
    access: 'read-only',
    kind: layer.kind,
    layerId: layer.id,
    sourceContentSha256: layer.contentSha256,
    sourceLocator: layer.sourceLocator,
    sourceRealPath: layer.sourceRealPath,
    target: mountTarget(layer.id),
  }));
  const counts = {
    descriptors: layers.reduce((total, layer) => total + layer.entries.length, 0),
    directories: layers.reduce(
      (total, layer) => total + layer.entries.filter((entry) => entry.kind === 'directory').length,
      0
    ),
    indirections: layers.reduce((total, layer) => total + layer.resolutionChain.length, 0),
    layers: layers.length,
    mounts: mounts.length,
    regularFiles: layers.reduce(
      (total, layer) =>
        total + layer.entries.filter((entry) => entry.kind === 'regular-file').length,
      0
    ),
  };
  const body = { counts, layers, mounts };

  return {
    ...body,
    rootSha256: canonicalHash(body),
  };
}

export function makeCandidateExpectation() {
  return {
    action: null,
    authority: 'none',
    expectedClosure: makeExpectedClosure(),
    normative: false,
    provenance: {
      anchorRequiredBeforeRealSourceUse: true,
      derivation: 'agent-authored-separate-roster-pending-human-review',
      kind: 'synthetic-pinned-candidate-fixture',
      realSourceAuthority: 'absent',
    },
    realSourceClosureClaim: false,
    schemaVersion: 'overlaykit-node22-source-lock-expectation/v1',
    study: STUDY,
    synthetic: true,
    temporalRole: 'candidate-precontract-expectation',
  };
}

export function makeObservationSnapshot() {
  const layers = OBSERVATION_LAYER_BLUEPRINTS.map(
    ([id, kind, regularCount, directoryCount, chainLength], index) => ({
      entries: makeObservedEntries(id, regularCount, directoryCount),
      id,
      kind,
      resolutionChain: makeResolutionChain(id, index, chainLength),
      sourceLocator: sourceLocator(id),
      sourceRealPath: sourceRealPath(id),
    })
  );

  return {
    action: null,
    authority: 'none',
    captureId: CAPTURE_ID,
    layers,
    mounts: layers.map((layer) => ({
      access: 'read-only',
      kind: layer.kind,
      layerId: layer.id,
      sourceLocator: layer.sourceLocator,
      sourceRealPath: layer.sourceRealPath,
      target: mountTarget(layer.id),
    })),
    mutableStateId: 'synthetic-current-state-001',
    normative: false,
    realSourceClosureClaim: false,
    schemaVersion: 'overlaykit-node22-source-lock-observation/v1',
    study: STUDY,
    synthetic: true,
    temporalRole: 'observation',
  };
}

export function makeExpectedEvidence() {
  const closure = makeExpectedClosure();
  const body = {
    action: null,
    authority: 'none',
    captureId: CAPTURE_ID,
    counts: closure.counts,
    layers: closure.layers,
    mounts: closure.mounts,
    normative: false,
    realSourceClosureClaim: false,
    rootSha256: closure.rootSha256,
    schemaVersion: 'overlaykit-node22-source-lock-evidence/v1',
    study: STUDY,
    synthetic: true,
    temporalRole: 'unassessed-source-lock-closure',
  };

  return {
    ...clone(body),
    semanticSha256: canonicalHash(body),
  };
}

export function fixtureCanonicalHash(value) {
  return canonicalHash(value);
}

export const fixtureConstants = Object.freeze({
  captureId: CAPTURE_ID,
  namespace: SYNTHETIC_NAMESPACE,
  study: STUDY,
});
