import { createHash } from 'node:crypto';

const STUDY = 'NODE22-SOURCE-LOCK-PREFLIGHT-001';
const SYNTHETIC_NAMESPACE = '/__overlaykit_source_lock_fixture__';

const EXPECTED_PROFILES = Object.freeze([
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

export class SourceLockProducerError extends Error {
  constructor(code) {
    super(code);
    this.name = 'SourceLockProducerError';
    this.code = code;
  }
}

function reject(code) {
  throw new SourceLockProducerError(code);
}

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

function hasExactKeys(value, expected) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return false;
  }

  const actual = Object.keys(value).sort(compareUtf8);
  const wanted = [...expected].sort(compareUtf8);
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function expectedSourceLocator(layerId) {
  return `${SYNTHETIC_NAMESPACE}/locators/${layerId}`;
}

function expectedSourceRealPath(layerId) {
  return `${SYNTHETIC_NAMESPACE}/sources/${layerId}`;
}

function expectedMountTarget(layerId) {
  return `${SYNTHETIC_NAMESPACE}/mounts/${layerId}`;
}

function pad(value) {
  return String(value).padStart(3, '0');
}

function expectedResolutionChain(runtimeIndex, length) {
  if (length === 0) {
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

  if (length === 1) {
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

function sameCanonical(left, right) {
  return JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right));
}

function validateObservationEnvelope(snapshot) {
  if (
    !hasExactKeys(snapshot, [
      'action',
      'authority',
      'captureId',
      'layers',
      'mounts',
      'mutableStateId',
      'normative',
      'realSourceClosureClaim',
      'schemaVersion',
      'study',
      'synthetic',
      'temporalRole',
    ])
  ) {
    reject('observation-shape-invalid');
  }

  if (
    snapshot.schemaVersion !== 'overlaykit-node22-source-lock-observation/v1' ||
    snapshot.study !== STUDY ||
    snapshot.temporalRole !== 'observation'
  ) {
    reject('observation-shape-invalid');
  }

  if (
    snapshot.synthetic !== true ||
    snapshot.normative !== false ||
    snapshot.realSourceClosureClaim !== false
  ) {
    reject('real-source-observation-forbidden');
  }

  if (snapshot.authority !== 'none' || snapshot.action !== null) {
    reject('authority-overclaim');
  }

  if (
    typeof snapshot.captureId !== 'string' ||
    snapshot.captureId.length === 0 ||
    typeof snapshot.mutableStateId !== 'string' ||
    snapshot.mutableStateId.length === 0
  ) {
    reject('observation-shape-invalid');
  }
}

function validateAndHashEntry(entry) {
  if (entry?.kind === 'directory') {
    if (!hasExactKeys(entry, ['kind', 'logicalPath', 'mode'])) {
      reject('descriptor-shape-invalid');
    }
    if (entry.mode !== '0555') {
      reject('descriptor-shape-invalid');
    }
    return {
      kind: entry.kind,
      logicalPath: entry.logicalPath,
      mode: entry.mode,
    };
  }

  if (entry?.kind === 'regular-file') {
    if (!hasExactKeys(entry, ['bytesUtf8', 'kind', 'logicalPath', 'mode'])) {
      reject('descriptor-shape-invalid');
    }
    if (typeof entry.bytesUtf8 !== 'string' || (entry.mode !== '0444' && entry.mode !== '0555')) {
      reject('descriptor-shape-invalid');
    }
    return {
      byteLength: Buffer.byteLength(entry.bytesUtf8, 'utf8'),
      kind: entry.kind,
      logicalPath: entry.logicalPath,
      mode: entry.mode,
      sha256: sha256(entry.bytesUtf8),
    };
  }

  reject('descriptor-shape-invalid');
}

function validateAndHashLayers(layers) {
  if (!Array.isArray(layers) || layers.length !== 25) {
    reject('layer-roster-incomplete');
  }

  const layerIds = layers.map((layer) => layer?.id);
  if (new Set(layerIds).size !== layerIds.length) {
    reject('layer-id-collision');
  }

  let descriptorCount = 0;
  let directoryCount = 0;
  let regularFileCount = 0;
  let indirectionCount = 0;

  const receipts = layers.map((layer, layerIndex) => {
    const [expectedId, expectedKind, regularCount, directoryCountForLayer, chainLength] =
      EXPECTED_PROFILES[layerIndex];

    if (
      !hasExactKeys(layer, [
        'entries',
        'id',
        'kind',
        'resolutionChain',
        'sourceLocator',
        'sourceRealPath',
      ])
    ) {
      reject('layer-shape-invalid');
    }

    if (layer.id !== expectedId || layer.kind !== expectedKind) {
      reject('layer-roster-incomplete');
    }

    if (
      layer.sourceLocator !== expectedSourceLocator(layer.id) ||
      layer.sourceRealPath !== expectedSourceRealPath(layer.id)
    ) {
      reject('source-path-rebound');
    }

    if (!Array.isArray(layer.entries)) {
      reject('descriptor-shape-invalid');
    }

    const logicalPaths = layer.entries.map((entry) => entry?.logicalPath);
    if (new Set(logicalPaths).size !== logicalPaths.length) {
      reject('descriptor-key-collision');
    }
    if (
      logicalPaths.some((logicalPath) => typeof logicalPath !== 'string') ||
      logicalPaths.some(
        (logicalPath, index) => index > 0 && compareUtf8(logicalPaths[index - 1], logicalPath) >= 0
      )
    ) {
      reject('canonical-order-invalid');
    }

    const regularObserved = layer.entries.filter((entry) => entry?.kind === 'regular-file').length;
    const directoriesObserved = layer.entries.filter((entry) => entry?.kind === 'directory').length;
    if (
      regularObserved !== regularCount ||
      directoriesObserved !== directoryCountForLayer ||
      layer.entries.length !== regularCount + directoryCountForLayer
    ) {
      reject('descriptor-roster-incomplete');
    }

    if (!Array.isArray(layer.resolutionChain)) {
      reject('indirection-shape-invalid');
    }
    if (layer.resolutionChain.length !== chainLength) {
      reject('indirection-roster-incomplete');
    }

    const expectedChain = expectedResolutionChain(layerIndex, chainLength);
    if (!sameCanonical(layer.resolutionChain, expectedChain)) {
      reject('symlink-chain-drift');
    }

    const entries = layer.entries.map(validateAndHashEntry);
    const resolutionChain = layer.resolutionChain.map((entry) => ({ ...entry }));
    descriptorCount += entries.length;
    directoryCount += directoriesObserved;
    regularFileCount += regularObserved;
    indirectionCount += layer.resolutionChain.length;

    const body = {
      entries,
      entryCount: entries.length,
      id: layer.id,
      kind: layer.kind,
      resolutionChain,
      sourceLocator: layer.sourceLocator,
      sourceRealPath: layer.sourceRealPath,
    };

    return {
      ...body,
      contentSha256: canonicalHash(body),
    };
  });

  if (descriptorCount !== 687 || directoryCount !== 74 || regularFileCount !== 613) {
    reject('descriptor-roster-incomplete');
  }
  if (indirectionCount !== 26) {
    reject('indirection-roster-incomplete');
  }

  return {
    counts: {
      descriptors: descriptorCount,
      directories: directoryCount,
      indirections: indirectionCount,
      layers: receipts.length,
      mounts: 25,
      regularFiles: regularFileCount,
    },
    receipts,
  };
}

function validateAndHashMounts(mounts, layers) {
  if (!Array.isArray(mounts) || mounts.length !== 25) {
    reject('mount-roster-incomplete');
  }

  const layerIds = mounts.map((mount) => mount?.layerId);
  if (new Set(layerIds).size !== layerIds.length) {
    reject('mount-layer-collision');
  }

  const targets = mounts.map((mount) => mount?.target);
  if (new Set(targets).size !== targets.length) {
    reject('mount-target-collision');
  }

  return mounts.map((mount, index) => {
    const layer = layers[index];
    if (
      !hasExactKeys(mount, [
        'access',
        'kind',
        'layerId',
        'sourceLocator',
        'sourceRealPath',
        'target',
      ])
    ) {
      reject('mount-shape-invalid');
    }

    if (
      mount.access !== 'read-only' ||
      mount.layerId !== layer.id ||
      mount.kind !== layer.kind ||
      mount.sourceLocator !== layer.sourceLocator ||
      mount.sourceRealPath !== layer.sourceRealPath ||
      mount.target !== expectedMountTarget(layer.id)
    ) {
      reject('mount-layer-bijection-invalid');
    }

    return {
      ...mount,
      sourceContentSha256: layer.contentSha256,
    };
  });
}

export function produceSourceLock(snapshot) {
  validateObservationEnvelope(snapshot);
  const { counts, receipts: layers } = validateAndHashLayers(snapshot.layers);
  const mounts = validateAndHashMounts(snapshot.mounts, layers);
  const closureBody = { counts, layers, mounts };
  const body = {
    action: null,
    authority: 'none',
    captureId: snapshot.captureId,
    counts,
    layers,
    mounts,
    normative: false,
    realSourceClosureClaim: false,
    rootSha256: canonicalHash(closureBody),
    schemaVersion: 'overlaykit-node22-source-lock-evidence/v1',
    study: STUDY,
    synthetic: true,
    temporalRole: 'unassessed-source-lock-closure',
  };

  return {
    ...body,
    semanticSha256: canonicalHash(body),
  };
}
