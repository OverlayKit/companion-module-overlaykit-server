import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  H048_GIT_COMMAND_POLICY,
  H048_PREDICATES,
  H048_UNRESOLVED_INDIRECTION_STATUSES,
  admitSetAnchor,
  assertCanonicalRoot,
  buildArchiveInventory,
  buildInventory,
  canonicalJson,
  createGitReader,
  framedSetSha256,
  sha256,
  snapshotRepository,
} from './inventory-lib.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
export const H048_ARTIFACT_ROOT = path.join(REPOSITORY_ROOT, 'artifacts', 'h048');
const HARNESS_REPOSITORY_KEY = 'h048-local-unsigned-source-closure';
const EXPECTED_REPOSITORIES = Object.freeze([
  Object.freeze({
    key: 'OverlayKit/companion-module-overlaykit-server',
    localLocator: '.',
    commit: '2d46d1c60e7aced224b47a8857d93015c5fb5c91',
    tree: '1ea80375569a43bf7d1ef53b719cf878658ad3c7',
    entryCount: 250,
    lsTreeSha256: '418f8d2ea8b50416c04f87a3dcc73caaf8b9360cf3bdaa6ffae6b80b0f90944d',
    refSetSha256: 'ef9b9c863e0061925eb58fb85882a2d56484d18b7cd811873f9c814a834f39f1',
  }),
  Object.freeze({
    key: 'OverlayKit/overlaykit',
    localLocator: '../overlaykit',
    commit: '9a5585de196ff972993c7ff81bf9c1461c47eaae',
    tree: '214f76e29d7c6a48497a6f26ebd69cfa80dc88ce',
    entryCount: 429,
    lsTreeSha256: 'c2cc0a619e0e1532a6de23e4dc4571e18bb0d5eff7add45d93d9ff6fa13bde28',
    refSetSha256: '51bcea856b0d74b10907203040bbeb9245ee11fb0c8b6bc8bf19f4be6182439e',
  }),
]);
const EXPECTED_CLAIM_BOUNDARY = Object.freeze({
  includes: Object.freeze([
    'the exact two nominated Git main trees',
    'tracked archive members reachable from those trees',
    'explicit repository-local and cross-repository indirections admitted by the review map',
    'the accepted repo-set and ref-set anchors only when their exact preimages are available',
  ]),
  excludes: Object.freeze([
    'inaccessible organization variables and secrets',
    'unreported or inaccessible private sources',
    'wikis, issues, projects, deleted refs, runbooks, and CMDB',
    'host configuration, current host state, live observation, intent, compliance, drift, cause, and remedy',
    'actual external operational ownership',
    'installation, configuration, start, stop, restart, signaling, reconciliation, publication, ADR, SPEC, and production policy',
  ]),
  authority: 'none',
  action: null,
});
const EXPECTED_TARGET = Object.freeze({
  imageReference: 'ghcr.io/bitfocus/companion/companion:v4.3.3',
  imageId: 'sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e',
  hostRole: 'spec-0001-linux-production-host',
  hostRoleSpecification: 'SPEC-0001',
  hostRoleSpecificationContentHash:
    '917f1ca2febe17f8901ab71f91a0b0135402f9be972a876f233fcd5c789b8179',
  imageInterpretation: 'historical-evidence-selector',
});
const EXPECTED_OUTCOME_POLICY = Object.freeze({
  invalid:
    'Any anchor, schema, source, archive, or artifact integrity failure is invalid evidence.',
  inconclusive:
    'Any opaque, omitted, ambiguous, conflicting, unresolved, or unreviewed source or potentially semantic relationship prevents supported or refuted.',
  supported:
    'Complete coverage, zero unknowns, and at least one fully linked eight-predicate desired-state chain.',
  refuted:
    'Complete coverage, zero unknowns, and zero fully linked eight-predicate desired-state chains.',
});

export const H048_SOURCE_PATHS = Object.freeze(
  [
    '.gitignore',
    '.overlaykit/governance/changes/CHG-0024.json',
    '.overlaykit/governance/manifest.json',
    'lab/h048/archive-lib.mjs',
    'lab/h048/inventory-lib.mjs',
    'lab/h048/inventory-lib.test.mjs',
    'lab/h048/review-map.json',
    'lab/h048/run.mjs',
    'lab/h048/run.test.mjs',
    'lab/h048/schema.test.mjs',
    'lab/h048/schemas/external-desired-state-run.schema.json',
    'lab/h048/subject-lock.json',
    'lab/h048/verify.mjs',
    'lab/h048/verify.test.mjs',
  ].sort()
);

function assertion(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, expected, label) {
  assertion(
    value !== null && typeof value === 'object' && !Array.isArray(value),
    `${label} must be an object`
  );
  assertion(
    canonicalJson(Object.keys(value).sort()) === canonicalJson([...expected].sort()),
    `${label} has unexpected keys`
  );
}

function parseJsonBytes(bytes, label) {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch (error) {
    throw new Error(`${label} is invalid JSON: ${error.message}`);
  }
}

export function validateSubjectLock(subjectLock) {
  exactKeys(
    subjectLock,
    [
      'schemaVersion',
      'hypothesis',
      'acceptedAt',
      'acceptedBy',
      'repoSet',
      'repositories',
      'target',
      'predicateOrder',
      'outcomePolicy',
      'claimBoundary',
    ],
    'subject lock'
  );
  assertion(
    subjectLock?.schemaVersion === 'overlaykit-h048-subject-lock/v1',
    'subject-lock schema'
  );
  exactKeys(
    subjectLock.repoSet,
    ['sha256', 'preimageStatus', 'canonicalization', 'preimage'],
    'subject-lock repo-set'
  );
  assertion(subjectLock.hypothesis === 'H-048', 'subject-lock hypothesis');
  assertion(subjectLock.acceptedAt === '2026-07-27', 'subject-lock acceptance date');
  assertion(subjectLock.acceptedBy === '@rodrigoteamx', 'subject-lock principal');
  assertion(
    subjectLock.repoSet.sha256 ===
      'c7d16003f59e7aab2d22dbdbed0812ea2096060215c9a67592caf11e00a97ee5',
    'subject-lock repo-set differs'
  );
  admitSetAnchor(subjectLock.repoSet, 'subject-lock repo-set');
  assertion(
    Array.isArray(subjectLock.repositories) &&
      subjectLock.repositories.length === EXPECTED_REPOSITORIES.length,
    'subject-lock repositories differ'
  );
  for (let index = 0; index < EXPECTED_REPOSITORIES.length; index += 1) {
    const actual = subjectLock.repositories[index];
    const expected = EXPECTED_REPOSITORIES[index];
    exactKeys(
      actual,
      ['key', 'localLocator', 'commit', 'tree', 'entryCount', 'lsTreeSha256', 'refSet'],
      `subject-lock repository ${index}`
    );
    for (const field of ['key', 'localLocator', 'commit', 'tree', 'entryCount', 'lsTreeSha256']) {
      assertion(actual[field] === expected[field], `subject-lock ${expected.key} ${field} differs`);
    }
    exactKeys(
      actual.refSet,
      ['sha256', 'preimageStatus', 'canonicalization', 'preimage'],
      `subject-lock ${expected.key} ref-set`
    );
    assertion(actual.refSet.sha256 === expected.refSetSha256, `${expected.key} ref-set differs`);
    admitSetAnchor(actual.refSet, `${expected.key} ref-set`);
  }
  assertion(
    canonicalJson(subjectLock.target) === canonicalJson(EXPECTED_TARGET),
    'subject-lock target differs'
  );
  assertion(
    canonicalJson(subjectLock.predicateOrder) === canonicalJson(H048_PREDICATES),
    'subject-lock predicate order differs'
  );
  assertion(
    canonicalJson(subjectLock.outcomePolicy) === canonicalJson(EXPECTED_OUTCOME_POLICY),
    'subject-lock outcome policy differs'
  );
  exactKeys(
    subjectLock.claimBoundary,
    ['includes', 'excludes', 'authority', 'action'],
    'subject-lock claim boundary'
  );
  assertion(
    canonicalJson(subjectLock.claimBoundary) === canonicalJson(EXPECTED_CLAIM_BOUNDARY),
    'subject-lock claim boundary differs'
  );
}

function readCanonicalFile(repositoryRoot, relativePath) {
  assertion(
    typeof repositoryRoot === 'string' && path.isAbsolute(repositoryRoot),
    'repository root must be absolute'
  );
  assertion(
    typeof relativePath === 'string' &&
      relativePath !== '' &&
      !relativePath.startsWith('/') &&
      !relativePath.includes('\\') &&
      relativePath
        .split('/')
        .every((segment) => segment !== '' && segment !== '.' && segment !== '..'),
    `unsafe source path: ${relativePath}`
  );
  const absolutePath = path.join(repositoryRoot, relativePath);
  const metadata = lstatSync(absolutePath);
  assertion(
    metadata.isFile() && !metadata.isSymbolicLink(),
    `source is not a regular file: ${relativePath}`
  );
  assertion(
    realpathSync(absolutePath) === absolutePath,
    `source path is not canonical: ${relativePath}`
  );
  const permissions = metadata.mode & 0o777;
  assertion([0o644, 0o755].includes(permissions), `source mode is unsupported: ${relativePath}`);
  const bytes = readFileSync(absolutePath);
  return {
    path: relativePath,
    mode: permissions === 0o755 ? '100755' : '100644',
    byteLength: bytes.length,
    sha256: sha256(bytes),
    bytes,
  };
}

export function readLocalSourceClosure(repositoryRoot = REPOSITORY_ROOT) {
  assertion(realpathSync(repositoryRoot) === repositoryRoot, 'repository root is not canonical');
  const sources = H048_SOURCE_PATHS.map((relativePath) =>
    readCanonicalFile(repositoryRoot, relativePath)
  );
  const sourceSetSha256 = framedSetSha256(
    sources.map(({ path: sourcePath, mode, byteLength, sha256: digest }) => ({
      repository: HARNESS_REPOSITORY_KEY,
      path: sourcePath,
      mode,
      byteLength,
      sha256: digest,
    }))
  );
  const blobs = new Map();
  for (const source of sources) {
    const existing = blobs.get(source.sha256);
    if (existing === undefined) blobs.set(source.sha256, source.bytes);
    else
      assertion(
        existing.equals(source.bytes),
        `SHA-256 collision in source closure: ${source.path}`
      );
  }
  return {
    document: {
      schemaVersion: 'overlaykit-h048-local-source-closure/v1',
      hypothesis: 'H-048',
      admission: {
        kind: 'local-content-addressed-unsigned',
        signatureStatus: 'absent-not-authorized',
        commit: null,
      },
      sourceCount: sources.length,
      uniqueBlobCount: blobs.size,
      sourceSetSha256,
      sources: sources.map(({ bytes: _bytes, ...source }) => ({
        repository: HARNESS_REPOSITORY_KEY,
        ...source,
        blobFile: `sources/${source.sha256}.bin`,
      })),
    },
    blobs,
  };
}

function assertLocalSourceClosureSnapshot(snapshot, label) {
  assertion(
    snapshot !== null &&
      typeof snapshot === 'object' &&
      snapshot.document?.schemaVersion === 'overlaykit-h048-local-source-closure/v1' &&
      snapshot.document.hypothesis === 'H-048' &&
      snapshot.blobs instanceof Map,
    `${label} is invalid`
  );
  for (const source of snapshot.document.sources) {
    const bytes = snapshot.blobs.get(source.sha256);
    assertion(Buffer.isBuffer(bytes), `${label} omits source bytes: ${source.path}`);
    assertion(bytes.length === source.byteLength, `${label} source length differs: ${source.path}`);
    assertion(sha256(bytes) === source.sha256, `${label} source digest differs: ${source.path}`);
  }
}

function sourceBytesFromClosure(snapshot, relativePath) {
  const source = snapshot.document.sources.find((candidate) => candidate.path === relativePath);
  assertion(source !== undefined, `source closure omits ${relativePath}`);
  const bytes = snapshot.blobs.get(source.sha256);
  assertion(Buffer.isBuffer(bytes), `source closure omits bytes for ${relativePath}`);
  return bytes;
}

function assertArtifactIgnoreContract(bytes) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (error) {
    throw new Error(`H-048 .gitignore is not UTF-8: ${error.message}`);
  }
  assertion(
    text.split(/\r?\n/u).includes('artifacts/'),
    'H-048 .gitignore lacks the exact artifacts/ rule'
  );
}

const MODULE_LOAD_SOURCE_CLOSURE = readLocalSourceClosure(REPOSITORY_ROOT);
assertLocalSourceClosureSnapshot(MODULE_LOAD_SOURCE_CLOSURE, 'module-load source closure');
assertArtifactIgnoreContract(sourceBytesFromClosure(MODULE_LOAD_SOURCE_CLOSURE, '.gitignore'));

function normalizedArtifact(file, value) {
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
  return {
    file,
    byteLength: bytes.length,
    sha256: sha256(bytes),
    bytes,
  };
}

function sanitizedArchiveInventory(archiveInventory) {
  return {
    policyVersion: 'overlaykit-h047-archive-expansion/v1',
    limits: archiveInventory.limits,
    observations: archiveInventory.observations,
    roots: archiveInventory.roots,
    archives: archiveInventory.archives,
    members: archiveInventory.members,
  };
}

function buildSourceMap(subjectLock, snapshots, archiveInventory) {
  const entries = snapshots
    .flatMap((snapshot) => snapshot.sourceEntries)
    .sort((left, right) => {
      const repositoryOrder = Buffer.compare(
        Buffer.from(left.repository, 'utf8'),
        Buffer.from(right.repository, 'utf8')
      );
      return repositoryOrder === 0
        ? Buffer.compare(Buffer.from(left.path, 'utf8'), Buffer.from(right.path, 'utf8'))
        : repositoryOrder;
    });
  return {
    schemaVersion: 'overlaykit-h048-source-map/v1',
    hypothesis: 'H-048',
    claimBoundary: subjectLock.claimBoundary,
    claimBoundaryCanonicalSha256: sha256(
      Buffer.from(canonicalJson(subjectLock.claimBoundary), 'utf8')
    ),
    acceptedRepoSetSha256: subjectLock.repoSet.sha256,
    repositories: snapshots.map((snapshot) => ({
      key: snapshot.repository,
      commit: snapshot.commit,
      tree: snapshot.tree,
      entryCount: snapshot.entries.length,
      lsTreeSha256: sha256(snapshot.treeBytes),
      sourceSetSha256: snapshot.sourceSetSha256,
    })),
    entryCount: entries.length,
    entries,
    sourceSetSha256: framedSetSha256(
      entries.map(({ repository, path: sourcePath, mode, byteLength, sha256: digest }) => ({
        repository,
        path: sourcePath,
        mode,
        byteLength,
        sha256: digest,
      }))
    ),
    archives: sanitizedArchiveInventory(archiveInventory),
  };
}

export function buildH048Bundle({
  repositoryRoot = REPOSITORY_ROOT,
  sourceClosureReader = readLocalSourceClosure,
} = {}) {
  assertion(process.versions.node === '22.20.0', 'H-048 producer requires exact Node 22.20.0');
  assertion(path.isAbsolute(repositoryRoot), 'repository root must be absolute');
  assertion(realpathSync(repositoryRoot) === repositoryRoot, 'repository root is not canonical');
  assertion(
    repositoryRoot === REPOSITORY_ROOT,
    'H-048 source execution must remain bound to the loaded repository root'
  );
  assertion(typeof sourceClosureReader === 'function', 'source closure reader');
  const sourceClosureBefore = sourceClosureReader(repositoryRoot);
  assertLocalSourceClosureSnapshot(sourceClosureBefore, 'pre-execution source closure');
  assertArtifactIgnoreContract(sourceBytesFromClosure(sourceClosureBefore, '.gitignore'));
  assertion(
    canonicalJson(sourceClosureBefore.document) ===
      canonicalJson(MODULE_LOAD_SOURCE_CLOSURE.document),
    'pre-execution source closure differs from module-load bytes'
  );
  const subjectLockBytes = sourceBytesFromClosure(
    sourceClosureBefore,
    'lab/h048/subject-lock.json'
  );
  const reviewMapBytes = sourceBytesFromClosure(sourceClosureBefore, 'lab/h048/review-map.json');
  const subjectLock = parseJsonBytes(subjectLockBytes, 'H-048 subject lock');
  const reviewMap = parseJsonBytes(reviewMapBytes, 'H-048 review map');
  validateSubjectLock(subjectLock);
  const roots = new Set();
  const snapshots = [];
  const readerReceipts = [];

  for (const repositoryLock of subjectLock.repositories) {
    const root = path.resolve(repositoryRoot, repositoryLock.localLocator);
    assertion(!roots.has(root), `duplicate repository root: ${root}`);
    roots.add(root);
    const reader = createGitReader({ root, repositoryLock });
    const snapshot = snapshotRepository({ repositoryLock, root, reader });
    snapshots.push(snapshot);
    readerReceipts.push({
      repository: repositoryLock.key,
      invocationCounts: reader.counts(),
    });
  }
  assertion(snapshots.length === 2, 'H-048 requires exactly two repository snapshots');

  const archiveInventory = buildArchiveInventory(snapshots);
  const sourceMap = buildSourceMap(subjectLock, snapshots, archiveInventory);
  assertion(sourceMap.entryCount === 679, 'H-048 main-tree entry total differs');
  const inventory = buildInventory({
    subjectLock,
    subjectLockBytes,
    reviewMap,
    snapshots,
    archiveInventory,
  });
  const { candidateIndex, reviewUniverse } = inventory;
  candidateIndex.review.sourceFileSha256 = sha256(reviewMapBytes);
  const sourceClosureAfter = sourceClosureReader(repositoryRoot);
  assertLocalSourceClosureSnapshot(sourceClosureAfter, 'post-execution source closure');
  assertion(
    canonicalJson(sourceClosureAfter.document) === canonicalJson(sourceClosureBefore.document),
    'source closure changed during producer execution'
  );
  const localSourceClosure = sourceClosureBefore;
  const sourceClosureArtifact = normalizedArtifact(
    'source-closure.json',
    localSourceClosure.document
  );
  const sourceMapArtifact = normalizedArtifact('source-map.json', sourceMap);
  const reviewUniverseArtifact = normalizedArtifact('review-universe.json', reviewUniverse);
  assertion(
    reviewUniverseArtifact.file === reviewMap.reviewUniverse.file &&
      reviewUniverseArtifact.byteLength === reviewMap.reviewUniverse.byteLength &&
      reviewUniverseArtifact.sha256 === reviewMap.reviewUniverse.sha256,
    'review universe artifact differs from review reference'
  );
  const candidateIndexArtifact = normalizedArtifact('candidate-index.json', candidateIndex);

  const semantic = {
    schemaVersion: 'overlaykit-h048-external-desired-state-run/v1',
    hypothesis: 'H-048',
    boundary: {
      acceptedAt: subjectLock.acceptedAt,
      acceptedBy: subjectLock.acceptedBy,
      repoSet: subjectLock.repoSet,
      repositories: subjectLock.repositories.map((repository) => ({
        key: repository.key,
        commit: repository.commit,
        tree: repository.tree,
        entryCount: repository.entryCount,
        lsTreeSha256: repository.lsTreeSha256,
        refSet: repository.refSet,
      })),
    },
    localSourceClosure: {
      kind: localSourceClosure.document.admission.kind,
      signatureStatus: localSourceClosure.document.admission.signatureStatus,
      commit: null,
      sourceCount: localSourceClosure.document.sourceCount,
      uniqueBlobCount: localSourceClosure.document.uniqueBlobCount,
      sourceSetSha256: localSourceClosure.document.sourceSetSha256,
    },
    target: subjectLock.target,
    artifacts: {
      sourceClosure: {
        file: sourceClosureArtifact.file,
        byteLength: sourceClosureArtifact.byteLength,
        sha256: sourceClosureArtifact.sha256,
      },
      sourceMap: {
        file: sourceMapArtifact.file,
        byteLength: sourceMapArtifact.byteLength,
        sha256: sourceMapArtifact.sha256,
      },
      reviewUniverse: {
        file: reviewUniverseArtifact.file,
        byteLength: reviewUniverseArtifact.byteLength,
        sha256: reviewUniverseArtifact.sha256,
      },
      candidateIndex: {
        file: candidateIndexArtifact.file,
        byteLength: candidateIndexArtifact.byteLength,
        sha256: candidateIndexArtifact.sha256,
      },
    },
    summary: {
      repositories: snapshots.length,
      mainTreeEntries: sourceMap.entryCount,
      trackedArchiveRoots: archiveInventory.roots.length,
      expandedArchiveOccurrences: archiveInventory.observations.archives,
      expandedArchiveMembers: archiveInventory.observations.regularMembers,
      candidates: candidateIndex.candidates.length,
      indirections: candidateIndex.indirections.length,
      unresolvedIndirections: candidateIndex.indirections.filter((indirection) =>
        H048_UNRESOLVED_INDIRECTION_STATUSES.includes(indirection.status)
      ).length,
      unknowns: candidateIndex.unknowns.length,
      eligibleChains: candidateIndex.eligibleChains.length,
      missingPredicates: candidateIndex.missingPredicates,
      coverageComplete: candidateIndex.coverageComplete,
    },
    outcome: candidateIndex.outcome,
    adrAssessment: candidateIndex.adrAssessment,
    capabilityAudit: {
      mode: 'two-repository-offline-read-only',
      nodeVersion: process.versions.node,
      gitExecutable: '/usr/bin/git',
      commandPolicy: H048_GIT_COMMAND_POLICY,
      observedRepositories: readerReceipts,
      gitNoLazyFetch: true,
      gitOptionalLocks: false,
      repositoryObjectReadsOnly: true,
      localIgnoredEvidenceWriteOnly: true,
      sourceSignatureStatus: 'absent-not-authorized',
      networkObserved: false,
      dockerObserved: false,
      usbObserved: false,
      procfsObserved: false,
      sysfsObserved: false,
      devfsObserved: false,
      systemdObserved: false,
      hidrawObserved: false,
      signalObserved: false,
      productionMutationObserved: false,
    },
    authority: 'none',
    action: null,
    claimBoundary: subjectLock.claimBoundary,
    claimBoundaryCanonicalSha256: sha256(
      Buffer.from(canonicalJson(subjectLock.claimBoundary), 'utf8')
    ),
  };
  const run = {
    ...semantic,
    semanticEvidenceSha256: sha256(Buffer.from(canonicalJson(semantic), 'utf8')),
  };
  return {
    run,
    sourceClosure: localSourceClosure.document,
    sourceMap,
    reviewUniverse,
    candidateIndex,
    sourceBlobs: localSourceClosure.blobs,
    serialized: {
      run: Buffer.from(`${canonicalJson(run)}\n`, 'utf8'),
      sourceClosure: sourceClosureArtifact.bytes,
      sourceMap: sourceMapArtifact.bytes,
      reviewUniverse: reviewUniverseArtifact.bytes,
      candidateIndex: candidateIndexArtifact.bytes,
    },
  };
}

function ensureDirectory(directory, { privateMode = true } = {}) {
  if (existsSync(directory)) {
    assertCanonicalRoot(directory);
    if (privateMode) {
      assertion((lstatSync(directory).mode & 0o777) === 0o700, `${directory} mode differs`);
    }
    return;
  }
  mkdirSync(directory, { mode: 0o700 });
  assertCanonicalRoot(directory);
  if (privateMode) {
    assertion((lstatSync(directory).mode & 0o777) === 0o700, `${directory} mode differs`);
  }
}

function writeExclusive(filePath, bytes) {
  writeFileSync(filePath, bytes, { flag: 'wx', mode: 0o600 });
  const metadata = lstatSync(filePath);
  assertion(metadata.isFile() && !metadata.isSymbolicLink(), `artifact is unsafe: ${filePath}`);
  assertion((metadata.mode & 0o777) === 0o600, `artifact mode differs: ${filePath}`);
  assertion(statSync(filePath).size === bytes.length, `artifact length differs: ${filePath}`);
}

export function writeBundle(runId, bundle) {
  assertion(process.versions.node === '22.20.0', 'H-048 writer requires exact Node 22.20.0');
  assertion(/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u.test(runId), 'invalid H-048 run id');
  ensureDirectory(path.dirname(H048_ARTIFACT_ROOT), { privateMode: false });
  ensureDirectory(H048_ARTIFACT_ROOT);
  const outputDirectory = path.join(H048_ARTIFACT_ROOT, runId);
  mkdirSync(outputDirectory, { mode: 0o700 });
  assertCanonicalRoot(outputDirectory);
  const sourceDirectory = path.join(outputDirectory, 'sources');
  mkdirSync(sourceDirectory, { mode: 0o700 });
  assertCanonicalRoot(sourceDirectory);

  for (const [digest, bytes] of [...bundle.sourceBlobs.entries()].sort(([left], [right]) =>
    left.localeCompare(right)
  )) {
    assertion(/^[0-9a-f]{64}$/u.test(digest), 'invalid source blob digest');
    writeExclusive(path.join(sourceDirectory, `${digest}.bin`), bytes);
  }
  for (const [name, bytes] of [
    ['source-closure.json', bundle.serialized.sourceClosure],
    ['source-map.json', bundle.serialized.sourceMap],
    ['review-universe.json', bundle.serialized.reviewUniverse],
    ['candidate-index.json', bundle.serialized.candidateIndex],
    ['run.json', bundle.serialized.run],
  ]) {
    writeExclusive(path.join(outputDirectory, name), bytes);
  }
  return outputDirectory;
}

function parseArguments(argv) {
  assertion(
    argv.length === 2 && argv[0] === '--run-id',
    'Usage: node lab/h048/run.mjs --run-id <id>'
  );
  assertion(/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u.test(argv[1]), 'invalid H-048 run id');
  return { runId: argv[1] };
}

if (
  process.argv[1] !== undefined &&
  realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
) {
  assertion(process.versions.node === '22.20.0', 'H-048 requires exact Node 22.20.0');
  const { runId } = parseArguments(process.argv.slice(2));
  const outputDirectory = writeBundle(runId, buildH048Bundle());
  const run = parseJsonBytes(readFileSync(path.join(outputDirectory, 'run.json')), 'written run');
  process.stdout.write(
    `${JSON.stringify({
      runId,
      outputDirectory,
      outcome: run.outcome,
      semanticEvidenceSha256: run.semanticEvidenceSha256,
      authority: run.authority,
      action: run.action,
    })}\n`
  );
}
