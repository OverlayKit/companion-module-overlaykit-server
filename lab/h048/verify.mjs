import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expandTarGzipForest } from './archive-lib.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const ARTIFACT_ROOT = path.join(REPOSITORY_ROOT, 'artifacts', 'h048');
const GIT_EXECUTABLE = '/usr/bin/git';
const HARNESS_REPOSITORY_KEY = 'h048-local-unsigned-source-closure';
const OID_PATTERN = /^[0-9a-f]{40}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const ARCHIVE_PATH_PATTERN = /\.(?:tar\.gz|tgz)$/iu;
const FATAL_UTF8 = new TextDecoder('utf-8', { fatal: true });
const EXPECTED_NODE_VERSION = '22.20.0';
const EXPECTED_JSON_SCHEMA_DIALECT = [
  'https:',
  '',
  'json-schema.org',
  'draft',
  '2020-12',
  'schema',
].join('/');
const EXPECTED_HUMAN_ACCEPTANCE_SHA256 = null;

const SOURCE_PATHS = Object.freeze(
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

const PREDICATES = Object.freeze([
  'effectiveAcceptedProductionAuthority',
  'exactImageReferenceAndId',
  'spec0001LinuxHostBinding',
  'deploymentPresenceAndCardinality',
  'repositoryDeclaredLifecycleOwner',
  'reconcilerMechanism',
  'absenceToConvergenceRule',
  'explicitLinkClosure',
]);

const COMMAND_POLICY = Object.freeze([
  'git cat-file blob <oid>',
  'git ls-tree -rz --full-tree <commit>',
  'git rev-parse <commit>^{tree}',
]);

const UNRESOLVED_INDIRECTION_STATUSES = Object.freeze([
  'subject-commit-mismatch',
  'unscoped-commit-reference',
  'unresolved-github-pull-request',
  'unversioned-subject-reference',
]);

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
const EXPECTED_CLAIM_BOUNDARY_CANONICAL_SHA256 =
  '3493ff642bc71755e0e2f4c492c552267ec15efd7500b473b477c11e00058224';

const SIGNAL_POLICY = Object.freeze([
  [
    'accepted-authority-language',
    /\b(?:accepted|authority|authoritative|normative|policy|governance)\b/iu,
  ],
  ['companion-product', /\b(?:bitfocus\s+)?companion\b/iu],
  ['exact-image-reference', /ghcr\.io\/bitfocus\/companion\/companion:v4\.3\.3/u],
  ['exact-image-id', /sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e/u],
  ['spec-linux-host', /\bSPEC-0001\b|\blinux production(?:-| )host\b|\bproduction host\b/iu],
  [
    'desired-state-language',
    /\bdesired(?:-| )state\b|\bmust (?:remain|be|run|exist|start|maintain)\b|\brequired deployment\b/iu,
  ],
  [
    'presence-cardinality-language',
    /\bpresence\b|\bcardinality\b|\breplicas?\b|\bexactly one\b|\bone (?:module|instance|deployment|container|process)\b/iu,
  ],
  [
    'lifecycle-owner-language',
    /\blifecycle(?:-| )owner\b|\bowner\b|\bownership\b|\bmaintainer\b/iu,
  ],
  [
    'reconciler-language',
    /\breconcil(?:e|er|iation|ing)\b|\bcontroller\b|\bsupervisor\b|\brestart(?:-| )policy\b|\bsystemd\b|\bkubernetes\b|\bhelm\b|\bterraform\b|\bansible\b/iu,
  ],
  [
    'absence-convergence-language',
    /\b(?:absence|absent|missing)\b[\s\S]{0,160}\b(?:converge|restore|recreate|restart|start|run)\b|\b(?:converge|restore|recreate|restart|start|run)\b[\s\S]{0,160}\b(?:absence|absent|missing)\b/iu,
  ],
  [
    'cross-repository-link',
    /OverlayKit\/companion-module-overlaykit-server|github\.com\/OverlayKit\/(?:overlaykit|companion-module-overlaykit-server)/u,
  ],
  [
    'deployment-surface-language',
    /\bdeployment\b|\bcontainer\b|\bdocker(?:-| )compose\b|\bservice\b|\binstall(?:ed|ation)?\b/iu,
  ],
]);

const KNOWN_NON_TEXT_EXTENSIONS = new Set([
  '.avif',
  '.bin',
  '.gif',
  '.ico',
  '.jpeg',
  '.jpg',
  '.pdf',
  '.png',
  '.sqlite',
  '.svgz',
  '.webp',
  '.woff',
  '.woff2',
  '.zip',
]);

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

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function assertGitBlobIdentity(oid, bytes) {
  assertion(OID_PATTERN.test(oid), 'Git blob object ID is invalid');
  assertion(Buffer.isBuffer(bytes), 'Git blob content must be bytes');
  const reconstructed = createHash('sha1')
    .update(Buffer.from(`blob ${bytes.length}\0`, 'utf8'))
    .update(bytes)
    .digest('hex');
  assertion(reconstructed === oid, `Git blob bytes do not reproduce ls-tree OID: ${oid}`);
}

export function assertH048VerifierGitBlobIdentityForTest(oid, bytes) {
  assertGitBlobIdentity(oid, bytes);
}

function byteCompare(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(FATAL_UTF8.decode(bytes));
  } catch (error) {
    throw new Error(`${label} is invalid JSON: ${error.message}`);
  }
}

function assertCanonicalJsonArtifact(bytes, value, label) {
  const expectedBytes = Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
  assertion(bytes.equals(expectedBytes), `${label} is not exact canonical JSON bytes`);
}

function validateCapturedRunSchemaIdentity(schema) {
  assertion(
    schema !== null && typeof schema === 'object' && !Array.isArray(schema),
    'captured run schema must be an object'
  );
  assertion(schema.$schema === EXPECTED_JSON_SCHEMA_DIALECT, 'captured run schema dialect differs');
  assertion(
    schema.$id === 'overlaykit-h048-external-desired-state-run/v1',
    'captured run schema identity differs'
  );
  assertion(
    schema.type === 'object' && schema.additionalProperties === false,
    'captured run schema root envelope differs'
  );
  assertion(
    schema.properties?.schemaVersion?.const === 'overlaykit-h048-external-desired-state-run/v1' &&
      schema.properties?.hypothesis?.const === 'H-048',
    'captured run schema subject differs'
  );
}

function validateSubjectLock(subjectLock) {
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
  assertion(subjectLock.schemaVersion === 'overlaykit-h048-subject-lock/v1', 'subject schema');
  assertion(subjectLock.hypothesis === 'H-048', 'subject hypothesis');
  assertion(subjectLock.acceptedAt === '2026-07-27', 'subject acceptance date');
  assertion(subjectLock.acceptedBy === '@rodrigoteamx', 'subject principal');
  exactKeys(
    subjectLock.repoSet,
    ['sha256', 'preimageStatus', 'canonicalization', 'preimage'],
    'subject repo-set'
  );
  assertion(
    subjectLock.repoSet.sha256 ===
      'c7d16003f59e7aab2d22dbdbed0812ea2096060215c9a67592caf11e00a97ee5',
    'subject repo-set differs'
  );
  admitSetAnchor(subjectLock.repoSet, 'subject repo-set');
  assertion(
    Array.isArray(subjectLock.repositories) &&
      subjectLock.repositories.length === EXPECTED_REPOSITORIES.length,
    'subject repository set differs'
  );
  for (let index = 0; index < EXPECTED_REPOSITORIES.length; index += 1) {
    const actual = subjectLock.repositories[index];
    const expected = EXPECTED_REPOSITORIES[index];
    exactKeys(
      actual,
      ['key', 'localLocator', 'commit', 'tree', 'entryCount', 'lsTreeSha256', 'refSet'],
      `subject repository ${expected.key}`
    );
    for (const field of ['key', 'localLocator', 'commit', 'tree', 'entryCount', 'lsTreeSha256']) {
      assertion(actual[field] === expected[field], `subject ${expected.key} ${field} differs`);
    }
    exactKeys(
      actual.refSet,
      ['sha256', 'preimageStatus', 'canonicalization', 'preimage'],
      `${expected.key} ref-set`
    );
    assertion(actual.refSet.sha256 === expected.refSetSha256, `${expected.key} ref-set differs`);
    admitSetAnchor(actual.refSet, `${expected.key} ref-set`);
  }
  exactKeys(
    subjectLock.target,
    [
      'imageReference',
      'imageId',
      'hostRole',
      'hostRoleSpecification',
      'hostRoleSpecificationContentHash',
      'imageInterpretation',
    ],
    'subject target'
  );
  assertion(
    canonicalJson(subjectLock.target) === canonicalJson(EXPECTED_TARGET),
    'subject target differs'
  );
  assertion(
    canonicalJson(subjectLock.predicateOrder) === canonicalJson(PREDICATES),
    'subject predicates differ'
  );
  exactKeys(
    subjectLock.outcomePolicy,
    ['invalid', 'inconclusive', 'supported', 'refuted'],
    'subject outcome policy'
  );
  assertion(
    canonicalJson(subjectLock.outcomePolicy) === canonicalJson(EXPECTED_OUTCOME_POLICY),
    'subject outcome policy differs'
  );
  exactKeys(
    subjectLock.claimBoundary,
    ['includes', 'excludes', 'authority', 'action'],
    'subject claim boundary'
  );
  assertion(
    canonicalJson(subjectLock.claimBoundary) === canonicalJson(EXPECTED_CLAIM_BOUNDARY),
    'subject claim boundary differs'
  );
  assertion(
    sha256(Buffer.from(canonicalJson(subjectLock.claimBoundary), 'utf8')) ===
      EXPECTED_CLAIM_BOUNDARY_CANONICAL_SHA256,
    'subject claim boundary digest differs'
  );
}

function admitSetAnchor(anchor, label = 'set anchor') {
  assertion(
    anchor !== null && typeof anchor === 'object' && !Array.isArray(anchor),
    `${label} must be an object`
  );
  assertion(SHA256_PATTERN.test(anchor.sha256), `${label} SHA-256`);
  if (anchor.preimageStatus === 'unavailable') {
    assertion(
      anchor.preimage === null && anchor.canonicalization === null,
      `${label} unavailable state must not carry a preimage`
    );
    return {
      admitted: false,
      reasonCode: 'accepted-source-anchor-opaque',
      sha256: anchor.sha256,
    };
  }
  assertion(anchor.preimageStatus === 'available', `${label} preimage status`);
  assertion(
    anchor.canonicalization === 'exact-base64-decoded-bytes/v1',
    `${label} canonicalization is unsupported`
  );
  assertion(typeof anchor.preimage === 'string' && anchor.preimage !== '', `${label} preimage`);
  const bytes = Buffer.from(anchor.preimage, 'base64');
  assertion(
    bytes.toString('base64') === anchor.preimage,
    `${label} preimage is not canonical base64`
  );
  assertion(sha256(bytes) === anchor.sha256, `${label} preimage digest differs`);
  return {
    admitted: true,
    reasonCode: 'exact-preimage-admitted',
    sha256: anchor.sha256,
    byteLength: bytes.length,
  };
}

function safePath(value) {
  return (
    typeof value === 'string' &&
    value !== '' &&
    !value.startsWith('/') &&
    !/^[A-Za-z]:/u.test(value) &&
    !/[\u0000-\u001f\u007f]/u.test(value) &&
    !value.includes('\\') &&
    value.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..')
  );
}

function parseTree(treeBytes) {
  assertion(Buffer.isBuffer(treeBytes), 'tree stream must be bytes');
  assertion(treeBytes.length > 0 && treeBytes.at(-1) === 0, 'tree stream must be NUL terminated');
  const entries = [];
  const paths = new Set();
  let start = 0;
  for (let index = 0; index < treeBytes.length; index += 1) {
    if (treeBytes[index] !== 0) continue;
    assertion(index > start, 'tree stream contains an empty record');
    let record;
    try {
      record = FATAL_UTF8.decode(treeBytes.subarray(start, index));
    } catch {
      throw new Error('tree stream record is not UTF-8');
    }
    const match = /^(100644|100755) blob ([0-9a-f]{40})\t(.+)$/u.exec(record);
    assertion(match !== null, `unsupported tree record: ${JSON.stringify(record)}`);
    const [, mode, oid, repositoryPath] = match;
    assertion(safePath(repositoryPath) && !repositoryPath.includes('!'), 'unsafe tree path');
    assertion(!paths.has(repositoryPath), `duplicate tree path: ${repositoryPath}`);
    paths.add(repositoryPath);
    entries.push({ mode, type: 'blob', oid, path: repositoryPath });
    start = index + 1;
  }
  assertion(start === treeBytes.length, 'tree stream was not fully consumed');
  return entries;
}

function framedDigest(entries) {
  const identities = new Set();
  const frames = [];
  for (const entry of [...entries].sort((left, right) => {
    const repositoryOrder = byteCompare(left.repository, right.repository);
    return repositoryOrder === 0 ? byteCompare(left.path, right.path) : repositoryOrder;
  })) {
    assertion(typeof entry.repository === 'string' && entry.repository !== '', 'framed repository');
    assertion(safePath(entry.path), 'framed path');
    assertion(['100644', '100755'].includes(entry.mode), 'framed mode');
    assertion(Number.isSafeInteger(entry.byteLength) && entry.byteLength >= 0, 'framed length');
    assertion(SHA256_PATTERN.test(entry.sha256), 'framed SHA-256');
    const identity = `${entry.repository}\u0000${entry.path}`;
    assertion(!identities.has(identity), `duplicate framed source: ${identity}`);
    identities.add(identity);
    frames.push(
      Buffer.from(
        `${entry.repository}\u0000${entry.path}\u0000${entry.mode}\u0000${entry.byteLength}\u0000${entry.sha256}\u0000`,
        'utf8'
      )
    );
  }
  return sha256(Buffer.concat(frames));
}

function captureExecutionSourceSnapshot(repositoryRoot) {
  assertion(
    repositoryRoot === REPOSITORY_ROOT,
    'verifier repository root must be the module repository'
  );
  assertion(realpathSync(repositoryRoot) === repositoryRoot, 'repository root is noncanonical');
  const sources = SOURCE_PATHS.map((sourcePath) => {
    const absolutePath = path.join(repositoryRoot, sourcePath);
    const metadata = lstatSync(absolutePath);
    assertion(
      metadata.isFile() && !metadata.isSymbolicLink(),
      `executed source is unsafe: ${sourcePath}`
    );
    assertion(
      realpathSync(absolutePath) === absolutePath,
      `executed source is noncanonical: ${sourcePath}`
    );
    const permissions = metadata.mode & 0o777;
    assertion(
      [0o644, 0o755].includes(permissions),
      `executed source mode is unsupported: ${sourcePath}`
    );
    const bytes = readFileSync(absolutePath);
    return {
      repository: HARNESS_REPOSITORY_KEY,
      path: sourcePath,
      mode: permissions === 0o755 ? '100755' : '100644',
      byteLength: bytes.length,
      sha256: sha256(bytes),
      bytes,
    };
  });
  return {
    sources,
    sourceSetSha256: framedDigest(sources.map(({ bytes: _bytes, ...source }) => source)),
  };
}

function assertExecutionSourceSnapshot(actual, expected, label) {
  assertion(actual.sourceSetSha256 === expected.sourceSetSha256, `${label} source-set differs`);
  assertion(actual.sources.length === expected.sources.length, `${label} source count differs`);
  for (let index = 0; index < expected.sources.length; index += 1) {
    const actualSource = actual.sources[index];
    const expectedSource = expected.sources[index];
    const { bytes: actualBytes, ...actualMetadata } = actualSource;
    const { bytes: expectedBytes, ...expectedMetadata } = expectedSource;
    assertion(
      canonicalJson(actualMetadata) === canonicalJson(expectedMetadata),
      `${label} source metadata differs: ${expectedSource.path}`
    );
    assertion(
      actualBytes.equals(expectedBytes),
      `${label} source bytes differ: ${expectedSource.path}`
    );
  }
}

const MODULE_LOAD_EXECUTION_SNAPSHOT = captureExecutionSourceSnapshot(REPOSITORY_ROOT);

function ensureCanonicalDirectory(directory) {
  const metadata = lstatSync(directory);
  assertion(metadata.isDirectory() && !metadata.isSymbolicLink(), `unsafe directory: ${directory}`);
  assertion(realpathSync(directory) === directory, `noncanonical directory: ${directory}`);
  assertion((metadata.mode & 0o777) === 0o700, `directory mode differs: ${directory}`);
}

function ensureCanonicalRepository(directory) {
  const metadata = lstatSync(directory);
  assertion(
    metadata.isDirectory() && !metadata.isSymbolicLink(),
    `unsafe repository directory: ${directory}`
  );
  assertion(
    realpathSync(directory) === directory,
    `noncanonical repository directory: ${directory}`
  );
}

function readArtifact(runDirectory, name) {
  assertion(safePath(name) && !name.includes('/'), `unsafe artifact name: ${name}`);
  const filePath = path.join(runDirectory, name);
  const metadata = lstatSync(filePath);
  assertion(metadata.isFile() && !metadata.isSymbolicLink(), `unsafe artifact: ${name}`);
  assertion(realpathSync(filePath) === filePath, `noncanonical artifact: ${name}`);
  assertion((metadata.mode & 0o777) === 0o600, `artifact mode differs: ${name}`);
  const bytes = readFileSync(filePath);
  assertion(bytes.length === metadata.size, `artifact size differs: ${name}`);
  return bytes;
}

function gitCommandKind(lock, args) {
  if (
    args.length === 3 &&
    args[0] === 'cat-file' &&
    args[1] === 'blob' &&
    OID_PATTERN.test(args[2])
  ) {
    return 'cat-file-blob';
  }
  if (canonicalJson(args) === canonicalJson(['ls-tree', '-rz', '--full-tree', lock.commit])) {
    return 'ls-tree';
  }
  if (canonicalJson(args) === canonicalJson(['rev-parse', `${lock.commit}^{tree}`])) {
    return 'rev-parse-tree';
  }
  return 'prohibited';
}

function repositoryReader(root, lock) {
  ensureCanonicalRepository(root);
  const counts = Object.create(null);
  return {
    git(args) {
      const kind = gitCommandKind(lock, args);
      assertion(kind !== 'prohibited', `verifier Git command is prohibited: ${args[0]}`);
      counts[kind] = (counts[kind] ?? 0) + 1;
      const result = spawnSync(GIT_EXECUTABLE, args, {
        cwd: root,
        encoding: null,
        env: {
          GIT_CONFIG_COUNT: '0',
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_NO_LAZY_FETCH: '1',
          GIT_NO_REPLACE_OBJECTS: '1',
          GIT_OPTIONAL_LOCKS: '0',
          GIT_TERMINAL_PROMPT: '0',
          LANG: 'C',
          LC_ALL: 'C',
          PATH: '/usr/bin:/bin',
        },
        maxBuffer: 64 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      assertion(result.error === undefined, `verifier git ${args[0]} failed to start`);
      assertion(
        result.status === 0 && result.signal === null,
        `verifier git ${args[0]} failed: ${String(result.stderr)}`
      );
      return result.stdout;
    },
    counts: () => Object.fromEntries(Object.entries(counts).sort()),
  };
}

function snapshot(root, lock) {
  const reader = repositoryReader(root, lock);
  const tree = FATAL_UTF8.decode(reader.git(['rev-parse', `${lock.commit}^{tree}`])).trim();
  assertion(tree === lock.tree, `${lock.key} tree differs`);
  const treeBytes = reader.git(['ls-tree', '-rz', '--full-tree', lock.commit]);
  assertion(sha256(treeBytes) === lock.lsTreeSha256, `${lock.key} tree stream differs`);
  const entries = parseTree(treeBytes);
  assertion(entries.length === lock.entryCount, `${lock.key} entry count differs`);
  const blobsByOid = new Map();
  for (const entry of entries) {
    if (!blobsByOid.has(entry.oid)) {
      const bytes = reader.git(['cat-file', 'blob', entry.oid]);
      assertGitBlobIdentity(entry.oid, bytes);
      blobsByOid.set(entry.oid, bytes);
    }
  }
  const sourceEntries = entries.map((entry) => {
    const bytes = blobsByOid.get(entry.oid);
    return {
      repository: lock.key,
      path: entry.path,
      mode: entry.mode,
      oid: entry.oid,
      byteLength: bytes.length,
      sha256: sha256(bytes),
    };
  });
  const find = (repositoryPath) => {
    const entry = entries.find((candidate) => candidate.path === repositoryPath);
    assertion(entry !== undefined, `${lock.key} missing ${repositoryPath}`);
    return blobsByOid.get(entry.oid);
  };
  const planBytes = find('.overlaykit/governance/plan.json');
  const plan = parseJson(planBytes, `${lock.key} plan`);
  assertion(
    plan !== null && typeof plan === 'object' && !Array.isArray(plan),
    `${lock.key} plan envelope differs`
  );
  return {
    repository: lock.key,
    commit: lock.commit,
    tree,
    treeBytes,
    entries,
    blobsByOid,
    sourceEntries,
    sourceSetSha256: framedDigest(
      sourceEntries.map(({ repository, path: sourcePath, mode, byteLength, sha256: digest }) => ({
        repository,
        path: sourcePath,
        mode,
        byteLength,
        sha256: digest,
      }))
    ),
    plan,
    invocationCounts: reader.counts(),
  };
}

function decodeText(bytes) {
  try {
    return FATAL_UTF8.decode(bytes);
  } catch {
    return null;
  }
}

function signalReceipt(bytes, repositoryPath) {
  const text = decodeText(bytes);
  if (text === null) {
    return {
      textStatus: KNOWN_NON_TEXT_EXTENSIONS.has(
        path.extname(repositoryPath).toLocaleLowerCase('en-US')
      )
        ? 'known-non-text'
        : 'opaque-non-text',
      roles: [],
    };
  }
  return {
    textStatus: 'utf8',
    roles: SIGNAL_POLICY.filter(([, pattern]) => pattern.test(text)).map(([id]) => id),
  };
}

function governanceMetadata(snapshotValue, sourceEntry, bytes) {
  const match =
    /^\.overlaykit\/governance\/(decisions|specifications|changes)\/((?:ADR|SPEC|CHG)-\d{4})\.json$/u.exec(
      sourceEntry.path
    );
  if (match === null) return null;
  const [, collection, id] = match;
  const record = parseJson(bytes, `${snapshotValue.repository}/${sourceEntry.path}`);
  assertion(record.id === id, `governance ID differs at ${sourceEntry.path}`);
  if (collection === 'decisions') {
    const compiled = snapshotValue.plan.decisions.find((candidate) => candidate.id === id);
    assertion(compiled !== undefined, `plan omits ${id}`);
    return {
      kind: 'decision',
      id,
      declaredStatus: record.status,
      effectiveStatus: compiled.effectiveStatus,
    };
  }
  if (collection === 'specifications') {
    const compiled = snapshotValue.plan.specifications.find((candidate) => candidate.id === id);
    assertion(compiled !== undefined, `plan omits ${id}`);
    return {
      kind: 'specification',
      id,
      declaredStatus: record.status,
      effectiveStatus: compiled.effectiveStatus,
    };
  }
  return {
    kind: 'change',
    id,
    declaredStatus: record.status,
    effectiveStatus: record.status,
  };
}

function sourceIdentityKey({
  repository,
  commit,
  path: repositoryPath,
  sourceKind,
  sha256: digest,
}) {
  return `${repository}\u0000${commit}\u0000${sourceKind}\u0000${repositoryPath}\u0000${digest}`;
}

function validateBindingEvidenceShape(bindingEvidence, binding, label) {
  exactKeys(
    bindingEvidence,
    ['kind', 'byteOffset', 'byteLength', 'sha256'],
    `${label} binding evidence`
  );
  assertion(bindingEvidence.kind === 'exact-utf8-byte-span/v1', `${label} binding evidence kind`);
  assertion(
    Number.isSafeInteger(bindingEvidence.byteOffset) && bindingEvidence.byteOffset >= 0,
    `${label} binding evidence offset`
  );
  const deploymentKeyBytes = Buffer.from(binding.deploymentKey, 'utf8');
  assertion(
    Number.isSafeInteger(bindingEvidence.byteLength) &&
      bindingEvidence.byteLength === deploymentKeyBytes.length &&
      bindingEvidence.byteLength > 0,
    `${label} binding evidence length`
  );
  assertion(
    bindingEvidence.sha256 === sha256(deploymentKeyBytes),
    `${label} binding evidence digest`
  );
  return deploymentKeyBytes;
}

function reviewPayloadSha256(reviewMap) {
  const { status: _status, humanAcceptanceRef: _humanAcceptanceRef, ...payload } = reviewMap;
  return sha256(Buffer.from(canonicalJson(payload), 'utf8'));
}

function reviewUniversePolicy() {
  return {
    schemaVersion: 'overlaykit-h048-review-universe-policy/v1',
    sourceCoverage:
      'every nominated main-tree blob and every strictly expanded archive-member occurrence',
    candidateAdmission:
      'exact source identity plus text status, semantic signal roles, governance metadata, and default-candidate admission before human review',
    signalPolicy: SIGNAL_POLICY.map(([id, pattern]) => ({
      id,
      source: pattern.source,
      flags: pattern.flags,
    })),
    knownNonTextExtensions: [...KNOWN_NON_TEXT_EXTENSIONS].sort(byteCompare),
    indirectionExtraction:
      'literal HTTP-or-HTTPS URLs, nominated repository tokens, and exact nominated commit tokens with noncanonical nominated URLs unresolved',
    indirectionStatuses: {
      resolved: ['resolved-exact-subject'],
      unresolved: [...UNRESOLVED_INDIRECTION_STATUSES].sort(byteCompare),
      terminalExcluded: ['excluded-github-surface', 'excluded-outside-nominated-boundary'],
    },
  };
}

function sortIndirections(indirections) {
  indirections.sort((left, right) => byteCompare(canonicalJson(left), canonicalJson(right)));
  return indirections;
}

function deriveReviewUniverse({ subjectLock, snapshots, archives }) {
  assertion(Array.isArray(snapshots) && snapshots.length === 2, 'review universe snapshots');
  assertion(Array.isArray(archives?.members), 'review universe archive members');
  const sources = [];
  const indirections = [];
  for (const snapshotValue of snapshots) {
    for (const entry of snapshotValue.sourceEntries) {
      const bytes = snapshotValue.blobsByOid.get(entry.oid);
      assertion(Buffer.isBuffer(bytes), `review universe bytes are absent: ${entry.path}`);
      const signal = signalReceipt(bytes, entry.path);
      const governance = governanceMetadata(snapshotValue, entry, bytes);
      sources.push({
        repository: snapshotValue.repository,
        commit: snapshotValue.commit,
        path: entry.path,
        sourceKind: 'git-blob',
        mode: entry.mode,
        oid: entry.oid,
        byteLength: entry.byteLength,
        sha256: entry.sha256,
        textStatus: signal.textStatus,
        semanticRoles: signal.roles,
        governance,
        defaultCandidateAdmission:
          signal.roles.length > 0 ||
          governance !== null ||
          (!ARCHIVE_PATH_PATTERN.test(entry.path) && signal.textStatus === 'opaque-non-text'),
      });
      indirections.push(
        ...indirectionsFromBytes({
          repository: snapshotValue.repository,
          ownerCommit: snapshotValue.commit,
          repositoryPath: entry.path,
          sourceKind: 'git-blob',
          sourceSha256: entry.sha256,
          bytes,
          subjectRepositories: subjectLock.repositories,
        })
      );
    }
  }
  for (const member of archives.members) {
    const bytes = archives.memberContents.get(member.virtualPath);
    assertion(Buffer.isBuffer(bytes), `review universe bytes are absent: ${member.virtualPath}`);
    const identity = memberIdentity(
      member.virtualPath,
      snapshots.map((snapshotValue) => snapshotValue.repository)
    );
    const repository = subjectLock.repositories.find(
      (candidate) => candidate.key === identity.repository
    );
    assertion(
      repository !== undefined,
      `review universe repository is not nominated: ${identity.repository}`
    );
    const signal = signalReceipt(bytes, identity.path);
    sources.push({
      repository: identity.repository,
      commit: repository.commit,
      path: identity.path,
      sourceKind: 'archive-member',
      mode: null,
      oid: null,
      byteLength: member.byteLength,
      sha256: member.sha256,
      textStatus: signal.textStatus,
      semanticRoles: signal.roles,
      governance: null,
      defaultCandidateAdmission: signal.roles.length > 0 || signal.textStatus === 'opaque-non-text',
    });
    indirections.push(
      ...indirectionsFromBytes({
        repository: identity.repository,
        ownerCommit: repository.commit,
        repositoryPath: identity.path,
        sourceKind: 'archive-member',
        sourceSha256: member.sha256,
        bytes,
        subjectRepositories: subjectLock.repositories,
      })
    );
  }
  sources.sort((left, right) => byteCompare(canonicalJson(left), canonicalJson(right)));
  sortIndirections(indirections);
  const sourceIdentities = new Set();
  for (const source of sources) {
    const key = sourceIdentityKey(source);
    assertion(!sourceIdentities.has(key), `duplicate review universe source: ${key}`);
    sourceIdentities.add(key);
  }
  const indirectionIds = new Set();
  for (const indirection of indirections) {
    assertion(
      !indirectionIds.has(indirection.id),
      `duplicate review universe edge: ${indirection.id}`
    );
    indirectionIds.add(indirection.id);
  }
  const defaultCandidateUniverse = sources
    .filter((source) => source.defaultCandidateAdmission)
    .map(({ repository, commit, path: sourcePath, sourceKind, sha256: digest }) => ({
      repository,
      commit,
      path: sourcePath,
      sourceKind,
      sha256: digest,
    }));
  const policy = reviewUniversePolicy();
  const material = {
    schemaVersion: 'overlaykit-h048-review-universe/v1',
    policy,
    sourceUniverse: sources,
    defaultCandidateUniverse,
    indirectionUniverse: indirections,
  };
  const materialBytes = Buffer.from(`${canonicalJson(material)}\n`, 'utf8');
  return {
    material,
    bytes: materialBytes,
    reference: {
      schemaVersion: 'overlaykit-h048-review-universe-ref/v1',
      file: 'review-universe.json',
      canonicalization: 'canonical-json-sorted-object-keys-utf8-lf/v1',
      policySha256: sha256(Buffer.from(canonicalJson(policy), 'utf8')),
      sourceCount: sources.length,
      sourceSha256: sha256(Buffer.from(canonicalJson(sources), 'utf8')),
      defaultCandidateCount: defaultCandidateUniverse.length,
      defaultCandidateSha256: sha256(Buffer.from(canonicalJson(defaultCandidateUniverse), 'utf8')),
      indirectionCount: indirections.length,
      indirectionSha256: sha256(Buffer.from(canonicalJson(indirections), 'utf8')),
      byteLength: materialBytes.length,
      sha256: sha256(materialBytes),
    },
  };
}

function validateHumanAcceptance({
  reviewMap,
  subjectLock,
  subjectLockBytes,
  expectedReviewUniverse,
}) {
  assertion(
    expectedReviewUniverse !== null &&
      typeof expectedReviewUniverse === 'object' &&
      canonicalJson(reviewMap.reviewUniverse) === canonicalJson(expectedReviewUniverse),
    'human acceptance review universe differs'
  );
  const payloadSha256 = reviewPayloadSha256(reviewMap);
  if (reviewMap.status === 'agent-proposed-pending-human-acceptance') {
    assertion(reviewMap.humanAcceptanceRef === null, 'pending review must not carry acceptance');
    assertion(
      Array.isArray(reviewMap.pendingHumanJudgments) && reviewMap.pendingHumanJudgments.length > 0,
      'pending review must retain human judgments'
    );
    return {
      accepted: false,
      payloadSha256,
      acceptanceReceiptSha256: null,
    };
  }
  assertion(reviewMap.status === 'human-accepted', 'review status');
  assertion(
    Array.isArray(reviewMap.pendingHumanJudgments) && reviewMap.pendingHumanJudgments.length === 0,
    'human-accepted review must resolve every pending judgment'
  );
  assertion(
    typeof EXPECTED_HUMAN_ACCEPTANCE_SHA256 === 'string' &&
      SHA256_PATTERN.test(EXPECTED_HUMAN_ACCEPTANCE_SHA256),
    'human acceptance lacks an externally nominated digest'
  );
  exactKeys(
    reviewMap.humanAcceptanceRef,
    ['kind', 'canonicalization', 'byteLength', 'sha256', 'preimageBase64'],
    'human acceptance reference'
  );
  const reference = reviewMap.humanAcceptanceRef;
  assertion(reference.kind === 'embedded-content-addressed-json', 'acceptance reference kind');
  assertion(
    reference.canonicalization === 'exact-base64-decoded-bytes/v1',
    'acceptance canonicalization'
  );
  assertion(
    Number.isSafeInteger(reference.byteLength) && reference.byteLength > 0,
    'acceptance length'
  );
  assertion(SHA256_PATTERN.test(reference.sha256), 'acceptance SHA-256');
  assertion(
    reference.sha256 === EXPECTED_HUMAN_ACCEPTANCE_SHA256,
    'acceptance digest is not the externally nominated digest'
  );
  assertion(
    typeof reference.preimageBase64 === 'string' && reference.preimageBase64 !== '',
    'acceptance preimage'
  );
  const bytes = Buffer.from(reference.preimageBase64, 'base64');
  assertion(
    bytes.toString('base64') === reference.preimageBase64,
    'acceptance base64 is not canonical'
  );
  assertion(bytes.length === reference.byteLength, 'acceptance byte length differs');
  assertion(sha256(bytes) === reference.sha256, 'acceptance digest differs');
  const acceptance = parseJson(bytes, 'H-048 human acceptance');
  exactKeys(
    acceptance,
    [
      'schemaVersion',
      'hypothesis',
      'principal',
      'reviewPayloadSha256',
      'subjectLockRawSha256',
      'subjectLockCanonicalSha256',
      'claimBoundaryCanonicalSha256',
      'repoSetSha256',
      'reviewUniverseSha256',
      'authority',
      'action',
    ],
    'human acceptance'
  );
  assertion(
    acceptance.schemaVersion === 'overlaykit-h048-human-acceptance/v1' &&
      acceptance.hypothesis === 'H-048' &&
      acceptance.principal === '@rodrigoteamx',
    'acceptance identity differs'
  );
  assertion(acceptance.reviewPayloadSha256 === payloadSha256, 'accepted review payload differs');
  assertion(
    acceptance.subjectLockRawSha256 === sha256(subjectLockBytes),
    'accepted subject-lock bytes differ'
  );
  assertion(
    acceptance.subjectLockCanonicalSha256 ===
      sha256(Buffer.from(canonicalJson(subjectLock), 'utf8')),
    'accepted subject-lock canonical digest differs'
  );
  assertion(
    acceptance.claimBoundaryCanonicalSha256 ===
      sha256(Buffer.from(canonicalJson(subjectLock.claimBoundary), 'utf8')),
    'accepted claim boundary differs'
  );
  assertion(acceptance.repoSetSha256 === subjectLock.repoSet.sha256, 'accepted repo-set differs');
  assertion(
    acceptance.reviewUniverseSha256 === expectedReviewUniverse.sha256,
    'accepted review universe differs'
  );
  assertion(
    acceptance.authority === 'none' && acceptance.action === null,
    'acceptance grants authority'
  );
  return {
    accepted: true,
    payloadSha256,
    acceptanceReceiptSha256: reference.sha256,
  };
}

function reviewIndex({
  reviewMap,
  subjectLock,
  subjectLockBytes,
  snapshots,
  archives,
  reviewUniverse,
}) {
  exactKeys(
    reviewMap,
    [
      'schemaVersion',
      'hypothesis',
      'status',
      'humanAcceptanceRef',
      'reviewUniverse',
      'defaultDisposition',
      'defaultIndirectionDisposition',
      'sources',
      'chainContributions',
      'pendingHumanJudgments',
      'authority',
      'action',
    ],
    'review map'
  );
  assertion(reviewMap.schemaVersion === 'overlaykit-h048-semantic-review/v1', 'review schema');
  assertion(reviewMap.hypothesis === 'H-048', 'review hypothesis');
  assertion(
    ['agent-proposed-pending-human-acceptance', 'human-accepted'].includes(reviewMap.status),
    'review status'
  );
  assertion(reviewMap.authority === 'none' && reviewMap.action === null, 'review authority');
  assertion(
    reviewUniverse !== null &&
      typeof reviewUniverse === 'object' &&
      reviewUniverse.material?.schemaVersion === 'overlaykit-h048-review-universe/v1',
    'derived review universe'
  );
  exactKeys(
    reviewMap.reviewUniverse,
    [
      'schemaVersion',
      'file',
      'canonicalization',
      'policySha256',
      'sourceCount',
      'sourceSha256',
      'defaultCandidateCount',
      'defaultCandidateSha256',
      'indirectionCount',
      'indirectionSha256',
      'byteLength',
      'sha256',
    ],
    'review universe reference'
  );
  assertion(
    canonicalJson(reviewMap.reviewUniverse) === canonicalJson(reviewUniverse.reference),
    'review universe reference differs'
  );
  exactKeys(
    reviewMap.defaultDisposition,
    ['classification', 'rationale', 'authority', 'action'],
    'review default disposition'
  );
  assertion(
    reviewMap.defaultDisposition.classification === 'no-eligible-predicate-contribution' &&
      typeof reviewMap.defaultDisposition.rationale === 'string' &&
      reviewMap.defaultDisposition.rationale !== '' &&
      reviewMap.defaultDisposition.authority === 'none' &&
      reviewMap.defaultDisposition.action === null,
    'review default disposition differs'
  );
  exactKeys(
    reviewMap.defaultIndirectionDisposition,
    ['classification', 'rationale', 'authority', 'action'],
    'review default indirection disposition'
  );
  assertion(
    reviewMap.defaultIndirectionDisposition.classification === 'no-eligible-semantic-indirection' &&
      typeof reviewMap.defaultIndirectionDisposition.rationale === 'string' &&
      reviewMap.defaultIndirectionDisposition.rationale !== '' &&
      reviewMap.defaultIndirectionDisposition.authority === 'none' &&
      reviewMap.defaultIndirectionDisposition.action === null,
    'review default indirection disposition differs'
  );
  assertion(
    Array.isArray(reviewMap.pendingHumanJudgments) &&
      new Set(reviewMap.pendingHumanJudgments).size === reviewMap.pendingHumanJudgments.length &&
      reviewMap.pendingHumanJudgments.every(
        (judgment) => typeof judgment === 'string' && judgment !== ''
      ),
    'pending human judgments'
  );
  if (reviewMap.status === 'agent-proposed-pending-human-acceptance') {
    assertion(reviewMap.pendingHumanJudgments.length > 0, 'pending review judgments are empty');
  } else {
    assertion(
      reviewMap.pendingHumanJudgments.length === 0,
      'accepted review retains pending human judgments'
    );
  }
  assertion(Array.isArray(reviewMap.sources), 'review sources');
  const repositoryByKey = new Map(
    subjectLock.repositories.map((repository) => [repository.key, repository])
  );
  const available = new Map();
  for (const item of snapshots) {
    for (const entry of item.sourceEntries) {
      const sourceBytes = item.blobsByOid.get(entry.oid);
      assertion(Buffer.isBuffer(sourceBytes), `review source bytes are absent: ${entry.path}`);
      available.set(
        sourceIdentityKey({
          repository: item.repository,
          commit: item.commit,
          path: entry.path,
          sourceKind: 'git-blob',
          sha256: entry.sha256,
        }),
        sourceBytes
      );
    }
  }
  for (const member of archives.members) {
    const identity = memberIdentity(
      member.virtualPath,
      snapshots.map((item) => item.repository)
    );
    const repository = repositoryByKey.get(identity.repository);
    assertion(
      repository !== undefined,
      `archive review repository is not nominated: ${identity.repository}`
    );
    const memberBytes = archives.memberContents.get(member.virtualPath);
    assertion(
      Buffer.isBuffer(memberBytes),
      `archive review bytes are absent: ${member.virtualPath}`
    );
    available.set(
      sourceIdentityKey({
        repository: identity.repository,
        commit: repository.commit,
        path: identity.path,
        sourceKind: 'archive-member',
        sha256: member.sha256,
      }),
      memberBytes
    );
  }
  const sources = new Map();
  for (const source of reviewMap.sources) {
    exactKeys(
      source,
      [
        'repository',
        'commit',
        'path',
        'sourceKind',
        'sha256',
        'classification',
        'predicateContributions',
        'eligibleForChain',
        'rationale',
      ],
      'review source'
    );
    const key = sourceIdentityKey(source);
    assertion(available.has(key), `review source is outside the subjects: ${key}`);
    assertion(!sources.has(key), `duplicate review source: ${key}`);
    assertion(
      typeof source.classification === 'string' &&
        source.classification !== '' &&
        typeof source.rationale === 'string' &&
        source.rationale !== '',
      `review classification is invalid: ${key}`
    );
    assertion(
      ['git-blob', 'archive-member'].includes(source.sourceKind),
      `review source kind: ${key}`
    );
    assertion(OID_PATTERN.test(source.commit), `review source commit: ${key}`);
    assertion(SHA256_PATTERN.test(source.sha256), `review source SHA-256: ${key}`);
    assertion(
      Array.isArray(source.predicateContributions) &&
        new Set(source.predicateContributions).size === source.predicateContributions.length &&
        source.predicateContributions.every((predicate) => PREDICATES.includes(predicate)),
      `review predicates are invalid: ${key}`
    );
    assertion(typeof source.eligibleForChain === 'boolean', `review eligibility: ${key}`);
    sources.set(key, source);
  }
  assertion(Array.isArray(reviewMap.chainContributions), 'review chain contributions');
  const chainContributions = [];
  const contributionKeys = new Set();
  for (const contribution of reviewMap.chainContributions) {
    exactKeys(
      contribution,
      [
        'repository',
        'commit',
        'path',
        'sourceKind',
        'sha256',
        'predicate',
        'disposition',
        'binding',
        'bindingEvidence',
      ],
      'chain contribution'
    );
    const sourceKey = sourceIdentityKey(contribution);
    const source = sources.get(sourceKey);
    assertion(source !== undefined, `chain contribution source is not reviewed: ${sourceKey}`);
    assertion(PREDICATES.includes(contribution.predicate), 'chain contribution predicate');
    assertion(
      ['supports', 'contradicts'].includes(contribution.disposition),
      'chain contribution disposition'
    );
    assertion(
      source.predicateContributions.includes(contribution.predicate),
      `chain contribution is absent from source classification: ${sourceKey}`
    );
    exactKeys(
      contribution.binding,
      ['deploymentKey', 'imageReference', 'imageId', 'hostRole'],
      'chain binding'
    );
    assertion(
      typeof contribution.binding.deploymentKey === 'string' &&
        /^[a-z0-9][a-z0-9._:/-]{0,199}$/u.test(contribution.binding.deploymentKey),
      'chain deployment key'
    );
    assertion(
      contribution.binding.imageReference === subjectLock.target.imageReference &&
        contribution.binding.imageId === subjectLock.target.imageId &&
        contribution.binding.hostRole === subjectLock.target.hostRole,
      'chain target binding differs'
    );
    const deploymentKeyBytes = validateBindingEvidenceShape(
      contribution.bindingEvidence,
      contribution.binding,
      'chain contribution'
    );
    const sourceBytes = available.get(sourceKey);
    assertion(Buffer.isBuffer(sourceBytes), `chain contribution bytes are absent: ${sourceKey}`);
    assertion(
      contribution.bindingEvidence.byteOffset + deploymentKeyBytes.length <= sourceBytes.length &&
        sourceBytes
          .subarray(
            contribution.bindingEvidence.byteOffset,
            contribution.bindingEvidence.byteOffset + deploymentKeyBytes.length
          )
          .equals(deploymentKeyBytes),
      `chain deployment key is not the cited exact source byte span: ${sourceKey}`
    );
    const contributionKey = canonicalJson(contribution);
    assertion(!contributionKeys.has(contributionKey), 'duplicate chain contribution');
    contributionKeys.add(contributionKey);
    chainContributions.push(contribution);
  }
  const sortedContributions = [...chainContributions].sort((left, right) =>
    byteCompare(canonicalJson(left), canonicalJson(right))
  );
  assertion(
    canonicalJson(chainContributions) === canonicalJson(sortedContributions),
    'chain contributions are not canonically ordered'
  );
  for (const [key, source] of sources) {
    const referenced = chainContributions.some(
      (contribution) => sourceIdentityKey(contribution) === key
    );
    assertion(
      source.eligibleForChain === referenced,
      `review eligibility does not match typed contributions: ${key}`
    );
  }
  return {
    sources,
    chainContributions,
    universe: reviewUniverse,
    acceptance: validateHumanAcceptance({
      reviewMap,
      subjectLock,
      subjectLockBytes,
      expectedReviewUniverse: reviewUniverse.reference,
    }),
  };
}

function archiveInventory(snapshots) {
  const roots = snapshots.flatMap((item) =>
    item.entries
      .filter((entry) => ARCHIVE_PATH_PATTERN.test(entry.path))
      .map((entry) => ({
        path: `repositories/${item.repository}/${entry.path}`,
        bytes: item.blobsByOid.get(entry.oid),
      }))
  );
  assertion(roots.length === 3, 'archive root count differs');
  const forest = expandTarGzipForest(roots);
  return {
    limits: forest.limits,
    observations: forest.observations,
    roots: forest.roots,
    archives: forest.archives,
    members: forest.members,
    memberContents: forest.memberContents,
  };
}

function memberIdentity(virtualPath, repositories) {
  for (const repository of repositories) {
    const prefix = `repositories/${repository}/`;
    if (virtualPath.startsWith(prefix)) {
      return { repository, path: virtualPath.slice(prefix.length) };
    }
  }
  throw new Error(`archive route is not repository-qualified: ${virtualPath}`);
}

function normalizedUrl(raw) {
  return raw.replace(/[),.;\]}]+$/u, '');
}

function nonCanonicalNominatedUrlTarget(value, repositoryByFoldedName) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  const hostname = parsed.hostname.toLowerCase();
  if (hostname !== 'github.com' && hostname !== 'codeload.github.com') return null;
  const segments = parsed.pathname.split('/').filter((segment) => segment.length > 0);
  if (segments.length < 2) return null;
  let owner;
  let repository;
  try {
    owner = decodeURIComponent(segments[0]);
    repository = decodeURIComponent(segments[1]).replace(/\.git$/iu, '');
  } catch {
    return null;
  }
  return repositoryByFoldedName.get(`${owner}/${repository}`.toLowerCase()) ?? null;
}

function indirectionsFromBytes({
  repository,
  ownerCommit,
  repositoryPath,
  sourceKind,
  sourceSha256,
  bytes,
  subjectRepositories,
}) {
  const text = decodeText(bytes);
  if (text === null) return [];
  const receipts = [];
  const repositoryByName = new Map(subjectRepositories.map((entry) => [entry.key, entry]));
  const repositoryByFoldedName = new Map(
    subjectRepositories.map((entry) => [entry.key.toLowerCase(), entry])
  );
  const repositoryByCommit = new Map(subjectRepositories.map((entry) => [entry.commit, entry]));
  const push = ({ kind, value, targetRepository = null, targetCommit = null, status }) => {
    const receipt = {
      ownerRepository: repository,
      ownerCommit,
      ownerPath: repositoryPath,
      ownerSourceKind: sourceKind,
      ownerSha256: sourceSha256,
      kind,
      value,
      targetRepository,
      targetCommit,
      status,
    };
    receipts.push({
      id: sha256(Buffer.from(canonicalJson(receipt), 'utf8')),
      ...receipt,
    });
  };

  const urlMatches = [...text.matchAll(/https?:\/\/[^\s"'<>`]+/gu)];
  const urlSpans = urlMatches.map((match) => [match.index, match.index + match[0].length]);
  const insideUrl = (index) => urlSpans.some(([start, end]) => index >= start && index < end);
  for (const match of urlMatches) {
    const value = normalizedUrl(match[0]);
    const github =
      /^https:\/\/github\.com\/(OverlayKit\/(?:overlaykit|companion-module-overlaykit-server))(?:\/(.*))?$/u.exec(
        value
      );
    const codeload =
      /^https:\/\/codeload\.github\.com\/(OverlayKit\/(?:overlaykit|companion-module-overlaykit-server))(?:\/(.*))?$/u.exec(
        value
      );
    const target = repositoryByName.get(github?.[1] ?? codeload?.[1] ?? '');
    if (target === undefined) {
      const nonCanonicalTarget = nonCanonicalNominatedUrlTarget(value, repositoryByFoldedName);
      if (nonCanonicalTarget !== null) {
        push({
          kind: 'subject-noncanonical-url',
          value,
          targetRepository: nonCanonicalTarget.key,
          status: 'unversioned-subject-reference',
        });
        continue;
      }
      push({
        kind: 'external-url-literal',
        value,
        status: 'excluded-outside-nominated-boundary',
      });
      continue;
    }
    const suffix = github?.[2] ?? codeload?.[2] ?? '';
    const atomicCommit =
      github === null
        ? (/^tar\.gz\/([0-9a-f]{40})(?:[/?#].*)?$/u.exec(suffix)?.[1] ?? null)
        : (/^(?:commit|tree)\/([0-9a-f]{40})(?:[/?#].*)?$/u.exec(suffix)?.[1] ?? null);
    if (atomicCommit !== null) {
      push({
        kind: 'subject-atomic-url',
        value,
        targetRepository: target.key,
        targetCommit: atomicCommit,
        status:
          atomicCommit === target.commit ? 'resolved-exact-subject' : 'subject-commit-mismatch',
      });
      continue;
    }
    if (/^(?:pull|pulls)(?:\/|$)/u.test(suffix)) {
      push({
        kind: 'subject-github-pull-request',
        value,
        targetRepository: target.key,
        status: 'unresolved-github-pull-request',
      });
      continue;
    }
    if (/^(?:issues|projects|wiki)(?:\/|$)/u.test(suffix)) {
      push({
        kind: 'subject-github-excluded-surface',
        value,
        targetRepository: target.key,
        status: 'excluded-github-surface',
      });
      continue;
    }
    push({
      kind: 'subject-repository-url',
      value,
      targetRepository: target.key,
      targetCommit: null,
      status: 'unversioned-subject-reference',
    });
  }
  for (const match of text.matchAll(
    /\bOverlayKit\/(?:overlaykit|companion-module-overlaykit-server)\b/gu
  )) {
    if (insideUrl(match.index)) continue;
    const target = repositoryByName.get(match[0]);
    assertion(target !== undefined, `unrecognized nominated repository token: ${match[0]}`);
    push({
      kind: 'subject-repository-token',
      value: match[0],
      targetRepository: target.key,
      targetCommit: null,
      status: 'unversioned-subject-reference',
    });
  }
  for (const [commit, target] of repositoryByCommit) {
    for (const match of text.matchAll(new RegExp(`\\b${commit}\\b`, 'gu'))) {
      if (insideUrl(match.index)) continue;
      push({
        kind: 'subject-commit-token',
        value: commit,
        targetRepository: target.key,
        targetCommit: commit,
        status: 'unscoped-commit-reference',
      });
    }
  }
  const unique = new Map();
  for (const receipt of receipts) {
    const key = canonicalJson(receipt);
    if (!unique.has(key)) unique.set(key, receipt);
  }
  return [...unique.values()];
}

function assembleChains({
  chainContributions,
  candidates,
  indirections,
  subjectRepositories,
  target,
  reviewAccepted,
}) {
  assertion(Array.isArray(chainContributions), 'typed chain contributions');
  assertion(Array.isArray(candidates), 'chain candidates');
  assertion(Array.isArray(indirections), 'chain indirections');
  assertion(Array.isArray(subjectRepositories), 'chain subject repositories');
  assertion(typeof reviewAccepted === 'boolean', 'chain review acceptance');
  const subjectByKey = new Map(
    subjectRepositories.map((repository) => [repository.key, repository])
  );
  const indirectionIds = new Set();
  for (const receipt of indirections) {
    exactKeys(
      receipt,
      [
        'id',
        'ownerRepository',
        'ownerCommit',
        'ownerPath',
        'ownerSourceKind',
        'ownerSha256',
        'kind',
        'value',
        'targetRepository',
        'targetCommit',
        'status',
      ],
      'indirection receipt'
    );
    const { id, ...body } = receipt;
    assertion(SHA256_PATTERN.test(id), 'indirection receipt ID');
    assertion(
      id === sha256(Buffer.from(canonicalJson(body), 'utf8')),
      'indirection receipt ID differs'
    );
    assertion(!indirectionIds.has(id), `duplicate indirection receipt ID: ${id}`);
    indirectionIds.add(id);
    if (receipt.status === 'resolved-exact-subject') {
      const targetSubject = subjectByKey.get(receipt.targetRepository);
      assertion(
        targetSubject !== undefined && receipt.targetCommit === targetSubject.commit,
        'resolved indirection target differs'
      );
    }
  }
  const candidateByIdentity = new Map();
  for (const candidate of candidates) {
    const key = sourceIdentityKey(candidate);
    assertion(!candidateByIdentity.has(key), `duplicate chain candidate identity: ${key}`);
    candidateByIdentity.set(key, candidate);
  }

  const groups = new Map();
  const componentIds = new Set();
  for (const contribution of chainContributions) {
    validateBindingEvidenceShape(
      contribution.bindingEvidence,
      contribution.binding,
      'chain contribution'
    );
    const subject = subjectByKey.get(contribution.repository);
    assertion(
      subject !== undefined && subject.commit === contribution.commit,
      'chain contribution subject anchor differs'
    );
    assertion(
      contribution.binding.imageReference === target.imageReference &&
        contribution.binding.imageId === target.imageId &&
        contribution.binding.hostRole === target.hostRole,
      'chain contribution target differs'
    );
    const candidate = candidateByIdentity.get(sourceIdentityKey(contribution));
    assertion(candidate !== undefined, 'chain contribution candidate is absent');
    assertion(
      candidate.eligibleForChain &&
        candidate.predicateContributions.includes(contribution.predicate),
      'chain contribution is not eligible in its reviewed source'
    );
    const chainKey = sha256(Buffer.from(canonicalJson(contribution.binding), 'utf8'));
    const source = {
      repository: candidate.repository,
      commit: candidate.commit,
      path: candidate.path,
      sourceKind: candidate.sourceKind,
      sha256: candidate.sha256,
      classification: candidate.classification,
    };
    const componentBody = {
      chainKey,
      binding: contribution.binding,
      bindingEvidence: contribution.bindingEvidence,
      predicate: contribution.predicate,
      disposition: contribution.disposition,
      source,
    };
    const component = {
      id: sha256(Buffer.from(canonicalJson(componentBody), 'utf8')),
      ...componentBody,
    };
    assertion(!componentIds.has(component.id), `duplicate chain component: ${component.id}`);
    componentIds.add(component.id);
    const group = groups.get(chainKey) ?? {
      binding: contribution.binding,
      components: [],
    };
    assertion(
      canonicalJson(group.binding) === canonicalJson(contribution.binding),
      `chain binding collision: ${chainKey}`
    );
    group.components.push(component);
    groups.set(chainKey, group);
  }

  const chainComponents = Object.fromEntries(PREDICATES.map((predicate) => [predicate, []]));
  for (const { components } of groups.values()) {
    for (const component of components) chainComponents[component.predicate].push(component);
  }
  for (const components of Object.values(chainComponents)) {
    components.sort((left, right) => byteCompare(left.id, right.id));
  }

  const eligibleChains = [];
  const chainAssessments = [];
  const unknowns = [];
  for (const chainKey of [...groups.keys()].sort(byteCompare)) {
    const group = groups.get(chainKey);
    const selected = {};
    const missingPredicates = [];
    const ambiguousPredicates = [];
    const contradictedPredicates = [];
    for (const predicate of PREDICATES) {
      const components = group.components.filter((component) => component.predicate === predicate);
      const supports = components
        .filter((component) => component.disposition === 'supports')
        .sort((left, right) => byteCompare(left.id, right.id));
      const contradictions = components
        .filter((component) => component.disposition === 'contradicts')
        .sort((left, right) => byteCompare(left.id, right.id));
      if (supports.length === 0) missingPredicates.push(predicate);
      else if (supports.length === 1) selected[predicate] = supports[0];
      else {
        ambiguousPredicates.push(predicate);
        unknowns.push({
          code: 'ambiguous-chain-component',
          chainKey,
          predicate,
          componentIds: supports.map((component) => component.id),
        });
      }
      if (contradictions.length > 0) {
        contradictedPredicates.push(predicate);
        unknowns.push({
          code: 'contradictory-chain-component',
          chainKey,
          predicate,
          componentIds: contradictions.map((component) => component.id),
        });
      }
    }

    let exactLinkReceiptIds = [];
    const structurallyComplete =
      missingPredicates.length === 0 &&
      ambiguousPredicates.length === 0 &&
      contradictedPredicates.length === 0;
    if (structurallyComplete) {
      const linkSource = selected.explicitLinkClosure.source;
      exactLinkReceiptIds = indirections
        .filter((receipt) => {
          if (
            receipt.status !== 'resolved-exact-subject' ||
            receipt.ownerRepository !== linkSource.repository ||
            receipt.ownerCommit !== linkSource.commit ||
            receipt.ownerPath !== linkSource.path ||
            receipt.ownerSourceKind !== linkSource.sourceKind ||
            receipt.ownerSha256 !== linkSource.sha256 ||
            receipt.targetRepository === linkSource.repository
          ) {
            return false;
          }
          const targetSubject = subjectByKey.get(receipt.targetRepository);
          return targetSubject !== undefined && receipt.targetCommit === targetSubject.commit;
        })
        .map((receipt) => receipt.id)
        .sort(byteCompare);
      if (exactLinkReceiptIds.length === 0) {
        unknowns.push({
          code: 'explicit-link-not-exact',
          chainKey,
          componentId: selected.explicitLinkClosure.id,
        });
      }
    }
    const eligible = reviewAccepted && structurallyComplete && exactLinkReceiptIds.length > 0;
    const assessment = {
      chainKey,
      binding: group.binding,
      missingPredicates,
      ambiguousPredicates,
      contradictedPredicates,
      exactLinkReceiptIds,
      eligible,
    };
    chainAssessments.push(assessment);
    if (eligible) {
      const components = PREDICATES.map((predicate) => selected[predicate]);
      const body = {
        chainKey,
        binding: group.binding,
        components,
        exactLinkReceiptIds,
      };
      eligibleChains.push({
        id: sha256(Buffer.from(canonicalJson(body), 'utf8')),
        ...body,
      });
    }
  }
  eligibleChains.sort((left, right) => byteCompare(left.id, right.id));
  return {
    chainComponents,
    chainAssessments,
    eligibleChains,
    missingPredicates: PREDICATES.filter(
      (predicate) =>
        !chainComponents[predicate].some((component) => component.disposition === 'supports')
    ),
    unknowns,
  };
}

function classifyOutcome({ invalid = false, coverageComplete, unknowns, eligibleChains }) {
  assertion(typeof invalid === 'boolean', 'invalid flag');
  assertion(typeof coverageComplete === 'boolean', 'coverage flag');
  assertion(Array.isArray(unknowns), 'unknown list');
  assertion(Array.isArray(eligibleChains), 'eligible chain list');
  if (invalid) {
    return {
      status: 'invalid',
      stage: 'source-admission',
      reasonCode: 'invalid-source-or-artifact-integrity',
    };
  }
  if (unknowns.some((unknown) => unknown.code === 'accepted-source-anchor-opaque')) {
    return {
      status: 'inconclusive',
      stage: 'source-admission',
      reasonCode: 'accepted-source-anchor-opaque',
    };
  }
  if (!coverageComplete || unknowns.length > 0) {
    return {
      status: 'inconclusive',
      stage: 'semantic-coverage',
      reasonCode: 'incomplete-ambiguous-or-unreviewed-coverage',
    };
  }
  if (eligibleChains.length > 0) {
    return {
      status: 'supported',
      stage: 'desired-state-chain',
      reasonCode: 'eligible-chain-present',
    };
  }
  return {
    status: 'refuted',
    stage: 'complete-nominated-git-boundary',
    reasonCode: 'complete-zero-eligible-chain-coverage',
  };
}

export {
  assembleChains as assembleH048VerifierChainsForTest,
  classifyOutcome as classifyH048VerifierOutcomeForTest,
  deriveReviewUniverse as deriveH048VerifierReviewUniverseForTest,
  indirectionsFromBytes as deriveH048VerifierIndirectionsForTest,
  validateHumanAcceptance as validateH048VerifierAcceptanceForTest,
};

function expectedCandidateIndex(
  subjectLock,
  subjectLockBytes,
  reviewMap,
  reviewMapBytes,
  snapshots,
  archives,
  reviewUniverse
) {
  const review = reviewIndex({
    reviewMap,
    subjectLock,
    subjectLockBytes,
    snapshots,
    archives,
    reviewUniverse,
  });
  const reviews = review.sources;
  const universeSources = new Map();
  for (const source of review.universe.material.sourceUniverse) {
    const key = sourceIdentityKey(source);
    assertion(!universeSources.has(key), `duplicate review universe source: ${key}`);
    universeSources.set(key, source);
  }
  const candidates = [];
  for (const item of snapshots) {
    for (const sourceEntry of item.sourceEntries) {
      const key = sourceIdentityKey({
        repository: item.repository,
        commit: item.commit,
        path: sourceEntry.path,
        sourceKind: 'git-blob',
        sha256: sourceEntry.sha256,
      });
      const universe = universeSources.get(key);
      assertion(universe !== undefined, `source is absent from review universe: ${key}`);
      const sourceReview = reviews.get(key) ?? null;
      if (!universe.defaultCandidateAdmission && sourceReview === null) continue;
      if (
        universe.semanticRoles.length === 0 &&
        sourceReview === null &&
        universe.governance === null
      ) {
        if (universe.textStatus !== 'opaque-non-text') continue;
        candidates.push({
          repository: item.repository,
          commit: item.commit,
          path: sourceEntry.path,
          mode: sourceEntry.mode,
          oid: sourceEntry.oid,
          byteLength: sourceEntry.byteLength,
          sha256: sourceEntry.sha256,
          sourceKind: 'git-blob',
          textStatus: universe.textStatus,
          semanticRoles: [],
          governance: universe.governance,
          classification: 'opaque-non-text-unreviewed',
          predicateContributions: [],
          eligibleForChain: false,
          reviewBasis: 'opaque',
        });
        continue;
      }
      candidates.push({
        repository: item.repository,
        commit: item.commit,
        path: sourceEntry.path,
        mode: sourceEntry.mode,
        oid: sourceEntry.oid,
        byteLength: sourceEntry.byteLength,
        sha256: sourceEntry.sha256,
        sourceKind: 'git-blob',
        textStatus: universe.textStatus,
        semanticRoles: universe.semanticRoles,
        governance: universe.governance,
        classification:
          sourceReview?.classification ?? 'agent-default-no-eligible-predicate-contribution',
        predicateContributions: sourceReview?.predicateContributions ?? [],
        eligibleForChain: sourceReview?.eligibleForChain ?? false,
        reviewBasis:
          sourceReview === null ? 'agent-default-pending-human-acceptance' : 'exact-review-entry',
        rationale: sourceReview?.rationale ?? null,
      });
    }
  }
  for (const member of archives.members) {
    const identity = memberIdentity(
      member.virtualPath,
      snapshots.map((item) => item.repository)
    );
    const repository = subjectLock.repositories.find(
      (candidate) => candidate.key === identity.repository
    );
    assertion(
      repository !== undefined,
      `archive repository is not nominated: ${identity.repository}`
    );
    const key = sourceIdentityKey({
      repository: identity.repository,
      commit: repository.commit,
      path: identity.path,
      sourceKind: 'archive-member',
      sha256: member.sha256,
    });
    const universe = universeSources.get(key);
    assertion(universe !== undefined, `archive member is absent from review universe: ${key}`);
    const sourceReview = reviews.get(key) ?? null;
    if (!universe.defaultCandidateAdmission && sourceReview === null) continue;
    candidates.push({
      repository: identity.repository,
      commit: repository.commit,
      path: identity.path,
      mode: null,
      oid: null,
      byteLength: member.byteLength,
      sha256: member.sha256,
      sourceKind: 'archive-member',
      textStatus: universe.textStatus,
      semanticRoles: universe.semanticRoles,
      governance: null,
      classification:
        sourceReview?.classification ??
        (universe.textStatus === 'opaque-non-text'
          ? 'opaque-archive-member-unreviewed'
          : 'agent-default-historical-or-vendored-archive-content'),
      predicateContributions: sourceReview?.predicateContributions ?? [],
      eligibleForChain: sourceReview?.eligibleForChain ?? false,
      reviewBasis:
        sourceReview === null ? 'agent-default-pending-human-acceptance' : 'exact-review-entry',
      rationale: sourceReview?.rationale ?? null,
    });
  }
  candidates.sort((left, right) => {
    const repositoryOrder = byteCompare(left.repository, right.repository);
    return repositoryOrder === 0 ? byteCompare(left.path, right.path) : repositoryOrder;
  });
  const indirections = review.universe.material.indirectionUniverse;

  const unknowns = [];
  const repoSetAdmission = admitSetAnchor(subjectLock.repoSet, 'accepted repo-set');
  if (!repoSetAdmission.admitted) {
    unknowns.push({
      code: repoSetAdmission.reasonCode,
      anchor: 'repo-set',
      sha256: subjectLock.repoSet.sha256,
    });
  }
  for (const repository of subjectLock.repositories) {
    const admission = admitSetAnchor(repository.refSet, `${repository.key} accepted ref-set`);
    if (!admission.admitted) {
      unknowns.push({
        code: admission.reasonCode,
        anchor: 'ref-set',
        repository: repository.key,
        sha256: repository.refSet.sha256,
      });
    }
  }
  if (!review.acceptance.accepted) {
    unknowns.push({
      code: 'human-review-not-accepted',
      reviewStatus: reviewMap.status,
      reviewPayloadSha256: review.acceptance.payloadSha256,
    });
  }
  const opaqueCandidates = candidates.filter((candidate) =>
    candidate.classification.startsWith('opaque-')
  );
  if (opaqueCandidates.length > 0) {
    unknowns.push({
      code: 'opaque-source-content',
      candidateCount: opaqueCandidates.length,
      candidates: opaqueCandidates.map(
        ({ repository, path: sourcePath, sourceKind, sha256: digest }) => ({
          repository,
          path: sourcePath,
          sourceKind,
          sha256: digest,
        })
      ),
    });
  }
  const unresolvedIndirections = indirections.filter((indirection) =>
    UNRESOLVED_INDIRECTION_STATUSES.includes(indirection.status)
  );
  if (unresolvedIndirections.length > 0) {
    unknowns.push({
      code: 'unresolved-subject-indirections',
      count: unresolvedIndirections.length,
      indirections: unresolvedIndirections,
    });
  }
  const chainResult = assembleChains({
    chainContributions: review.chainContributions,
    candidates,
    indirections,
    subjectRepositories: subjectLock.repositories,
    target: subjectLock.target,
    reviewAccepted: review.acceptance.accepted,
  });
  unknowns.push(...chainResult.unknowns);
  const coverageComplete = unknowns.length === 0;
  const outcome = classifyOutcome({
    coverageComplete,
    unknowns,
    eligibleChains: chainResult.eligibleChains,
  });
  const claimBoundaryCanonicalSha256 = sha256(
    Buffer.from(canonicalJson(subjectLock.claimBoundary), 'utf8')
  );
  return {
    schemaVersion: 'overlaykit-h048-candidate-index/v1',
    hypothesis: 'H-048',
    claimBoundary: subjectLock.claimBoundary,
    claimBoundaryCanonicalSha256,
    review: {
      schemaVersion: reviewMap.schemaVersion,
      status: reviewMap.status,
      humanAcceptanceRef: reviewMap.humanAcceptanceRef,
      sourceFileSha256: sha256(reviewMapBytes),
      canonicalSha256: sha256(Buffer.from(canonicalJson(reviewMap), 'utf8')),
      payloadCanonicalSha256: review.acceptance.payloadSha256,
      acceptanceReceiptSha256: review.acceptance.acceptanceReceiptSha256,
      universe: review.universe.reference,
      exactEntries: reviews.size,
      typedContributions: review.chainContributions.length,
      defaultClassification: reviewMap.defaultDisposition.classification,
      defaultIndirectionClassification: reviewMap.defaultIndirectionDisposition.classification,
      pendingHumanJudgments: reviewMap.pendingHumanJudgments,
    },
    candidates,
    indirections,
    chainComponents: chainResult.chainComponents,
    chainAssessments: chainResult.chainAssessments,
    missingPredicates: chainResult.missingPredicates,
    eligibleChains: chainResult.eligibleChains,
    unknowns,
    coverageComplete,
    outcome,
    adrAssessment: {
      status: 'no-decision-candidate-activated',
      rationaleCode: 'offline-boundary-inventory-selects-no-new-architecture',
      futureDecisionQuestion:
        'which accepted source of truth, lifecycle-owner role, reconciler, and absence-to-convergence policy should govern Companion if persistent deployment is desired',
      authority: 'none',
      action: null,
    },
  };
}

function expectedSourceMap(subjectLock, snapshots, archives) {
  const entries = snapshots
    .flatMap((item) => item.sourceEntries)
    .sort((left, right) => {
      const repositoryOrder = byteCompare(left.repository, right.repository);
      return repositoryOrder === 0 ? byteCompare(left.path, right.path) : repositoryOrder;
    });
  return {
    schemaVersion: 'overlaykit-h048-source-map/v1',
    hypothesis: 'H-048',
    claimBoundary: subjectLock.claimBoundary,
    claimBoundaryCanonicalSha256: sha256(
      Buffer.from(canonicalJson(subjectLock.claimBoundary), 'utf8')
    ),
    acceptedRepoSetSha256: subjectLock.repoSet.sha256,
    repositories: snapshots.map((item) => ({
      key: item.repository,
      commit: item.commit,
      tree: item.tree,
      entryCount: item.entries.length,
      lsTreeSha256: sha256(item.treeBytes),
      sourceSetSha256: item.sourceSetSha256,
    })),
    entryCount: entries.length,
    entries,
    sourceSetSha256: framedDigest(
      entries.map(({ repository, path: sourcePath, mode, byteLength, sha256: digest }) => ({
        repository,
        path: sourcePath,
        mode,
        byteLength,
        sha256: digest,
      }))
    ),
    archives: {
      policyVersion: 'overlaykit-h047-archive-expansion/v1',
      limits: archives.limits,
      observations: archives.observations,
      roots: archives.roots,
      archives: archives.archives,
      members: archives.members,
    },
  };
}

function validateSourceClosure(runDirectory, document, executionSnapshot) {
  exactKeys(
    document,
    [
      'schemaVersion',
      'hypothesis',
      'admission',
      'sourceCount',
      'uniqueBlobCount',
      'sourceSetSha256',
      'sources',
    ],
    'source closure'
  );
  assertion(
    document.schemaVersion === 'overlaykit-h048-local-source-closure/v1' &&
      document.hypothesis === 'H-048',
    'source closure identity differs'
  );
  exactKeys(document.admission, ['kind', 'signatureStatus', 'commit'], 'source closure admission');
  assertion(
    document.admission.kind === 'local-content-addressed-unsigned' &&
      document.admission.signatureStatus === 'absent-not-authorized' &&
      document.admission.commit === null,
    'source closure admission differs'
  );
  assertion(document.sourceCount === SOURCE_PATHS.length, 'source closure count differs');
  assertion(Array.isArray(document.sources), 'source closure sources differ');
  assertion(
    document.sourceSetSha256 === executionSnapshot.sourceSetSha256,
    'captured source-set differs from executed source-set'
  );
  assertion(
    canonicalJson(document.sources.map(({ path: sourcePath }) => sourcePath)) ===
      canonicalJson(SOURCE_PATHS),
    'source closure paths differ'
  );
  const sourceDirectory = path.join(runDirectory, 'sources');
  ensureCanonicalDirectory(sourceDirectory);
  const expectedBlobFiles = [
    ...new Set(document.sources.map(({ blobFile }) => path.basename(blobFile))),
  ].sort();
  assertion(
    canonicalJson(readdirSync(sourceDirectory).sort()) === canonicalJson(expectedBlobFiles),
    'source blob file set differs'
  );
  const framed = [];
  const blobDigests = new Set();
  const sourceBytesByPath = new Map();
  const executedByPath = new Map(executionSnapshot.sources.map((source) => [source.path, source]));
  for (const source of document.sources) {
    exactKeys(
      source,
      ['repository', 'path', 'mode', 'byteLength', 'sha256', 'blobFile'],
      'source closure entry'
    );
    assertion(source.repository === HARNESS_REPOSITORY_KEY, 'source repository differs');
    assertion(SOURCE_PATHS.includes(source.path), `source path is not allowed: ${source.path}`);
    assertion(source.blobFile === `sources/${source.sha256}.bin`, 'source blob locator differs');
    assertion(SHA256_PATTERN.test(source.sha256), 'source digest is invalid');
    const blobPath = path.join(runDirectory, source.blobFile);
    const metadata = lstatSync(blobPath);
    assertion(metadata.isFile() && !metadata.isSymbolicLink(), 'source blob is unsafe');
    assertion(realpathSync(blobPath) === blobPath, 'source blob path is noncanonical');
    assertion((metadata.mode & 0o777) === 0o600, 'source blob mode differs');
    const bytes = readFileSync(blobPath);
    assertion(bytes.length === source.byteLength, `source length differs: ${source.path}`);
    assertion(sha256(bytes) === source.sha256, `source digest differs: ${source.path}`);
    const executed = executedByPath.get(source.path);
    assertion(executed !== undefined, `executed source is missing: ${source.path}`);
    assertion(source.mode === executed.mode, `executed source mode differs: ${source.path}`);
    assertion(
      source.byteLength === executed.byteLength,
      `executed source length differs: ${source.path}`
    );
    assertion(source.sha256 === executed.sha256, `executed source digest differs: ${source.path}`);
    assertion(bytes.equals(executed.bytes), `executed source bytes differ: ${source.path}`);
    sourceBytesByPath.set(source.path, bytes);
    blobDigests.add(source.sha256);
    framed.push({
      repository: source.repository,
      path: source.path,
      mode: source.mode,
      byteLength: source.byteLength,
      sha256: source.sha256,
    });
  }
  assertion(document.uniqueBlobCount === blobDigests.size, 'unique source blob count differs');
  assertion(framedDigest(framed) === document.sourceSetSha256, 'source-set digest differs');
  return {
    sourceSetSha256: document.sourceSetSha256,
    sourceCount: document.sourceCount,
    uniqueBlobCount: document.uniqueBlobCount,
    bytes(relativePath) {
      const bytes = sourceBytesByPath.get(relativePath);
      assertion(Buffer.isBuffer(bytes), `captured source is missing: ${relativePath}`);
      return bytes;
    },
  };
}

function assertArtifactIgnoreContract(bytes) {
  let text;
  try {
    text = FATAL_UTF8.decode(bytes);
  } catch (error) {
    throw new Error(`H-048 .gitignore is not UTF-8: ${error.message}`);
  }
  assertion(
    text.split(/\r?\n/u).includes('artifacts/'),
    'H-048 .gitignore lacks the exact artifacts/ rule'
  );
}

export function verifyH048Directory(
  runDirectory,
  { repositoryRoot = REPOSITORY_ROOT, write = false } = {}
) {
  assertion(
    process.versions.node === EXPECTED_NODE_VERSION,
    `H-048 verifier requires exact Node ${EXPECTED_NODE_VERSION}`
  );
  assertion(path.isAbsolute(runDirectory), 'run directory must be absolute');
  assertion(path.isAbsolute(repositoryRoot), 'repository root must be absolute');
  assertion(
    repositoryRoot === REPOSITORY_ROOT,
    'verifier repository root must be the module repository'
  );
  assertion(realpathSync(repositoryRoot) === repositoryRoot, 'repository root is noncanonical');
  assertion(realpathSync(runDirectory) === runDirectory, 'run directory is noncanonical');
  assertion(
    path.dirname(runDirectory) === path.join(repositoryRoot, 'artifacts', 'h048'),
    'run root differs'
  );
  const startExecutionSnapshot = captureExecutionSourceSnapshot(repositoryRoot);
  assertExecutionSourceSnapshot(
    startExecutionSnapshot,
    MODULE_LOAD_EXECUTION_SNAPSHOT,
    'verification-start'
  );
  ensureCanonicalDirectory(runDirectory);
  const names = readdirSync(runDirectory).sort();
  const expectedNames = [
    'candidate-index.json',
    'review-universe.json',
    'run.json',
    'source-closure.json',
    'source-map.json',
    'sources',
  ];
  if (names.includes('verification.json')) expectedNames.push('verification.json');
  assertion(
    canonicalJson(names) === canonicalJson(expectedNames.sort()),
    'run artifact set differs'
  );

  const runBytes = readArtifact(runDirectory, 'run.json');
  const sourceClosureBytes = readArtifact(runDirectory, 'source-closure.json');
  const sourceMapBytes = readArtifact(runDirectory, 'source-map.json');
  const reviewUniverseBytes = readArtifact(runDirectory, 'review-universe.json');
  const candidateIndexBytes = readArtifact(runDirectory, 'candidate-index.json');
  const run = parseJson(runBytes, 'run');
  const sourceClosure = parseJson(sourceClosureBytes, 'source closure');
  const sourceMap = parseJson(sourceMapBytes, 'source map');
  const reviewUniverse = parseJson(reviewUniverseBytes, 'review universe');
  const candidateIndex = parseJson(candidateIndexBytes, 'candidate index');
  assertCanonicalJsonArtifact(runBytes, run, 'run artifact');
  assertCanonicalJsonArtifact(sourceClosureBytes, sourceClosure, 'source closure artifact');
  assertCanonicalJsonArtifact(sourceMapBytes, sourceMap, 'source map artifact');
  assertCanonicalJsonArtifact(reviewUniverseBytes, reviewUniverse, 'review universe artifact');
  assertCanonicalJsonArtifact(candidateIndexBytes, candidateIndex, 'candidate index artifact');
  const closureReceipt = validateSourceClosure(runDirectory, sourceClosure, startExecutionSnapshot);
  assertArtifactIgnoreContract(closureReceipt.bytes('.gitignore'));
  const subjectLockBytes = closureReceipt.bytes('lab/h048/subject-lock.json');
  const reviewMapBytes = closureReceipt.bytes('lab/h048/review-map.json');
  const schemaBytes = closureReceipt.bytes(
    'lab/h048/schemas/external-desired-state-run.schema.json'
  );
  const subjectLock = parseJson(subjectLockBytes, 'captured subject lock');
  const reviewMap = parseJson(reviewMapBytes, 'captured review map');
  const schema = parseJson(schemaBytes, 'captured run schema');
  validateSubjectLock(subjectLock);
  validateCapturedRunSchemaIdentity(schema);

  assertion(
    sha256(sourceClosureBytes) === run.artifacts.sourceClosure.sha256,
    'closure artifact digest'
  );
  assertion(
    sourceClosureBytes.length === run.artifacts.sourceClosure.byteLength,
    'closure artifact length'
  );
  assertion(sha256(sourceMapBytes) === run.artifacts.sourceMap.sha256, 'source map digest');
  assertion(sourceMapBytes.length === run.artifacts.sourceMap.byteLength, 'source map length');
  assertion(
    sha256(reviewUniverseBytes) === run.artifacts.reviewUniverse.sha256,
    'review universe digest'
  );
  assertion(
    reviewUniverseBytes.length === run.artifacts.reviewUniverse.byteLength,
    'review universe length'
  );
  assertion(
    sha256(candidateIndexBytes) === run.artifacts.candidateIndex.sha256,
    'candidate digest'
  );
  assertion(
    candidateIndexBytes.length === run.artifacts.candidateIndex.byteLength,
    'candidate length'
  );
  assertion(run.artifacts.sourceClosure.file === 'source-closure.json', 'closure artifact name');
  assertion(run.artifacts.sourceMap.file === 'source-map.json', 'source-map artifact name');
  assertion(
    run.artifacts.reviewUniverse.file === 'review-universe.json',
    'review-universe artifact name'
  );
  assertion(
    run.artifacts.candidateIndex.file === 'candidate-index.json',
    'candidate artifact name'
  );

  const snapshots = subjectLock.repositories.map((lock) =>
    snapshot(path.resolve(repositoryRoot, lock.localLocator), lock)
  );
  const archives = archiveInventory(snapshots);
  const reconstructedReviewUniverse = deriveReviewUniverse({
    subjectLock,
    snapshots,
    archives,
  });
  assertion(
    reconstructedReviewUniverse.bytes.equals(reviewUniverseBytes),
    'independent review-universe reconstruction differs'
  );
  const reconstructedSourceMap = expectedSourceMap(subjectLock, snapshots, archives);
  assertion(
    canonicalJson(sourceMap) === canonicalJson(reconstructedSourceMap),
    'independent source-map reconstruction differs'
  );
  const reconstructedCandidateIndex = expectedCandidateIndex(
    subjectLock,
    subjectLockBytes,
    reviewMap,
    reviewMapBytes,
    snapshots,
    archives,
    reconstructedReviewUniverse
  );
  assertion(
    canonicalJson(candidateIndex) === canonicalJson(reconstructedCandidateIndex),
    'independent candidate reconstruction differs'
  );

  const expectedSemantic = {
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
      kind: sourceClosure.admission.kind,
      signatureStatus: sourceClosure.admission.signatureStatus,
      commit: null,
      sourceCount: sourceClosure.sourceCount,
      uniqueBlobCount: sourceClosure.uniqueBlobCount,
      sourceSetSha256: sourceClosure.sourceSetSha256,
    },
    target: subjectLock.target,
    artifacts: run.artifacts,
    summary: {
      repositories: snapshots.length,
      mainTreeEntries: sourceMap.entryCount,
      trackedArchiveRoots: archives.roots.length,
      expandedArchiveOccurrences: archives.observations.archives,
      expandedArchiveMembers: archives.observations.regularMembers,
      candidates: candidateIndex.candidates.length,
      indirections: candidateIndex.indirections.length,
      unresolvedIndirections: candidateIndex.indirections.filter((indirection) =>
        UNRESOLVED_INDIRECTION_STATUSES.includes(indirection.status)
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
      nodeVersion: EXPECTED_NODE_VERSION,
      gitExecutable: '/usr/bin/git',
      commandPolicy: COMMAND_POLICY,
      observedRepositories: snapshots.map((item) => ({
        repository: item.repository,
        invocationCounts: item.invocationCounts,
      })),
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
  const semantic = { ...run };
  delete semantic.semanticEvidenceSha256;
  assertion(
    canonicalJson(semantic) === canonicalJson(expectedSemantic),
    'independent semantic envelope differs'
  );
  const semanticEvidenceSha256 = sha256(Buffer.from(canonicalJson(expectedSemantic), 'utf8'));
  assertion(
    semanticEvidenceSha256 === run.semanticEvidenceSha256,
    'semantic evidence digest differs'
  );
  const endExecutionSnapshot = captureExecutionSourceSnapshot(repositoryRoot);
  assertExecutionSourceSnapshot(endExecutionSnapshot, startExecutionSnapshot, 'verification-end');

  const verification = {
    schemaVersion: 'overlaykit-h048-verification/v1',
    hypothesis: 'H-048',
    sourceClosureSha256: sha256(sourceClosureBytes),
    localSourceSetSha256: closureReceipt.sourceSetSha256,
    sourceMapSha256: sha256(sourceMapBytes),
    reviewUniverseSha256: sha256(reviewUniverseBytes),
    candidateIndexSha256: sha256(candidateIndexBytes),
    semanticEvidenceSha256,
    subject: {
      repositories: snapshots.map((item) => ({
        repository: item.repository,
        commit: item.commit,
        tree: item.tree,
        entryCount: item.entries.length,
        lsTreeSha256: sha256(item.treeBytes),
      })),
      totalEntries: snapshots.reduce((sum, item) => sum + item.entries.length, 0),
      archiveRoots: archives.roots.length,
      archiveOccurrences: archives.observations.archives,
      archiveMembers: archives.observations.regularMembers,
    },
    outcome: candidateIndex.outcome,
    checks: {
      strictRunSchemaSourceExact: true,
      runEnvelopeExact: true,
      nodeVersionExact: true,
      localSourceClosureExact: true,
      sourceBlobsExact: true,
      executedSourceClosureExact: true,
      sourceDoubleSnapshotExact: true,
      twoRepositoryTreesExact: true,
      repositoryQualifiedSourceMapExact: true,
      archiveClosureExact: true,
      reviewUniverseIndependentlyReconstructed: true,
      candidateIndexIndependentlyReconstructed: true,
      semanticEnvelopeIndependentlyReconstructed: true,
      acceptedSetPreimagesAvailable: [
        admitSetAnchor(subjectLock.repoSet, 'verification repo-set'),
        ...subjectLock.repositories.map((repository) =>
          admitSetAnchor(repository.refSet, `verification ${repository.key} ref-set`)
        ),
      ].every((admission) => admission.admitted),
      authorityNone: true,
      actionNull: true,
    },
    verified: true,
    authority: 'none',
    action: null,
  };
  const verificationBytes = Buffer.from(`${canonicalJson(verification)}\n`, 'utf8');
  const verificationPath = path.join(runDirectory, 'verification.json');
  if (existsSync(verificationPath)) {
    const existingVerificationBytes = readArtifact(runDirectory, 'verification.json');
    assertion(
      existingVerificationBytes.equals(verificationBytes),
      'existing verification receipt differs'
    );
  }
  if (write) {
    assertion(!existsSync(verificationPath), 'verification already exists');
    writeFileSync(verificationPath, verificationBytes, { flag: 'wx', mode: 0o600 });
  }
  return { verification, bytes: verificationBytes };
}

function parseArguments(argv) {
  assertion(
    argv.length === 1 || (argv.length === 2 && argv[1] === '--write'),
    'Usage: node lab/h048/verify.mjs <run-directory> [--write]'
  );
  const runDirectory = path.resolve(argv[0]);
  return { runDirectory, write: argv[1] === '--write' };
}

if (
  process.argv[1] !== undefined &&
  realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
) {
  assertion(
    process.versions.node === EXPECTED_NODE_VERSION,
    `H-048 verifier requires exact Node ${EXPECTED_NODE_VERSION}`
  );
  const { runDirectory, write } = parseArguments(process.argv.slice(2));
  const { verification } = verifyH048Directory(runDirectory, { write });
  process.stdout.write(`${JSON.stringify(verification)}\n`);
}
