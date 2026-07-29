import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateSync } from 'node:zlib';

const LAB_DIRECTORY = realpathSync(path.dirname(fileURLToPath(import.meta.url)));
const REPOSITORY_ROOT = realpathSync(path.resolve(LAB_DIRECTORY, '../..'));
const SUBJECT_PATH = path.join(LAB_DIRECTORY, 'subject-lock.json');
const GIT_DIRECTORY = path.join(REPOSITORY_ROOT, '.git');
const H054_RUN_PATH = path.join(
  REPOSITORY_ROOT,
  'artifacts',
  'h054',
  'runs',
  '8547552f833c37664099febcc0ad5ab081a277806e129a4b9dba98cdd39b8ec0',
  'run.json'
);

const EXPECTED = Object.freeze({
  studyId: 'NODE22-BOUNDARY-PREFLIGHT-001',
  predecessorCommit: 'bb6ce5db53541a7926eb74b3c722fa039ca9dabd',
  predecessorTree: '823796b0c9f509cf4ed35b9febeb71c284626036',
  planRawSha256: '2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243',
  planHash: 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4',
  predecessorManifestRawSha256: '8b3fb70d5dc2f8835a2b65b7b882880eb40cdbd58864135ecdaf5b3b105d062e',
  chg0035RawSha256: 'c745964d4d2277dfb88a5893ef971df87a849dfe2266563268603e77f98f7922',
  h054RawSha256: '250e6115b9e9dc6d9e750788c16626657feca5577c102b84a48e4fb4bf2444f2',
  h054SemanticSha256: '8547552f833c37664099febcc0ad5ab081a277806e129a4b9dba98cdd39b8ec0',
  node22Version: 'v22.22.2',
  node22Path: '/usr/bin/node-22',
  node22Sha256: '1a1ebcd93dc90cf3e3dc37493e8efc04a1f60bddada1402453094214af03e33d',
  bwrapPath: '/usr/bin/bwrap',
  bwrapVersion: 'bubblewrap 0.11.0',
  bwrapSha256: 'b3708edde1d80e5f570f2e15d692e49c1d96dc8f411896c60abd489c13368390',
  gitignoreRawSha256: '2c42503834e61def3bf5840b5c553a73b2d569cee732c69e7420f75ce5e6f1fc',
  subjectRawSha256: 'c909b2c5736c1b50ee03b03ac29dc3d4881db04d455fab05f93e6685486692e6',
});

const KNOWN_BLOCKERS = Object.freeze([
  'exhaustive-esm-and-open-file-trace-not-admitted',
  'content-addressed-effective-seccomp-policy-not-admitted',
  'kernel-vdso-and-late-loaded-object-closure-not-established',
  'bubblewrap-host-dynamic-library-and-effective-kernel-enforcement-not-independently-traced',
  'worker-and-child-process-cardinality-not-independently-traced',
  'universal-successor-absence-not-provable-without-exhaustive-trace',
  'anchor-resolver-host-dynamic-library-and-git-object-read-closure-not-independently-traced',
  'path-execution-image-identity-not-atomically-bound',
  'successor-apparatus-and-accepted-h054-layer-source-lock-not-established',
  'failed-attempt-evidence-preservation-and-outcome-derivation-not-established',
]);

const EXPECTED_ANCHOR_RESOLVER = Object.freeze({
  executable: '/usr/bin/git',
  version: 'git version 2.55.0',
  sha256: '8d8d470218586c27909c9b6ae77d18df32a9e05e725044ae2052d60254791c26',
  environment: {
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_SYSTEM: '/dev/null',
    GIT_NO_LAZY_FETCH: '1',
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_TERMINAL_PROMPT: '0',
    HOME: '/nonexistent',
    LANG: 'C',
    LC_ALL: 'C',
    PATH: '/usr/bin',
  },
  headCommitCommand: ['rev-parse', 'HEAD^{commit}'],
  headTreeCommand: ['rev-parse', 'HEAD^{tree}'],
  predecessorManifestCommand: [
    'show',
    'bb6ce5db53541a7926eb74b3c722fa039ca9dabd:.overlaykit/governance/manifest.json',
  ],
});

const EXPECTED_CONTROL_CONTRACT = Object.freeze([
  { expectedReasonCode: 'temporal-anchor-stale', id: 'stale-temporal-anchor' },
  { expectedReasonCode: 'runtime-identity-drift', id: 'substitute-node22' },
  { expectedReasonCode: 'apparatus-source-set-drift', id: 'stale-apparatus' },
  { expectedReasonCode: 'apparatus-source-set-drift', id: 'omit-apparatus-entry' },
  { expectedReasonCode: 'module-universe-incomplete', id: 'omit-package-mount' },
  { expectedReasonCode: 'module-universe-incomplete', id: 'omit-import-target' },
  { expectedReasonCode: 'module-universe-incomplete', id: 'stale-ajv-entry' },
  { expectedReasonCode: 'loader-config-escape', id: 'enable-tsconfig-fallback' },
  { expectedReasonCode: 'loader-config-escape', id: 'add-tsconfig-extends-chain' },
  { expectedReasonCode: 'environment-closure-drift', id: 'inject-environment-selector' },
  { expectedReasonCode: 'permission-envelope-drift', id: 'weaken-node-permission-flags' },
  { expectedReasonCode: 'mount-boundary-broadened', id: 'broaden-root-bind' },
  { expectedReasonCode: 'mount-boundary-broadened', id: 'add-write-bind' },
  { expectedReasonCode: 'isolation-policy-drift', id: 'share-network-namespace' },
  { expectedReasonCode: 'native-closure-drift', id: 'omit-shared-object' },
  { expectedReasonCode: 'native-closure-drift', id: 'substitute-esbuild-native' },
  { expectedReasonCode: 'path-resolution-invalid', id: 'symlink-retarget' },
  { expectedReasonCode: 'path-resolution-invalid', id: 'symlink-escape' },
  { expectedReasonCode: 'path-resolution-invalid', id: 'symlink-cycle' },
  { expectedReasonCode: 'path-resolution-invalid', id: 'symlink-dangling' },
  { expectedReasonCode: 'mutable-state-observed', id: 'scratch-residue' },
  { expectedReasonCode: 'mutable-state-observed', id: 'enable-loader-cache' },
  { expectedReasonCode: 'ambient-capability-observed', id: 'working-directory-drift' },
  { expectedReasonCode: 'layer-collision', id: 'layer-logical-path-collision' },
  { expectedReasonCode: 'layer-collision', id: 'cross-layer-mount-target-collision' },
  { expectedReasonCode: 'determinism-failure', id: 'duplicate-attempt-divergence' },
  { expectedReasonCode: 'forbidden-subject-path', id: 'forbidden-subject-import' },
  { expectedReasonCode: 'outcome-policy-violation', id: 'claim-supported-with-blocker' },
  { expectedReasonCode: 'evidence-integrity-drift', id: 'receipt-tamper' },
  { expectedReasonCode: 'authority-overclaim', id: 'authority-tamper' },
  { expectedReasonCode: 'successor-state-overclaim', id: 'false-successor-state' },
]);

const EXPECTED_REQUIRED_PREDICATES = Object.freeze([
  'trackedPredecessorExact',
  'acceptedH054ExactAndUnchanged',
  'selectedNode22Exact',
  'apparatusSourceClosureExact',
  'emptyRootMountClosureExact',
  'environmentClosureExact',
  'nodePermissionEnvelopeExact',
  'isolatedNetworkNamespaceExact',
  'syntheticTsxObservationExact',
  'syntheticAjvObservationExact',
  'syntheticEsbuildObservationExact',
  'attemptsCanonicallyEquivalent',
  'failureBranchEvidenceMaterializable',
  'independentVerifierReconstructs',
  'allControlsFailClosed',
  'exhaustiveOpenFileAndModuleClosure',
  'effectiveSyscallClosure',
  'nativeAndLateLoadedObjectClosure',
  'noSuccessorHypothesisOpenedOrExecuted',
  'authorityNoneAndActionNull',
]);

const EXPECTED_ENVIRONMENT = Object.freeze({
  ESBUILD_BINARY_PATH: '/workspace/node_modules/@esbuild/linux-x64/bin/esbuild',
  ESBUILD_WORKER_THREADS: '0',
  HOME: '/home/probe',
  LANG: 'C',
  LC_ALL: 'C',
  NODE_DISABLE_COLORS: '1',
  NODE_DISABLE_COMPILE_CACHE: '1',
  NO_COLOR: '1',
  PATH: '/usr/bin',
  PWD: '/workspace',
  TERM: 'dumb',
  TMPDIR: '/tmp',
  TSX_DISABLE_CACHE: '1',
  TSX_TSCONFIG_PATH: '/workspace/lab/node22-boundary-preflight/fixtures/tsconfig.json',
  TZ: 'UTC',
  XDG_CACHE_HOME: '/tmp',
});

const EXPECTED_TSX_CONFIG_MODE = 'explicit-register-option';

const EXPECTED_INPUTS = Object.freeze({
  fixture: {
    locator: 'lab/node22-boundary-preflight/fixtures/synthetic-probe.ts',
    sha256: '99e2e5d85d058cc357a030bde230267982a35306e67e22d75e4871d9d7062136',
  },
  tsconfig: {
    extends: null,
    locator: 'lab/node22-boundary-preflight/fixtures/tsconfig.json',
    sha256: '0947c5ba6762c9ec613c48b9fa55df51d6a4c72783b5870f4abaff0ee82aaac0',
  },
});

const EXPECTED_RAW_EVIDENCE_POLICY = Object.freeze({
  evidenceRootLocator: 'artifacts/',
  gitignore: {
    locator: '.gitignore',
    rawSha256: '2c42503834e61def3bf5840b5c553a73b2d569cee732c69e7420f75ce5e6f1fc',
    requiredPattern: 'artifacts/',
  },
  mustRemainIgnored: true,
});

const EXPECTED_NODE_ARGV = Object.freeze([
  '/usr/bin/node-22',
  '--permission',
  '--allow-fs-read=/workspace',
  '--allow-fs-read=/WORKSPACE',
  '--allow-fs-read=/tmp',
  '--allow-worker',
  '--allow-child-process',
  '--no-addons',
  '--no-warnings',
  '/workspace/lab/node22-boundary-preflight/probe.mjs',
]);

const EXPECTED_EXEC_ARGV = Object.freeze(EXPECTED_NODE_ARGV.slice(1, -1));

const RUN_KEYS = Object.freeze([
  'action',
  'anchors',
  'attempts',
  'authority',
  'blockers',
  'controls',
  'humanReview',
  'interpretation',
  'launcher',
  'normalizations',
  'observation',
  'outcome',
  'predicates',
  'repeatability',
  'runId',
  'schemaVersion',
  'semanticSha256',
  'sourceClosure',
  'studyId',
]);

const OBSERVATION_KEYS = Object.freeze([
  'action',
  'ajv',
  'authority',
  'blockers',
  'environment',
  'esbuild',
  'fixture',
  'invocation',
  'normalizations',
  'outcome',
  'permissionEnvelope',
  'pathResolution',
  'runtime',
  'schemaVersion',
  'scratch',
  'tsconfig',
  'tsx',
]);

export class InvalidNode22PreflightEvidenceError extends Error {
  constructor(reasonCode, message) {
    super(message);
    this.name = 'InvalidNode22PreflightEvidenceError';
    this.reasonCode = reasonCode;
  }
}

function assertion(condition, reasonCode, message) {
  if (!condition) {
    throw new InvalidNode22PreflightEvidenceError(reasonCode, message);
  }
}

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
  );
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function sameArray(left, right) {
  return (
    Array.isArray(left) &&
    Array.isArray(right) &&
    left.length === right.length &&
    left.every((entry, index) => entry === right[index])
  );
}

function exactKeys(value, expected, label, reasonCode = 'evidence-shape-invalid') {
  assertion(isPlainObject(value), reasonCode, `${label} must be an object`);
  const actual = Object.keys(value).sort(compareUtf8);
  const wanted = [...expected].sort(compareUtf8);
  assertion(sameArray(actual, wanted), reasonCode, `${label} keys differ: ${actual.join(',')}`);
}

function canonicalValue(value, seen = new Set()) {
  if (Array.isArray(value)) {
    assertion(!seen.has(value), 'canonical-value-invalid', 'canonical JSON contains a cycle');
    seen.add(value);
    const result = value.map((entry) => canonicalValue(entry, seen));
    seen.delete(value);
    return result;
  }
  if (isPlainObject(value)) {
    assertion(!seen.has(value), 'canonical-value-invalid', 'canonical JSON contains a cycle');
    seen.add(value);
    const result = Object.fromEntries(
      Object.keys(value)
        .sort(compareUtf8)
        .map((key) => [key, canonicalValue(value[key], seen)])
    );
    seen.delete(value);
    return result;
  }
  assertion(
    value === null ||
      typeof value === 'string' ||
      typeof value === 'boolean' ||
      (typeof value === 'number' && Number.isSafeInteger(value)),
    'canonical-value-invalid',
    `unsupported canonical value: ${String(value)}`
  );
  return value;
}

export function canonicalJsonIndependent(value) {
  return JSON.stringify(canonicalValue(value));
}

export function canonicalPrettyJsonIndependent(value) {
  return `${JSON.stringify(canonicalValue(value), null, 2)}\n`;
}

export function sha256Independent(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

export function canonicalHashIndependent(value) {
  return sha256Independent(Buffer.from(canonicalJsonIndependent(value), 'utf8'));
}

function governanceCanonicalHashIndependent(value) {
  function canonicalize(entry) {
    if (Array.isArray(entry)) return entry.map((item) => canonicalize(item));
    if (isPlainObject(entry)) {
      return Object.fromEntries(
        Object.keys(entry)
          .sort((left, right) => left.localeCompare(right))
          .map((key) => [key, canonicalize(entry[key])])
      );
    }
    assertion(
      entry === null ||
        typeof entry === 'string' ||
        typeof entry === 'boolean' ||
        (typeof entry === 'number' && Number.isFinite(entry)),
      'temporal-anchor-stale',
      'unsupported governance manifest value'
    );
    return entry;
  }
  return sha256Independent(Buffer.from(JSON.stringify(canonicalize(value)), 'utf8'));
}

function parseJsonBytes(bytes, label) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (error) {
    throw new InvalidNode22PreflightEvidenceError(
      'evidence-utf8-invalid',
      `${label}: ${error.message}`
    );
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new InvalidNode22PreflightEvidenceError(
      'evidence-json-invalid',
      `${label}: ${error.message}`
    );
  }
}

function stableMetadata(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs
  );
}

function readRegularFileStable(absolutePath, label) {
  const pathnameBefore = lstatSync(absolutePath);
  assertion(
    pathnameBefore.isFile() && !pathnameBefore.isSymbolicLink(),
    'path-resolution-invalid',
    `${label} is not a regular file`
  );
  const descriptor = openSync(absolutePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(descriptor);
    assertion(
      before.isFile() &&
        before.dev === pathnameBefore.dev &&
        before.ino === pathnameBefore.ino &&
        before.mode === pathnameBefore.mode,
      'path-resolution-invalid',
      `${label} changed before read`
    );
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    const pathnameAfter = lstatSync(absolutePath);
    assertion(
      stableMetadata(before, after) &&
        pathnameAfter.dev === after.dev &&
        pathnameAfter.ino === after.ino &&
        pathnameAfter.mode === after.mode &&
        pathnameAfter.nlink === after.nlink &&
        pathnameAfter.size === after.size,
      'path-resolution-invalid',
      `${label} changed while read`
    );
    return { bytes, metadata: after };
  } finally {
    closeSync(descriptor);
  }
}

function octalMode(metadata) {
  return (metadata.mode & 0o7777).toString(8).padStart(4, '0');
}

function repositoryAbsolute(logicalPath) {
  assertion(
    typeof logicalPath === 'string' &&
      logicalPath !== '' &&
      !logicalPath.startsWith('/') &&
      !logicalPath.includes('\\') &&
      path.posix.normalize(logicalPath) === logicalPath &&
      logicalPath.split('/').every((component) => component !== '' && component !== '..'),
    'path-resolution-invalid',
    `unsafe repository path: ${String(logicalPath)}`
  );
  const absolute = path.resolve(REPOSITORY_ROOT, logicalPath);
  assertion(
    absolute.startsWith(`${REPOSITORY_ROOT}${path.sep}`),
    'path-resolution-invalid',
    logicalPath
  );
  return absolute;
}

function assertRepositoryPathComponentsSymlinkFree(absolutePath) {
  const relative = path.relative(REPOSITORY_ROOT, absolutePath);
  assertion(
    relative !== '' &&
      relative !== '..' &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative),
    'raw-path-invalid',
    'raw evidence path escapes the repository'
  );
  let cursor = REPOSITORY_ROOT;
  for (const segment of relative.split(path.sep)) {
    cursor = path.join(cursor, segment);
    const metadata = lstatSync(cursor);
    assertion(
      !metadata.isSymbolicLink(),
      'raw-path-invalid',
      `raw evidence path contains a symbolic link: ${cursor}`
    );
  }
}

function assertPrivateRawDirectory(absolutePath, label) {
  const metadata = lstatSync(absolutePath);
  assertion(
    metadata.isDirectory() &&
      !metadata.isSymbolicLink() &&
      (metadata.mode & 0o777) === 0o700 &&
      metadata.uid === process.getuid(),
    'raw-directory-invalid',
    `${label} is not a private owner-controlled 0700 directory`
  );
}

function verifyRawIgnoreBoundary() {
  const receipt = readRegularFileStable(
    path.join(REPOSITORY_ROOT, '.gitignore'),
    'repository ignore policy'
  );
  assertion(
    sha256Independent(receipt.bytes) === EXPECTED.gitignoreRawSha256,
    'raw-ignore-invalid',
    'repository ignore policy bytes differ'
  );
  const lines = receipt.bytes.toString('utf8').split(/\r?\n/u);
  assertion(
    lines.filter((line) => line === 'artifacts/').length === 1,
    'raw-ignore-invalid',
    'artifacts ignore rule is absent or ambiguous'
  );
}

function fileSha256(absolutePath, label = absolutePath) {
  return sha256Independent(readRegularFileStable(absolutePath, label).bytes);
}

function assertOptionalGitIndirectionsAbsent() {
  const forbiddenFiles = [
    path.join(GIT_DIRECTORY, 'info', 'grafts'),
    path.join(GIT_DIRECTORY, 'objects', 'info', 'alternates'),
    path.join(GIT_DIRECTORY, 'shallow'),
  ];
  for (const pathname of forbiddenFiles) {
    try {
      const metadata = lstatSync(pathname);
      assertion(
        metadata.isFile() && readRegularFileStable(pathname, pathname).bytes.length === 0,
        'temporal-anchor-stale',
        `${pathname} changes Git object semantics`
      );
    } catch (error) {
      if (error instanceof InvalidNode22PreflightEvidenceError) throw error;
      assertion(error?.code === 'ENOENT', 'temporal-anchor-stale', pathname);
    }
  }

  const replaceDirectory = path.join(GIT_DIRECTORY, 'refs', 'replace');
  try {
    assertion(
      readdirSync(replaceDirectory).length === 0,
      'temporal-anchor-stale',
      'replace refs are present'
    );
  } catch (error) {
    if (error instanceof InvalidNode22PreflightEvidenceError) throw error;
    assertion(error?.code === 'ENOENT', 'temporal-anchor-stale', replaceDirectory);
  }
}

function readLooseGitObject(oid, expectedType) {
  assertion(/^[0-9a-f]{40}$/u.test(oid), 'temporal-anchor-stale', `invalid OID ${oid}`);
  const objectPath = path.join(GIT_DIRECTORY, 'objects', oid.slice(0, 2), oid.slice(2));
  let inflated;
  try {
    inflated = inflateSync(readRegularFileStable(objectPath, `Git object ${oid}`).bytes);
  } catch (error) {
    if (error instanceof InvalidNode22PreflightEvidenceError) throw error;
    throw new InvalidNode22PreflightEvidenceError(
      'temporal-anchor-stale',
      `loose Git object ${oid} is unavailable or invalid: ${error.message}`
    );
  }
  assertion(
    createHash('sha1').update(inflated).digest('hex') === oid,
    'temporal-anchor-stale',
    `Git object ${oid} does not reproduce its OID`
  );
  const separator = inflated.indexOf(0);
  assertion(separator > 0, 'temporal-anchor-stale', `Git object ${oid} has no header`);
  const header = inflated.subarray(0, separator).toString('ascii');
  const match = /^(?<type>[a-z]+) (?<size>[0-9]+)$/u.exec(header);
  assertion(match !== null, 'temporal-anchor-stale', `Git object ${oid} header is invalid`);
  const body = inflated.subarray(separator + 1);
  assertion(
    match.groups.type === expectedType && Number(match.groups.size) === body.length,
    'temporal-anchor-stale',
    `Git object ${oid} type or length differs`
  );
  return body;
}

function parseLooseTree(body, treeOid) {
  const entries = [];
  let offset = 0;
  while (offset < body.length) {
    const modeEnd = body.indexOf(0x20, offset);
    const nameEnd = body.indexOf(0x00, modeEnd + 1);
    assertion(
      modeEnd > offset && nameEnd > modeEnd + 1 && nameEnd + 21 <= body.length,
      'temporal-anchor-stale',
      `tree ${treeOid} has a malformed entry`
    );
    const mode = body.subarray(offset, modeEnd).toString('ascii');
    const nameBytes = body.subarray(modeEnd + 1, nameEnd);
    const name = nameBytes.toString('utf8');
    assertion(
      Buffer.from(name, 'utf8').equals(nameBytes) &&
        name !== '.' &&
        name !== '..' &&
        !name.includes('/'),
      'temporal-anchor-stale',
      `tree ${treeOid} has a non-canonical name`
    );
    entries.push({
      mode,
      name,
      oid: body.subarray(nameEnd + 1, nameEnd + 21).toString('hex'),
    });
    offset = nameEnd + 21;
  }
  assertion(offset === body.length, 'temporal-anchor-stale', `tree ${treeOid} is truncated`);
  return entries;
}

function resolveLooseGitPath(rootTreeOid, pathSegments) {
  let treeOid = rootTreeOid;
  const traversedTrees = [];
  for (const [index, segment] of pathSegments.entries()) {
    const treeBody = readLooseGitObject(treeOid, 'tree');
    traversedTrees.push({
      byteLength: treeBody.length,
      oid: treeOid,
      sha256: sha256Independent(treeBody),
    });
    const entry = parseLooseTree(treeBody, treeOid).find(({ name }) => name === segment);
    assertion(
      entry !== undefined,
      'temporal-anchor-stale',
      `${pathSegments.slice(0, index + 1).join('/')} is absent from predecessor tree`
    );
    if (index < pathSegments.length - 1) {
      assertion(
        entry.mode === '40000',
        'temporal-anchor-stale',
        `${pathSegments.slice(0, index + 1).join('/')} is not a tree`
      );
      treeOid = entry.oid;
      continue;
    }
    assertion(
      entry.mode === '100644' || entry.mode === '100755',
      'temporal-anchor-stale',
      `${pathSegments.join('/')} is not a regular blob`
    );
    const blob = readLooseGitObject(entry.oid, 'blob');
    return {
      blob,
      blobOid: entry.oid,
      mode: entry.mode,
      traversedTrees,
    };
  }
  throw new InvalidNode22PreflightEvidenceError(
    'temporal-anchor-stale',
    'empty predecessor Git path'
  );
}

function verifyControlContract(subject) {
  assertion(
    canonicalJsonIndependent(subject.controlContract) ===
      canonicalJsonIndependent(EXPECTED_CONTROL_CONTRACT),
    'evidence-integrity-drift',
    'control contract differs from the independently pinned 31-control roster'
  );
  for (const [index, control] of subject.controlContract.entries()) {
    exactKeys(
      control,
      ['expectedReasonCode', 'id'],
      `control contract ${index}`,
      'evidence-integrity-drift'
    );
    assertion(
      typeof control.id === 'string' &&
        control.id !== '' &&
        typeof control.expectedReasonCode === 'string' &&
        control.expectedReasonCode !== '',
      'evidence-integrity-drift',
      `control contract ${index} is malformed`
    );
  }
  assertion(
    canonicalJsonIndependent(subject.controlExecutionPolicy) ===
      canonicalJsonIndependent({
        forbiddenSubjectMayBeImportedOrExecuted: false,
        hostileBoundaryMutationDisposition: 'reject-before-execution',
        launchCountScope: 'positive-bubblewrap-boundary-only',
        mutationMedium: 'in-memory declaration or receipt only',
        onlyPositiveBoundaryMayLaunch: true,
        weakenedSandboxMayLaunch: false,
      }),
    'evidence-integrity-drift',
    'control execution policy differs'
  );
}

export function reconstructLooseGitAnchor() {
  assertOptionalGitIndirectionsAbsent();
  const headBytes = readRegularFileStable(path.join(GIT_DIRECTORY, 'HEAD'), '.git/HEAD').bytes;
  const head = headBytes.toString('utf8').trim();
  const symbolic = /^ref: (?<ref>refs\/[A-Za-z0-9._/-]+)$/u.exec(head);
  assertion(symbolic !== null, 'temporal-anchor-stale', `unsupported HEAD: ${head}`);
  assertion(
    symbolic.groups.ref === 'refs/heads/main',
    'temporal-anchor-stale',
    `HEAD resolves ${symbolic.groups.ref}`
  );
  const refPath = path.join(GIT_DIRECTORY, ...symbolic.groups.ref.split('/'));
  const commit = readRegularFileStable(refPath, symbolic.groups.ref).bytes.toString('ascii').trim();
  assertion(commit === EXPECTED.predecessorCommit, 'temporal-anchor-stale', `HEAD is ${commit}`);
  const commitBody = readLooseGitObject(commit, 'commit');
  const treeMatch = /^tree (?<tree>[0-9a-f]{40})$/mu.exec(commitBody.toString('utf8'));
  assertion(treeMatch !== null, 'temporal-anchor-stale', 'commit has no tree');
  const tree = treeMatch.groups.tree;
  assertion(tree === EXPECTED.predecessorTree, 'temporal-anchor-stale', `HEAD tree is ${tree}`);
  const treeBody = readLooseGitObject(tree, 'tree');
  const predecessorManifest = resolveLooseGitPath(tree, [
    '.overlaykit',
    'governance',
    'manifest.json',
  ]);
  assertion(
    sha256Independent(predecessorManifest.blob) === EXPECTED.predecessorManifestRawSha256,
    'temporal-anchor-stale',
    'loose predecessor manifest bytes drifted'
  );
  return {
    commit,
    commitObjectSha256: sha256Independent(commitBody),
    headRef: symbolic.groups.ref,
    predecessorManifest: {
      blobByteLength: predecessorManifest.blob.length,
      blobOid: predecessorManifest.blobOid,
      mode: predecessorManifest.mode,
      rawSha256: sha256Independent(predecessorManifest.blob),
      traversedTrees: predecessorManifest.traversedTrees,
    },
    tree,
    treeObjectByteLength: treeBody.length,
    treeObjectSha256: sha256Independent(treeBody),
  };
}

function verifySubjectContract(subject) {
  exactKeys(
    subject,
    [
      'agent',
      'authorization',
      'controlContract',
      'controlExecutionPolicy',
      'executionContract',
      'hypothesis',
      'id',
      'knownBlockingUnknowns',
      'normative',
      'rawEvidencePolicy',
      'requiredPredicates',
      'schemaVersion',
      'temporalBoundary',
    ],
    'subject lock',
    'temporal-anchor-stale'
  );
  assertion(
    subject.schemaVersion === 'overlaykit-node22-boundary-preflight-subject/v1' &&
      subject.id === EXPECTED.studyId &&
      subject.normative === false &&
      subject.agent?.identity === 'Codex /root' &&
      subject.agent?.humanPrincipal === '@rodrigoteamx' &&
      subject.agent?.authority === 'none' &&
      subject.agent?.action === null,
    'temporal-anchor-stale',
    'subject identity differs'
  );
  const temporal = subject.temporalBoundary;
  assertion(
    temporal?.trackedPredecessor?.commit === EXPECTED.predecessorCommit &&
      temporal.trackedPredecessor.tree === EXPECTED.predecessorTree &&
      temporal.trackedPredecessor.planRawSha256 === EXPECTED.planRawSha256 &&
      temporal.trackedPredecessor.planHash === EXPECTED.planHash &&
      temporal.trackedPredecessor.predecessorManifestRawSha256 ===
        EXPECTED.predecessorManifestRawSha256 &&
      temporal.trackedPredecessor.chg0035RawSha256 === EXPECTED.chg0035RawSha256 &&
      temporal?.acceptedH054?.classification === 'inconclusive' &&
      temporal.acceptedH054.rawSha256 === EXPECTED.h054RawSha256 &&
      temporal.acceptedH054.semanticSha256 === EXPECTED.h054SemanticSha256 &&
      temporal.acceptedH054.adrCandidate === false &&
      temporal.acceptedH054.preserveByteIdentical === true &&
      temporal?.prospectiveRuntimeSelection?.id === 'node22' &&
      temporal.prospectiveRuntimeSelection.commandPath === EXPECTED.node22Path &&
      temporal.prospectiveRuntimeSelection.version === EXPECTED.node22Version &&
      temporal.prospectiveRuntimeSelection.executableSha256 === EXPECTED.node22Sha256 &&
      temporal.prospectiveRuntimeSelection.rewritesAcceptedH054 === false,
    'temporal-anchor-stale',
    'subject temporal boundary differs'
  );
  assertion(
    canonicalJsonIndependent(subject.knownBlockingUnknowns) ===
      canonicalJsonIndependent(KNOWN_BLOCKERS),
    'outcome-policy-violation',
    'known blockers differ'
  );
  assertion(
    canonicalJsonIndependent(subject.requiredPredicates) ===
      canonicalJsonIndependent(EXPECTED_REQUIRED_PREDICATES),
    'outcome-policy-violation',
    'required predicate roster differs'
  );
  assertion(
    canonicalJsonIndependent(subject.rawEvidencePolicy) ===
      canonicalJsonIndependent(EXPECTED_RAW_EVIDENCE_POLICY),
    'raw-evidence-policy-drift',
    'raw evidence policy differs'
  );
  verifyControlContract(subject);
  const execution = subject.executionContract;
  assertion(
    canonicalJsonIndependent(execution?.normalizations) === '[]' &&
      canonicalJsonIndependent(execution?.environment) ===
        canonicalJsonIndependent(EXPECTED_ENVIRONMENT) &&
      canonicalJsonIndependent(execution?.expectedInputs) ===
        canonicalJsonIndependent(EXPECTED_INPUTS) &&
      canonicalJsonIndependent(execution?.nodeArgv) ===
        canonicalJsonIndependent(EXPECTED_NODE_ARGV) &&
      canonicalJsonIndependent(execution?.anchorResolver) ===
        canonicalJsonIndependent(EXPECTED_ANCHOR_RESOLVER) &&
      execution?.launcher?.executable === EXPECTED.bwrapPath &&
      execution.launcher.version === EXPECTED.bwrapVersion &&
      execution.launcher.sha256 === EXPECTED.bwrapSha256 &&
      execution.moduleResolution.fixture === `/workspace/${EXPECTED_INPUTS.fixture.locator}` &&
      execution.moduleResolution.tsxConfig === `/workspace/${EXPECTED_INPUTS.tsconfig.locator}` &&
      execution.seccompPolicy === null &&
      execution.expectedAttemptCount === 2,
    'temporal-anchor-stale',
    'execution contract differs'
  );
}

function readAndVerifySubject() {
  const receipt = readRegularFileStable(SUBJECT_PATH, 'subject lock');
  const subject = parseJsonBytes(receipt.bytes, 'subject lock');
  verifySubjectContract(subject);
  const rawSha256 = sha256Independent(receipt.bytes);
  assertion(
    rawSha256 === EXPECTED.subjectRawSha256,
    'temporal-anchor-stale',
    'subject lock bytes differ from the independently pinned source'
  );
  return { subject, rawSha256 };
}

function runPinnedAnchorResolver(resolver, argv) {
  const allowed = [
    resolver.headCommitCommand,
    resolver.headTreeCommand,
    resolver.predecessorManifestCommand,
  ];
  assertion(
    allowed.some((command) => canonicalJsonIndependent(command) === canonicalJsonIndependent(argv)),
    'anchor-resolver-command-drift',
    canonicalHashIndependent(argv)
  );
  const result = spawnSync(resolver.executable, argv, {
    cwd: REPOSITORY_ROOT,
    encoding: null,
    env: { ...resolver.environment },
    maxBuffer: 16 * 1024 * 1024,
  });
  assertion(
    result.error === undefined &&
      result.status === 0 &&
      result.signal === null &&
      result.stderr.length === 0,
    'temporal-anchor-unavailable',
    result.error?.message ?? result.stderr?.toString('utf8') ?? ''
  );
  return result.stdout;
}

function verifyPinnedAnchorResolver(subject, looseGit) {
  const resolver = subject.executionContract.anchorResolver;
  assertion(
    canonicalJsonIndependent(resolver) === canonicalJsonIndependent(EXPECTED_ANCHOR_RESOLVER),
    'anchor-resolver-identity-drift',
    'anchor resolver declaration differs'
  );
  const executable = readRegularFileStable(resolver.executable, 'anchor resolver');
  assertion(
    sha256Independent(executable.bytes) === resolver.sha256,
    'anchor-resolver-identity-drift',
    'anchor resolver executable bytes differ'
  );
  const version = spawnSync(resolver.executable, ['--version'], {
    cwd: REPOSITORY_ROOT,
    encoding: null,
    env: { ...resolver.environment },
    maxBuffer: 1024 * 1024,
  });
  assertion(
    version.error === undefined &&
      version.status === 0 &&
      version.signal === null &&
      version.stderr.length === 0 &&
      version.stdout.toString('utf8').trim() === resolver.version,
    'anchor-resolver-identity-drift',
    version.error?.message ?? version.stdout?.toString('utf8').trim() ?? ''
  );

  const commit = runPinnedAnchorResolver(resolver, resolver.headCommitCommand)
    .toString('utf8')
    .trim();
  const tree = runPinnedAnchorResolver(resolver, resolver.headTreeCommand).toString('utf8').trim();
  const predecessorManifest = runPinnedAnchorResolver(
    resolver,
    resolver.predecessorManifestCommand
  );
  assertion(
    commit === EXPECTED.predecessorCommit &&
      tree === EXPECTED.predecessorTree &&
      commit === looseGit.commit &&
      tree === looseGit.tree,
    'temporal-anchor-stale',
    'pinned resolver and loose Git reconstruction disagree'
  );
  assertion(
    sha256Independent(predecessorManifest) === EXPECTED.predecessorManifestRawSha256 &&
      predecessorManifest.equals(
        resolveLooseGitPath(looseGit.tree, ['.overlaykit', 'governance', 'manifest.json']).blob
      ),
    'temporal-anchor-stale',
    'pinned resolver predecessor manifest differs from loose reconstruction'
  );

  return {
    commands: {
      headCommit: [...resolver.headCommitCommand],
      headTree: [...resolver.headTreeCommand],
      predecessorManifest: [...resolver.predecessorManifestCommand],
    },
    environment: { ...resolver.environment },
    executablePath: resolver.executable,
    executableSha256: resolver.sha256,
    predecessorManifestRawSha256: sha256Independent(predecessorManifest),
    version: resolver.version,
  };
}

function verifyProtectedAnchors(subject) {
  const git = reconstructLooseGitAnchor();
  const anchorResolver = verifyPinnedAnchorResolver(subject, git);
  assertion(
    fileSha256(path.join(REPOSITORY_ROOT, '.overlaykit', 'governance', 'plan.json')) ===
      EXPECTED.planRawSha256,
    'temporal-anchor-stale',
    'compiled plan bytes drifted'
  );
  assertion(
    fileSha256(
      path.join(REPOSITORY_ROOT, '.overlaykit', 'governance', 'changes', 'CHG-0035.json')
    ) === EXPECTED.chg0035RawSha256,
    'temporal-anchor-stale',
    'CHG-0035 bytes drifted'
  );
  const h054Receipt = readRegularFileStable(H054_RUN_PATH, 'accepted H-054 run');
  assertion(
    sha256Independent(h054Receipt.bytes) === EXPECTED.h054RawSha256,
    'temporal-anchor-stale',
    'accepted H-054 raw bytes drifted'
  );
  const h054 = parseJsonBytes(h054Receipt.bytes, 'accepted H-054 run');
  assertion(
    h054.semanticSha256 === EXPECTED.h054SemanticSha256 &&
      h054.runtimeSelection === null &&
      h054.experiment?.outcome?.status === 'inconclusive',
    'temporal-anchor-stale',
    'accepted H-054 semantics drifted'
  );
  const node = readRegularFileStable(EXPECTED.node22Path, EXPECTED.node22Path);
  assertion(
    sha256Independent(node.bytes) === EXPECTED.node22Sha256,
    'runtime-identity-drift',
    'selected Node 22 bytes drifted'
  );
  const bwrap = readRegularFileStable(EXPECTED.bwrapPath, EXPECTED.bwrapPath);
  assertion(
    sha256Independent(bwrap.bytes) === EXPECTED.bwrapSha256,
    'isolation-policy-drift',
    'bubblewrap bytes drifted'
  );
  return {
    anchorResolver,
    git,
    h054RawSha256: EXPECTED.h054RawSha256,
    node22Sha256: EXPECTED.node22Sha256,
    planRawSha256: EXPECTED.planRawSha256,
    subjectId: subject.id,
  };
}

function verifyRunAnchors(anchors, subject, subjectRawSha256) {
  exactKeys(
    anchors,
    ['acceptedH054', 'anchorResolver', 'governance', 'subject', 'trackedPredecessor'],
    'run anchors',
    'temporal-anchor-stale'
  );
  exactKeys(
    anchors.acceptedH054,
    ['classification', 'locator', 'rawSha256', 'semanticSha256'],
    'accepted H-054 anchor',
    'temporal-anchor-stale'
  );
  exactKeys(
    anchors.anchorResolver,
    ['commands', 'environment', 'executablePath', 'executableSha256', 'version'],
    'anchor resolver anchor',
    'temporal-anchor-stale'
  );
  exactKeys(
    anchors.anchorResolver.commands,
    ['headCommit', 'headTree', 'predecessorManifest'],
    'anchor resolver commands',
    'temporal-anchor-stale'
  );
  exactKeys(
    anchors.governance,
    [
      'chg0035RawSha256',
      'chg0036',
      'currentManifest',
      'planHash',
      'planRawSha256',
      'predecessorManifestRawSha256',
    ],
    'governance anchors',
    'temporal-anchor-stale'
  );
  exactKeys(
    anchors.governance.chg0036,
    ['locator', 'manifestEntry', 'rawSha256', 'status'],
    'CHG-0036 anchor',
    'temporal-anchor-stale'
  );
  exactKeys(
    anchors.governance.currentManifest,
    ['changeEntry', 'contentHash', 'locator', 'rawSha256'],
    'current manifest anchor',
    'temporal-anchor-stale'
  );
  exactKeys(anchors.subject, ['locator', 'rawSha256'], 'subject anchor', 'temporal-anchor-stale');
  exactKeys(
    anchors.trackedPredecessor,
    ['commit', 'tree'],
    'tracked predecessor anchor',
    'temporal-anchor-stale'
  );

  const chg0036Locator = '.overlaykit/governance/changes/CHG-0036.json';
  const manifestLocator = '.overlaykit/governance/manifest.json';
  const chg0036Receipt = readRegularFileStable(repositoryAbsolute(chg0036Locator), 'CHG-0036');
  const manifestReceipt = readRegularFileStable(
    repositoryAbsolute(manifestLocator),
    'governance manifest'
  );
  const chg0036 = parseJsonBytes(chg0036Receipt.bytes, 'CHG-0036');
  const manifest = parseJsonBytes(manifestReceipt.bytes, 'governance manifest');
  const manifestEntry = manifest.changes?.['CHG-0036'];
  const { contentHash: _contentHash, ...manifestBody } = manifest;
  assertion(
    chg0036.id === 'CHG-0036' &&
      chg0036.status === 'proposed' &&
      typeof manifestEntry === 'string' &&
      manifestEntry === sha256Independent(chg0036Receipt.bytes) &&
      manifest.contentHash === governanceCanonicalHashIndependent(manifestBody),
    'temporal-anchor-stale',
    'current CHG-0036 governance state differs'
  );
  const expected = {
    acceptedH054: {
      classification: 'inconclusive',
      locator: `artifacts/h054/runs/${EXPECTED.h054SemanticSha256}/run.json`,
      rawSha256: EXPECTED.h054RawSha256,
      semanticSha256: EXPECTED.h054SemanticSha256,
    },
    anchorResolver: {
      commands: {
        headCommit: [...EXPECTED_ANCHOR_RESOLVER.headCommitCommand],
        headTree: [...EXPECTED_ANCHOR_RESOLVER.headTreeCommand],
        predecessorManifest: [...EXPECTED_ANCHOR_RESOLVER.predecessorManifestCommand],
      },
      environment: { ...EXPECTED_ANCHOR_RESOLVER.environment },
      executablePath: EXPECTED_ANCHOR_RESOLVER.executable,
      executableSha256: EXPECTED_ANCHOR_RESOLVER.sha256,
      version: EXPECTED_ANCHOR_RESOLVER.version,
    },
    governance: {
      chg0035RawSha256: EXPECTED.chg0035RawSha256,
      chg0036: {
        locator: chg0036Locator,
        manifestEntry,
        rawSha256: sha256Independent(chg0036Receipt.bytes),
        status: 'proposed',
      },
      currentManifest: {
        changeEntry: manifestEntry,
        contentHash: manifest.contentHash,
        locator: manifestLocator,
        rawSha256: sha256Independent(manifestReceipt.bytes),
      },
      planHash: EXPECTED.planHash,
      planRawSha256: EXPECTED.planRawSha256,
      predecessorManifestRawSha256: EXPECTED.predecessorManifestRawSha256,
    },
    subject: {
      locator: 'lab/node22-boundary-preflight/subject-lock.json',
      rawSha256: subjectRawSha256,
    },
    trackedPredecessor: {
      commit: EXPECTED.predecessorCommit,
      tree: EXPECTED.predecessorTree,
    },
  };
  assertion(
    canonicalJsonIndependent(anchors) === canonicalJsonIndependent(expected),
    'temporal-anchor-stale',
    'run anchors differ from independent reconstruction'
  );
  assertion(
    subject.temporalBoundary.trackedPredecessor.predecessorManifestRawSha256 ===
      anchors.governance.predecessorManifestRawSha256,
    'temporal-anchor-stale',
    'predecessor manifest anchor differs'
  );
}

function verifyObservation(observation, subject) {
  exactKeys(observation, OBSERVATION_KEYS, 'observation');
  assertion(
    observation.schemaVersion === 'overlaykit-node22-boundary-preflight-observation/v1' &&
      observation.authority === 'none' &&
      observation.action === null &&
      canonicalJsonIndependent(observation.normalizations) === '[]',
    'evidence-integrity-drift',
    'observation envelope differs'
  );
  const importedUrls = Array.isArray(observation.tsx?.importUrls) ? observation.tsx.importUrls : [];
  const admittedImportUrls = subject.executionContract.expectedObservations.tsx.importUrls;
  assertion(
    importedUrls.every(
      (url) =>
        typeof url === 'string' &&
        admittedImportUrls.includes(url) &&
        !/(?:\/|%2f)forbidden-subject(?:\/|%2f|$)/iu.test(url) &&
        !/\/(?:src|tests|tools\/governance)\//iu.test(url)
    ),
    'forbidden-subject-path',
    'observation includes a predecessor, successor, product, or governance import'
  );
  assertion(
    canonicalJsonIndependent(observation.blockers) === canonicalJsonIndependent(KNOWN_BLOCKERS),
    'outcome-policy-violation',
    'observation blockers differ'
  );
  assertion(
    observation.environment?.TSX_DISABLE_CACHE === '1',
    'mutable-state-observed',
    'probe loader cache enabled'
  );
  assertion(
    observation.environment?.TSX_TSCONFIG_PATH === EXPECTED_ENVIRONMENT.TSX_TSCONFIG_PATH,
    'loader-config-escape',
    'probe TSX config is not pinned'
  );
  assertion(
    canonicalJsonIndependent(observation.environment) ===
      canonicalJsonIndependent(EXPECTED_ENVIRONMENT),
    'environment-closure-drift',
    'probe environment differs'
  );
  assertion(
    canonicalJsonIndependent(observation.invocation) ===
      canonicalJsonIndependent({
        execArgv: EXPECTED_EXEC_ARGV,
        executable: EXPECTED.node22Path,
        script: '/workspace/lab/node22-boundary-preflight/probe.mjs',
      }),
    'permission-envelope-drift',
    'probe invocation differs'
  );
  assertion(
    canonicalJsonIndependent(observation.permissionEnvelope) ===
      canonicalJsonIndependent({
        addons: false,
        child: true,
        fsReadTmp: true,
        fsReadUpperWorkspace: true,
        fsReadWorkspace: true,
        fsWriteGlobal: false,
        worker: true,
      }),
    'permission-envelope-drift',
    'probe permission envelope differs'
  );
  assertion(
    canonicalJsonIndependent(observation.scratch) ===
      canonicalJsonIndependent({ after: [], before: [] }),
    'mutable-state-observed',
    'scratch is not empty'
  );
  const expectedObservations = subject.executionContract.expectedObservations;
  const expectedSharedObjects = [
    ...subject.executionContract.runtimeFileMounts.slice(1),
    'linux-vdso.so.1',
  ].sort(compareUtf8);
  assertion(
    canonicalJsonIndependent(observation.runtime) ===
      canonicalJsonIndependent({
        ...expectedObservations.runtime,
        sharedObjects: expectedSharedObjects,
        sharedObjectsSha256: canonicalHashIndependent(expectedSharedObjects),
      }),
    'runtime-identity-drift',
    'runtime observation differs'
  );
  assertion(
    canonicalJsonIndependent(observation.ajv) ===
      canonicalJsonIndependent(expectedObservations.ajv),
    'synthetic-ajv-observation-failed',
    'Ajv observation differs'
  );
  assertion(
    canonicalJsonIndependent(observation.esbuild) ===
      canonicalJsonIndependent(expectedObservations.esbuild),
    'synthetic-esbuild-observation-failed',
    'esbuild observation differs'
  );
  assertion(
    observation.tsx?.configMode === EXPECTED_TSX_CONFIG_MODE,
    'loader-config-escape',
    'TSX configuration mode is not explicitly pinned'
  );
  assertion(
    canonicalJsonIndependent(observation.tsx) ===
      canonicalJsonIndependent(expectedObservations.tsx),
    'synthetic-tsx-observation-failed',
    'TSX observation differs'
  );
  assertion(
    canonicalJsonIndependent(observation.pathResolution) ===
      canonicalJsonIndependent({
        caseVariantAbsent: true,
        caseVariantErrorCode: 'ENOENT',
        caseVariantPath: '/WORKSPACE',
      }),
    'loader-config-escape',
    'case-variant read boundary differs'
  );

  const fixture = readRegularFileStable(
    repositoryAbsolute(EXPECTED_INPUTS.fixture.locator),
    'synthetic fixture'
  );
  const tsconfig = readRegularFileStable(
    repositoryAbsolute(EXPECTED_INPUTS.tsconfig.locator),
    'synthetic tsconfig'
  );
  assertion(
    sha256Independent(fixture.bytes) === EXPECTED_INPUTS.fixture.sha256,
    'apparatus-source-set-drift',
    'synthetic fixture bytes differ from independent pin'
  );
  assertion(
    sha256Independent(tsconfig.bytes) === EXPECTED_INPUTS.tsconfig.sha256,
    'loader-config-escape',
    'synthetic tsconfig bytes differ from independent pin'
  );
  const tsconfigDocument = parseJsonBytes(tsconfig.bytes, 'synthetic tsconfig');
  assertion(
    isPlainObject(tsconfigDocument) &&
      (!Object.hasOwn(tsconfigDocument, 'extends') || tsconfigDocument.extends === null),
    'loader-config-escape',
    'synthetic tsconfig contains an extends chain'
  );
  assertion(
    canonicalJsonIndependent(observation.fixture) ===
      canonicalJsonIndependent({
        byteLength: fixture.bytes.length,
        path: `/workspace/${EXPECTED_INPUTS.fixture.locator}`,
        sha256: EXPECTED_INPUTS.fixture.sha256,
      }),
    'apparatus-source-set-drift',
    'fixture receipt differs'
  );
  assertion(
    canonicalJsonIndependent(observation.tsconfig) ===
      canonicalJsonIndependent({
        byteLength: tsconfig.bytes.length,
        extends: EXPECTED_INPUTS.tsconfig.extends,
        path: `/workspace/${EXPECTED_INPUTS.tsconfig.locator}`,
        sha256: EXPECTED_INPUTS.tsconfig.sha256,
      }),
    'loader-config-escape',
    'tsconfig receipt differs'
  );
  assertion(
    canonicalJsonIndependent(observation.outcome) ===
      canonicalJsonIndependent({
        reason: 'known-boundary-completeness-blockers-remain',
        refutationEligible: false,
        status: 'inconclusive',
        supportEligible: false,
      }),
    'outcome-policy-violation',
    'observation outcome differs'
  );
}

function verifyAttempts(run) {
  assertion(
    Array.isArray(run.attempts) && run.attempts.length === 2,
    'determinism-failure',
    'exactly two attempts are required'
  );
  const observationSemanticSha256 = canonicalHashIndependent(run.observation);
  const stdout = Buffer.from(`${canonicalJsonIndependent(run.observation)}\n`, 'utf8');
  const emptySha256 = sha256Independent(Buffer.alloc(0));
  for (const [index, attempt] of run.attempts.entries()) {
    exactKeys(
      attempt,
      [
        'exitCode',
        'observationSemanticSha256',
        'ordinal',
        'signal',
        'stderrByteLength',
        'stderrSha256',
        'stdoutByteLength',
        'stdoutSha256',
      ],
      `attempt ${index + 1}`
    );
    assertion(
      attempt.ordinal === index + 1 &&
        attempt.exitCode === 0 &&
        attempt.signal === null &&
        attempt.stderrByteLength === 0 &&
        attempt.stderrSha256 === emptySha256 &&
        attempt.stdoutByteLength === stdout.length &&
        attempt.stdoutSha256 === sha256Independent(stdout) &&
        attempt.observationSemanticSha256 === observationSemanticSha256,
      'determinism-failure',
      `attempt ${index + 1} differs`
    );
  }
  exactKeys(
    run.repeatability,
    ['attemptCount', 'byteIdentical', 'observationSemanticSha256', 'semanticIdentical'],
    'repeatability'
  );
  assertion(
    run.repeatability.attemptCount === 2 &&
      run.repeatability.byteIdentical === true &&
      run.repeatability.semanticIdentical === true &&
      run.repeatability.observationSemanticSha256 === observationSemanticSha256 &&
      canonicalJsonIndependent(run.attempts[0]) ===
        canonicalJsonIndependent({ ...run.attempts[1], ordinal: 1 }),
    'determinism-failure',
    'attempt repeatability differs'
  );
  return observationSemanticSha256;
}

function describeRegularFileIndependent(logicalPath, absolutePath) {
  const { bytes, metadata } = readRegularFileStable(absolutePath, absolutePath);
  return {
    byteLength: bytes.length,
    kind: 'regular-file',
    logicalPath,
    mode: octalMode(metadata),
    sha256: sha256Independent(bytes),
  };
}

function describeDirectoryEntriesIndependent(sourcePath) {
  const entries = [];

  function visit(relativePath) {
    const absolutePath =
      relativePath === '.' ? sourcePath : path.join(sourcePath, ...relativePath.split('/'));
    const metadata = lstatSync(absolutePath);
    if (metadata.isSymbolicLink()) {
      const linkTarget = readlinkSync(absolutePath, 'utf8');
      throw new InvalidNode22PreflightEvidenceError(
        'path-resolution-invalid',
        `${relativePath} is a symbolic link to ${linkTarget}`
      );
    }
    if (metadata.isDirectory()) {
      entries.push({
        kind: 'directory',
        logicalPath: relativePath,
        mode: octalMode(metadata),
      });
      const names = readdirSync(absolutePath, { encoding: 'utf8' }).sort(compareUtf8);
      for (const name of names) {
        visit(relativePath === '.' ? name : `${relativePath}/${name}`);
      }
      return;
    }
    if (metadata.isFile()) {
      entries.push(describeRegularFileIndependent(relativePath, absolutePath));
      return;
    }
    throw new InvalidNode22PreflightEvidenceError(
      'path-resolution-invalid',
      `${relativePath} has an unsupported type`
    );
  }

  visit('.');
  return entries.sort((left, right) => compareUtf8(left.logicalPath, right.logicalPath));
}

function runtimeResolutionChainIndependent(sourceLocator) {
  assertion(path.isAbsolute(sourceLocator), 'path-resolution-invalid', sourceLocator);
  const chain = [];
  const components = sourceLocator.split('/').filter(Boolean);
  let requestedPath = '';
  let resolvedParent = '/';
  for (const component of components) {
    requestedPath = `${requestedPath}/${component}`;
    const candidate = path.join(resolvedParent, component);
    let metadata;
    try {
      metadata = lstatSync(candidate);
    } catch (error) {
      throw new InvalidNode22PreflightEvidenceError(
        'path-resolution-invalid',
        `${requestedPath}: ${error.message}`
      );
    }
    if (metadata.isSymbolicLink()) {
      let resolvedPath;
      try {
        resolvedPath = realpathSync(candidate);
      } catch (error) {
        throw new InvalidNode22PreflightEvidenceError(
          'path-resolution-invalid',
          `${requestedPath}: ${error.message}`
        );
      }
      chain.push({
        kind: 'symbolic-link',
        linkTarget: readlinkSync(candidate, 'utf8'),
        mode: octalMode(metadata),
        requestedPath,
        resolvedPath,
      });
      resolvedParent = resolvedPath;
      continue;
    }
    resolvedParent = candidate;
  }
  assertion(
    resolvedParent === realpathSync(sourceLocator),
    'path-resolution-invalid',
    `${sourceLocator} resolution chain differs`
  );
  return chain;
}

function layerWithIdentityIndependent(body) {
  return {
    ...body,
    contentSha256: canonicalHashIndependent(body),
    entryCount: body.entries.length,
  };
}

function expectedDirectoryLayer(declaration) {
  const absoluteSource = repositoryAbsolute(declaration.source);
  const metadata = lstatSync(absoluteSource);
  assertion(
    metadata.isDirectory() && !metadata.isSymbolicLink(),
    'path-resolution-invalid',
    declaration.source
  );
  const sourceRealPath = realpathSync(absoluteSource);
  return layerWithIdentityIndependent({
    entries: describeDirectoryEntriesIndependent(sourceRealPath),
    id: declaration.layerId,
    kind: 'directory-tree',
    sourceLocator: declaration.source,
    sourceRealPath,
  });
}

function expectedRuntimeLayer(sourceLocator) {
  const sourceRealPath = realpathSync(sourceLocator);
  return layerWithIdentityIndependent({
    entries: [describeRegularFileIndependent('.', sourceRealPath)],
    id: `runtime-file:${sourceLocator}`,
    kind: 'runtime-file',
    resolutionChain: runtimeResolutionChainIndependent(sourceLocator),
    sourceLocator,
    sourceRealPath,
  });
}

function expectedSourceClosure(subject) {
  const contract = subject.executionContract;
  const layers = [
    ...contract.runtimeFileMounts.map((source) => expectedRuntimeLayer(source)),
    ...contract.readOnlyDirectoryMounts.map((declaration) => expectedDirectoryLayer(declaration)),
  ];
  const byId = new Map(layers.map((layer) => [layer.id, layer]));
  const mounts = [
    ...contract.runtimeFileMounts.map((source) => ({
      access: 'read-only',
      kind: 'runtime-file',
      layerId: `runtime-file:${source}`,
      sourceContentSha256: byId.get(`runtime-file:${source}`).contentSha256,
      sourceLocator: source,
      sourceRealPath: byId.get(`runtime-file:${source}`).sourceRealPath,
      target: source,
    })),
    ...contract.readOnlyDirectoryMounts.map(({ layerId, source, target }) => ({
      access: 'read-only',
      kind: 'directory-tree',
      layerId,
      sourceContentSha256: byId.get(layerId).contentSha256,
      sourceLocator: source,
      sourceRealPath: byId.get(layerId).sourceRealPath,
      target,
    })),
  ];
  return {
    layers,
    mounts,
    rootSha256: canonicalHashIndependent({ layers, mounts }),
  };
}

function sourceLayerReason(layerId) {
  if (layerId === 'apparatus') return 'apparatus-source-set-drift';
  if (layerId === 'package/@esbuild/linux-x64@0.28.1') return 'native-closure-drift';
  if (layerId.startsWith('package/')) return 'module-universe-incomplete';
  if (layerId === `runtime-file:${EXPECTED.node22Path}`) return 'runtime-identity-drift';
  if (layerId.startsWith('runtime-file:')) return 'native-closure-drift';
  return 'apparatus-source-set-drift';
}

function verifySourceClosure(sourceClosure, subject) {
  exactKeys(
    sourceClosure,
    ['layers', 'mounts', 'postRootSha256', 'preRootSha256', 'rootSha256', 'stable'],
    'source closure'
  );
  assertion(
    Array.isArray(sourceClosure.layers) &&
      Array.isArray(sourceClosure.mounts) &&
      sourceClosure.stable === true,
    'apparatus-source-set-drift',
    'source closure is malformed or unstable'
  );
  const layerIds = [];
  for (const [index, layer] of sourceClosure.layers.entries()) {
    const expectedKeys =
      layer.kind === 'runtime-file'
        ? [
            'contentSha256',
            'entries',
            'entryCount',
            'id',
            'kind',
            'resolutionChain',
            'sourceLocator',
            'sourceRealPath',
          ]
        : [
            'contentSha256',
            'entries',
            'entryCount',
            'id',
            'kind',
            'sourceLocator',
            'sourceRealPath',
          ];
    exactKeys(layer, expectedKeys, `source layer ${index}`);
    assertion(
      typeof layer.id === 'string' &&
        typeof layer.kind === 'string' &&
        typeof layer.sourceLocator === 'string' &&
        typeof layer.sourceRealPath === 'string' &&
        Array.isArray(layer.entries) &&
        Number.isSafeInteger(layer.entryCount) &&
        layer.entryCount === layer.entries.length,
      'apparatus-source-set-drift',
      `source layer ${index} is malformed`
    );
    const body = {
      entries: layer.entries,
      id: layer.id,
      kind: layer.kind,
      sourceLocator: layer.sourceLocator,
      sourceRealPath: layer.sourceRealPath,
    };
    if (layer.kind === 'runtime-file') body.resolutionChain = layer.resolutionChain;
    assertion(
      layer.contentSha256 === canonicalHashIndependent(body),
      'apparatus-source-set-drift',
      `${layer.id} content hash differs`
    );
    layerIds.push(layer.id);
  }
  assertion(
    new Set(layerIds).size === layerIds.length,
    'layer-collision',
    'layer roster contains a duplicate ID'
  );
  for (const [index, mount] of sourceClosure.mounts.entries()) {
    exactKeys(
      mount,
      [
        'access',
        'kind',
        'layerId',
        'sourceContentSha256',
        'sourceLocator',
        'sourceRealPath',
        'target',
      ],
      `mount ${index}`
    );
    assertion(
      mount.access === 'read-only' &&
        typeof mount.kind === 'string' &&
        layerIds.includes(mount.layerId),
      'mount-boundary-broadened',
      `mount ${index} is not an exact read-only source`
    );
    const layer = sourceClosure.layers.find(({ id }) => id === mount.layerId);
    assertion(
      mount.sourceContentSha256 === layer.contentSha256 &&
        mount.sourceLocator === layer.sourceLocator &&
        mount.sourceRealPath === layer.sourceRealPath,
      'mount-boundary-broadened',
      `mount ${mount.target} is not bijective with ${mount.layerId}`
    );
  }
  const mountTargets = sourceClosure.mounts.map(({ target }) => target);
  assertion(
    new Set(mountTargets).size === mountTargets.length,
    'layer-collision',
    'cross-layer mount target collision observed'
  );
  const body = { layers: sourceClosure.layers, mounts: sourceClosure.mounts };
  const rootSha256 = canonicalHashIndependent(body);
  assertion(
    sourceClosure.rootSha256 === rootSha256 &&
      sourceClosure.preRootSha256 === rootSha256 &&
      sourceClosure.postRootSha256 === rootSha256,
    'apparatus-source-set-drift',
    'source closure roots differ'
  );
  const expected = expectedSourceClosure(subject);
  const observedById = new Map(sourceClosure.layers.map((layer) => [layer.id, layer]));
  for (const expectedLayer of expected.layers) {
    const observed = observedById.get(expectedLayer.id);
    assertion(
      observed !== undefined,
      sourceLayerReason(expectedLayer.id),
      `${expectedLayer.id} is missing`
    );
    const observedPaths = observed.entries.map(({ logicalPath }) => logicalPath);
    assertion(
      new Set(observedPaths).size === observedPaths.length,
      'layer-collision',
      `${expectedLayer.id} contains a duplicate logical path`
    );
    if (expectedLayer.kind === 'runtime-file') {
      assertion(
        canonicalJsonIndependent(observed.resolutionChain) ===
          canonicalJsonIndependent(expectedLayer.resolutionChain),
        'path-resolution-invalid',
        `${expectedLayer.id} resolution chain differs`
      );
    }
    assertion(
      canonicalJsonIndependent(observed) === canonicalJsonIndependent(expectedLayer),
      sourceLayerReason(expectedLayer.id),
      `${expectedLayer.id} differs from independent reconstruction`
    );
  }
  assertion(
    sourceClosure.layers.length === expected.layers.length,
    'layer-collision',
    'source closure contains an unexpected layer'
  );
  assertion(
    canonicalJsonIndependent(sourceClosure.mounts) === canonicalJsonIndependent(expected.mounts),
    'mount-boundary-broadened',
    'mount roster differs from independent reconstruction'
  );
  assertion(
    rootSha256 === expected.rootSha256,
    'apparatus-source-set-drift',
    'source root differs from independent reconstruction'
  );
  return rootSha256;
}

export function buildExpectedBwrapArgvIndependent(subject) {
  const contract = subject.executionContract;
  const argv = [
    '--die-with-parent',
    '--new-session',
    '--unshare-all',
    '--unshare-user',
    '--disable-userns',
    '--assert-userns-disabled',
    '--hostname',
    'node22-preflight',
    '--cap-drop',
    'ALL',
    '--tmpfs',
    '/',
  ];
  for (const directory of contract.emptyDirectories) {
    argv.push('--dir', directory);
  }
  for (const privateMount of contract.readOnlyPrivateMounts) {
    argv.push(...privateMount.create);
    for (const child of privateMount.childrenBeforeRemount) argv.push(...child);
  }
  for (const source of contract.runtimeFileMounts) argv.push('--ro-bind', source, source);
  for (const { source, target } of contract.readOnlyDirectoryMounts) {
    argv.push('--ro-bind', source, target);
  }
  for (const privateMount of contract.readOnlyPrivateMounts) argv.push(...privateMount.remount);
  argv.push('--remount-ro', '/', '--clearenv');
  for (const name of Object.keys(EXPECTED_ENVIRONMENT).sort(compareUtf8)) {
    argv.push('--setenv', name, EXPECTED_ENVIRONMENT[name]);
  }
  argv.push('--chdir', '/workspace', ...EXPECTED_NODE_ARGV);
  return argv;
}

function verifyLauncher(run, subject) {
  exactKeys(
    run.launcher,
    ['bubblewrap', 'effectiveEnvironment', 'mountRosterSha256', 'nodeArgv', 'nodeArgvSha256'],
    'launcher'
  );
  exactKeys(
    run.launcher.bubblewrap,
    ['argv', 'argvSha256', 'executablePath', 'executableSha256', 'identityWindow', 'version'],
    'bubblewrap launcher'
  );
  exactKeys(
    run.launcher.bubblewrap.identityWindow,
    ['postSha256', 'preSha256', 'stable'],
    'bubblewrap identity window'
  );
  const expectedArgv = buildExpectedBwrapArgvIndependent(subject);
  const argv = run.launcher.bubblewrap.argv;
  assertion(Array.isArray(argv), 'isolation-policy-drift', 'bubblewrap argv is not an array');
  assertion(!argv.includes('--share-net'), 'isolation-policy-drift', 'network namespace shared');
  const broadRoot = argv.some(
    (argument, index) =>
      argument === '--bind' ||
      argument === '--bind-try' ||
      (argument === '--ro-bind' && argv[index + 1] === '/' && argv[index + 2] === '/')
  );
  assertion(!broadRoot, 'mount-boundary-broadened', 'root or write bind observed');
  const chdirIndex = argv.indexOf('--chdir');
  assertion(
    chdirIndex !== -1 && argv[chdirIndex + 1] === '/workspace',
    'ambient-capability-observed',
    'working directory differs'
  );
  assertion(
    run.launcher.effectiveEnvironment?.TSX_DISABLE_CACHE === '1',
    'mutable-state-observed',
    'loader cache enabled'
  );
  assertion(
    run.launcher.effectiveEnvironment?.TSX_TSCONFIG_PATH === EXPECTED_ENVIRONMENT.TSX_TSCONFIG_PATH,
    'loader-config-escape',
    'TSX config is not pinned'
  );
  assertion(
    canonicalJsonIndependent(run.launcher.effectiveEnvironment) ===
      canonicalJsonIndependent(EXPECTED_ENVIRONMENT),
    'environment-closure-drift',
    'launcher environment differs'
  );
  assertion(
    canonicalJsonIndependent(run.launcher.nodeArgv) ===
      canonicalJsonIndependent(EXPECTED_NODE_ARGV) &&
      run.launcher.nodeArgvSha256 === canonicalHashIndependent(EXPECTED_NODE_ARGV),
    'permission-envelope-drift',
    'launcher Node argv differs'
  );
  assertion(
    run.launcher.bubblewrap.executablePath === EXPECTED.bwrapPath &&
      run.launcher.bubblewrap.executableSha256 === EXPECTED.bwrapSha256 &&
      run.launcher.bubblewrap.identityWindow.preSha256 === EXPECTED.bwrapSha256 &&
      run.launcher.bubblewrap.identityWindow.postSha256 === EXPECTED.bwrapSha256 &&
      run.launcher.bubblewrap.identityWindow.stable === true &&
      run.launcher.bubblewrap.version === EXPECTED.bwrapVersion &&
      run.launcher.bubblewrap.argvSha256 === canonicalHashIndependent(expectedArgv) &&
      canonicalJsonIndependent(run.launcher.bubblewrap.argv) ===
        canonicalJsonIndependent(expectedArgv),
    'isolation-policy-drift',
    'bubblewrap identity or argv hash differs'
  );
  assertion(
    run.launcher.mountRosterSha256 === canonicalHashIndependent(run.sourceClosure.mounts),
    'mount-boundary-broadened',
    'mount roster hash differs'
  );
}

function verifyPredicatesAndOutcome(run, subject) {
  const deferred = new Map([
    ['independentVerifierReconstructs', 'independent-verifier-required'],
    ['allControlsFailClosed', 'independent-hostile-controls-required'],
  ]);
  const blocked = new Map([
    ['selectedNode22Exact', ['path-execution-image-identity-not-atomically-bound']],
    [
      'apparatusSourceClosureExact',
      [
        'successor-apparatus-and-accepted-h054-layer-source-lock-not-established',
        'path-execution-image-identity-not-atomically-bound',
      ],
    ],
    [
      'emptyRootMountClosureExact',
      [
        'bubblewrap-host-dynamic-library-and-effective-kernel-enforcement-not-independently-traced',
        'path-execution-image-identity-not-atomically-bound',
      ],
    ],
    [
      'isolatedNetworkNamespaceExact',
      ['bubblewrap-host-dynamic-library-and-effective-kernel-enforcement-not-independently-traced'],
    ],
    ['exhaustiveOpenFileAndModuleClosure', ['exhaustive-esm-and-open-file-trace-not-admitted']],
    [
      'effectiveSyscallClosure',
      [
        'content-addressed-effective-seccomp-policy-not-admitted',
        'bubblewrap-host-dynamic-library-and-effective-kernel-enforcement-not-independently-traced',
        'worker-and-child-process-cardinality-not-independently-traced',
      ],
    ],
    [
      'nativeAndLateLoadedObjectClosure',
      ['kernel-vdso-and-late-loaded-object-closure-not-established'],
    ],
    [
      'noSuccessorHypothesisOpenedOrExecuted',
      ['universal-successor-absence-not-provable-without-exhaustive-trace'],
    ],
    [
      'failureBranchEvidenceMaterializable',
      ['failed-attempt-evidence-preservation-and-outcome-derivation-not-established'],
    ],
  ]);
  const expectedPredicates = subject.requiredPredicates.map((id) => {
    if (deferred.has(id)) return { id, reason: deferred.get(id), status: 'deferred' };
    if (blocked.has(id)) return { blockers: blocked.get(id), id, status: 'blocked' };
    return { id, status: 'passed' };
  });
  assertion(
    canonicalJsonIndependent(run.predicates) === canonicalJsonIndependent(expectedPredicates),
    'outcome-policy-violation',
    'predicate assessments differ'
  );
  assertion(
    canonicalJsonIndependent(run.blockers) === canonicalJsonIndependent(KNOWN_BLOCKERS),
    'outcome-policy-violation',
    'run blockers differ'
  );
  exactKeys(run.outcome, ['reason', 'refutationEligible', 'status', 'supportEligible'], 'outcome');
  assertion(
    run.outcome.status === 'inconclusive' &&
      run.outcome.reason === 'known-boundary-completeness-blockers-remain' &&
      run.outcome.supportEligible === false &&
      run.outcome.refutationEligible === false,
    'outcome-policy-violation',
    'known blockers require inconclusive'
  );
  exactKeys(
    run.interpretation,
    ['adrCandidate', 'claimBoundary', 'successorState'],
    'interpretation'
  );
  exactKeys(
    run.interpretation.successorState,
    ['observation', 'syscallTrace', 'universalAbsenceProved'],
    'successor-state interpretation'
  );
  assertion(
    run.interpretation.adrCandidate === null &&
      typeof run.interpretation.claimBoundary === 'string' &&
      run.interpretation.claimBoundary.length > 0 &&
      canonicalJsonIndependent(run.interpretation.successorState) ===
        canonicalJsonIndependent({
          observation: 'not-observed-within-nominated-boundary',
          syscallTrace: null,
          universalAbsenceProved: false,
        }),
    'successor-state-overclaim',
    'interpretation creates authority or successor semantics'
  );
  exactKeys(run.humanReview, ['accepted', 'required'], 'human review');
  assertion(
    run.humanReview.accepted === null && run.humanReview.required === true,
    'authority-overclaim',
    'producer records human acceptance'
  );
}

function verifyProducerControlDeclarations(run, subject) {
  assertion(
    Array.isArray(run.controls) && run.controls.length === subject.controlContract.length,
    'evidence-integrity-drift',
    'producer control declaration roster differs'
  );
  const expected = subject.controlContract.map(({ expectedReasonCode, id }) => ({
    executionDisposition: 'reject-before-execution',
    expectedReasonCode,
    id,
    launchScope: 'positive-bubblewrap-boundary-only',
    mutationMode: 'in-memory-only',
    observedReasonCode: null,
    passed: null,
    positiveBoundaryLaunchCount: 0,
    status: 'deferred-to-independent-verifier',
  }));
  assertion(
    canonicalJsonIndependent(run.controls) === canonicalJsonIndependent(expected),
    'evidence-integrity-drift',
    'producer control declarations differ'
  );
}

function verifyRunIdentity(run) {
  exactKeys(run, RUN_KEYS, 'run');
  assertion(
    run.schemaVersion === 'overlaykit-node22-boundary-preflight-run/v1' &&
      run.studyId === EXPECTED.studyId,
    'evidence-integrity-drift',
    'run identity differs'
  );
  assertion(
    run.authority === 'none' && run.action === null,
    'authority-overclaim',
    'run claims authority or action'
  );
  assertion(
    canonicalJsonIndependent(run.normalizations) === '[]',
    'evidence-integrity-drift',
    'run declares normalization'
  );
  const { runId: _runId, semanticSha256: _semanticSha256, ...body } = run;
  const semanticSha256 = canonicalHashIndependent(body);
  assertion(
    run.semanticSha256 === semanticSha256 &&
      run.runId === `node22-boundary-preflight-${semanticSha256.slice(0, 24)}`,
    'evidence-integrity-drift',
    'run semantic hash or ID differs'
  );
  return semanticSha256;
}

function verifyNode22PreflightRunCore(run) {
  const semanticSha256 = verifyRunIdentity(run);
  const { subject, rawSha256: subjectRawSha256 } = readAndVerifySubject();
  const anchors = verifyProtectedAnchors(subject);
  verifyRunAnchors(run.anchors, subject, subjectRawSha256);
  const sourceRootSha256 = verifySourceClosure(run.sourceClosure, subject);
  verifyLauncher(run, subject);
  verifyObservation(run.observation, subject);
  const observationSemanticSha256 = verifyAttempts(run);
  verifyProducerControlDeclarations(run, subject);
  verifyPredicatesAndOutcome(run, subject);
  return {
    action: null,
    adrCandidate: null,
    authority: 'none',
    blockers: [...KNOWN_BLOCKERS],
    controlContract: structuredClone(subject.controlContract),
    humanReview: {
      accepted: null,
      required: true,
    },
    normalizations: [],
    failureBranch: 'not-materializable-by-current-producer',
    sourceClosureQualification: 'current-state-pre-post-observation-not-precontract-anchor',
    successorState: {
      observation: 'not-observed-within-nominated-boundary',
      syscallTrace: null,
      universalAbsenceProved: false,
    },
    observationSemanticSha256,
    outcome: {
      reason: 'known-boundary-completeness-blockers-remain',
      refutationEligible: false,
      status: 'inconclusive',
      supportEligible: false,
    },
    protectedAnchors: anchors,
    runId: run.runId,
    schemaVersion: 'overlaykit-node22-boundary-preflight-independent-verification/v1',
    semanticSha256,
    sourceRootSha256,
    studyId: EXPECTED.studyId,
    subjectRawSha256,
  };
}

export function refreshRunIdentityIndependent(run) {
  const { runId: _runId, semanticSha256: _semanticSha256, ...body } = run;
  const semanticSha256 = canonicalHashIndependent(body);
  run.semanticSha256 = semanticSha256;
  run.runId = `node22-boundary-preflight-${semanticSha256.slice(0, 24)}`;
  return run;
}

function refreshLayerIdentityIndependent(layer) {
  const body = {
    entries: layer.entries,
    id: layer.id,
    kind: layer.kind,
    sourceLocator: layer.sourceLocator,
    sourceRealPath: layer.sourceRealPath,
  };
  if (layer.kind === 'runtime-file') body.resolutionChain = layer.resolutionChain;
  layer.entryCount = layer.entries.length;
  layer.contentSha256 = canonicalHashIndependent(body);
}

function refreshSourceClosureIdentityIndependent(run) {
  for (const layer of run.sourceClosure.layers) refreshLayerIdentityIndependent(layer);
  const byId = new Map(run.sourceClosure.layers.map((layer) => [layer.id, layer]));
  for (const mount of run.sourceClosure.mounts) {
    const layer = byId.get(mount.layerId);
    if (layer !== undefined) {
      mount.sourceContentSha256 = layer.contentSha256;
      mount.sourceLocator = layer.sourceLocator;
      mount.sourceRealPath = layer.sourceRealPath;
    }
  }
  const rootSha256 = canonicalHashIndependent({
    layers: run.sourceClosure.layers,
    mounts: run.sourceClosure.mounts,
  });
  run.sourceClosure.rootSha256 = rootSha256;
  run.sourceClosure.preRootSha256 = rootSha256;
  run.sourceClosure.postRootSha256 = rootSha256;
  run.launcher.mountRosterSha256 = canonicalHashIndependent(run.sourceClosure.mounts);
}

function refreshObservationReceiptsIndependent(run) {
  const observationSemanticSha256 = canonicalHashIndependent(run.observation);
  const stdout = Buffer.from(`${canonicalJsonIndependent(run.observation)}\n`, 'utf8');
  for (const attempt of run.attempts) {
    attempt.observationSemanticSha256 = observationSemanticSha256;
    attempt.stdoutByteLength = stdout.length;
    attempt.stdoutSha256 = sha256Independent(stdout);
  }
  run.repeatability.observationSemanticSha256 = observationSemanticSha256;
}

function refreshLauncherIdentityIndependent(run) {
  run.launcher.bubblewrap.argvSha256 = canonicalHashIndependent(run.launcher.bubblewrap.argv);
  run.launcher.nodeArgvSha256 = canonicalHashIndependent(run.launcher.nodeArgv);
}

function replaceLauncherEnvironmentIndependent(run, environment) {
  const argv = run.launcher.bubblewrap.argv;
  const clearIndex = argv.indexOf('--clearenv');
  const chdirIndex = argv.indexOf('--chdir', clearIndex + 1);
  assertion(
    clearIndex !== -1 && chdirIndex > clearIndex,
    'control-precondition-failed',
    'launcher environment segment'
  );
  const environmentArguments = [];
  for (const name of Object.keys(environment).sort(compareUtf8)) {
    environmentArguments.push('--setenv', name, environment[name]);
  }
  run.launcher.effectiveEnvironment = structuredClone(environment);
  run.launcher.bubblewrap.argv = [
    ...argv.slice(0, clearIndex + 1),
    ...environmentArguments,
    ...argv.slice(chdirIndex),
  ];
  refreshLauncherIdentityIndependent(run);
}

function replaceLauncherNodeArgvIndependent(run, nodeArgv) {
  const argv = run.launcher.bubblewrap.argv;
  const chdirIndex = argv.indexOf('--chdir');
  assertion(
    chdirIndex !== -1 && argv[chdirIndex + 1] === '/workspace',
    'control-precondition-failed',
    'launcher Node argv segment'
  );
  run.launcher.nodeArgv = [...nodeArgv];
  run.launcher.bubblewrap.argv = [...argv.slice(0, chdirIndex + 2), ...nodeArgv];
  refreshLauncherIdentityIndependent(run);
}

function requiredLayerForControl(run, id) {
  const layer = run.sourceClosure.layers.find((candidate) => candidate.id === id);
  assertion(layer !== undefined, 'control-precondition-failed', id);
  return layer;
}

function firstRegularEntryForControl(layer, preferredPattern = null) {
  const preferred =
    preferredPattern === null
      ? null
      : layer.entries.find(
          ({ kind, logicalPath }) => kind === 'regular-file' && preferredPattern.test(logicalPath)
        );
  const entry = preferred ?? layer.entries.find(({ kind }) => kind === 'regular-file');
  assertion(entry !== undefined, 'control-precondition-failed', layer.id);
  return entry;
}

function removeLayerAndMount(run, layerId) {
  const beforeLayers = run.sourceClosure.layers.length;
  const beforeMounts = run.sourceClosure.mounts.length;
  run.sourceClosure.layers = run.sourceClosure.layers.filter(({ id }) => id !== layerId);
  run.sourceClosure.mounts = run.sourceClosure.mounts.filter((mount) => mount.layerId !== layerId);
  assertion(
    run.sourceClosure.layers.length === beforeLayers - 1 &&
      run.sourceClosure.mounts.length === beforeMounts - 1,
    'control-precondition-failed',
    layerId
  );
}

export function selfCycleLinkTargetIndependent(requestedPath) {
  assertion(
    typeof requestedPath === 'string' &&
      path.posix.isAbsolute(requestedPath) &&
      path.posix.basename(requestedPath) !== '/',
    'control-precondition-failed',
    'self-cycle requested path'
  );
  return path.posix.basename(requestedPath);
}

export function symlinkControlTargetIndependent(controlId, requestedPath) {
  assertion(
    requestedPath === '/lib64',
    'control-precondition-failed',
    `${controlId}:requested-path`
  );
  const linkTargets = {
    'symlink-cycle': 'lib64',
    'symlink-dangling': 'node22-preflight-definitely-absent',
    'symlink-escape': 'etc',
    'symlink-retarget': 'usr/lib',
  };
  const linkTarget = linkTargets[controlId];
  assertion(linkTarget !== undefined, 'control-precondition-failed', `${controlId}:unsupported`);
  const resolvedPath = path.posix.resolve(path.posix.dirname(requestedPath), linkTarget);
  const expectedResolvedPaths = {
    'symlink-cycle': '/lib64',
    'symlink-dangling': '/node22-preflight-definitely-absent',
    'symlink-escape': '/etc',
    'symlink-retarget': '/usr/lib',
  };
  assertion(
    resolvedPath === expectedResolvedPaths[controlId],
    'control-precondition-failed',
    `${controlId}:resolution`
  );
  if (controlId === 'symlink-dangling') {
    let absent = false;
    try {
      lstatSync(resolvedPath);
    } catch (error) {
      absent = error?.code === 'ENOENT';
    }
    assertion(absent, 'control-precondition-failed', `${controlId}:target-present`);
  } else {
    const metadata = lstatSync(resolvedPath);
    assertion(
      controlId === 'symlink-cycle' || metadata.isDirectory(),
      'control-precondition-failed',
      `${controlId}:target-invalid`
    );
  }
  return { linkTarget, requestedPath, resolvedPath };
}

function mutateControlRun(run, controlId) {
  switch (controlId) {
    case 'stale-temporal-anchor':
      run.anchors.trackedPredecessor.tree = '0'.repeat(40);
      break;
    case 'substitute-node22': {
      const layer = requiredLayerForControl(run, `runtime-file:${EXPECTED.node22Path}`);
      const entry = layer.entries.find(
        ({ kind, logicalPath }) => kind === 'regular-file' && logicalPath === '.'
      );
      assertion(
        entry !== undefined && entry.sha256 === EXPECTED.node22Sha256,
        'control-precondition-failed',
        `runtime-file:${EXPECTED.node22Path}:.`
      );
      entry.sha256 = '0'.repeat(64);
      refreshSourceClosureIdentityIndependent(run);
      run.observation.runtime.version = 'v22.22.2-substituted';
      refreshObservationReceiptsIndependent(run);
      break;
    }
    case 'stale-apparatus': {
      const layer = requiredLayerForControl(run, 'apparatus');
      layer.sourceRealPath = `${layer.sourceRealPath}-stale`;
      refreshSourceClosureIdentityIndependent(run);
      break;
    }
    case 'omit-apparatus-entry': {
      const layer = requiredLayerForControl(run, 'apparatus');
      const entry = firstRegularEntryForControl(layer, /probe\.mjs$/u);
      layer.entries = layer.entries.filter(({ logicalPath }) => logicalPath !== entry.logicalPath);
      refreshSourceClosureIdentityIndependent(run);
      break;
    }
    case 'omit-package-mount':
      removeLayerAndMount(run, 'package/tsx@4.23.1');
      refreshSourceClosureIdentityIndependent(run);
      break;
    case 'omit-import-target': {
      const layer = requiredLayerForControl(run, 'package/tsx@4.23.1');
      const entry = layer.entries.find(
        ({ kind, logicalPath }) =>
          kind === 'regular-file' && logicalPath === 'dist/esm/api/index.mjs'
      );
      assertion(
        entry !== undefined,
        'control-precondition-failed',
        'package/tsx@4.23.1:dist/esm/api/index.mjs'
      );
      layer.entries = layer.entries.filter(({ logicalPath }) => logicalPath !== entry.logicalPath);
      refreshSourceClosureIdentityIndependent(run);
      break;
    }
    case 'stale-ajv-entry': {
      const layer = requiredLayerForControl(run, 'package/ajv@8.20.0');
      const entry = layer.entries.find(
        ({ kind, logicalPath }) => kind === 'regular-file' && logicalPath === 'dist/ajv.js'
      );
      assertion(
        entry !== undefined,
        'control-precondition-failed',
        'package/ajv@8.20.0:dist/ajv.js'
      );
      entry.sha256 = '0'.repeat(64);
      refreshSourceClosureIdentityIndependent(run);
      break;
    }
    case 'enable-tsconfig-fallback': {
      const environment = structuredClone(run.launcher.effectiveEnvironment);
      delete environment.TSX_TSCONFIG_PATH;
      replaceLauncherEnvironmentIndependent(run, environment);
      run.observation.environment = structuredClone(environment);
      run.observation.tsx.configMode = 'ambient-fallback';
      refreshObservationReceiptsIndependent(run);
      break;
    }
    case 'add-tsconfig-extends-chain':
      run.observation.tsconfig.extends = '/workspace/forbidden-subject/tsconfig.base.json';
      refreshObservationReceiptsIndependent(run);
      break;
    case 'inject-environment-selector': {
      const environment = structuredClone(run.launcher.effectiveEnvironment);
      environment.NODE_OPTIONS = '--inspect=0';
      replaceLauncherEnvironmentIndependent(run, environment);
      run.observation.environment = structuredClone(environment);
      refreshObservationReceiptsIndependent(run);
      break;
    }
    case 'weaken-node-permission-flags': {
      const nodeArgv = run.launcher.nodeArgv.filter((argument) => argument !== '--no-addons');
      replaceLauncherNodeArgvIndependent(run, nodeArgv);
      break;
    }
    case 'broaden-root-bind':
      run.launcher.bubblewrap.argv.splice(12, 0, '--ro-bind', '/', '/');
      refreshLauncherIdentityIndependent(run);
      break;
    case 'add-write-bind':
      run.launcher.bubblewrap.argv.splice(12, 0, '--bind', '/tmp', '/escape');
      refreshLauncherIdentityIndependent(run);
      break;
    case 'share-network-namespace':
      run.launcher.bubblewrap.argv.splice(2, 0, '--share-net');
      refreshLauncherIdentityIndependent(run);
      break;
    case 'omit-shared-object':
      removeLayerAndMount(run, 'runtime-file:/lib64/libz.so.1');
      refreshSourceClosureIdentityIndependent(run);
      break;
    case 'substitute-esbuild-native': {
      const layer = requiredLayerForControl(run, 'package/@esbuild/linux-x64@0.28.1');
      const entry = firstRegularEntryForControl(layer, /bin\/esbuild$/u);
      entry.sha256 = '0'.repeat(64);
      refreshSourceClosureIdentityIndependent(run);
      break;
    }
    case 'symlink-retarget':
    case 'symlink-escape':
    case 'symlink-cycle':
    case 'symlink-dangling': {
      const layer = run.sourceClosure.layers.find(
        ({ kind, resolutionChain }) =>
          kind === 'runtime-file' &&
          Array.isArray(resolutionChain) &&
          resolutionChain.some(({ requestedPath }) => requestedPath === '/lib64')
      );
      assertion(layer !== undefined, 'control-precondition-failed', controlId);
      const link = layer.resolutionChain.find(({ requestedPath }) => requestedPath === '/lib64');
      assertion(
        link !== undefined && link.linkTarget === 'usr/lib64',
        'control-precondition-failed',
        `${controlId}:/lib64`
      );
      const mutation = symlinkControlTargetIndependent(controlId, link.requestedPath);
      link.linkTarget = mutation.linkTarget;
      link.resolvedPath = mutation.resolvedPath;
      refreshSourceClosureIdentityIndependent(run);
      break;
    }
    case 'scratch-residue':
      run.observation.scratch.after = ['synthetic-residue'];
      refreshObservationReceiptsIndependent(run);
      break;
    case 'enable-loader-cache': {
      const environment = {
        ...run.launcher.effectiveEnvironment,
        TSX_DISABLE_CACHE: '0',
      };
      replaceLauncherEnvironmentIndependent(run, environment);
      run.observation.environment = structuredClone(environment);
      refreshObservationReceiptsIndependent(run);
      break;
    }
    case 'working-directory-drift': {
      const index = run.launcher.bubblewrap.argv.indexOf('--chdir');
      assertion(index !== -1, 'control-precondition-failed', controlId);
      run.launcher.bubblewrap.argv[index + 1] = '/tmp';
      refreshLauncherIdentityIndependent(run);
      break;
    }
    case 'layer-logical-path-collision': {
      const layer = requiredLayerForControl(run, 'apparatus');
      const entry = firstRegularEntryForControl(layer);
      layer.entries.push(structuredClone(entry));
      layer.entries.sort((left, right) => compareUtf8(left.logicalPath, right.logicalPath));
      refreshSourceClosureIdentityIndependent(run);
      break;
    }
    case 'cross-layer-mount-target-collision': {
      const [first, second] = run.sourceClosure.mounts;
      assertion(
        first !== undefined &&
          second !== undefined &&
          first.layerId !== second.layerId &&
          first.target !== second.target,
        'control-precondition-failed',
        controlId
      );
      second.target = first.target;
      refreshSourceClosureIdentityIndependent(run);
      break;
    }
    case 'duplicate-attempt-divergence':
      run.attempts[1].stdoutSha256 = '0'.repeat(64);
      break;
    case 'forbidden-subject-import':
      run.observation.tsx.importUrls.push('file:///workspace/forbidden-subject/semantic.mjs');
      refreshObservationReceiptsIndependent(run);
      break;
    case 'claim-supported-with-blocker':
      run.observation.outcome = {
        reason: 'all-predicates-passed',
        refutationEligible: false,
        status: 'supported',
        supportEligible: true,
      };
      run.outcome = structuredClone(run.observation.outcome);
      refreshObservationReceiptsIndependent(run);
      break;
    case 'receipt-tamper':
      run.controls[0].observedReasonCode = 'forged-self-certification';
      break;
    case 'authority-tamper':
      run.authority = 'producer';
      break;
    case 'false-successor-state':
      run.interpretation.successorState = {
        observation: 'universally-absent',
        syscallTrace: null,
        universalAbsenceProved: true,
      };
      break;
    default:
      throw new InvalidNode22PreflightEvidenceError('control-unimplemented', controlId);
  }
  return refreshRunIdentityIndependent(run);
}

export function verifyIndependentControls(run) {
  const { subject } = readAndVerifySubject();
  const receipts = [];
  for (const control of subject.controlContract) {
    const mutated = mutateControlRun(structuredClone(run), control.id);
    let observedReasonCode = null;
    try {
      verifyNode22PreflightRunCore(mutated);
    } catch (error) {
      if (!(error instanceof InvalidNode22PreflightEvidenceError)) throw error;
      observedReasonCode = error.reasonCode;
    }
    assertion(
      observedReasonCode === control.expectedReasonCode,
      'control-reason-drift',
      `${control.id}: expected ${control.expectedReasonCode}, observed ${String(
        observedReasonCode
      )}`
    );
    receipts.push({
      executionDisposition: 'reject-before-execution',
      expectedReasonCode: control.expectedReasonCode,
      id: control.id,
      launchScope: 'positive-bubblewrap-boundary-only',
      mutationMode: 'in-memory-only',
      observedReasonCode,
      passed: true,
      positiveBoundaryLaunchCount: 0,
      status: 'independently-reapplied',
    });
  }
  return receipts;
}

export function verifyNode22PreflightRun(run) {
  const receipt = verifyNode22PreflightRunCore(run);
  return {
    ...receipt,
    controls: verifyIndependentControls(run),
  };
}

function loadCanonicalNode22PreflightFile(runPath) {
  const absolutePath = path.resolve(runPath);
  const relative = path.relative(REPOSITORY_ROOT, absolutePath);
  const segments = relative.split(path.sep);
  assertion(
    segments.length === 5 &&
      segments[0] === 'artifacts' &&
      segments[1] === 'node22-boundary-preflight' &&
      segments[2] === 'runs' &&
      /^[0-9a-f]{64}$/u.test(segments[3]) &&
      segments[4] === 'run.json',
    'raw-path-invalid',
    'run is not at the exact content-addressed evidence path'
  );
  assertRepositoryPathComponentsSymlinkFree(absolutePath);
  verifyRawIgnoreBoundary();
  const studyDirectory = path.join(REPOSITORY_ROOT, 'artifacts', 'node22-boundary-preflight');
  const runsDirectory = path.join(studyDirectory, 'runs');
  const runDirectory = path.join(runsDirectory, segments[3]);
  assertPrivateRawDirectory(studyDirectory, 'study evidence directory');
  assertPrivateRawDirectory(runsDirectory, 'runs evidence directory');
  assertPrivateRawDirectory(runDirectory, 'content-addressed run directory');
  const runDirectoryEntries = readdirSync(runDirectory, {
    encoding: 'utf8',
  }).sort(compareUtf8);
  assertion(
    sameArray(runDirectoryEntries, ['run.json']),
    'raw-directory-invalid',
    'content-addressed run directory contains sidecars or unexpected entries'
  );
  const receipt = readRegularFileStable(absolutePath, 'preflight run');
  const run = parseJsonBytes(receipt.bytes, 'preflight run');
  assertion(
    absolutePath ===
      path.join(
        REPOSITORY_ROOT,
        'artifacts',
        'node22-boundary-preflight',
        'runs',
        run.semanticSha256,
        'run.json'
      ),
    'raw-path-invalid',
    'run directory does not match its semantic hash'
  );
  assertion(
    receipt.metadata.nlink === 1 &&
      (receipt.metadata.mode & 0o777) === 0o600 &&
      receipt.metadata.uid === process.getuid(),
    'raw-file-invalid',
    'run file ownership, link count, or mode differs'
  );
  assertion(
    receipt.bytes.equals(Buffer.from(canonicalPrettyJsonIndependent(run), 'utf8')),
    'raw-serialization-invalid',
    'run bytes are not the exact canonical pretty serialization'
  );
  const result = verifyNode22PreflightRun(run);
  return {
    result,
    rawSha256: sha256Independent(receipt.bytes),
    run,
  };
}

export function verifyNode22PreflightFile(runPath) {
  const loaded = loadCanonicalNode22PreflightFile(runPath);
  return {
    ...loaded.result,
    rawSha256: loaded.rawSha256,
  };
}

export function rerunPositiveBoundary(run) {
  const verification = verifyNode22PreflightRun(run);
  const { subject } = readAndVerifySubject();
  const argv = buildExpectedBwrapArgvIndependent(subject);
  const expectedStdout = Buffer.from(`${canonicalJsonIndependent(run.observation)}\n`, 'utf8');
  const attempts = [];
  for (let ordinal = 1; ordinal <= 2; ordinal += 1) {
    const result = spawnSync(subject.executionContract.launcher.executable, argv, {
      cwd: subject.executionContract.launcher.hostCwd,
      encoding: null,
      env: {},
      maxBuffer: 16 * 1024 * 1024,
    });
    assertion(
      result.error === undefined &&
        result.status === 0 &&
        result.signal === null &&
        result.stderr.length === 0 &&
        result.stdout.equals(expectedStdout),
      'independent-rerun-drift',
      `attempt ${ordinal} differs from the verified positive boundary`
    );
    attempts.push({
      exitCode: result.status,
      ordinal,
      signal: result.signal,
      stderrByteLength: result.stderr.length,
      stderrSha256: sha256Independent(result.stderr),
      stdoutByteLength: result.stdout.length,
      stdoutSha256: sha256Independent(result.stdout),
    });
  }
  const postVerification = verifyNode22PreflightRun(run);
  assertion(
    canonicalJsonIndependent({
      protectedAnchors: verification.protectedAnchors,
      sourceRootSha256: verification.sourceRootSha256,
      subjectRawSha256: verification.subjectRawSha256,
    }) ===
      canonicalJsonIndependent({
        protectedAnchors: postVerification.protectedAnchors,
        sourceRootSha256: postVerification.sourceRootSha256,
        subjectRawSha256: postVerification.subjectRawSha256,
      }),
    'independent-rerun-drift',
    'protected anchors or source closure changed across rerun'
  );
  return {
    attempts,
    byteIdentical: attempts[0].stdoutSha256 === attempts[1].stdoutSha256,
    launchCount: attempts.length,
    postVerification,
    prePostBoundaryEquivalent: true,
    verification,
  };
}

function main() {
  const args = process.argv.slice(2);
  assertion(
    args.length === 1 || (args.length === 2 && args[0] === '--rerun'),
    'invocation-invalid',
    'usage: node verify.mjs [--rerun] /absolute/path/to/run.json'
  );
  const rerun = args[0] === '--rerun';
  const runPath = rerun ? args[1] : args[0];
  if (!rerun) {
    process.stdout.write(`${canonicalJsonIndependent(verifyNode22PreflightFile(runPath))}\n`);
    return;
  }
  const loaded = loadCanonicalNode22PreflightFile(runPath);
  process.stdout.write(`${canonicalJsonIndependent(rerunPositiveBoundary(loaded.run))}\n`);
}

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main();
}
