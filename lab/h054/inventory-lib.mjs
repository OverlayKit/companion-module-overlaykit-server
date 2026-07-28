import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
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
  statfsSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const LAB_DIRECTORY = realpathSync(path.dirname(fileURLToPath(import.meta.url)));
const REPOSITORY_ROOT = realpathSync(path.resolve(LAB_DIRECTORY, '../..'));

const EXPECTED_MAIN_COMMIT = '161554b968b6dc38fb1cc055c829b414ba5b85ae';
const EXPECTED_MAIN_TREE = 'd8087b92796a8be07ee5779a5847e0e3859930a0';
const EXPECTED_MAIN_RECURSIVE_ENTRY_COUNT = 319;
const EXPECTED_MAIN_RECURSIVE_LS_TREE_SHA256 =
  '9c5dc303da5ed8da64ee59c78e5cd5a3efaab617e93ab502925a884364d9cde1';
const EXPECTED_H053_CLOSURE_SHA256 =
  'e84b9faeb4858549eec513c3a08f19da566987665f4c79a448102dbc957b4911';
const EXPECTED_H053_RUN_RAW_SHA256 =
  '5a55fc6ec2dff653858d4c8a70a22d3085400b423b8c93e265f14774078bf14f';
const EXPECTED_ERRORS_SHA256 = '23f0c8e843f655a61dae807709c75670a42ef4b851beb0d8cacd584d0e0578b4';
const EXPECTED_GUARDED_REGULAR_FILE_COUNT = 40;
const EXPECTED_H053_GUARDED_SURFACE_SHA256 =
  '4f3d19de30dc7df9819037004a27672a7b319693cc6fff54ad081a2999056ce8';
const EXPECTED_H053_APPARATUS_REGULAR_FILE_COUNT = 10;
const EXPECTED_H053_APPARATUS_SHA256 =
  '1c686c08b995890b39ab750e0fc593766d5916fed2dfc5e6f657ea51f6b40126';
const EXPECTED_PACKAGE_REGULAR_FILE_COUNT = 587;

const H053_CLOSURE_DIRECTORY =
  'artifacts/h053/post-review-closures/5a55fc6ec2dff653858d4c8a70a22d3085400b423b8c93e265f14774078bf14f';
const H053_RUN_DIRECTORY =
  'artifacts/h053/runs/0e979b5191acbf68a865d6f9c651d8683e93fbcc26cfd44bbf06ad363a3b29d4';

const GUARDED_PATHS = Object.freeze([
  '.overlaykit/governance/decisions',
  '.overlaykit/governance/mechanisms.json',
  '.overlaykit/governance/plan.json',
  '.overlaykit/governance/profile.json',
  '.overlaykit/governance/schemas',
  '.overlaykit/governance/specifications',
  'package-lock.json',
  'package.json',
  'src',
  'tests',
  'tools/governance/src',
]);

const LOADER_CONFIGURATION_PATHS = Object.freeze([
  'node_modules/.package-lock.json',
  'package-lock.json',
  'package.json',
  'tools/governance/package.json',
  'tools/governance/tsconfig.build.json',
  'tools/governance/tsconfig.json',
  'tsconfig.build.json',
  'tsconfig.json',
]);

const PACKAGE_SEEDS = Object.freeze(['ajv', 'tsx']);

const NODE_CANDIDATES = Object.freeze([
  {
    id: 'node22',
    version: 'v22.22.2',
    commandPath: '/usr/bin/node',
    executablePath: '/usr/bin/node-22',
    executableSha256: '1a1ebcd93dc90cf3e3dc37493e8efc04a1f60bddada1402453094214af03e33d',
  },
  {
    id: 'node24',
    version: 'v24.16.0',
    commandPath: '/home/rod/.local/share/nodejs/node-v24.16.0-linux-x64/bin/node',
    executablePath: '/home/rod/.local/share/nodejs/node-v24.16.0-linux-x64/bin/node',
    executableSha256: 'b2959781cc5a74c357ffa02367efa8a0330cbb1c9cb347732fdfaaaca381cbcd',
  },
]);

const GIT_EXECUTABLE = '/usr/bin/git';
const EXPECTED_GIT_SHA256 = '8d8d470218586c27909c9b6ae77d18df32a9e05e725044ae2052d60254791c26';
const ESBUILD_EXECUTABLE = 'node_modules/@esbuild/linux-x64/bin/esbuild';
const EXPECTED_ESBUILD_SHA256 = '0c6588b092a2c291a72bab90659f3c9e0e25e0fe59c9ac12b4dae4d945e5548c';

const SEMANTIC_ENVIRONMENT_KEYS = Object.freeze([
  'ESBUILD_BINARY_PATH',
  'ESBUILD_MAX_BUFFER',
  'ESBUILD_WORKER_THREADS',
  'FORCE_COLOR',
  'HOME',
  'LANG',
  'LC_ALL',
  'LC_COLLATE',
  'LC_CTYPE',
  'LC_MESSAGES',
  'LD_AUDIT',
  'LD_LIBRARY_PATH',
  'LD_PRELOAD',
  'NODE_OPTIONS',
  'NODE_PATH',
  'NODE_ICU_DATA',
  'NO_COLOR',
  'OPENSSL_CONF',
  'OPENSSL_MODULES',
  'PATH',
  'SSL_CERT_DIR',
  'SSL_CERT_FILE',
  'TEMP',
  'TMP',
  'TMPDIR',
  'TSX_DEBUG',
  'TSX_DISABLE_CACHE',
  'TSX_TSCONFIG_PATH',
  'TZ',
  'XDG_CACHE_HOME',
]);

const ENVIRONMENT_VALUES_SAFE_TO_RECORD = new Set([
  'FORCE_COLOR',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'NO_COLOR',
  'TEMP',
  'TMP',
  'TMPDIR',
  'TZ',
]);

const HOST_CONTEXT_PATHS = Object.freeze([
  '/etc/crypto-policies/back-ends/opensslcnf.config',
  '/etc/crypto-policies/config',
  '/etc/ld.so.cache',
  '/etc/locale.conf',
  '/etc/localtime',
  '/etc/os-release',
  '/etc/ssl/openssl.cnf',
  '/usr/lib/locale/locale-archive',
]);

const CONTROL_REASON_CODES = Object.freeze([
  ['omit-errors-ts', 'required-entry-omitted'],
  ['omit-ajv-transitive', 'required-package-entry-omitted'],
  ['omit-esbuild-native', 'required-native-binary-omitted'],
  ['omit-node-final-or-libnode', 'runtime-dependency-omitted'],
  ['omit-git-or-library', 'git-runtime-dependency-omitted'],
  ['omit-env-cache-selector', 'environment-selector-omitted'],
  ['stale-main-anchor', 'main-anchor-stale'],
  ['stale-h053-closure', 'h053-closure-stale'],
  ['stale-apparatus', 'apparatus-stale'],
  ['symlink-retarget', 'symlink-chain-drift'],
  ['symlink-cycle-escape', 'symlink-invalid'],
  ['flatten-layer-collision', 'layer-qualified-cardinality-drift'],
]);

export const H054_EVIDENCE_PATHS = Object.freeze({
  repositoryRoot: REPOSITORY_ROOT,
  artifactsRoot: path.join(REPOSITORY_ROOT, 'artifacts'),
  h054Root: path.join(REPOSITORY_ROOT, 'artifacts', 'h054'),
  runsRoot: path.join(REPOSITORY_ROOT, 'artifacts', 'h054', 'runs'),
});

export const H054_CONSTANTS = Object.freeze({
  expectedMainCommit: EXPECTED_MAIN_COMMIT,
  expectedMainTree: EXPECTED_MAIN_TREE,
  expectedMainRecursiveEntryCount: EXPECTED_MAIN_RECURSIVE_ENTRY_COUNT,
  expectedMainRecursiveLsTreeSha256: EXPECTED_MAIN_RECURSIVE_LS_TREE_SHA256,
  expectedH053ClosureSha256: EXPECTED_H053_CLOSURE_SHA256,
  expectedH053RunRawSha256: EXPECTED_H053_RUN_RAW_SHA256,
  expectedErrorsSha256: EXPECTED_ERRORS_SHA256,
  guardedPaths: GUARDED_PATHS,
  loaderConfigurationPaths: LOADER_CONFIGURATION_PATHS,
  controlIds: CONTROL_REASON_CODES.map(([id]) => id),
  runtimeSelection: null,
});

export class InvalidH054InventoryError extends Error {
  constructor(reasonCode, message) {
    super(message);
    this.name = 'InvalidH054InventoryError';
    this.reasonCode = reasonCode;
  }
}

function assertion(condition, reasonCode, message) {
  if (!condition) {
    throw new InvalidH054InventoryError(reasonCode, message);
  }
}

export function compareUtf8Bytewise(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function canonicalizeBytewise(value) {
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalizeBytewise(entry));
  }
  if (value !== null && typeof value === 'object') {
    assertion(
      Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null,
      'canonical-value-invalid',
      'only plain objects may enter canonical JSON'
    );
    return Object.fromEntries(
      Object.keys(value)
        .sort(compareUtf8Bytewise)
        .map((key) => [key, canonicalizeBytewise(value[key])])
    );
  }
  assertion(
    value === null ||
      typeof value === 'string' ||
      typeof value === 'boolean' ||
      (typeof value === 'number' && Number.isFinite(value)),
    'canonical-value-invalid',
    `unsupported canonical value ${String(value)}`
  );
  return value;
}

export function canonicalJsonBytewise(value) {
  return JSON.stringify(canonicalizeBytewise(value));
}

export function canonicalPrettyJsonBytewise(value) {
  return `${JSON.stringify(canonicalizeBytewise(value), null, 2)}\n`;
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function canonicalHashBytewise(value) {
  return sha256(Buffer.from(canonicalJsonBytewise(value), 'utf8'));
}

function canonicalRelativePath(value) {
  assertion(typeof value === 'string' && value.length > 0, 'path-invalid', 'logical path is empty');
  assertion(
    !path.posix.isAbsolute(value) &&
      !value.includes('\\') &&
      value === path.posix.normalize(value) &&
      !value.split('/').some((component) => component === '' || component === '..'),
    'path-invalid',
    `logical path is not canonical POSIX relative: ${value}`
  );
  assertion(
    Buffer.from(value, 'utf8').toString('utf8') === value,
    'path-invalid',
    `logical path is not valid UTF-8: ${value}`
  );
  return value;
}

function octalMode(metadata) {
  return (metadata.mode & 0o7777).toString(8).padStart(4, '0');
}

function stableMetadata(before, after) {
  return (
    before.dev === after.dev &&
    before.ino === after.ino &&
    before.mode === after.mode &&
    before.nlink === after.nlink &&
    before.size === after.size &&
    before.mtimeMs === after.mtimeMs
  );
}

function regularFileDescriptor(absolutePath, logicalPath, metadata = lstatSync(absolutePath)) {
  assertion(metadata.isFile(), 'file-type-invalid', `not a regular file: ${absolutePath}`);
  const descriptor = openSync(absolutePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(descriptor);
    assertion(
      before.isFile() &&
        before.dev === metadata.dev &&
        before.ino === metadata.ino &&
        before.mode === metadata.mode,
      'file-race-detected',
      `pathname changed before read: ${absolutePath}`
    );
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    const pathnameAfter = lstatSync(absolutePath);
    assertion(
      stableMetadata(before, after) &&
        after.dev === pathnameAfter.dev &&
        after.ino === pathnameAfter.ino &&
        after.mode === pathnameAfter.mode,
      'file-race-detected',
      `file changed while read: ${absolutePath}`
    );
    assertion(
      bytes.length === after.size,
      'file-race-detected',
      `file length changed while read: ${absolutePath}`
    );
    return {
      logicalPath: canonicalRelativePath(logicalPath),
      kind: 'regular-file',
      mode: octalMode(after),
      nlink: after.nlink,
      hardLinked: after.nlink !== 1,
      byteLength: bytes.length,
      sha256: sha256(bytes),
    };
  } finally {
    closeSync(descriptor);
  }
}

function filesystemDescriptor(absolutePath, logicalPath) {
  const before = lstatSync(absolutePath);
  if (before.isFile()) {
    return regularFileDescriptor(absolutePath, logicalPath, before);
  }
  if (before.isDirectory()) {
    return {
      logicalPath: canonicalRelativePath(logicalPath),
      kind: 'directory',
      mode: octalMode(before),
      nlink: before.nlink,
    };
  }
  if (before.isSymbolicLink()) {
    const linkTarget = readlinkSync(absolutePath);
    const after = lstatSync(absolutePath);
    assertion(
      stableMetadata(before, after),
      'symlink-race-detected',
      `symlink changed while read: ${absolutePath}`
    );
    return {
      logicalPath: canonicalRelativePath(logicalPath),
      kind: 'symbolic-link',
      mode: octalMode(before),
      linkTarget,
      linkTargetByteLength: Buffer.byteLength(linkTarget, 'utf8'),
      linkTargetSha256: sha256(Buffer.from(linkTarget, 'utf8')),
    };
  }
  return {
    logicalPath: canonicalRelativePath(logicalPath),
    kind: 'unsupported-special-file',
    mode: octalMode(before),
    classification: 'opaque-not-executable-boundary-eligible',
  };
}

function walkFilesystem(absolutePath, logicalPath, entries) {
  const descriptor = filesystemDescriptor(absolutePath, logicalPath);
  entries.push(descriptor);
  if (descriptor.kind !== 'directory') {
    return;
  }
  const children = readdirSync(absolutePath, { withFileTypes: true })
    .map(({ name }) => name)
    .sort(compareUtf8Bytewise);
  for (const child of children) {
    walkFilesystem(path.join(absolutePath, child), path.posix.join(logicalPath, child), entries);
  }
}

function sortedUniqueEntries(entries, layerId) {
  const sorted = [...entries].sort((left, right) =>
    compareUtf8Bytewise(left.logicalPath, right.logicalPath)
  );
  for (let index = 0; index < sorted.length; index += 1) {
    canonicalRelativePath(sorted[index].logicalPath);
    assertion(
      index === 0 || sorted[index - 1].logicalPath !== sorted[index].logicalPath,
      'layer-path-collision',
      `${layerId} repeats ${sorted[index].logicalPath}`
    );
  }
  return sorted;
}

function makeLayer(id, kind, entries, metadata = {}) {
  const sortedEntries = sortedUniqueEntries(entries, id);
  const body = {
    schemaVersion: 'overlaykit-h054-content-layer/v1',
    id,
    kind,
    metadata,
    entries: sortedEntries,
  };
  return {
    ...body,
    entryCount: sortedEntries.length,
    contentSha256: canonicalHashBytewise(body),
  };
}

function snapshotRepositoryPaths(id, kind, logicalPaths, metadata = {}) {
  const entries = [];
  for (const logicalPath of [...logicalPaths].sort(compareUtf8Bytewise)) {
    canonicalRelativePath(logicalPath);
    const absolutePath = path.resolve(REPOSITORY_ROOT, logicalPath);
    assertion(absolutePath.startsWith(`${REPOSITORY_ROOT}${path.sep}`), 'path-escape', logicalPath);
    walkFilesystem(absolutePath, logicalPath, entries);
  }
  return makeLayer(id, kind, entries, { ...metadata, logicalPaths: [...logicalPaths] });
}

function h053RegularFileDescriptorReceipt(layer) {
  const files = layer.entries
    .filter(({ kind }) => kind === 'regular-file')
    .map(({ logicalPath: filePath, byteLength, sha256: fileSha256 }) => ({
      path: filePath,
      byteLength,
      sha256: fileSha256,
    }))
    .sort((left, right) => compareUtf8Bytewise(left.path, right.path));
  return {
    regularFileCount: files.length,
    descriptorSetSha256: canonicalHashBytewise(files),
  };
}

function snapshotGuardedSurface() {
  const provisional = snapshotRepositoryPaths(
    'source/guarded-worktree',
    'guarded-worktree-surface',
    GUARDED_PATHS,
    {
      source: 'H-053 guardedSurface.paths',
      symlinkPolicy: 'inventory-but-classify-ineligible',
    }
  );
  const receipt = h053RegularFileDescriptorReceipt(provisional);
  assertion(
    receipt.regularFileCount === EXPECTED_GUARDED_REGULAR_FILE_COUNT &&
      receipt.descriptorSetSha256 === EXPECTED_H053_GUARDED_SURFACE_SHA256,
    'guarded-surface-drift',
    `expected ${EXPECTED_GUARDED_REGULAR_FILE_COUNT}/${EXPECTED_H053_GUARDED_SURFACE_SHA256}, observed ${receipt.regularFileCount}/${receipt.descriptorSetSha256}`
  );
  return makeLayer(provisional.id, provisional.kind, provisional.entries, {
    ...provisional.metadata,
    h053Receipt: receipt,
  });
}

function snapshotH053Apparatus() {
  const provisional = snapshotRepositoryPaths(
    'apparatus/h053',
    'accepted-h053-experimental-apparatus',
    ['lab/h053'],
    {
      executionDistinction:
        'tests are inventoried apparatus but are not asserted to have executed in the canonical run',
    }
  );
  const receipt = h053RegularFileDescriptorReceipt(provisional);
  assertion(
    receipt.regularFileCount === EXPECTED_H053_APPARATUS_REGULAR_FILE_COUNT &&
      receipt.descriptorSetSha256 === EXPECTED_H053_APPARATUS_SHA256,
    'h053-apparatus-drift',
    `expected ${EXPECTED_H053_APPARATUS_REGULAR_FILE_COUNT}/${EXPECTED_H053_APPARATUS_SHA256}, observed ${receipt.regularFileCount}/${receipt.descriptorSetSha256}`
  );
  return makeLayer(provisional.id, provisional.kind, provisional.entries, {
    ...provisional.metadata,
    h053Receipt: receipt,
  });
}

function readRepositoryFile(logicalPath) {
  const absolutePath = path.resolve(REPOSITORY_ROOT, logicalPath);
  const descriptor = regularFileDescriptor(absolutePath, logicalPath);
  const fileDescriptor = openSync(absolutePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const bytes = readFileSync(fileDescriptor);
    assertion(
      bytes.length === descriptor.byteLength && sha256(bytes) === descriptor.sha256,
      'file-race-detected',
      `bytes changed between reads: ${absolutePath}`
    );
    return { bytes, descriptor };
  } finally {
    closeSync(fileDescriptor);
  }
}

function gitEnvironment() {
  return {
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_SYSTEM: '/dev/null',
    GIT_NO_LAZY_FETCH: '1',
    GIT_NO_REPLACE_OBJECTS: '1',
    GIT_OPTIONAL_LOCKS: '0',
    LANG: 'C',
    LC_ALL: 'C',
    PATH: '/usr/bin:/bin',
  };
}

function gitInvocationReceipt(invocations) {
  const argv = invocations.map((args) => [...args]);
  return {
    executablePath: GIT_EXECUTABLE,
    argv,
    argvCount: argv.length,
    argvSetSha256: canonicalHashBytewise(argv),
    childEnvironment: gitEnvironment(),
  };
}

function gitRead(args, options = {}) {
  const allowed = new Set(['cat-file', 'for-each-ref', 'ls-tree', 'rev-parse', '--version']);
  assertion(
    Array.isArray(args) && args.length > 0 && allowed.has(args[0]),
    'git-operation-refused',
    `operation is not read-only allowlisted: ${String(args[0])}`
  );
  return execFileSync(GIT_EXECUTABLE, args, {
    cwd: REPOSITORY_ROOT,
    env: gitEnvironment(),
    encoding: options.encoding ?? null,
    maxBuffer: options.maxBuffer ?? 32 * 1024 * 1024,
    windowsHide: true,
  });
}

function snapshotMainGitTree() {
  const headArgs = ['rev-parse', '--verify', 'HEAD^{commit}'];
  const commitArgs = ['rev-parse', '--verify', `${EXPECTED_MAIN_COMMIT}^{commit}`];
  const treeArgs = ['rev-parse', `${EXPECTED_MAIN_COMMIT}^{tree}`];
  const lsTreeArgs = ['ls-tree', '-rz', '--full-tree', '-r', EXPECTED_MAIN_COMMIT];
  const head = gitRead(headArgs, { encoding: 'utf8' }).trim();
  const commit = gitRead(commitArgs, {
    encoding: 'utf8',
  }).trim();
  const tree = gitRead(treeArgs, {
    encoding: 'utf8',
  }).trim();
  assertion(
    head === EXPECTED_MAIN_COMMIT && commit === EXPECTED_MAIN_COMMIT && tree === EXPECTED_MAIN_TREE,
    'main-anchor-drift',
    `expected ${EXPECTED_MAIN_COMMIT}/${EXPECTED_MAIN_TREE}, observed ${head}/${tree}`
  );

  const treeBytes = gitRead(lsTreeArgs);
  const records = treeBytes.toString('utf8').split('\0').filter(Boolean);
  assertion(
    records.length === EXPECTED_MAIN_RECURSIVE_ENTRY_COUNT &&
      sha256(treeBytes) === EXPECTED_MAIN_RECURSIVE_LS_TREE_SHA256,
    'main-recursive-tree-drift',
    `expected ${EXPECTED_MAIN_RECURSIVE_ENTRY_COUNT}/${EXPECTED_MAIN_RECURSIVE_LS_TREE_SHA256}, observed ${records.length}/${sha256(
      treeBytes
    )}`
  );
  const entries = records.map((record) => {
    const match = /^(?<mode>[0-9]{6}) (?<type>[a-z]+) (?<oid>[0-9a-f]{40})\t(?<path>.+)$/u.exec(
      record
    );
    assertion(match !== null, 'git-tree-invalid', `malformed ls-tree record: ${record}`);
    const sourceBytes = gitRead(['cat-file', match.groups.type, match.groups.oid]);
    const common = {
      logicalPath: canonicalRelativePath(match.groups.path),
      gitMode: match.groups.mode,
      gitType: match.groups.type,
      gitOid: match.groups.oid,
      byteLength: sourceBytes.length,
      sha256: sha256(sourceBytes),
    };
    if (match.groups.mode === '120000') {
      return {
        ...common,
        kind: 'git-symbolic-link',
        linkTarget: sourceBytes.toString('utf8'),
      };
    }
    if (match.groups.mode === '160000') {
      return {
        ...common,
        kind: 'gitlink',
        classification: 'opaque-external-object',
      };
    }
    if (match.groups.mode === '040000' && match.groups.type === 'tree') {
      return { ...common, kind: 'git-tree' };
    }
    return { ...common, kind: 'git-regular-file' };
  });
  return makeLayer('source/main-git-tree', 'git-tree', entries, {
    commit: EXPECTED_MAIN_COMMIT,
    tree: EXPECTED_MAIN_TREE,
    recursiveEntryCount: records.length,
    recursiveLsTreeSha256: sha256(treeBytes),
    invocationReceipt: gitInvocationReceipt([
      headArgs,
      commitArgs,
      treeArgs,
      lsTreeArgs,
      ...entries.map(({ gitType, gitOid }) => ['cat-file', gitType, gitOid]),
    ]),
  });
}

function verifyAnchoredFile(logicalPath, expectedSha256, label) {
  const absolutePath = path.join(REPOSITORY_ROOT, logicalPath);
  const descriptor = regularFileDescriptor(absolutePath, logicalPath);
  assertion(
    descriptor.sha256 === expectedSha256,
    'anchored-file-drift',
    `${label} expected ${expectedSha256}, observed ${descriptor.sha256}`
  );
  return descriptor;
}

function snapshotH053Artifacts() {
  verifyAnchoredFile(
    `${H053_CLOSURE_DIRECTORY}/closure.json`,
    EXPECTED_H053_CLOSURE_SHA256,
    'H-053 post-review closure'
  );
  verifyAnchoredFile(
    `${H053_RUN_DIRECTORY}/run.json`,
    EXPECTED_H053_RUN_RAW_SHA256,
    'H-053 canonical run'
  );
  const layers = [
    snapshotRepositoryPaths(
      'evidence/h053-post-review-closure',
      'local-content-addressed-evidence',
      [H053_CLOSURE_DIRECTORY],
      {
        anchorFile: `${H053_CLOSURE_DIRECTORY}/closure.json`,
        anchorSha256: EXPECTED_H053_CLOSURE_SHA256,
      }
    ),
    snapshotRepositoryPaths(
      'evidence/h053-canonical-run',
      'local-content-addressed-evidence',
      [H053_RUN_DIRECTORY],
      {
        anchorFile: `${H053_RUN_DIRECTORY}/run.json`,
        anchorSha256: EXPECTED_H053_RUN_RAW_SHA256,
      }
    ),
  ];
  const closureRegularFileCount = layers[0].entries.filter(
    ({ kind }) => kind === 'regular-file'
  ).length;
  const runRegularFileCount = layers[1].entries.filter(
    ({ kind }) => kind === 'regular-file'
  ).length;
  assertion(
    closureRegularFileCount === 6 && runRegularFileCount === 1,
    'h053-evidence-cardinality-drift',
    `expected closure/run regular-file counts 6/1, observed ${closureRegularFileCount}/${runRegularFileCount}`
  );
  return [
    makeLayer(layers[0].id, layers[0].kind, layers[0].entries, {
      ...layers[0].metadata,
      regularFileCount: closureRegularFileCount,
    }),
    makeLayer(layers[1].id, layers[1].kind, layers[1].entries, {
      ...layers[1].metadata,
      regularFileCount: runRegularFileCount,
    }),
  ];
}

function deriveInstalledPackageRoots() {
  const lockReceipt = readRepositoryFile('package-lock.json');
  let lock;
  try {
    lock = JSON.parse(lockReceipt.bytes.toString('utf8'));
  } catch (error) {
    throw new InvalidH054InventoryError(
      'package-lock-invalid',
      `package-lock.json: ${error.message}`
    );
  }
  assertion(
    lock.lockfileVersion === 3 && lock.packages !== null && typeof lock.packages === 'object',
    'package-lock-invalid',
    'package-lock must expose a v3 packages map'
  );

  const queue = [...PACKAGE_SEEDS].sort(compareUtf8Bytewise);
  const seen = new Set();
  const roots = [];
  while (queue.length > 0) {
    const name = queue.shift();
    if (seen.has(name)) {
      continue;
    }
    seen.add(name);
    const logicalRoot = `node_modules/${name}`;
    const packageJsonPath = `${logicalRoot}/package.json`;
    const manifestReceipt = readRepositoryFile(packageJsonPath);
    let manifest;
    try {
      manifest = JSON.parse(manifestReceipt.bytes.toString('utf8'));
    } catch (error) {
      throw new InvalidH054InventoryError(
        'package-manifest-invalid',
        `${packageJsonPath}: ${error.message}`
      );
    }
    const lockEntry = lock.packages[logicalRoot];
    assertion(
      lockEntry !== null &&
        typeof lockEntry === 'object' &&
        manifest.name === name &&
        typeof manifest.version === 'string' &&
        lockEntry.version === manifest.version &&
        typeof lockEntry.resolved === 'string' &&
        typeof lockEntry.integrity === 'string',
      'package-lock-resolution-drift',
      `${name} is not bound byte-for-byte to the installed lock entry`
    );

    const dependencies = manifest.dependencies ?? {};
    const optionalDependencies = manifest.optionalDependencies ?? {};
    const requiredNames = Object.keys(dependencies).sort(compareUtf8Bytewise);
    const optionalNames = Object.keys(optionalDependencies).sort(compareUtf8Bytewise);
    const followedOptionalNames = [];
    const absentOptionalNames = [];
    for (const dependencyName of requiredNames) {
      try {
        lstatSync(path.join(REPOSITORY_ROOT, 'node_modules', dependencyName, 'package.json'));
      } catch (error) {
        assertion(
          false,
          'required-package-dependency-missing',
          `${name} requires absent ${dependencyName}: ${String(error?.code ?? 'UNKNOWN')}`
        );
      }
      queue.push(dependencyName);
    }
    for (const dependencyName of optionalNames) {
      try {
        lstatSync(path.join(REPOSITORY_ROOT, 'node_modules', dependencyName, 'package.json'));
        followedOptionalNames.push(dependencyName);
        queue.push(dependencyName);
      } catch (error) {
        assertion(
          error?.code === 'ENOENT',
          'optional-package-dependency-unclassifiable',
          `${name}/${dependencyName}: ${String(error?.code ?? 'UNKNOWN')}`
        );
        absentOptionalNames.push(dependencyName);
      }
    }
    queue.sort(compareUtf8Bytewise);
    roots.push({
      name,
      version: manifest.version,
      logicalRoot,
      packageManifestSha256: manifestReceipt.descriptor.sha256,
      lockResolved: lockEntry.resolved,
      lockIntegrity: lockEntry.integrity,
      declaredDependencies: Object.fromEntries(
        [...requiredNames, ...optionalNames]
          .sort(compareUtf8Bytewise)
          .map((dependencyName) => [
            dependencyName,
            dependencies[dependencyName] ?? optionalDependencies[dependencyName],
          ])
      ),
      requiredDependencies: requiredNames,
      followedOptionalDependencies: followedOptionalNames,
      absentOptionalDependencies: absentOptionalNames,
      seed: PACKAGE_SEEDS.includes(name),
      packageEntryPointResolution: {
        exportsDeclared: Object.hasOwn(manifest, 'exports'),
        exportsValueSha256: Object.hasOwn(manifest, 'exports')
          ? canonicalHashBytewise(manifest.exports)
          : null,
        main: typeof manifest.main === 'string' ? manifest.main : null,
        binValueSha256: Object.hasOwn(manifest, 'bin') ? canonicalHashBytewise(manifest.bin) : null,
        classification:
          'whole-tree-inventoried-per-import-and-export-condition-resolution-not-enumerated',
      },
    });
  }
  return roots.sort((left, right) => compareUtf8Bytewise(left.name, right.name));
}

function snapshotPackageLayers() {
  return deriveInstalledPackageRoots().map(
    ({
      name,
      version,
      logicalRoot,
      packageManifestSha256,
      lockResolved,
      lockIntegrity,
      declaredDependencies,
      requiredDependencies,
      followedOptionalDependencies,
      absentOptionalDependencies,
      seed,
      packageEntryPointResolution,
    }) => {
      const provisional = snapshotRepositoryPaths(
        `package/${name}@${version}`,
        'installed-package-tree',
        [logicalRoot],
        {
          name,
          version,
          packageManifestSha256,
          lockResolved,
          lockIntegrity,
          declaredDependencies,
          requiredDependencies,
          followedOptionalDependencies,
          absentOptionalDependencies,
          seed,
          packageEntryPointResolution,
          derivation:
            'human-nominated H-053 seeds followed through installed required and optional package edges',
          resolution: 'whole-installed-tree-conservative-closure',
        }
      );
      const regularFileCount = provisional.entries.filter(
        ({ kind }) => kind === 'regular-file'
      ).length;
      return makeLayer(provisional.id, provisional.kind, provisional.entries, {
        ...provisional.metadata,
        regularFileCount,
      });
    }
  );
}

function pathPrefixes(absolutePath) {
  assertion(path.isAbsolute(absolutePath), 'absolute-path-invalid', absolutePath);
  const parts = path.normalize(absolutePath).split(path.sep).filter(Boolean);
  const prefixes = [];
  let current = path.parse(absolutePath).root;
  for (const part of parts) {
    current = path.join(current, part);
    prefixes.push(current);
  }
  return prefixes;
}

function absoluteLogicalPath(absolutePath) {
  return canonicalRelativePath(`host${path.normalize(absolutePath).replaceAll(path.sep, '/')}`);
}

function collectAbsolutePathDescriptors(requestedPaths) {
  const descriptorPaths = new Set();
  const resolutions = [];
  for (const requestedPath of [...requestedPaths].sort(compareUtf8Bytewise)) {
    assertion(path.isAbsolute(requestedPath), 'absolute-path-invalid', requestedPath);
    let realPath = null;
    let errorCode = null;
    try {
      realPath = realpathSync(requestedPath);
      for (const prefix of pathPrefixes(requestedPath)) {
        const metadata = lstatSync(prefix);
        if (metadata.isSymbolicLink()) {
          descriptorPaths.add(prefix);
        }
      }
      descriptorPaths.add(requestedPath);
      descriptorPaths.add(realPath);
    } catch (error) {
      errorCode = error?.code ?? 'UNKNOWN';
    }
    resolutions.push({
      requestedPath,
      realPath,
      status: realPath === null ? 'unresolved' : 'resolved',
      errorCode,
    });
  }
  const entries = [...descriptorPaths]
    .sort(compareUtf8Bytewise)
    .map((absolutePath) => filesystemDescriptor(absolutePath, absoluteLogicalPath(absolutePath)));
  return { entries, resolutions };
}

function lddReceipt(executablePath) {
  let output;
  try {
    output = execFileSync('/usr/bin/ldd', [executablePath], {
      cwd: REPOSITORY_ROOT,
      env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin' },
      encoding: 'utf8',
      maxBuffer: 4 * 1024 * 1024,
      windowsHide: true,
    });
  } catch (error) {
    const normalized = {
      status: 'opaque',
      exitCode: error?.status ?? null,
      resolvedPaths: [],
      unresolvedLibraries: [],
      virtualLibraries: [],
      unparsedLines: [],
      diagnosticOutput: 'not-content-addressed-because-loader-addresses-are-nondeterministic',
    };
    return {
      ...normalized,
      normalizedReceiptSha256: canonicalHashBytewise(normalized),
    };
  }

  const resolvedPaths = new Set();
  const unresolvedLibraries = [];
  const virtualLibraries = [];
  const unparsedLines = [];
  for (const rawLine of output.split('\n')) {
    const line = rawLine.trim();
    if (line === '') {
      continue;
    }
    if (line.startsWith('linux-vdso.so.1')) {
      virtualLibraries.push('linux-vdso.so.1');
      continue;
    }
    const resolvedMatch = /^(?:[^ ]+ => )?(?<path>\/[^ ]+) \(0x[0-9a-f]+\)$/u.exec(line);
    if (resolvedMatch !== null) {
      resolvedPaths.add(resolvedMatch.groups.path);
      continue;
    }
    const missingMatch = /^(?<name>[^ ]+) => not found$/u.exec(line);
    if (missingMatch !== null) {
      unresolvedLibraries.push(missingMatch.groups.name);
      continue;
    }
    unparsedLines.push(line.replaceAll(/0x[0-9a-f]+/gu, '0x<address>'));
  }
  const normalized = {
    status:
      unresolvedLibraries.length === 0 && unparsedLines.length === 0
        ? 'resolved-with-virtual-context'
        : 'incomplete',
    resolvedPaths: [...resolvedPaths].sort(compareUtf8Bytewise),
    unresolvedLibraries: unresolvedLibraries.sort(compareUtf8Bytewise),
    virtualLibraries: virtualLibraries.sort(compareUtf8Bytewise),
    unparsedLines: unparsedLines.sort(compareUtf8Bytewise),
    normalization:
      'parsed library names and resolved paths plus normalized unparsed lines; ASLR load addresses and raw ldd output excluded',
  };
  return {
    ...normalized,
    normalizedReceiptSha256: canonicalHashBytewise(normalized),
  };
}

function runtimeProbe(candidate) {
  const expression = `JSON.stringify({
    version: process.version,
    versions: process.versions,
    architecture: process.arch,
    platform: process.platform,
    executablePath: process.execPath,
    features: process.features,
    moduleHooks: {
      register: typeof require('node:module').register,
      registerHooks: typeof require('node:module').registerHooks,
      stripTypeScriptTypes: typeof require('node:module').stripTypeScriptTypes
    },
    locale: {
      collator: new Intl.Collator().resolvedOptions().locale,
      dateTime: new Intl.DateTimeFormat().resolvedOptions()
    },
    temporaryDirectory: require('node:os').tmpdir()
  })`;
  const output = execFileSync(candidate.executablePath, ['-p', expression], {
    cwd: REPOSITORY_ROOT,
    env: { LANG: 'C', LC_ALL: 'C', PATH: '/usr/bin:/bin', TZ: 'UTC' },
    encoding: 'utf8',
    maxBuffer: 2 * 1024 * 1024,
    windowsHide: true,
  }).trim();
  let receipt;
  try {
    receipt = JSON.parse(output);
  } catch (error) {
    throw new InvalidH054InventoryError(
      'runtime-probe-invalid',
      `${candidate.id}: ${error.message}`
    );
  }
  assertion(
    receipt.version === candidate.version,
    'runtime-version-drift',
    `${candidate.id}: expected ${candidate.version}, observed ${String(receipt.version)}`
  );
  return receipt;
}

function snapshotRuntimeCandidate(candidate) {
  const executableDescriptor = filesystemDescriptor(
    candidate.executablePath,
    absoluteLogicalPath(candidate.executablePath)
  );
  assertion(
    executableDescriptor.kind === 'regular-file' &&
      executableDescriptor.sha256 === candidate.executableSha256,
    'runtime-executable-drift',
    `${candidate.id}: expected ${candidate.executableSha256}, observed ${String(
      executableDescriptor.sha256
    )}`
  );
  const libraries = lddReceipt(candidate.executablePath);
  const requestedPaths = [
    candidate.commandPath,
    candidate.executablePath,
    '/usr/bin/ldd',
    '/etc/ld.so.cache',
    ...libraries.resolvedPaths,
  ];
  const absolute = collectAbsolutePathDescriptors(requestedPaths);
  const probe = runtimeProbe(candidate);
  return makeLayer(
    `runtime/${candidate.id}-candidate`,
    'unselected-node-runtime-candidate',
    absolute.entries,
    {
      candidateId: candidate.id,
      selection: null,
      commandPath: candidate.commandPath,
      executablePath: candidate.executablePath,
      executableSha256: candidate.executableSha256,
      dynamicLibraryInspector: '/usr/bin/ldd',
      dynamicLibraryInspectorClosure: 'opaque-not-recursively-closed',
      probe,
      dynamicLibraries: libraries,
      pathResolutions: absolute.resolutions,
    }
  );
}

function snapshotGitRuntime() {
  const executableDescriptor = filesystemDescriptor(
    GIT_EXECUTABLE,
    absoluteLogicalPath(GIT_EXECUTABLE)
  );
  assertion(
    executableDescriptor.kind === 'regular-file' &&
      executableDescriptor.sha256 === EXPECTED_GIT_SHA256,
    'git-executable-drift',
    `expected ${EXPECTED_GIT_SHA256}, observed ${String(executableDescriptor.sha256)}`
  );
  const libraries = lddReceipt(GIT_EXECUTABLE);
  const absolute = collectAbsolutePathDescriptors([
    GIT_EXECUTABLE,
    '/usr/bin/ldd',
    '/etc/ld.so.cache',
    ...libraries.resolvedPaths,
  ]);
  const version = gitRead(['--version'], { encoding: 'utf8' }).trim();
  return makeLayer('tool/git-runtime', 'read-only-git-runtime', absolute.entries, {
    executablePath: GIT_EXECUTABLE,
    executableSha256: EXPECTED_GIT_SHA256,
    dynamicLibraryInspector: '/usr/bin/ldd',
    dynamicLibraryInspectorClosure: 'opaque-not-recursively-closed',
    version,
    dynamicLibraries: libraries,
    pathResolutions: absolute.resolutions,
    childEnvironment: gitEnvironment(),
    invocationReceipt: gitInvocationReceipt([['--version']]),
  });
}

function snapshotGitRepositoryState() {
  const relativeCandidates = [
    '.git/HEAD',
    '.git/config',
    '.git/config.worktree',
    '.git/info/grafts',
    '.git/objects/info/alternates',
    '.git/packed-refs',
    '.git/shallow',
  ];
  const headBytes = readRepositoryFile('.git/HEAD').bytes.toString('utf8').trim();
  const symbolicHead = /^ref: (?<logicalPath>refs\/[A-Za-z0-9._/-]+)$/u.exec(headBytes);
  if (symbolicHead !== null) {
    const headRefPath = `.git/${symbolicHead.groups.logicalPath}`;
    assertion(
      headRefPath === path.posix.normalize(headRefPath) && !headRefPath.includes('..'),
      'git-head-ref-invalid',
      headRefPath
    );
    relativeCandidates.push(headRefPath);
  }
  const present = [];
  const absenceReceipts = [];
  for (const logicalPath of relativeCandidates) {
    try {
      lstatSync(path.join(REPOSITORY_ROOT, logicalPath));
      present.push(logicalPath);
    } catch (error) {
      assertion(error?.code === 'ENOENT', 'git-state-read-failed', logicalPath);
      absenceReceipts.push({ logicalPath, status: 'absent' });
    }
  }
  const replaceRefs = gitRead(
    ['for-each-ref', '--format=%(refname)%00%(objectname)', 'refs/replace'],
    { encoding: 'utf8' }
  );
  const allRefs = gitRead(['for-each-ref', '--format=%(refname)%00%(objectname)'], {
    encoding: 'utf8',
  });
  const layer = snapshotRepositoryPaths(
    'tool/git-repository-state',
    'git-object-resolution-state',
    present,
    {
      absent: absenceReceipts,
      replaceRefOutputSha256: sha256(Buffer.from(replaceRefs, 'utf8')),
      replaceRefCount: replaceRefs.trim() === '' ? 0 : replaceRefs.trim().split('\n').length,
      refOutputSha256: sha256(Buffer.from(allRefs, 'utf8')),
      refCount: allRefs.trim() === '' ? 0 : allRefs.trim().split('\n').length,
      head: {
        valueSha256: sha256(Buffer.from(headBytes, 'utf8')),
        symbolicRef: symbolicHead?.groups.logicalPath ?? null,
      },
      objectReads: 'main layer binds every consumed Git object by OID and SHA-256 bytes',
      invocationReceipt: gitInvocationReceipt([
        ['for-each-ref', '--format=%(refname)%00%(objectname)', 'refs/replace'],
        ['for-each-ref', '--format=%(refname)%00%(objectname)'],
      ]),
    }
  );
  return layer;
}

function snapshotEsbuildNative() {
  const descriptor = verifyAnchoredFile(
    ESBUILD_EXECUTABLE,
    EXPECTED_ESBUILD_SHA256,
    'esbuild Linux x64 native executable'
  );
  return makeLayer('native/esbuild-linux-x64@0.28.1', 'static-native-executable', [descriptor], {
    executablePath: ESBUILD_EXECUTABLE,
    selectionBasis: 'installed @esbuild/linux-x64 package for linux/x64',
    dynamicLibraryClassification: 'static-no-dynamic-section',
  });
}

function environmentReceipt() {
  const semanticVariables = [...SEMANTIC_ENVIRONMENT_KEYS].sort(compareUtf8Bytewise).map((name) => {
    const value = process.env[name];
    if (value === undefined) {
      return { name, present: false };
    }
    const bytes = Buffer.from(value, 'utf8');
    return {
      name,
      present: true,
      byteLength: bytes.length,
      valueSha256: sha256(bytes),
      value: ENVIRONMENT_VALUES_SAFE_TO_RECORD.has(name) ? value : null,
      valueDisclosure: ENVIRONMENT_VALUES_SAFE_TO_RECORD.has(name)
        ? 'recorded-non-secret'
        : 'hash-only',
    };
  });
  const environmentNames = Object.keys(process.env).sort(compareUtf8Bytewise);
  return {
    policy: 'semantic-allowlist-values-only-no-secret-capture',
    semanticVariables,
    inheritedNameCount: environmentNames.length,
    inheritedNameSetSha256: canonicalHashBytewise(environmentNames),
    unclassifiedNameCount: environmentNames.filter(
      (name) => !SEMANTIC_ENVIRONMENT_KEYS.includes(name)
    ).length,
    unclassifiedValues: 'not-recorded-potentially-secret',
    futureHermeticRequirement: 'env-i-with-explicit-reviewed-allowlist',
  };
}

function processReceipt() {
  const repositoryStats = statfsSync(REPOSITORY_ROOT);
  const temporaryStats = statfsSync(os.tmpdir());
  return {
    executablePath: process.execPath,
    executableRealPath: realpathSync(process.execPath),
    argv: [...process.argv],
    execArgv: [...process.execArgv],
    cwd: process.cwd(),
    cwdRealPath: realpathSync(process.cwd()),
    architecture: process.arch,
    platform: process.platform,
    nodeVersion: process.version,
    nodeVersions: process.versions,
    umask: process.umask().toString(8).padStart(4, '0'),
    locale: {
      collator: new Intl.Collator().resolvedOptions(),
      dateTime: new Intl.DateTimeFormat().resolvedOptions(),
    },
    filesystem: {
      repository: {
        type: String(repositoryStats.type),
        blockSize: repositoryStats.bsize,
      },
      temporaryDirectory: {
        path: os.tmpdir(),
        type: String(temporaryStats.type),
        blockSize: temporaryStats.bsize,
      },
    },
  };
}

function snapshotProcessLayers() {
  return [
    makeLayer('process/invocation', 'producer-process-observation', [], processReceipt()),
    makeLayer('process/environment', 'redacted-environment-observation', [], environmentReceipt()),
  ];
}

function snapshotCacheLayer() {
  const suffix =
    typeof process.geteuid === 'function' ? String(process.geteuid()) : os.userInfo().username;
  const cachePath = path.join(os.tmpdir(), `tsx-${suffix}`);
  let present = true;
  try {
    lstatSync(cachePath);
  } catch (error) {
    assertion(error?.code === 'ENOENT', 'cache-read-failed', cachePath);
    present = false;
  }
  if (!present) {
    return makeLayer('cache/tsx-global-current', 'mutable-global-cache-observation', [], {
      cachePath,
      present: false,
      historicalH053Attribution: 'irrecoverable',
      eligibility: 'not-successor-boundary-eligible',
    });
  }
  const entries = [];
  walkFilesystem(cachePath, 'cache-root', entries);
  return makeLayer('cache/tsx-global-current', 'mutable-global-cache-observation', entries, {
    cachePath,
    present: true,
    historicalH053Attribution: 'irrecoverable',
    eligibility: 'not-successor-boundary-eligible-without-private-pre-post-anchor',
    alternative: 'TSX_DISABLE_CACHE=1 remains an unselected successor constraint',
  });
}

function snapshotHostContext() {
  const existingPaths = [];
  const absent = [];
  for (const absolutePath of HOST_CONTEXT_PATHS) {
    try {
      lstatSync(absolutePath);
      existingPaths.push(absolutePath);
    } catch (error) {
      assertion(error?.code === 'ENOENT', 'host-context-read-failed', absolutePath);
      absent.push(absolutePath);
    }
  }
  const absolute = collectAbsolutePathDescriptors(existingPaths);
  return makeLayer(
    'host/context',
    'current-host-observation-not-universal-closure',
    absolute.entries,
    {
      absent,
      pathResolutions: absolute.resolutions,
      kernel: {
        type: os.type(),
        release: os.release(),
        version: os.version(),
        machine: os.machine(),
      },
      irrecoverableOrOpaque: [
        'H-053 historical inherited argv, environment, cwd, umask, and cache prestate',
        'kernel and vDSO executable semantics',
        'CPU instruction semantics and microcode',
        'filesystem race, case-folding, normalization, and mount semantics',
        'syscall/capability behavior because no H-053 trace or enforced allowlist exists',
      ],
    }
  );
}

function snapshotH054Apparatus() {
  return snapshotRepositoryPaths(
    'apparatus/h054-producer',
    'non-normative-experimental-apparatus',
    ['lab/h054'],
    {
      authority: 'none',
      action: null,
      executedHypotheses: [],
    }
  );
}

function layerReceipts(layers) {
  return layers
    .map(({ id, kind, entryCount, contentSha256 }) => ({
      id,
      kind,
      entryCount,
      contentSha256,
    }))
    .sort((left, right) => compareUtf8Bytewise(left.id, right.id));
}

function snapshotRootHash(anchors, layers) {
  return canonicalHashBytewise({
    schemaVersion: 'overlaykit-h054-layer-set/v1',
    anchors,
    runtimeSelection: null,
    layers: layerReceipts(layers),
  });
}

export function collectH054Snapshot() {
  const anchors = {
    mainCommit: EXPECTED_MAIN_COMMIT,
    mainTree: EXPECTED_MAIN_TREE,
    h053ClosureSha256: EXPECTED_H053_CLOSURE_SHA256,
    h053RunRawSha256: EXPECTED_H053_RUN_RAW_SHA256,
  };

  const errorsDescriptor = verifyAnchoredFile(
    'tools/governance/src/errors.ts',
    EXPECTED_ERRORS_SHA256,
    'errors.ts'
  );
  const packageLayers = snapshotPackageLayers();
  const packageRegularFileCount = packageLayers.reduce(
    (sum, layer) => sum + layer.metadata.regularFileCount,
    0
  );
  assertion(
    packageRegularFileCount === EXPECTED_PACKAGE_REGULAR_FILE_COUNT,
    'package-file-cardinality-drift',
    `expected ${EXPECTED_PACKAGE_REGULAR_FILE_COUNT} regular package files, observed ${packageRegularFileCount}`
  );
  const layers = [
    snapshotMainGitTree(),
    snapshotGuardedSurface(),
    ...snapshotH053Artifacts(),
    makeLayer('source/errors-ts', 'explicit-first-party-execution-dependency', [errorsDescriptor]),
    snapshotH053Apparatus(),
    snapshotH054Apparatus(),
    snapshotRepositoryPaths(
      'configuration/loader-and-package-resolution',
      'loader-resolution-configuration',
      LOADER_CONFIGURATION_PATHS,
      {
        reason:
          'tsx may consume tsconfig and package resolution inputs outside the H-053 guarded surface',
      }
    ),
    ...packageLayers,
    snapshotEsbuildNative(),
    ...NODE_CANDIDATES.map((candidate) => snapshotRuntimeCandidate(candidate)),
    snapshotGitRuntime(),
    snapshotGitRepositoryState(),
    ...snapshotProcessLayers(),
    snapshotCacheLayer(),
    snapshotHostContext(),
  ].sort((left, right) => compareUtf8Bytewise(left.id, right.id));

  const ids = layers.map(({ id }) => id);
  assertion(
    new Set(ids).size === ids.length,
    'layer-id-collision',
    'layer identifiers must be unique'
  );

  return {
    schemaVersion: 'overlaykit-h054-inventory-snapshot/v1',
    anchors,
    runtimeCandidates: NODE_CANDIDATES.map(({ id, version, executablePath }) => ({
      id,
      version,
      executablePath,
      selection: null,
    })),
    runtimeSelection: null,
    exactReceipts: {
      mainRecursiveEntryCount: EXPECTED_MAIN_RECURSIVE_ENTRY_COUNT,
      mainRecursiveLsTreeSha256: EXPECTED_MAIN_RECURSIVE_LS_TREE_SHA256,
      guardedRegularFileCount: EXPECTED_GUARDED_REGULAR_FILE_COUNT,
      h053GuardedSurfaceSha256: EXPECTED_H053_GUARDED_SURFACE_SHA256,
      h053ApparatusRegularFileCount: EXPECTED_H053_APPARATUS_REGULAR_FILE_COUNT,
      h053ApparatusSha256: EXPECTED_H053_APPARATUS_SHA256,
      packageRegularFileCount,
    },
    layers,
    layerReceipts: layerReceipts(layers),
    rootSha256: snapshotRootHash(anchors, layers),
  };
}

function alteredLayer(layer, transformEntries) {
  return makeLayer(layer.id, layer.kind, transformEntries(layer.entries), layer.metadata);
}

function replaceLayer(snapshot, replacement) {
  return snapshot.layers.map((layer) => (layer.id === replacement.id ? replacement : layer));
}

function rootWithLayers(snapshot, layers, anchors = snapshot.anchors) {
  return snapshotRootHash(anchors, layers);
}

function parsedRepositoryJson(logicalPath) {
  const { bytes, descriptor } = readRepositoryFile(logicalPath);
  try {
    return { value: JSON.parse(bytes.toString('utf8')), descriptor };
  } catch (error) {
    throw new InvalidH054InventoryError('json-source-invalid', `${logicalPath}: ${error.message}`);
  }
}

function verifyControlContract() {
  const subject = parsedRepositoryJson('lab/h054/subject-lock.json');
  const fixture = parsedRepositoryJson('lab/h054/fixtures/adversarial-boundary.synthetic.json');
  const expectedIds = CONTROL_REASON_CODES.map(([id]) => id);
  const subjectIds = subject.value.controlIds;
  const mutations = fixture.value.mutations;
  assertion(
    Array.isArray(subjectIds) &&
      Array.isArray(mutations) &&
      canonicalJsonBytewise(subjectIds) === canonicalJsonBytewise(expectedIds) &&
      canonicalJsonBytewise(mutations.map(({ id }) => id)) === canonicalJsonBytewise(expectedIds),
    'control-roster-drift',
    'subject-lock and fixture must retain the exact twelve control IDs'
  );
  const actualReasonCodes = mutations.map(({ id, expectedReasonCode }) => [id, expectedReasonCode]);
  assertion(
    canonicalJsonBytewise(actualReasonCodes) === canonicalJsonBytewise(CONTROL_REASON_CODES),
    'control-reason-code-drift',
    'fixture expectedReasonCode values differ'
  );
  return {
    receipt: {
      subjectLockRawSha256: subject.descriptor.sha256,
      fixtureRawSha256: fixture.descriptor.sha256,
      controlIds: expectedIds,
    },
    fixture: fixture.value,
  };
}

function requiredLayer(snapshot, id) {
  const layer = snapshot.layers.find((candidate) => candidate.id === id);
  assertion(layer !== undefined, 'control-precondition-failed', `missing layer ${id}`);
  return layer;
}

function omitMatchingEntries(layer, predicate, expectedMinimum = 1) {
  const omitted = layer.entries.filter(predicate);
  assertion(
    omitted.length >= expectedMinimum,
    'control-precondition-failed',
    `${layer.id} lacks the nominated control target`
  );
  return {
    omitted,
    layer: alteredLayer(layer, (entries) => entries.filter((entry) => !predicate(entry))),
  };
}

function changedLayerReceipts(pre, post) {
  const changedLayers = [];
  const preById = new Map(pre.layerReceipts.map((receipt) => [receipt.id, receipt]));
  const postById = new Map(post.layerReceipts.map((receipt) => [receipt.id, receipt]));
  for (const id of [...new Set([...preById.keys(), ...postById.keys()])].sort(
    compareUtf8Bytewise
  )) {
    const before = preById.get(id) ?? null;
    const after = postById.get(id) ?? null;
    if (
      before === null ||
      after === null ||
      before.contentSha256 !== after.contentSha256 ||
      before.entryCount !== after.entryCount
    ) {
      changedLayers.push({ id, before, after });
    }
  }
  return changedLayers;
}

function controlResult(id, passed, { variantReasonCodes = [] } = {}) {
  const expectedReasonCode = new Map(CONTROL_REASON_CODES).get(id);
  assertion(expectedReasonCode !== undefined, 'control-id-invalid', id);
  return {
    id,
    passed,
    expectedReasonCode,
    observedReasonCode: passed ? expectedReasonCode : 'control-not-detected',
    variantReasonCodes,
  };
}

function classifySyntheticSymlinkTarget(entry, replacement) {
  const parent = path.posix.dirname(entry.logicalPath);
  const resolved = path.posix.normalize(path.posix.join(parent, replacement));
  if (resolved === entry.logicalPath) {
    return 'symlink-cycle';
  }
  if (resolved === '..' || resolved.startsWith('../') || !resolved.startsWith('host/')) {
    return 'symlink-boundary-escape';
  }
  return 'symlink-target-admitted';
}

function controlReceipts(pre) {
  const errorsLayer = requiredLayer(pre, 'source/errors-ts');
  const ajvLayer = requiredLayer(pre, 'package/ajv@8.20.0');
  const nativeLayer = requiredLayer(pre, 'native/esbuild-linux-x64@0.28.1');
  const node22Layer = requiredLayer(pre, 'runtime/node22-candidate');
  const gitLayer = requiredLayer(pre, 'tool/git-runtime');
  const environmentLayer = requiredLayer(pre, 'process/environment');
  const cacheLayer = requiredLayer(pre, 'cache/tsx-global-current');
  const apparatusLayer = requiredLayer(pre, 'apparatus/h054-producer');

  const errorsOmission = omitMatchingEntries(
    errorsLayer,
    ({ logicalPath }) => logicalPath === 'tools/governance/src/errors.ts'
  );
  const ajvOmission = omitMatchingEntries(
    ajvLayer,
    ({ logicalPath }) => logicalPath === 'node_modules/ajv/dist/core.js'
  );
  const esbuildOmission = omitMatchingEntries(
    nativeLayer,
    ({ logicalPath }) => logicalPath === 'node_modules/@esbuild/linux-x64/bin/esbuild'
  );
  const nodeExecutableOmission = omitMatchingEntries(
    node22Layer,
    ({ logicalPath }) => logicalPath === 'host/usr/bin/node-22'
  );
  const libnodeOmission = omitMatchingEntries(node22Layer, ({ logicalPath }) =>
    logicalPath.endsWith('/libnode.so.127')
  );
  const gitExecutableOmission = omitMatchingEntries(
    gitLayer,
    ({ logicalPath }) => logicalPath === 'host/usr/bin/git'
  );
  const gitLibraryOmission = omitMatchingEntries(
    gitLayer,
    ({ logicalPath }) => logicalPath.includes('/libpcre2-8.so') || logicalPath.includes('/libz.so')
  );

  const environmentMetadata = structuredClone(environmentLayer.metadata);
  const selectorBefore = environmentMetadata.semanticVariables.length;
  environmentMetadata.semanticVariables = environmentMetadata.semanticVariables.filter(
    ({ name }) => name !== 'TSX_DISABLE_CACHE'
  );
  assertion(
    environmentMetadata.semanticVariables.length === selectorBefore - 1,
    'control-precondition-failed',
    'TSX_DISABLE_CACHE selector receipt is absent'
  );
  const environmentOmission = makeLayer(
    environmentLayer.id,
    environmentLayer.kind,
    environmentLayer.entries,
    environmentMetadata
  );
  const envCacheLayers = replaceLayer(pre, environmentOmission).filter(
    ({ id }) => id !== cacheLayer.id
  );

  const staleMainRoot = rootWithLayers(pre, pre.layers, {
    ...pre.anchors,
    mainTree: 'f'.repeat(40),
  });
  const staleClosureRoot = rootWithLayers(pre, pre.layers, {
    ...pre.anchors,
    h053ClosureSha256: 'e'.repeat(64),
  });

  const apparatusEntry = apparatusLayer.entries.find(
    ({ kind, logicalPath }) =>
      kind === 'regular-file' && logicalPath === 'lab/h054/inventory-lib.mjs'
  );
  assertion(
    apparatusEntry !== undefined,
    'control-precondition-failed',
    'H-054 inventory apparatus entry is absent'
  );
  const staleApparatus = alteredLayer(apparatusLayer, (entries) =>
    entries.map((entry) =>
      entry.logicalPath === apparatusEntry.logicalPath
        ? { ...entry, sha256: 'd'.repeat(64) }
        : entry
    )
  );

  const nodeSymlink = node22Layer.entries.find(
    ({ kind, logicalPath }) => kind === 'symbolic-link' && logicalPath === 'host/usr/bin/node'
  );
  assertion(
    nodeSymlink !== undefined,
    'control-precondition-failed',
    'Node 22 command symlink is absent'
  );
  const retargetedNode = alteredLayer(node22Layer, (entries) =>
    entries.map((entry) =>
      entry.logicalPath === nodeSymlink.logicalPath
        ? {
            ...entry,
            linkTarget: 'node-24',
            linkTargetByteLength: 7,
            linkTargetSha256: sha256(Buffer.from('node-24', 'utf8')),
          }
        : entry
    )
  );
  const cycleReason = classifySyntheticSymlinkTarget(nodeSymlink, 'node');
  const escapeReason = classifySyntheticSymlinkTarget(nodeSymlink, '../../../../outside');

  const compositeKeys = pre.layers.flatMap((layer) =>
    layer.entries.map((entry) => `${layer.id}\0${entry.logicalPath}`)
  );
  const flattenedPaths = pre.layers.flatMap((layer) =>
    layer.entries.map((entry) => entry.logicalPath)
  );
  const flattenedUniqueCount = new Set(flattenedPaths).size;
  const duplicateFlattenedPaths = [...new Set(flattenedPaths)]
    .filter(
      (logicalPath) => flattenedPaths.filter((candidate) => candidate === logicalPath).length > 1
    )
    .sort(compareUtf8Bytewise);

  return [
    controlResult(
      'omit-errors-ts',
      rootWithLayers(pre, replaceLayer(pre, errorsOmission.layer)) !== pre.rootSha256,
      { omittedCompositeKeys: errorsOmission.omitted.map(({ logicalPath }) => logicalPath) }
    ),
    controlResult(
      'omit-ajv-transitive',
      rootWithLayers(pre, replaceLayer(pre, ajvOmission.layer)) !== pre.rootSha256,
      { omittedCompositeKeys: ajvOmission.omitted.map(({ logicalPath }) => logicalPath) }
    ),
    controlResult(
      'omit-esbuild-native',
      rootWithLayers(pre, replaceLayer(pre, esbuildOmission.layer)) !== pre.rootSha256,
      { omittedCompositeKeys: esbuildOmission.omitted.map(({ logicalPath }) => logicalPath) }
    ),
    controlResult(
      'omit-node-final-or-libnode',
      rootWithLayers(pre, replaceLayer(pre, nodeExecutableOmission.layer)) !== pre.rootSha256 &&
        rootWithLayers(pre, replaceLayer(pre, libnodeOmission.layer)) !== pre.rootSha256,
      {
        variantReasonCodes: ['runtime-dependency-omitted', 'runtime-dependency-omitted'],
      }
    ),
    controlResult(
      'omit-git-or-library',
      rootWithLayers(pre, replaceLayer(pre, gitExecutableOmission.layer)) !== pre.rootSha256 &&
        rootWithLayers(pre, replaceLayer(pre, gitLibraryOmission.layer)) !== pre.rootSha256,
      {
        variantReasonCodes: ['git-runtime-dependency-omitted', 'git-runtime-dependency-omitted'],
      }
    ),
    controlResult(
      'omit-env-cache-selector',
      rootWithLayers(pre, envCacheLayers) !== pre.rootSha256,
      { omittedSelector: 'TSX_DISABLE_CACHE', omittedLayer: cacheLayer.id }
    ),
    controlResult('stale-main-anchor', staleMainRoot !== pre.rootSha256, {
      alteredRootSha256: staleMainRoot,
    }),
    controlResult('stale-h053-closure', staleClosureRoot !== pre.rootSha256, {
      alteredRootSha256: staleClosureRoot,
    }),
    controlResult(
      'stale-apparatus',
      rootWithLayers(pre, replaceLayer(pre, staleApparatus)) !== pre.rootSha256,
      { alteredLogicalPath: apparatusEntry.logicalPath }
    ),
    controlResult(
      'symlink-retarget',
      rootWithLayers(pre, replaceLayer(pre, retargetedNode)) !== pre.rootSha256,
      { alteredLogicalPath: nodeSymlink.logicalPath, replacementLinkTarget: 'node-24' }
    ),
    controlResult(
      'symlink-cycle-escape',
      cycleReason === 'symlink-cycle' && escapeReason === 'symlink-boundary-escape',
      {
        variantReasonCodes: [cycleReason, escapeReason],
      }
    ),
    controlResult(
      'flatten-layer-collision',
      new Set(compositeKeys).size === compositeKeys.length &&
        flattenedUniqueCount < flattenedPaths.length &&
        duplicateFlattenedPaths.length > 0,
      {
        compositeKeyCount: compositeKeys.length,
        flattenedPathCount: flattenedPaths.length,
        flattenedUniqueCount,
        duplicateFlattenedPathCount: duplicateFlattenedPaths.length,
        duplicateFlattenedPathSetSha256: canonicalHashBytewise(duplicateFlattenedPaths),
      }
    ),
  ];
}

function fixtureCompositeKey({ layerId, logicalPath }) {
  return `${layerId}\0${logicalPath}`;
}

function fixtureTargetEntry(entries, target) {
  return entries.filter(
    ({ layerId, logicalPath }) => layerId === target.layerId && logicalPath === target.logicalPath
  );
}

function classifyFixtureSymlink(entry, linkText) {
  const parent = path.posix.dirname(entry.logicalPath);
  const resolved = path.posix.normalize(path.posix.join(parent, linkText));
  if (resolved === entry.logicalPath) {
    return 'symlink-cycle';
  }
  if (resolved === '..' || resolved.startsWith('../')) {
    return 'symlink-boundary-escape';
  }
  return 'symlink-target-admitted';
}

function validateFixtureBaseGraph(fixture) {
  const graph = fixture.baseGraph;
  assertion(
    graph !== null &&
      typeof graph === 'object' &&
      Array.isArray(graph.layers) &&
      Array.isArray(graph.entries) &&
      Array.isArray(graph.edges),
    'control-fixture-invalid',
    'synthetic base graph is malformed'
  );
  const compositeKeys = graph.entries.map(fixtureCompositeKey);
  assertion(
    new Set(compositeKeys).size === compositeKeys.length &&
      graph.entries.every(({ layerId }) => graph.layers.includes(layerId)),
    'control-fixture-invalid',
    'synthetic base graph has a composite-key collision or undeclared layer'
  );
  for (const entry of graph.entries) {
    if (typeof entry.contentUtf8 === 'string') {
      assertion(
        sha256(Buffer.from(entry.contentUtf8, 'utf8')) === entry.sha256,
        'control-fixture-invalid',
        `synthetic bytes do not match ${fixtureCompositeKey(entry)}`
      );
    }
    if (typeof entry.linkText === 'string' && entry.linkTextSha256 !== undefined) {
      assertion(
        sha256(Buffer.from(entry.linkText, 'utf8')) === entry.linkTextSha256,
        'control-fixture-invalid',
        `synthetic link text does not match ${fixtureCompositeKey(entry)}`
      );
    }
  }
  return graph;
}

function fixtureControlReceipts(pre, fixture) {
  const graph = validateFixtureBaseGraph(fixture);
  const cacheLayer = requiredLayer(pre, 'cache/tsx-global-current');
  return fixture.mutations.map((mutation) => {
    let passed = false;
    let details = {};

    if (mutation.kind === 'omit-entry') {
      const matches = fixtureTargetEntry(graph.entries, mutation.target);
      const altered = graph.entries.filter(
        (entry) => fixtureCompositeKey(entry) !== fixtureCompositeKey(mutation.target)
      );
      passed = matches.length === 1 && fixtureTargetEntry(altered, mutation.target).length === 0;
      if (mutation.id === 'omit-env-cache-selector') {
        passed = passed && cacheLayer.metadata.historicalH053Attribution === 'irrecoverable';
      }
      details = {
        target: mutation.target,
        originalCardinality: matches.length,
        alteredCardinality: fixtureTargetEntry(altered, mutation.target).length,
        cacheClassification:
          mutation.id === 'omit-env-cache-selector'
            ? cacheLayer.metadata.historicalH053Attribution
            : null,
      };
    } else if (mutation.kind === 'omit-entry-variants') {
      const variants = mutation.targets.map((target) => {
        const matches = fixtureTargetEntry(graph.entries, target);
        const altered = graph.entries.filter(
          (entry) => fixtureCompositeKey(entry) !== fixtureCompositeKey(target)
        );
        return {
          target,
          originalCardinality: matches.length,
          alteredCardinality: fixtureTargetEntry(altered, target).length,
          detected: matches.length === 1 && fixtureTargetEntry(altered, target).length === 0,
        };
      });
      passed = variants.length > 0 && variants.every(({ detected }) => detected);
      details = { variants };
    } else if (mutation.kind === 'replace-anchor-digest') {
      const baseline =
        mutation.target === 'main.tree'
          ? pre.anchors.mainTree
          : mutation.target === 'h053PostReviewClosure.rawSha256'
            ? pre.anchors.h053ClosureSha256
            : null;
      const expectedDigestLength = mutation.target === 'main.tree' ? 40 : 64;
      passed =
        typeof baseline === 'string' &&
        mutation.replacement !== baseline &&
        new RegExp(`^[0-9a-f]{${expectedDigestLength}}$`, 'u').test(mutation.replacement);
      details = {
        target: mutation.target,
        baseline,
        replacement: mutation.replacement,
      };
    } else if (mutation.kind === 'replace-entry-content-and-rehash-envelope') {
      const matches = fixtureTargetEntry(graph.entries, mutation.target);
      const replacementSha256 = sha256(Buffer.from(mutation.replacementContentUtf8, 'utf8'));
      passed =
        matches.length === 1 &&
        replacementSha256 !== matches[0].sha256 &&
        replacementSha256 === sha256(Buffer.from(mutation.replacementContentUtf8, 'utf8'));
      details = {
        target: mutation.target,
        baselineSha256: matches[0]?.sha256 ?? null,
        replacementSha256,
        envelopeRehashed: true,
      };
    } else if (mutation.kind === 'replace-symlink-target') {
      const matches = fixtureTargetEntry(graph.entries, mutation.target);
      passed =
        matches.length === 1 &&
        matches[0].kind === 'symbolic-link' &&
        (matches[0].linkText !== mutation.replacementLinkText ||
          matches[0].targetLayerId !== mutation.replacementTarget.layerId ||
          matches[0].targetLogicalPath !== mutation.replacementTarget.logicalPath);
      details = {
        target: mutation.target,
        baselineLinkText: matches[0]?.linkText ?? null,
        replacementLinkText: mutation.replacementLinkText,
        replacementTarget: mutation.replacementTarget,
      };
    } else if (mutation.kind === 'symlink-invalid-variants') {
      const matches = fixtureTargetEntry(graph.entries, mutation.target);
      const variants =
        matches.length === 1
          ? mutation.variants.map(({ linkText, expectedReasonCode }) => {
              const observedReasonCode = classifyFixtureSymlink(matches[0], linkText);
              return {
                linkText,
                expectedReasonCode,
                observedReasonCode,
                detected: observedReasonCode === expectedReasonCode,
              };
            })
          : [];
      passed = variants.length === 2 && variants.every(({ detected }) => detected);
      details = { target: mutation.target, variants };
    } else if (mutation.kind === 'deduplicate-by-logical-path') {
      const matches = graph.entries.filter(
        ({ logicalPath }) => logicalPath === mutation.targetLogicalPath
      );
      const flattened = new Map(matches.map((entry) => [entry.logicalPath, entry]));
      passed =
        matches.length === mutation.expectedOriginalCardinality &&
        flattened.size === mutation.expectedFlattenedCardinality &&
        new Set(matches.map(({ layerId }) => layerId)).size === matches.length;
      details = {
        targetLogicalPath: mutation.targetLogicalPath,
        originalCardinality: matches.length,
        flattenedCardinality: flattened.size,
        originalLayerIds: matches.map(({ layerId }) => layerId).sort(compareUtf8Bytewise),
      };
    }

    const variantReasonCodes =
      mutation.kind === 'omit-entry-variants'
        ? mutation.targets.map(() => mutation.expectedReasonCode)
        : mutation.kind === 'symlink-invalid-variants'
          ? details.variants.map(({ observedReasonCode }) => observedReasonCode)
          : [];
    return controlResult(mutation.id, passed, { variantReasonCodes });
  });
}

function semanticBody(run) {
  const { runId: _runId, semanticSha256: _semanticSha256, ...body } = run;
  return body;
}

function strictBlockingClassifications(snapshot) {
  const environmentLayer = requiredLayer(snapshot, 'process/environment');
  const cacheLayer = requiredLayer(snapshot, 'cache/tsx-global-current');
  const hostLayer = requiredLayer(snapshot, 'host/context');
  const opaqueEntries = snapshot.layers.flatMap((layer) =>
    layer.entries
      .filter(
        ({ classification }) =>
          typeof classification === 'string' &&
          (classification.includes('opaque') ||
            classification.includes('irrecoverable') ||
            classification.includes('unclassified'))
      )
      .map(({ logicalPath, classification }) => ({
        layerId: layer.id,
        logicalPath,
        classification,
      }))
  );
  const dynamicLibraryOpenLayers = snapshot.layers
    .filter(
      ({ metadata }) =>
        metadata?.dynamicLibraries?.status !== undefined &&
        (metadata.dynamicLibraries.status !== 'resolved-with-virtual-context' ||
          metadata.dynamicLibraries.unresolvedLibraries?.length > 0 ||
          metadata.dynamicLibraries.unparsedLines?.length > 0 ||
          metadata.dynamicLibraryInspectorClosure === 'opaque-not-recursively-closed')
    )
    .map(({ id }) => id)
    .sort(compareUtf8Bytewise);
  const packageEntryPointOpenLayers = snapshot.layers
    .filter(
      ({ metadata }) =>
        metadata?.packageEntryPointResolution?.classification ===
        'whole-tree-inventoried-per-import-and-export-condition-resolution-not-enumerated'
    )
    .map(({ id }) => id)
    .sort(compareUtf8Bytewise);
  const blocking = [
    {
      id: 'runtime-selection-null',
      classification: 'unresolved-human-selection',
      count: snapshot.runtimeSelection === null ? 1 : 0,
    },
    {
      id: 'historical-h053-cache-attribution',
      classification: cacheLayer.metadata.historicalH053Attribution,
      count: cacheLayer.metadata.historicalH053Attribution === 'irrecoverable' ? 1 : 0,
    },
    {
      id: 'unclassified-environment-values',
      classification: environmentLayer.metadata.unclassifiedValues,
      count: environmentLayer.metadata.unclassifiedNameCount,
    },
    {
      id: 'opaque-host-execution-context',
      classification: 'irrecoverable-or-opaque',
      count: hostLayer.metadata.irrecoverableOrOpaque.length,
    },
    {
      id: 'opaque-entry-classifications',
      classification: 'opaque-entry',
      count: opaqueEntries.length,
      entrySetSha256: canonicalHashBytewise(opaqueEntries),
    },
    {
      id: 'dynamic-library-inspector-closure',
      classification: 'opaque-not-recursively-closed',
      count: dynamicLibraryOpenLayers.length,
      layerSetSha256: canonicalHashBytewise(dynamicLibraryOpenLayers),
    },
    {
      id: 'package-entry-point-resolution-method',
      classification: 'methodologically-incomplete',
      count: packageEntryPointOpenLayers.length,
      layerSetSha256: canonicalHashBytewise(packageEntryPointOpenLayers),
    },
  ].filter(({ count }) => count > 0);
  assertion(
    blocking.some(({ id }) => id === 'runtime-selection-null'),
    'outcome-policy-drift',
    'H-054 must retain null runtime selection'
  );
  return blocking;
}

export function buildH054Evidence() {
  const { receipt: controlContract, fixture } = verifyControlContract();
  const pre = collectH054Snapshot();
  const post = collectH054Snapshot();
  const liveControls = controlReceipts(pre);
  const fixtureControls = fixtureControlReceipts(pre, fixture);
  assertion(
    canonicalJsonBytewise(liveControls) === canonicalJsonBytewise(fixtureControls),
    'control-real-fixture-divergence',
    'real-layer and synthetic-fixture controls must produce identical receipts'
  );
  const controls = liveControls;
  assertion(
    canonicalJsonBytewise(controls.map(({ id }) => id)) ===
      canonicalJsonBytewise(controlContract.controlIds),
    'control-roster-drift',
    'producer control receipts differ from subject-lock order'
  );
  const failedControls = controls.filter(({ passed }) => passed !== true);
  const stable = pre.rootSha256 === post.rootSha256;
  const changedLayers = changedLayerReceipts(pre, post);
  const blockingClassifications = strictBlockingClassifications(pre);
  const status = 'inconclusive';
  const reason = 'runtime-selection-null-or-boundary-input-unclosed';

  const body = {
    schemaVersion: 'overlaykit-h054-executable-boundary-inventory-run/v1',
    hypothesis: 'H-054',
    normative: false,
    authority: 'none',
    action: null,
    anchors: pre.anchors,
    runtimeSelection: null,
    controlContract,
    inventory: {
      classification: 'current-host-layer-qualified-inventory-only',
      pre,
      post: {
        schemaVersion: post.schemaVersion,
        anchors: post.anchors,
        runtimeCandidates: post.runtimeCandidates,
        runtimeSelection: null,
        exactReceipts: post.exactReceipts,
        layerReceipts: post.layerReceipts,
        rootSha256: post.rootSha256,
      },
      stability: {
        stable: stable && changedLayers.length === 0,
        preRootSha256: pre.rootSha256,
        postRootSha256: post.rootSha256,
        changedLayers,
      },
      historicalReconstruction: {
        h053Closed: false,
        classification: 'irrecoverable',
        missing: [
          'exact inherited H-053 argv and execArgv',
          'exact inherited H-053 environment',
          'exact H-053 cwd and umask',
          'exact pre-run global tsx cache state and cache attribution',
          'syscall trace or enforced capability allowlist',
        ],
      },
      successorEligibility: {
        h055Ready: false,
        reason: 'human runtime selection and separate governed experiment remain required',
      },
    },
    controls,
    experiment: {
      outcome: {
        status,
        reason,
        reasonCode: reason,
        blockingClassifications,
        failedControlIds: failedControls.map(({ id }) => id),
        claimBoundary:
          'offline/read-only inventory stability and explicit classification on this host only',
        authority: 'none',
        action: null,
      },
    },
    capabilityAudit: {
      classification: 'static-producer-contract-plus-content-delta-observation',
      closed: false,
      observed: {
        h053Executed: false,
        h055Executed: false,
        networkActivityRequested: false,
        liveObservationRequested: false,
        usbOrHidrawActivityRequested: false,
        dockerActivityRequested: false,
        signalsOrServicesActivityRequested: false,
        productOrGovernanceMutationRequested: false,
        gitIndexOrHistoryMutationRequested: false,
        rawEvidenceWriteOptionalAndLocal: true,
      },
      unknowns: [
        'No syscall trace or sandbox-enforced capability allowlist closes producer behavior.',
        'Kernel, vDSO, CPU, and filesystem semantics remain contextual observations.',
      ],
    },
    interpretation: {
      humanReview: { required: true, accepted: null },
      runtimeDecision: {
        required: true,
        selected: null,
        candidates: ['node22', 'node24'],
      },
      adrAssessment: {
        candidateNominated: false,
        candidateActivated: false,
        candidateRecordCreated: false,
      },
      doesNotDemonstrate: [
        'historical H-053 execution closure',
        'equivalence of Node 22 and Node 24',
        'selection of a successor runtime',
        'H-053 or H-055 support or refutation',
        'production policy, implementation authority, or live host behavior',
      ],
    },
  };

  const semanticSha256 = canonicalHashBytewise(body);
  return {
    runId: `h054-${semanticSha256.slice(0, 24)}`,
    semanticSha256,
    ...body,
  };
}

export function validateH054RunIdentity(run) {
  assertion(
    run !== null && typeof run === 'object' && !Array.isArray(run),
    'run-invalid',
    'run must be an object'
  );
  assertion(
    run.schemaVersion === 'overlaykit-h054-executable-boundary-inventory-run/v1' &&
      run.hypothesis === 'H-054' &&
      run.normative === false &&
      run.authority === 'none' &&
      run.action === null,
    'run-invalid',
    'run envelope creates authority or has the wrong identity'
  );
  assertion(
    run.runtimeSelection === null &&
      run.inventory?.pre?.runtimeSelection === null &&
      run.inventory?.post?.runtimeSelection === null &&
      run.interpretation?.runtimeDecision?.selected === null,
    'runtime-selection-not-null',
    'H-054 must not select a runtime'
  );
  assertion(
    run.experiment?.outcome?.status === 'inconclusive' &&
      run.experiment.outcome.reason === 'runtime-selection-null-or-boundary-input-unclosed' &&
      run.experiment.outcome.reasonCode === run.experiment.outcome.reason &&
      Array.isArray(run.experiment.outcome.blockingClassifications) &&
      run.experiment.outcome.blockingClassifications.length > 0,
    'outcome-policy-drift',
    'null, opaque, irrecoverable, or unclassified inputs must remain inconclusive'
  );
  assertion(
    Array.isArray(run.controls) &&
      canonicalJsonBytewise(run.controls.map(({ id }) => id)) ===
        canonicalJsonBytewise(CONTROL_REASON_CODES.map(([id]) => id)) &&
      run.controls.every(
        ({ id, expectedReasonCode }) => new Map(CONTROL_REASON_CODES).get(id) === expectedReasonCode
      ),
    'control-roster-drift',
    'run must contain exactly the twelve nominated controls and reason codes'
  );
  assertion(
    run.capabilityAudit?.observed?.h053Executed === false &&
      run.capabilityAudit?.observed?.h055Executed === false,
    'hypothesis-execution-overclaim',
    'H-054 records execution of H-053 or H-055'
  );
  const recomputed = canonicalHashBytewise(semanticBody(run));
  assertion(
    run.semanticSha256 === recomputed && run.runId === `h054-${recomputed.slice(0, 24)}`,
    'run-identity-invalid',
    'run identity does not match canonical semantic content'
  );
  return recomputed;
}

export function encodeH054Evidence(run) {
  validateH054RunIdentity(run);
  return Buffer.from(canonicalPrettyJsonBytewise(run), 'utf8');
}
