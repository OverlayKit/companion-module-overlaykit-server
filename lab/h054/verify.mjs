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
import { fileURLToPath, pathToFileURL } from 'node:url';

const LAB_DIRECTORY = realpathSync(path.dirname(fileURLToPath(import.meta.url)));
const REPOSITORY_ROOT = realpathSync(path.resolve(LAB_DIRECTORY, '../..'));

const EXPECTED = Object.freeze({
  mainCommit: '161554b968b6dc38fb1cc055c829b414ba5b85ae',
  mainTree: 'd8087b92796a8be07ee5779a5847e0e3859930a0',
  mainEntryCount: 319,
  mainLsTreeSha256: '9c5dc303da5ed8da64ee59c78e5cd5a3efaab617e93ab502925a884364d9cde1',
  guardedRegularFileCount: 40,
  guardedLsTreeSha256: '4c06c282e4c5e063bb5dfdeee9a1f28512fbba7b2c524552ae7a174423554f0d',
  h053ClosureSha256: 'e84b9faeb4858549eec513c3a08f19da566987665f4c79a448102dbc957b4911',
  h053RunRawSha256: '5a55fc6ec2dff653858d4c8a70a22d3085400b423b8c93e265f14774078bf14f',
  h053ApparatusRegularFileCount: 10,
  h053ApparatusDescriptorSetSha256:
    '1c686c08b995890b39ab750e0fc593766d5916fed2dfc5e6f657ea51f6b40126',
  errorsSha256: '23f0c8e843f655a61dae807709c75670a42ef4b851beb0d8cacd584d0e0578b4',
  subjectLockSha256: 'a8c49c8937b978d2b4edddf05f2ae6f8cc1467e0edac36eea8d53d27114643eb',
  fixtureSha256: '01e9c68f28e2da048c8c3f90592ad81521e6c557f36f27a6e6a4f2d7180121a4',
  gitSha256: '8d8d470218586c27909c9b6ae77d18df32a9e05e725044ae2052d60254791c26',
  esbuildSha256: '0c6588b092a2c291a72bab90659f3c9e0e25e0fe59c9ac12b4dae4d945e5548c',
});

const SUBJECT_LOCK_PATH = 'lab/h054/subject-lock.json';
const FIXTURE_PATH = 'lab/h054/fixtures/adversarial-boundary.synthetic.json';
const H053_CLOSURE_DIRECTORY =
  'artifacts/h053/post-review-closures/5a55fc6ec2dff653858d4c8a70a22d3085400b423b8c93e265f14774078bf14f';
const H053_RUN_DIRECTORY =
  'artifacts/h053/runs/0e979b5191acbf68a865d6f9c651d8683e93fbcc26cfd44bbf06ad363a3b29d4';
const GIT_EXECUTABLE = '/usr/bin/git';
const PRODUCER_PATH = path.join(REPOSITORY_ROOT, 'lab', 'h054', 'run.mjs');
const ESBUILD_EXECUTABLE = 'node_modules/@esbuild/linux-x64/bin/esbuild';

const PACKAGE_SEEDS = Object.freeze(['ajv', 'tsx']);

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

const EXPECTED_LAYER_IDS = Object.freeze(
  [
    'apparatus/h053',
    'apparatus/h054-producer',
    'cache/tsx-global-current',
    'configuration/loader-and-package-resolution',
    'evidence/h053-canonical-run',
    'evidence/h053-post-review-closure',
    'host/context',
    'native/esbuild-linux-x64@0.28.1',
    'package/@esbuild/linux-x64@0.28.1',
    'package/ajv@8.20.0',
    'package/esbuild@0.28.1',
    'package/fast-deep-equal@3.1.3',
    'package/fast-uri@3.1.4',
    'package/json-schema-traverse@1.0.0',
    'package/require-from-string@2.0.2',
    'package/tsx@4.23.1',
    'process/environment',
    'process/invocation',
    'runtime/node22-candidate',
    'runtime/node24-candidate',
    'source/errors-ts',
    'source/guarded-worktree',
    'source/main-git-tree',
    'tool/git-repository-state',
    'tool/git-runtime',
  ].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
);

const EXPECTED_PACKAGE_REGULAR_FILES = Object.freeze({
  'package/@esbuild/linux-x64@0.28.1': 3,
  'package/ajv@8.20.0': 466,
  'package/esbuild@0.28.1': 7,
  'package/fast-deep-equal@3.1.3': 11,
  'package/fast-uri@3.1.4': 34,
  'package/json-schema-traverse@1.0.0': 12,
  'package/require-from-string@2.0.2': 4,
  'package/tsx@4.23.1': 50,
});

const EXPECTED_PACKAGE_REGULAR_FILE_COUNT = Object.values(EXPECTED_PACKAGE_REGULAR_FILES).reduce(
  (sum, count) => sum + count,
  0
);

const EXPECTED_RUNTIME_CANDIDATES = Object.freeze([
  Object.freeze({
    id: 'node22',
    version: 'v22.22.2',
    commandPath: '/usr/bin/node',
    executablePath: '/usr/bin/node-22',
    executableSha256: '1a1ebcd93dc90cf3e3dc37493e8efc04a1f60bddada1402453094214af03e33d',
    layerId: 'runtime/node22-candidate',
  }),
  Object.freeze({
    id: 'node24',
    version: 'v24.16.0',
    commandPath: '/home/rod/.local/share/nodejs/node-v24.16.0-linux-x64/bin/node',
    executablePath: '/home/rod/.local/share/nodejs/node-v24.16.0-linux-x64/bin/node',
    executableSha256: 'b2959781cc5a74c357ffa02367efa8a0330cbb1c9cb347732fdfaaaca381cbcd',
    layerId: 'runtime/node24-candidate',
  }),
]);

const CONTROL_IDS = Object.freeze([
  'omit-errors-ts',
  'omit-ajv-transitive',
  'omit-esbuild-native',
  'omit-node-final-or-libnode',
  'omit-git-or-library',
  'omit-env-cache-selector',
  'stale-main-anchor',
  'stale-h053-closure',
  'stale-apparatus',
  'symlink-retarget',
  'symlink-cycle-escape',
  'flatten-layer-collision',
]);

const RUN_TOP_LEVEL_KEYS = Object.freeze([
  'action',
  'anchors',
  'authority',
  'capabilityAudit',
  'controlContract',
  'controls',
  'experiment',
  'hypothesis',
  'interpretation',
  'inventory',
  'normative',
  'runId',
  'runtimeSelection',
  'schemaVersion',
  'semanticSha256',
]);

export class InvalidH054VerificationError extends Error {
  constructor(reasonCode, message) {
    super(message);
    this.name = 'InvalidH054VerificationError';
    this.reasonCode = reasonCode;
  }
}

function assertion(condition, reasonCode, message) {
  if (!condition) {
    throw new InvalidH054VerificationError(reasonCode, message);
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
    left.every((value, index) => value === right[index])
  );
}

function exactKeys(value, expected, label) {
  assertion(isPlainObject(value), 'shape-invalid', `${label} must be an object`);
  const actualKeys = Object.keys(value).sort(compareUtf8);
  const expectedKeys = [...expected].sort(compareUtf8);
  assertion(
    sameArray(actualKeys, expectedKeys),
    'shape-invalid',
    `${label} keys differ: ${actualKeys.join(',')}`
  );
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
      (typeof value === 'number' && Number.isFinite(value)),
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

export function sha256Independent(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function canonicalHashIndependent(value) {
  return sha256Independent(Buffer.from(canonicalJsonIndependent(value), 'utf8'));
}

function parseJsonBytes(bytes, label) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (error) {
    throw new InvalidH054VerificationError(
      'utf8-invalid',
      `${label} is not UTF-8: ${error.message}`
    );
  }
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new InvalidH054VerificationError(
      'json-invalid',
      `${label} is not JSON: ${error.message}`
    );
  }
}

function octalMode(metadata) {
  return (metadata.mode & 0o7777).toString(8).padStart(4, '0');
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
    'file-type-drift',
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
      'file-race-detected',
      `${label} changed before read`
    );
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    const pathnameAfter = lstatSync(absolutePath);
    assertion(
      stableMetadata(before, after) &&
        after.dev === pathnameAfter.dev &&
        after.ino === pathnameAfter.ino &&
        after.mode === pathnameAfter.mode &&
        bytes.length === after.size,
      'file-race-detected',
      `${label} changed while read`
    );
    return { bytes, metadata: after };
  } finally {
    closeSync(descriptor);
  }
}

function repositoryAbsolute(logicalPath) {
  assertion(
    typeof logicalPath === 'string' &&
      logicalPath !== '' &&
      !logicalPath.startsWith('/') &&
      !logicalPath.includes('\\') &&
      logicalPath === path.posix.normalize(logicalPath) &&
      logicalPath.split('/').every((component) => component !== '' && component !== '..'),
    'logical-path-invalid',
    `unsafe repository logical path: ${String(logicalPath)}`
  );
  const absolutePath = path.resolve(REPOSITORY_ROOT, logicalPath);
  assertion(absolutePath.startsWith(`${REPOSITORY_ROOT}${path.sep}`), 'path-escape', logicalPath);
  return absolutePath;
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

function gitInvocationReceiptIndependent(invocations) {
  const argv = invocations.map((args) => [...args]);
  return {
    executablePath: GIT_EXECUTABLE,
    argv,
    argvCount: argv.length,
    argvSetSha256: canonicalHashIndependent(argv),
    childEnvironment: gitEnvironment(),
  };
}

function gitRead(args, encoding = null) {
  const allowed = new Set(['--version', 'cat-file', 'for-each-ref', 'ls-tree', 'rev-parse']);
  assertion(
    Array.isArray(args) && args.length > 0 && allowed.has(args[0]),
    'git-operation-refused',
    `non-read-only Git operation: ${String(args[0])}`
  );
  return execFileSync(GIT_EXECUTABLE, args, {
    cwd: REPOSITORY_ROOT,
    env: gitEnvironment(),
    encoding,
    maxBuffer: 64 * 1024 * 1024,
    windowsHide: true,
  });
}

function canonicalRelativePathIndependent(value) {
  assertion(
    typeof value === 'string' &&
      value !== '' &&
      !path.posix.isAbsolute(value) &&
      !value.includes('\\') &&
      value === path.posix.normalize(value) &&
      value.split('/').every((component) => component !== '' && component !== '..') &&
      Buffer.from(value, 'utf8').toString('utf8') === value,
    'logical-path-invalid',
    `non-canonical logical path: ${String(value)}`
  );
  return value;
}

function filesystemDescriptorIndependent(absolutePath, logicalPath) {
  canonicalRelativePathIndependent(logicalPath);
  const before = lstatSync(absolutePath);
  if (before.isFile()) {
    const observed = readRegularFileStable(absolutePath, logicalPath);
    return {
      logicalPath,
      kind: 'regular-file',
      mode: octalMode(observed.metadata),
      nlink: observed.metadata.nlink,
      hardLinked: observed.metadata.nlink !== 1,
      byteLength: observed.bytes.length,
      sha256: sha256Independent(observed.bytes),
    };
  }
  if (before.isDirectory()) {
    return {
      logicalPath,
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
      logicalPath,
      kind: 'symbolic-link',
      mode: octalMode(before),
      linkTarget,
      linkTargetByteLength: Buffer.byteLength(linkTarget, 'utf8'),
      linkTargetSha256: sha256Independent(Buffer.from(linkTarget, 'utf8')),
    };
  }
  return {
    logicalPath,
    kind: 'unsupported-special-file',
    mode: octalMode(before),
    classification: 'opaque-not-executable-boundary-eligible',
  };
}

function walkFilesystemIndependent(absolutePath, logicalPath, entries) {
  const descriptor = filesystemDescriptorIndependent(absolutePath, logicalPath);
  entries.push(descriptor);
  if (descriptor.kind !== 'directory') {
    return;
  }
  const childNames = readdirSync(absolutePath, { withFileTypes: true })
    .map(({ name }) => name)
    .sort(compareUtf8);
  for (const childName of childNames) {
    walkFilesystemIndependent(
      path.join(absolutePath, childName),
      path.posix.join(logicalPath, childName),
      entries
    );
  }
}

function sortedUniqueEntriesIndependent(entries, layerId) {
  const sorted = [...entries].sort((left, right) =>
    compareUtf8(left.logicalPath, right.logicalPath)
  );
  for (const [index, entry] of sorted.entries()) {
    canonicalRelativePathIndependent(entry.logicalPath);
    assertion(
      index === 0 || sorted[index - 1].logicalPath !== entry.logicalPath,
      'independent-layer-path-collision',
      `${layerId}:${entry.logicalPath}`
    );
  }
  return sorted;
}

function makeLayerIndependent(id, kind, entries, metadata = {}) {
  const sortedEntries = sortedUniqueEntriesIndependent(entries, id);
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
    contentSha256: canonicalHashIndependent(body),
  };
}

function snapshotRepositoryPathsIndependent(id, kind, logicalPaths, metadata = {}) {
  const entries = [];
  for (const logicalPath of [...logicalPaths].sort(compareUtf8)) {
    canonicalRelativePathIndependent(logicalPath);
    const absolutePath = repositoryAbsolute(logicalPath);
    walkFilesystemIndependent(absolutePath, logicalPath, entries);
  }
  return makeLayerIndependent(id, kind, entries, {
    ...metadata,
    logicalPaths: [...logicalPaths],
  });
}

function regularFileDescriptorReceiptIndependent(layer) {
  const files = layer.entries
    .filter(({ kind }) => kind === 'regular-file')
    .map(({ logicalPath: filePath, byteLength, sha256 }) => ({
      path: filePath,
      byteLength,
      sha256,
    }))
    .sort((left, right) => compareUtf8(left.path, right.path));
  return {
    regularFileCount: files.length,
    descriptorSetSha256: canonicalHashIndependent(files),
  };
}

function absoluteLogicalPathIndependent(absolutePath) {
  return canonicalRelativePathIndependent(
    `host${path.normalize(absolutePath).replaceAll(path.sep, '/')}`
  );
}

function pathPrefixesIndependent(absolutePath) {
  assertion(path.isAbsolute(absolutePath), 'absolute-path-invalid', absolutePath);
  const prefixes = [];
  let current = path.parse(absolutePath).root;
  for (const component of path.normalize(absolutePath).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    prefixes.push(current);
  }
  return prefixes;
}

function collectAbsolutePathDescriptorsIndependent(requestedPaths) {
  const descriptorPaths = new Set();
  const resolutions = [];
  for (const requestedPath of [...requestedPaths].sort(compareUtf8)) {
    assertion(path.isAbsolute(requestedPath), 'absolute-path-invalid', requestedPath);
    let realPath = null;
    let errorCode = null;
    try {
      realPath = realpathSync(requestedPath);
      for (const prefix of pathPrefixesIndependent(requestedPath)) {
        if (lstatSync(prefix).isSymbolicLink()) {
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
    .sort(compareUtf8)
    .map((absolutePath) =>
      filesystemDescriptorIndependent(absolutePath, absoluteLogicalPathIndependent(absolutePath))
    );
  return { entries, resolutions };
}

function lddReceiptIndependent(executablePath) {
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
      normalizedReceiptSha256: canonicalHashIndependent(normalized),
    };
  }

  const resolvedPaths = new Set();
  const unresolvedLibraries = [];
  const virtualLibraries = [];
  const unparsedLines = [];
  for (const rawLine of output.split('\n')) {
    const line = rawLine.trim();
    if (line === '') continue;
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
    resolvedPaths: [...resolvedPaths].sort(compareUtf8),
    unresolvedLibraries: unresolvedLibraries.sort(compareUtf8),
    virtualLibraries: virtualLibraries.sort(compareUtf8),
    unparsedLines: unparsedLines.sort(compareUtf8),
    normalization:
      'parsed library names and resolved paths plus normalized unparsed lines; ASLR load addresses and raw ldd output excluded',
  };
  return {
    ...normalized,
    normalizedReceiptSha256: canonicalHashIndependent(normalized),
  };
}

function runtimeProbeIndependent(candidate) {
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
    throw new InvalidH054VerificationError(
      'runtime-probe-invalid',
      `${candidate.id}: ${error.message}`
    );
  }
  assertion(
    receipt.version === candidate.version,
    'runtime-version-drift',
    `${candidate.id}: ${String(receipt.version)}`
  );
  return receipt;
}

function runtimeLayerIndependent(candidate) {
  const libraries = lddReceiptIndependent(candidate.executablePath);
  const absolute = collectAbsolutePathDescriptorsIndependent([
    candidate.commandPath,
    candidate.executablePath,
    '/usr/bin/ldd',
    '/etc/ld.so.cache',
    ...libraries.resolvedPaths,
  ]);
  return makeLayerIndependent(
    candidate.layerId,
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
      probe: runtimeProbeIndependent(candidate),
      dynamicLibraries: libraries,
      pathResolutions: absolute.resolutions,
    }
  );
}

function environmentReceiptIndependent() {
  const semanticVariables = [...SEMANTIC_ENVIRONMENT_KEYS].sort(compareUtf8).map((name) => {
    const value = process.env[name];
    if (value === undefined) {
      return { name, present: false };
    }
    const bytes = Buffer.from(value, 'utf8');
    const disclose = ENVIRONMENT_VALUES_SAFE_TO_RECORD.has(name);
    return {
      name,
      present: true,
      byteLength: bytes.length,
      valueSha256: sha256Independent(bytes),
      value: disclose ? value : null,
      valueDisclosure: disclose ? 'recorded-non-secret' : 'hash-only',
    };
  });
  const environmentNames = Object.keys(process.env).sort(compareUtf8);
  return {
    policy: 'semantic-allowlist-values-only-no-secret-capture',
    semanticVariables,
    inheritedNameCount: environmentNames.length,
    inheritedNameSetSha256: canonicalHashIndependent(environmentNames),
    unclassifiedNameCount: environmentNames.filter(
      (name) => !SEMANTIC_ENVIRONMENT_KEYS.includes(name)
    ).length,
    unclassifiedValues: 'not-recorded-potentially-secret',
    futureHermeticRequirement: 'env-i-with-explicit-reviewed-allowlist',
  };
}

function processReceiptIndependent() {
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

function cacheLayerIndependent() {
  const suffix =
    typeof process.geteuid === 'function' ? String(process.geteuid()) : os.userInfo().username;
  const cachePath = path.join(os.tmpdir(), `tsx-${suffix}`);
  try {
    lstatSync(cachePath);
  } catch (error) {
    assertion(error?.code === 'ENOENT', 'cache-read-failed', cachePath);
    return makeLayerIndependent(
      'cache/tsx-global-current',
      'mutable-global-cache-observation',
      [],
      {
        cachePath,
        present: false,
        historicalH053Attribution: 'irrecoverable',
        eligibility: 'not-successor-boundary-eligible',
      }
    );
  }
  const entries = [];
  walkFilesystemIndependent(cachePath, 'cache-root', entries);
  return makeLayerIndependent(
    'cache/tsx-global-current',
    'mutable-global-cache-observation',
    entries,
    {
      cachePath,
      present: true,
      historicalH053Attribution: 'irrecoverable',
      eligibility: 'not-successor-boundary-eligible-without-private-pre-post-anchor',
      alternative: 'TSX_DISABLE_CACHE=1 remains an unselected successor constraint',
    }
  );
}

function gitRuntimeLayerIndependent() {
  const libraries = lddReceiptIndependent(GIT_EXECUTABLE);
  const absolute = collectAbsolutePathDescriptorsIndependent([
    GIT_EXECUTABLE,
    '/usr/bin/ldd',
    '/etc/ld.so.cache',
    ...libraries.resolvedPaths,
  ]);
  return makeLayerIndependent('tool/git-runtime', 'read-only-git-runtime', absolute.entries, {
    executablePath: GIT_EXECUTABLE,
    executableSha256: EXPECTED.gitSha256,
    dynamicLibraryInspector: '/usr/bin/ldd',
    dynamicLibraryInspectorClosure: 'opaque-not-recursively-closed',
    version: gitRead(['--version'], 'utf8').trim(),
    dynamicLibraries: libraries,
    pathResolutions: absolute.resolutions,
    childEnvironment: gitEnvironment(),
    invocationReceipt: gitInvocationReceiptIndependent([['--version']]),
  });
}

function gitRepositoryStateLayerIndependent() {
  const candidates = [
    '.git/HEAD',
    '.git/config',
    '.git/config.worktree',
    '.git/info/grafts',
    '.git/objects/info/alternates',
    '.git/packed-refs',
    '.git/shallow',
  ];
  const headBytes = readRegularFileStable(repositoryAbsolute('.git/HEAD'), '.git/HEAD')
    .bytes.toString('utf8')
    .trim();
  const symbolicHead = /^ref: (?<logicalPath>refs\/[A-Za-z0-9._/-]+)$/u.exec(headBytes);
  if (symbolicHead !== null) {
    const headRefPath = `.git/${symbolicHead.groups.logicalPath}`;
    assertion(
      headRefPath === path.posix.normalize(headRefPath) && !headRefPath.includes('..'),
      'git-head-ref-invalid',
      headRefPath
    );
    candidates.push(headRefPath);
  }
  const present = [];
  const absent = [];
  for (const logicalPath of candidates) {
    try {
      lstatSync(repositoryAbsolute(logicalPath));
      present.push(logicalPath);
    } catch (error) {
      assertion(error?.code === 'ENOENT', 'git-state-read-failed', logicalPath);
      absent.push({ logicalPath, status: 'absent' });
    }
  }
  const replaceRefs = gitRead(
    ['for-each-ref', '--format=%(refname)%00%(objectname)', 'refs/replace'],
    'utf8'
  );
  const allRefs = gitRead(['for-each-ref', '--format=%(refname)%00%(objectname)'], 'utf8');
  return snapshotRepositoryPathsIndependent(
    'tool/git-repository-state',
    'git-object-resolution-state',
    present,
    {
      absent,
      replaceRefOutputSha256: sha256Independent(Buffer.from(replaceRefs, 'utf8')),
      replaceRefCount: replaceRefs.trim() === '' ? 0 : replaceRefs.trim().split('\n').length,
      refOutputSha256: sha256Independent(Buffer.from(allRefs, 'utf8')),
      refCount: allRefs.trim() === '' ? 0 : allRefs.trim().split('\n').length,
      head: {
        valueSha256: sha256Independent(Buffer.from(headBytes, 'utf8')),
        symbolicRef: symbolicHead?.groups.logicalPath ?? null,
      },
      objectReads: 'main layer binds every consumed Git object by OID and SHA-256 bytes',
      invocationReceipt: gitInvocationReceiptIndependent([
        ['for-each-ref', '--format=%(refname)%00%(objectname)', 'refs/replace'],
        ['for-each-ref', '--format=%(refname)%00%(objectname)'],
      ]),
    }
  );
}

function hostContextLayerIndependent() {
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
  const absolute = collectAbsolutePathDescriptorsIndependent(existingPaths);
  return makeLayerIndependent(
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

function parseRepositoryJsonIndependent(logicalPath, label = logicalPath) {
  const receipt = readRegularFileStable(repositoryAbsolute(logicalPath), label);
  return {
    bytes: receipt.bytes,
    value: parseJsonBytes(receipt.bytes, label),
  };
}

function sortedStringObjectIndependent(value) {
  assertion(
    isPlainObject(value),
    'package-dependency-map-invalid',
    'dependency map is not an object'
  );
  return Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => compareUtf8(left, right))
  );
}

function installedPackageStatusIndependent(name) {
  const logicalRoot = `node_modules/${name}`;
  try {
    const metadata = lstatSync(repositoryAbsolute(logicalRoot));
    assertion(
      metadata.isDirectory() && !metadata.isSymbolicLink(),
      'package-root-type-invalid',
      logicalRoot
    );
    return { installed: true, logicalRoot };
  } catch (error) {
    assertion(error?.code === 'ENOENT', 'package-root-read-failed', logicalRoot);
    return { installed: false, logicalRoot };
  }
}

function normalizePackageBinIndependent(name, bin) {
  const executableName = name.includes('/') ? name.slice(name.lastIndexOf('/') + 1) : name;
  if (typeof bin === 'string') {
    return { [executableName]: bin.replace(/^\.\//u, '') };
  }
  if (isPlainObject(bin)) {
    return Object.fromEntries(
      Object.entries(bin)
        .sort(([left], [right]) => compareUtf8(left, right))
        .map(([key, value]) => [
          key,
          typeof value === 'string' ? value.replace(/^\.\//u, '') : value,
        ])
    );
  }
  return bin;
}

function derivePackageLayersIndependent() {
  const lock = parseRepositoryJsonIndependent('package-lock.json', 'package lock').value;
  assertion(
    lock.lockfileVersion === 3 && isPlainObject(lock.packages),
    'package-lock-shape-invalid',
    'package-lock.json does not expose a v3 packages map'
  );

  const pending = [...PACKAGE_SEEDS].sort(compareUtf8);
  const discovered = new Map();
  while (pending.length > 0) {
    pending.sort(compareUtf8);
    const name = pending.shift();
    if (discovered.has(name)) continue;

    const installation = installedPackageStatusIndependent(name);
    assertion(installation.installed, 'required-package-missing', name);
    const lockPath = `node_modules/${name}`;
    const lockRecord = lock.packages[lockPath];
    assertion(isPlainObject(lockRecord), 'package-lock-entry-missing', lockPath);
    assertion(
      typeof lockRecord.version === 'string' &&
        typeof lockRecord.integrity === 'string' &&
        typeof lockRecord.resolved === 'string',
      'package-lock-entry-incomplete',
      lockPath
    );

    const packageJsonPath = `${installation.logicalRoot}/package.json`;
    const manifestReceipt = parseRepositoryJsonIndependent(packageJsonPath, packageJsonPath);
    const manifest = manifestReceipt.value;
    assertion(
      manifest.name === name &&
        typeof manifest.version === 'string' &&
        lockRecord.version === manifest.version,
      'package-manifest-identity-drift',
      `${name}: ${String(manifest.name)}@${String(manifest.version)}`
    );
    if (lockRecord.bin !== undefined) {
      assertion(
        canonicalJsonIndependent(normalizePackageBinIndependent(name, manifest.bin)) ===
          canonicalJsonIndependent(normalizePackageBinIndependent(name, lockRecord.bin)),
        'package-bin-lock-drift',
        name
      );
    }
    if (Object.hasOwn(manifest, 'exports')) {
      assertion(
        manifest.exports !== undefined,
        'package-exports-invalid',
        `${name} exports is undefined`
      );
    }

    const dependencies = isPlainObject(manifest.dependencies) ? manifest.dependencies : {};
    const optionalDependencies = isPlainObject(manifest.optionalDependencies)
      ? manifest.optionalDependencies
      : {};
    const requiredDependencies = Object.keys(dependencies).sort(compareUtf8);
    const optionalNames = Object.keys(optionalDependencies).sort(compareUtf8);
    const followedOptionalDependencies = [];
    const absentOptionalDependencies = [];

    for (const dependencyName of requiredDependencies) {
      assertion(
        installedPackageStatusIndependent(dependencyName).installed,
        'required-package-missing',
        `${name}->${dependencyName}`
      );
      pending.push(dependencyName);
    }
    for (const dependencyName of optionalNames) {
      if (installedPackageStatusIndependent(dependencyName).installed) {
        followedOptionalDependencies.push(dependencyName);
        pending.push(dependencyName);
      } else {
        absentOptionalDependencies.push(dependencyName);
      }
    }

    const declaredDependencyNames = [...new Set([...requiredDependencies, ...optionalNames])].sort(
      compareUtf8
    );
    const declaredDependencies = Object.fromEntries(
      declaredDependencyNames.map((dependencyName) => [
        dependencyName,
        Object.hasOwn(optionalDependencies, dependencyName)
          ? optionalDependencies[dependencyName]
          : dependencies[dependencyName],
      ])
    );
    discovered.set(name, {
      name,
      version: manifest.version,
      logicalRoot: installation.logicalRoot,
      packageManifestSha256: sha256Independent(manifestReceipt.bytes),
      lockResolved: lockRecord.resolved,
      lockIntegrity: lockRecord.integrity,
      declaredDependencies: sortedStringObjectIndependent(declaredDependencies),
      requiredDependencies,
      followedOptionalDependencies,
      absentOptionalDependencies,
      seed: PACKAGE_SEEDS.includes(name),
      packageEntryPointResolution: {
        exportsDeclared: Object.hasOwn(manifest, 'exports'),
        exportsValueSha256: Object.hasOwn(manifest, 'exports')
          ? canonicalHashIndependent(manifest.exports)
          : null,
        main: typeof manifest.main === 'string' ? manifest.main : null,
        binValueSha256: Object.hasOwn(manifest, 'bin')
          ? canonicalHashIndependent(manifest.bin)
          : null,
        classification:
          'whole-tree-inventoried-per-import-and-export-condition-resolution-not-enumerated',
      },
    });
  }

  const layers = [];
  for (const boundary of [...discovered.values()].sort((left, right) =>
    compareUtf8(left.name, right.name)
  )) {
    const provisional = snapshotRepositoryPathsIndependent(
      `package/${boundary.name}@${boundary.version}`,
      'installed-package-tree',
      [boundary.logicalRoot],
      {
        name: boundary.name,
        version: boundary.version,
        packageManifestSha256: boundary.packageManifestSha256,
        lockResolved: boundary.lockResolved,
        lockIntegrity: boundary.lockIntegrity,
        declaredDependencies: boundary.declaredDependencies,
        requiredDependencies: boundary.requiredDependencies,
        followedOptionalDependencies: boundary.followedOptionalDependencies,
        absentOptionalDependencies: boundary.absentOptionalDependencies,
        seed: boundary.seed,
        packageEntryPointResolution: boundary.packageEntryPointResolution,
        derivation:
          'human-nominated H-053 seeds followed through installed required and optional package edges',
        resolution: 'whole-installed-tree-conservative-closure',
      }
    );
    const regularFileCount = provisional.entries.filter(
      ({ kind }) => kind === 'regular-file'
    ).length;
    layers.push(
      makeLayerIndependent(provisional.id, provisional.kind, provisional.entries, {
        ...provisional.metadata,
        regularFileCount,
      })
    );
  }
  return layers;
}

function parseLsTree(bytes) {
  return bytes
    .toString('utf8')
    .split('\0')
    .filter(Boolean)
    .map((record) => {
      const match =
        /^(?<mode>[0-9]{6}) (?<type>[a-z]+) (?<oid>[0-9a-f]{40})\t(?<logicalPath>.+)$/u.exec(
          record
        );
      assertion(match !== null, 'git-tree-invalid', `malformed ls-tree record: ${record}`);
      return match.groups;
    });
}

function expectedGitEntry(record) {
  const bytes = gitRead(['cat-file', record.type, record.oid]);
  const common = {
    logicalPath: record.logicalPath,
    gitMode: record.mode,
    gitType: record.type,
    gitOid: record.oid,
    byteLength: bytes.length,
    sha256: sha256Independent(bytes),
  };
  if (record.mode === '120000') {
    return { ...common, kind: 'git-symbolic-link', linkTarget: bytes.toString('utf8') };
  }
  if (record.mode === '160000') {
    return { ...common, kind: 'gitlink', classification: 'opaque-external-object' };
  }
  const objectOid = createHash('sha1')
    .update(Buffer.from(`${record.type} ${bytes.length}\0`, 'utf8'))
    .update(bytes)
    .digest('hex');
  assertion(
    objectOid === record.oid,
    'git-object-identity-invalid',
    `${record.logicalPath} bytes do not reproduce ${record.oid}`
  );
  return { ...common, kind: 'git-regular-file' };
}

function verifyAnchors(anchors) {
  exactKeys(
    anchors,
    ['h053ClosureSha256', 'h053RunRawSha256', 'mainCommit', 'mainTree'],
    'run anchors'
  );
  assertion(
    anchors.mainCommit === EXPECTED.mainCommit &&
      anchors.mainTree === EXPECTED.mainTree &&
      anchors.h053ClosureSha256 === EXPECTED.h053ClosureSha256 &&
      anchors.h053RunRawSha256 === EXPECTED.h053RunRawSha256,
    'anchor-drift',
    'run anchors differ from the human-nominated boundary'
  );

  const commit = gitRead(
    ['rev-parse', '--verify', `${EXPECTED.mainCommit}^{commit}`],
    'utf8'
  ).trim();
  const tree = gitRead(['rev-parse', `${EXPECTED.mainCommit}^{tree}`], 'utf8').trim();
  const head = gitRead(['rev-parse', '--verify', 'HEAD^{commit}'], 'utf8').trim();
  assertion(
    commit === EXPECTED.mainCommit && tree === EXPECTED.mainTree && head === EXPECTED.mainCommit,
    'main-anchor-stale',
    `observed ${head}/${tree}`
  );

  const h053Closure = readRegularFileStable(
    repositoryAbsolute(
      'artifacts/h053/post-review-closures/5a55fc6ec2dff653858d4c8a70a22d3085400b423b8c93e265f14774078bf14f/closure.json'
    ),
    'H-053 closure'
  );
  const h053Run = readRegularFileStable(
    repositoryAbsolute(
      'artifacts/h053/runs/0e979b5191acbf68a865d6f9c651d8683e93fbcc26cfd44bbf06ad363a3b29d4/run.json'
    ),
    'H-053 run'
  );
  assertion(
    sha256Independent(h053Closure.bytes) === EXPECTED.h053ClosureSha256,
    'h053-closure-stale',
    'H-053 closure bytes drifted'
  );
  assertion(
    sha256Independent(h053Run.bytes) === EXPECTED.h053RunRawSha256,
    'h053-run-stale',
    'H-053 run bytes drifted'
  );
}

function verifyEntryShape(entry, label) {
  assertion(isPlainObject(entry), 'entry-shape-invalid', `${label} is not an object`);
  const shapes = {
    directory: ['kind', 'logicalPath', 'mode', 'nlink'],
    'git-regular-file': [
      'byteLength',
      'gitMode',
      'gitOid',
      'gitType',
      'kind',
      'logicalPath',
      'sha256',
    ],
    'git-symbolic-link': [
      'byteLength',
      'gitMode',
      'gitOid',
      'gitType',
      'kind',
      'linkTarget',
      'logicalPath',
      'sha256',
    ],
    gitlink: [
      'byteLength',
      'classification',
      'gitMode',
      'gitOid',
      'gitType',
      'kind',
      'logicalPath',
      'sha256',
    ],
    'regular-file': ['byteLength', 'hardLinked', 'kind', 'logicalPath', 'mode', 'nlink', 'sha256'],
    'symbolic-link': [
      'kind',
      'linkTarget',
      'linkTargetByteLength',
      'linkTargetSha256',
      'logicalPath',
      'mode',
    ],
    'unsupported-special-file': ['classification', 'kind', 'logicalPath', 'mode'],
  };
  assertion(
    Object.hasOwn(shapes, entry.kind),
    'entry-kind-invalid',
    `${label} has unknown kind ${String(entry.kind)}`
  );
  exactKeys(entry, shapes[entry.kind], label);
  assertion(
    typeof entry.logicalPath === 'string' && entry.logicalPath !== '',
    'logical-path-invalid',
    `${label} has no logical path`
  );
  if (Object.hasOwn(entry, 'sha256')) {
    assertion(
      typeof entry.sha256 === 'string' && /^[0-9a-f]{64}$/u.test(entry.sha256),
      'descriptor-sha-invalid',
      `${label} SHA-256 is malformed`
    );
  }
}

function resolveDescriptorPath(layer, entry) {
  if (entry.logicalPath.startsWith('host/')) {
    return path.resolve('/', entry.logicalPath.slice('host/'.length));
  }
  if (
    layer.id === 'cache/tsx-global-current' &&
    (entry.logicalPath === 'cache-root' || entry.logicalPath.startsWith('cache-root/'))
  ) {
    const cachePath = layer.metadata?.cachePath;
    assertion(
      typeof cachePath === 'string' && path.isAbsolute(cachePath),
      'cache-path-invalid',
      'cache layer has no absolute cachePath'
    );
    const suffix =
      entry.logicalPath === 'cache-root' ? '' : entry.logicalPath.slice('cache-root/'.length);
    const resolved = path.resolve(cachePath, suffix);
    assertion(
      resolved === path.resolve(cachePath) ||
        resolved.startsWith(`${path.resolve(cachePath)}${path.sep}`),
      'path-escape',
      entry.logicalPath
    );
    return resolved;
  }
  return repositoryAbsolute(entry.logicalPath);
}

function verifyFilesystemEntry(layer, entry) {
  const absolutePath = resolveDescriptorPath(layer, entry);
  const metadata = lstatSync(absolutePath);
  if (entry.kind === 'regular-file') {
    const observed = readRegularFileStable(absolutePath, `${layer.id}:${entry.logicalPath}`);
    const expected = {
      logicalPath: entry.logicalPath,
      kind: 'regular-file',
      mode: octalMode(observed.metadata),
      nlink: observed.metadata.nlink,
      hardLinked: observed.metadata.nlink !== 1,
      byteLength: observed.bytes.length,
      sha256: sha256Independent(observed.bytes),
    };
    assertion(
      canonicalJsonIndependent(entry) === canonicalJsonIndependent(expected),
      'descriptor-byte-drift',
      `${layer.id}:${entry.logicalPath}`
    );
    return;
  }
  if (entry.kind === 'directory') {
    assertion(metadata.isDirectory(), 'descriptor-type-drift', entry.logicalPath);
    const expected = {
      logicalPath: entry.logicalPath,
      kind: 'directory',
      mode: octalMode(metadata),
      nlink: metadata.nlink,
    };
    assertion(
      canonicalJsonIndependent(entry) === canonicalJsonIndependent(expected),
      'descriptor-metadata-drift',
      `${layer.id}:${entry.logicalPath}`
    );
    return;
  }
  if (entry.kind === 'symbolic-link') {
    assertion(metadata.isSymbolicLink(), 'descriptor-type-drift', entry.logicalPath);
    const linkTarget = readlinkSync(absolutePath);
    const expected = {
      logicalPath: entry.logicalPath,
      kind: 'symbolic-link',
      mode: octalMode(metadata),
      linkTarget,
      linkTargetByteLength: Buffer.byteLength(linkTarget, 'utf8'),
      linkTargetSha256: sha256Independent(Buffer.from(linkTarget, 'utf8')),
    };
    assertion(
      canonicalJsonIndependent(entry) === canonicalJsonIndependent(expected),
      'symlink-chain-drift',
      `${layer.id}:${entry.logicalPath}`
    );
    return;
  }
  assertion(
    !metadata.isFile() && !metadata.isDirectory() && !metadata.isSymbolicLink(),
    'descriptor-type-drift',
    entry.logicalPath
  );
  assertion(entry.mode === octalMode(metadata), 'descriptor-metadata-drift', entry.logicalPath);
}

function layerBody(layer) {
  return {
    schemaVersion: layer.schemaVersion,
    id: layer.id,
    kind: layer.kind,
    metadata: layer.metadata,
    entries: layer.entries,
  };
}

function verifyLayerShape(layer, index) {
  exactKeys(
    layer,
    ['contentSha256', 'entries', 'entryCount', 'id', 'kind', 'metadata', 'schemaVersion'],
    `layer ${index}`
  );
  assertion(
    layer.schemaVersion === 'overlaykit-h054-content-layer/v1' &&
      typeof layer.id === 'string' &&
      typeof layer.kind === 'string' &&
      isPlainObject(layer.metadata) &&
      Array.isArray(layer.entries) &&
      Number.isSafeInteger(layer.entryCount) &&
      layer.entryCount === layer.entries.length,
    'layer-shape-invalid',
    `layer ${index}`
  );
  const logicalPaths = [];
  for (const [entryIndex, entry] of layer.entries.entries()) {
    verifyEntryShape(entry, `${layer.id} entry ${entryIndex}`);
    logicalPaths.push(entry.logicalPath);
  }
  const sortedPaths = [...logicalPaths].sort(compareUtf8);
  assertion(
    sameArray(logicalPaths, sortedPaths) && new Set(logicalPaths).size === logicalPaths.length,
    'layer-entry-order-invalid',
    layer.id
  );
  assertion(
    canonicalHashIndependent(layerBody(layer)) === layer.contentSha256,
    'layer-hash-invalid',
    layer.id
  );
}

function expectedLayerReceipt(layer) {
  return {
    id: layer.id,
    kind: layer.kind,
    entryCount: layer.entryCount,
    contentSha256: layer.contentSha256,
  };
}

function verifyMainGitLayer(layer) {
  const treeBytes = gitRead(['ls-tree', '-rz', '--full-tree', '-r', EXPECTED.mainCommit]);
  const records = parseLsTree(treeBytes);
  assertion(
    records.length === EXPECTED.mainEntryCount &&
      layer.entryCount === EXPECTED.mainEntryCount &&
      sha256Independent(treeBytes) === EXPECTED.mainLsTreeSha256 &&
      layer.metadata?.commit === EXPECTED.mainCommit &&
      layer.metadata?.tree === EXPECTED.mainTree &&
      layer.metadata?.recursiveEntryCount === EXPECTED.mainEntryCount &&
      layer.metadata?.recursiveLsTreeSha256 === EXPECTED.mainLsTreeSha256,
    'main-tree-cardinality-or-hash-drift',
    'main tree does not reproduce the nominated 319-entry anchor'
  );
  const expectedEntries = records.map((record) => expectedGitEntry(record));
  const expectedLayer = makeLayerIndependent('source/main-git-tree', 'git-tree', expectedEntries, {
    commit: EXPECTED.mainCommit,
    tree: EXPECTED.mainTree,
    recursiveEntryCount: records.length,
    recursiveLsTreeSha256: sha256Independent(treeBytes),
    invocationReceipt: gitInvocationReceiptIndependent([
      ['rev-parse', '--verify', 'HEAD^{commit}'],
      ['rev-parse', '--verify', `${EXPECTED.mainCommit}^{commit}`],
      ['rev-parse', `${EXPECTED.mainCommit}^{tree}`],
      ['ls-tree', '-rz', '--full-tree', '-r', EXPECTED.mainCommit],
      ...records.map(({ type, oid }) => ['cat-file', type, oid]),
    ]),
  });
  assertExactReconstructedLayer(
    layer,
    expectedLayer,
    'main-tree-descriptor-drift',
    'main-tree-entry-omitted'
  );
  return records.map(({ logicalPath }) => logicalPath);
}

function pathUnderAny(logicalPath, roots) {
  return roots.some((root) => logicalPath === root || logicalPath.startsWith(`${root}/`));
}

function verifyGuardedLayer(layer, mainGitPaths) {
  const regularPaths = layer.entries
    .filter(({ kind }) => kind === 'regular-file')
    .map(({ logicalPath }) => logicalPath);
  const expectedPaths = mainGitPaths.filter((logicalPath) =>
    pathUnderAny(logicalPath, GUARDED_PATHS)
  );
  assertion(
    regularPaths.length === EXPECTED.guardedRegularFileCount &&
      expectedPaths.length === EXPECTED.guardedRegularFileCount &&
      sameArray(regularPaths, expectedPaths),
    'guarded-surface-cardinality-drift',
    'guarded surface does not contain the exact 40 tracked files'
  );

  const treeBytes = gitRead([
    'ls-tree',
    '-rz',
    '--full-tree',
    EXPECTED.mainCommit,
    '--',
    ...GUARDED_PATHS,
  ]);
  assertion(
    sha256Independent(treeBytes) === EXPECTED.guardedLsTreeSha256,
    'guarded-surface-anchor-drift',
    'guarded restricted ls-tree hash differs'
  );
}

function verifyH053Apparatus(layer) {
  const regular = layer.entries.filter(({ kind }) => kind === 'regular-file');
  assertion(
    regular.length === EXPECTED.h053ApparatusRegularFileCount,
    'h053-apparatus-cardinality-drift',
    `expected 10 H-053 apparatus files, observed ${regular.length}`
  );
  const descriptors = regular
    .map(({ logicalPath: sourcePath, byteLength, sha256 }) => ({
      path: sourcePath,
      byteLength,
      sha256,
    }))
    .sort((left, right) => compareUtf8(left.path, right.path));
  assertion(
    canonicalHashIndependent(descriptors) === EXPECTED.h053ApparatusDescriptorSetSha256,
    'h053-apparatus-hash-drift',
    'H-053 apparatus descriptor set differs from 1c686c08...'
  );
}

function verifyH054Apparatus(layer, subjectLock) {
  const regularPaths = layer.entries
    .filter(({ kind }) => kind === 'regular-file')
    .map(({ logicalPath }) => logicalPath);
  const expectedPaths = [...subjectLock.trackedApparatusPaths].sort(compareUtf8);
  assertion(
    sameArray(regularPaths, expectedPaths),
    'h054-apparatus-roster-drift',
    `expected ${expectedPaths.join(',')}, observed ${regularPaths.join(',')}`
  );
}

function requiredLayerIndependent(layers, id, reasonCode = 'layer-missing') {
  const layer = layers.find((candidate) => candidate.id === id);
  assertion(layer !== undefined, reasonCode, id);
  return layer;
}

function assertExactReconstructedLayer(
  observed,
  expected,
  reasonCode,
  missingEntryReasonCode = reasonCode
) {
  const observedPaths = new Set(observed.entries.map(({ logicalPath }) => logicalPath));
  const missingPaths = expected.entries
    .map(({ logicalPath }) => logicalPath)
    .filter((logicalPath) => !observedPaths.has(logicalPath));
  assertion(
    missingPaths.length === 0,
    missingEntryReasonCode,
    `${expected.id}: ${missingPaths.join(',')}`
  );
  assertion(
    canonicalJsonIndependent(observed) === canonicalJsonIndependent(expected),
    reasonCode,
    `${expected.id} differs from independent reconstruction`
  );
}

function verifyStaticRepositoryLayers(layers) {
  const guardedProvisional = snapshotRepositoryPathsIndependent(
    'source/guarded-worktree',
    'guarded-worktree-surface',
    GUARDED_PATHS,
    {
      source: 'H-053 guardedSurface.paths',
      symlinkPolicy: 'inventory-but-classify-ineligible',
    }
  );
  const guardedReceipt = regularFileDescriptorReceiptIndependent(guardedProvisional);
  const guarded = makeLayerIndependent(
    guardedProvisional.id,
    guardedProvisional.kind,
    guardedProvisional.entries,
    {
      ...guardedProvisional.metadata,
      h053Receipt: guardedReceipt,
    }
  );

  const h053ApparatusProvisional = snapshotRepositoryPathsIndependent(
    'apparatus/h053',
    'accepted-h053-experimental-apparatus',
    ['lab/h053'],
    {
      executionDistinction:
        'tests are inventoried apparatus but are not asserted to have executed in the canonical run',
    }
  );
  const h053ApparatusReceipt = regularFileDescriptorReceiptIndependent(h053ApparatusProvisional);
  const h053Apparatus = makeLayerIndependent(
    h053ApparatusProvisional.id,
    h053ApparatusProvisional.kind,
    h053ApparatusProvisional.entries,
    {
      ...h053ApparatusProvisional.metadata,
      h053Receipt: h053ApparatusReceipt,
    }
  );

  const h054Apparatus = snapshotRepositoryPathsIndependent(
    'apparatus/h054-producer',
    'non-normative-experimental-apparatus',
    ['lab/h054'],
    {
      authority: 'none',
      action: null,
      executedHypotheses: [],
    }
  );

  const closureProvisional = snapshotRepositoryPathsIndependent(
    'evidence/h053-post-review-closure',
    'local-content-addressed-evidence',
    [H053_CLOSURE_DIRECTORY],
    {
      anchorFile: `${H053_CLOSURE_DIRECTORY}/closure.json`,
      anchorSha256: EXPECTED.h053ClosureSha256,
    }
  );
  const closure = makeLayerIndependent(
    closureProvisional.id,
    closureProvisional.kind,
    closureProvisional.entries,
    {
      ...closureProvisional.metadata,
      regularFileCount: closureProvisional.entries.filter(({ kind }) => kind === 'regular-file')
        .length,
    }
  );

  const runProvisional = snapshotRepositoryPathsIndependent(
    'evidence/h053-canonical-run',
    'local-content-addressed-evidence',
    [H053_RUN_DIRECTORY],
    {
      anchorFile: `${H053_RUN_DIRECTORY}/run.json`,
      anchorSha256: EXPECTED.h053RunRawSha256,
    }
  );
  const h053Run = makeLayerIndependent(
    runProvisional.id,
    runProvisional.kind,
    runProvisional.entries,
    {
      ...runProvisional.metadata,
      regularFileCount: runProvisional.entries.filter(({ kind }) => kind === 'regular-file').length,
    }
  );

  const configuration = snapshotRepositoryPathsIndependent(
    'configuration/loader-and-package-resolution',
    'loader-resolution-configuration',
    LOADER_CONFIGURATION_PATHS,
    {
      reason:
        'tsx may consume tsconfig and package resolution inputs outside the H-053 guarded surface',
    }
  );

  const errors = makeLayerIndependent(
    'source/errors-ts',
    'explicit-first-party-execution-dependency',
    [
      filesystemDescriptorIndependent(
        repositoryAbsolute('tools/governance/src/errors.ts'),
        'tools/governance/src/errors.ts'
      ),
    ]
  );
  const esbuild = makeLayerIndependent(
    'native/esbuild-linux-x64@0.28.1',
    'static-native-executable',
    [filesystemDescriptorIndependent(repositoryAbsolute(ESBUILD_EXECUTABLE), ESBUILD_EXECUTABLE)],
    {
      executablePath: ESBUILD_EXECUTABLE,
      selectionBasis: 'installed @esbuild/linux-x64 package for linux/x64',
      dynamicLibraryClassification: 'static-no-dynamic-section',
    }
  );

  for (const [expected, reasonCode, omissionReasonCode] of [
    [guarded, 'guarded-layer-drift', 'guarded-layer-entry-omitted'],
    [h053Apparatus, 'h053-apparatus-layer-drift', 'h053-apparatus-entry-omitted'],
    [h054Apparatus, 'h054-apparatus-layer-drift', 'h054-apparatus-entry-omitted'],
    [closure, 'h053-closure-layer-drift', 'h053-closure-entry-omitted'],
    [h053Run, 'h053-run-layer-drift', 'h053-run-entry-omitted'],
    [configuration, 'configuration-layer-drift', 'configuration-entry-omitted'],
    [errors, 'errors-ts-layer-drift', 'required-entry-omitted'],
    [esbuild, 'esbuild-native-layer-drift', 'required-native-binary-omitted'],
  ]) {
    assertExactReconstructedLayer(
      requiredLayerIndependent(layers, expected.id),
      expected,
      reasonCode,
      omissionReasonCode
    );
  }
}

function verifyPackages(layers, subjectLock) {
  const reconstructed = derivePackageLayersIndependent();
  const derivedRoots = reconstructed
    .map(({ metadata }) => metadata.logicalPaths[0])
    .sort(compareUtf8);
  assertion(
    sameArray(subjectLock.packageRootRoster, derivedRoots),
    'package-root-roster-drift',
    `derived ${derivedRoots.join(',')}`
  );
  const derivedIds = reconstructed.map(({ id }) => id).sort(compareUtf8);
  const observedIds = layers
    .filter(({ id }) => id.startsWith('package/'))
    .map(({ id }) => id)
    .sort(compareUtf8);
  assertion(
    sameArray(observedIds, derivedIds),
    'package-roster-derivation-drift',
    `derived ${derivedIds.join(',')}; observed ${observedIds.join(',')}`
  );

  let total = 0;
  for (const expectedLayer of reconstructed) {
    const observedLayer = requiredLayerIndependent(
      layers,
      expectedLayer.id,
      'package-layer-missing'
    );
    assertExactReconstructedLayer(
      observedLayer,
      expectedLayer,
      'package-layer-drift',
      'package-tree-entry-omitted'
    );
    const count = expectedLayer.entries.filter(({ kind }) => kind === 'regular-file').length;
    const acceptedCount = EXPECTED_PACKAGE_REGULAR_FILES[expectedLayer.id];
    assertion(
      count === acceptedCount,
      'package-regular-file-cardinality-drift',
      `${expectedLayer.id}: expected ${String(acceptedCount)}, observed ${count}`
    );
    total += count;
  }
  assertion(
    total === EXPECTED_PACKAGE_REGULAR_FILE_COUNT && total === 587,
    'package-regular-file-cardinality-drift',
    `expected 587 package regular files, observed ${total}`
  );
}

function verifyRuntimeCandidates(snapshot, layers) {
  assertion(
    snapshot.runtimeSelection === null &&
      Array.isArray(snapshot.runtimeCandidates) &&
      snapshot.runtimeCandidates.length === EXPECTED_RUNTIME_CANDIDATES.length,
    'runtime-selection-not-null',
    'runtime selection must remain null with exactly two candidates'
  );
  for (const [index, expected] of EXPECTED_RUNTIME_CANDIDATES.entries()) {
    const candidate = snapshot.runtimeCandidates[index];
    exactKeys(
      candidate,
      ['executablePath', 'id', 'selection', 'version'],
      `runtime candidate ${index}`
    );
    assertion(
      candidate.id === expected.id &&
        candidate.version === expected.version &&
        candidate.executablePath === expected.executablePath &&
        candidate.selection === null,
      'runtime-candidate-drift',
      expected.id
    );
    const layer = layers.find(({ id }) => id === expected.layerId);
    assertion(layer !== undefined, 'runtime-layer-missing', expected.layerId);
    const reconstructed = runtimeLayerIndependent(expected);
    assertExactReconstructedLayer(
      layer,
      reconstructed,
      'runtime-layer-drift',
      'runtime-library-omitted'
    );
  }
}

function verifyProcessAndCacheLayers(layers, invocationContext) {
  const invocation = requiredLayerIndependent(
    layers,
    'process/invocation',
    'process-invocation-layer-missing'
  );
  const current = processReceiptIndependent();
  const sameProcess =
    sameArray(invocation.metadata?.argv, current.argv) &&
    sameArray(invocation.metadata?.execArgv, current.execArgv);
  const canonicalProducer =
    invocationContext === 'canonical-writer-file' &&
    sameArray(invocation.metadata?.argv, [current.executablePath, PRODUCER_PATH, '--write']) &&
    sameArray(invocation.metadata?.execArgv, []);
  assertion(
    sameProcess || canonicalProducer,
    'process-invocation-drift',
    'producer argv is neither the current process nor the fixed canonical writer invocation'
  );
  const expectedInvocation = makeLayerIndependent(
    'process/invocation',
    'producer-process-observation',
    [],
    {
      ...current,
      argv: [...invocation.metadata.argv],
      execArgv: [...invocation.metadata.execArgv],
    }
  );
  assertExactReconstructedLayer(
    invocation,
    expectedInvocation,
    'process-invocation-drift',
    'process-invocation-drift'
  );

  const environment = requiredLayerIndependent(
    layers,
    'process/environment',
    'process-environment-layer-missing'
  );
  const expectedEnvironment = makeLayerIndependent(
    'process/environment',
    'redacted-environment-observation',
    [],
    environmentReceiptIndependent()
  );
  const observedEnvironmentNames = environment.metadata?.semanticVariables?.map(({ name }) => name);
  const expectedEnvironmentNames = expectedEnvironment.metadata.semanticVariables.map(
    ({ name }) => name
  );
  assertion(
    sameArray(observedEnvironmentNames, expectedEnvironmentNames),
    'environment-selector-omitted',
    'semantic environment selector roster differs'
  );
  assertExactReconstructedLayer(
    environment,
    expectedEnvironment,
    'process-environment-drift',
    'process-environment-drift'
  );

  const cache = requiredLayerIndependent(layers, 'cache/tsx-global-current', 'cache-layer-missing');
  const expectedCache = cacheLayerIndependent();
  assertExactReconstructedLayer(cache, expectedCache, 'cache-layer-drift', 'cache-entry-omitted');
}

function verifyGitAndHostLayers(layers) {
  const gitRuntime = requiredLayerIndependent(
    layers,
    'tool/git-runtime',
    'git-runtime-layer-missing'
  );
  assertExactReconstructedLayer(
    gitRuntime,
    gitRuntimeLayerIndependent(),
    'git-runtime-layer-drift',
    'git-runtime-library-omitted'
  );

  const gitState = requiredLayerIndependent(
    layers,
    'tool/git-repository-state',
    'git-repository-state-layer-missing'
  );
  assertExactReconstructedLayer(
    gitState,
    gitRepositoryStateLayerIndependent(),
    'git-repository-state-drift',
    'git-repository-state-entry-omitted'
  );

  const host = requiredLayerIndependent(layers, 'host/context', 'host-context-layer-missing');
  assertExactReconstructedLayer(
    host,
    hostContextLayerIndependent(),
    'host-context-drift',
    'host-context-entry-omitted'
  );
}

function verifySpecialAnchors(layers) {
  const errorsLayer = layers.find(({ id }) => id === 'source/errors-ts');
  assertion(
    errorsLayer?.entries.length === 1 &&
      errorsLayer.entries[0].logicalPath === 'tools/governance/src/errors.ts' &&
      errorsLayer.entries[0].sha256 === EXPECTED.errorsSha256,
    'errors-ts-anchor-drift',
    'errors.ts is absent or changed'
  );

  const closureLayer = layers.find(({ id }) => id === 'evidence/h053-post-review-closure');
  const closureFiles = closureLayer?.entries.filter(({ kind }) => kind === 'regular-file');
  assertion(
    closureFiles?.length === 6 &&
      closureFiles.some(
        ({ logicalPath, sha256 }) =>
          logicalPath.endsWith('/closure.json') && sha256 === EXPECTED.h053ClosureSha256
      ),
    'h053-closure-stale',
    'H-053 closure layer differs'
  );

  const runLayer = layers.find(({ id }) => id === 'evidence/h053-canonical-run');
  const runFiles = runLayer?.entries.filter(({ kind }) => kind === 'regular-file');
  assertion(
    runFiles?.length === 1 &&
      runFiles[0].logicalPath.endsWith('/run.json') &&
      runFiles[0].sha256 === EXPECTED.h053RunRawSha256,
    'h053-run-stale',
    'H-053 run layer differs'
  );

  const nativeLayer = layers.find(({ id }) => id === 'native/esbuild-linux-x64@0.28.1');
  assertion(
    nativeLayer?.entries.length === 1 && nativeLayer.entries[0].sha256 === EXPECTED.esbuildSha256,
    'esbuild-native-drift',
    'esbuild native binary differs'
  );

  const gitLayer = layers.find(({ id }) => id === 'tool/git-runtime');
  const gitEntry = gitLayer?.entries.find(({ logicalPath }) => logicalPath === 'host/usr/bin/git');
  assertion(
    gitEntry?.kind === 'regular-file' && gitEntry.sha256 === EXPECTED.gitSha256,
    'git-executable-drift',
    'Git executable differs'
  );
}

function verifyLiveDescriptors(layers) {
  for (const layer of layers) {
    if (layer.id === 'source/main-git-tree') continue;
    for (const entry of layer.entries) {
      verifyFilesystemEntry(layer, entry);
    }
  }
}

function expectedLayerReceipts(layers) {
  return layers
    .map((layer) => expectedLayerReceipt(layer))
    .sort((left, right) => compareUtf8(left.id, right.id));
}

function snapshotRoot(anchors, receipts) {
  return canonicalHashIndependent({
    schemaVersion: 'overlaykit-h054-layer-set/v1',
    anchors,
    runtimeSelection: null,
    layers: receipts,
  });
}

function verifySnapshot(snapshot, subjectLock, invocationContext) {
  exactKeys(
    snapshot,
    [
      'anchors',
      'exactReceipts',
      'layerReceipts',
      'layers',
      'rootSha256',
      'runtimeCandidates',
      'runtimeSelection',
      'schemaVersion',
    ],
    'pre snapshot'
  );
  assertion(
    snapshot.schemaVersion === 'overlaykit-h054-inventory-snapshot/v1' &&
      snapshot.runtimeSelection === null &&
      Array.isArray(snapshot.layers) &&
      Array.isArray(snapshot.layerReceipts),
    'snapshot-shape-invalid',
    'pre snapshot'
  );
  verifyAnchors(snapshot.anchors);
  exactKeys(
    snapshot.exactReceipts,
    [
      'guardedRegularFileCount',
      'h053ApparatusRegularFileCount',
      'h053ApparatusSha256',
      'h053GuardedSurfaceSha256',
      'mainRecursiveEntryCount',
      'mainRecursiveLsTreeSha256',
      'packageRegularFileCount',
    ],
    'pre exact receipts'
  );
  assertion(
    snapshot.exactReceipts.mainRecursiveEntryCount === EXPECTED.mainEntryCount &&
      snapshot.exactReceipts.mainRecursiveLsTreeSha256 === EXPECTED.mainLsTreeSha256 &&
      snapshot.exactReceipts.guardedRegularFileCount === EXPECTED.guardedRegularFileCount &&
      snapshot.exactReceipts.h053GuardedSurfaceSha256 ===
        '4f3d19de30dc7df9819037004a27672a7b319693cc6fff54ad081a2999056ce8' &&
      snapshot.exactReceipts.h053ApparatusRegularFileCount ===
        EXPECTED.h053ApparatusRegularFileCount &&
      snapshot.exactReceipts.h053ApparatusSha256 === EXPECTED.h053ApparatusDescriptorSetSha256 &&
      snapshot.exactReceipts.packageRegularFileCount === EXPECTED_PACKAGE_REGULAR_FILE_COUNT,
    'exact-receipt-drift',
    'pre exact cardinality or digest receipts differ'
  );

  const layerIds = snapshot.layers.map(({ id }) => id);
  assertion(
    sameArray(layerIds, EXPECTED_LAYER_IDS) && new Set(layerIds).size === layerIds.length,
    'layer-roster-drift',
    `observed ${layerIds.join(',')}`
  );

  for (const [index, layer] of snapshot.layers.entries()) {
    verifyLayerShape(layer, index);
  }
  const receipts = expectedLayerReceipts(snapshot.layers);
  assertion(
    canonicalJsonIndependent(snapshot.layerReceipts) === canonicalJsonIndependent(receipts),
    'layer-receipt-drift',
    'pre layer receipts do not reproduce the layers'
  );
  assertion(
    snapshot.rootSha256 === snapshotRoot(snapshot.anchors, receipts),
    'inventory-root-invalid',
    'pre root does not reproduce anchors and layer receipts'
  );

  const mainLayer = snapshot.layers.find(({ id }) => id === 'source/main-git-tree');
  const mainPaths = verifyMainGitLayer(mainLayer);
  verifyGuardedLayer(
    snapshot.layers.find(({ id }) => id === 'source/guarded-worktree'),
    mainPaths
  );
  verifyH053Apparatus(snapshot.layers.find(({ id }) => id === 'apparatus/h053'));
  verifyH054Apparatus(
    snapshot.layers.find(({ id }) => id === 'apparatus/h054-producer'),
    subjectLock
  );
  verifyStaticRepositoryLayers(snapshot.layers);
  verifyPackages(snapshot.layers, subjectLock);
  verifyRuntimeCandidates(snapshot, snapshot.layers);
  verifyProcessAndCacheLayers(snapshot.layers, invocationContext);
  verifyGitAndHostLayers(snapshot.layers);
  verifySpecialAnchors(snapshot.layers);
  verifyLiveDescriptors(snapshot.layers);
  return receipts;
}

function verifyPostSnapshot(post, pre, receipts) {
  exactKeys(
    post,
    [
      'anchors',
      'exactReceipts',
      'layerReceipts',
      'rootSha256',
      'runtimeCandidates',
      'runtimeSelection',
      'schemaVersion',
    ],
    'post snapshot'
  );
  assertion(
    post.schemaVersion === 'overlaykit-h054-inventory-snapshot/v1' &&
      post.runtimeSelection === null &&
      canonicalJsonIndependent(post.anchors) === canonicalJsonIndependent(pre.anchors) &&
      canonicalJsonIndependent(post.runtimeCandidates) ===
        canonicalJsonIndependent(pre.runtimeCandidates) &&
      canonicalJsonIndependent(post.exactReceipts) ===
        canonicalJsonIndependent(pre.exactReceipts) &&
      canonicalJsonIndependent(post.layerReceipts) === canonicalJsonIndependent(receipts) &&
      post.rootSha256 === snapshotRoot(post.anchors, receipts) &&
      post.rootSha256 === pre.rootSha256,
    'pre-post-snapshot-drift',
    'post snapshot does not reproduce the independently reopened pre snapshot'
  );
}

function validateBoundArtifacts() {
  const subjectReceipt = readRegularFileStable(
    repositoryAbsolute(SUBJECT_LOCK_PATH),
    SUBJECT_LOCK_PATH
  );
  const fixtureReceipt = readRegularFileStable(repositoryAbsolute(FIXTURE_PATH), FIXTURE_PATH);
  assertion(
    sha256Independent(subjectReceipt.bytes) === EXPECTED.subjectLockSha256,
    'subject-lock-stale',
    SUBJECT_LOCK_PATH
  );
  assertion(
    sha256Independent(fixtureReceipt.bytes) === EXPECTED.fixtureSha256,
    'fixture-stale',
    FIXTURE_PATH
  );
  const subjectLock = parseJsonBytes(subjectReceipt.bytes, SUBJECT_LOCK_PATH);
  const fixture = parseJsonBytes(fixtureReceipt.bytes, FIXTURE_PATH);
  const runtimeIds = EXPECTED_RUNTIME_CANDIDATES.map(({ id }) => id);
  const subjectRuntimeIds = subjectLock.runtimePolicy?.candidates?.map(({ id }) => id);
  const inspector = readRegularFileStable('/usr/bin/ldd', '/usr/bin/ldd');
  assertion(
    subjectLock.schemaVersion === 'overlaykit-h054-subject-lock/v1' &&
      subjectLock.hypothesis === 'H-054' &&
      subjectLock.normative === false &&
      subjectLock.runtimePolicy?.selection === null &&
      sameArray(subjectRuntimeIds, runtimeIds) &&
      sameArray(subjectLock.packageSeedRoster, PACKAGE_SEEDS) &&
      sameArray(
        subjectLock.environmentSelectorRoster,
        [...SEMANTIC_ENVIRONMENT_KEYS].sort(compareUtf8)
      ) &&
      subjectLock.packageTraversalPolicy ===
        'Follow all installed dependencies and installed optionalDependencies from the human-nominated H-053 seeds; classify each absent optional dependency explicitly and fail on any absent required dependency.' &&
      subjectLock.packageEntryPointPolicy ===
        'Content-address declared exports and bin values inside complete installed trees; per-import and conditional export resolution remains not enumerated and methodologically incomplete.' &&
      subjectLock.preflightObservations?.dynamicLibraryInspector?.locator === '/usr/bin/ldd' &&
      subjectLock.preflightObservations.dynamicLibraryInspector.rawSha256 ===
        sha256Independent(inspector.bytes) &&
      subjectLock.preflightObservations.dynamicLibraryInspector.closure ===
        'opaque-not-recursively-closed' &&
      subjectLock.authority === 'none' &&
      subjectLock.action === null &&
      sameArray(subjectLock.layerRoster, EXPECTED_LAYER_IDS) &&
      sameArray(subjectLock.controlIds, CONTROL_IDS),
    'subject-lock-shape-invalid',
    SUBJECT_LOCK_PATH
  );
  assertion(
    fixture.schemaVersion === 'overlaykit-h054-adversarial-boundary-fixture/v1' &&
      fixture.hypothesis === 'H-054' &&
      fixture.normative === false &&
      fixture.synthetic === true &&
      fixture.runtimeSelection === null &&
      fixture.authority === 'none' &&
      fixture.action === null &&
      Array.isArray(fixture.mutations) &&
      sameArray(
        fixture.mutations.map(({ id }) => id),
        CONTROL_IDS
      ),
    'fixture-shape-invalid',
    FIXTURE_PATH
  );
  return { subjectLock, fixture };
}

function compositeKey(value) {
  return `${value.layerId}\0${value.logicalPath}`;
}

function fixtureGraphHash(graph) {
  return canonicalHashIndependent({
    layers: graph.layers,
    entries: graph.entries,
    edges: graph.edges,
  });
}

function fixtureEntryMap(entries) {
  const map = new Map();
  for (const entry of entries) {
    assertion(
      typeof entry.layerId === 'string' && typeof entry.logicalPath === 'string',
      'fixture-entry-invalid',
      'fixture entry lacks a composite identity'
    );
    const key = compositeKey(entry);
    assertion(!map.has(key), 'fixture-entry-collision', key);
    if (Object.hasOwn(entry, 'contentUtf8')) {
      assertion(
        entry.sha256 === sha256Independent(Buffer.from(entry.contentUtf8, 'utf8')),
        'fixture-preimage-invalid',
        key
      );
    }
    if (Object.hasOwn(entry, 'linkTextSha256')) {
      assertion(
        entry.linkTextSha256 === sha256Independent(Buffer.from(entry.linkText, 'utf8')),
        'fixture-preimage-invalid',
        key
      );
    }
    map.set(key, entry);
  }
  return map;
}

function expectedOmissionReason(target) {
  const key = compositeKey(target);
  const reasons = new Map([
    ['h053-execution-only\0tools/governance/src/errors.ts', 'required-entry-omitted'],
    ['package-runtime\0node_modules/ajv/dist/core.js', 'required-package-entry-omitted'],
    [
      'native-binaries\0node_modules/@esbuild/linux-x64/bin/esbuild',
      'required-native-binary-omitted',
    ],
    ['node22-candidate\0usr/bin/node-22', 'runtime-dependency-omitted'],
    ['shared-libraries\0lib/libnode.so', 'runtime-dependency-omitted'],
    ['git-runtime\0bin/git', 'git-runtime-dependency-omitted'],
    ['shared-libraries\0lib/libgit-synthetic.so', 'git-runtime-dependency-omitted'],
    ['process-environment\0TSX_DISABLE_CACHE', 'environment-selector-omitted'],
  ]);
  return reasons.get(key) ?? null;
}

function resolveSyntheticLink(logicalPath, linkText) {
  assertion(!path.posix.isAbsolute(linkText), 'fixture-symlink-invalid', 'synthetic absolute link');
  return path.posix.normalize(path.posix.join(path.posix.dirname(logicalPath), linkText));
}

function independentlyApplyMutation(fixture, mutation) {
  const baselineEntries = structuredClone(fixture.baseGraph.entries);
  const baselineMap = fixtureEntryMap(baselineEntries);
  const baselineGraphHash = fixtureGraphHash(fixture.baseGraph);
  const variants = [];
  let observedReasonCode = null;

  if (mutation.kind === 'omit-entry') {
    const targetKey = compositeKey(mutation.target);
    assertion(baselineMap.has(targetKey), 'control-precondition-failed', mutation.id);
    const entries = baselineEntries.filter((entry) => compositeKey(entry) !== targetKey);
    assertion(entries.length === baselineEntries.length - 1, 'control-failed', mutation.id);
    observedReasonCode = expectedOmissionReason(mutation.target);
  } else if (mutation.kind === 'omit-entry-variants') {
    assertion(
      Array.isArray(mutation.targets) && mutation.targets.length > 0,
      'control-precondition-failed',
      mutation.id
    );
    for (const target of mutation.targets) {
      const targetKey = compositeKey(target);
      assertion(baselineMap.has(targetKey), 'control-precondition-failed', targetKey);
      const entries = baselineEntries.filter((entry) => compositeKey(entry) !== targetKey);
      assertion(entries.length === baselineEntries.length - 1, 'control-failed', targetKey);
      variants.push(expectedOmissionReason(target));
    }
    assertion(
      variants.every((reason) => reason !== null && reason === variants[0]),
      'control-failed',
      mutation.id
    );
    observedReasonCode = variants[0];
  } else if (mutation.kind === 'replace-anchor-digest') {
    if (mutation.target === 'main.tree') {
      assertion(
        mutation.replacement !== EXPECTED.mainTree && /^[0-9a-f]{40}$/u.test(mutation.replacement),
        'control-failed',
        mutation.id
      );
      observedReasonCode = 'main-anchor-stale';
    } else if (mutation.target === 'h053PostReviewClosure.rawSha256') {
      assertion(
        mutation.replacement !== EXPECTED.h053ClosureSha256 &&
          /^[0-9a-f]{64}$/u.test(mutation.replacement),
        'control-failed',
        mutation.id
      );
      observedReasonCode = 'h053-closure-stale';
    }
  } else if (mutation.kind === 'replace-entry-content-and-rehash-envelope') {
    const targetKey = compositeKey(mutation.target);
    const target = baselineMap.get(targetKey);
    assertion(target !== undefined, 'control-precondition-failed', mutation.id);
    const entries = baselineEntries.map((entry) =>
      compositeKey(entry) === targetKey
        ? {
            ...entry,
            contentUtf8: mutation.replacementContentUtf8,
            sha256: sha256Independent(Buffer.from(mutation.replacementContentUtf8, 'utf8')),
          }
        : entry
    );
    const changedGraphHash = fixtureGraphHash({ ...fixture.baseGraph, entries });
    assertion(changedGraphHash !== baselineGraphHash, 'control-failed', mutation.id);
    observedReasonCode = 'apparatus-stale';
  } else if (mutation.kind === 'replace-symlink-target') {
    const targetKey = compositeKey(mutation.target);
    const target = baselineMap.get(targetKey);
    assertion(target?.kind === 'symbolic-link', 'control-precondition-failed', mutation.id);
    const entries = baselineEntries.map((entry) =>
      compositeKey(entry) === targetKey
        ? {
            ...entry,
            linkText: mutation.replacementLinkText,
            linkTextSha256: sha256Independent(Buffer.from(mutation.replacementLinkText, 'utf8')),
            targetLayerId: mutation.replacementTarget.layerId,
            targetLogicalPath: mutation.replacementTarget.logicalPath,
          }
        : entry
    );
    assertion(
      fixtureGraphHash({ ...fixture.baseGraph, entries }) !== baselineGraphHash,
      'control-failed',
      mutation.id
    );
    observedReasonCode = 'symlink-chain-drift';
  } else if (mutation.kind === 'symlink-invalid-variants') {
    const targetKey = compositeKey(mutation.target);
    const target = baselineMap.get(targetKey);
    assertion(target?.kind === 'symbolic-link', 'control-precondition-failed', mutation.id);
    for (const variant of mutation.variants) {
      const resolved = resolveSyntheticLink(target.logicalPath, variant.linkText);
      if (resolved === target.logicalPath) {
        variants.push('symlink-cycle');
      } else if (
        resolved === '..' ||
        resolved.startsWith('../') ||
        path.posix.isAbsolute(resolved)
      ) {
        variants.push('symlink-boundary-escape');
      } else {
        variants.push('symlink-unclassified');
      }
    }
    assertion(
      variants.length === 2 &&
        variants[0] === 'symlink-cycle' &&
        variants[1] === 'symlink-boundary-escape',
      'control-failed',
      mutation.id
    );
    observedReasonCode = 'symlink-invalid';
  } else if (mutation.kind === 'deduplicate-by-logical-path') {
    const matching = baselineEntries.filter(
      ({ logicalPath }) => logicalPath === mutation.targetLogicalPath
    );
    const flattened = new Map(matching.map((entry) => [entry.logicalPath, entry]));
    assertion(
      matching.length === mutation.expectedOriginalCardinality &&
        flattened.size === mutation.expectedFlattenedCardinality &&
        matching.length === 3 &&
        flattened.size === 1,
      'control-failed',
      mutation.id
    );
    observedReasonCode = 'layer-qualified-cardinality-drift';
  }

  assertion(
    observedReasonCode !== null,
    'control-kind-unclassified',
    `${mutation.id}:${mutation.kind}`
  );
  assertion(
    mutation.expectedReasonCode === observedReasonCode,
    'control-reason-drift',
    `${mutation.id}: expected ${mutation.expectedReasonCode}, observed ${observedReasonCode}`
  );
  if (Array.isArray(mutation.variants)) {
    assertion(
      sameArray(
        mutation.variants.map(({ expectedReasonCode }) => expectedReasonCode),
        variants
      ),
      'control-variant-reason-drift',
      mutation.id
    );
  }
  return {
    id: mutation.id,
    passed: true,
    expectedReasonCode: mutation.expectedReasonCode,
    observedReasonCode,
    variantReasonCodes: variants,
  };
}

export function reapplyH054Controls(fixture) {
  assertion(
    Array.isArray(fixture?.mutations) &&
      sameArray(
        fixture.mutations.map(({ id }) => id),
        CONTROL_IDS
      ),
    'control-roster-invalid',
    'fixture control roster differs'
  );
  fixtureEntryMap(fixture.baseGraph.entries);
  return fixture.mutations.map((mutation) => independentlyApplyMutation(fixture, mutation));
}

function collectOpenEligibilityIssues(run) {
  const issues = [];
  if (run.runtimeSelection === null) {
    issues.push('runtime-selection-unresolved');
  }
  if (run.inventory?.historicalReconstruction?.h053Closed !== true) {
    issues.push('historical-h053-not-closed');
  }
  if ((run.inventory?.historicalReconstruction?.missing ?? []).length > 0) {
    issues.push('historical-inputs-irrecoverable');
  }
  if (run.capabilityAudit?.closed !== true) {
    issues.push('capability-boundary-open');
  }
  if ((run.capabilityAudit?.unknowns ?? []).length > 0) {
    issues.push('capability-unknowns-present');
  }

  for (const layer of run.inventory.pre.layers) {
    for (const entry of layer.entries) {
      if (
        entry.kind === 'unsupported-special-file' ||
        (typeof entry.classification === 'string' &&
          /opaque|irrecoverable|unclassified|unresolved/iu.test(entry.classification))
      ) {
        issues.push(`${layer.id}:${entry.logicalPath}:entry-open`);
      }
    }
    const metadata = layer.metadata;
    if (
      Array.isArray(metadata?.irrecoverableOrOpaque) &&
      metadata.irrecoverableOrOpaque.length > 0
    ) {
      issues.push(`${layer.id}:irrecoverable-or-opaque`);
    }
    if (metadata?.historicalH053Attribution === 'irrecoverable') {
      issues.push(`${layer.id}:historical-attribution-irrecoverable`);
    }
    if (
      typeof metadata?.eligibility === 'string' &&
      metadata.eligibility.includes('not-successor-boundary-eligible')
    ) {
      issues.push(`${layer.id}:not-successor-boundary-eligible`);
    }
    if (
      metadata?.dynamicLibraries?.status !== undefined &&
      (metadata.dynamicLibraries.status !== 'resolved-with-virtual-context' ||
        (metadata.dynamicLibraries.unresolvedLibraries?.length ?? 0) > 0 ||
        (metadata.dynamicLibraries.unparsedLines?.length ?? 0) > 0 ||
        metadata.dynamicLibraryInspectorClosure === 'opaque-not-recursively-closed')
    ) {
      issues.push(`${layer.id}:dynamic-libraries-open`);
    }
    if (
      Array.isArray(metadata?.pathResolutions) &&
      metadata.pathResolutions.some(({ status }) => status !== 'resolved')
    ) {
      issues.push(`${layer.id}:path-resolution-open`);
    }
    if (
      Number.isSafeInteger(metadata?.unclassifiedNameCount) &&
      metadata.unclassifiedNameCount > 0
    ) {
      issues.push(`${layer.id}:environment-unclassified`);
    }
    if (
      metadata?.packageEntryPointResolution?.classification ===
      'whole-tree-inventoried-per-import-and-export-condition-resolution-not-enumerated'
    ) {
      issues.push(`${layer.id}:package-entry-point-resolution-open`);
    }
  }
  return [...new Set(issues)].sort(compareUtf8);
}

function independentlyBlockingClassifications(snapshot) {
  const environment = requiredLayerIndependent(snapshot.layers, 'process/environment');
  const cache = requiredLayerIndependent(snapshot.layers, 'cache/tsx-global-current');
  const host = requiredLayerIndependent(snapshot.layers, 'host/context');
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
          (metadata.dynamicLibraries.unresolvedLibraries?.length ?? 0) > 0 ||
          (metadata.dynamicLibraries.unparsedLines?.length ?? 0) > 0 ||
          metadata.dynamicLibraryInspectorClosure === 'opaque-not-recursively-closed')
    )
    .map(({ id }) => id)
    .sort(compareUtf8);
  const packageEntryPointOpenLayers = snapshot.layers
    .filter(
      ({ metadata }) =>
        metadata?.packageEntryPointResolution?.classification ===
        'whole-tree-inventoried-per-import-and-export-condition-resolution-not-enumerated'
    )
    .map(({ id }) => id)
    .sort(compareUtf8);
  return [
    {
      id: 'runtime-selection-null',
      classification: 'unresolved-human-selection',
      count: snapshot.runtimeSelection === null ? 1 : 0,
    },
    {
      id: 'historical-h053-cache-attribution',
      classification: cache.metadata.historicalH053Attribution,
      count: cache.metadata.historicalH053Attribution === 'irrecoverable' ? 1 : 0,
    },
    {
      id: 'unclassified-environment-values',
      classification: environment.metadata.unclassifiedValues,
      count: environment.metadata.unclassifiedNameCount,
    },
    {
      id: 'opaque-host-execution-context',
      classification: 'irrecoverable-or-opaque',
      count: host.metadata.irrecoverableOrOpaque.length,
    },
    {
      id: 'opaque-entry-classifications',
      classification: 'opaque-entry',
      count: opaqueEntries.length,
      entrySetSha256: canonicalHashIndependent(opaqueEntries),
    },
    {
      id: 'dynamic-library-inspector-closure',
      classification: 'opaque-not-recursively-closed',
      count: dynamicLibraryOpenLayers.length,
      layerSetSha256: canonicalHashIndependent(dynamicLibraryOpenLayers),
    },
    {
      id: 'package-entry-point-resolution-method',
      classification: 'methodologically-incomplete',
      count: packageEntryPointOpenLayers.length,
      layerSetSha256: canonicalHashIndependent(packageEntryPointOpenLayers),
    },
  ].filter(({ count }) => count > 0);
}

function verifyRunEnvelope(run) {
  exactKeys(run, RUN_TOP_LEVEL_KEYS, 'run');
  assertion(
    run.schemaVersion === 'overlaykit-h054-executable-boundary-inventory-run/v1' &&
      run.hypothesis === 'H-054' &&
      run.normative === false &&
      run.authority === 'none' &&
      run.action === null,
    'run-envelope-invalid',
    'run identity or authority differs'
  );
  assertion(
    typeof run.semanticSha256 === 'string' && /^[0-9a-f]{64}$/u.test(run.semanticSha256),
    'run-identity-invalid',
    'semantic SHA-256 is malformed'
  );
  const { runId: _runId, semanticSha256: _semanticSha256, ...body } = run;
  const semanticSha256 = canonicalHashIndependent(body);
  assertion(
    semanticSha256 === run.semanticSha256 && run.runId === `h054-${semanticSha256.slice(0, 24)}`,
    'run-identity-invalid',
    'semantic hash or run ID differs'
  );
  return semanticSha256;
}

function verifyCapabilityAndInterpretation(run) {
  const expectedCapabilityAudit = {
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
  };
  const expectedInterpretation = {
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
  };
  assertion(
    canonicalJsonIndependent(run.capabilityAudit) ===
      canonicalJsonIndependent(expectedCapabilityAudit),
    'unauthorized-capability-recorded',
    'capability audit differs from the closed producer contract'
  );
  assertion(
    canonicalJsonIndependent(run.interpretation) ===
      canonicalJsonIndependent(expectedInterpretation),
    'self-approval-or-runtime-selection',
    'interpretation self-approves, selects a runtime, creates an ADR, or overclaims scope'
  );
}

function verifyH054RunInContext(run, invocationContext) {
  const semanticSha256 = verifyRunEnvelope(run);
  const { subjectLock, fixture } = validateBoundArtifacts();
  assertion(
    run.runtimeSelection === null &&
      run.inventory?.pre?.runtimeSelection === null &&
      run.inventory?.post?.runtimeSelection === null,
    'runtime-selection-not-null',
    'H-054 selected a runtime'
  );
  exactKeys(
    run.inventory,
    [
      'classification',
      'historicalReconstruction',
      'post',
      'pre',
      'stability',
      'successorEligibility',
    ],
    'inventory'
  );
  assertion(
    run.inventory.classification === 'current-host-layer-qualified-inventory-only' &&
      canonicalJsonIndependent(run.inventory.historicalReconstruction) ===
        canonicalJsonIndependent({
          h053Closed: false,
          classification: 'irrecoverable',
          missing: [
            'exact inherited H-053 argv and execArgv',
            'exact inherited H-053 environment',
            'exact H-053 cwd and umask',
            'exact pre-run global tsx cache state and cache attribution',
            'syscall trace or enforced capability allowlist',
          ],
        }) &&
      canonicalJsonIndependent(run.inventory.successorEligibility) ===
        canonicalJsonIndependent({
          h055Ready: false,
          reason: 'human runtime selection and separate governed experiment remain required',
        }),
    'inventory-classification-drift',
    'historical reconstruction or successor eligibility overclaims closure'
  );
  exactKeys(
    run.controlContract,
    ['controlIds', 'fixtureRawSha256', 'subjectLockRawSha256'],
    'control contract'
  );
  assertion(
    sameArray(run.controlContract.controlIds, CONTROL_IDS) &&
      run.controlContract.subjectLockRawSha256 === EXPECTED.subjectLockSha256 &&
      run.controlContract.fixtureRawSha256 === EXPECTED.fixtureSha256,
    'control-contract-drift',
    'control contract does not bind the exact subject lock and fixture'
  );
  const receipts = verifySnapshot(run.inventory.pre, subjectLock, invocationContext);
  assertion(
    canonicalJsonIndependent(run.anchors) === canonicalJsonIndependent(run.inventory.pre.anchors),
    'run-anchor-drift',
    'top-level anchors differ from the independently reconstructed snapshot'
  );
  verifyPostSnapshot(run.inventory.post, run.inventory.pre, receipts);
  exactKeys(
    run.inventory.stability,
    ['changedLayers', 'postRootSha256', 'preRootSha256', 'stable'],
    'inventory stability'
  );
  assertion(
    run.inventory.stability.stable === true &&
      Array.isArray(run.inventory.stability.changedLayers) &&
      run.inventory.stability.changedLayers.length === 0 &&
      run.inventory.stability.preRootSha256 === run.inventory.pre.rootSha256 &&
      run.inventory.stability.postRootSha256 === run.inventory.post.rootSha256,
    'inventory-stability-drift',
    'producer pre/post stability receipt differs'
  );
  verifyCapabilityAndInterpretation(run);

  const independentControls = reapplyH054Controls(fixture);
  assertion(
    canonicalJsonIndependent(run.controls) === canonicalJsonIndependent(independentControls),
    'control-roster-or-receipt-drift',
    'producer controls do not match twelve independently reapplied controls'
  );

  const outcome = run.experiment?.outcome;
  exactKeys(run.experiment, ['outcome'], 'experiment');
  exactKeys(
    outcome,
    [
      'action',
      'authority',
      'blockingClassifications',
      'claimBoundary',
      'failedControlIds',
      'reason',
      'reasonCode',
      'status',
    ],
    'experiment outcome'
  );
  assertion(
    outcome.authority === 'none' &&
      outcome.action === null &&
      outcome.reason === 'runtime-selection-null-or-boundary-input-unclosed' &&
      outcome.reasonCode === outcome.reason &&
      outcome.claimBoundary ===
        'offline/read-only inventory stability and explicit classification on this host only' &&
      Array.isArray(outcome.blockingClassifications) &&
      outcome.blockingClassifications.length > 0 &&
      Array.isArray(outcome.failedControlIds) &&
      outcome.failedControlIds.length === 0 &&
      ['supported', 'refuted', 'inconclusive', 'invalid'].includes(outcome.status),
    'outcome-invalid',
    'outcome identity differs'
  );
  const reconstructedBlockingClassifications = independentlyBlockingClassifications(
    run.inventory.pre
  );
  assertion(
    canonicalJsonIndependent(outcome.blockingClassifications) ===
      canonicalJsonIndependent(reconstructedBlockingClassifications),
    'blocking-classification-drift',
    'producer blocking classifications differ from independently reconstructed open layers'
  );

  const openIssues = collectOpenEligibilityIssues(run);
  assertion(
    !(outcome.status === 'supported' && (run.runtimeSelection === null || openIssues.length > 0)),
    'supported-with-open-boundary',
    `supported is forbidden with: ${openIssues.join(',')}`
  );
  assertion(
    outcome.status === 'inconclusive',
    'outcome-polarity-invalid',
    'the independently reconstructed runtime-null/open inventory is inconclusive'
  );
  assertion(
    run.inventory.successorEligibility?.h055Ready === false &&
      typeof run.inventory.successorEligibility?.reason === 'string',
    'h055-readiness-overclaim',
    'H-055 readiness must remain false'
  );

  return {
    schemaVersion: 'overlaykit-h054-independent-verification/v1',
    hypothesis: 'H-054',
    runId: run.runId,
    semanticSha256,
    inventoryRootSha256: run.inventory.pre.rootSha256,
    layerCount: run.inventory.pre.layers.length,
    mainEntryCount: EXPECTED.mainEntryCount,
    guardedRegularFileCount: EXPECTED.guardedRegularFileCount,
    h053ApparatusRegularFileCount: EXPECTED.h053ApparatusRegularFileCount,
    packageRegularFileCount: EXPECTED_PACKAGE_REGULAR_FILE_COUNT,
    runtimeSelection: null,
    controlCount: independentControls.length,
    controls: independentControls,
    openIssues,
    outcome: {
      status: 'inconclusive',
      supportEligible: false,
      h055Ready: false,
    },
    authority: 'none',
    action: null,
  };
}

export function verifyH054Run(run) {
  return verifyH054RunInContext(run, 'same-process');
}

function assertNoSymlinkAncestors(root, target) {
  const absoluteRoot = path.resolve(root);
  const absoluteTarget = path.resolve(target);
  const relative = path.relative(absoluteRoot, absoluteTarget);
  assertion(
    relative !== '' &&
      relative !== '..' &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative),
    'run-path-invalid',
    absoluteTarget
  );
  let current = absoluteRoot;
  for (const component of relative.split(path.sep)) {
    current = path.join(current, component);
    const metadata = lstatSync(current);
    assertion(!metadata.isSymbolicLink(), 'run-path-symlink', current);
  }
}

function assertDirectorySafety(directory, expectedMode, reasonCode) {
  const metadata = lstatSync(directory);
  assertion(
    metadata.isDirectory() && !metadata.isSymbolicLink() && metadata.nlink >= 1,
    reasonCode,
    directory
  );
  if (expectedMode !== null) {
    assertion((metadata.mode & 0o777) === expectedMode, reasonCode, directory);
  }
}

export function verifyH054File(runPath) {
  const absolutePath = path.resolve(runPath);
  const artifactsRoot = path.join(REPOSITORY_ROOT, 'artifacts');
  const h054Root = path.join(artifactsRoot, 'h054');
  const runsRoot = path.join(h054Root, 'runs');
  const relative = path.relative(runsRoot, absolutePath);
  assertion(
    /^[0-9a-f]{64}[/\\]run\.json$/u.test(relative),
    'run-path-invalid',
    `expected artifacts/h054/runs/<semantic-sha256>/run.json: ${runPath}`
  );
  assertNoSymlinkAncestors(REPOSITORY_ROOT, absolutePath);
  assertDirectorySafety(artifactsRoot, null, 'run-root-unsafe');
  assertDirectorySafety(h054Root, 0o700, 'run-root-unsafe');
  assertDirectorySafety(runsRoot, 0o700, 'run-root-unsafe');
  assertDirectorySafety(path.dirname(absolutePath), 0o700, 'run-directory-unsafe');
  const { bytes, metadata } = readRegularFileStable(absolutePath, runPath);
  assertion((metadata.mode & 0o777) === 0o600 && metadata.nlink === 1, 'run-file-unsafe', runPath);
  const run = parseJsonBytes(bytes, runPath);
  assertion(
    bytes.equals(Buffer.from(canonicalPrettyJsonIndependent(run), 'utf8')),
    'run-serialization-noncanonical',
    runPath
  );
  const receipt = verifyH054RunInContext(run, 'canonical-writer-file');
  assertion(
    path.basename(path.dirname(absolutePath)) === receipt.semanticSha256,
    'run-path-content-mismatch',
    runPath
  );
  return {
    ...receipt,
    rawSha256: sha256Independent(bytes),
    byteLength: bytes.length,
    path: path.relative(REPOSITORY_ROOT, absolutePath),
  };
}

function main() {
  const args = process.argv.slice(2);
  assertion(args.length === 1, 'usage-invalid', 'usage: node lab/h054/verify.mjs <run.json>');
  process.stdout.write(`${canonicalJsonIndependent(verifyH054File(args[0]))}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    const receipt = {
      schemaVersion: 'overlaykit-h054-independent-verification-failure/v1',
      hypothesis: 'H-054',
      verified: false,
      reasonCode:
        error instanceof InvalidH054VerificationError
          ? error.reasonCode
          : 'unexpected-verifier-error',
      message: error instanceof Error ? error.message : String(error),
      authority: 'none',
      action: null,
    };
    process.stderr.write(`${canonicalJsonIndependent(receipt)}\n`);
    process.exitCode = 1;
  }
}
