import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const LAB_DIRECTORY = realpathSync(path.dirname(fileURLToPath(import.meta.url)));
const REPOSITORY_ROOT = realpathSync(path.resolve(LAB_DIRECTORY, '../..'));
const EXPECTED_COMBINED_SOURCE_SET_SHA256 =
  'd257830144a01545cd4bdd11c3209481adc54dc6d47603eb8273f6884f17a54f';
const EXPECTED_GIT_SOURCE_SET_SHA256 =
  '6031fbc61fc8ccf1be86b712f8d718412a449fe3f393d8fca59fb820473169dd';
const EXPECTED_LOCAL_SOURCE_SET_SHA256 =
  '45f826086a17aaacdfc0b7dbd8ef2046cfe4044f34ef34c3d1536c783b632f8a';
const EXPECTED_RESTRICTED_TREE_SHA256 =
  '20e85f20358fe0b186281d3ff006074ccfcdd3de72c2e2fbe1255283326667ac';
const EXPECTED_COMMIT = '16d0d29b32eb80603c17cc1cb1e3ed1265787008';
const EXPECTED_TREE = '0bff82e4d790b8fc133810230f28590c6b518bc7';
const EXPECTED_PRE_H053_MANIFEST_SHA256 =
  '888e02e5605c6387c83644bacb049761451605d2c27b501b14f0b8d826af2666';
const EXPECTED_H052_ARCHIVE_SHA256 =
  '460a524ea707ede8aef7529e7fb7f37395d96cabd1cad9f04d9ac2f42c0df33f';
const CONSUMED_WORKTREE_INPUT_PATHS = Object.freeze([
  '.overlaykit/governance/plan.json',
  '.overlaykit/governance/profile.json',
  '.overlaykit/governance/schemas/profile.schema.json',
  '.overlaykit/governance/schemas/specification.schema.json',
  '.overlaykit/governance/specifications/SPEC-0001.json',
  '.overlaykit/governance/specifications/SPEC-0002.json',
]);
const EXECUTED_FIRST_PARTY_SOURCE_PATHS = Object.freeze([
  'tools/governance/src/canonical.ts',
  'tools/governance/src/compiler.ts',
  'tools/governance/src/errors.ts',
  'tools/governance/src/manifest.ts',
  'tools/governance/src/projector.ts',
  'tools/governance/src/types.ts',
  'tools/governance/src/validator.ts',
]);
const EXECUTION_DEPENDENCY_PATHS = Object.freeze([
  ...CONSUMED_WORKTREE_INPUT_PATHS,
  ...EXECUTED_FIRST_PARTY_SOURCE_PATHS,
]);
const NOMINATED_NOT_EXECUTED_SOURCE_PATHS = Object.freeze(['tools/governance/src/repository.ts']);

export class InvalidH053SourceError extends Error {
  constructor(reasonCode, message) {
    super(message);
    this.name = 'InvalidH053SourceError';
    this.reasonCode = reasonCode;
  }
}

function assertion(condition, reasonCode, message) {
  if (!condition) {
    throw new InvalidH053SourceError(reasonCode, message);
  }
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

// This is deliberately not the governance host canonicalizer. H-053 was nominated
// with the earlier evidence canonicalizer, whose default Array#sort ordering is
// part of the accepted preimage.
export function nominatedCanonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => nominatedCanonicalJson(entry)).join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${nominatedCanonicalJson(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

export function nominatedCanonicalHash(value) {
  return sha256(Buffer.from(nominatedCanonicalJson(value), 'utf8'));
}

function exactKeys(value, expected, label) {
  assertion(
    value !== null && typeof value === 'object' && !Array.isArray(value),
    'subject-lock-shape-invalid',
    `${label} must be an object`
  );
  assertion(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort()),
    'subject-lock-shape-invalid',
    `${label} keys differ`
  );
}

function assertCanonicalRelativePath(value) {
  assertion(typeof value === 'string' && value.length > 0, 'source-path-invalid', 'empty path');
  assertion(!path.posix.isAbsolute(value), 'source-path-invalid', `absolute path: ${value}`);
  assertion(!value.includes('\\'), 'source-path-invalid', `alternate separator: ${value}`);
  assertion(
    value === path.posix.normalize(value),
    'source-path-invalid',
    `non-canonical path: ${value}`
  );
  assertion(
    !value.split('/').some((part) => part === '' || part === '.' || part === '..'),
    'source-path-invalid',
    `unsafe path: ${value}`
  );
}

function assertRoster(paths, label) {
  for (const sourcePath of paths) {
    assertCanonicalRelativePath(sourcePath);
  }
  assertion(new Set(paths).size === paths.length, 'source-roster-invalid', `${label} duplicates`);
  assertion(
    JSON.stringify(paths) === JSON.stringify([...paths].sort()),
    'source-roster-invalid',
    `${label} is not in nominated bytewise order`
  );
}

function gitEnvironment() {
  return {
    PATH: '/usr/bin:/usr/local/bin:/bin',
    LANG: 'C',
    LC_ALL: 'C',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_SYSTEM: '/dev/null',
    GIT_NO_LAZY_FETCH: '1',
    GIT_OPTIONAL_LOCKS: '0',
  };
}

function defaultGitReader(args) {
  const allowed = new Set(['cat-file', 'ls-tree', 'rev-parse']);
  assertion(
    Array.isArray(args) && args.length > 0 && allowed.has(args[0]),
    'git-operation-not-allowed',
    'Git operation is outside the read-only allowlist'
  );
  return execFileSync('/usr/bin/git', args, {
    cwd: REPOSITORY_ROOT,
    env: gitEnvironment(),
    encoding: null,
    maxBuffer: 8 * 1024 * 1024,
    windowsHide: true,
  });
}

function parseLsTree(bytes) {
  return bytes
    .toString('utf8')
    .split('\0')
    .filter(Boolean)
    .map((record) => {
      const match = /^(?<mode>[0-9]{6}) (?<type>[a-z]+) (?<oid>[0-9a-f]{40})\t(?<path>.+)$/u.exec(
        record
      );
      assertion(match !== null, 'git-tree-output-invalid', 'Malformed git ls-tree record');
      return match.groups;
    });
}

function assertNoSymlinkAncestors(relativePath) {
  let current = REPOSITORY_ROOT;
  for (const component of relativePath.split('/')) {
    current = path.join(current, component);
    const stats = lstatSync(current);
    assertion(
      !stats.isSymbolicLink(),
      'local-source-symlink',
      `Symlink in local source path: ${relativePath}`
    );
  }
}

function readExactLocalSource(descriptor) {
  assertCanonicalRelativePath(descriptor.path);
  const absolutePath = path.resolve(REPOSITORY_ROOT, descriptor.path);
  assertion(
    absolutePath.startsWith(`${REPOSITORY_ROOT}${path.sep}`),
    'source-path-invalid',
    `Local source escapes repository: ${descriptor.path}`
  );
  assertNoSymlinkAncestors(descriptor.path);
  const stats = lstatSync(absolutePath);
  assertion(stats.isFile(), 'local-source-type-invalid', `Not a file: ${descriptor.path}`);
  assertion(stats.nlink === 1, 'local-source-hardlink', `Hard-linked source: ${descriptor.path}`);
  const mode = (stats.mode & 0o777).toString(8).padStart(4, '0');
  assertion(mode === descriptor.mode, 'local-source-mode-drift', descriptor.path);
  const bytes = readFileSync(absolutePath);
  assertion(
    bytes.length === descriptor.byteLength && sha256(bytes) === descriptor.sha256,
    'local-source-byte-drift',
    descriptor.path
  );
  return bytes;
}

function bindExecutionDependency(sourcePath, descriptor) {
  assertCanonicalRelativePath(sourcePath);
  const absolutePath = path.resolve(REPOSITORY_ROOT, sourcePath);
  assertNoSymlinkAncestors(sourcePath);
  const stats = lstatSync(absolutePath);
  assertion(
    stats.isFile() && stats.nlink === 1 && (stats.mode & 0o777) === 0o644,
    'executed-worktree-source-unsafe',
    sourcePath
  );
  const bytes = readFileSync(absolutePath);
  if (descriptor !== undefined) {
    assertion(
      bytes.length === descriptor.byteLength && sha256(bytes) === descriptor.sha256,
      'executed-worktree-source-drift',
      sourcePath
    );
  }
  return {
    path: sourcePath,
    byteLength: bytes.length,
    sha256: sha256(bytes),
    admittedToNominatedBoundary: descriptor !== undefined,
  };
}

function tarString(header, start, length) {
  const field = header.subarray(start, start + length);
  const nul = field.indexOf(0);
  return field.subarray(0, nul === -1 ? field.length : nul).toString('utf8');
}

function tarSize(header) {
  const value = tarString(header, 124, 12).trim();
  assertion(/^[0-7]+$/u.test(value), 'recovery-archive-invalid', 'Non-octal tar size');
  return Number.parseInt(value, 8);
}

export function extractRegularTarMember(archiveBytes, expectedPath) {
  assertCanonicalRelativePath(expectedPath);
  let offset = 0;
  let match = null;
  let zeroBlocks = 0;
  while (offset + 512 <= archiveBytes.length) {
    const header = archiveBytes.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      zeroBlocks += 1;
      offset += 512;
      continue;
    }
    assertion(zeroBlocks === 0, 'recovery-archive-invalid', 'Data follows tar terminator');
    const name = tarString(header, 0, 100);
    const prefix = tarString(header, 345, 155);
    const memberPath = prefix === '' ? name : `${prefix}/${name}`;
    const type = header[156];
    const size = tarSize(header);
    const dataStart = offset + 512;
    const dataEnd = dataStart + size;
    assertion(dataEnd <= archiveBytes.length, 'recovery-archive-invalid', 'Truncated tar member');
    if (memberPath === expectedPath) {
      assertion(
        type === 0 || type === 48,
        'recovery-archive-invalid',
        'Recovery member is not regular'
      );
      assertion(match === null, 'recovery-archive-invalid', 'Duplicate recovery member');
      match = Buffer.from(archiveBytes.subarray(dataStart, dataEnd));
    }
    offset = dataStart + Math.ceil(size / 512) * 512;
  }
  assertion(zeroBlocks >= 2, 'recovery-archive-invalid', 'Tar terminator is incomplete');
  assertion(match !== null, 'recovery-member-missing', expectedPath);
  return match;
}

export function parseSubjectLock(
  bytes = readFileSync(path.join(LAB_DIRECTORY, 'subject-lock.json'))
) {
  let lock;
  try {
    lock = JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw new InvalidH053SourceError('subject-lock-json-invalid', error.message);
  }
  return { lock, bytes };
}

export function verifySubjectLockStructure(lock) {
  exactKeys(
    lock,
    [
      'schemaVersion',
      'hypothesis',
      'normative',
      'nominatedCombinedSourceSetSha256',
      'canonicalization',
      'sourceBoundary',
      'mutableSourceRecovery',
      'boundary',
      'authority',
      'action',
    ],
    'subject lock'
  );
  assertion(
    lock.schemaVersion === 'overlaykit-h053-subject-lock/v1' &&
      lock.hypothesis === 'H-053' &&
      lock.normative === false,
    'subject-lock-envelope-drift',
    'Subject lock identity differs'
  );
  assertion(
    lock.authority === 'none' && lock.action === null,
    'authority-overclaim',
    'Subject lock creates authority'
  );
  assertion(
    lock.nominatedCombinedSourceSetSha256 === EXPECTED_COMBINED_SOURCE_SET_SHA256,
    'combined-source-set-drift',
    'Nominated source boundary differs'
  );
  const { sourceBoundary } = lock;
  assertion(
    sourceBoundary.schemaVersion === 'overlaykit-h053-proposed-source-boundary/v1',
    'source-boundary-envelope-drift',
    'Source boundary schema differs'
  );
  assertion(
    sourceBoundary.gitSubject.commit === EXPECTED_COMMIT &&
      sourceBoundary.gitSubject.tree === EXPECTED_TREE &&
      sourceBoundary.gitSubject.sourceCount === 21 &&
      sourceBoundary.gitSubject.restrictedLsTreeSha256 === EXPECTED_RESTRICTED_TREE_SHA256 &&
      sourceBoundary.gitSubject.sourceSetSha256 === EXPECTED_GIT_SOURCE_SET_SHA256,
    'git-subject-drift',
    'Git subject differs'
  );
  assertion(
    sourceBoundary.localPredecessor.sourceCount === 8 &&
      sourceBoundary.localPredecessor.sourceSetSha256 === EXPECTED_LOCAL_SOURCE_SET_SHA256,
    'local-subject-drift',
    'Local predecessor differs'
  );
  const gitPaths = sourceBoundary.gitSubject.sources.map(({ path: sourcePath }) => sourcePath);
  const localPaths = sourceBoundary.localPredecessor.sources.map(
    ({ path: sourcePath }) => sourcePath
  );
  assertRoster(gitPaths, 'Git sources');
  assertRoster(localPaths, 'local sources');
  assertion(gitPaths.length === 21 && localPaths.length === 8, 'source-cardinality-drift', 'count');
  assertion(
    nominatedCanonicalHash(sourceBoundary.gitSubject.sources) === EXPECTED_GIT_SOURCE_SET_SHA256 &&
      nominatedCanonicalHash(sourceBoundary.localPredecessor.sources) ===
        EXPECTED_LOCAL_SOURCE_SET_SHA256 &&
      nominatedCanonicalHash(sourceBoundary) === EXPECTED_COMBINED_SOURCE_SET_SHA256,
    'source-descriptor-hash-drift',
    'Source descriptor hashes differ'
  );
  assertion(
    lock.mutableSourceRecovery.path === '.overlaykit/governance/manifest.json' &&
      lock.mutableSourceRecovery.archiveMember === 'sources/h052-frame/001' &&
      lock.mutableSourceRecovery.recoveredRawSha256 === EXPECTED_PRE_H053_MANIFEST_SHA256,
    'mutable-source-recovery-drift',
    'Manifest recovery locator differs'
  );
  const allPaths = [...gitPaths, ...localPaths];
  assertion(
    !allPaths.includes('.overlaykit/governance/changes/CHG-0034.json') &&
      !allPaths.some((sourcePath) => sourcePath.startsWith('lab/h053/')) &&
      !allPaths.some((sourcePath) => sourcePath.startsWith('artifacts/h053/')),
    'self-source-admission',
    'Successor apparatus entered its own subject'
  );
  return {
    gitSourceCount: gitPaths.length,
    localSourceCount: localPaths.length,
    totalSourceCount: allPaths.length,
    combinedSourceSetSha256: EXPECTED_COMBINED_SOURCE_SET_SHA256,
  };
}

export function inspectH053Sources({
  subjectLockBytes,
  gitReader = defaultGitReader,
  localOverrides = new Map(),
} = {}) {
  const { lock, bytes: lockBytes } = parseSubjectLock(subjectLockBytes);
  verifySubjectLockStructure(lock);
  const { gitSubject, localPredecessor } = lock.sourceBoundary;
  const commit = gitReader(['rev-parse', '--verify', `${gitSubject.commit}^{commit}`])
    .toString('utf8')
    .trim();
  const tree = gitReader(['rev-parse', `${gitSubject.commit}^{tree}`])
    .toString('utf8')
    .trim();
  assertion(
    commit === EXPECTED_COMMIT && tree === EXPECTED_TREE,
    'git-subject-drift',
    'Resolved Git subject differs'
  );
  const gitPaths = gitSubject.sources.map(({ path: sourcePath }) => sourcePath);
  const restrictedTree = gitReader([
    'ls-tree',
    '-rz',
    '--full-tree',
    gitSubject.commit,
    '--',
    ...gitPaths,
  ]);
  assertion(
    sha256(restrictedTree) === EXPECTED_RESTRICTED_TREE_SHA256,
    'restricted-tree-drift',
    'Restricted tree stream differs'
  );
  const entries = parseLsTree(restrictedTree);
  assertion(entries.length === gitSubject.sources.length, 'git-source-cardinality-drift', 'count');
  const gitSourceBytesByPath = new Map();
  for (let index = 0; index < gitSubject.sources.length; index += 1) {
    const expected = gitSubject.sources[index];
    const actual = entries[index];
    assertion(
      actual.path === expected.path &&
        actual.mode === expected.mode &&
        actual.type === expected.type &&
        actual.oid === expected.oid,
      'git-source-metadata-drift',
      expected.path
    );
    const sourceBytes = gitReader(['cat-file', 'blob', expected.oid]);
    assertion(
      sourceBytes.length === expected.byteLength && sha256(sourceBytes) === expected.sha256,
      'git-source-byte-drift',
      expected.path
    );
    gitSourceBytesByPath.set(expected.path, sourceBytes);
  }
  const gitDescriptorsByPath = new Map(
    gitSubject.sources.map((descriptor) => [descriptor.path, descriptor])
  );
  const executionDependencyBindings = EXECUTION_DEPENDENCY_PATHS.map((sourcePath) =>
    bindExecutionDependency(sourcePath, gitDescriptorsByPath.get(sourcePath))
  );
  const consumedInputBindings = executionDependencyBindings.filter(({ path: sourcePath }) =>
    CONSUMED_WORKTREE_INPUT_PATHS.includes(sourcePath)
  );
  const executedFirstPartyBindings = executionDependencyBindings.filter(({ path: sourcePath }) =>
    EXECUTED_FIRST_PARTY_SOURCE_PATHS.includes(sourcePath)
  );
  const unadmittedExecutionDependencies = executionDependencyBindings.filter(
    ({ admittedToNominatedBoundary }) => admittedToNominatedBoundary === false
  );
  assertion(
    unadmittedExecutionDependencies.length === 1 &&
      unadmittedExecutionDependencies[0].path === 'tools/governance/src/errors.ts',
    'execution-closure-classification-drift',
    'The exact unadmitted execution dependency is no longer errors.ts'
  );
  assertion(
    NOMINATED_NOT_EXECUTED_SOURCE_PATHS.every(
      (sourcePath) =>
        gitDescriptorsByPath.has(sourcePath) &&
        !EXECUTED_FIRST_PARTY_SOURCE_PATHS.includes(sourcePath)
    ),
    'execution-roster-drift',
    'repository.ts must remain nominated source material but not executed apparatus'
  );
  const sourceExecutionClosure = {
    classification: 'incomplete',
    closed: false,
    method: 'static-first-party-import-closure-plus-consumed-worktree-inputs',
    dependencyCount: executionDependencyBindings.length,
    admittedDependencyCount:
      executionDependencyBindings.length - unadmittedExecutionDependencies.length,
    unadmittedDependencyCount: unadmittedExecutionDependencies.length,
    consumedInputCount: consumedInputBindings.length,
    executedFirstPartySourceCount: executedFirstPartyBindings.length,
    bindings: executionDependencyBindings,
    bindingsSha256: nominatedCanonicalHash(executionDependencyBindings),
    unadmittedDependencies: unadmittedExecutionDependencies,
    nominatedButNotExecutedSources: [...NOMINATED_NOT_EXECUTED_SOURCE_PATHS],
    reason:
      'tools/governance/src/errors.ts executes transitively through compiler.ts and validator.ts but is absent from the nominated d257 source roster',
  };

  const mutablePath = lock.mutableSourceRecovery.path;
  const localSourceBytesByPath = new Map();
  for (const descriptor of localPredecessor.sources) {
    if (descriptor.path === mutablePath) {
      continue;
    }
    const sourceBytes = localOverrides.get(descriptor.path) ?? readExactLocalSource(descriptor);
    assertion(
      sourceBytes.length === descriptor.byteLength && sha256(sourceBytes) === descriptor.sha256,
      'local-source-byte-drift',
      descriptor.path
    );
    localSourceBytesByPath.set(descriptor.path, sourceBytes);
  }
  const archivePath = lock.mutableSourceRecovery.archivePath;
  const archiveBytes = localSourceBytesByPath.get(archivePath);
  assertion(
    archiveBytes !== undefined && sha256(archiveBytes) === EXPECTED_H052_ARCHIVE_SHA256,
    'recovery-archive-drift',
    'H-052 archive differs'
  );
  const recoveredManifest = extractRegularTarMember(
    archiveBytes,
    lock.mutableSourceRecovery.archiveMember
  );
  const manifestDescriptor = localPredecessor.sources.find(
    ({ path: sourcePath }) => sourcePath === mutablePath
  );
  assertion(manifestDescriptor !== undefined, 'recovery-descriptor-missing', mutablePath);
  assertion(
    recoveredManifest.length === manifestDescriptor.byteLength &&
      sha256(recoveredManifest) === manifestDescriptor.sha256,
    'recovered-manifest-drift',
    'Recovered pre-H-053 manifest differs'
  );
  localSourceBytesByPath.set(mutablePath, recoveredManifest);
  assertion(
    gitSourceBytesByPath.size === 21 && localSourceBytesByPath.size === 8,
    'source-cardinality-drift',
    'resolved source count'
  );

  return {
    subjectLockRawSha256: sha256(lockBytes),
    gitSourceBytesByPath,
    localSourceBytesByPath,
    gitSourceCount: 21,
    localSourceCount: 8,
    totalSourceCount: 29,
    restrictedLsTreeSha256: sha256(restrictedTree),
    gitSourceSetSha256: nominatedCanonicalHash(gitSubject.sources),
    localSourceSetSha256: nominatedCanonicalHash(localPredecessor.sources),
    combinedSourceSetSha256: nominatedCanonicalHash(lock.sourceBoundary),
    recoveredPreH053ManifestSha256: sha256(recoveredManifest),
    sourceExecutionClosure,
    executedWorktreeBindings: executionDependencyBindings,
    executedWorktreeBindingsSha256: sourceExecutionClosure.bindingsSha256,
  };
}

export const H053_SOURCE_CONSTANTS = Object.freeze({
  repositoryRoot: REPOSITORY_ROOT,
  labDirectory: LAB_DIRECTORY,
  combinedSourceSetSha256: EXPECTED_COMBINED_SOURCE_SET_SHA256,
  preH053ManifestSha256: EXPECTED_PRE_H053_MANIFEST_SHA256,
});
