import { spawnSync } from 'node:child_process';
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  writeSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  H049_ADR_ASSESSMENT,
  H049_CLAIM_BOUNDARY,
  buildCandidateIndex,
  buildNormativeInventory,
  canonicalArtifact,
  canonicalJson,
  semanticEvidenceSha256,
  sha256,
} from './inventory-lib.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
export const H049_REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const GIT_EXECUTABLE = '/usr/bin/git';
const GIT_OID_PATTERN = /^[0-9a-f]{40}$/u;
const OUTPUT_ARGUMENT_PATTERN = /^artifacts\/h049\/[a-z0-9][a-z0-9-]{0,63}$/u;
const SUBJECT_LOCK_PATH = 'lab/h049/subject-lock.json';
const SUBJECT_LOCK_RAW_SHA256 = 'e29698e4e9768ab7ff5f6773f5c4aab4834c312c7b90fce97ccf326244cce73a';
const IGNORE_PROBE_PATH = 'artifacts/h049/__h049-ignore-probe__';

export const H049_CHECK_IGNORE_ARGS = Object.freeze([
  'check-ignore',
  '-v',
  '--no-index',
  '--',
  IGNORE_PROBE_PATH,
]);

export const H049_SOURCE_PATHS = Object.freeze(
  [
    '.gitignore',
    '.overlaykit/governance/changes/CHG-0026.json',
    '.overlaykit/governance/manifest.json',
    'lab/h049/inventory-lib.mjs',
    'lab/h049/inventory-lib.test.mjs',
    'lab/h049/review-map.json',
    'lab/h049/run.mjs',
    'lab/h049/run.test.mjs',
    'lab/h049/schema.test.mjs',
    'lab/h049/schemas/normative-recovery-obligation-run.schema.json',
    'lab/h049/subject-lock.json',
    'lab/h049/verify.mjs',
    'lab/h049/verify.test.mjs',
  ].sort()
);

const FIXED_GIT_ENVIRONMENT = Object.freeze({
  GIT_ALTERNATE_OBJECT_DIRECTORIES: '',
  GIT_ATTR_NOSYSTEM: '1',
  GIT_CONFIG_COUNT: '0',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_CONFIG_SYSTEM: '/dev/null',
  GIT_NO_LAZY_FETCH: '1',
  GIT_NO_REPLACE_OBJECTS: '1',
  GIT_OPTIONAL_LOCKS: '0',
  GIT_TERMINAL_PROMPT: '0',
  LANG: 'C',
  LC_ALL: 'C',
  PATH: '/usr/bin:/bin',
});

const PROHIBITED_CAPABILITIES = Object.freeze([
  'network',
  'docker',
  'usb',
  'hidraw',
  'procfs',
  'sysfs',
  'devfs',
  'systemd',
  'signals',
  'lifecycle',
  'installation',
  'configuration',
  'controller-implementation',
  'production-mutation',
]);

function assertion(condition, message) {
  if (!condition) throw new Error(message);
}

function exactOptionKeys(value, allowed, label) {
  assertion(
    value !== null && typeof value === 'object' && !Array.isArray(value),
    `${label} options must be an object`
  );
  assertion(
    canonicalJson(Object.keys(value).sort()) === canonicalJson([...allowed].sort()),
    `${label} options are outside the sealed interface`
  );
}

function oneLine(bytes, label) {
  const value = new TextDecoder('utf-8', { fatal: true }).decode(bytes).trim();
  assertion(value !== '' && !value.includes('\n') && !value.includes('\r'), `${label} one line`);
  return value;
}

function fixedTrackedPath(relativePath) {
  assertion(H049_SOURCE_PATHS.includes(relativePath), `untracked H-049 read: ${relativePath}`);
  const absolutePath = path.resolve(H049_REPOSITORY_ROOT, relativePath);
  assertion(
    absolutePath.startsWith(`${H049_REPOSITORY_ROOT}${path.sep}`),
    `tracked H-049 read escapes the repository: ${relativePath}`
  );
  return absolutePath;
}

function sameFileIdentity(before, after) {
  return (
    before.dev === after.dev &&
    before.ino === after.ino &&
    before.mode === after.mode &&
    before.nlink === after.nlink &&
    before.size === after.size &&
    before.mtimeMs === after.mtimeMs &&
    before.ctimeMs === after.ctimeMs
  );
}

function readTrackedFile(relativePath) {
  assertion(Number.isInteger(fsConstants.O_NOFOLLOW), 'O_NOFOLLOW is required');
  const absolutePath = fixedTrackedPath(relativePath);
  const descriptor = openSync(absolutePath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    const before = fstatSync(descriptor);
    assertion(
      before.isFile() && (before.mode & 0o777) === 0o644 && before.nlink === 1,
      `tracked source must be one regular 0644 file: ${relativePath}`
    );
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    assertion(
      sameFileIdentity(before, after) && bytes.length === after.size,
      `tracked source changed while reading: ${relativePath}`
    );
    return { bytes, metadata: after };
  } finally {
    closeSync(descriptor);
  }
}

function parseJsonFile(relativePath) {
  const { bytes } = readTrackedFile(relativePath);
  try {
    return { bytes, value: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) };
  } catch (error) {
    throw new Error(`${relativePath} is not valid UTF-8 JSON: ${error.message}`);
  }
}

export function admitH049SubjectLockBytes(bytes) {
  assertion(Buffer.isBuffer(bytes), 'subject lock must be bytes');
  assertion(
    sha256(bytes) === SUBJECT_LOCK_RAW_SHA256,
    'subject lock bytes are not exactly admitted'
  );
  let value;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch (error) {
    throw new Error(`subject lock is not valid UTF-8 JSON: ${error.message}`);
  }
  assertion(
    value?.subject?.commit === '226d299a9b0d8acd592675f514a67d6229d0134a' &&
      value?.subject?.tree === 'f0cd2b22b3c9da7b2c2d2cf5b93baa97dd1a5bcd' &&
      Array.isArray(value?.sources) &&
      value.sources.length === 9,
    'subject lock admitted identity differs'
  );
  return value;
}

function readAdmittedSubjectLock() {
  return admitH049SubjectLockBytes(readTrackedFile(SUBJECT_LOCK_PATH).bytes);
}

export function validateH049IgnoreProbe(bytes) {
  assertion(Buffer.isBuffer(bytes), 'check-ignore output must be bytes');
  const value = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  assertion(
    /^\.gitignore:[1-9][0-9]*:artifacts\/\tartifacts\/h049\/__h049-ignore-probe__\n$/u.test(value),
    'artifacts/h049 is not admitted by the exact artifacts/ ignore policy'
  );
}

function commandKey(args, subjectLock) {
  if (!Array.isArray(args) || args.some((value) => typeof value !== 'string')) return 'prohibited';
  if (canonicalJson(args) === canonicalJson(H049_CHECK_IGNORE_ARGS)) return 'check-ignore';
  if (
    args.length === 2 &&
    args[0] === 'rev-parse' &&
    [`${subjectLock.subject.commit}^{commit}`, `${subjectLock.subject.commit}^{tree}`].includes(
      args[1]
    )
  ) {
    return 'rev-parse';
  }
  if (
    args.length === 5 + subjectLock.sources.length &&
    args[0] === 'ls-tree' &&
    args[1] === '-rz' &&
    args[2] === '--full-tree' &&
    args[3] === subjectLock.subject.commit &&
    args[4] === '--' &&
    canonicalJson(args.slice(5)) ===
      canonicalJson(subjectLock.sources.map(({ path: value }) => value))
  ) {
    return 'restricted-ls-tree';
  }
  if (
    args.length === 3 &&
    args[0] === 'cat-file' &&
    args[1] === 'blob' &&
    GIT_OID_PATTERN.test(args[2]) &&
    subjectLock.sources.some(({ oid }) => oid === args[2])
  ) {
    return 'cat-file-blob';
  }
  return 'prohibited';
}

export function createH049GitReader(options = {}) {
  exactOptionKeys(options, Object.hasOwn(options, 'spawn') ? ['spawn'] : [], 'Git reader');
  const { spawn = spawnSync } = options;
  assertion(typeof spawn === 'function', 'Git spawn seam must be a function');
  const subjectLock = readAdmittedSubjectLock();
  const counts = Object.create(null);
  function git(args) {
    const key = commandKey(args, subjectLock);
    assertion(key !== 'prohibited', `Git command is outside the H-049 allowlist: ${args?.[0]}`);
    counts[key] = (counts[key] ?? 0) + 1;
    const result = spawn(GIT_EXECUTABLE, args, {
      cwd: H049_REPOSITORY_ROOT,
      encoding: null,
      env: { ...FIXED_GIT_ENVIRONMENT },
      maxBuffer: 2 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    assertion(result.error === undefined, `git ${args[0]} failed to start`);
    assertion(
      result.status === 0 && result.signal === null,
      `git ${args[0]} failed (${result.status ?? result.signal})`
    );
    assertion(Buffer.isBuffer(result.stdout), `git ${args[0]} stdout must be bytes`);
    assertion(Buffer.isBuffer(result.stderr), `git ${args[0]} stderr must be bytes`);
    assertion(result.stderr.length === 0, `git ${args[0]} produced stderr`);
    return result.stdout;
  }
  return {
    git,
    counts: () => Object.fromEntries(Object.entries(counts).sort()),
  };
}

function sourceClosure() {
  const sources = H049_SOURCE_PATHS.map((relativePath) => {
    const { bytes, metadata } = readTrackedFile(relativePath);
    return {
      path: relativePath,
      mode: (metadata.mode & 0o777).toString(8).padStart(4, '0'),
      byteLength: bytes.length,
      sha256: sha256(bytes),
    };
  });
  return {
    schemaVersion: 'overlaykit-h049-harness-source-map/v1',
    hypothesis: 'H-049',
    sourceCount: sources.length,
    sourceSetSha256: sha256(canonicalJson(sources)),
    sources,
  };
}

function artifactReference(file, bytes) {
  return {
    file,
    byteLength: bytes.length,
    sha256: sha256(bytes),
  };
}

export function buildH049Bundle(options = {}) {
  const allowedOptions = [];
  if (Object.hasOwn(options, 'sourceClosureBefore')) allowedOptions.push('sourceClosureBefore');
  if (Object.hasOwn(options, 'spawn')) allowedOptions.push('spawn');
  exactOptionKeys(options, allowedOptions, 'bundle');
  const { sourceClosureBefore, spawn = spawnSync } = options;
  const subjectLockInput = parseJsonFile(SUBJECT_LOCK_PATH);
  const reviewMapInput = parseJsonFile('lab/h049/review-map.json');
  const subjectLock = admitH049SubjectLockBytes(subjectLockInput.bytes);
  const activeReader = createH049GitReader({ spawn });
  validateH049IgnoreProbe(activeReader.git([...H049_CHECK_IGNORE_ARGS]));
  const commit = oneLine(
    activeReader.git(['rev-parse', `${subjectLock.subject.commit}^{commit}`]),
    'subject commit'
  );
  const tree = oneLine(
    activeReader.git(['rev-parse', `${subjectLock.subject.commit}^{tree}`]),
    'subject tree'
  );
  assertion(commit === subjectLock.subject.commit, 'subject commit differs');
  assertion(tree === subjectLock.subject.tree, 'subject tree differs');
  const restrictedTreeBytes = activeReader.git([
    'ls-tree',
    '-rz',
    '--full-tree',
    subjectLock.subject.commit,
    '--',
    ...subjectLock.sources.map(({ path: value }) => value),
  ]);
  const sourceBytesByPath = new Map(
    subjectLock.sources.map((source) => [
      source.path,
      activeReader.git(['cat-file', 'blob', source.oid]),
    ])
  );
  const inventory = buildNormativeInventory({
    subjectLock,
    restrictedTreeBytes,
    sourceBytesByPath,
  });
  const candidateIndex = buildCandidateIndex({
    reviewMap: reviewMapInput.value,
    clauseUniverse: inventory.clauseUniverse,
    parsedByPath: inventory.parsedByPath,
  });
  const closure = sourceClosureBefore ?? sourceClosure();
  const harnessSourceMapBytes = canonicalArtifact(closure);
  const sourceMapBytes = canonicalArtifact(inventory.sourceMap);
  const clauseUniverseBytes = canonicalArtifact(inventory.clauseUniverse);
  const candidateIndexBytes = canonicalArtifact(candidateIndex);
  const artifacts = {
    harnessSourceMap: artifactReference('harness-source-map.json', harnessSourceMapBytes),
    sourceMap: artifactReference('source-map.json', sourceMapBytes),
    clauseUniverse: artifactReference('clause-universe.json', clauseUniverseBytes),
    candidateIndex: artifactReference('candidate-index.json', candidateIndexBytes),
  };
  const reviewMapRawSha256 = sha256(reviewMapInput.bytes);
  const reviewMapCanonicalSha256 = sha256(canonicalArtifact(reviewMapInput.value));
  const evidenceSha256 = semanticEvidenceSha256({
    harnessSourceMapArtifact: artifacts.harnessSourceMap,
    sourceMapArtifact: artifacts.sourceMap,
    clauseUniverseArtifact: artifacts.clauseUniverse,
    candidateIndexArtifact: artifacts.candidateIndex,
    outcome: candidateIndex.outcome,
  });
  const run = {
    schemaVersion: 'overlaykit-h049-normative-recovery-obligation-run/v1',
    hypothesis: 'H-049',
    subject: {
      commit,
      tree,
      sourceCount: inventory.sourceMap.sourceCount,
      sourceSetSha256: inventory.sourceMap.sourceSetSha256,
      restrictedLsTreeSha256: subjectLock.subject.restrictedLsTreeSha256,
      planRawSha256: subjectLock.subject.planRawSha256,
      planHash: subjectLock.subject.planHash,
    },
    harness: {
      sourceCount: closure.sourceCount,
      sourceSetSha256: closure.sourceSetSha256,
      reviewMapRawSha256,
      reviewMapCanonicalSha256,
    },
    artifacts,
    summary: {
      clauses: inventory.clauseUniverse.clauseCount,
      candidates: candidateIndex.candidates.length,
      pendingHumanJudgments: candidateIndex.semanticReview.pendingHumanJudgments.length,
      eligibleChains: candidateIndex.eligibleChains.length,
      mechanicalCoverageComplete: candidateIndex.mechanicalCoverageComplete,
      semanticCoverageComplete: candidateIndex.semanticReview.coverageComplete,
    },
    outcome: candidateIndex.outcome,
    projectedOutcomeIfExactMapAccepted: candidateIndex.projectedOutcomeIfExactMapAccepted,
    adrAssessment: H049_ADR_ASSESSMENT,
    capabilityAudit: {
      mode: 'offline-read-only-normative-subject',
      gitExecutable: GIT_EXECUTABLE,
      commandPolicy: [
        'git check-ignore -v --no-index -- artifacts/h049/__h049-ignore-probe__',
        'git rev-parse <fixed-subject>^{commit|tree}',
        'git ls-tree -rz --full-tree <fixed-subject> -- <nine-fixed-paths>',
        'git cat-file blob <one-of-nine-fixed-oids>',
      ],
      commandCounts: activeReader.counts(),
      fixedGitEnvironment: FIXED_GIT_ENVIRONMENT,
      sourceBinding: 'on-disk-preflight-and-postflight-no-loader-attestation',
      trackedReads: H049_SOURCE_PATHS,
      ignoredWriteRoot: 'artifacts/h049',
      outputFiles: [
        'harness-source-map.json',
        'source-map.json',
        'clause-universe.json',
        'candidate-index.json',
        'run.json',
      ],
      prohibitedCapabilities: PROHIBITED_CAPABILITIES,
    },
    authority: 'none',
    action: null,
    claimBoundary: H049_CLAIM_BOUNDARY,
    semanticEvidenceSha256: evidenceSha256,
  };
  return {
    documents: {
      harnessSourceMap: closure,
      sourceMap: inventory.sourceMap,
      clauseUniverse: inventory.clauseUniverse,
      candidateIndex,
      run,
    },
    bytes: {
      harnessSourceMap: harnessSourceMapBytes,
      sourceMap: sourceMapBytes,
      clauseUniverse: clauseUniverseBytes,
      candidateIndex: candidateIndexBytes,
      run: canonicalArtifact(run),
    },
  };
}

export function parseH049Cli(argumentsList) {
  assertion(Array.isArray(argumentsList), 'CLI arguments must be an array');
  assertion(
    argumentsList.length === 2 && argumentsList[0] === '--out',
    'usage: node lab/h049/run.mjs --out artifacts/h049/<run-id>'
  );
  assertion(OUTPUT_ARGUMENT_PATTERN.test(argumentsList[1]), 'output path is outside H-049 policy');
  return { output: argumentsList[1] };
}

function ensureDirectory(absolutePath, mode, enforceMode = true) {
  const created = !existsSync(absolutePath);
  if (created) mkdirSync(absolutePath, { mode });
  assertion(
    Number.isInteger(fsConstants.O_NOFOLLOW) && Number.isInteger(fsConstants.O_DIRECTORY),
    'O_NOFOLLOW and O_DIRECTORY are required'
  );
  const descriptor = openSync(
    absolutePath,
    fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NOFOLLOW
  );
  try {
    const before = fstatSync(descriptor);
    assertion(before.isDirectory(), `unsafe directory: ${absolutePath}`);
    if (created || enforceMode) fchmodSync(descriptor, mode);
    const after = fstatSync(descriptor);
    assertion(
      after.isDirectory() &&
        before.dev === after.dev &&
        before.ino === after.ino &&
        (!(created || enforceMode) || (after.mode & 0o777) === mode),
      `directory identity or mode differs: ${absolutePath}`
    );
  } finally {
    closeSync(descriptor);
  }
}

export function resolveH049OutputDirectory(relativePath) {
  assertion(OUTPUT_ARGUMENT_PATTERN.test(relativePath), 'output path is outside H-049 policy');
  const artifactsRoot = path.join(H049_REPOSITORY_ROOT, 'artifacts');
  const h049Root = path.join(artifactsRoot, 'h049');
  ensureDirectory(artifactsRoot, 0o700, false);
  ensureDirectory(h049Root, 0o700);
  const realRepository = realpathSync(H049_REPOSITORY_ROOT);
  const realRoot = realpathSync(h049Root);
  assertion(
    realRoot.startsWith(`${realRepository}${path.sep}`),
    'H-049 artifact root escapes the repository'
  );
  const output = path.resolve(H049_REPOSITORY_ROOT, relativePath);
  assertion(path.dirname(output) === realRoot, 'output directory parent differs from H-049 root');
  assertion(!existsSync(output), 'output directory already exists');
  ensureDirectory(output, 0o700);
  assertion(
    realpathSync(output).startsWith(`${realRoot}${path.sep}`),
    'output directory escapes root'
  );
  return output;
}

function writeExclusive(absolutePath, bytes) {
  assertion(Number.isInteger(fsConstants.O_NOFOLLOW), 'O_NOFOLLOW is required');
  const descriptor = openSync(
    absolutePath,
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW,
    0o600
  );
  try {
    fchmodSync(descriptor, 0o600);
    const before = fstatSync(descriptor);
    assertion(
      before.isFile() && (before.mode & 0o777) === 0o600 && before.nlink === 1,
      `unsafe output file: ${absolutePath}`
    );
    let offset = 0;
    while (offset < bytes.length) {
      offset += writeSync(descriptor, bytes, offset, bytes.length - offset);
    }
    fsyncSync(descriptor);
    const after = fstatSync(descriptor);
    assertion(
      after.isFile() &&
        before.dev === after.dev &&
        before.ino === after.ino &&
        (after.mode & 0o777) === 0o600 &&
        after.nlink === 1 &&
        after.size === bytes.length,
      `output file identity, mode, or length differs: ${absolutePath}`
    );
  } finally {
    closeSync(descriptor);
  }
}

export function runH049(relativeOutput) {
  const sourceClosureBefore = sourceClosure();
  const bundle = buildH049Bundle({ sourceClosureBefore });
  const sourceClosureAfter = sourceClosure();
  assertion(
    canonicalJson(sourceClosureAfter) === canonicalJson(sourceClosureBefore),
    'H-049 harness sources changed during execution'
  );
  const output = resolveH049OutputDirectory(relativeOutput);
  const ordered = [
    ['harness-source-map.json', bundle.bytes.harnessSourceMap],
    ['source-map.json', bundle.bytes.sourceMap],
    ['clause-universe.json', bundle.bytes.clauseUniverse],
    ['candidate-index.json', bundle.bytes.candidateIndex],
    ['run.json', bundle.bytes.run],
  ];
  for (const [file, bytes] of ordered) writeExclusive(path.join(output, file), bytes);
  return {
    output,
    semanticEvidenceSha256: bundle.documents.run.semanticEvidenceSha256,
    outcome: bundle.documents.run.outcome,
  };
}

const isMain =
  process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const { output } = parseH049Cli(process.argv.slice(2));
  const result = runH049(output);
  process.stdout.write(
    `${canonicalJson({
      output: path.relative(H049_REPOSITORY_ROOT, result.output),
      semanticEvidenceSha256: result.semanticEvidenceSha256,
      outcome: result.outcome,
      authority: 'none',
      action: null,
    })}\n`
  );
}
