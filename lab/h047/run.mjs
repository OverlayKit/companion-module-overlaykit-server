import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, realpathSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  H047_CLAIM_BOUNDARY,
  H047_IMAGE,
  H047_SUBJECT,
  buildInventory,
  canonicalJson,
  parseLsTreeZ,
  sha256,
  sourceSetSha256,
} from './inventory-lib.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const GIT_EXECUTABLE = '/usr/bin/git';
const SUBJECT_MANIFEST_CONTENT_HASH =
  'a31de506836ffd12f9b1a2849bdb0c353e886481800a2ab01a3dd293ebb7c87e';
const SPEC_0001_CONTENT_HASH = '917f1ca2febe17f8901ab71f91a0b0135402f9be972a876f233fcd5c789b8179';
const GIT_OID_PATTERN = /^[0-9a-f]{40}$/u;
const REPOSITORY_GIT_ENV = Object.freeze({
  GIT_CONFIG_COUNT: '0',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_NO_LAZY_FETCH: '1',
  GIT_NO_REPLACE_OBJECTS: '1',
  GIT_OPTIONAL_LOCKS: '0',
  GIT_TERMINAL_PROMPT: '0',
  GNUPGHOME: '/home/rod/.gnupg',
  LANG: 'C',
  LC_ALL: 'C',
  PATH: '/usr/bin:/bin',
});
const H047_ADR_ASSESSMENT = Object.freeze({
  status: 'no-decision-candidate-activated',
  rationaleCode: 'repository-inventory-selects-no-new-architecture',
  futureDecisionQuestion:
    'which accepted source of truth, lifecycle-owner role, reconciler, and convergence policy should govern a persistent Companion deployment if one is desired',
  authority: 'none',
  action: null,
});

export const H047_SOURCE_PATHS = Object.freeze(
  [
    '.overlaykit/governance/changes/CHG-0022.json',
    '.overlaykit/governance/manifest.json',
    'lab/h047/inventory-lib.mjs',
    'lab/h047/inventory-lib.test.mjs',
    'lab/h047/review-map.json',
    'lab/h047/run.mjs',
    'lab/h047/run.test.mjs',
    'lab/h047/schema.test.mjs',
    'lab/h047/schemas/repository-desired-state-run.schema.json',
    'lab/h047/verify.mjs',
    'lab/h047/verify.test.mjs',
  ].sort()
);

const COMMAND_POLICY = Object.freeze([
  'git cat-file blob <oid>',
  'git cat-file commit <source-anchor>',
  'git diff-tree --no-commit-id --name-only -r -z <subject> <source-anchor>',
  'git ls-tree -rz --full-tree <commit>',
  'git rev-parse <revision>',
  'git status --porcelain=v1 --untracked-files=all',
  'git verify-commit <source-anchor>',
]);

function assertion(condition, message) {
  if (!condition) throw new Error(message);
}

function exactKeys(value, expected, label) {
  assertion(
    value !== null && typeof value === 'object' && !Array.isArray(value),
    `${label} object`
  );
  assertion(
    canonicalJson(Object.keys(value).sort()) === canonicalJson([...expected].sort()),
    `${label} keys`
  );
}

function parseNulPaths(bytes, label) {
  assertion(Buffer.isBuffer(bytes), `${label} must be bytes`);
  if (bytes.length === 0) return [];
  assertion(bytes.at(-1) === 0, `${label} must be NUL terminated`);
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const result = [];
  let start = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] !== 0) continue;
    assertion(index > start, `${label} contains an empty path`);
    const value = decoder.decode(bytes.subarray(start, index));
    assertion(
      !value.startsWith('/') &&
        !value.includes('\\') &&
        value.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..'),
      `${label} contains an unsafe path`
    );
    result.push(value);
    start = index + 1;
  }
  assertion(new Set(result).size === result.length, `${label} contains duplicate paths`);
  return result;
}

function commandKey(args) {
  if (!Array.isArray(args) || args.some((value) => typeof value !== 'string')) {
    return 'prohibited';
  }
  if (
    args.length === 3 &&
    args[0] === 'cat-file' &&
    args[1] === 'blob' &&
    GIT_OID_PATTERN.test(args[2])
  ) {
    return 'cat-file-blob';
  }
  if (
    args.length === 3 &&
    args[0] === 'cat-file' &&
    args[1] === 'commit' &&
    GIT_OID_PATTERN.test(args[2])
  ) {
    return 'cat-file-commit';
  }
  if (
    args.length === 7 &&
    canonicalJson(args.slice(0, 6)) ===
      canonicalJson([
        'diff-tree',
        '--no-commit-id',
        '--name-only',
        '-r',
        '-z',
        H047_SUBJECT.commit,
      ]) &&
    GIT_OID_PATTERN.test(args[6])
  ) {
    return 'diff-tree';
  }
  if (
    args.length === 4 &&
    canonicalJson(args.slice(0, 3)) === canonicalJson(['ls-tree', '-rz', '--full-tree']) &&
    GIT_OID_PATTERN.test(args[3])
  ) {
    return 'ls-tree';
  }
  if (
    args.length === 2 &&
    args[0] === 'rev-parse' &&
    ['HEAD^{commit}', 'HEAD^1', 'HEAD^{tree}', `${H047_SUBJECT.commit}^{tree}`].includes(args[1])
  ) {
    return 'rev-parse';
  }
  if (
    canonicalJson(args) === canonicalJson(['status', '--porcelain=v1', '--untracked-files=all'])
  ) {
    return 'status';
  }
  if (args.length === 2 && args[0] === 'verify-commit' && GIT_OID_PATTERN.test(args[1])) {
    return 'verify-commit';
  }
  return 'prohibited';
}

export function createRepositoryReader({ root = REPOSITORY_ROOT, spawn = spawnSync } = {}) {
  assertion(typeof spawn === 'function', 'H-047 Git spawn seam must be a function');
  const counts = Object.create(null);

  function git(args) {
    const key = commandKey(args);
    const command = Array.isArray(args) && typeof args[0] === 'string' ? args[0] : '<invalid>';
    assertion(key !== 'prohibited', `Git command is outside the H-047 allowlist: ${command}`);
    counts[key] = (counts[key] ?? 0) + 1;
    const result = spawn(GIT_EXECUTABLE, args, {
      cwd: root,
      encoding: null,
      env: { ...REPOSITORY_GIT_ENV },
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    assertion(result.error === undefined, `git ${args[0]} failed to start: ${result.error?.code}`);
    assertion(
      result.status === 0 && result.signal === null,
      `git ${args[0]} failed (${result.status ?? result.signal}): ${String(result.stderr)}`
    );
    return result.stdout;
  }

  return {
    git,
    counts: () => Object.fromEntries(Object.entries(counts).sort()),
  };
}

function text(bytes, label) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${label} is not valid UTF-8`);
  }
}

function oneLine(bytes, label) {
  const value = text(bytes, label).trim();
  assertion(value !== '' && !value.includes('\n') && !value.includes('\r'), `${label} one line`);
  return value;
}

function json(bytes, label) {
  try {
    return JSON.parse(text(bytes, label));
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${error.message}`);
  }
}

function treeSnapshot(reader, commit) {
  const treeBytes = reader.git(['ls-tree', '-rz', '--full-tree', commit]);
  const entries = parseLsTreeZ(treeBytes);
  const blobsByOid = new Map();
  for (const { oid } of entries) {
    if (!blobsByOid.has(oid)) blobsByOid.set(oid, reader.git(['cat-file', 'blob', oid]));
  }
  return { treeBytes, entries, blobsByOid };
}

function entryBytes(snapshot, relativePath) {
  const entry = snapshot.entries.find(({ path: candidate }) => candidate === relativePath);
  assertion(entry !== undefined, `Missing required repository path: ${relativePath}`);
  const bytes = snapshot.blobsByOid.get(entry.oid);
  assertion(Buffer.isBuffer(bytes), `Missing required blob: ${relativePath}`);
  return { entry, bytes };
}

function sourceClosure(anchorSnapshot) {
  const entries = H047_SOURCE_PATHS.map((relativePath) => {
    const { entry, bytes } = entryBytes(anchorSnapshot, relativePath);
    return {
      path: relativePath,
      mode: entry.mode,
      oid: entry.oid,
      byteLength: bytes.length,
      sha256: sha256(bytes),
    };
  });
  return { entries, sourceSetSha256: sourceSetSha256(entries) };
}

function normalizedArtifact(file, value) {
  const bytes = Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
  return {
    file,
    byteLength: bytes.length,
    sha256: sha256(bytes),
    bytes,
  };
}

function candidateDocument(inventory) {
  return {
    schemaVersion: 'overlaykit-h047-candidate-index/v1',
    hypothesis: 'H-047',
    governance: inventory.governance,
    acceptedRecordReview: inventory.acceptedRecordReview,
    targetOccurrences: inventory.targetOccurrences,
    targetOccurrencePathCounts: inventory.targetOccurrencePathCounts,
    deploymentSurfaces: inventory.surfaces,
    semanticReview: inventory.semanticReview,
    candidates: inventory.candidates,
    chainComponents: inventory.chainComponents,
    unknowns: inventory.unknowns,
    eligibleChains: inventory.eligibleChains,
    coverageComplete: inventory.coverageComplete,
    outcome: inventory.outcome,
    adrAssessment: H047_ADR_ASSESSMENT,
  };
}

export function buildH047Bundle({ reader = createRepositoryReader() } = {}) {
  const sourceAnchorCommit = oneLine(reader.git(['rev-parse', 'HEAD^{commit}']), 'source anchor');
  const sourceAnchorParent = oneLine(reader.git(['rev-parse', 'HEAD^1']), 'source anchor parent');
  const sourceAnchorTree = oneLine(reader.git(['rev-parse', 'HEAD^{tree}']), 'source anchor tree');
  const subjectTree = oneLine(
    reader.git(['rev-parse', `${H047_SUBJECT.commit}^{tree}`]),
    'subject tree'
  );
  assertion(
    GIT_OID_PATTERN.test(sourceAnchorCommit),
    'Source anchor commit is not an exact Git OID'
  );
  assertion(
    GIT_OID_PATTERN.test(sourceAnchorParent),
    'Source anchor parent is not an exact Git OID'
  );
  assertion(GIT_OID_PATTERN.test(sourceAnchorTree), 'Source anchor tree is not an exact Git OID');
  assertion(GIT_OID_PATTERN.test(subjectTree), 'Subject tree is not an exact Git OID');
  assertion(sourceAnchorParent === H047_SUBJECT.commit, 'Source anchor parent is not the subject');
  assertion(subjectTree === H047_SUBJECT.tree, 'Subject tree identity differs');
  const commitObject = text(
    reader.git(['cat-file', 'commit', sourceAnchorCommit]),
    'source anchor commit object'
  );
  const headerSeparator = commitObject.search(/\r?\n\r?\n/u);
  assertion(headerSeparator >= 0, 'Source anchor commit object has no header boundary');
  const commitHeaders = commitObject.slice(0, headerSeparator);
  const parentLines = commitHeaders.split(/\r?\n/u).filter((line) => line.startsWith('parent '));
  assertion(
    parentLines.length === 1 && parentLines[0] === `parent ${H047_SUBJECT.commit}`,
    'Source anchor must have exactly the subject as its only parent'
  );
  reader.git(['verify-commit', sourceAnchorCommit]);
  const status = reader.git(['status', '--porcelain=v1', '--untracked-files=all']);
  assertion(status.length === 0, 'Working tree must be clean before H-047 execution');
  const deltaPaths = parseNulPaths(
    reader.git([
      'diff-tree',
      '--no-commit-id',
      '--name-only',
      '-r',
      '-z',
      H047_SUBJECT.commit,
      sourceAnchorCommit,
    ]),
    'source-anchor delta'
  ).sort();
  assertion(
    canonicalJson(deltaPaths) === canonicalJson(H047_SOURCE_PATHS),
    'Source-anchor delta differs from the exact H-047 source closure'
  );

  const subjectSnapshot = treeSnapshot(reader, H047_SUBJECT.commit);
  const anchorSnapshot = treeSnapshot(reader, sourceAnchorCommit);
  const reviewMap = json(
    entryBytes(anchorSnapshot, 'lab/h047/review-map.json').bytes,
    'semantic review map'
  );
  const inventory = buildInventory({
    treeBytes: subjectSnapshot.treeBytes,
    blobsByOid: subjectSnapshot.blobsByOid,
    reviewMap,
  });
  const plan = json(
    entryBytes(subjectSnapshot, '.overlaykit/governance/plan.json').bytes,
    'subject plan'
  );
  const manifest = json(
    entryBytes(subjectSnapshot, '.overlaykit/governance/manifest.json').bytes,
    'subject manifest'
  );
  exactKeys(
    { planHash: plan.planHash, manifestContentHash: manifest.contentHash },
    ['planHash', 'manifestContentHash'],
    'governance identities'
  );
  assertion(plan.planHash === H047_SUBJECT.planHash, 'Subject plan hash differs');
  assertion(
    manifest.contentHash === SUBJECT_MANIFEST_CONTENT_HASH,
    'Subject manifest content hash differs'
  );
  assertion(
    plan.specifications.some(
      (record) =>
        record.id === 'SPEC-0001' &&
        record.effectiveStatus === 'accepted' &&
        record.contentHash === SPEC_0001_CONTENT_HASH
    ),
    'SPEC-0001 logical host role is not effective and exact'
  );

  const source = sourceClosure(anchorSnapshot);
  const sourceMapDocument = {
    schemaVersion: 'overlaykit-h047-source-map/v1',
    hypothesis: 'H-047',
    subject: {
      ...H047_SUBJECT,
      manifestContentHash: SUBJECT_MANIFEST_CONTENT_HASH,
    },
    entryCount: inventory.sourceMap.entryCount,
    entries: inventory.sourceMap.entries,
    sourceSetSha256: inventory.sourceMap.sourceSetSha256,
  };
  const candidateIndexDocument = candidateDocument(inventory);
  const sourceMapArtifact = normalizedArtifact('source-map.json', sourceMapDocument);
  const candidateIndexArtifact = normalizedArtifact('candidate-index.json', candidateIndexDocument);

  const semantic = {
    schemaVersion: 'overlaykit-h047-repository-desired-state-run/v1',
    hypothesis: 'H-047',
    subject: {
      commit: H047_SUBJECT.commit,
      tree: H047_SUBJECT.tree,
      entryCount: H047_SUBJECT.entryCount,
      lsTreeSha256: H047_SUBJECT.lsTreeSha256,
      planHash: H047_SUBJECT.planHash,
      manifestContentHash: SUBJECT_MANIFEST_CONTENT_HASH,
    },
    sourceAnchor: {
      commit: sourceAnchorCommit,
      parent: sourceAnchorParent,
      parentCount: parentLines.length,
      tree: sourceAnchorTree,
      signatureVerified: true,
      deltaPaths,
      sourceSetSha256: source.sourceSetSha256,
      sources: source.entries,
    },
    target: {
      imageReference: H047_IMAGE.reference,
      imageId: H047_IMAGE.imageId,
      hostRole: 'spec-0001-linux-production-host',
      hostRoleSpecification: 'SPEC-0001',
      hostRoleSpecificationContentHash: SPEC_0001_CONTENT_HASH,
      imageInterpretation: 'historical-evidence-selector',
    },
    artifacts: {
      sourceMap: {
        file: sourceMapArtifact.file,
        byteLength: sourceMapArtifact.byteLength,
        sha256: sourceMapArtifact.sha256,
      },
      candidateIndex: {
        file: candidateIndexArtifact.file,
        byteLength: candidateIndexArtifact.byteLength,
        sha256: candidateIndexArtifact.sha256,
      },
    },
    summary: {
      acceptedDecisions: inventory.governance.counts.decisions.accepted ?? 0,
      acceptedSpecifications: inventory.governance.counts.specifications.accepted ?? 0,
      implementedChanges: inventory.governance.counts.changes.implemented ?? 0,
      proposedChanges: inventory.governance.counts.changes.proposed ?? 0,
      identityPaths: inventory.targetOccurrences.length,
      deploymentSurfaces: inventory.surfaces.length,
      candidates: inventory.candidates.length,
      unknowns: inventory.unknowns.length,
      eligibleChains: inventory.eligibleChains.length,
      coverageComplete: inventory.coverageComplete,
    },
    outcome: inventory.outcome,
    adrAssessment: H047_ADR_ASSESSMENT,
    capabilityAudit: {
      mode: 'repository-only-read-only',
      gitExecutable: GIT_EXECUTABLE,
      commandPolicy: COMMAND_POLICY,
      observedInvocationCounts: reader.counts(),
      gitNoLazyFetch: true,
      gitOptionalLocks: false,
      sourceAnchorSignatureVerified: true,
      sourceAnchorParentCount: parentLines.length,
      repositoryReadsOnly: true,
      localIgnoredEvidenceWriteOnly: true,
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
    claimBoundary: H047_CLAIM_BOUNDARY,
  };
  const run = {
    ...semantic,
    semanticEvidenceSha256: sha256(canonicalJson(semantic)),
  };
  return {
    run,
    sourceMap: sourceMapDocument,
    candidateIndex: candidateIndexDocument,
    serialized: {
      run: Buffer.from(`${canonicalJson(run)}\n`, 'utf8'),
      sourceMap: sourceMapArtifact.bytes,
      candidateIndex: candidateIndexArtifact.bytes,
    },
  };
}

function parseArgs(argv) {
  assertion(
    argv.length === 2 && argv[0] === '--run-id',
    'Usage: node lab/h047/run.mjs --run-id <id>'
  );
  assertion(/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u.test(argv[1]), 'Invalid run id');
  return { runId: argv[1] };
}

function ensureCanonicalDirectory(directory) {
  if (existsSync(directory)) {
    const metadata = lstatSync(directory);
    assertion(metadata.isDirectory() && !metadata.isSymbolicLink(), `${directory} is unsafe`);
  } else {
    mkdirSync(directory, { mode: 0o700 });
  }
  assertion(realpathSync(directory) === directory, `${directory} is not canonical`);
  assertion(statSync(directory).isDirectory(), `${directory} is not a directory`);
}

function writeBundle(runId, bundle) {
  assertion(realpathSync(REPOSITORY_ROOT) === REPOSITORY_ROOT, 'Repository root is not canonical');
  const artifactRoot = path.join(REPOSITORY_ROOT, 'artifacts');
  const h047Root = path.join(artifactRoot, 'h047');
  ensureCanonicalDirectory(artifactRoot);
  ensureCanonicalDirectory(h047Root);
  const outputDirectory = path.join(h047Root, runId);
  mkdirSync(outputDirectory, { mode: 0o700 });
  for (const [name, bytes] of [
    ['source-map.json', bundle.serialized.sourceMap],
    ['candidate-index.json', bundle.serialized.candidateIndex],
    ['run.json', bundle.serialized.run],
  ]) {
    writeFileSync(path.join(outputDirectory, name), bytes, { flag: 'wx', mode: 0o600 });
  }
  return outputDirectory;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const { runId } = parseArgs(process.argv.slice(2));
  const bundle = buildH047Bundle();
  const outputDirectory = writeBundle(runId, bundle);
  process.stdout.write(
    `${JSON.stringify({
      runId,
      outputDirectory,
      outcome: bundle.run.outcome,
      semanticEvidenceSha256: bundle.run.semanticEvidenceSha256,
      sourceSetSha256: bundle.run.sourceAnchor.sourceSetSha256,
    })}\n`
  );
}
