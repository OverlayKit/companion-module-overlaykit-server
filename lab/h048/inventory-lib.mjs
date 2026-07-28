import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync, realpathSync, statSync } from 'node:fs';
import path from 'node:path';
import { expandTarGzipForest } from './archive-lib.mjs';

const GIT_EXECUTABLE = '/usr/bin/git';
const OID_PATTERN = /^[0-9a-f]{40}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const FATAL_UTF8 = new TextDecoder('utf-8', { fatal: true });
const ARCHIVE_PATH_PATTERN = /\.(?:tar\.gz|tgz)$/iu;

export const H048_PREDICATES = Object.freeze([
  'effectiveAcceptedProductionAuthority',
  'exactImageReferenceAndId',
  'spec0001LinuxHostBinding',
  'deploymentPresenceAndCardinality',
  'repositoryDeclaredLifecycleOwner',
  'reconcilerMechanism',
  'absenceToConvergenceRule',
  'explicitLinkClosure',
]);

export const H048_GIT_COMMAND_POLICY = Object.freeze([
  'git cat-file blob <oid>',
  'git ls-tree -rz --full-tree <commit>',
  'git rev-parse <commit>^{tree}',
]);

export const H048_UNRESOLVED_INDIRECTION_STATUSES = Object.freeze([
  'unresolved-github-pull-request',
  'subject-commit-mismatch',
  'unscoped-commit-reference',
  'unversioned-subject-reference',
]);

export const H048_EXPECTED_HUMAN_ACCEPTANCE_SHA256 = null;

const SIGNAL_POLICY = Object.freeze([
  {
    id: 'accepted-authority-language',
    pattern: /\b(?:accepted|authority|authoritative|normative|policy|governance)\b/iu,
  },
  {
    id: 'companion-product',
    pattern: /\b(?:bitfocus\s+)?companion\b/iu,
  },
  {
    id: 'exact-image-reference',
    pattern: /ghcr\.io\/bitfocus\/companion\/companion:v4\.3\.3/u,
  },
  {
    id: 'exact-image-id',
    pattern: /sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e/u,
  },
  {
    id: 'spec-linux-host',
    pattern: /\bSPEC-0001\b|\blinux production(?:-| )host\b|\bproduction host\b/iu,
  },
  {
    id: 'desired-state-language',
    pattern:
      /\bdesired(?:-| )state\b|\bmust (?:remain|be|run|exist|start|maintain)\b|\brequired deployment\b/iu,
  },
  {
    id: 'presence-cardinality-language',
    pattern:
      /\bpresence\b|\bcardinality\b|\breplicas?\b|\bexactly one\b|\bone (?:module|instance|deployment|container|process)\b/iu,
  },
  {
    id: 'lifecycle-owner-language',
    pattern: /\blifecycle(?:-| )owner\b|\bowner\b|\bownership\b|\bmaintainer\b/iu,
  },
  {
    id: 'reconciler-language',
    pattern:
      /\breconcil(?:e|er|iation|ing)\b|\bcontroller\b|\bsupervisor\b|\brestart(?:-| )policy\b|\bsystemd\b|\bkubernetes\b|\bhelm\b|\bterraform\b|\bansible\b/iu,
  },
  {
    id: 'absence-convergence-language',
    pattern:
      /\b(?:absence|absent|missing)\b[\s\S]{0,160}\b(?:converge|restore|recreate|restart|start|run)\b|\b(?:converge|restore|recreate|restart|start|run)\b[\s\S]{0,160}\b(?:absence|absent|missing)\b/iu,
  },
  {
    id: 'cross-repository-link',
    pattern:
      /OverlayKit\/companion-module-overlaykit-server|github\.com\/OverlayKit\/(?:overlaykit|companion-module-overlaykit-server)/u,
  },
  {
    id: 'deployment-surface-language',
    pattern:
      /\bdeployment\b|\bcontainer\b|\bdocker(?:-| )compose\b|\bservice\b|\binstall(?:ed|ation)?\b/iu,
  },
]);

const KNOWN_NON_TEXT_EXTENSIONS = Object.freeze(
  new Set([
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
  ])
);

function assertion(condition, message) {
  if (!condition) throw new Error(message);
}

function byteCompare(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
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

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function assertGitBlobIdentity(oid, bytes) {
  assertion(OID_PATTERN.test(oid), 'Git blob OID');
  assertion(Buffer.isBuffer(bytes), 'Git blob bytes');
  const actual = createHash('sha1')
    .update(Buffer.from(`blob ${bytes.length}\0`, 'utf8'))
    .update(bytes)
    .digest('hex');
  assertion(actual === oid, `Git blob object identity differs: ${oid}`);
}

export function safeRepositoryPath(value) {
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

export function parseLsTreeZ(treeBytes) {
  assertion(Buffer.isBuffer(treeBytes), 'ls-tree input must be bytes');
  assertion(treeBytes.length > 0 && treeBytes.at(-1) === 0, 'ls-tree must be NUL terminated');
  const records = [];
  const paths = new Set();
  let start = 0;
  for (let index = 0; index < treeBytes.length; index += 1) {
    if (treeBytes[index] !== 0) continue;
    assertion(index > start, 'ls-tree contains an empty record');
    let record;
    try {
      record = FATAL_UTF8.decode(treeBytes.subarray(start, index));
    } catch {
      throw new Error('ls-tree contains a non-UTF-8 record');
    }
    const match = /^(100644|100755) blob ([0-9a-f]{40})\t(.+)$/u.exec(record);
    assertion(match !== null, `ls-tree record is unsupported: ${JSON.stringify(record)}`);
    const [, mode, oid, repositoryPath] = match;
    assertion(safeRepositoryPath(repositoryPath), `ls-tree path is unsafe: ${repositoryPath}`);
    assertion(!repositoryPath.includes('!'), `ls-tree path reserves !: ${repositoryPath}`);
    assertion(!paths.has(repositoryPath), `ls-tree path is duplicated: ${repositoryPath}`);
    paths.add(repositoryPath);
    records.push({ mode, type: 'blob', oid, path: repositoryPath });
    start = index + 1;
  }
  assertion(start === treeBytes.length, 'ls-tree parser did not consume all bytes');
  return records;
}

export function framedSetSha256(entries) {
  assertion(Array.isArray(entries) && entries.length > 0, 'framed set must not be empty');
  const sorted = [...entries].sort((left, right) => {
    const repositoryOrder = byteCompare(left.repository, right.repository);
    return repositoryOrder === 0 ? byteCompare(left.path, right.path) : repositoryOrder;
  });
  const frames = [];
  const identities = new Set();
  for (const entry of sorted) {
    exactKeys(entry, ['repository', 'path', 'mode', 'byteLength', 'sha256'], 'framed source entry');
    assertion(typeof entry.repository === 'string' && entry.repository !== '', 'repository key');
    assertion(safeRepositoryPath(entry.path), `unsafe framed path: ${entry.path}`);
    assertion(['100644', '100755'].includes(entry.mode), `unsupported mode: ${entry.mode}`);
    assertion(Number.isSafeInteger(entry.byteLength) && entry.byteLength >= 0, 'byte length');
    assertion(SHA256_PATTERN.test(entry.sha256), 'source SHA-256');
    const identity = `${entry.repository}\u0000${entry.path}`;
    assertion(!identities.has(identity), `duplicate framed identity: ${identity}`);
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

export function admitSetAnchor(anchor, label = 'set anchor') {
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

function commandKind(repositoryLock, args) {
  if (!Array.isArray(args) || args.some((value) => typeof value !== 'string')) {
    return 'prohibited';
  }
  if (
    args.length === 3 &&
    args[0] === 'cat-file' &&
    args[1] === 'blob' &&
    OID_PATTERN.test(args[2])
  ) {
    return 'cat-file-blob';
  }
  if (
    args.length === 4 &&
    args[0] === 'ls-tree' &&
    args[1] === '-rz' &&
    args[2] === '--full-tree' &&
    args[3] === repositoryLock.commit
  ) {
    return 'ls-tree';
  }
  if (
    args.length === 2 &&
    args[0] === 'rev-parse' &&
    args[1] === `${repositoryLock.commit}^{tree}`
  ) {
    return 'rev-parse-tree';
  }
  return 'prohibited';
}

export function createGitReader({ root, repositoryLock, spawn = spawnSync }) {
  assertion(typeof root === 'string' && path.isAbsolute(root), 'repository root must be absolute');
  assertion(typeof spawn === 'function', 'Git spawn seam must be a function');
  assertion(repositoryLock !== null && typeof repositoryLock === 'object', 'repository lock');
  const rootMetadata = lstatSync(root);
  assertion(
    rootMetadata.isDirectory() && !rootMetadata.isSymbolicLink(),
    'repository root is unsafe'
  );
  assertion(realpathSync(root) === root, 'repository root is not canonical');
  const counts = Object.create(null);

  return {
    git(args) {
      const kind = commandKind(repositoryLock, args);
      assertion(kind !== 'prohibited', `Git command is outside the H-048 allowlist: ${args?.[0]}`);
      counts[kind] = (counts[kind] ?? 0) + 1;
      const result = spawn(GIT_EXECUTABLE, args, {
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
      assertion(result.error === undefined, `git ${args[0]} failed to start`);
      assertion(
        result.status === 0 && result.signal === null,
        `git ${args[0]} failed (${result.status ?? result.signal}): ${String(result.stderr)}`
      );
      return result.stdout;
    },
    counts() {
      return Object.fromEntries(Object.entries(counts).sort());
    },
  };
}

function decodeText(bytes) {
  try {
    return FATAL_UTF8.decode(bytes);
  } catch {
    return null;
  }
}

function parseJsonBytes(bytes, label) {
  const text = decodeText(bytes);
  assertion(text !== null, `${label} is not UTF-8`);
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`${label} is invalid JSON: ${error.message}`);
  }
}

function entryBytes(snapshot, repositoryPath) {
  const entry = snapshot.entries.find((candidate) => candidate.path === repositoryPath);
  assertion(
    entry !== undefined,
    `missing repository path: ${snapshot.repository}/${repositoryPath}`
  );
  const bytes = snapshot.blobsByOid.get(entry.oid);
  assertion(
    Buffer.isBuffer(bytes),
    `missing repository blob: ${snapshot.repository}/${repositoryPath}`
  );
  return { entry, bytes };
}

export function snapshotRepository({ repositoryLock, root, reader }) {
  const tree = decodeText(reader.git(['rev-parse', `${repositoryLock.commit}^{tree}`]))?.trim();
  assertion(tree === repositoryLock.tree, `${repositoryLock.key} tree differs`);
  const treeBytes = reader.git(['ls-tree', '-rz', '--full-tree', repositoryLock.commit]);
  assertion(
    sha256(treeBytes) === repositoryLock.lsTreeSha256,
    `${repositoryLock.key} ls-tree digest differs`
  );
  const entries = parseLsTreeZ(treeBytes);
  assertion(
    entries.length === repositoryLock.entryCount,
    `${repositoryLock.key} entry count differs`
  );
  const blobsByOid = new Map();
  for (const { oid } of entries) {
    if (!blobsByOid.has(oid)) {
      const bytes = reader.git(['cat-file', 'blob', oid]);
      assertGitBlobIdentity(oid, bytes);
      blobsByOid.set(oid, bytes);
    }
  }
  const sourceEntries = entries.map((entry) => {
    const bytes = blobsByOid.get(entry.oid);
    return {
      repository: repositoryLock.key,
      path: entry.path,
      mode: entry.mode,
      oid: entry.oid,
      byteLength: bytes.length,
      sha256: sha256(bytes),
    };
  });
  const planReceipt = entryBytes(
    { repository: repositoryLock.key, entries, blobsByOid },
    '.overlaykit/governance/plan.json'
  );
  const plan = parseJsonBytes(planReceipt.bytes, `${repositoryLock.key} plan`);
  assertion(
    plan !== null && typeof plan === 'object' && !Array.isArray(plan),
    `${repositoryLock.key} plan envelope differs`
  );
  return {
    repository: repositoryLock.key,
    root,
    commit: repositoryLock.commit,
    tree,
    treeBytes,
    entries,
    blobsByOid,
    sourceEntries,
    sourceSetSha256: framedSetSha256(
      sourceEntries.map(({ repository, path, mode, byteLength, sha256: digest }) => ({
        repository,
        path,
        mode,
        byteLength,
        sha256: digest,
      }))
    ),
    plan,
  };
}

export function scanSignals(bytes, repositoryPath) {
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
    roles: SIGNAL_POLICY.filter(({ pattern }) => pattern.test(text)).map(({ id }) => id),
  };
}

function governanceMetadata(snapshot, sourceEntry, bytes) {
  const match =
    /^\.overlaykit\/governance\/(decisions|specifications|changes)\/((?:ADR|SPEC|CHG)-\d{4})\.json$/u.exec(
      sourceEntry.path
    );
  if (match === null) return null;
  const [, collection, id] = match;
  const record = parseJsonBytes(bytes, `${snapshot.repository}/${sourceEntry.path}`);
  assertion(
    record.id === id,
    `governance identity differs at ${snapshot.repository}/${sourceEntry.path}`
  );
  if (collection === 'decisions') {
    const compiled = snapshot.plan.decisions.find((candidate) => candidate.id === id);
    assertion(compiled !== undefined, `${snapshot.repository} plan omits ${id}`);
    return {
      kind: 'decision',
      id,
      declaredStatus: record.status,
      effectiveStatus: compiled.effectiveStatus,
    };
  }
  if (collection === 'specifications') {
    const compiled = snapshot.plan.specifications.find((candidate) => candidate.id === id);
    assertion(compiled !== undefined, `${snapshot.repository} plan omits ${id}`);
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

export function reviewPayloadSha256(reviewMap) {
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
    signalPolicy: SIGNAL_POLICY.map(({ id, pattern }) => ({
      id,
      source: pattern.source,
      flags: pattern.flags,
    })),
    knownNonTextExtensions: [...KNOWN_NON_TEXT_EXTENSIONS].sort(byteCompare),
    indirectionExtraction:
      'literal HTTP-or-HTTPS URLs, nominated repository tokens, and exact nominated commit tokens with noncanonical nominated URLs unresolved',
    indirectionStatuses: {
      resolved: ['resolved-exact-subject'],
      unresolved: [...H048_UNRESOLVED_INDIRECTION_STATUSES].sort(byteCompare),
      terminalExcluded: ['excluded-github-surface', 'excluded-outside-nominated-boundary'],
    },
  };
}

function sortIndirections(indirections) {
  indirections.sort((left, right) => byteCompare(canonicalJson(left), canonicalJson(right)));
  return indirections;
}

export function deriveReviewUniverse({ subjectLock, snapshots, archiveInventory }) {
  assertion(Array.isArray(snapshots) && snapshots.length === 2, 'review universe snapshots');
  assertion(Array.isArray(archiveInventory?.members), 'review universe archive members');
  const sources = [];
  const indirections = [];
  for (const snapshot of snapshots) {
    for (const entry of snapshot.sourceEntries) {
      const bytes = snapshot.blobsByOid.get(entry.oid);
      assertion(Buffer.isBuffer(bytes), `review universe bytes are absent: ${entry.path}`);
      const signal = scanSignals(bytes, entry.path);
      const governance = governanceMetadata(snapshot, entry, bytes);
      sources.push({
        repository: snapshot.repository,
        commit: snapshot.commit,
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
          repository: snapshot.repository,
          ownerCommit: snapshot.commit,
          repositoryPath: entry.path,
          sourceKind: 'git-blob',
          sourceSha256: entry.sha256,
          bytes,
          subjectRepositories: subjectLock.repositories,
        })
      );
    }
  }
  for (const member of archiveInventory.members) {
    const bytes = archiveInventory.memberContents.get(member.virtualPath);
    assertion(Buffer.isBuffer(bytes), `review universe bytes are absent: ${member.virtualPath}`);
    const identity = archiveRepositoryAndPath(
      member.virtualPath,
      snapshots.map((snapshot) => snapshot.repository)
    );
    const repository = subjectLock.repositories.find(
      (candidate) => candidate.key === identity.repository
    );
    assertion(
      repository !== undefined,
      `review universe repository is not nominated: ${identity.repository}`
    );
    const signal = scanSignals(bytes, identity.path);
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
    .map(({ repository, commit, path: repositoryPath, sourceKind, sha256: digest }) => ({
      repository,
      commit,
      path: repositoryPath,
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

export function validateHumanAcceptance({
  reviewMap,
  subjectLock,
  subjectLockBytes,
  expectedReviewUniverse,
  expectedAcceptanceSha256 = H048_EXPECTED_HUMAN_ACCEPTANCE_SHA256,
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
    typeof expectedAcceptanceSha256 === 'string' && SHA256_PATTERN.test(expectedAcceptanceSha256),
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
    reference.sha256 === expectedAcceptanceSha256,
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
  const acceptance = parseJsonBytes(bytes, 'H-048 human acceptance');
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

export function validateReviewMap({
  reviewMap,
  subjectLock,
  subjectLockBytes,
  snapshots,
  archiveInventory,
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
  assertion(reviewMap?.schemaVersion === 'overlaykit-h048-semantic-review/v1', 'review schema');
  assertion(reviewMap.hypothesis === 'H-048', 'review hypothesis');
  assertion(
    ['agent-proposed-pending-human-acceptance', 'human-accepted'].includes(reviewMap.status),
    'review status'
  );
  assertion(reviewMap.authority === 'none' && reviewMap.action === null, 'review authority');
  const reviewUniverse = deriveReviewUniverse({
    subjectLock,
    snapshots,
    archiveInventory,
  });
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
  assertion(Array.isArray(reviewMap.pendingHumanJudgments), 'pending human judgments');
  if (reviewMap.status === 'agent-proposed-pending-human-acceptance') {
    assertion(
      reviewMap.pendingHumanJudgments.length > 0 &&
        new Set(reviewMap.pendingHumanJudgments).size === reviewMap.pendingHumanJudgments.length &&
        reviewMap.pendingHumanJudgments.every(
          (judgment) => typeof judgment === 'string' && judgment !== ''
        ),
      'pending review must enumerate unresolved human judgments'
    );
  } else {
    assertion(
      reviewMap.pendingHumanJudgments.length === 0,
      'human-accepted review must not retain pending judgments'
    );
  }
  assertion(Array.isArray(reviewMap.sources), 'review sources');
  const repositoryByKey = new Map(
    subjectLock.repositories.map((repository) => [repository.key, repository])
  );
  const available = new Map();
  for (const snapshot of snapshots) {
    for (const entry of snapshot.sourceEntries) {
      const sourceBytes = snapshot.blobsByOid.get(entry.oid);
      assertion(Buffer.isBuffer(sourceBytes), `review source bytes are absent: ${entry.path}`);
      available.set(
        sourceIdentityKey({
          repository: snapshot.repository,
          commit: snapshot.commit,
          path: entry.path,
          sourceKind: 'git-blob',
          sha256: entry.sha256,
        }),
        sourceBytes
      );
    }
  }
  for (const member of archiveInventory.members) {
    const identity = archiveRepositoryAndPath(
      member.virtualPath,
      snapshots.map((snapshot) => snapshot.repository)
    );
    const repository = repositoryByKey.get(identity.repository);
    assertion(
      repository !== undefined,
      `archive review repository is not nominated: ${identity.repository}`
    );
    const memberBytes = archiveInventory.memberContents.get(member.virtualPath);
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
  const result = new Map();
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
    assertion(!result.has(key), `duplicate review source: ${key}`);
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
        source.predicateContributions.every((predicate) => H048_PREDICATES.includes(predicate)),
      `review predicates are invalid: ${key}`
    );
    assertion(typeof source.eligibleForChain === 'boolean', `review eligibility: ${key}`);
    result.set(key, source);
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
    const source = result.get(sourceKey);
    assertion(source !== undefined, `chain contribution source is not reviewed: ${sourceKey}`);
    assertion(H048_PREDICATES.includes(contribution.predicate), 'chain contribution predicate');
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
    const key = canonicalJson(contribution);
    assertion(!contributionKeys.has(key), 'duplicate chain contribution');
    contributionKeys.add(key);
    chainContributions.push(contribution);
  }
  const sortedContributions = [...chainContributions].sort((left, right) =>
    byteCompare(canonicalJson(left), canonicalJson(right))
  );
  assertion(
    canonicalJson(chainContributions) === canonicalJson(sortedContributions),
    'chain contributions are not canonically ordered'
  );
  for (const [key, source] of result) {
    const referenced = chainContributions.some(
      (contribution) => sourceIdentityKey(contribution) === key
    );
    assertion(
      source.eligibleForChain === referenced,
      `review eligibility does not match typed contributions: ${key}`
    );
  }
  return {
    sources: result,
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

export function buildArchiveInventory(snapshots) {
  const roots = [];
  for (const snapshot of snapshots) {
    for (const entry of snapshot.entries) {
      if (!ARCHIVE_PATH_PATTERN.test(entry.path)) continue;
      roots.push({
        path: `repositories/${snapshot.repository}/${entry.path}`,
        bytes: snapshot.blobsByOid.get(entry.oid),
      });
    }
  }
  assertion(roots.length > 0, 'H-048 expected at least one tracked archive');
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

function candidateFromSource(snapshot, sourceEntry, reviewSources, universeSources) {
  const key = sourceIdentityKey({
    repository: snapshot.repository,
    commit: snapshot.commit,
    path: sourceEntry.path,
    sourceKind: 'git-blob',
    sha256: sourceEntry.sha256,
  });
  const universe = universeSources.get(key);
  assertion(universe !== undefined, `source is absent from review universe: ${key}`);
  const review = reviewSources.get(key) ?? null;
  if (!universe.defaultCandidateAdmission && review === null) return null;
  if (universe.semanticRoles.length === 0 && review === null && universe.governance === null) {
    return universe.textStatus === 'opaque-non-text'
      ? {
          repository: snapshot.repository,
          commit: snapshot.commit,
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
        }
      : null;
  }
  return {
    repository: snapshot.repository,
    commit: snapshot.commit,
    path: sourceEntry.path,
    mode: sourceEntry.mode,
    oid: sourceEntry.oid,
    byteLength: sourceEntry.byteLength,
    sha256: sourceEntry.sha256,
    sourceKind: 'git-blob',
    textStatus: universe.textStatus,
    semanticRoles: universe.semanticRoles,
    governance: universe.governance,
    classification: review?.classification ?? 'agent-default-no-eligible-predicate-contribution',
    predicateContributions: review?.predicateContributions ?? [],
    eligibleForChain: review?.eligibleForChain ?? false,
    reviewBasis: review === null ? 'agent-default-pending-human-acceptance' : 'exact-review-entry',
    rationale: review?.rationale ?? null,
  };
}

function archiveRepositoryAndPath(virtualPath, repositories) {
  for (const repository of repositories) {
    const prefix = `repositories/${repository}/`;
    if (virtualPath.startsWith(prefix)) {
      return {
        repository,
        path: virtualPath.slice(prefix.length),
      };
    }
  }
  throw new Error(`archive member is outside a repository namespace: ${virtualPath}`);
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

export function indirectionsFromBytes({
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
    if (/^(?:issues|projects|wiki)(?:\/|$)/u.test(suffix)) {
      push({
        kind: 'subject-github-excluded-surface',
        value,
        targetRepository: target.key,
        status: 'excluded-github-surface',
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

export function assembleDesiredStateChains({
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

  const chainComponents = Object.fromEntries(H048_PREDICATES.map((predicate) => [predicate, []]));
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
    for (const predicate of H048_PREDICATES) {
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
      const components = H048_PREDICATES.map((predicate) => selected[predicate]);
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
    missingPredicates: H048_PREDICATES.filter(
      (predicate) =>
        !chainComponents[predicate].some((component) => component.disposition === 'supports')
    ),
    unknowns,
  };
}

function candidateFromArchiveMember(member, subjectRepositories, reviewSources, universeSources) {
  const identity = archiveRepositoryAndPath(
    member.virtualPath,
    subjectRepositories.map((repository) => repository.key)
  );
  const repository = subjectRepositories.find((candidate) => candidate.key === identity.repository);
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
  const review = reviewSources.get(key) ?? null;
  if (!universe.defaultCandidateAdmission && review === null) return null;
  return {
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
      review?.classification ??
      (universe.textStatus === 'opaque-non-text'
        ? 'opaque-archive-member-unreviewed'
        : 'agent-default-historical-or-vendored-archive-content'),
    predicateContributions: review?.predicateContributions ?? [],
    eligibleForChain: review?.eligibleForChain ?? false,
    reviewBasis: review === null ? 'agent-default-pending-human-acceptance' : 'exact-review-entry',
    rationale: review?.rationale ?? null,
  };
}

export function deriveOutcome({ invalid = false, coverageComplete, unknowns, eligibleChains }) {
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

export function buildInventory({
  subjectLock,
  subjectLockBytes,
  reviewMap,
  snapshots,
  archiveInventory,
}) {
  assertion(subjectLock?.schemaVersion === 'overlaykit-h048-subject-lock/v1', 'subject lock');
  assertion(subjectLock.hypothesis === 'H-048', 'subject hypothesis');
  assertion(
    canonicalJson(subjectLock.predicateOrder) === canonicalJson(H048_PREDICATES),
    'predicate order differs'
  );
  assertion(Buffer.isBuffer(subjectLockBytes), 'subject-lock bytes');
  const review = validateReviewMap({
    reviewMap,
    subjectLock,
    subjectLockBytes,
    snapshots,
    archiveInventory,
  });
  const reviewSources = review.sources;
  const universeSources = new Map();
  for (const source of review.universe.material.sourceUniverse) {
    const key = sourceIdentityKey(source);
    assertion(!universeSources.has(key), `duplicate review universe source: ${key}`);
    universeSources.set(key, source);
  }
  const candidates = snapshots
    .flatMap((snapshot) =>
      snapshot.sourceEntries
        .map((entry) => candidateFromSource(snapshot, entry, reviewSources, universeSources))
        .filter((entry) => entry !== null)
    )
    .concat(
      archiveInventory.members
        .map((member) =>
          candidateFromArchiveMember(
            member,
            subjectLock.repositories,
            reviewSources,
            universeSources
          )
        )
        .filter((entry) => entry !== null)
    )
    .sort((left, right) => {
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
      candidates: opaqueCandidates.map(({ repository, path, sourceKind, sha256: digest }) => ({
        repository,
        path,
        sourceKind,
        sha256: digest,
      })),
    });
  }
  const unresolvedIndirections = indirections.filter((indirection) =>
    H048_UNRESOLVED_INDIRECTION_STATUSES.includes(indirection.status)
  );
  if (unresolvedIndirections.length > 0) {
    unknowns.push({
      code: 'unresolved-subject-indirections',
      count: unresolvedIndirections.length,
      indirections: unresolvedIndirections,
    });
  }

  const chainResult = assembleDesiredStateChains({
    chainContributions: review.chainContributions,
    candidates,
    indirections,
    subjectRepositories: subjectLock.repositories,
    target: subjectLock.target,
    reviewAccepted: review.acceptance.accepted,
  });
  unknowns.push(...chainResult.unknowns);
  const coverageComplete = unknowns.length === 0;
  const outcome = deriveOutcome({
    coverageComplete,
    unknowns,
    eligibleChains: chainResult.eligibleChains,
  });
  const claimBoundaryCanonicalSha256 = sha256(
    Buffer.from(canonicalJson(subjectLock.claimBoundary), 'utf8')
  );

  const candidateIndex = {
    schemaVersion: 'overlaykit-h048-candidate-index/v1',
    hypothesis: 'H-048',
    claimBoundary: subjectLock.claimBoundary,
    claimBoundaryCanonicalSha256,
    review: {
      schemaVersion: reviewMap.schemaVersion,
      status: reviewMap.status,
      humanAcceptanceRef: reviewMap.humanAcceptanceRef,
      sourceFileSha256: null,
      canonicalSha256: sha256(Buffer.from(canonicalJson(reviewMap), 'utf8')),
      payloadCanonicalSha256: review.acceptance.payloadSha256,
      acceptanceReceiptSha256: review.acceptance.acceptanceReceiptSha256,
      universe: review.universe.reference,
      exactEntries: reviewSources.size,
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
  return {
    candidateIndex,
    reviewUniverse: review.universe.material,
  };
}

export function assertCanonicalRoot(directory) {
  const metadata = lstatSync(directory);
  assertion(metadata.isDirectory() && !metadata.isSymbolicLink(), `${directory} is unsafe`);
  assertion(realpathSync(directory) === directory, `${directory} is not canonical`);
  assertion(statSync(directory).isDirectory(), `${directory} is not a directory`);
}
