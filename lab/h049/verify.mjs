import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  realpathSync,
  writeSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const GIT_EXECUTABLE = '/usr/bin/git';
const RUN_PATH_PATTERN = /^artifacts\/h049\/[a-z0-9][a-z0-9-]{0,63}$/u;
const IGNORE_PROBE_PATH = 'artifacts/h049/__h049-ignore-probe__';
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const GIT_OID_PATTERN = /^[0-9a-f]{40}$/u;

const PREDICATES = Object.freeze([
  'effectiveAcceptedNormativeAuthority',
  'spec0001LinuxRoleBinding',
  'physicalStreamDeckMk2Scope',
  'postLoginDisconnectOrReenumerationTrigger',
  'automaticRecoveryObligation',
  'physicalCommandDeliveryRestored',
  'observableRecoveryDeadline',
]);

const SUBJECT = Object.freeze({
  commit: '226d299a9b0d8acd592675f514a67d6229d0134a',
  tree: 'f0cd2b22b3c9da7b2c2d2cf5b93baa97dd1a5bcd',
  restrictedLsTreeSha256: 'e9e46d2e5affa66e72df0fbd1ed516c13327ebbb02d668ee92da2a4cd47b93c8',
  planRawSha256: '2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243',
  planHash: 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4',
  sourceSetSha256: '3136aa776e1d15dcc2f3fc3597a6e7011f2b9601492936c5e1da65920a67e218',
});

const SOURCES = Object.freeze([
  {
    path: '.overlaykit/governance/decisions/ADR-0001.json',
    mode: '100644',
    oid: '658d9a65b692eda327c7c0467e43e341e6805496',
    byteLength: 6660,
    sha256: 'e597cbaa8c69d53e197eb82f3baf71a7626f96db0d28a2b54e91c035bef917d6',
  },
  {
    path: '.overlaykit/governance/decisions/ADR-0002.json',
    mode: '100644',
    oid: '279b8ec2585d1a45a13e61ff64a7f86359c7274d',
    byteLength: 4974,
    sha256: '6e99edcf98a6ec3a91c1d74be8fbe2f87b5108de6cc2f240671451b635875a00',
  },
  {
    path: '.overlaykit/governance/decisions/ADR-0003.json',
    mode: '100644',
    oid: '96c92e1b597e351df2979bd47c3d651ac9033880',
    byteLength: 6030,
    sha256: '8d10bfca940203cfa8fcfe96640d3c4c22ff25a14692a4a6ac459a3dc3743ce2',
  },
  {
    path: '.overlaykit/governance/decisions/ADR-0004.json',
    mode: '100644',
    oid: 'b79e367a4c42fabef33c44c636e8d9d202345455',
    byteLength: 4421,
    sha256: '9eb30ec5ed70d282bb4e96674ea44e9796f95cb3fbd41b45f1f77da51f40812d',
  },
  {
    path: '.overlaykit/governance/decisions/ADR-0005.json',
    mode: '100644',
    oid: 'f9500d868b051ff1c3e19eb3e5b8583e09bb5eac',
    byteLength: 7550,
    sha256: 'f59ff9a71f87864fcb2478ce17a92b2f0dc4aa133ca6d01c56fb90ab682cb2d6',
  },
  {
    path: '.overlaykit/governance/decisions/ADR-0006.json',
    mode: '100644',
    oid: '46d087824a500f9dc6bf5fadbd2171fbe1f4aeb9',
    byteLength: 6334,
    sha256: '619fbfe60cc8c4c298c6c1eaaa25825b514b1d36bc0b8ec6588d4c3718b9f360',
  },
  {
    path: '.overlaykit/governance/plan.json',
    mode: '100644',
    oid: '750f5694f9e3abd5025b3a380fe7df8972529761',
    byteLength: 22610,
    sha256: '2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243',
  },
  {
    path: '.overlaykit/governance/specifications/SPEC-0001.json',
    mode: '100644',
    oid: '45a1452e51681107005db9119c9724d29b29e23e',
    byteLength: 10127,
    sha256: '917f1ca2febe17f8901ab71f91a0b0135402f9be972a876f233fcd5c789b8179',
  },
  {
    path: '.overlaykit/governance/specifications/SPEC-0002.json',
    mode: '100644',
    oid: '4ee3541194fd13b5e68f141504a87b915823795d',
    byteLength: 10804,
    sha256: 'd15b1cbf7e97bd92aadf40342421161a0955e210b8566f7ae870dc78c05e89f6',
  },
]);

const HARNESS_SOURCE_PATHS = Object.freeze(
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

const EXPECTED_CANDIDATES = Object.freeze({
  'spec0001-network-reconnect': {
    obligationKey: 'spec0001-retryable-network-server-reconnect',
    classification: 'normative-positive',
    citationCount: 12,
    predicates: {
      effectiveAcceptedNormativeAuthority: true,
      spec0001LinuxRoleBinding: true,
      physicalStreamDeckMk2Scope: false,
      postLoginDisconnectOrReenumerationTrigger: false,
      automaticRecoveryObligation: true,
      physicalCommandDeliveryRestored: false,
      observableRecoveryDeadline: false,
    },
    explicitLinkClosure: true,
    exclusionOrContradiction: true,
  },
  'adr0006-bounded-surface-thread-mechanism': {
    obligationKey: 'adr0006-h042-bounded-mechanism-and-future-preconditions',
    classification: 'future-precondition',
    citationCount: 14,
    predicates: {
      effectiveAcceptedNormativeAuthority: true,
      spec0001LinuxRoleBinding: false,
      physicalStreamDeckMk2Scope: true,
      postLoginDisconnectOrReenumerationTrigger: true,
      automaticRecoveryObligation: false,
      physicalCommandDeliveryRestored: false,
      observableRecoveryDeadline: false,
    },
    explicitLinkClosure: true,
    exclusionOrContradiction: true,
  },
  'spec0002-virtual-action-deadline': {
    obligationKey: 'spec0002-virtual-invocation-to-visible-authoritative-state',
    classification: 'normative-positive',
    citationCount: 10,
    predicates: {
      effectiveAcceptedNormativeAuthority: true,
      spec0001LinuxRoleBinding: false,
      physicalStreamDeckMk2Scope: false,
      postLoginDisconnectOrReenumerationTrigger: false,
      automaticRecoveryObligation: false,
      physicalCommandDeliveryRestored: false,
      observableRecoveryDeadline: false,
    },
    explicitLinkClosure: true,
    exclusionOrContradiction: true,
  },
  'spec0001-button-command-surface': {
    obligationKey: 'spec0001-operator-button-to-authorized-command',
    classification: 'normative-positive',
    citationCount: 14,
    predicates: {
      effectiveAcceptedNormativeAuthority: true,
      spec0001LinuxRoleBinding: true,
      physicalStreamDeckMk2Scope: false,
      postLoginDisconnectOrReenumerationTrigger: false,
      automaticRecoveryObligation: false,
      physicalCommandDeliveryRestored: false,
      observableRecoveryDeadline: false,
    },
    explicitLinkClosure: true,
    exclusionOrContradiction: true,
  },
  'strongest-cross-domain-composite': {
    obligationKey: 'invalid-spec0001-adr0006-spec0002-cartesian-stitch',
    classification: 'cross-domain-composite',
    citationCount: 13,
    predicates: {
      effectiveAcceptedNormativeAuthority: true,
      spec0001LinuxRoleBinding: true,
      physicalStreamDeckMk2Scope: true,
      postLoginDisconnectOrReenumerationTrigger: true,
      automaticRecoveryObligation: true,
      physicalCommandDeliveryRestored: false,
      observableRecoveryDeadline: false,
    },
    explicitLinkClosure: false,
    exclusionOrContradiction: true,
  },
});

const REVIEW_RAW_SHA256 = '6b07f91932451ceacc9a28d28116404328f0fb4143160ff58a73c8dbf50d9782';
const REVIEW_CANONICAL_SHA256 = '6e4c69836c57de051cd92826b5ac9103b7a9eeef2f1b0fb072f5df8f9c8db928';
const CLAUSE_UNIVERSE_SHA256 = '637671ba036157351305e3bf023645bcebb9f8ab0ec19d37e4988799754e7c79';

const ADR_ASSESSMENT = Object.freeze({
  status: 'no-decision-candidate-activated',
  rationaleCode: 'normative-audit-selects-no-product-or-production-architecture',
  futureDecisionQuestion:
    'whether the human principal wants a successor product specification for physical MK.2 recovery before any controller architecture is investigated',
  authority: 'none',
  action: null,
});

const CLAIM_BOUNDARY = Object.freeze({
  subject:
    'only plan.json, ADR-0001 through ADR-0006, and SPEC-0001 through SPEC-0002 at main@226d299a9b0d8acd592675f514a67d6229d0134a',
  conclusion:
    'the pre-review result classifies only whether that exact accepted-law boundary contains an explicit seven-predicate automatic physical MK.2 recovery obligation',
  excluded:
    'external policy, future product intent, live host state, USB or hidraw behavior, controller safety, implementation authority, ADR or specification authority, production policy, and action authority remain unknown',
});

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

function assertion(condition, message) {
  if (!condition) throw new Error(message);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, expected, label) {
  assertion(isObject(value), `${label} object`);
  assertion(
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort()),
    `${label} keys`
  );
}

function canonicalize(value, seen = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    assertion(Number.isFinite(value), 'non-finite canonical number');
    return value;
  }
  assertion(!seen.has(value), 'canonical cycle');
  seen.add(value);
  if (Array.isArray(value)) {
    const result = value.map((item) => canonicalize(item, seen));
    seen.delete(value);
    return result;
  }
  assertion(isObject(value), 'canonical plain object');
  const result = {};
  for (const key of Object.keys(value).sort()) result[key] = canonicalize(value[key], seen);
  seen.delete(value);
  return result;
}

export function canonicalIndependentJson(value) {
  return JSON.stringify(canonicalize(value));
}

function canonicalBytes(value) {
  return Buffer.from(`${canonicalIndependentJson(value)}\n`, 'utf8');
}

export function independentSha256(value) {
  return createHash('sha256')
    .update(Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8'))
    .digest('hex');
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch (error) {
    throw new Error(`${label} invalid JSON: ${error.message}`);
  }
}

function oneLine(bytes, label) {
  const value = new TextDecoder('utf-8', { fatal: true }).decode(bytes).trim();
  assertion(value !== '' && !value.includes('\n') && !value.includes('\r'), `${label} one line`);
  return value;
}

function safeReadRegularFile(absolutePath, label, expectedMode) {
  let descriptor;
  try {
    descriptor = openSync(absolutePath, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
  } catch {
    throw new Error(`unsafe ${label}`);
  }
  try {
    const before = fstatSync(descriptor, { bigint: true });
    assertion(
      before.isFile() && (before.mode & 0o777n) === BigInt(expectedMode) && before.nlink === 1n,
      `unsafe ${label}`
    );
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor, { bigint: true });
    assertion(
      before.dev === after.dev &&
        before.ino === after.ino &&
        before.size === after.size &&
        before.mtimeNs === after.mtimeNs &&
        before.ctimeNs === after.ctimeNs &&
        after.size === BigInt(bytes.length),
      `${label} changed while being read`
    );
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

function parseTree(bytes) {
  assertion(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.at(-1) === 0, 'tree NUL stream');
  const entries = [];
  let start = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] !== 0) continue;
    const record = bytes.subarray(start, index);
    const tab = record.indexOf(9);
    assertion(tab > 0, 'tree tab');
    const [mode, type, oid] = record.subarray(0, tab).toString('ascii').split(' ');
    const sourcePath = new TextDecoder('utf-8', { fatal: true }).decode(record.subarray(tab + 1));
    assertion(mode === '100644' && type === 'blob' && GIT_OID_PATTERN.test(oid), 'tree entry');
    entries.push({ path: sourcePath, mode, type, oid });
    start = index + 1;
  }
  assertion(
    new Set(entries.map(({ path: value }) => value)).size === entries.length,
    'tree duplicates'
  );
  return entries;
}

function unescapePointer(value) {
  return value.replaceAll('~1', '/').replaceAll('~0', '~');
}

function escapePointer(value) {
  return value.replaceAll('~', '~0').replaceAll('/', '~1');
}

function resolvePointer(value, pointer) {
  assertion(typeof pointer === 'string' && pointer.startsWith('/'), 'pointer syntax');
  let cursor = value;
  for (const token of pointer.slice(1).split('/').map(unescapePointer)) {
    if (Array.isArray(cursor)) {
      assertion(/^(0|[1-9][0-9]*)$/u.test(token), 'array pointer');
      cursor = cursor[Number(token)];
    } else {
      assertion(isObject(cursor) && Object.hasOwn(cursor, token), `pointer missing ${pointer}`);
      cursor = cursor[token];
    }
    assertion(cursor !== undefined, `pointer undefined ${pointer}`);
  }
  return cursor;
}

function role(pointer) {
  return pointer.slice(1).split('/').map(unescapePointer).slice(-3).join('/');
}

function collectStrings(value, sourcePath, pointer = '', clauses = []) {
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    clauses.push({
      sourcePath,
      pointer: pointer || '/',
      structuralRole: role(pointer || '/'),
      value,
      valueByteLength: bytes.length,
      valueSha256: independentSha256(bytes),
    });
  } else if (Array.isArray(value)) {
    value.forEach((item, index) =>
      collectStrings(item, sourcePath, `${pointer}/${index}`, clauses)
    );
  } else if (isObject(value)) {
    for (const key of Object.keys(value).sort()) {
      collectStrings(value[key], sourcePath, `${pointer}/${escapePointer(key)}`, clauses);
    }
  }
  return clauses;
}

function commandKey(args) {
  if (!Array.isArray(args) || args.some((value) => typeof value !== 'string')) return 'prohibited';
  if (
    JSON.stringify(args) ===
    JSON.stringify(['check-ignore', '-v', '--no-index', '--', IGNORE_PROBE_PATH])
  ) {
    return 'check-ignore';
  }
  if (
    JSON.stringify(args) === JSON.stringify(['rev-parse', `${SUBJECT.commit}^{commit}`]) ||
    JSON.stringify(args) === JSON.stringify(['rev-parse', `${SUBJECT.commit}^{tree}`])
  ) {
    return 'rev-parse';
  }
  if (
    JSON.stringify(args) ===
    JSON.stringify([
      'ls-tree',
      '-rz',
      '--full-tree',
      SUBJECT.commit,
      '--',
      ...SOURCES.map(({ path: value }) => value),
    ])
  ) {
    return 'restricted-ls-tree';
  }
  if (
    args.length === 3 &&
    args[0] === 'cat-file' &&
    args[1] === 'blob' &&
    SOURCES.some(({ oid }) => oid === args[2])
  ) {
    return 'cat-file-blob';
  }
  return 'prohibited';
}

function createReader({ spawn = spawnSync } = {}) {
  const counts = Object.create(null);
  function git(args) {
    const key = commandKey(args);
    assertion(key !== 'prohibited', 'independent Git allowlist');
    counts[key] = (counts[key] ?? 0) + 1;
    const result = spawn(GIT_EXECUTABLE, args, {
      cwd: REPOSITORY_ROOT,
      encoding: null,
      env: { ...FIXED_GIT_ENVIRONMENT },
      maxBuffer: 2 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    assertion(
      result.error === undefined && result.status === 0 && result.signal === null,
      `independent git failure ${args[0]}`
    );
    return result.stdout;
  }
  return { git, counts: () => Object.fromEntries(Object.entries(counts).sort()) };
}

function assertIgnoredArtifactBoundary(reader) {
  const result = oneLine(
    reader.git(['check-ignore', '-v', '--no-index', '--', IGNORE_PROBE_PATH]),
    'ignore policy'
  );
  assertion(
    result === `.gitignore:5:artifacts/\t${IGNORE_PROBE_PATH}`,
    'H-049 artifact path is not ignored by the exact governed rule'
  );
}

function reconstructNormative(reader) {
  assertion(
    oneLine(reader.git(['rev-parse', `${SUBJECT.commit}^{commit}`]), 'commit') === SUBJECT.commit,
    'independent commit'
  );
  assertion(
    oneLine(reader.git(['rev-parse', `${SUBJECT.commit}^{tree}`]), 'tree') === SUBJECT.tree,
    'independent tree'
  );
  const treeBytes = reader.git([
    'ls-tree',
    '-rz',
    '--full-tree',
    SUBJECT.commit,
    '--',
    ...SOURCES.map(({ path: value }) => value),
  ]);
  assertion(independentSha256(treeBytes) === SUBJECT.restrictedLsTreeSha256, 'tree digest');
  const entries = parseTree(treeBytes);
  assertion(entries.length === 9, 'nine tree entries');
  const parsed = new Map();
  const sourceMapEntries = [];
  entries.forEach((entry, index) => {
    const expected = SOURCES[index];
    assertion(
      entry.path === expected.path && entry.mode === expected.mode && entry.oid === expected.oid,
      'tree identity'
    );
    const bytes = reader.git(['cat-file', 'blob', entry.oid]);
    const actual = {
      path: entry.path,
      mode: entry.mode,
      oid: entry.oid,
      byteLength: bytes.length,
      sha256: independentSha256(bytes),
    };
    assertion(
      canonicalIndependentJson(actual) === canonicalIndependentJson(expected),
      `source ${entry.path}`
    );
    sourceMapEntries.push(actual);
    parsed.set(entry.path, parseJson(bytes, entry.path));
  });
  const plan = parsed.get('.overlaykit/governance/plan.json');
  assertion(plan.planHash === SUBJECT.planHash, 'planHash');
  assertion(plan.decisions.length === 6 && plan.specifications.length === 2, 'plan cardinality');
  [...plan.decisions, ...plan.specifications].forEach((record) => {
    assertion(
      record.declaredStatus === 'accepted' &&
        record.effectiveStatus === 'accepted' &&
        record.supersededBy === null,
      `accepted state ${record.id}`
    );
    const directory = record.id.startsWith('ADR-') ? 'decisions' : 'specifications';
    const source = SOURCES.find(
      ({ path: value }) => value === `.overlaykit/governance/${directory}/${record.id}.json`
    );
    assertion(
      source !== undefined && record.contentHash === source.sha256,
      `plan source hash ${record.id}`
    );
  });
  const sourceSetSha256 = independentSha256(canonicalIndependentJson(sourceMapEntries));
  assertion(sourceSetSha256 === SUBJECT.sourceSetSha256, 'source set digest');
  const sourceMap = {
    schemaVersion: 'overlaykit-h049-source-map/v1',
    hypothesis: 'H-049',
    subject: {
      commit: SUBJECT.commit,
      tree: SUBJECT.tree,
      restrictedLsTreeSha256: SUBJECT.restrictedLsTreeSha256,
      planRawSha256: SUBJECT.planRawSha256,
      planHash: SUBJECT.planHash,
    },
    sourceSetSha256,
    sourceCount: 9,
    sources: sourceMapEntries,
  };
  const clauses = [];
  for (const source of sourceMapEntries)
    collectStrings(parsed.get(source.path), source.path, '', clauses);
  assertion(clauses.length === 901, 'clause count');
  assertion(
    new Set(clauses.map(({ sourcePath, pointer }) => `${sourcePath}\u0000${pointer}`)).size === 901,
    'clause identities'
  );
  const clauseUniverse = {
    schemaVersion: 'overlaykit-h049-clause-universe/v1',
    hypothesis: 'H-049',
    subject: {
      commit: SUBJECT.commit,
      tree: SUBJECT.tree,
      sourceSetSha256,
    },
    clauseCount: 901,
    clauses,
  };
  assertion(
    independentSha256(canonicalBytes(clauseUniverse)) === CLAUSE_UNIVERSE_SHA256,
    'universe hash'
  );
  return { sourceMap, clauseUniverse, parsed };
}

function verifyReview(review, reviewBytes, normative) {
  assertion(independentSha256(reviewBytes) === REVIEW_RAW_SHA256, 'review raw hash');
  assertion(
    independentSha256(canonicalBytes(review)) === REVIEW_CANONICAL_SHA256,
    'review canonical hash'
  );
  assertion(review.status === 'agent-proposed-pending-human-acceptance', 'review status');
  assertion(review.humanAcceptanceRef === null, 'review acceptance');
  assertion(review.authority === 'none' && review.action === null, 'review authority');
  assertion(
    review.clauseUniverse.clauseCount === 901 &&
      review.clauseUniverse.sha256 === CLAUSE_UNIVERSE_SHA256,
    'review universe binding'
  );
  assertion(
    review.defaultDisposition.classification === 'no-additional-eligible-chain' &&
      review.defaultDisposition.allUnlistedClauses === true &&
      review.defaultDisposition.humanAcceptanceRequired === true,
    'review default'
  );
  assertion(review.pendingHumanJudgments.length === 9, 'nine review judgments');
  assertion(review.candidates.length === 5, 'five candidates');
  const clauseByKey = new Map(
    normative.clauseUniverse.clauses.map((clause) => [
      `${clause.sourcePath}\u0000${clause.pointer}`,
      clause,
    ])
  );
  const candidates = review.candidates.map((candidate) => {
    const expected = EXPECTED_CANDIDATES[candidate.id];
    assertion(expected !== undefined, `unexpected candidate ${candidate.id}`);
    assertion(candidate.obligationKey === expected.obligationKey, `obligation ${candidate.id}`);
    assertion(
      candidate.classification === expected.classification,
      `classification ${candidate.id}`
    );
    assertion(candidate.citations.length === expected.citationCount, `citations ${candidate.id}`);
    assertion(
      canonicalIndependentJson(candidate.predicates) ===
        canonicalIndependentJson(expected.predicates),
      `predicates ${candidate.id}`
    );
    assertion(
      candidate.explicitLinkClosure === expected.explicitLinkClosure,
      `links ${candidate.id}`
    );
    assertion(
      candidate.exclusionOrContradiction === expected.exclusionOrContradiction,
      `exclusion ${candidate.id}`
    );
    const citationKeys = new Set();
    for (const citation of candidate.citations) {
      const key = `${citation.sourcePath}\u0000${citation.pointer}`;
      assertion(!citationKeys.has(key), `duplicate citation ${candidate.id}`);
      citationKeys.add(key);
      const clause = clauseByKey.get(key);
      assertion(
        clause !== undefined && clause.valueSha256 === citation.valueSha256,
        `citation ${key}`
      );
      const value = resolvePointer(normative.parsed.get(citation.sourcePath), citation.pointer);
      assertion(
        typeof value === 'string' && independentSha256(value) === citation.valueSha256,
        `pointer ${key}`
      );
    }
    const eligible =
      PREDICATES.every((predicate) => candidate.predicates[predicate] === true) &&
      candidate.explicitLinkClosure === true &&
      candidate.exclusionOrContradiction === false;
    return { ...candidate, eligible };
  });
  assertion(
    new Set(candidates.map(({ id }) => id)).size === Object.keys(EXPECTED_CANDIDATES).length,
    'candidate identity set'
  );
  const unknowns = review.pendingHumanJudgments.map((statement, index) => ({
    id: `human-review-${String(index + 1).padStart(2, '0')}`,
    stage: 'semantic-review',
    statement,
  }));
  const outcome = {
    status: 'inconclusive',
    stage: 'semantic-review',
    reasonCode: 'human-review-pending-or-semantic-coverage-incomplete',
  };
  const projectedOutcomeIfExactMapAccepted = {
    status: 'refuted',
    stage: 'closed-accepted-law-boundary',
    reasonCode: 'complete-zero-chain-coverage',
    condition: 'only-after-exact-map-content-addressed-human-acceptance-and-zero-pending-judgments',
  };
  const candidateIndex = {
    schemaVersion: 'overlaykit-h049-candidate-index/v1',
    hypothesis: 'H-049',
    predicates: PREDICATES,
    chainInvariant:
      'one obligationKey, explicit link closure, all seven predicates true, and no exclusion or contradiction',
    mechanicalCoverageComplete: true,
    semanticReview: {
      status: review.status,
      humanAcceptanceRef: null,
      pendingHumanJudgments: review.pendingHumanJudgments,
      coverageComplete: false,
    },
    candidates,
    eligibleChains: [],
    unknowns,
    outcome,
    projectedOutcomeIfExactMapAccepted,
    adrAssessment: ADR_ASSESSMENT,
    authority: 'none',
    action: null,
  };
  return { candidateIndex, outcome, projectedOutcomeIfExactMapAccepted };
}

function currentHarnessSourceMap() {
  const sources = HARNESS_SOURCE_PATHS.map((relativePath) => {
    const absolute = path.join(REPOSITORY_ROOT, relativePath);
    const bytes = safeReadRegularFile(absolute, `harness source ${relativePath}`, 0o644);
    return {
      path: relativePath,
      mode: '0644',
      byteLength: bytes.length,
      sha256: independentSha256(bytes),
    };
  });
  return {
    schemaVersion: 'overlaykit-h049-harness-source-map/v1',
    hypothesis: 'H-049',
    sourceCount: 13,
    sourceSetSha256: independentSha256(canonicalIndependentJson(sources)),
    sources,
  };
}

function artifactReference(file, bytes) {
  return { file, byteLength: bytes.length, sha256: independentSha256(bytes) };
}

function semanticDigest(artifacts, outcome) {
  return independentSha256(
    canonicalIndependentJson({
      schemaVersion: 'overlaykit-h049-semantic-evidence/v1',
      hypothesis: 'H-049',
      subject: SUBJECT.commit,
      artifacts,
      outcome,
      adrAssessment: ADR_ASSESSMENT,
      authority: 'none',
      action: null,
      claimBoundary: CLAIM_BOUNDARY,
    })
  );
}

function safeRunDirectory(relativePath) {
  assertion(RUN_PATH_PATTERN.test(relativePath), 'run path outside H-049 policy');
  const h049Root = path.join(REPOSITORY_ROOT, 'artifacts/h049');
  assertion(existsSync(h049Root), 'H-049 artifact root absent');
  const rootMetadata = lstatSync(h049Root);
  assertion(
    rootMetadata.isDirectory() &&
      !rootMetadata.isSymbolicLink() &&
      (rootMetadata.mode & 0o777) === 0o700,
    'unsafe H-049 root'
  );
  const absolute = path.join(REPOSITORY_ROOT, relativePath);
  const metadata = lstatSync(absolute);
  assertion(
    metadata.isDirectory() && !metadata.isSymbolicLink() && (metadata.mode & 0o777) === 0o700,
    'unsafe run directory'
  );
  assertion(
    realpathSync(absolute).startsWith(`${realpathSync(h049Root)}${path.sep}`),
    'run directory escapes root'
  );
  return absolute;
}

function readArtifact(directory, file) {
  const absolute = path.join(directory, file);
  const bytes = safeReadRegularFile(absolute, `artifact ${file}`, 0o600);
  return { bytes, value: parseJson(bytes, file) };
}

function compareArtifact(actual, expected, label) {
  const expectedBytes = canonicalBytes(expected);
  assertion(actual.bytes.equals(expectedBytes), `${label} bytes differ`);
  assertion(
    canonicalIndependentJson(actual.value) === canonicalIndependentJson(expected),
    `${label} semantic value differs`
  );
  return expectedBytes;
}

export function verifyH049(relativeRunPath, { reader = createReader() } = {}) {
  const harnessSourceMapBefore = currentHarnessSourceMap();
  const directory = safeRunDirectory(relativeRunPath);
  const actual = {
    harnessSourceMap: readArtifact(directory, 'harness-source-map.json'),
    sourceMap: readArtifact(directory, 'source-map.json'),
    clauseUniverse: readArtifact(directory, 'clause-universe.json'),
    candidateIndex: readArtifact(directory, 'candidate-index.json'),
    run: readArtifact(directory, 'run.json'),
  };
  assertIgnoredArtifactBoundary(reader);
  const normative = reconstructNormative(reader);
  const reviewBytes = safeReadRegularFile(
    path.join(REPOSITORY_ROOT, 'lab/h049/review-map.json'),
    'review map',
    0o644
  );
  const review = parseJson(reviewBytes, 'review map');
  const reviewed = verifyReview(review, reviewBytes, normative);
  const harnessSourceMap = harnessSourceMapBefore;
  const bytes = {
    harnessSourceMap: compareArtifact(
      actual.harnessSourceMap,
      harnessSourceMap,
      'harness source map'
    ),
    sourceMap: compareArtifact(actual.sourceMap, normative.sourceMap, 'source map'),
    clauseUniverse: compareArtifact(
      actual.clauseUniverse,
      normative.clauseUniverse,
      'clause universe'
    ),
    candidateIndex: compareArtifact(
      actual.candidateIndex,
      reviewed.candidateIndex,
      'candidate index'
    ),
  };
  const artifacts = {
    harnessSourceMap: artifactReference('harness-source-map.json', bytes.harnessSourceMap),
    sourceMap: artifactReference('source-map.json', bytes.sourceMap),
    clauseUniverse: artifactReference('clause-universe.json', bytes.clauseUniverse),
    candidateIndex: artifactReference('candidate-index.json', bytes.candidateIndex),
  };
  const semanticEvidenceSha256 = semanticDigest(artifacts, reviewed.outcome);
  const expectedRun = {
    schemaVersion: 'overlaykit-h049-normative-recovery-obligation-run/v1',
    hypothesis: 'H-049',
    subject: {
      commit: SUBJECT.commit,
      tree: SUBJECT.tree,
      sourceCount: 9,
      sourceSetSha256: SUBJECT.sourceSetSha256,
      restrictedLsTreeSha256: SUBJECT.restrictedLsTreeSha256,
      planRawSha256: SUBJECT.planRawSha256,
      planHash: SUBJECT.planHash,
    },
    harness: {
      sourceCount: 13,
      sourceSetSha256: harnessSourceMap.sourceSetSha256,
      reviewMapRawSha256: REVIEW_RAW_SHA256,
      reviewMapCanonicalSha256: REVIEW_CANONICAL_SHA256,
    },
    artifacts,
    summary: {
      clauses: 901,
      candidates: 5,
      pendingHumanJudgments: 9,
      eligibleChains: 0,
      mechanicalCoverageComplete: true,
      semanticCoverageComplete: false,
    },
    outcome: reviewed.outcome,
    projectedOutcomeIfExactMapAccepted: reviewed.projectedOutcomeIfExactMapAccepted,
    adrAssessment: ADR_ASSESSMENT,
    capabilityAudit: {
      mode: 'offline-read-only-normative-subject',
      gitExecutable: GIT_EXECUTABLE,
      commandPolicy: [
        'git check-ignore -v --no-index -- artifacts/h049/__h049-ignore-probe__',
        'git rev-parse <fixed-subject>^{commit|tree}',
        'git ls-tree -rz --full-tree <fixed-subject> -- <nine-fixed-paths>',
        'git cat-file blob <one-of-nine-fixed-oids>',
      ],
      commandCounts: reader.counts(),
      fixedGitEnvironment: FIXED_GIT_ENVIRONMENT,
      sourceBinding: 'on-disk-preflight-and-postflight-no-loader-attestation',
      trackedReads: HARNESS_SOURCE_PATHS,
      ignoredWriteRoot: 'artifacts/h049',
      outputFiles: [
        'harness-source-map.json',
        'source-map.json',
        'clause-universe.json',
        'candidate-index.json',
        'run.json',
      ],
      prohibitedCapabilities: [
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
      ],
    },
    authority: 'none',
    action: null,
    claimBoundary: CLAIM_BOUNDARY,
    semanticEvidenceSha256,
  };
  const runBytes = compareArtifact(actual.run, expectedRun, 'run');
  assertion(
    canonicalIndependentJson(currentHarnessSourceMap()) ===
      canonicalIndependentJson(harnessSourceMapBefore),
    'H-049 harness sources changed during verification'
  );
  const verification = {
    schemaVersion: 'overlaykit-h049-independent-verification/v1',
    hypothesis: 'H-049',
    subject: {
      commit: SUBJECT.commit,
      tree: SUBJECT.tree,
      sourceSetSha256: SUBJECT.sourceSetSha256,
    },
    harnessSourceSetSha256: harnessSourceMap.sourceSetSha256,
    artifacts: {
      harnessSourceMap: artifacts.harnessSourceMap,
      sourceMap: artifacts.sourceMap,
      clauseUniverse: artifacts.clauseUniverse,
      candidateIndex: artifacts.candidateIndex,
      run: artifactReference('run.json', runBytes),
    },
    review: {
      status: review.status,
      humanAcceptanceRef: null,
      rawSha256: REVIEW_RAW_SHA256,
      canonicalSha256: REVIEW_CANONICAL_SHA256,
      pendingHumanJudgments: 9,
    },
    summary: expectedRun.summary,
    outcome: reviewed.outcome,
    projectedOutcomeIfExactMapAccepted: reviewed.projectedOutcomeIfExactMapAccepted,
    semanticEvidenceSha256,
    checks: {
      subjectClosure: true,
      compiledLawStatus: true,
      clauseUniverseClosure: true,
      candidateCitationClosure: true,
      exactPendingReviewMapPreserved: true,
      reviewPendingFailClosed: true,
      artifactCanonicality: true,
      harnessSourceStability: true,
      capabilityBoundary: true,
      authorityBoundary: true,
    },
    verified: true,
    authority: 'none',
    action: null,
  };
  return { verification, bytes: canonicalBytes(verification) };
}

function writeExclusive(absolutePath, bytes) {
  const descriptor = openSync(
    absolutePath,
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | (fsConstants.O_NOFOLLOW ?? 0),
    0o600
  );
  try {
    let offset = 0;
    while (offset < bytes.length) offset += writeSync(descriptor, bytes, offset);
    fchmodSync(descriptor, 0o600);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

export function verifyAndWriteH049(relativeRunPath) {
  const result = verifyH049(relativeRunPath);
  const directory = safeRunDirectory(relativeRunPath);
  const output = path.join(directory, 'verification.json');
  assertion(!existsSync(output), 'verification artifact already exists');
  writeExclusive(output, result.bytes);
  return {
    output,
    semanticEvidenceSha256: result.verification.semanticEvidenceSha256,
    outcome: result.verification.outcome,
    verified: true,
  };
}

function parseCli(argumentsList) {
  assertion(
    Array.isArray(argumentsList) && argumentsList.length === 2 && argumentsList[0] === '--run',
    'usage: node lab/h049/verify.mjs --run artifacts/h049/<run-id>'
  );
  assertion(RUN_PATH_PATTERN.test(argumentsList[1]), 'run path outside H-049 policy');
  return argumentsList[1];
}

const isMain =
  process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const result = verifyAndWriteH049(parseCli(process.argv.slice(2)));
  process.stdout.write(
    `${canonicalIndependentJson({
      output: path.relative(REPOSITORY_ROOT, result.output),
      semanticEvidenceSha256: result.semanticEvidenceSha256,
      outcome: result.outcome,
      verified: true,
      authority: 'none',
      action: null,
    })}\n`
  );
}
