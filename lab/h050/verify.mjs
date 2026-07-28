import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const LAB_DIRECTORY = path.dirname(new URL(import.meta.url).pathname);
export const H050_REPOSITORY_ROOT = realpathSync(path.resolve(LAB_DIRECTORY, '../..'));

const GIT_EXECUTABLE = '/usr/bin/git';
const SUBJECT_LOCK_PATH = path.join(LAB_DIRECTORY, 'subject-lock.json');
const DOCKET_PATH = path.join(LAB_DIRECTORY, 'product-intent-docket.json');
const SUBJECT_LOCK_RAW_SHA256 = '6588b1d31321ecf77616a9952a68620383de4a3b336829074ec632980a68239e';
const DOCKET_RAW_SHA256 = '7a145c440af25f5bbbb71c111381f886dccba387e6a0880853e666ceabea6684';

const SUBJECT = Object.freeze({
  commit: '2810e63defe37025f575ebea37be7e1c5e97c18e',
  tree: '421ae43dbac2b52fe4dc7f594fda795a870b4c10',
  sourceCount: 13,
  restrictedLsTreeSha256: '57c794871d39e2fd9f1cb78d69126477a5c9b6121afc39699e258e8e061718b7',
  sourceSetSha256: 'a9b0c3a354fbdea6867f4343d69a051763395a882ae2dea8c76ff8ff6c20732b',
  planRawSha256: '2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243',
  planHash: 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4',
  manifestRawSha256: '1a32305c13fedf67a1a0e76cd8d9040dc91e39da16df5719fa889187f89c98d9',
  manifestContentHash: '8bcf82852821ceee10c951a89ce34bb692346b0fc2ea23613bddc2f05a17f152',
});

const SOURCES = Object.freeze([
  {
    path: '.overlaykit/governance/changes/CHG-0023.json',
    mode: '100644',
    oid: 'f1c60a668ff5b72003639a3f5e957bf6198dfa5c',
    byteLength: 16128,
    sha256: '99db59f15b1a4850b9c043ffe687c354bf33762c23f141a10f0e53474b5c2266',
  },
  {
    path: '.overlaykit/governance/changes/CHG-0025.json',
    mode: '100644',
    oid: '0d6d68072f5f18763fd0b917b9a889faed53803e',
    byteLength: 16696,
    sha256: '8121de0e241a8a2816aa172402ad9bec3614b4c725c71b7e59261ac995e3a470',
  },
  {
    path: '.overlaykit/governance/changes/CHG-0027.json',
    mode: '100644',
    oid: 'f89f99ed193a309f4128de32f875b913d076f1f3',
    byteLength: 17459,
    sha256: 'db9063cd01d280a1f3481b6374eafa62dd406e1f5ff1e04ea3cc3d7efa15620d',
  },
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
    path: '.overlaykit/governance/manifest.json',
    mode: '100644',
    oid: 'c56f7f24f28671cef1461ca4a3fea2673a6cedf2',
    byteLength: 4188,
    sha256: '1a32305c13fedf67a1a0e76cd8d9040dc91e39da16df5719fa889187f89c98d9',
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

export const H050_PREDICATES = Object.freeze([
  'automaticRecoveryObligation',
  'linuxRoleAndPhysicalMk2Scope',
  'triggerAndIdentityContinuity',
  'restoredPhysicalCommandDelivery',
  'recoveryDeadlineAndClock',
  'degradedFailureAndManualFallback',
  'safetySecurityAndAuthorityBoundary',
  'acceptanceEvidenceAndScenarioCoverage',
  'specificationRelationship',
]);

const PREDICATE_QUESTIONS = Object.freeze({
  automaticRecoveryObligation:
    'Is recovery after the nominated physical interruption mandatory and automatic rather than optional, investigatory, best-effort, or manual?',
  linuxRoleAndPhysicalMk2Scope:
    'Which SPEC-0001 Linux production role and which physical Stream Deck MK.2 surface are governed by the obligation?',
  triggerAndIdentityContinuity:
    'Which post-login disconnect, return, or re-enumeration event starts the obligation, and how is the same governed physical device identified?',
  restoredPhysicalCommandDelivery:
    'Which observable physical-key-to-Companion-to-authorized-OverlayKit-command outcome proves recovery rather than descriptor or marker reacquisition alone?',
  recoveryDeadlineAndClock:
    'What maximum recovery duration applies, and what exact observable event starts and stops its monotonic clock?',
  degradedFailureAndManualFallback:
    'What visible degraded state, retry limit, terminal failure, and manual fallback are required when automatic recovery does not converge?',
  safetySecurityAndAuthorityBoundary:
    'What identity, race, repeated-intervention, credential, configuration, and server-authority constraints must recovery preserve?',
  acceptanceEvidenceAndScenarioCoverage:
    'Which causal observations and scenarios, including repeated recovery, long outage, and multiple-device cases, are required for product acceptance?',
  specificationRelationship:
    'Must a later product specification supersede, extend, or remain separate from SPEC-0001 and SPEC-0002 without rewriting either accepted record?',
});

const SOURCE_ROLES = Object.freeze({
  normativeLaw: [
    '.overlaykit/governance/decisions/ADR-0001.json',
    '.overlaykit/governance/decisions/ADR-0002.json',
    '.overlaykit/governance/decisions/ADR-0003.json',
    '.overlaykit/governance/decisions/ADR-0004.json',
    '.overlaykit/governance/decisions/ADR-0005.json',
    '.overlaykit/governance/decisions/ADR-0006.json',
    '.overlaykit/governance/plan.json',
    '.overlaykit/governance/specifications/SPEC-0001.json',
    '.overlaykit/governance/specifications/SPEC-0002.json',
  ],
  acceptedEvidenceFindings: [
    '.overlaykit/governance/changes/CHG-0023.json',
    '.overlaykit/governance/changes/CHG-0025.json',
    '.overlaykit/governance/changes/CHG-0027.json',
  ],
  integrityIndex: ['.overlaykit/governance/manifest.json'],
});

const LOCK_BOUNDARY = Object.freeze({
  subject: 'only the thirteen nominated Git blobs at main@2810e63defe37025f575ebea37be7e1c5e97c18e',
  purpose:
    'separate effective accepted product law from bounded H-047, H-048, and H-049 evidence findings before any physical-recovery product decision',
  excluded:
    'conversation, external policy, live host state, USB, hidraw, network access, implementation, SPEC or ADR creation, production policy, and action authority',
});

const DOCKET_BOUNDARY = Object.freeze({
  conclusion:
    'this docket can classify only whether an exact human product-intent motion selects automatic recovery and all nine product decisions, explicitly rejects the obligation, or leaves the question unresolved',
  nonAuthority:
    'the docket is a non-normative question artifact and cannot itself create product law, a specification, an ADR, implementation authority, or production policy',
  excluded:
    'mechanism selection, controller design, live safety, host state, USB or hidraw behavior, implementation, publication, and every operational action',
});

const OUTCOME_POLICY = Object.freeze({
  supported:
    'exact-content-addressed-human-motion-with-require-automatic-and-nine-of-nine-explicit-predicate-decisions',
  refuted: 'exact-content-addressed-human-motion-with-explicit-no-obligation-decision',
  inconclusive: 'human-motion-absent-incomplete-or-ambiguous',
  invalid: 'source-or-docket-drift-authority-action-or-implementation-overclaim',
});

const FIXED_GIT_ENVIRONMENT = Object.freeze({
  GIT_CONFIG_COUNT: '0',
  GIT_CONFIG_GLOBAL: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_NO_LAZY_FETCH: '1',
  GIT_NO_REPLACE_OBJECTS: '1',
  GIT_OPTIONAL_LOCKS: '0',
  GIT_TERMINAL_PROMPT: '0',
  LANG: 'C',
  LC_ALL: 'C',
  PATH: '/usr/bin:/bin',
});

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const GIT_OID_PATTERN = /^[0-9a-f]{40}$/u;

class InvalidEvidenceError extends Error {
  constructor(message, reasonCode = 'source-or-docket-drift') {
    super(message);
    this.name = 'InvalidEvidenceError';
    this.reasonCode = reasonCode;
  }
}

function assertion(condition, message, reasonCode) {
  if (!condition) throw new InvalidEvidenceError(message, reasonCode);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, expected, label, reasonCode) {
  assertion(isObject(value), `${label} must be an object`, reasonCode);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  assertion(JSON.stringify(actual) === JSON.stringify(wanted), `${label} keys differ`, reasonCode);
}

function canonicalize(value, seen = new Set()) {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isFinite(value))
  ) {
    return value;
  }
  assertion(value !== undefined && typeof value !== 'function', 'unsupported canonical value');
  assertion(!seen.has(value), 'canonical cycle');
  seen.add(value);
  if (Array.isArray(value)) {
    const result = value.map((item) => canonicalize(item, seen));
    seen.delete(value);
    return result;
  }
  assertion(isObject(value), 'canonical value must be a plain object');
  const result = {};
  for (const key of Object.keys(value).sort((left, right) => left.localeCompare(right))) {
    result[key] = canonicalize(value[key], seen);
  }
  seen.delete(value);
  return result;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function canonicalArtifact(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
}

export function sha256(value) {
  return createHash('sha256')
    .update(Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8'))
    .digest('hex');
}

function parseJsonBytes(bytes, label) {
  assertion(Buffer.isBuffer(bytes), `${label} must be bytes`);
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch (error) {
    throw new InvalidEvidenceError(`${label} is not exact UTF-8 JSON: ${error.message}`);
  }
}

function readLocalRegularFile(filePath, label) {
  const stat = lstatSync(filePath);
  assertion(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1, `${label} is unsafe`);
  return readFileSync(filePath);
}

function oneLine(bytes, label) {
  const value = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  assertion(/^[0-9a-f]{40}\n$/u.test(value), `${label} is not one Git OID line`);
  return value.trim();
}

function parseLsTreeZ(bytes) {
  assertion(Buffer.isBuffer(bytes), 'ls-tree result must be bytes');
  assertion(bytes.length > 0 && bytes.at(-1) === 0, 'ls-tree result must be NUL terminated');
  const entries = [];
  let start = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] !== 0) continue;
    const record = bytes.subarray(start, index);
    const tab = record.indexOf(9);
    assertion(tab > 0, 'ls-tree record lacks a tab');
    const metadata = record.subarray(0, tab).toString('ascii').split(' ');
    assertion(metadata.length === 3, 'ls-tree metadata field count');
    const [mode, type, oid] = metadata;
    const sourcePath = new TextDecoder('utf-8', { fatal: true }).decode(record.subarray(tab + 1));
    assertion(mode === '100644' && type === 'blob', `unsupported source: ${sourcePath}`);
    assertion(GIT_OID_PATTERN.test(oid), `invalid source OID: ${sourcePath}`);
    assertion(
      sourcePath !== '' &&
        !sourcePath.startsWith('/') &&
        !sourcePath.includes('\\') &&
        sourcePath.split('/').every((segment) => !['', '.', '..'].includes(segment)),
      `unsafe source path: ${sourcePath}`
    );
    entries.push({ path: sourcePath, mode, oid });
    start = index + 1;
  }
  assertion(
    new Set(entries.map(({ path: value }) => value)).size === entries.length,
    'paths repeat'
  );
  return entries;
}

function allowedGitCommand(args) {
  const serialized = JSON.stringify(args);
  if (serialized === JSON.stringify(['rev-parse', `${SUBJECT.commit}^{commit}`])) return true;
  if (serialized === JSON.stringify(['rev-parse', `${SUBJECT.commit}^{tree}`])) return true;
  if (
    serialized ===
    JSON.stringify([
      'ls-tree',
      '-rz',
      '--full-tree',
      SUBJECT.commit,
      '--',
      ...SOURCES.map(({ path: value }) => value),
    ])
  ) {
    return true;
  }
  return (
    args.length === 3 &&
    args[0] === 'cat-file' &&
    args[1] === 'blob' &&
    SOURCES.some(({ oid }) => oid === args[2])
  );
}

export function createH050GitReader({ spawn = spawnSync } = {}) {
  const counts = { revParse: 0, lsTree: 0, catFile: 0 };
  return {
    git(args) {
      assertion(Array.isArray(args) && allowedGitCommand(args), 'Git command is not allowed');
      const result = spawn(GIT_EXECUTABLE, args, {
        cwd: H050_REPOSITORY_ROOT,
        env: { ...FIXED_GIT_ENVIRONMENT },
        encoding: null,
        maxBuffer: 16 * 1024 * 1024,
      });
      assertion(result.error === undefined, `Git failed to start: ${args[0]}`);
      assertion(result.status === 0, `Git failed: ${args[0]}`);
      assertion(Buffer.isBuffer(result.stdout), `Git stdout is not bytes: ${args[0]}`);
      assertion(Buffer.isBuffer(result.stderr), `Git stderr is not bytes: ${args[0]}`);
      assertion(result.stderr.length === 0, `Git wrote stderr: ${args[0]}`);
      if (args[0] === 'rev-parse') counts.revParse += 1;
      if (args[0] === 'ls-tree') counts.lsTree += 1;
      if (args[0] === 'cat-file') counts.catFile += 1;
      return result.stdout;
    },
    counts() {
      return { ...counts };
    },
  };
}

function validateSubjectLock(lock) {
  exactKeys(
    lock,
    [
      'schemaVersion',
      'hypothesis',
      'subject',
      'sources',
      'sourceRoles',
      'boundary',
      'authority',
      'action',
    ],
    'subject lock'
  );
  assertion(lock.schemaVersion === 'overlaykit-h050-subject-lock/v1', 'subject lock schema');
  assertion(lock.hypothesis === 'H-050', 'subject lock hypothesis');
  exactKeys(lock.subject, Object.keys(SUBJECT), 'subject identity');
  assertion(canonicalJson(lock.subject) === canonicalJson(SUBJECT), 'subject identity drift');
  assertion(Array.isArray(lock.sources), 'subject sources must be an array');
  assertion(canonicalJson(lock.sources) === canonicalJson(SOURCES), 'subject source roster drift');
  exactKeys(
    lock.sourceRoles,
    ['normativeLaw', 'acceptedEvidenceFindings', 'integrityIndex'],
    'source roles'
  );
  assertion(canonicalJson(lock.sourceRoles) === canonicalJson(SOURCE_ROLES), 'source roles drift');
  const flattenedRoles = Object.values(lock.sourceRoles).flat().sort();
  assertion(
    canonicalJson(flattenedRoles) === canonicalJson(SOURCES.map(({ path: value }) => value).sort()),
    'source roles do not partition the roster'
  );
  exactKeys(lock.boundary, ['subject', 'purpose', 'excluded'], 'lock boundary');
  assertion(canonicalJson(lock.boundary) === canonicalJson(LOCK_BOUNDARY), 'lock boundary drift');
  assertion(lock.authority === 'none' && lock.action === null, 'lock authority overclaim');
}

function validateDocket(docket) {
  exactKeys(
    docket,
    [
      'schemaVersion',
      'hypothesis',
      'title',
      'status',
      'normative',
      'subject',
      'question',
      'predicates',
      'outcomePolicy',
      'humanDecision',
      'claimBoundary',
      'authority',
      'action',
    ],
    'docket',
    'authority-action-or-implementation-overclaim'
  );
  assertion(
    docket.schemaVersion === 'overlaykit-h050-product-intent-docket/v1' &&
      docket.hypothesis === 'H-050',
    'docket identity drift'
  );
  assertion(
    docket.title === 'Physical MK.2 automatic-recovery product-intent docket',
    'docket title drift'
  );
  assertion(
    docket.status === 'pending-human-decision' &&
      docket.normative === false &&
      docket.humanDecision === null,
    'docket is not a pending non-normative question'
  );
  exactKeys(docket.subject, ['commit', 'tree', 'sourceCount', 'sourceSetSha256'], 'docket subject');
  assertion(
    canonicalJson(docket.subject) ===
      canonicalJson({
        commit: SUBJECT.commit,
        tree: SUBJECT.tree,
        sourceCount: SUBJECT.sourceCount,
        sourceSetSha256: SUBJECT.sourceSetSha256,
      }),
    'docket subject drift'
  );
  assertion(
    docket.question ===
      'Does the human principal require automatic physical Stream Deck MK.2 command-delivery recovery, and if so what exact nine-part product boundary must a later specification express?',
    'docket question drift'
  );
  assertion(Array.isArray(docket.predicates) && docket.predicates.length === 9, 'nine predicates');
  for (const [index, predicate] of docket.predicates.entries()) {
    const id = H050_PREDICATES[index];
    exactKeys(predicate, ['id', 'question', 'decision'], `predicate ${index}`);
    assertion(
      predicate.id === id &&
        predicate.question === PREDICATE_QUESTIONS[id] &&
        predicate.decision === null,
      `predicate ${id} is not exact and undecided`
    );
  }
  exactKeys(
    docket.outcomePolicy,
    ['supported', 'refuted', 'inconclusive', 'invalid'],
    'outcome policy'
  );
  assertion(canonicalJson(docket.outcomePolicy) === canonicalJson(OUTCOME_POLICY), 'outcome drift');
  exactKeys(
    docket.claimBoundary,
    ['conclusion', 'nonAuthority', 'excluded'],
    'docket claim boundary'
  );
  assertion(
    canonicalJson(docket.claimBoundary) === canonicalJson(DOCKET_BOUNDARY),
    'docket boundary drift'
  );
  assertion(
    docket.authority === 'none' && docket.action === null,
    'docket authority or action overclaim',
    'authority-action-or-implementation-overclaim'
  );
}

function reconstructSubject(reader) {
  assertion(
    oneLine(reader.git(['rev-parse', `${SUBJECT.commit}^{commit}`]), 'commit') === SUBJECT.commit,
    'subject commit drift'
  );
  assertion(
    oneLine(reader.git(['rev-parse', `${SUBJECT.commit}^{tree}`]), 'tree') === SUBJECT.tree,
    'subject tree drift'
  );
  const restrictedTreeBytes = reader.git([
    'ls-tree',
    '-rz',
    '--full-tree',
    SUBJECT.commit,
    '--',
    ...SOURCES.map(({ path: value }) => value),
  ]);
  assertion(
    sha256(restrictedTreeBytes) === SUBJECT.restrictedLsTreeSha256,
    'restricted tree drift'
  );
  const treeEntries = parseLsTreeZ(restrictedTreeBytes);
  assertion(treeEntries.length === SUBJECT.sourceCount, 'restricted tree cardinality');
  const sourceBytesByPath = new Map();
  const reconstructedSources = treeEntries.map((entry, index) => {
    const expected = SOURCES[index];
    assertion(
      entry.path === expected.path && entry.mode === expected.mode && entry.oid === expected.oid,
      `source tree identity drift: ${entry.path}`
    );
    const bytes = reader.git(['cat-file', 'blob', entry.oid]);
    const reconstructed = {
      path: entry.path,
      mode: entry.mode,
      oid: entry.oid,
      byteLength: bytes.length,
      sha256: sha256(bytes),
    };
    assertion(
      canonicalJson(reconstructed) === canonicalJson(expected),
      `source bytes drift: ${entry.path}`
    );
    sourceBytesByPath.set(entry.path, bytes);
    return reconstructed;
  });
  assertion(
    sha256(canonicalJson(reconstructedSources)) === SUBJECT.sourceSetSha256,
    'source-set drift'
  );
  return { restrictedTreeBytes, sources: reconstructedSources, sourceBytesByPath };
}

function validateGovernanceSources(sourceBytesByPath) {
  const parsed = new Map();
  for (const source of SOURCES) {
    parsed.set(source.path, parseJsonBytes(sourceBytesByPath.get(source.path), source.path));
  }
  const planPath = '.overlaykit/governance/plan.json';
  const manifestPath = '.overlaykit/governance/manifest.json';
  const planBytes = sourceBytesByPath.get(planPath);
  const manifestBytes = sourceBytesByPath.get(manifestPath);
  assertion(sha256(planBytes) === SUBJECT.planRawSha256, 'plan raw drift');
  assertion(sha256(manifestBytes) === SUBJECT.manifestRawSha256, 'manifest raw drift');
  const plan = parsed.get(planPath);
  const manifest = parsed.get(manifestPath);
  assertion(plan.planHash === SUBJECT.planHash, 'planHash drift');
  assertion(manifest.contentHash === SUBJECT.manifestContentHash, 'manifest contentHash drift');
  const { contentHash, ...manifestBody } = manifest;
  assertion(sha256(canonicalJson(manifestBody)) === contentHash, 'manifest self-hash drift');

  const expectedDecisionIds = Array.from(
    { length: 6 },
    (_, index) => `ADR-${String(index + 1).padStart(4, '0')}`
  );
  const expectedSpecificationIds = ['SPEC-0001', 'SPEC-0002'];
  assertion(
    Array.isArray(plan.decisions) &&
      canonicalJson(plan.decisions.map(({ id }) => id)) === canonicalJson(expectedDecisionIds),
    'plan decision roster drift'
  );
  assertion(
    Array.isArray(plan.specifications) &&
      canonicalJson(plan.specifications.map(({ id }) => id)) ===
        canonicalJson(expectedSpecificationIds),
    'plan specification roster drift'
  );
  for (const record of [...plan.decisions, ...plan.specifications]) {
    assertion(
      record.declaredStatus === 'accepted' &&
        record.effectiveStatus === 'accepted' &&
        record.supersededBy === null,
      `${record.id} is not effective accepted unsuperseded law`
    );
    const directory = record.id.startsWith('ADR-') ? 'decisions' : 'specifications';
    const sourcePath = `.overlaykit/governance/${directory}/${record.id}.json`;
    const expectedHash = sha256(sourceBytesByPath.get(sourcePath));
    assertion(record.contentHash === expectedHash, `${record.id} plan hash drift`);
    const manifestGroup = record.id.startsWith('ADR-')
      ? manifest.decisions
      : manifest.specifications;
    assertion(manifestGroup[record.id] === expectedHash, `${record.id} manifest hash drift`);
  }
  for (const id of ['CHG-0023', 'CHG-0025', 'CHG-0027']) {
    const sourcePath = `.overlaykit/governance/changes/${id}.json`;
    const change = parsed.get(sourcePath);
    assertion(change.id === id && change.status === 'implemented', `${id} status drift`);
    assertion(
      manifest.changes[id] === sha256(sourceBytesByPath.get(sourcePath)),
      `${id} hash drift`
    );
  }
  return { plan, manifest };
}

function outcome(status, reasonCode, extra = {}) {
  const stage =
    status === 'invalid'
      ? 'evidence-admission'
      : status === 'inconclusive'
        ? 'human-product-intent'
        : 'closed-human-product-intent';
  return { status, stage, reasonCode, ...extra };
}

function invalidOutcome(reasonCode, detail) {
  return outcome('invalid', reasonCode, { detail });
}

function validateMotionShape(motion, docketRawSha256) {
  exactKeys(
    motion,
    [
      'schemaVersion',
      'hypothesis',
      'principal',
      'subjectCommit',
      'docketRawSha256',
      'productIntent',
      'predicateDecisions',
      'decisionsExplicitUnambiguousConflictFree',
      'mechanismSelected',
      'specificationAuthorized',
      'adrAuthorized',
      'implementationAuthorized',
      'authority',
      'action',
    ],
    'human motion',
    'authority-action-or-implementation-overclaim'
  );
  assertion(
    motion.schemaVersion === 'overlaykit-h050-human-product-intent-motion/v1' &&
      motion.hypothesis === 'H-050' &&
      motion.principal === '@rodrigoteamx' &&
      motion.subjectCommit === SUBJECT.commit,
    'human motion identity drift',
    'human-motion-identity-drift'
  );
  assertion(
    motion.docketRawSha256 === docketRawSha256,
    'human motion docket binding drift',
    'human-motion-docket-drift'
  );
  assertion(
    ['require-automatic', 'no-obligation', 'undecided'].includes(motion.productIntent),
    'human motion product intent is not classified',
    'human-motion-ambiguous'
  );
  assertion(
    motion.decisionsExplicitUnambiguousConflictFree === true,
    'human motion does not declare its decisions explicit, unambiguous, and conflict-free',
    'human-motion-decisions-not-explicit-unambiguous-conflict-free'
  );
  assertion(
    motion.authority === 'none' &&
      motion.action === null &&
      motion.mechanismSelected === false &&
      motion.specificationAuthorized === false &&
      motion.adrAuthorized === false &&
      motion.implementationAuthorized === false,
    'human motion overclaims a mechanism, authority, action, SPEC, ADR, or implementation',
    'authority-action-or-implementation-overclaim'
  );
  assertion(Array.isArray(motion.predicateDecisions), 'predicate decisions are not an array');
  assertion(motion.predicateDecisions.length <= 9, 'too many predicate decisions');
  const seen = new Set();
  for (const decision of motion.predicateDecisions) {
    exactKeys(decision, ['id', 'decision', 'value'], 'predicate decision');
    assertion(H050_PREDICATES.includes(decision.id), `unknown predicate decision ${decision.id}`);
    assertion(!seen.has(decision.id), `duplicate predicate decision ${decision.id}`);
    assertion(
      decision.decision === 'selected' &&
        typeof decision.value === 'string' &&
        decision.value === decision.value.trim() &&
        decision.value.length >= 8,
      `empty, nominal, or invalid predicate decision ${decision.id}`
    );
    seen.add(decision.id);
  }
  return seen;
}

export function classifyH050HumanMotion({
  docketBytes,
  humanMotionBytes = null,
  nominatedMotionSha256 = null,
}) {
  assertion(Buffer.isBuffer(docketBytes), 'docket bytes are required');
  if (humanMotionBytes === null && nominatedMotionSha256 === null) {
    return {
      outcome: outcome('inconclusive', 'exact-human-motion-absent'),
      motion: null,
    };
  }
  if (!Buffer.isBuffer(humanMotionBytes) || nominatedMotionSha256 === null) {
    return {
      outcome: outcome('inconclusive', 'exact-human-motion-incomplete'),
      motion: null,
    };
  }
  if (!SHA256_PATTERN.test(nominatedMotionSha256)) {
    return {
      outcome: invalidOutcome('human-motion-nomination-invalid', 'nomination is not SHA-256'),
      motion: null,
    };
  }
  const actualMotionSha256 = sha256(humanMotionBytes);
  if (actualMotionSha256 !== nominatedMotionSha256) {
    return {
      outcome: invalidOutcome(
        'human-motion-digest-mismatch',
        'motion bytes differ from nomination'
      ),
      motion: { nominatedSha256: nominatedMotionSha256, rawSha256: actualMotionSha256 },
    };
  }
  let motion;
  try {
    motion = parseJsonBytes(humanMotionBytes, 'human motion');
    assertion(
      humanMotionBytes.equals(canonicalArtifact(motion)),
      'human motion is not canonical JSON with one LF',
      'human-motion-noncanonical'
    );
    const selected = validateMotionShape(motion, sha256(docketBytes));
    const receipt = {
      nominatedSha256: nominatedMotionSha256,
      rawSha256: actualMotionSha256,
      productIntent: motion.productIntent,
      selectedPredicateCount: selected.size,
    };
    if (motion.productIntent === 'no-obligation') {
      if (selected.size !== 0) {
        return {
          outcome: outcome('inconclusive', 'human-motion-self-ambiguous'),
          motion: receipt,
        };
      }
      return {
        outcome: outcome('refuted', 'human-explicitly-selected-no-obligation'),
        motion: receipt,
      };
    }
    if (motion.productIntent === 'undecided') {
      return {
        outcome: outcome('inconclusive', 'human-product-intent-undecided'),
        motion: receipt,
      };
    }
    if (selected.size !== H050_PREDICATES.length) {
      return {
        outcome: outcome('inconclusive', 'require-automatic-missing-predicate-decisions', {
          missingPredicates: H050_PREDICATES.filter((id) => !selected.has(id)),
        }),
        motion: receipt,
      };
    }
    return {
      outcome: outcome('supported', 'human-require-automatic-nine-of-nine'),
      motion: receipt,
    };
  } catch (error) {
    if (error instanceof InvalidEvidenceError) {
      return {
        outcome: invalidOutcome(error.reasonCode, error.message),
        motion: {
          nominatedSha256: nominatedMotionSha256,
          rawSha256: actualMotionSha256,
        },
      };
    }
    throw error;
  }
}

export function verifyH050(options = {}) {
  const subjectLockBytes =
    options.subjectLockBytes ?? readLocalRegularFile(SUBJECT_LOCK_PATH, 'subject lock');
  const docketBytes = options.docketBytes ?? readLocalRegularFile(DOCKET_PATH, 'product docket');
  const reader = options.reader ?? createH050GitReader();
  const subjectLock = parseJsonBytes(subjectLockBytes, 'subject lock');
  const docket = parseJsonBytes(docketBytes, 'product docket');
  assertion(sha256(subjectLockBytes) === SUBJECT_LOCK_RAW_SHA256, 'subject lock raw bytes drift');
  assertion(sha256(docketBytes) === DOCKET_RAW_SHA256, 'product docket raw bytes drift');
  validateSubjectLock(subjectLock);
  validateDocket(docket);
  const reconstructed = reconstructSubject(reader);
  const governance = validateGovernanceSources(reconstructed.sourceBytesByPath);
  const classified = classifyH050HumanMotion({
    docketBytes,
    humanMotionBytes: options.humanMotionBytes ?? null,
    nominatedMotionSha256: options.nominatedMotionSha256 ?? null,
  });
  const result = {
    schemaVersion: 'overlaykit-h050-independent-verification/v1',
    verified: classified.outcome.status !== 'invalid',
    subject: {
      commit: SUBJECT.commit,
      tree: SUBJECT.tree,
      sourceCount: reconstructed.sources.length,
      sourceSetSha256: SUBJECT.sourceSetSha256,
      restrictedLsTreeSha256: sha256(reconstructed.restrictedTreeBytes),
      planHash: governance.plan.planHash,
      manifestContentHash: governance.manifest.contentHash,
    },
    docket: {
      rawSha256: sha256(docketBytes),
      status: docket.status,
      normative: docket.normative,
      predicateCount: docket.predicates.length,
      decidedPredicateCount: docket.predicates.filter(({ decision }) => decision !== null).length,
      humanDecision: docket.humanDecision,
    },
    humanMotion: classified.motion,
    outcome: classified.outcome,
    capabilityAudit: {
      mode: 'offline-read-only-local-git',
      gitExecutable: GIT_EXECUTABLE,
      commandCounts: reader.counts(),
      network: false,
      liveHost: false,
      usb: false,
      hidraw: false,
      writes: false,
    },
    checks: {
      exactSubjectLock: true,
      exactThirteenSourceClosure: true,
      sourceRolesSeparated: true,
      acceptedLawEffectiveAndUnsuperseded: true,
      precedentFindingsImplementedButNonNormative: true,
      docketPendingAndNonNormative: true,
      ninePredicatesUndecidedWithoutDefaults: true,
      noSpecificationAdrOrImplementationAuthority: true,
    },
    authority: 'none',
    action: null,
  };
  return result;
}

export function verifyH050Safe(options = {}) {
  try {
    return verifyH050(options);
  } catch (error) {
    if (!(error instanceof InvalidEvidenceError)) throw error;
    return {
      schemaVersion: 'overlaykit-h050-independent-verification/v1',
      verified: false,
      outcome: invalidOutcome(error.reasonCode, error.message),
      authority: 'none',
      action: null,
    };
  }
}

function isMain() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMain()) {
  const result = verifyH050Safe();
  process.stdout.write(`${canonicalJson(result)}\n`);
  if (!result.verified) process.exitCode = 1;
}
