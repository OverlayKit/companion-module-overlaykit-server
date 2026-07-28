import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

const LAB_DIRECTORY = realpathSync(path.dirname(fileURLToPath(import.meta.url)));
const REPOSITORY_ROOT = realpathSync(path.resolve(LAB_DIRECTORY, '../..'));

const ARTIFACTS = Object.freeze({
  precontract: Object.freeze({
    path: path.join(REPOSITORY_ROOT, '.overlaykit/governance/changes/CHG-0031.json'),
    rawSha256: '6cdc124c9707cd4a743cfdd68a1706534418ad5163da720aefe8e0c2ded7adf5',
  }),
  subjectLock: Object.freeze({
    path: path.join(LAB_DIRECTORY, 'subject-lock.json'),
    rawSha256: 'e95b3c806c512fd116e169be3bd02c8673e8fc39c72f28b245e8ab28fabe0a0a',
  }),
  docket: Object.freeze({
    path: path.join(LAB_DIRECTORY, 'specification-readiness-docket.json'),
    rawSha256: 'adcd317603eb8678ab970f8dd0bcf63a3444d0bc6af669fa60b134b5d89237bc',
  }),
  readinessMap: Object.freeze({
    path: path.join(LAB_DIRECTORY, 'readiness-map.json'),
    rawSha256: 'dfb1156e6c16721c01d008cb5d760b05f10dc2328cfb871a3a80a29a4447c7ce',
  }),
});

const SCHEMAS = Object.freeze({
  subjectLock: Object.freeze({
    path: path.join(LAB_DIRECTORY, 'schemas/subject-lock.schema.json'),
    rawSha256: '96f781cfae12b89efeeb59fec55f159f54df7afd07a7774b222b4da0aad3bd5b',
  }),
  docket: Object.freeze({
    path: path.join(LAB_DIRECTORY, 'schemas/specification-readiness-docket.schema.json'),
    rawSha256: '68beb26521a95eb945958a30a01a90bb7507dd1fdfccd1d2a57f95c995bbfd9c',
  }),
  readinessMap: Object.freeze({
    path: path.join(LAB_DIRECTORY, 'schemas/readiness-map.schema.json'),
    rawSha256: 'bb1f4aff225fd00004ae411d8cd55464a89b4eb125b89f3bc6b68ef427725384',
  }),
});

export const H051_PREDICATES = Object.freeze([
  'mapsAutomaticRecoveryObligation',
  'mapsLinuxRoleAndPhysicalMk2Scope',
  'mapsTriggerAndIdentityContinuity',
  'mapsRestoredPhysicalCommandDelivery',
  'mapsRecoveryDeadlineAndClock',
  'mapsDegradedFailureAndManualFallback',
  'mapsSafetySecurityAndAuthorityBoundary',
  'mapsAcceptanceEvidenceAndScenarioCoverage',
  'mapsSpecificationRelationship',
  'projectionIsNonInventiveAndConflictFree',
  'schemaCompilerAdmitsAdditiveLifecycle',
]);

const H051_MAPPING_PREDICATES = Object.freeze(H051_PREDICATES.slice(0, 9));
const EXPECTED_GIT_SOURCE_COUNT = 18;
const EXPECTED_LOCAL_SOURCE_COUNT = 8;
const EXPECTED_TOTAL_SOURCE_COUNT = 26;
const EXPECTED_GIT_SOURCE_SET_SHA256 =
  '08eb7c113f2ecb7836b1def73ac5443ab9e2bea95b313fa7262d4b867f2c646d';
const EXPECTED_LOCAL_SOURCE_SET_SHA256 =
  '7d913e55e09df8c6cb86fdd12bc70fc59b41b61a620aefb22ede0af3085e29f8';
const EXPECTED_COMBINED_SOURCE_SET_SHA256 =
  '6d54e3ca53b02dc31495f3d1e2cdd965f48f04b24f1460e7a5149267c8921317';
const EXPECTED_COMMIT = '2810e63defe37025f575ebea37be7e1c5e97c18e';
const EXPECTED_TREE = '421ae43dbac2b52fe4dc7f594fda795a870b4c10';
const EXPECTED_PLAN_HASH = 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4';
const EXPECTED_CLOSURE_SHA256 = '2fe8d261ac60594ca4700002758af23b2a8455bc2152bbc19475ce54611f7d1e';
const EXPECTED_PRECONTRACT_SHA256 =
  '6cdc124c9707cd4a743cfdd68a1706534418ad5163da720aefe8e0c2ded7adf5';
const EXPECTED_PREDECESSOR_CHANGE_SHA256 =
  'fdf68ebab17501486fd2418e5a2c91099c50cbe2c36a6e69e69b94a506b713f7';

const EXPECTED_ROLE_NAMES = Object.freeze([
  'acceptedLaw',
  'acceptedPredecessorFinding',
  'representationCarrier',
  'h050PreReview',
  'h050AcceptedIntent',
  'h050EvidenceClosure',
]);

const ALLOWED_GIT_OPERATIONS = Object.freeze(['cat-file', 'ls-tree', 'rev-parse']);

export class InvalidH051EvidenceError extends Error {
  constructor(reasonCode, message) {
    super(message);
    this.name = 'InvalidH051EvidenceError';
    this.reasonCode = reasonCode;
  }
}

function assertion(condition, reasonCode, message) {
  if (!condition) {
    throw new InvalidH051EvidenceError(reasonCode, message);
  }
}

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function jsonBytesHash(value) {
  return sha256(Buffer.from(canonicalJson(value), 'utf8'));
}

function exactKeys(value, expected, label) {
  assertion(
    value !== null && typeof value === 'object' && !Array.isArray(value),
    'artifact-shape-invalid',
    `${label} must be an object`
  );
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  assertion(
    JSON.stringify(actual) === JSON.stringify(wanted),
    'artifact-shape-invalid',
    `${label} keys differ`
  );
}

function exactArray(actual, expected, reasonCode, label) {
  assertion(Array.isArray(actual), reasonCode, `${label} must be an array`);
  assertion(JSON.stringify(actual) === JSON.stringify(expected), reasonCode, `${label} differs`);
}

function unique(values, reasonCode, label) {
  assertion(new Set(values).size === values.length, reasonCode, `${label} contains duplicates`);
}

function sorted(values) {
  return [...values].sort((left, right) => left.localeCompare(right));
}

function assertCanonicalRelativePath(value, reasonCode = 'source-path-invalid') {
  assertion(typeof value === 'string' && value.length > 0, reasonCode, 'source path is empty');
  assertion(!path.posix.isAbsolute(value), reasonCode, `absolute source path: ${value}`);
  assertion(!value.includes('\\'), reasonCode, `alternate separator in source path: ${value}`);
  assertion(
    value === path.posix.normalize(value),
    reasonCode,
    `non-canonical source path: ${value}`
  );
  assertion(
    !value.split('/').some((part) => part === '..' || part === '.' || part === ''),
    reasonCode,
    `unsafe source path: ${value}`
  );
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw new InvalidH051EvidenceError(
      'artifact-json-invalid',
      `${label} is not valid JSON: ${error.message}`
    );
  }
}

function artifactBytes(name, overrides = {}) {
  const descriptor = ARTIFACTS[name];
  const bytes = overrides[name] ?? readFileSync(descriptor.path);
  assertion(sha256(bytes) === descriptor.rawSha256, `${name}-raw-drift`, `${name} raw bytes drift`);
  return bytes;
}

function schemaBytes(name, overrides = {}) {
  const descriptor = SCHEMAS[name];
  const bytes = overrides[name] ?? readFileSync(descriptor.path);
  assertion(
    sha256(bytes) === descriptor.rawSha256,
    'schema-raw-drift',
    `${name} schema raw bytes drift`
  );
  return bytes;
}

export function validateH051Schemas({
  subjectLock,
  docket,
  readinessMap,
  schemaOverrides = {},
} = {}) {
  const values = {
    subjectLock: subjectLock ?? parseJson(artifactBytes('subjectLock'), 'subject lock'),
    docket: docket ?? parseJson(artifactBytes('docket'), 'docket'),
    readinessMap: readinessMap ?? parseJson(artifactBytes('readinessMap'), 'readiness map'),
  };
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  for (const name of ['subjectLock', 'docket', 'readinessMap']) {
    const schema = parseJson(schemaBytes(name, schemaOverrides), `${name} schema`);
    const validator = ajv.compile(schema);
    const valid = validator(values[name]);
    assertion(
      valid,
      'schema-validation-failed',
      `${name} schema validation failed: ${JSON.stringify(validator.errors ?? [])}`
    );
  }
  return true;
}

function assertSourceRosterOrder(sources, reasonCode, label) {
  const paths = sources.map(({ path: sourcePath }) => sourcePath);
  for (const sourcePath of paths) {
    assertCanonicalRelativePath(sourcePath, reasonCode);
  }
  unique(paths, reasonCode, `${label} paths`);
}

export function verifySubjectLockStructure(lock) {
  exactKeys(
    lock,
    [
      'schemaVersion',
      'hypothesis',
      'normativeGit',
      'localPredecessorEvidence',
      'combinedSourceSetSha256',
      'gitSources',
      'localSources',
      'sourceRoles',
      'excludedSources',
      'boundary',
      'authority',
      'action',
    ],
    'subject lock'
  );
  assertion(
    lock.schemaVersion === 'overlaykit-h051-subject-lock/v1' && lock.hypothesis === 'H-051',
    'subject-lock-envelope-drift',
    'subject lock identity differs'
  );
  assertion(
    lock.authority === 'none' && lock.action === null,
    'authority-overclaim',
    'subject lock authority or action overclaim'
  );
  assertion(
    lock.normativeGit.commit === EXPECTED_COMMIT &&
      lock.normativeGit.tree === EXPECTED_TREE &&
      lock.normativeGit.sourceCount === EXPECTED_GIT_SOURCE_COUNT &&
      lock.normativeGit.sourceSetSha256 === EXPECTED_GIT_SOURCE_SET_SHA256 &&
      lock.normativeGit.planHash === EXPECTED_PLAN_HASH,
    'git-subject-drift',
    'normative Git subject differs'
  );
  assertion(
    lock.localPredecessorEvidence.admission === 'local-content-addressed-unsigned' &&
      lock.localPredecessorEvidence.signatureStatus === 'absent-not-authorized' &&
      lock.localPredecessorEvidence.signedCommit === null &&
      lock.localPredecessorEvidence.durabilityClaimed === false &&
      lock.localPredecessorEvidence.sourceCount === EXPECTED_LOCAL_SOURCE_COUNT &&
      lock.localPredecessorEvidence.sourceSetSha256 === EXPECTED_LOCAL_SOURCE_SET_SHA256 &&
      lock.localPredecessorEvidence.closureRawSha256 === EXPECTED_CLOSURE_SHA256,
    'local-predecessor-envelope-drift',
    'local predecessor evidence envelope differs'
  );
  assertion(
    lock.combinedSourceSetSha256 === EXPECTED_COMBINED_SOURCE_SET_SHA256,
    'combined-source-set-drift',
    'combined source-set identity differs'
  );
  assertion(
    lock.gitSources.length === EXPECTED_GIT_SOURCE_COUNT &&
      lock.localSources.length === EXPECTED_LOCAL_SOURCE_COUNT,
    'source-roster-cardinality-drift',
    'source roster cardinality differs'
  );
  assertSourceRosterOrder(lock.gitSources, 'git-source-roster-invalid', 'Git source');
  assertSourceRosterOrder(lock.localSources, 'local-source-roster-invalid', 'local source');
  for (const source of lock.gitSources) {
    assertion(
      source.mode === '100644' &&
        source.type === 'blob' &&
        /^[0-9a-f]{40}$/u.test(source.oid) &&
        Number.isSafeInteger(source.byteLength) &&
        source.byteLength > 0 &&
        /^[0-9a-f]{64}$/u.test(source.sha256),
      'git-source-metadata-invalid',
      `invalid Git source metadata: ${source.path}`
    );
  }
  for (const source of lock.localSources) {
    assertion(
      (source.mode === '0644' || source.mode === '0600') &&
        Number.isSafeInteger(source.byteLength) &&
        source.byteLength > 0 &&
        /^[0-9a-f]{64}$/u.test(source.sha256),
      'local-source-metadata-invalid',
      `invalid local source metadata: ${source.path}`
    );
  }
  assertion(
    jsonBytesHash(lock.gitSources) === EXPECTED_GIT_SOURCE_SET_SHA256,
    'git-source-set-drift',
    'Git source-set hash differs'
  );
  assertion(
    jsonBytesHash(lock.localSources) === EXPECTED_LOCAL_SOURCE_SET_SHA256,
    'local-source-set-drift',
    'local source-set hash differs'
  );
  assertion(
    jsonBytesHash({ gitSources: lock.gitSources, localSources: lock.localSources }) ===
      EXPECTED_COMBINED_SOURCE_SET_SHA256,
    'combined-source-set-drift',
    'combined source-set reconstruction differs'
  );

  exactArray(
    Object.keys(lock.sourceRoles),
    EXPECTED_ROLE_NAMES,
    'source-role-roster-drift',
    'source role names'
  );
  const allSources = [...lock.gitSources, ...lock.localSources].map(
    ({ path: sourcePath }) => sourcePath
  );
  const rolePaths = EXPECTED_ROLE_NAMES.flatMap((role) => {
    const values = lock.sourceRoles[role];
    return values;
  });
  unique(rolePaths, 'source-role-overlap', 'source role paths');
  exactArray(
    sorted(rolePaths),
    sorted(allSources),
    'source-role-coverage-drift',
    'source role coverage'
  );
  assertion(
    lock.excludedSources.mutableWorktreeManifest === '.overlaykit/governance/manifest.json' &&
      lock.excludedSources.immutableMainManifestIncluded === true &&
      lock.excludedSources.successorChange === '.overlaykit/governance/changes/CHG-0031.json' &&
      lock.excludedSources.selfPrefix === 'lab/h051/',
    'temporal-boundary-drift',
    'excluded-source boundary differs'
  );
  assertion(
    lock.gitSources.some(
      ({ path: sourcePath }) => sourcePath === '.overlaykit/governance/manifest.json'
    ) &&
      !allSources.includes('.overlaykit/governance/changes/CHG-0031.json') &&
      !allSources.some((sourcePath) => sourcePath.startsWith('lab/h051/')),
    'self-source-admission',
    'source lock admits successor or self evidence'
  );
  return {
    gitSourceCount: lock.gitSources.length,
    localSourceCount: lock.localSources.length,
    totalSourceCount: allSources.length,
    combinedSourceSetSha256: lock.combinedSourceSetSha256,
  };
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
  assertion(
    Array.isArray(args) && args.length > 0 && ALLOWED_GIT_OPERATIONS.includes(args[0]),
    'git-command-not-allowed',
    'Git reader command is outside the exact allowlist'
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
    .map((entry) => {
      const match = /^(?<mode>[0-9]{6}) (?<type>[a-z]+) (?<oid>[0-9a-f]{40})\t(?<path>.+)$/u.exec(
        entry
      );
      assertion(match !== null, 'git-tree-output-invalid', 'Git ls-tree output is malformed');
      return match.groups;
    });
}

function assertNoSymlinkAncestors(relativePath) {
  const parts = relativePath.split('/');
  let current = REPOSITORY_ROOT;
  for (const part of parts) {
    current = path.join(current, part);
    const stats = lstatSync(current);
    assertion(
      !stats.isSymbolicLink(),
      'local-source-symlink',
      `symlink source path: ${relativePath}`
    );
  }
}

function localSourceBytes(source, overrides = new Map()) {
  assertCanonicalRelativePath(source.path);
  const absolutePath = path.resolve(REPOSITORY_ROOT, source.path);
  assertion(
    absolutePath.startsWith(`${REPOSITORY_ROOT}${path.sep}`),
    'source-path-invalid',
    `local source escapes repository: ${source.path}`
  );
  assertNoSymlinkAncestors(source.path);
  const stats = lstatSync(absolutePath);
  assertion(stats.isFile(), 'local-source-type-invalid', `not a regular file: ${source.path}`);
  assertion(stats.nlink === 1, 'local-source-hardlink', `hard-linked source: ${source.path}`);
  const actualMode = (stats.mode & 0o777).toString(8).padStart(4, '0');
  assertion(
    actualMode === source.mode,
    'local-source-mode-drift',
    `local source mode drift: ${source.path}`
  );
  return overrides.get(source.path) ?? readFileSync(absolutePath);
}

export function inspectH051Sources(
  lock,
  { gitReader = defaultGitReader, localOverrides = new Map() } = {}
) {
  verifySubjectLockStructure(lock);
  const resolvedCommit = gitReader([
    'rev-parse',
    '--verify',
    `${lock.normativeGit.commit}^{commit}`,
  ])
    .toString('utf8')
    .trim();
  const resolvedTree = gitReader(['rev-parse', `${lock.normativeGit.commit}^{tree}`])
    .toString('utf8')
    .trim();
  assertion(
    resolvedCommit === EXPECTED_COMMIT && resolvedTree === EXPECTED_TREE,
    'git-subject-drift',
    'resolved Git subject differs'
  );
  const gitPaths = lock.gitSources.map(({ path: sourcePath }) => sourcePath);
  const treeBytes = gitReader([
    'ls-tree',
    '-rz',
    '--full-tree',
    lock.normativeGit.commit,
    '--',
    ...gitPaths,
  ]);
  assertion(
    sha256(treeBytes) === lock.normativeGit.restrictedLsTreeSha256,
    'restricted-tree-drift',
    'restricted ls-tree stream differs'
  );
  const treeEntries = parseLsTree(treeBytes);
  assertion(
    treeEntries.length === lock.gitSources.length,
    'git-source-roster-cardinality-drift',
    'Git tree entry cardinality differs'
  );

  const sourceBytesByPath = new Map();
  for (let index = 0; index < lock.gitSources.length; index += 1) {
    const expected = lock.gitSources[index];
    const observed = treeEntries[index];
    assertion(
      observed.path === expected.path &&
        observed.mode === expected.mode &&
        observed.type === expected.type &&
        observed.oid === expected.oid,
      'git-source-metadata-drift',
      `Git source metadata drift: ${expected.path}`
    );
    const bytes = gitReader(['cat-file', 'blob', expected.oid]);
    assertion(
      bytes.length === expected.byteLength && sha256(bytes) === expected.sha256,
      'git-source-byte-drift',
      `Git source byte drift: ${expected.path}`
    );
    sourceBytesByPath.set(expected.path, bytes);
  }

  for (const source of lock.localSources) {
    const bytes = localSourceBytes(source, localOverrides);
    assertion(
      bytes.length === source.byteLength && sha256(bytes) === source.sha256,
      'local-source-byte-drift',
      `local source byte drift: ${source.path}`
    );
    sourceBytesByPath.set(source.path, bytes);
  }
  assertion(
    sourceBytesByPath.size === EXPECTED_TOTAL_SOURCE_COUNT,
    'source-roster-cardinality-drift',
    'resolved source cardinality differs'
  );
  const plan = parseJson(sourceBytesByPath.get('.overlaykit/governance/plan.json'), 'plan');
  assertion(plan.planHash === EXPECTED_PLAN_HASH, 'plan-hash-drift', 'compiled planHash differs');
  return {
    sourceBytesByPath,
    restrictedLsTreeSha256: sha256(treeBytes),
    sourceCount: sourceBytesByPath.size,
  };
}

export function resolveJsonPointer(value, pointer) {
  assertion(
    typeof pointer === 'string' && (pointer === '' || pointer.startsWith('/')),
    'citation-pointer-invalid',
    `invalid JSON pointer: ${pointer}`
  );
  if (pointer === '') return value;
  let current = value;
  for (const encodedToken of pointer.slice(1).split('/')) {
    const token = encodedToken.replaceAll('~1', '/').replaceAll('~0', '~');
    if (Array.isArray(current)) {
      assertion(
        /^(?:0|[1-9][0-9]*)$/u.test(token),
        'citation-pointer-invalid',
        `invalid array token: ${token}`
      );
      const index = Number(token);
      assertion(
        index < current.length,
        'citation-pointer-missing',
        `missing array index: ${token}`
      );
      current = current[index];
    } else {
      assertion(
        current !== null &&
          typeof current === 'object' &&
          Object.prototype.hasOwnProperty.call(current, token),
        'citation-pointer-missing',
        `missing object token: ${token}`
      );
      current = current[token];
    }
  }
  return current;
}

function assertNoSpecShapedProjection(map) {
  const serialized = JSON.stringify(map);
  assertion(
    map.mappingPolicy.specificationFixturePermitted === false &&
      map.carrierAssessment.specificationFixturePresent === false,
    'spec-shaped-fixture-overclaim',
    'SPEC-shaped fixture is admitted'
  );
  assertion(
    !/\bSPEC-(?:000[3-9]|00[1-9][0-9]|0[1-9][0-9]{2}|[1-9][0-9]{3})\b/u.test(serialized) &&
      !/\bREQ-[A-Z]+-[0-9]{3}\b/u.test(serialized),
    'spec-shaped-fixture-overclaim',
    'readiness map contains future SPEC or requirement identities'
  );
}

function resolveCitations(map, sourceBytesByPath, admittedPaths) {
  let citationCount = 0;
  for (const mapping of map.mappings) {
    for (const citation of mapping.sourceCitations) {
      assertion(
        admittedPaths.has(citation.path) && sourceBytesByPath.has(citation.path),
        'citation-source-not-admitted',
        `citation source is outside the lock: ${citation.path}`
      );
      const source = parseJson(sourceBytesByPath.get(citation.path), citation.path);
      resolveJsonPointer(source, citation.pointer);
      citationCount += 1;
    }
  }
  return citationCount;
}

export function verifyDocketStructure(
  docket,
  { precontractRawSha256, predecessorChangeRawSha256, sourceLockRawSha256, readinessMapRawSha256 }
) {
  assertion(
    docket.schemaVersion === 'overlaykit-h051-specification-readiness-docket/v1' &&
      docket.hypothesis === 'H-051' &&
      docket.status === 'agent-proposed-pending-human-acceptance' &&
      docket.normative === false,
    'docket-envelope-drift',
    'docket identity or lifecycle differs'
  );
  assertion(
    docket.authority === 'none' && docket.action === null,
    'authority-overclaim',
    'docket authority or action overclaim'
  );
  assertion(
    docket.subject.precontractPath === '.overlaykit/governance/changes/CHG-0031.json' &&
      docket.subject.precontractRawSha256 === precontractRawSha256 &&
      precontractRawSha256 === EXPECTED_PRECONTRACT_SHA256,
    'precontract-binding-drift',
    'docket precontract binding differs'
  );
  assertion(
    docket.subject.sourceLockRawSha256 === sourceLockRawSha256 &&
      docket.subject.readinessMapRawSha256 === readinessMapRawSha256 &&
      docket.subject.normativeCommit === EXPECTED_COMMIT &&
      docket.subject.normativeTree === EXPECTED_TREE &&
      docket.subject.h050ClosureRawSha256 === EXPECTED_CLOSURE_SHA256,
    'docket-subject-drift',
    'docket subject binding differs'
  );
  assertion(
    docket.authorizationContext.predecessorChangeRawSha256 === predecessorChangeRawSha256 &&
      predecessorChangeRawSha256 === EXPECTED_PREDECESSOR_CHANGE_SHA256,
    'predecessor-change-binding-drift',
    'docket predecessor change binding differs'
  );
  const reply = docket.authorizationContext.modelVisibleReply;
  assertion(
    reply.value === 'adelante con lo que sigue' &&
      reply.utf8ByteLength === Buffer.byteLength(reply.value, 'utf8') &&
      reply.sha256 === sha256(Buffer.from(reply.value, 'utf8')) &&
      reply.transportBytesClaimed === false &&
      docket.authorizationContext.predecessorClosureRawSha256 === EXPECTED_CLOSURE_SHA256 &&
      docket.authorizationContext.successorHypothesis === 'H-051' &&
      docket.authorizationContext.successorChange === 'CHG-0031',
    'authorization-context-drift',
    'contextual grant is replayable or target-unbound'
  );
  assertion(
    docket.authorizationContext.interpretation ===
      'one local offline governed-discovery pre-review cycle only',
    'authorization-overclaim',
    'authorization interpretation differs'
  );
  exactArray(docket.predicates, H051_PREDICATES, 'predicate-roster-drift', 'docket predicates');
  assertion(
    docket.preReviewResult.status === 'inconclusive' &&
      docket.preReviewResult.reasonCode ===
        'relationship-carrier-ambiguous-and-schema-compiler-pending' &&
      docket.preReviewResult.satisfiedPredicateCount === 9 &&
      docket.preReviewResult.ambiguousPredicateCount === 1 &&
      docket.preReviewResult.unresolvedPredicateCount === 1 &&
      docket.preReviewResult.humanAcceptance === null,
    'pre-review-outcome-drift',
    'docket pre-review outcome differs'
  );
  assertion(
    docket.discoveryFrame.observableEvidence.includes('structurally reconstructed') &&
      docket.discoveryFrame.observableEvidence.includes('pending human acceptance') &&
      !docket.discoveryFrame.observableEvidence.includes('independently recomputed'),
    'semantic-self-approval',
    'docket overclaims semantic independent verification'
  );
  assertion(
    docket.adrAssessment.candidateActivated === false,
    'adr-overclaim',
    'docket activates an ADR candidate'
  );
  const capabilities = docket.capabilityAudit;
  assertion(
    capabilities.network === false &&
      capabilities.liveHost === false &&
      capabilities.usb === false &&
      capabilities.hidraw === false &&
      capabilities.docker === false &&
      capabilities.signals === false &&
      capabilities.acceptedRecordMutation === false &&
      capabilities.productMutation === false &&
      capabilities.gitHistoryMutation === false,
    'capability-overclaim',
    'docket claims an unauthorized capability'
  );
  exactArray(
    capabilities.authorizedLocalGovernanceWritesOutsideThisHarnessSubtask,
    ['.overlaykit/governance/changes/CHG-0031.json', '.overlaykit/governance/manifest.json'],
    'governance-write-boundary-drift',
    'authorized local governance writes'
  );
  return true;
}

export function verifyReadinessMapStructure(map, { lock, sourceBytesByPath }) {
  assertion(
    map.schemaVersion === 'overlaykit-h051-specification-readiness-map/v1' &&
      map.hypothesis === 'H-051' &&
      map.status === 'agent-proposed-pending-human-acceptance' &&
      map.normative === false,
    'readiness-map-envelope-drift',
    'readiness map identity or lifecycle differs'
  );
  assertion(
    map.authority === 'none' && map.action === null,
    'authority-overclaim',
    'readiness map authority or action overclaim'
  );
  assertion(
    map.sourceLock.rawSha256 === ARTIFACTS.subjectLock.rawSha256,
    'readiness-map-source-lock-drift',
    'readiness map source-lock binding differs'
  );
  assertion(
    map.mappingPolicy.sourceForm === 'exact-source-json-pointers-only' &&
      map.mappingPolicy.targetForm === 'abstract-product-specification-slots-only' &&
      map.mappingPolicy.specificationFixturePermitted === false &&
      map.mappingPolicy.proseCarrierCountsAsResolved === false &&
      map.mappingPolicy.machineReadableRelationshipRequiredByAgent === false &&
      map.mappingPolicy.humanAdjudicationRequired === true,
    'mapping-policy-drift',
    'mapping policy differs'
  );
  assertNoSpecShapedProjection(map);
  const universe = map.mappingPolicy.abstractSlotUniverse;
  unique(universe, 'abstract-slot-universe-invalid', 'abstract slot universe');
  exactArray(
    universe,
    sorted(universe),
    'abstract-slot-universe-invalid',
    'abstract slot universe'
  );

  const mappingIds = map.mappings.map(({ id }) => id);
  exactArray(mappingIds, H051_MAPPING_PREDICATES, 'mapping-roster-drift', 'mapping IDs');
  const usedSlots = [];
  let mappedCount = 0;
  let ambiguousCount = 0;
  for (const mapping of map.mappings) {
    unique(mapping.abstractSlots, 'mapping-slot-duplicate', `${mapping.id} abstract slots`);
    for (const slot of mapping.abstractSlots) {
      assertion(
        universe.includes(slot),
        'mapping-slot-not-admitted',
        `unknown abstract slot: ${slot}`
      );
      usedSlots.push(slot);
    }
    assertion(
      mapping.sourceCitations.length > 0,
      'mapping-citation-omitted',
      `${mapping.id} has no source citation`
    );
    if (mapping.classification === 'mapped') {
      mappedCount += 1;
      assertion(
        mapping.ambiguity === null,
        'mapping-classification-drift',
        `${mapping.id} ambiguity differs`
      );
    } else if (mapping.classification === 'ambiguous') {
      ambiguousCount += 1;
      assertion(
        typeof mapping.ambiguity === 'string' && mapping.ambiguity.length > 0,
        'mapping-classification-drift',
        `${mapping.id} ambiguity is absent`
      );
    } else {
      throw new InvalidH051EvidenceError(
        'mapping-classification-drift',
        `${mapping.id} classification is not admitted`
      );
    }
  }
  unique(usedSlots, 'mapping-slot-overlap', 'mapped abstract slots');
  exactArray(sorted(usedSlots), universe, 'mapping-slot-coverage-drift', 'mapped abstract slots');
  assertion(
    mappedCount === 8 &&
      ambiguousCount === 1 &&
      map.mappings.at(-1).id === 'mapsSpecificationRelationship' &&
      map.mappings.at(-1).classification === 'ambiguous',
    'mapping-classification-drift',
    'mapping classifications differ'
  );

  const admittedPaths = new Set([
    ...lock.gitSources.map(({ path: sourcePath }) => sourcePath),
    ...lock.localSources.map(({ path: sourcePath }) => sourcePath),
  ]);
  const citationCount = resolveCitations(map, sourceBytesByPath, admittedPaths);

  const receiptIds = map.predicateReceipts.map(({ id }) => id);
  exactArray(receiptIds, H051_PREDICATES, 'predicate-receipt-roster-drift', 'predicate receipts');
  const receiptStatuses = new Map(map.predicateReceipts.map(({ id, status }) => [id, status]));
  for (const mapping of map.mappings) {
    const expectedStatus = mapping.classification === 'mapped' ? 'satisfied' : 'ambiguous';
    assertion(
      receiptStatuses.get(mapping.id) === expectedStatus,
      'predicate-receipt-drift',
      `${mapping.id} receipt status differs`
    );
  }
  assertion(
    receiptStatuses.get('projectionIsNonInventiveAndConflictFree') === 'satisfied' &&
      receiptStatuses.get('schemaCompilerAdmitsAdditiveLifecycle') === 'unresolved',
    'predicate-receipt-drift',
    'meta-predicate receipt status differs'
  );
  const counts = {
    satisfied: map.predicateReceipts.filter(({ status }) => status === 'satisfied').length,
    ambiguous: map.predicateReceipts.filter(({ status }) => status === 'ambiguous').length,
    unresolved: map.predicateReceipts.filter(({ status }) => status === 'unresolved').length,
  };
  assertion(
    counts.satisfied === 9 &&
      counts.ambiguous === 1 &&
      counts.unresolved === 1 &&
      map.coverage.expectedMappingCount === 9 &&
      map.coverage.mappedCount === 8 &&
      map.coverage.ambiguousCount === 1 &&
      map.coverage.omittedCount === 0 &&
      map.coverage.expectedPredicateCount === 11 &&
      map.coverage.satisfiedPredicateCount === counts.satisfied &&
      map.coverage.ambiguousPredicateCount === counts.ambiguous &&
      map.coverage.unresolvedPredicateCount === counts.unresolved &&
      map.coverage.conflicts.length === 0,
    'coverage-receipt-drift',
    'coverage receipt differs'
  );
  exactArray(
    map.coverage.unresolved,
    ['mapsSpecificationRelationship', 'schemaCompilerAdmitsAdditiveLifecycle'],
    'coverage-receipt-drift',
    'unresolved predicate roster'
  );
  assertion(
    map.carrierAssessment.status === 'pending' &&
      map.carrierAssessment.schemaSlotsEnumerated === true &&
      map.carrierAssessment.compilerSourcesClosed === true &&
      map.carrierAssessment.specificationFixturePresent === false &&
      map.carrierAssessment.reasonCode === 'spec-shaped-fixture-not-authorized',
    'carrier-assessment-drift',
    'carrier assessment differs'
  );
  assertion(
    map.outcome.status === 'inconclusive' &&
      map.outcome.stage === 'pre-review-specification-readiness' &&
      map.outcome.reasonCode === 'relationship-carrier-ambiguous-and-schema-compiler-pending' &&
      map.outcome.humanAcceptanceRequired === true,
    'pre-review-outcome-drift',
    'readiness map outcome differs'
  );
  assertion(
    map.adrAssessment.candidateActivated === false,
    'adr-overclaim',
    'readiness map activates an ADR candidate'
  );
  return {
    mappingCount: map.mappings.length,
    predicateReceiptCount: map.predicateReceipts.length,
    citationCount,
    abstractSlotCount: universe.length,
    structurallySatisfiedPredicateCount: counts.satisfied,
    ambiguousPredicateCount: counts.ambiguous,
    unresolvedPredicateCount: counts.unresolved,
  };
}

function inspectCarrierSources(sourceBytesByPath) {
  const specificationSchema = parseJson(
    sourceBytesByPath.get('.overlaykit/governance/schemas/specification.schema.json'),
    'specification schema'
  );
  const profileSchema = parseJson(
    sourceBytesByPath.get('.overlaykit/governance/schemas/profile.schema.json'),
    'profile schema'
  );
  const profile = parseJson(
    sourceBytesByPath.get('.overlaykit/governance/profile.json'),
    'profile'
  );
  const compilerSource = sourceBytesByPath.get('tools/governance/src/compiler.ts').toString('utf8');
  const validatorSource = sourceBytesByPath
    .get('tools/governance/src/validator.ts')
    .toString('utf8');
  assertion(
    specificationSchema.additionalProperties === false &&
      Object.prototype.hasOwnProperty.call(specificationSchema.properties, 'supersedes') &&
      !Object.prototype.hasOwnProperty.call(specificationSchema.properties, 'extends') &&
      !Object.prototype.hasOwnProperty.call(specificationSchema.properties, 'references'),
    'carrier-source-drift',
    'specification relationship carrier differs'
  );
  assertion(
    Object.prototype.hasOwnProperty.call(profileSchema.properties, 'specificationIds') &&
      JSON.stringify(profile.specificationIds) === JSON.stringify(['SPEC-0001', 'SPEC-0002']),
    'carrier-source-drift',
    'profile specification carrier differs'
  );
  assertion(
    compilerSource.includes('specificationIds') &&
      compilerSource.includes('specificationSupersededBy') &&
      validatorSource.includes('deriveSpecificationSupersededBy'),
    'carrier-source-drift',
    'compiler or validator carrier evidence differs'
  );
  return {
    specificationAdditionalProperties: false,
    hasSupersedes: true,
    hasExtends: false,
    hasReferences: false,
    activeSpecificationCount: profile.specificationIds.length,
    compilerSourcesClosed: true,
    additiveLifecycleExecuted: false,
  };
}

function invalidOutcome(reasonCode, message) {
  return {
    status: 'invalid',
    stage: 'pre-review-specification-readiness',
    reasonCode,
    message,
  };
}

export function verifyH051({
  artifactOverrides = {},
  schemaOverrides = {},
  gitReader = defaultGitReader,
  localOverrides = new Map(),
} = {}) {
  const precontractBytes = artifactBytes('precontract', artifactOverrides);
  const subjectLockBytes = artifactBytes('subjectLock', artifactOverrides);
  const docketBytes = artifactBytes('docket', artifactOverrides);
  const readinessMapBytes = artifactBytes('readinessMap', artifactOverrides);
  const subjectLock = parseJson(subjectLockBytes, 'subject lock');
  const precontract = parseJson(precontractBytes, 'precontract');
  const docket = parseJson(docketBytes, 'docket');
  const readinessMap = parseJson(readinessMapBytes, 'readiness map');

  validateH051Schemas({
    subjectLock,
    docket,
    readinessMap,
    schemaOverrides,
  });
  const sourceLockReceipt = verifySubjectLockStructure(subjectLock);
  const sourceReceipt = inspectH051Sources(subjectLock, {
    gitReader,
    localOverrides,
  });
  assertion(
    precontract.id === 'CHG-0031' && precontract.status === 'proposed',
    'precontract-identity-drift',
    'precontract identity or lifecycle differs'
  );
  const predecessorChangeRawSha256 = sha256(
    sourceReceipt.sourceBytesByPath.get('.overlaykit/governance/changes/CHG-0030.json')
  );
  verifyDocketStructure(docket, {
    precontractRawSha256: sha256(precontractBytes),
    predecessorChangeRawSha256,
    sourceLockRawSha256: sha256(subjectLockBytes),
    readinessMapRawSha256: sha256(readinessMapBytes),
  });
  const traceability = verifyReadinessMapStructure(readinessMap, {
    lock: subjectLock,
    sourceBytesByPath: sourceReceipt.sourceBytesByPath,
  });
  const carrier = inspectCarrierSources(sourceReceipt.sourceBytesByPath);

  return {
    schemaVersion: 'overlaykit-h051-verification/v1',
    structuralIntegrityVerified: true,
    structuralReconstructionVerified: true,
    semanticClassificationsAccepted: false,
    hypothesis: 'H-051',
    sourceClosure: {
      ...sourceLockReceipt,
      restrictedLsTreeSha256: sourceReceipt.restrictedLsTreeSha256,
      subjectLockRawSha256: sha256(subjectLockBytes),
      docketRawSha256: sha256(docketBytes),
      readinessMapRawSha256: sha256(readinessMapBytes),
      precontractRawSha256: sha256(precontractBytes),
      predecessorChangeRawSha256,
    },
    traceability,
    carrier,
    outcome: {
      status: 'inconclusive',
      stage: 'pre-review-specification-readiness',
      reasonCode: 'relationship-carrier-ambiguous-and-schema-compiler-pending',
      claimBoundary:
        'exact source and abstract-slot structure only; semantic mappings remain agent-proposed pending human acceptance',
    },
    adrAssessment: {
      candidateActivated: false,
      futureCandidateQuestion:
        'whether specification composition requires a machine-readable relationship remains unselected',
    },
    capabilityAudit: {
      mode: 'offline-local-readonly-verification',
      network: false,
      liveHost: false,
      usb: false,
      hidraw: false,
      docker: false,
      signals: false,
      writes: false,
      gitHistoryMutation: false,
      productMutation: false,
      specificationMutation: false,
      adrMutation: false,
    },
    authority: 'none',
    action: null,
  };
}

export function verifyH051Safe(options = {}) {
  try {
    return verifyH051(options);
  } catch (error) {
    if (!(error instanceof InvalidH051EvidenceError)) throw error;
    return {
      schemaVersion: 'overlaykit-h051-verification/v1',
      structuralIntegrityVerified: false,
      structuralReconstructionVerified: false,
      semanticClassificationsAccepted: false,
      hypothesis: 'H-051',
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
  const result = verifyH051Safe();
  process.stdout.write(`${canonicalJson(result)}\n`);
  if (!result.structuralIntegrityVerified) process.exitCode = 1;
}
