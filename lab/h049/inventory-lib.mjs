import { createHash } from 'node:crypto';

export const H049_PREDICATES = Object.freeze([
  'effectiveAcceptedNormativeAuthority',
  'spec0001LinuxRoleBinding',
  'physicalStreamDeckMk2Scope',
  'postLoginDisconnectOrReenumerationTrigger',
  'automaticRecoveryObligation',
  'physicalCommandDeliveryRestored',
  'observableRecoveryDeadline',
]);

export const H049_CLAIM_BOUNDARY = Object.freeze({
  subject:
    'only plan.json, ADR-0001 through ADR-0006, and SPEC-0001 through SPEC-0002 at main@226d299a9b0d8acd592675f514a67d6229d0134a',
  conclusion:
    'the pre-review result classifies only whether that exact accepted-law boundary contains an explicit seven-predicate automatic physical MK.2 recovery obligation',
  excluded:
    'external policy, future product intent, live host state, USB or hidraw behavior, controller safety, implementation authority, ADR or specification authority, production policy, and action authority remain unknown',
});

export const H049_ADR_ASSESSMENT = Object.freeze({
  status: 'no-decision-candidate-activated',
  rationaleCode: 'normative-audit-selects-no-product-or-production-architecture',
  futureDecisionQuestion:
    'whether the human principal wants a successor product specification for physical MK.2 recovery before any controller architecture is investigated',
  authority: 'none',
  action: null,
});

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const GIT_OID_PATTERN = /^[0-9a-f]{40}$/u;
const REVIEW_CLASSIFICATIONS = new Set([
  'normative-positive',
  'normative-exclusion',
  'historical-context',
  'future-precondition',
  'cross-domain-composite',
]);

function assertion(condition, message) {
  if (!condition) throw new Error(message);
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, expected, label) {
  assertion(isObject(value), `${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  assertion(JSON.stringify(actual) === JSON.stringify(wanted), `${label} keys differ`);
}

function nonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function canonicalValue(value, seen) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    assertion(Number.isFinite(value), 'canonical JSON forbids non-finite numbers');
    return value;
  }
  assertion(typeof value !== 'undefined' && typeof value !== 'function', 'unsupported value');
  assertion(!seen.has(value), 'canonical JSON forbids cycles');
  seen.add(value);
  if (Array.isArray(value)) {
    const result = value.map((item) => canonicalValue(item, seen));
    seen.delete(value);
    return result;
  }
  assertion(isObject(value), 'canonical JSON requires plain objects');
  const result = {};
  for (const key of Object.keys(value).sort()) {
    result[key] = canonicalValue(value[key], seen);
  }
  seen.delete(value);
  return result;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value, new Set()));
}

export function sha256(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
  return createHash('sha256').update(bytes).digest('hex');
}

export function canonicalArtifact(value) {
  return Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
}

export function parseJsonBytes(bytes, label) {
  assertion(Buffer.isBuffer(bytes), `${label} must be bytes`);
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch (error) {
    throw new Error(`${label} is not valid UTF-8 JSON: ${error.message}`);
  }
}

export function parseLsTreeZ(bytes) {
  assertion(Buffer.isBuffer(bytes), 'ls-tree stream must be bytes');
  assertion(bytes.length > 0 && bytes.at(-1) === 0, 'ls-tree stream must be NUL terminated');
  const entries = [];
  let start = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] !== 0) continue;
    const record = bytes.subarray(start, index);
    const tab = record.indexOf(9);
    assertion(tab > 0, 'ls-tree record must contain a tab');
    const metadata = record.subarray(0, tab).toString('ascii').split(' ');
    assertion(metadata.length === 3, 'ls-tree metadata field count');
    const [mode, type, oid] = metadata;
    const path = new TextDecoder('utf-8', { fatal: true }).decode(record.subarray(tab + 1));
    assertion(mode === '100644' && type === 'blob', `unsupported source mode or type: ${path}`);
    assertion(GIT_OID_PATTERN.test(oid), `invalid source OID: ${path}`);
    assertion(
      path !== '' &&
        !path.startsWith('/') &&
        !path.includes('\\') &&
        path.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..'),
      `unsafe source path: ${path}`
    );
    entries.push({ path, mode, type, oid });
    start = index + 1;
  }
  assertion(
    new Set(entries.map(({ path }) => path)).size === entries.length,
    'duplicate source path'
  );
  return entries;
}

function escapePointerToken(value) {
  return value.replaceAll('~', '~0').replaceAll('/', '~1');
}

function unescapePointerToken(value) {
  return value.replaceAll('~1', '/').replaceAll('~0', '~');
}

export function jsonPointer(value, pointer) {
  assertion(
    typeof pointer === 'string' && pointer.startsWith('/'),
    'JSON pointer must start with /'
  );
  let cursor = value;
  for (const token of pointer.slice(1).split('/').map(unescapePointerToken)) {
    if (Array.isArray(cursor)) {
      assertion(/^(0|[1-9][0-9]*)$/u.test(token), `invalid array pointer token: ${pointer}`);
      const index = Number(token);
      assertion(index < cursor.length, `array pointer out of range: ${pointer}`);
      cursor = cursor[index];
    } else {
      assertion(
        isObject(cursor) && Object.hasOwn(cursor, token),
        `missing JSON pointer: ${pointer}`
      );
      cursor = cursor[token];
    }
  }
  return cursor;
}

function structuralRole(pointer) {
  const tokens = pointer.slice(1).split('/').map(unescapePointerToken);
  return tokens.slice(Math.max(0, tokens.length - 3)).join('/');
}

function collectStrings(value, sourcePath, pointer = '', output = []) {
  if (typeof value === 'string') {
    const bytes = Buffer.from(value, 'utf8');
    output.push({
      sourcePath,
      pointer: pointer || '/',
      structuralRole: structuralRole(pointer || '/'),
      value,
      valueByteLength: bytes.length,
      valueSha256: sha256(bytes),
    });
    return output;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      collectStrings(item, sourcePath, `${pointer}/${index}`, output);
    });
    return output;
  }
  if (isObject(value)) {
    for (const key of Object.keys(value).sort()) {
      collectStrings(value[key], sourcePath, `${pointer}/${escapePointerToken(key)}`, output);
    }
  }
  return output;
}

function validateSubjectLock(lock) {
  exactKeys(
    lock,
    [
      'schemaVersion',
      'hypothesis',
      'subject',
      'sources',
      'predicates',
      'chainInvariant',
      'outcomePolicy',
      'authority',
      'action',
    ],
    'subject lock'
  );
  assertion(lock.schemaVersion === 'overlaykit-h049-subject-lock/v1', 'subject lock schema');
  assertion(lock.hypothesis === 'H-049', 'subject lock hypothesis');
  exactKeys(
    lock.subject,
    ['commit', 'tree', 'restrictedLsTreeSha256', 'planRawSha256', 'planHash'],
    'subject identity'
  );
  assertion(GIT_OID_PATTERN.test(lock.subject.commit), 'subject commit');
  assertion(GIT_OID_PATTERN.test(lock.subject.tree), 'subject tree');
  assertion(SHA256_PATTERN.test(lock.subject.restrictedLsTreeSha256), 'restricted tree hash');
  assertion(SHA256_PATTERN.test(lock.subject.planRawSha256), 'raw plan hash');
  assertion(SHA256_PATTERN.test(lock.subject.planHash), 'plan hash');
  assertion(
    Array.isArray(lock.sources) && lock.sources.length === 9,
    'exactly nine sources required'
  );
  const paths = lock.sources.map(({ path }) => path);
  assertion(new Set(paths).size === 9, 'source paths must be unique');
  assertion(
    JSON.stringify(paths) === JSON.stringify([...paths].sort()),
    'source paths must be sorted'
  );
  for (const source of lock.sources) {
    exactKeys(source, ['path', 'mode', 'oid', 'byteLength', 'sha256'], `source ${source.path}`);
    assertion(nonEmptyString(source.path), 'source path');
    assertion(source.mode === '100644', `source mode: ${source.path}`);
    assertion(GIT_OID_PATTERN.test(source.oid), `source OID: ${source.path}`);
    assertion(
      Number.isSafeInteger(source.byteLength) && source.byteLength > 0,
      `source size: ${source.path}`
    );
    assertion(SHA256_PATTERN.test(source.sha256), `source SHA-256: ${source.path}`);
  }
  assertion(
    Array.isArray(lock.predicates) && lock.predicates.length === 7,
    'seven predicates required'
  );
  assertion(
    JSON.stringify(lock.predicates.map(({ id }) => id)) === JSON.stringify(H049_PREDICATES),
    'predicate order or identity differs'
  );
  for (const predicate of lock.predicates) {
    exactKeys(predicate, ['id', 'definition'], `predicate ${predicate.id}`);
    assertion(nonEmptyString(predicate.definition), `predicate definition ${predicate.id}`);
  }
  assertion(nonEmptyString(lock.chainInvariant), 'chain invariant');
  exactKeys(
    lock.outcomePolicy,
    ['invalidEvidence', 'inconclusive', 'supported', 'refuted'],
    'outcome policy'
  );
  assertion(lock.authority === 'none' && lock.action === null, 'subject lock authority boundary');
}

function validatePlan(plan, lock, sourceBytesByPath) {
  assertion(isObject(plan), 'plan object');
  assertion(plan.planHash === lock.subject.planHash, 'compiled planHash differs');
  assertion(
    Array.isArray(plan.decisions) && plan.decisions.length === 6,
    'six plan decisions required'
  );
  assertion(
    Array.isArray(plan.specifications) && plan.specifications.length === 2,
    'two plan specifications required'
  );
  const expectedDecisionIds = Array.from(
    { length: 6 },
    (_, index) => `ADR-${String(index + 1).padStart(4, '0')}`
  );
  const expectedSpecificationIds = ['SPEC-0001', 'SPEC-0002'];
  assertion(
    JSON.stringify(plan.decisions.map(({ id }) => id)) === JSON.stringify(expectedDecisionIds),
    'plan decision identities differ'
  );
  assertion(
    JSON.stringify(plan.specifications.map(({ id }) => id)) ===
      JSON.stringify(expectedSpecificationIds),
    'plan specification identities differ'
  );
  for (const record of [...plan.decisions, ...plan.specifications]) {
    assertion(
      record.declaredStatus === 'accepted' &&
        record.effectiveStatus === 'accepted' &&
        record.supersededBy === null,
      `${record.id} is not effective accepted and unsuperseded`
    );
    const directory = record.id.startsWith('ADR-') ? 'decisions' : 'specifications';
    const path = `.overlaykit/governance/${directory}/${record.id}.json`;
    const bytes = sourceBytesByPath.get(path);
    assertion(Buffer.isBuffer(bytes), `missing accepted source ${record.id}`);
    assertion(record.contentHash === sha256(bytes), `${record.id} plan contentHash differs`);
  }
}

export function buildNormativeInventory({ subjectLock, restrictedTreeBytes, sourceBytesByPath }) {
  validateSubjectLock(subjectLock);
  assertion(sourceBytesByPath instanceof Map, 'source bytes map required');
  assertion(
    sha256(restrictedTreeBytes) === subjectLock.subject.restrictedLsTreeSha256,
    'restricted ls-tree SHA-256 differs'
  );
  const treeEntries = parseLsTreeZ(restrictedTreeBytes);
  assertion(treeEntries.length === 9, 'restricted tree must contain exactly nine entries');
  const lockByPath = new Map(subjectLock.sources.map((source) => [source.path, source]));
  const sourceMapEntries = treeEntries.map((entry) => {
    const expected = lockByPath.get(entry.path);
    assertion(expected !== undefined, `unexpected normative source: ${entry.path}`);
    const bytes = sourceBytesByPath.get(entry.path);
    assertion(Buffer.isBuffer(bytes), `missing source bytes: ${entry.path}`);
    const actual = {
      path: entry.path,
      mode: entry.mode,
      oid: entry.oid,
      byteLength: bytes.length,
      sha256: sha256(bytes),
    };
    assertion(
      canonicalJson(actual) === canonicalJson(expected),
      `source identity differs: ${entry.path}`
    );
    return actual;
  });
  assertion(sourceBytesByPath.size === 9, 'source byte map must contain exactly nine entries');
  const planPath = '.overlaykit/governance/plan.json';
  const planBytes = sourceBytesByPath.get(planPath);
  assertion(sha256(planBytes) === subjectLock.subject.planRawSha256, 'raw plan SHA-256 differs');
  const parsedByPath = new Map();
  for (const source of sourceMapEntries) {
    parsedByPath.set(
      source.path,
      parseJsonBytes(sourceBytesByPath.get(source.path), `source ${source.path}`)
    );
  }
  validatePlan(parsedByPath.get(planPath), subjectLock, sourceBytesByPath);
  const clauses = [];
  for (const source of sourceMapEntries) {
    collectStrings(parsedByPath.get(source.path), source.path, '', clauses);
  }
  const clauseKeys = clauses.map(({ sourcePath, pointer }) => `${sourcePath}\u0000${pointer}`);
  assertion(new Set(clauseKeys).size === clauses.length, 'clause identities must be unique');
  const sourceSetSha256 = sha256(canonicalJson(sourceMapEntries));
  const sourceMap = {
    schemaVersion: 'overlaykit-h049-source-map/v1',
    hypothesis: 'H-049',
    subject: subjectLock.subject,
    sourceSetSha256,
    sourceCount: sourceMapEntries.length,
    sources: sourceMapEntries,
  };
  const clauseUniverse = {
    schemaVersion: 'overlaykit-h049-clause-universe/v1',
    hypothesis: 'H-049',
    subject: {
      commit: subjectLock.subject.commit,
      tree: subjectLock.subject.tree,
      sourceSetSha256,
    },
    clauseCount: clauses.length,
    clauses,
  };
  return {
    sourceMap,
    clauseUniverse,
    parsedByPath,
  };
}

function validatePredicates(value, label) {
  exactKeys(value, H049_PREDICATES, `${label} predicates`);
  for (const predicate of H049_PREDICATES) {
    assertion(typeof value[predicate] === 'boolean', `${label} predicate ${predicate}`);
  }
}

export function evaluateReviewMap({ reviewMap, clauseUniverse, parsedByPath }) {
  exactKeys(
    reviewMap,
    [
      'schemaVersion',
      'hypothesis',
      'status',
      'humanAcceptanceRef',
      'subject',
      'clauseUniverse',
      'defaultDisposition',
      'pendingHumanJudgments',
      'candidates',
      'authority',
      'action',
    ],
    'review map'
  );
  assertion(reviewMap.schemaVersion === 'overlaykit-h049-semantic-review/v1', 'review map schema');
  assertion(reviewMap.hypothesis === 'H-049', 'review map hypothesis');
  assertion(
    reviewMap.status === 'agent-proposed-pending-human-acceptance',
    'this pre-review harness cannot admit human acceptance'
  );
  assertion(reviewMap.humanAcceptanceRef === null, 'pending review must have null acceptance');
  assertion(reviewMap.authority === 'none' && reviewMap.action === null, 'review map authority');
  exactKeys(reviewMap.subject, ['commit', 'tree'], 'review subject');
  assertion(
    reviewMap.subject.commit === clauseUniverse.subject.commit &&
      reviewMap.subject.tree === clauseUniverse.subject.tree,
    'review subject differs'
  );
  exactKeys(reviewMap.clauseUniverse, ['clauseCount', 'sha256'], 'review clause universe');
  const clauseBytes = canonicalArtifact(clauseUniverse);
  assertion(
    reviewMap.clauseUniverse.clauseCount === clauseUniverse.clauseCount,
    'clause count differs'
  );
  assertion(
    reviewMap.clauseUniverse.sha256 === sha256(clauseBytes),
    'clause universe hash differs'
  );
  exactKeys(
    reviewMap.defaultDisposition,
    ['classification', 'rationale', 'allUnlistedClauses', 'humanAcceptanceRequired'],
    'default disposition'
  );
  assertion(
    reviewMap.defaultDisposition.classification === 'no-additional-eligible-chain',
    'default classification'
  );
  assertion(
    reviewMap.defaultDisposition.allUnlistedClauses === true &&
      reviewMap.defaultDisposition.humanAcceptanceRequired === true,
    'default disposition must be complete and human reviewed'
  );
  assertion(nonEmptyString(reviewMap.defaultDisposition.rationale), 'default rationale');
  assertion(
    Array.isArray(reviewMap.pendingHumanJudgments) &&
      reviewMap.pendingHumanJudgments.length > 0 &&
      reviewMap.pendingHumanJudgments.every(nonEmptyString) &&
      new Set(reviewMap.pendingHumanJudgments).size === reviewMap.pendingHumanJudgments.length,
    'pending human judgments'
  );
  assertion(
    Array.isArray(reviewMap.candidates) && reviewMap.candidates.length > 0,
    'review candidates required'
  );
  const clauseByKey = new Map(
    clauseUniverse.clauses.map((clause) => [`${clause.sourcePath}\u0000${clause.pointer}`, clause])
  );
  const candidateIds = [];
  const evaluated = reviewMap.candidates.map((candidate) => {
    exactKeys(
      candidate,
      [
        'id',
        'obligationKey',
        'classification',
        'citations',
        'predicates',
        'explicitLinkClosure',
        'exclusionOrContradiction',
        'rationale',
      ],
      `candidate ${candidate.id}`
    );
    assertion(nonEmptyString(candidate.id), 'candidate id');
    assertion(nonEmptyString(candidate.obligationKey), `candidate obligation key ${candidate.id}`);
    assertion(
      REVIEW_CLASSIFICATIONS.has(candidate.classification),
      `candidate classification ${candidate.id}`
    );
    assertion(
      Array.isArray(candidate.citations) && candidate.citations.length > 0,
      `candidate citations ${candidate.id}`
    );
    const citationKeys = new Set();
    const citations = candidate.citations.map((citation) => {
      exactKeys(
        citation,
        ['sourcePath', 'pointer', 'valueSha256', 'role'],
        `candidate citation ${candidate.id}`
      );
      assertion(nonEmptyString(citation.role), `citation role ${candidate.id}`);
      const key = `${citation.sourcePath}\u0000${citation.pointer}`;
      assertion(!citationKeys.has(key), `duplicate citation ${candidate.id}`);
      citationKeys.add(key);
      const clause = clauseByKey.get(key);
      assertion(clause !== undefined, `citation is not in clause universe: ${key}`);
      assertion(clause.valueSha256 === citation.valueSha256, `citation value hash differs: ${key}`);
      const source = parsedByPath.get(citation.sourcePath);
      assertion(source !== undefined, `citation source missing: ${citation.sourcePath}`);
      const value = jsonPointer(source, citation.pointer);
      assertion(
        typeof value === 'string' && sha256(value) === citation.valueSha256,
        `citation retargeted: ${key}`
      );
      return citation;
    });
    validatePredicates(candidate.predicates, `candidate ${candidate.id}`);
    assertion(
      typeof candidate.explicitLinkClosure === 'boolean',
      `candidate link closure ${candidate.id}`
    );
    assertion(
      typeof candidate.exclusionOrContradiction === 'boolean',
      `candidate exclusion flag ${candidate.id}`
    );
    assertion(nonEmptyString(candidate.rationale), `candidate rationale ${candidate.id}`);
    const eligible =
      H049_PREDICATES.every((predicate) => candidate.predicates[predicate] === true) &&
      candidate.explicitLinkClosure === true &&
      candidate.exclusionOrContradiction === false;
    candidateIds.push(candidate.id);
    return { ...candidate, citations, eligible };
  });
  assertion(new Set(candidateIds).size === candidateIds.length, 'candidate ids must be unique');
  const eligibleChains = evaluated.filter(({ eligible }) => eligible);
  const reviewAccepted = false;
  const unknowns = reviewMap.pendingHumanJudgments.map((statement, index) => ({
    id: `human-review-${String(index + 1).padStart(2, '0')}`,
    stage: 'semantic-review',
    statement,
  }));
  const coverageComplete = false;
  return {
    candidates: evaluated,
    eligibleChains,
    unknowns,
    coverageComplete,
    reviewAccepted,
  };
}

export function deriveH049Outcome({
  validEvidence = true,
  coverageComplete,
  unknowns,
  eligibleChains,
}) {
  if (validEvidence !== true) return null;
  assertion(typeof coverageComplete === 'boolean', 'coverageComplete boolean required');
  assertion(Array.isArray(unknowns), 'unknowns array required');
  assertion(Array.isArray(eligibleChains), 'eligibleChains array required');
  if (!coverageComplete || unknowns.length > 0) {
    return {
      status: 'inconclusive',
      stage: 'semantic-review',
      reasonCode: 'human-review-pending-or-semantic-coverage-incomplete',
    };
  }
  if (eligibleChains.length > 0) {
    return {
      status: 'supported',
      stage: 'normative-obligation-chain',
      reasonCode: 'complete-seven-predicate-chain-present',
    };
  }
  return {
    status: 'refuted',
    stage: 'closed-accepted-law-boundary',
    reasonCode: 'complete-zero-chain-coverage',
  };
}

export function buildCandidateIndex({ reviewMap, clauseUniverse, parsedByPath }) {
  const review = evaluateReviewMap({ reviewMap, clauseUniverse, parsedByPath });
  const outcome = deriveH049Outcome(review);
  const projectedOutcomeIfExactMapAccepted =
    review.eligibleChains.length > 0
      ? {
          status: 'supported',
          stage: 'normative-obligation-chain',
          reasonCode: 'complete-seven-predicate-chain-present',
        }
      : {
          status: 'refuted',
          stage: 'closed-accepted-law-boundary',
          reasonCode: 'complete-zero-chain-coverage',
          condition:
            'only-after-exact-map-content-addressed-human-acceptance-and-zero-pending-judgments',
        };
  return {
    schemaVersion: 'overlaykit-h049-candidate-index/v1',
    hypothesis: 'H-049',
    predicates: H049_PREDICATES,
    chainInvariant:
      'one obligationKey, explicit link closure, all seven predicates true, and no exclusion or contradiction',
    mechanicalCoverageComplete: true,
    semanticReview: {
      status: reviewMap.status,
      humanAcceptanceRef: reviewMap.humanAcceptanceRef,
      pendingHumanJudgments: reviewMap.pendingHumanJudgments,
      coverageComplete: review.coverageComplete,
    },
    candidates: review.candidates,
    eligibleChains: review.eligibleChains.map(({ id, obligationKey }) => ({ id, obligationKey })),
    unknowns: review.unknowns,
    outcome,
    projectedOutcomeIfExactMapAccepted,
    adrAssessment: H049_ADR_ASSESSMENT,
    authority: 'none',
    action: null,
  };
}

export function semanticEvidenceSha256({
  harnessSourceMapArtifact,
  sourceMapArtifact,
  clauseUniverseArtifact,
  candidateIndexArtifact,
  outcome,
}) {
  for (const artifact of [
    harnessSourceMapArtifact,
    sourceMapArtifact,
    clauseUniverseArtifact,
    candidateIndexArtifact,
  ]) {
    exactKeys(artifact, ['file', 'byteLength', 'sha256'], 'semantic artifact reference');
  }
  return sha256(
    canonicalJson({
      schemaVersion: 'overlaykit-h049-semantic-evidence/v1',
      hypothesis: 'H-049',
      subject: '226d299a9b0d8acd592675f514a67d6229d0134a',
      artifacts: {
        harnessSourceMap: harnessSourceMapArtifact,
        sourceMap: sourceMapArtifact,
        clauseUniverse: clauseUniverseArtifact,
        candidateIndex: candidateIndexArtifact,
      },
      outcome,
      adrAssessment: H049_ADR_ASSESSMENT,
      authority: 'none',
      action: null,
      claimBoundary: H049_CLAIM_BOUNDARY,
    })
  );
}
