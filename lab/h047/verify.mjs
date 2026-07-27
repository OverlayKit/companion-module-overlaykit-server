import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { crc32, inflateRawSync } from 'node:zlib';
import Ajv2020 from 'ajv/dist/2020.js';
import { parseDocument as parseYamlDocument } from 'yaml';

const VERIFIER_PATH = fileURLToPath(import.meta.url);
const LAB_DIRECTORY = path.dirname(VERIFIER_PATH);
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const GIT_EXECUTABLE = '/usr/bin/git';
const GIT_OID_PATTERN = /^[0-9a-f]{40}$/u;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const SEMANTIC_REVIEW_SCHEMA = 'overlaykit-h047-semantic-review/v2';
const SIGNAL_POLICY_VERSION = 'overlaykit-h047-semantic-signal-policy/v2';
const ARCHIVE_POLICY_VERSION = 'overlaykit-h047-archive-expansion/v1';
const SIGNAL_ROLE_ORDER = Object.freeze([
  'image',
  'deployment',
  'accepted-governance',
  'lifecycle-wording',
]);
const SIGNAL_TOKEN_PATTERNS = Object.freeze([
  'deploy',
  'lifecycle',
  'desired[-_ ]?state',
  'cardinality',
  'reconcil',
  'converg',
  'production[-_ ]?host',
  'linux production',
  'drift',
  'restart[-_ ]?policy',
  'restartPolicy',
  'restart:',
  'replicas:',
  'systemd',
  'ExecStart=',
]);
const ARCHIVE_LIMITS = Object.freeze({
  maxDepth: 1,
  maxArchives: 4,
  maxCompressedBytes: 2 * 1024 * 1024,
  maxArchiveDecompressedBytes: 4 * 1024 * 1024,
  maxDecompressedBytes: 8 * 1024 * 1024,
  maxMemberBytes: 512 * 1024,
  maxPayloadBytes: 8 * 1024 * 1024,
  maxMembers: 256,
  maxMemberPathBytes: 256,
  maxVirtualRouteBytes: 1024,
});
const EDGE_CONTRACTS = Object.freeze({
  'archive-nesting': {
    roles: ['containment'],
    targets: ['path'],
    assertionKeys: [['memberPath', 'nestedClosureSha256']],
    citationCounts: [1],
  },
  'compose-dockerfile': {
    roles: ['operational'],
    targets: ['path'],
    assertionKeys: [['composePath']],
    citationCounts: [1],
  },
  'compose-entrypoint': {
    roles: ['operational'],
    targets: ['path'],
    assertionKeys: [['containerPath', 'readOnlySourceEnvironmentKey']],
    citationCounts: [2],
  },
  'docker-build-context': {
    roles: ['containment'],
    targets: ['path-set'],
    assertionKeys: [['contextRoot', 'dockerignorePath']],
    citationCounts: [2],
  },
  'dockerfile-copy': {
    roles: ['operational'],
    targets: ['path'],
    assertionKeys: [['selector'], ['targetPath']],
    citationCounts: [1],
  },
  'dockerfile-entrypoint': {
    roles: ['operational'],
    targets: ['path'],
    assertionKeys: [['selector'], ['targetPath']],
    citationCounts: [1],
  },
  'dockerfile-package-script': {
    roles: ['operational'],
    targets: ['path'],
    assertionKeys: [['selector']],
    citationCounts: [1],
  },
  'js-command': {
    roles: ['verification'],
    targets: ['path'],
    assertionKeys: [['executable', 'relativePath']],
    citationCounts: [1],
  },
  'js-environment-path-binding': {
    roles: ['operational'],
    targets: ['path'],
    assertionKeys: [['boundDirectory', 'environmentKey']],
    citationCounts: [1],
  },
  'js-import': {
    roles: ['operational', 'verification'],
    targets: ['path'],
    assertionKeys: [['module']],
    citationCounts: [1],
  },
  'js-path-binding': {
    roles: ['content-binding', 'operational', 'verification'],
    targets: ['path'],
    assertionKeys: [['constant', 'relativePath'], ['relativePath']],
    citationCounts: [1],
  },
  'manifest-record': {
    roles: ['content-binding'],
    targets: ['path'],
    assertionKeys: [['contentHash', 'recordId']],
    citationCounts: [1],
  },
  'package-script-entrypoint': {
    roles: ['operational'],
    targets: ['path'],
    assertionKeys: [['entrypoint', 'scriptNames']],
    citationCounts: [8],
  },
  'package-script-glob-member': {
    roles: ['operational'],
    targets: ['path'],
    assertionKeys: [['expandedGlob', 'scriptName']],
    citationCounts: [1],
  },
  'package-script-runner': {
    roles: ['operational'],
    targets: ['path'],
    assertionKeys: [['scriptName']],
    citationCounts: [1],
  },
  'package-workspace-script': {
    roles: ['operational'],
    targets: ['path'],
    assertionKeys: [['scriptName', 'workspaceName']],
    citationCounts: [2],
  },
  'plan-record': {
    roles: ['authority-binding'],
    targets: ['path'],
    assertionKeys: [['contentHash', 'effectiveStatus', 'recordId']],
    citationCounts: [1],
  },
  'record-reference': {
    roles: ['non-normative-reference'],
    targets: ['path'],
    assertionKeys: [['relation']],
    citationCounts: [1],
  },
  'shell-exec': {
    roles: ['operational'],
    targets: ['path'],
    assertionKeys: [['executable']],
    citationCounts: [1],
  },
  'workflow-npm-script': {
    roles: ['operational'],
    targets: ['path'],
    assertionKeys: [['scriptName'], ['scriptNames']],
    citationCounts: [1],
  },
});

export const H047_INDEPENDENT_GIT_ENV = Object.freeze({
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

export const H047_INDEPENDENT_SUBJECT = Object.freeze({
  commit: 'a68ab8f2c8a64828c1c685161ef9319bd8a837c7',
  tree: '9ee6e2f74f7fd6272559d1b91fe4005726cc5b18',
  entryCount: 238,
  lsTreeSha256: 'c9abef88898ec71e5130e041920ca285bce46bbabb08b6a6d885e292295aad05',
  planHash: 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4',
  manifestContentHash: 'a31de506836ffd12f9b1a2849bdb0c353e886481800a2ab01a3dd293ebb7c87e',
});

const SPEC_0001_CONTENT_HASH = '917f1ca2febe17f8901ab71f91a0b0135402f9be972a876f233fcd5c789b8179';
const EXPECTED_TYPED_EDGE_COUNT = 106;
const EXPECTED_TYPED_EDGE_CLOSURE_SHA256 =
  '72a06238c7ab380eb97ec5cc10789bf23cf191849ba3e381ec4ca3005271fa79';
const IMAGE_REFERENCE = 'ghcr.io/bitfocus/companion/companion:v4.3.3';
const IMAGE_ID = 'sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e';

export const H047_INDEPENDENT_PREDICATES = Object.freeze([
  'currentAcceptedProductionAuthority',
  'exactImageReferenceAndId',
  'linuxProductionHostRoleBinding',
  'desiredPresenceAndCardinality',
  'repositoryDeclaredLifecycleOwnerRole',
  'reconcilerMechanism',
  'absenceToConvergenceRule',
  'explicitLinkClosure',
]);

export const H047_INDEPENDENT_SOURCE_PATHS = Object.freeze(
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

export const H047_INDEPENDENT_ADR_ASSESSMENT = Object.freeze({
  status: 'no-decision-candidate-activated',
  rationaleCode: 'repository-inventory-selects-no-new-architecture',
  futureDecisionQuestion:
    'which accepted source of truth, lifecycle-owner role, reconciler, and convergence policy should govern a persistent Companion deployment if one is desired',
  authority: 'none',
  action: null,
});

const ACCEPTED_DECISIONS = Object.freeze(
  Array.from({ length: 6 }, (_, index) => `ADR-${String(index + 1).padStart(4, '0')}`)
);
const ACCEPTED_SPECIFICATIONS = Object.freeze(['SPEC-0001', 'SPEC-0002']);
const IMPLEMENTED_CHANGES = Object.freeze([
  'CHG-0001',
  'CHG-0002',
  'CHG-0003',
  'CHG-0004',
  'CHG-0005',
  'CHG-0014',
  'CHG-0016',
  'CHG-0018',
  'CHG-0021',
]);

const SURFACES = Object.freeze([
  Object.freeze({
    path: '.github/workflows/governance.yml',
    kind: 'ci-workflow',
    disposition: 'repository-ci',
  }),
  Object.freeze({
    path: '.github/workflows/h034-canonical.yml',
    kind: 'ci-workflow',
    disposition: 'ephemeral-lab-ci',
  }),
  Object.freeze({
    path: 'lab/h034/Dockerfile.companion',
    kind: 'dockerfile',
    disposition: 'ephemeral-lab',
  }),
  Object.freeze({
    path: 'lab/h034/Dockerfile.overlaykit',
    kind: 'dockerfile',
    disposition: 'ephemeral-lab',
  }),
  Object.freeze({
    path: 'lab/h034/Dockerfile.overlaykit-local',
    kind: 'dockerfile',
    disposition: 'ephemeral-lab',
  }),
  Object.freeze({
    path: 'lab/h034/compose.local-source.yaml',
    kind: 'compose',
    disposition: 'ephemeral-lab',
  }),
  Object.freeze({
    path: 'lab/h034/compose.yaml',
    kind: 'compose',
    disposition: 'ephemeral-lab',
  }),
  Object.freeze({
    path: 'lab/h038/compose.yaml',
    kind: 'compose',
    disposition: 'ephemeral-lab',
  }),
]);

const IDENTITY_PATHS = Object.freeze([
  '.overlaykit/governance/changes/CHG-0008.json',
  '.overlaykit/governance/changes/CHG-0014.json',
  '.overlaykit/governance/changes/CHG-0019.json',
  '.overlaykit/governance/decisions/ADR-0006.json',
  'lab/h034/Dockerfile.companion',
  'lab/h034/inputs.lock.json',
  'lab/h037/acquisition-lib.mjs',
  'lab/h037/verify.mjs',
  'lab/h041/run.mjs',
  'lab/h041/schema.test.mjs',
  'lab/h041/schemas/dynamic-reacquisition-run.schema.json',
  'lab/h041/verify.mjs',
  'lab/h041/verify.test.mjs',
  'lab/h042/run.mjs',
  'lab/h042/runtime-lib.mjs',
  'lab/h042/schema.test.mjs',
  'lab/h042/schemas/surface-worker-recycle-run.schema.json',
  'lab/h042/verify.mjs',
  'lab/h045/admission-lib.mjs',
  'lab/h045/classifier-lib.mjs',
  'lab/h045/observer-lib.mjs',
  'lab/h045/observer-lib.test.mjs',
  'lab/h045/run.test.mjs',
  'lab/h045/schemas/live-run.schema.json',
  'lab/h045/verify.mjs',
  'lab/h045/verify.test.mjs',
]);

const SURFACE_BY_PATH = new Map(SURFACES.map((surface) => [surface.path, surface]));
const IDENTITY_SET = new Set(IDENTITY_PATHS);

const CLAIM_BOUNDARY = Object.freeze({
  proves: Object.freeze([
    'whether the exact immutable repository subject contains a fully explicit eight-predicate desired-state chain for the exact accepted Companion image',
    'the exact subject inventory, governance status inventory, image-identity occurrences, and deployment-shaped path inventory',
  ]),
  excludes: Object.freeze([
    'desired state held outside the exact repository subject',
    'current host state, operator intent, compliance, drift, or cause',
    'actual or externally held operational lifecycle ownership',
    'remediation authority, installation, configuration, signaling, restart, reconciliation, or production action',
  ]),
  authority: 'none',
  action: null,
});

const ALLOWED_MODES = new Set(['100644', '100755']);

function assertion(condition, message) {
  if (!condition) throw new Error(message);
}

function canonicalValue(value, seen) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    assertion(Number.isFinite(value), 'canonical JSON rejects non-finite numbers');
    return value;
  }
  if (Array.isArray(value)) return value.map((entry) => canonicalValue(entry, seen));
  assertion(value !== null && typeof value === 'object', 'canonical JSON rejects non-data values');
  assertion(!seen.has(value), 'canonical JSON rejects cycles');
  seen.add(value);
  const result = {};
  for (const key of Object.keys(value).sort()) {
    assertion(value[key] !== undefined, `canonical JSON rejects undefined at ${key}`);
    result[key] = canonicalValue(value[key], seen);
  }
  seen.delete(value);
  return result;
}

export function canonicalIndependentJson(value) {
  return JSON.stringify(canonicalValue(value, new Set()));
}

export function independentSha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function exactObjectKeys(value, expected) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    canonicalIndependentJson(Object.keys(value).sort()) ===
      canonicalIndependentJson([...expected].sort())
  );
}

function nonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function safePath(value) {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    !value.startsWith('/') &&
    !/^[A-Za-z]:/u.test(value) &&
    !value.includes('\\') &&
    value.split('/').every((segment) => segment !== '' && segment !== '.' && segment !== '..')
  );
}

function jsonPointer(value, pointer) {
  if (pointer === '') return value;
  assertion(typeof pointer === 'string' && pointer.startsWith('/'), 'invalid JSON pointer');
  return pointer
    .slice(1)
    .split('/')
    .map((token) => {
      assertion(!/~(?:[^01]|$)/u.test(token), 'invalid JSON pointer escape');
      return token.replace(/~1/gu, '/').replace(/~0/gu, '~');
    })
    .reduce((current, token) => {
      if (
        current === null ||
        typeof current !== 'object' ||
        !Object.prototype.hasOwnProperty.call(current, token)
      ) {
        return undefined;
      }
      return current[token];
    }, value);
}

function parseJsonBytes(bytes, label) {
  assertion(Buffer.isBuffer(bytes), `${label} bytes unavailable`);
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch (error) {
    throw new Error(`${label} invalid UTF-8 JSON: ${error.message}`);
  }
}

function parseLsTreeZ(bytes) {
  assertion(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.at(-1) === 0, 'bad ls-tree frame');
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const result = [];
  const paths = new Set();
  let start = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] !== 0) continue;
    assertion(index > start, 'empty ls-tree record');
    const record = decoder.decode(bytes.subarray(start, index));
    const match = /^([0-7]{6}) (blob|tree|commit) ([0-9a-f]{40})\t([\s\S]+)$/u.exec(record);
    assertion(match !== null, 'malformed ls-tree record');
    const [, mode, type, oid, relativePath] = match;
    assertion(type === 'blob', `unsupported Git object: ${relativePath}`);
    assertion(ALLOWED_MODES.has(mode), `unsupported Git mode: ${relativePath}`);
    assertion(safePath(relativePath), `unsafe Git path: ${relativePath}`);
    assertion(!paths.has(relativePath), `duplicate Git path: ${relativePath}`);
    paths.add(relativePath);
    result.push({ mode, type, oid, path: relativePath });
    start = index + 1;
  }
  assertion(
    canonicalIndependentJson(result.map(({ path: value }) => value)) ===
      canonicalIndependentJson(
        result
          .map(({ path: value }) => value)
          .sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)))
      ),
    'ls-tree is not sorted'
  );
  return result;
}

function sourceSetSha256(entries) {
  const paths = new Set();
  const records = entries
    .map(({ path: relativePath, mode, byteLength, sha256: digest }) => {
      assertion(safePath(relativePath), `unsafe source path: ${relativePath}`);
      assertion(ALLOWED_MODES.has(mode), `unsupported source mode: ${relativePath}`);
      assertion(Number.isSafeInteger(byteLength) && byteLength >= 0, 'bad source length');
      assertion(SHA256_PATTERN.test(digest), 'bad source digest');
      assertion(!paths.has(relativePath), `duplicate source path: ${relativePath}`);
      paths.add(relativePath);
      return { path: relativePath, mode, byteLength, sha256: digest };
    })
    .sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  const framed = records
    .map(
      ({ path: relativePath, mode, byteLength, sha256: digest }) =>
        `${relativePath}\0${mode}\0${byteLength}\0${digest}\0`
    )
    .join('');
  return independentSha256(Buffer.from(framed, 'utf8'));
}

function git(args) {
  const result = spawnSync(GIT_EXECUTABLE, args, {
    cwd: REPOSITORY_ROOT,
    encoding: null,
    env: H047_INDEPENDENT_GIT_ENV,
    maxBuffer: 64 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  assertion(result.error === undefined, `git failed to start: ${result.error?.code}`);
  assertion(
    result.status === 0 && result.signal === null,
    `git ${args[0]} failed: ${String(result.stderr)}`
  );
  return result.stdout;
}

function oneLine(bytes, label) {
  const value = new TextDecoder('utf-8', { fatal: true }).decode(bytes).trim();
  assertion(value !== '' && !value.includes('\n') && !value.includes('\r'), `${label} one line`);
  return value;
}

function treeSnapshot(commit) {
  assertion(GIT_OID_PATTERN.test(commit), 'invalid tree snapshot commit');
  const treeBytes = git(['ls-tree', '-rz', '--full-tree', commit]);
  const entries = parseLsTreeZ(treeBytes);
  const blobs = new Map();
  for (const { oid } of entries) {
    if (!blobs.has(oid)) blobs.set(oid, git(['cat-file', 'blob', oid]));
  }
  return { treeBytes, entries, blobs };
}

function entryBytes(snapshot, relativePath) {
  const entry = snapshot.entries.find(({ path: candidate }) => candidate === relativePath);
  assertion(entry !== undefined, `missing Git path: ${relativePath}`);
  const bytes = snapshot.blobs.get(entry.oid);
  assertion(Buffer.isBuffer(bytes), `missing Git blob: ${relativePath}`);
  return { entry, bytes };
}

function sameSet(actual, expected) {
  if (!Array.isArray(actual) || !Array.isArray(expected) || actual.length !== expected.length) {
    return false;
  }
  const left = [...actual].sort();
  const right = [...expected].sort();
  return left.every((value, index) => value === right[index]);
}

function governanceKind(relativePath) {
  if (/^\.overlaykit\/governance\/decisions\/ADR-[0-9]{4}\.json$/u.test(relativePath)) {
    return 'decision';
  }
  if (/^\.overlaykit\/governance\/specifications\/SPEC-[0-9]{4}\.json$/u.test(relativePath)) {
    return 'specification';
  }
  if (/^\.overlaykit\/governance\/changes\/CHG-[0-9]{4}\.json$/u.test(relativePath)) {
    return 'change';
  }
  return null;
}

function classifyDeploymentPath(relativePath) {
  const expected = SURFACE_BY_PATH.get(relativePath);
  if (expected) {
    return {
      deploymentShaped: true,
      recognized: true,
      kind: expected.kind,
      disposition: expected.disposition,
    };
  }
  const basename = relativePath.split('/').at(-1);
  const suspicious =
    /^Dockerfile(?:\..+)?$/u.test(basename) ||
    /^(?:docker-)?compose(?:\.[^/]+)?\.ya?ml$/u.test(basename) ||
    /\.(?:service|socket|timer|target|mount|path|tf|tf\.json|nomad)$/u.test(basename) ||
    /^(?:Chart|values)\.ya?ml$/u.test(basename) ||
    /(?:^|[-_.])(?:deployment|statefulset|daemonset|playbook|kustomization)(?:[-_.]|$)/iu.test(
      basename
    ) ||
    /(?:^|\/)(?:helm|k8s|kubernetes|terraform|ansible)(?:\/|$)/iu.test(relativePath);
  return suspicious
    ? {
        deploymentShaped: true,
        recognized: false,
        kind: 'unknown-deployment-format',
        disposition: 'unknown',
      }
    : {
        deploymentShaped: false,
        recognized: true,
        kind: null,
        disposition: 'not-deployment-shaped',
      };
}

function candidateRole(relativePath, statusMap) {
  const status = statusMap[relativePath]?.status;
  const kind = governanceKind(relativePath);
  if (kind === 'decision') return status === 'accepted' ? 'accepted-decision' : 'unknown-decision';
  if (kind === 'specification') {
    return status === 'accepted' ? 'accepted-specification' : 'unknown-specification';
  }
  if (kind === 'change') {
    if (status === 'implemented') return 'implemented-change';
    if (status === 'proposed') return 'non-authoritative-proposal';
    return 'unknown-change';
  }
  const surface = classifyDeploymentPath(relativePath);
  if (surface.deploymentShaped) {
    if (!surface.recognized) return 'unknown-deployment-surface';
    return surface.kind === 'ci-workflow' ? 'ci-workflow' : 'ephemeral-lab-deployment';
  }
  if (IDENTITY_SET.has(relativePath)) return 'historical-image-identity-source';
  return 'non-candidate';
}

function statusCounts(records) {
  const result = { total: records.length };
  for (const { status } of records) result[status] = (result[status] ?? 0) + 1;
  return result;
}

function countOccurrences(bytes, needle) {
  let count = 0;
  let offset = 0;
  while ((offset = bytes.indexOf(needle, offset)) !== -1) {
    count += 1;
    offset += needle.length;
  }
  return count;
}

function byteLex(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function sortedUniqueStrings(values, label, order = byteLex) {
  assertion(
    Array.isArray(values) && values.every(nonEmptyString) && new Set(values).size === values.length,
    `${label} must contain unique non-empty strings`
  );
  assertion(
    canonicalIndependentJson(values) === canonicalIndependentJson([...values].sort(order)),
    `${label} must be sorted`
  );
}

function uniqueStrings(values, label) {
  assertion(
    Array.isArray(values) && values.every(nonEmptyString) && new Set(values).size === values.length,
    `${label} must contain unique non-empty strings`
  );
}

function decodeUtf8OrNull(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function expectedSignalPolicy() {
  return {
    roleOrder: SIGNAL_ROLE_ORDER,
    exactImageReference: IMAGE_REFERENCE,
    exactImageId: IMAGE_ID,
    recognizedDeploymentSurfaces: SURFACES.map(({ path: relativePath }) => relativePath),
    acceptedGovernanceBinding: 'compiled-plan-effectiveStatus-accepted',
    utf8CaseInsensitiveTokens: SIGNAL_TOKEN_PATTERNS,
    archiveExpansionPolicyVersion: ARCHIVE_POLICY_VERSION,
  };
}

function detectedFormat(relativePath, bytes) {
  const basename = relativePath.split('/').at(-1);
  if (/\.(?:tar\.gz|tgz)$/iu.test(relativePath)) {
    assertion(bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b, 'archive signature');
    return 'tar+gzip';
  }
  const text = decodeUtf8OrNull(bytes);
  assertion(text !== null, `unsupported non-UTF-8 source: ${relativePath}`);
  if (/\.json$/iu.test(basename)) {
    parseJsonBytes(bytes, relativePath);
    return 'json';
  }
  if (/\.ya?ml$/iu.test(basename)) return 'yaml';
  if (/^Dockerfile(?:\..+)?$/u.test(basename)) return 'dockerfile';
  if (/\.(?:[cm]?js|[cm]?ts|tsx|jsx)$/iu.test(basename)) return 'javascript';
  if (/\.sh$/iu.test(basename)) return 'shell';
  if (/\.md$/iu.test(basename)) return 'markdown';
  return 'utf8-text';
}

function signalReceipt(role, origin, matches, evidenceRef) {
  return { role, origin, matches, evidenceRef };
}

export function deriveIndependentSignals({
  relativePath,
  bytes,
  digest = independentSha256(bytes),
  acceptedGovernance = false,
  planAuthorityIndex = false,
  recognizedDeployment = false,
  origin = 'raw-blob',
  evidencePrefix = origin === 'raw-blob' ? 'blob-sha256:' : 'sha256:',
}) {
  assertion(safePath(relativePath), 'signal path');
  assertion(Buffer.isBuffer(bytes), 'signal bytes');
  assertion(SHA256_PATTERN.test(digest) && independentSha256(bytes) === digest, 'signal digest');
  assertion(['raw-blob', 'archive-member'].includes(origin), 'signal origin');
  const text = decodeUtf8OrNull(bytes);
  const signals = [];
  const imageMatches = [];
  if (bytes.includes(Buffer.from(IMAGE_ID, 'utf8'))) imageMatches.push('exact-image-id');
  if (bytes.includes(Buffer.from(IMAGE_REFERENCE, 'utf8'))) {
    imageMatches.push('exact-image-reference');
  }
  if (imageMatches.length > 0) {
    signals.push(signalReceipt('image', origin, imageMatches, `${evidencePrefix}${digest}`));
  }
  if (recognizedDeployment || (text !== null && /deploy/iu.test(text))) {
    signals.push(
      signalReceipt(
        'deployment',
        origin,
        [recognizedDeployment ? 'recognized-deployment-surface' : 'deployment-wording'],
        `${evidencePrefix}${digest}`
      )
    );
  }
  if (acceptedGovernance || planAuthorityIndex) {
    signals.push(
      signalReceipt(
        'accepted-governance',
        origin,
        [planAuthorityIndex ? 'effective-authority-index' : 'effective-accepted-record'],
        `${evidencePrefix}${digest}`
      )
    );
  }
  if (
    text !== null &&
    SIGNAL_TOKEN_PATTERNS.slice(1).some((source) => new RegExp(source, 'iu').test(text))
  ) {
    signals.push(
      signalReceipt(
        'lifecycle-wording',
        origin,
        ['predicate-vocabulary'],
        `${evidencePrefix}${digest}`
      )
    );
  }
  return signals;
}

function aggregateArchiveSignals(expansion) {
  const present = new Set(
    expansion.members.flatMap(({ signals }) => signals.map(({ role }) => role))
  );
  return SIGNAL_ROLE_ORDER.filter(
    (role) => role !== 'accepted-governance' && present.has(role)
  ).map((role) =>
    signalReceipt(
      role,
      'archive-expansion',
      ['embedded-archive-member-signal'],
      `archive-closure-sha256:${expansion.closureSha256}`
    )
  );
}

function pendingReview(signals) {
  const candidate = signals.length > 0;
  return {
    agentDisposition: candidate ? 'candidate' : 'dismissed',
    rationaleCode: candidate ? 'direct-semantic-signal' : 'no-direct-semantic-signal',
    humanDisposition: 'pending',
    humanJudgmentIds: [],
  };
}

function archiveAssertion(condition, message) {
  assertion(condition, `H-047 independent archive: ${message}`);
}

function allZero(bytes) {
  return bytes.every((byte) => byte === 0);
}

function tarTextField(bytes, label) {
  const nul = bytes.indexOf(0);
  const content = nul === -1 ? bytes : bytes.subarray(0, nul);
  archiveAssertion(nul === -1 || allZero(bytes.subarray(nul)), `${label} termination`);
  const decoded = decodeUtf8OrNull(content);
  archiveAssertion(decoded !== null, `${label} UTF-8`);
  return decoded;
}

function tarOctal(bytes, label, allowEmpty = true) {
  archiveAssertion((bytes[0] & 0x80) === 0, `${label} base-256 unsupported`);
  archiveAssertion(
    [...bytes].every((byte) => byte === 0 || byte === 0x20 || (byte >= 0x30 && byte <= 0x37)),
    `${label} octal bytes`
  );
  const nul = bytes.indexOf(0);
  archiveAssertion(
    nul === -1 || [...bytes.subarray(nul)].every((byte) => byte === 0 || byte === 0x20),
    `${label} padding`
  );
  const value = (nul === -1 ? bytes : bytes.subarray(0, nul)).toString('ascii').trim();
  if (value === '') {
    archiveAssertion(allowEmpty, `${label} empty`);
    return 0;
  }
  archiveAssertion(/^[0-7]+$/u.test(value), `${label} syntax`);
  const parsed = BigInt(`0o${value}`);
  archiveAssertion(parsed <= BigInt(Number.MAX_SAFE_INTEGER), `${label} range`);
  return Number(parsed);
}

function tarPath(header) {
  const name = tarTextField(header.subarray(0, 100), 'name');
  const prefix = tarTextField(header.subarray(345, 500), 'prefix');
  const relativePath = prefix === '' ? name : `${prefix}/${name}`;
  archiveAssertion(
    safePath(relativePath) &&
      !relativePath.includes('!') &&
      !/[\u0000-\u001f\u007f]/u.test(relativePath) &&
      Buffer.byteLength(relativePath, 'utf8') <= ARCHIVE_LIMITS.maxMemberPathBytes,
    `unsafe member path ${JSON.stringify(relativePath)}`
  );
  return relativePath;
}

function validateTarHeader(header, offset) {
  const signature = header.subarray(257, 265);
  const posix = signature.equals(Buffer.from('ustar\0' + '00', 'ascii'));
  const gnu = signature.equals(Buffer.from([0x75, 0x73, 0x74, 0x61, 0x72, 0x20, 0x20, 0x00]));
  archiveAssertion(posix || gnu, `unsupported header at ${offset}`);
  const expected = tarOctal(header.subarray(148, 156), 'checksum', false);
  let unsigned = 0;
  let signed = 0;
  for (let index = 0; index < header.length; index += 1) {
    const byte = index >= 148 && index < 156 ? 0x20 : header[index];
    unsigned += byte;
    signed += byte > 0x7f ? byte - 0x100 : byte;
  }
  archiveAssertion(expected === unsigned || expected === signed, `checksum at ${offset}`);
}

function strictGunzip(bytes, maxOutputLength) {
  archiveAssertion(bytes.length >= 18, 'truncated gzip wrapper');
  archiveAssertion(
    bytes[0] === 0x1f && bytes[1] === 0x8b && bytes[2] === 8,
    'gzip identity or method'
  );
  const flags = bytes[3];
  archiveAssertion((flags & 0xe0) === 0, 'gzip reserved flags');
  let cursor = 10;
  if ((flags & 0x04) !== 0) {
    archiveAssertion(cursor + 2 <= bytes.length, 'gzip extra length');
    const extraLength = bytes.readUInt16LE(cursor);
    cursor += 2 + extraLength;
    archiveAssertion(cursor <= bytes.length, 'gzip extra field');
  }
  for (const flag of [0x08, 0x10]) {
    if ((flags & flag) === 0) continue;
    const terminator = bytes.indexOf(0, cursor);
    archiveAssertion(terminator !== -1, 'gzip string field');
    cursor = terminator + 1;
  }
  if ((flags & 0x02) !== 0) {
    archiveAssertion(cursor + 2 <= bytes.length, 'gzip header checksum');
    const expected = bytes.readUInt16LE(cursor);
    const actual = crc32(bytes.subarray(0, cursor)) & 0xffff;
    archiveAssertion(expected === actual, 'gzip header checksum mismatch');
    cursor += 2;
  }
  archiveAssertion(cursor + 8 <= bytes.length, 'gzip deflate payload');
  let decoded;
  try {
    decoded = inflateRawSync(bytes.subarray(cursor), {
      info: true,
      maxOutputLength,
    });
  } catch (error) {
    throw new Error(`H-047 independent archive: deflate decode: ${error.message}`);
  }
  const trailer = cursor + decoded.engine.bytesWritten;
  archiveAssertion(trailer + 8 === bytes.length, 'gzip trailing or concatenated stream');
  archiveAssertion(
    crc32(decoded.buffer) >>> 0 === bytes.readUInt32LE(trailer),
    'gzip payload checksum'
  );
  archiveAssertion(
    decoded.buffer.length >>> 0 === bytes.readUInt32LE(trailer + 4),
    'gzip payload length'
  );
  return decoded.buffer;
}

function parseStrictTarGzip(bytes, remaining) {
  archiveAssertion(bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b, 'gzip signature');
  const tar = strictGunzip(
    bytes,
    Math.min(ARCHIVE_LIMITS.maxArchiveDecompressedBytes, remaining.decompressedBytes)
  );
  archiveAssertion(tar.length % 512 === 0, 'tar block alignment');
  const records = [];
  const names = new Set();
  let offset = 0;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (allZero(header)) {
      archiveAssertion(offset + 1024 <= tar.length, 'truncated terminator');
      archiveAssertion(allZero(tar.subarray(offset + 512, offset + 1024)), 'single terminator');
      archiveAssertion(allZero(tar.subarray(offset + 1024)), 'non-zero trailer');
      return { records, decompressedBytes: tar.length };
    }
    validateTarHeader(header, offset);
    const type = header[156] === 0 ? '0' : String.fromCharCode(header[156]);
    archiveAssertion(type === '0', `unsupported member type ${JSON.stringify(type)}`);
    archiveAssertion(allZero(header.subarray(157, 257)), 'link name on regular member');
    const permissionBits = tarOctal(header.subarray(100, 108), 'member mode');
    archiveAssertion(
      permissionBits === 0o644 || permissionBits === 0o755,
      `unsupported member mode ${permissionBits.toString(8)}`
    );
    const byteLength = tarOctal(header.subarray(124, 136), 'member size');
    archiveAssertion(byteLength <= ARCHIVE_LIMITS.maxMemberBytes, 'member too large');
    const dataStart = offset + 512;
    const dataEnd = dataStart + byteLength;
    const next = dataStart + Math.ceil(byteLength / 512) * 512;
    archiveAssertion(dataEnd <= tar.length && next <= tar.length, 'truncated member');
    archiveAssertion(allZero(tar.subarray(dataEnd, next)), 'non-zero member padding');
    const relativePath = tarPath(header);
    archiveAssertion(!names.has(relativePath), `duplicate member ${relativePath}`);
    names.add(relativePath);
    records.push({
      path: relativePath,
      mode: permissionBits === 0o755 ? '100755' : '100644',
      bytes: Buffer.from(tar.subarray(dataStart, dataEnd)),
    });
    archiveAssertion(records.length <= remaining.members, 'member budget');
    offset = next;
  }
  throw new Error('H-047 independent archive: missing tar terminator');
}

function archiveClosure(members) {
  const material = members.map((member) => ({
    path: member.path,
    type: member.type,
    mode: member.mode,
    byteLength: member.byteLength,
    sha256: member.sha256,
    nestedArchiveClosureSha256: member.nestedArchiveRef?.closureSha256 ?? null,
  }));
  return independentSha256(Buffer.from(canonicalIndependentJson(material), 'utf8'));
}

export function expandIndependentArchiveForest(rootInputs, entryDigestByPath = new Map()) {
  assertion(Array.isArray(rootInputs) && rootInputs.length > 0, 'archive roots required');
  const roots = [...rootInputs].sort((left, right) => byteLex(left.path, right.path));
  assertion(
    new Set(roots.map(({ path: relativePath }) => relativePath)).size === roots.length,
    'duplicate archive root'
  );
  const counters = {
    archiveOccurrences: 0,
    memberOccurrences: 0,
    compressedBytes: 0,
    decompressedBytes: 0,
    payloadBytes: 0,
  };
  const memberBytesByKey = new Map();

  const visit = (archivePath, bytes, depth) => {
    archiveAssertion(depth <= ARCHIVE_LIMITS.maxDepth, 'depth budget');
    archiveAssertion(
      safePath(archivePath) &&
        (depth > 0 || !archivePath.includes('!')) &&
        /\.(?:tar\.gz|tgz)$/iu.test(archivePath) &&
        Buffer.byteLength(archivePath, 'utf8') <= ARCHIVE_LIMITS.maxVirtualRouteBytes,
      'archive route'
    );
    counters.archiveOccurrences += 1;
    counters.compressedBytes += bytes.length;
    archiveAssertion(counters.archiveOccurrences <= ARCHIVE_LIMITS.maxArchives, 'archive budget');
    archiveAssertion(
      counters.compressedBytes <= ARCHIVE_LIMITS.maxCompressedBytes,
      'compressed byte budget'
    );
    const parsed = parseStrictTarGzip(bytes, {
      decompressedBytes: ARCHIVE_LIMITS.maxDecompressedBytes - counters.decompressedBytes,
      members: ARCHIVE_LIMITS.maxMembers - counters.memberOccurrences,
    });
    counters.decompressedBytes += parsed.decompressedBytes;
    archiveAssertion(
      counters.decompressedBytes <= ARCHIVE_LIMITS.maxDecompressedBytes,
      'decompressed byte budget'
    );
    const members = [];
    const nestedArchives = [];
    let recursiveMemberCount = parsed.records.length;
    let recursivePayloadBytes = 0;
    for (const record of parsed.records.sort((left, right) => byteLex(left.path, right.path))) {
      counters.memberOccurrences += 1;
      counters.payloadBytes += record.bytes.length;
      archiveAssertion(
        counters.memberOccurrences <= ARCHIVE_LIMITS.maxMembers,
        'global member budget'
      );
      archiveAssertion(counters.payloadBytes <= ARCHIVE_LIMITS.maxPayloadBytes, 'payload budget');
      const virtualRoute = `${archivePath}!/${record.path}`;
      archiveAssertion(
        Buffer.byteLength(virtualRoute, 'utf8') <= ARCHIVE_LIMITS.maxVirtualRouteBytes,
        'virtual route budget'
      );
      const digest = independentSha256(record.bytes);
      const archiveByName = /\.(?:tar\.gz|tgz)$/iu.test(record.path);
      const archiveByMagic =
        record.bytes.length >= 2 && record.bytes[0] === 0x1f && record.bytes[1] === 0x8b;
      archiveAssertion(archiveByName === archiveByMagic, `archive signature ${record.path}`);
      let nestedArchiveRef = null;
      let signals;
      if (archiveByName) {
        const nested = visit(virtualRoute, record.bytes, depth + 1);
        const subjectDigest = entryDigestByPath.get(record.path);
        archiveAssertion(subjectDigest === digest, `nested subject binding ${record.path}`);
        nestedArchiveRef = {
          archiveSha256: nested.archiveSha256,
          closureSha256: nested.closureSha256,
          immediateMemberCount: nested.immediateMemberCount,
          recursiveMemberCount: nested.recursiveMemberCount,
          subjectPath: record.path,
        };
        nestedArchives.push({ memberPath: record.path, ...nestedArchiveRef });
        recursiveMemberCount += nested.recursiveMemberCount;
        recursivePayloadBytes += nested.recursivePayloadBytes;
        const roles = new Set(
          nested.members.flatMap((member) => member.signals.map(({ role }) => role))
        );
        signals = SIGNAL_ROLE_ORDER.filter(
          (role) => role !== 'accepted-governance' && roles.has(role)
        ).map((role) =>
          signalReceipt(role, 'archive-member', ['nested-archive-signal'], `sha256:${digest}`)
        );
      } else {
        recursivePayloadBytes += record.bytes.length;
        signals = deriveIndependentSignals({
          relativePath: record.path,
          bytes: record.bytes,
          digest,
          origin: 'archive-member',
        });
      }
      const member = {
        path: record.path,
        type: 'file',
        mode: record.mode,
        byteLength: record.bytes.length,
        sha256: digest,
        format: detectedFormat(record.path, record.bytes),
        signals,
        review: pendingReview(signals),
        nestedArchiveRef,
      };
      members.push(member);
      const key = `${archivePath}\0${record.path}`;
      archiveAssertion(!memberBytesByKey.has(key), `duplicate member route ${key}`);
      memberBytesByKey.set(key, record.bytes);
    }
    const totalUncompressedBytes = members.reduce((sum, member) => sum + member.byteLength, 0);
    const closureSha256 = archiveClosure(members);
    return {
      policyVersion: ARCHIVE_POLICY_VERSION,
      format: 'tar+gzip',
      state: 'closed',
      archiveSha256: independentSha256(bytes),
      immediateMemberCount: members.length,
      recursiveMemberCount,
      totalUncompressedBytes,
      recursivePayloadBytes,
      closureSha256,
      members,
      nestedArchives,
    };
  };

  const expandedRoots = roots.map(({ path: relativePath, bytes }) => {
    assertion(safePath(relativePath) && Buffer.isBuffer(bytes), 'archive root shape');
    return { path: relativePath, expansion: visit(relativePath, bytes, 0) };
  });
  return {
    roots: expandedRoots,
    memberBytesByKey,
    audit: {
      rootCount: expandedRoots.length,
      archiveOccurrences: counters.archiveOccurrences,
      memberOccurrences: counters.memberOccurrences,
      decompressedBytes: counters.decompressedBytes,
      payloadBytes: counters.payloadBytes,
      rootClosures: expandedRoots.map(({ path: relativePath, expansion }) => ({
        path: relativePath,
        closureSha256: expansion.closureSha256,
        immediateMemberCount: expansion.immediateMemberCount,
        recursiveMemberCount: expansion.recursiveMemberCount,
      })),
    },
  };
}

function lineRange(bytes, startLine, endLine, label) {
  assertion(
    Number.isSafeInteger(startLine) &&
      Number.isSafeInteger(endLine) &&
      startLine >= 1 &&
      endLine >= startLine,
    `${label} line range`
  );
  const text = decodeUtf8OrNull(bytes);
  assertion(text !== null, `${label} UTF-8`);
  const lines = text.split(/\r?\n/u);
  if (lines.at(-1) === '') lines.pop();
  assertion(endLine <= lines.length, `${label} line range bounds`);
  return lines.slice(startLine - 1, endLine).join('\n');
}

function yamlAtSegments(bytes, segments, label) {
  assertion(
    Array.isArray(segments) &&
      segments.length > 0 &&
      segments.every(
        (segment) =>
          (typeof segment === 'string' && segment.length > 0) ||
          (Number.isSafeInteger(segment) && segment >= 0)
      ),
    `${label} YAML segments`
  );
  const text = decodeUtf8OrNull(bytes);
  assertion(text !== null, `${label} YAML UTF-8`);
  const document = parseYamlDocument(text, {
    prettyErrors: false,
    strict: true,
    uniqueKeys: true,
  });
  assertion(document.errors.length === 0 && document.warnings.length === 0, `${label} YAML parse`);
  let current = document.toJS({ maxAliasCount: 0 });
  for (const segment of segments) {
    assertion(
      current !== null &&
        typeof current === 'object' &&
        Object.prototype.hasOwnProperty.call(current, segment),
      `${label} YAML segment missing`
    );
    current = current[segment];
  }
  return current;
}

function selectedDigest(value, encoding, rawBytes, label) {
  if (encoding === 'raw-bytes') {
    assertion(value === null && Buffer.isBuffer(rawBytes), `${label} raw selection`);
    return independentSha256(rawBytes);
  }
  if (encoding === 'utf8-string') {
    assertion(typeof value === 'string', `${label} string selection`);
    return independentSha256(Buffer.from(value, 'utf8'));
  }
  assertion(encoding === 'canonical-json', `${label} encoding`);
  assertion(value !== null && typeof value === 'object', `${label} JSON selection`);
  return independentSha256(Buffer.from(canonicalIndependentJson(value), 'utf8'));
}

function selectorStrings(value) {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap(selectorStrings);
  if (value !== null && typeof value === 'object') {
    return Object.values(value).flatMap(selectorStrings);
  }
  return [];
}

function validateCitation(citation, owner, bytes, archiveForest) {
  const common = [
    'id',
    'kind',
    'sourcePath',
    'sourceBlobSha256',
    'selectedType',
    'selectedEncoding',
    'selectedValueSha256',
    'selectedValue',
  ];
  const kindFields = {
    'json-pointer': ['pointer'],
    'yaml-path': ['segments'],
    'utf8-line-range': ['startLine', 'endLine', 'selector'],
    'docker-instruction': ['startLine', 'endLine', 'selector'],
    'javascript-node': ['startLine', 'endLine', 'selector'],
    'shell-command': ['startLine', 'endLine', 'selector'],
    'archive-member': ['memberPath', 'memberSha256', 'archiveClosureSha256'],
  };
  assertion(nonEmptyString(citation?.kind) && kindFields[citation.kind], 'citation kind');
  assertion(exactObjectKeys(citation, [...common, ...kindFields[citation.kind]]), 'citation keys');
  assertion(
    nonEmptyString(citation.id) &&
      citation.sourcePath === owner.path &&
      citation.sourceBlobSha256 === owner.blobSha256 &&
      SHA256_PATTERN.test(citation.selectedValueSha256),
    `citation identity: ${citation.id}`
  );
  let selected;
  let selectedRaw;
  if (citation.kind === 'json-pointer') {
    selected = jsonPointer(parseJsonBytes(bytes, owner.path), citation.pointer);
    assertion(selected !== undefined, `citation pointer: ${citation.id}`);
  } else if (citation.kind === 'yaml-path') {
    selected = yamlAtSegments(bytes, citation.segments, citation.id);
  } else if (
    ['utf8-line-range', 'docker-instruction', 'javascript-node', 'shell-command'].includes(
      citation.kind
    )
  ) {
    const selectorShapes = {
      'utf8-line-range': [['syntax']],
      'docker-instruction': [['selector'], ['targetPath'], ['opcode', 'ordinal']],
      'javascript-node': [
        ['commandTarget'],
        ['constant'],
        ['environmentKey'],
        ['module'],
        ['pathExpression'],
      ],
      'shell-command': [['executable']],
    };
    assertion(
      citation.selector !== null &&
        typeof citation.selector === 'object' &&
        !Array.isArray(citation.selector) &&
        selectorShapes[citation.kind].some((keys) => exactObjectKeys(citation.selector, keys)),
      `citation selector: ${citation.id}`
    );
    selected = lineRange(bytes, citation.startLine, citation.endLine, citation.id);
    if (citation.kind === 'utf8-line-range') {
      assertion(
        exactObjectKeys(citation.selector, ['syntax']) && nonEmptyString(citation.selector.syntax),
        `line syntax selector: ${citation.id}`
      );
    } else {
      assertion(
        selectorStrings(citation.selector).length > 0 &&
          selectorStrings(citation.selector).every((value) => selected.includes(value)),
        `typed selector content: ${citation.id}`
      );
    }
    if (citation.kind === 'docker-instruction' && citation.selector.opcode !== undefined) {
      assertion(
        exactObjectKeys(citation.selector, ['opcode', 'ordinal']) &&
          /^[A-Z]+$/u.test(citation.selector.opcode) &&
          Number.isSafeInteger(citation.selector.ordinal) &&
          citation.selector.ordinal >= 1 &&
          (selected.split('\n')[0] === citation.selector.opcode ||
            selected.split('\n')[0].startsWith(`${citation.selector.opcode} `)) &&
          decodeUtf8OrNull(bytes)
            .split(/\r?\n/u)
            .map((line, index) => ({ line, lineNumber: index + 1 }))
            .filter(({ line }) =>
              new RegExp(`^\\s*${citation.selector.opcode}(?:\\s|$)`, 'iu').test(line)
            )[citation.selector.ordinal - 1]?.lineNumber === citation.startLine,
        `Docker instruction selector: ${citation.id}`
      );
    }
  } else {
    assertion(
      safePath(citation.memberPath) &&
        SHA256_PATTERN.test(citation.memberSha256) &&
        SHA256_PATTERN.test(citation.archiveClosureSha256),
      `archive citation shape: ${citation.id}`
    );
    const root = archiveForest.roots.find(({ path: relativePath }) => relativePath === owner.path);
    assertion(
      root?.expansion.closureSha256 === citation.archiveClosureSha256,
      `archive citation closure: ${citation.id}`
    );
    selectedRaw = archiveForest.memberBytesByKey.get(`${owner.path}\0${citation.memberPath}`);
    assertion(
      Buffer.isBuffer(selectedRaw) && independentSha256(selectedRaw) === citation.memberSha256,
      `archive citation member: ${citation.id}`
    );
    selected = null;
  }
  assertion(
    canonicalIndependentJson(citation.selectedValue) === canonicalIndependentJson(selected),
    `citation selected value: ${citation.id}`
  );
  const actualType =
    selectedRaw !== undefined
      ? 'binary'
      : selected !== null && typeof selected === 'object'
        ? 'object'
        : typeof selected;
  assertion(citation.selectedType === actualType, `citation selected type: ${citation.id}`);
  assertion(
    selectedDigest(selected, citation.selectedEncoding, selectedRaw, citation.id) ===
      citation.selectedValueSha256,
    `citation selected digest: ${citation.id}`
  );
}

function exactExpectedAtoms() {
  return [
    {
      id: 'atom-spec0001-effective-authority',
      kind: 'effective-authority',
      subjectKey: 'SPEC-0001',
      assertion: {
        authorityId: 'SPEC-0001',
        recordPath: '.overlaykit/governance/specifications/SPEC-0001.json',
        effectiveStatus: 'accepted',
        scopeKey: 'linux-production-control',
      },
      citationIds: [
        'citation-plan-spec0001-id',
        'citation-plan-spec0001-effective-status',
        'citation-plan-spec0001-content-hash',
        'citation-spec0001-id',
        'citation-spec0001-title',
      ],
    },
    {
      id: 'atom-spec0001-host-role-definition',
      kind: 'host-role-definition',
      subjectKey: 'spec-0001-linux-production-host',
      assertion: {
        roleKey: 'spec-0001-linux-production-host',
        statement: 'OverlayKit and Companion are reachable from the Linux production host.',
      },
      citationIds: ['citation-spec0001-host-role'],
    },
  ];
}

function validateExactAtomBinding(atom, ownerPath, citationById, entryByPath) {
  const specificationPath = '.overlaykit/governance/specifications/SPEC-0001.json';
  const planPath = '.overlaykit/governance/plan.json';
  assertion(ownerPath === specificationPath, `atom owner binding: ${atom.id}`);

  const expectCitation = (id, sourcePath, pointer, selectedValue) => {
    const citation = citationById.get(id);
    assertion(
      citation?.kind === 'json-pointer' &&
        citation.sourcePath === sourcePath &&
        citation.pointer === pointer &&
        canonicalIndependentJson(citation.selectedValue) ===
          canonicalIndependentJson(selectedValue),
      `atom citation binding: ${atom.id}:${id}`
    );
  };

  if (atom.kind === 'effective-authority') {
    const specification = entryByPath.get(specificationPath);
    assertion(specification !== undefined, `atom authority target: ${atom.id}`);
    expectCitation('citation-plan-spec0001-id', planPath, '/specifications/0/id', 'SPEC-0001');
    expectCitation(
      'citation-plan-spec0001-effective-status',
      planPath,
      '/specifications/0/effectiveStatus',
      'accepted'
    );
    expectCitation(
      'citation-plan-spec0001-content-hash',
      planPath,
      '/specifications/0/contentHash',
      specification.sha256
    );
    expectCitation('citation-spec0001-id', specificationPath, '/id', 'SPEC-0001');
    expectCitation(
      'citation-spec0001-title',
      specificationPath,
      '/title',
      'Linux production control through Bitfocus Companion'
    );
    return;
  }

  assertion(atom.kind === 'host-role-definition', `atom binding kind: ${atom.id}`);
  expectCitation(
    'citation-spec0001-host-role',
    specificationPath,
    '/userStories/0/preconditions/2',
    atom.assertion.statement
  );
}

function validateTarget(target, entryByPath, label) {
  assertion(
    target !== null && typeof target === 'object' && !Array.isArray(target),
    `${label} target`
  );
  if (target.kind === 'path') {
    assertion(exactObjectKeys(target, ['kind', 'path', 'blobSha256']), `${label} path target keys`);
    const entry = entryByPath.get(target.path);
    assertion(
      safePath(target.path) && entry?.sha256 === target.blobSha256,
      `${label} path target binding`
    );
    return;
  }
  assertion(
    target.kind === 'path-set' &&
      exactObjectKeys(target, ['kind', 'members', 'closureSha256']) &&
      SHA256_PATTERN.test(target.closureSha256),
    `${label} path-set target`
  );
  assertion(
    Array.isArray(target.members) && target.members.length > 0,
    `${label} path-set members`
  );
  const paths = [];
  for (const member of target.members) {
    assertion(exactObjectKeys(member, ['path', 'blobSha256']), `${label} path-set member keys`);
    const entry = entryByPath.get(member.path);
    assertion(
      safePath(member.path) && entry?.sha256 === member.blobSha256,
      `${label} path-set member binding`
    );
    paths.push(member.path);
  }
  sortedUniqueStrings(paths, `${label} path-set members`);
  assertion(
    independentSha256(Buffer.from(canonicalIndependentJson(target.members), 'utf8')) ===
      target.closureSha256,
    `${label} path-set closure`
  );
}

function assertionData(value) {
  if (typeof value === 'string') return value.length > 0;
  if (typeof value === 'number') return Number.isSafeInteger(value) && value >= 0;
  if (typeof value === 'boolean') return true;
  if (Array.isArray(value)) return value.length > 0 && value.every(assertionData);
  return (
    value !== null &&
    typeof value === 'object' &&
    Object.keys(value).length > 0 &&
    Object.values(value).every(assertionData)
  );
}

function edgeEvidenceText(edge, citationById) {
  return edge.citationIds
    .map((id) => citationById.get(id).selectedValue)
    .map((value) => (typeof value === 'string' ? value : canonicalIndependentJson(value)))
    .join('\n');
}

function matchesIndependentSupportedGlob(relativePath, pattern) {
  const recursiveSuffix = '/**/*.test.mjs';
  if (pattern.endsWith(recursiveSuffix)) {
    const prefix = pattern.slice(0, -recursiveSuffix.length);
    return relativePath.startsWith(`${prefix}/`) && relativePath.endsWith('.test.mjs');
  }
  const directSuffix = '/*.test.mjs';
  if (pattern.endsWith(directSuffix) && !pattern.includes('**')) {
    const prefix = pattern.slice(0, -directSuffix.length);
    return (
      path.posix.dirname(relativePath) === prefix &&
      path.posix.basename(relativePath).endsWith('.test.mjs')
    );
  }
  return false;
}

function expectedIndependentDockerContextMembers(entryByPath, ignoreText) {
  const supportedPatterns = [
    '.git',
    '.github',
    'artifacts',
    'build',
    'coverage',
    'dist',
    'node_modules',
    'pkg',
    '*.log',
  ];
  assertion(
    canonicalIndependentJson(ignoreText.split('\n')) ===
      canonicalIndependentJson(supportedPatterns),
    'Docker context ignore policy'
  );
  const ignored = (relativePath) =>
    supportedPatterns.some((pattern) => {
      if (pattern === '*.log') return path.posix.basename(relativePath).endsWith('.log');
      return relativePath === pattern || relativePath.startsWith(`${pattern}/`);
    });
  return [...entryByPath.values()]
    .filter(({ path: relativePath }) => !ignored(relativePath))
    .map(({ path: relativePath, sha256: blobSha256 }) => ({
      path: relativePath,
      blobSha256,
    }))
    .sort((left, right) => byteLex(left.path, right.path));
}

function assertMaterializedEdgeBinding({
  edge,
  ownerPath,
  citations,
  entryByPath,
  contentsByPath,
}) {
  const targetPath = edge.target.kind === 'path' ? edge.target.path : null;
  const evidence = citations
    .map(({ selectedValue }) =>
      typeof selectedValue === 'string' ? selectedValue : canonicalIndependentJson(selectedValue)
    )
    .join('\n');
  const onlyCitation = citations.length === 1 ? citations[0] : null;

  if (edge.kind === 'archive-nesting' || edge.kind === 'js-import') return;

  if (edge.kind === 'plan-record' || edge.kind === 'manifest-record') return;

  if (edge.kind === 'compose-dockerfile') {
    assertion(
      onlyCitation?.kind === 'yaml-path' &&
        canonicalIndependentJson(onlyCitation.segments) ===
          canonicalIndependentJson(edge.assertion.composePath) &&
        onlyCitation.selectedValue === targetPath,
      `compose Dockerfile edge binding: ${edge.id}`
    );
    return;
  }

  if (edge.kind === 'compose-entrypoint') {
    const entrypointCitation = citations.find(
      ({ selectedValue }) => selectedValue === edge.assertion.containerPath
    );
    const mountCitation = citations.find(({ id }) => id !== entrypointCitation?.id);
    const containerDirectory = path.posix.dirname(edge.assertion.containerPath);
    assertion(
      citations.every(({ kind }) => kind === 'yaml-path') &&
        entrypointCitation !== undefined &&
        typeof mountCitation?.selectedValue === 'string' &&
        mountCitation.selectedValue.includes(
          `\${${edge.assertion.readOnlySourceEnvironmentKey}:?`
        ) &&
        mountCitation.selectedValue.endsWith(`:${containerDirectory}:ro`) &&
        targetPath ===
          path.posix.join(
            path.posix.dirname(ownerPath),
            path.posix.basename(edge.assertion.containerPath)
          ),
      `compose entrypoint edge binding: ${edge.id}`
    );
    return;
  }

  if (edge.kind === 'docker-build-context') {
    const dockerCitation = citations.find(
      ({ sourcePath, kind }) => sourcePath === ownerPath && kind === 'docker-instruction'
    );
    const ignoreCitation = citations.find(
      ({ sourcePath, kind }) => sourcePath === '.dockerignore' && kind === 'utf8-line-range'
    );
    assertion(
      dockerCitation?.selectedValue === 'COPY . .' &&
        typeof ignoreCitation?.selectedValue === 'string' &&
        edge.assertion.contextRoot === '.' &&
        edge.assertion.dockerignorePath === '.dockerignore' &&
        canonicalIndependentJson(edge.target.members) ===
          canonicalIndependentJson(
            expectedIndependentDockerContextMembers(entryByPath, ignoreCitation.selectedValue)
          ),
      `Docker build context edge binding: ${edge.id}`
    );
    return;
  }

  if (edge.kind === 'dockerfile-copy' || edge.kind === 'dockerfile-entrypoint') {
    const copySource =
      typeof onlyCitation?.selectedValue === 'string'
        ? /^COPY\s+(?:--[^\s]+\s+)*([^\s]+)\s+/u.exec(onlyCitation.selectedValue)?.[1]
        : undefined;
    assertion(
      onlyCitation?.kind === 'docker-instruction' &&
        copySource === targetPath &&
        (edge.kind !== 'dockerfile-entrypoint' ||
          onlyCitation.selectedValue.includes('ENTRYPOINT')) &&
        Object.values(edge.assertion).every((value) => onlyCitation.selectedValue.includes(value)),
      `Dockerfile materialized edge binding: ${edge.id}`
    );
    return;
  }

  if (edge.kind === 'dockerfile-package-script') {
    const scriptName = edge.assertion.selector.slice('npm run '.length);
    const packageJson = parseJsonBytes(contentsByPath.get(targetPath), targetPath);
    assertion(
      targetPath === 'package.json' &&
        onlyCitation?.kind === 'docker-instruction' &&
        /^npm run [a-z0-9:-]+$/u.test(edge.assertion.selector) &&
        onlyCitation.selectedValue.includes(edge.assertion.selector) &&
        nonEmptyString(packageJson.scripts?.[scriptName]),
      `Dockerfile package script edge binding: ${edge.id}`
    );
    return;
  }

  if (edge.kind === 'js-command') {
    const candidates = [
      path.posix.normalize(
        path.posix.join(path.posix.dirname(ownerPath), edge.assertion.relativePath)
      ),
      path.posix.normalize(edge.assertion.relativePath),
    ];
    assertion(
      onlyCitation?.kind === 'javascript-node' &&
        onlyCitation.selector.commandTarget === edge.assertion.relativePath &&
        candidates.includes(targetPath) &&
        onlyCitation.selectedValue.includes(edge.assertion.executable),
      `JavaScript command edge binding: ${edge.id}`
    );
    return;
  }

  if (edge.kind === 'js-environment-path-binding') {
    assertion(
      onlyCitation?.kind === 'javascript-node' &&
        onlyCitation.selector.environmentKey === edge.assertion.environmentKey &&
        onlyCitation.selectedValue.trim() ===
          `${edge.assertion.environmentKey}: ${edge.assertion.boundDirectory},` &&
        targetPath === path.posix.join(path.posix.dirname(ownerPath), 'companion-entrypoint.sh'),
      `JavaScript environment edge binding: ${edge.id}`
    );
    return;
  }

  if (edge.kind === 'js-path-binding') {
    const candidates = [
      path.posix.normalize(
        path.posix.join(path.posix.dirname(ownerPath), edge.assertion.relativePath)
      ),
      path.posix.normalize(edge.assertion.relativePath),
    ];
    const selectorValue = onlyCitation?.selector.constant ?? onlyCitation?.selector.pathExpression;
    assertion(
      onlyCitation?.kind === 'javascript-node' &&
        candidates.includes(targetPath) &&
        onlyCitation.selectedValue.includes(edge.assertion.relativePath) &&
        (selectorValue === edge.assertion.constant ||
          selectorValue === edge.assertion.relativePath),
      `JavaScript path edge binding: ${edge.id}`
    );
    return;
  }

  if (edge.kind === 'package-script-entrypoint') {
    const citedScriptNames = citations.map(({ pointer }) => pointer.replace(/^\/scripts\//u, ''));
    assertion(
      ownerPath.endsWith('/package.json') &&
        targetPath === path.posix.join(path.posix.dirname(ownerPath), edge.assertion.entrypoint) &&
        citations.every(
          ({ kind, pointer, selectedValue }) =>
            kind === 'json-pointer' &&
            /^\/scripts\/[^/]+$/u.test(pointer) &&
            typeof selectedValue === 'string' &&
            selectedValue.includes(edge.assertion.entrypoint)
        ) &&
        canonicalIndependentJson(citedScriptNames) ===
          canonicalIndependentJson(edge.assertion.scriptNames),
      `package entrypoint edge binding: ${edge.id}`
    );
    return;
  }

  if (edge.kind === 'package-script-glob-member') {
    assertion(
      ownerPath === 'package.json' &&
        onlyCitation?.kind === 'json-pointer' &&
        onlyCitation.pointer === `/scripts/${edge.assertion.scriptName}` &&
        typeof onlyCitation.selectedValue === 'string' &&
        onlyCitation.selectedValue.split(/\s+/u).includes(edge.assertion.expandedGlob) &&
        matchesIndependentSupportedGlob(targetPath, edge.assertion.expandedGlob),
      `package glob edge binding: ${edge.id}`
    );
    return;
  }

  if (edge.kind === 'package-script-runner') {
    assertion(
      ownerPath === 'package.json' &&
        onlyCitation?.kind === 'json-pointer' &&
        onlyCitation.pointer === `/scripts/${edge.assertion.scriptName}` &&
        typeof onlyCitation.selectedValue === 'string' &&
        onlyCitation.selectedValue.includes(`node ${targetPath}`),
      `package runner edge binding: ${edge.id}`
    );
    return;
  }

  if (edge.kind === 'package-workspace-script') {
    const scriptCitation = citations.find(
      ({ pointer }) => pointer === `/scripts/${edge.assertion.scriptName}`
    );
    const workspaceCitation = citations.find(({ pointer }) =>
      /^\/workspaces\/(?:0|[1-9][0-9]*)$/u.test(pointer)
    );
    const targetPackage = parseJsonBytes(contentsByPath.get(targetPath), targetPath);
    assertion(
      ownerPath === 'package.json' &&
        typeof scriptCitation?.selectedValue === 'string' &&
        scriptCitation.selectedValue.includes(`--workspace ${edge.assertion.workspaceName}`) &&
        typeof workspaceCitation?.selectedValue === 'string' &&
        targetPath === `${workspaceCitation.selectedValue}/package.json` &&
        targetPackage.name === edge.assertion.workspaceName,
      `package workspace edge binding: ${edge.id}`
    );
    return;
  }

  if (edge.kind === 'record-reference') {
    const targetId = path.posix.basename(targetPath, '.json');
    assertion(
      ['cited-as-not-declaring-persistent-obligation', 'mentioned-as-unchanged'].includes(
        edge.assertion.relation
      ) && evidence.includes(targetId),
      `record reference edge binding: ${edge.id}`
    );
    return;
  }

  if (edge.kind === 'shell-exec') {
    assertion(
      onlyCitation?.kind === 'shell-command' &&
        onlyCitation.selector.executable === edge.assertion.executable &&
        onlyCitation.selectedValue.includes(edge.assertion.executable) &&
        targetPath ===
          path.posix.join(
            path.posix.dirname(ownerPath),
            path.posix.basename(edge.assertion.executable)
          ),
      `shell executable edge binding: ${edge.id}`
    );
    return;
  }

  if (edge.kind === 'workflow-npm-script') {
    assertion(targetPath === 'package.json', `workflow npm edge binding: ${edge.id}`);
    const scriptNames = [...onlyCitation.selectedValue.matchAll(/\bnpm run ([a-z0-9:-]+)/gu)].map(
      (match) => match[1]
    );
    const assertedNames = edge.assertion.scriptNames ?? [edge.assertion.scriptName];
    const packageJson = parseJsonBytes(contentsByPath.get(targetPath), targetPath);
    assertion(
      onlyCitation?.kind === 'yaml-path' &&
        canonicalIndependentJson(scriptNames) === canonicalIndependentJson(assertedNames) &&
        assertedNames.every((scriptName) => nonEmptyString(packageJson.scripts?.[scriptName])),
      `workflow npm edge binding: ${edge.id}`
    );
    return;
  }

  assertion(false, `edge kind lacks an independent materializer: ${edge.kind}`);
}

export function classifyIndependentChains({
  pathReceipts,
  citationById,
  entryByPath,
  contentsByPath,
  conflicts = [],
}) {
  assertion(Array.isArray(pathReceipts) && Array.isArray(conflicts), 'review graph arrays');
  assertion(
    citationById instanceof Map && entryByPath instanceof Map && contentsByPath instanceof Map,
    'review graph indexes'
  );
  const edgeIds = new Set();
  const typedEdgeClosure = [];
  const atomIds = new Set();
  const atoms = [];
  const mechanicalBlockers = [];
  for (const receipt of pathReceipts) {
    const localEdgeIds = [];
    for (const edge of receipt.outgoingEdges) {
      const contract = EDGE_CONTRACTS[edge?.kind];
      assertion(
        exactObjectKeys(edge, [
          'id',
          'kind',
          'semanticRole',
          'resolution',
          'target',
          'citationIds',
          'assertion',
        ]) &&
          nonEmptyString(edge.id) &&
          contract !== undefined &&
          contract.roles.includes(edge.semanticRole) &&
          edge.resolution === 'resolved' &&
          contract.targets.includes(edge.target?.kind) &&
          contract.assertionKeys.some((keys) => exactObjectKeys(edge.assertion, keys)) &&
          contract.citationCounts.includes(edge.citationIds?.length) &&
          edge.assertion !== null &&
          typeof edge.assertion === 'object' &&
          !Array.isArray(edge.assertion) &&
          assertionData(edge.assertion),
        `edge shape: ${edge?.id ?? 'unknown'}`
      );
      assertion(!edgeIds.has(edge.id), `duplicate edge id: ${edge.id}`);
      edgeIds.add(edge.id);
      localEdgeIds.push(edge.id);
      uniqueStrings(edge.citationIds, `edge citations: ${edge.id}`);
      assertion(
        edge.citationIds.length > 0 && edge.citationIds.every((id) => citationById.has(id)),
        `edge citation resolution: ${edge.id}`
      );
      const citationSources = edge.citationIds.map((id) => citationById.get(id).sourcePath);
      if (edge.kind === 'docker-build-context') {
        assertion(
          sameSet(citationSources, [receipt.path, '.dockerignore']),
          `edge citation ownership: ${edge.id}`
        );
      } else {
        assertion(
          citationSources.every((sourcePath) => sourcePath === receipt.path),
          `edge citation ownership: ${edge.id}`
        );
      }
      validateTarget(edge.target, entryByPath, `edge ${edge.id}`);
      if (edge.semanticRole === 'authority-binding') {
        const targetId = edge.target.path
          .split('/')
          .at(-1)
          .replace(/\.json$/u, '');
        const evidence = edgeEvidenceText(edge, citationById);
        assertion(
          edge.kind === 'plan-record' &&
            receipt.path === '.overlaykit/governance/plan.json' &&
            /^\.overlaykit\/governance\/(?:decisions\/ADR|specifications\/SPEC)-[0-9]{4}\.json$/u.test(
              edge.target.path
            ) &&
            edge.assertion.recordId === targetId &&
            edge.assertion.effectiveStatus === 'accepted' &&
            edge.assertion.contentHash === edge.target.blobSha256 &&
            evidence.includes(targetId) &&
            evidence.includes(edge.target.blobSha256),
          `authority edge binding: ${edge.id}`
        );
      }
      if (edge.kind === 'manifest-record') {
        const targetId = edge.target.path
          .split('/')
          .at(-1)
          .replace(/\.json$/u, '');
        const evidence = edgeEvidenceText(edge, citationById);
        assertion(
          receipt.path === '.overlaykit/governance/manifest.json' &&
            edge.assertion.recordId === targetId &&
            edge.assertion.contentHash === edge.target.blobSha256 &&
            evidence.includes(edge.target.blobSha256),
          `manifest edge binding: ${edge.id}`
        );
      }
      if (edge.kind === 'js-import') {
        const moduleName = edge.assertion.module;
        const citation = citationById.get(edge.citationIds[0]);
        assertion(
          citation.kind === 'javascript-node' &&
            citation.selector.module === moduleName &&
            moduleName.startsWith('.') &&
            path.posix.normalize(path.posix.join(path.posix.dirname(receipt.path), moduleName)) ===
              edge.target.path,
          `JavaScript import edge binding: ${edge.id}`
        );
      }
      if (edge.kind === 'archive-nesting') {
        const citation =
          edge.citationIds.length === 1 ? citationById.get(edge.citationIds[0]) : undefined;
        const member = receipt.indirections.archiveExpansion?.members.find(
          ({ path: memberPath }) => memberPath === edge.target.path
        );
        assertion(
          edge.semanticRole === 'containment' &&
            edge.target.kind === 'path' &&
            exactObjectKeys(edge.assertion, ['memberPath', 'nestedClosureSha256']) &&
            citation?.kind === 'archive-member' &&
            edge.assertion.memberPath === edge.target.path &&
            edge.assertion.memberPath === citation.memberPath &&
            citation.memberSha256 === edge.target.blobSha256 &&
            member?.nestedArchiveRef !== null &&
            member?.nestedArchiveRef?.archiveSha256 === edge.target.blobSha256 &&
            member?.nestedArchiveRef?.closureSha256 === edge.assertion.nestedClosureSha256,
          `archive nesting edge binding: ${edge.id}`
        );
      }
      assertMaterializedEdgeBinding({
        edge,
        ownerPath: receipt.path,
        citations: edge.citationIds.map((id) => citationById.get(id)),
        entryByPath,
        contentsByPath,
      });
      typedEdgeClosure.push({ ownerPath: receipt.path, edge });
    }
    assertion(
      canonicalIndependentJson(receipt.indirections.edgeIds) ===
        canonicalIndependentJson(localEdgeIds),
      `indirection edge closure: ${receipt.path}`
    );
    for (const atom of receipt.atoms) {
      assertion(
        exactObjectKeys(atom, ['id', 'kind', 'subjectKey', 'assertion', 'citationIds']) &&
          nonEmptyString(atom.id) &&
          ['effective-authority', 'host-role-definition'].includes(atom.kind) &&
          nonEmptyString(atom.subjectKey) &&
          atom.assertion !== null &&
          typeof atom.assertion === 'object' &&
          !Array.isArray(atom.assertion),
        `atom shape: ${atom?.id ?? 'unknown'}`
      );
      assertion(!atomIds.has(atom.id), `duplicate atom id: ${atom.id}`);
      atomIds.add(atom.id);
      uniqueStrings(atom.citationIds, `atom citations: ${atom.id}`);
      assertion(
        atom.citationIds.length > 0 && atom.citationIds.every((id) => citationById.has(id)),
        `atom citation resolution: ${atom.id}`
      );
      validateExactAtomBinding(atom, receipt.path, citationById, entryByPath);
      atoms.push(atom);
    }
    if (receipt.indirections.state === 'unresolved') {
      mechanicalBlockers.push({ code: 'unresolved-indirection', path: receipt.path });
    }
  }
  assertion(
    typedEdgeClosure.length === EXPECTED_TYPED_EDGE_COUNT &&
      independentSha256(canonicalIndependentJson(typedEdgeClosure)) ===
        EXPECTED_TYPED_EDGE_CLOSURE_SHA256,
    'typed edge exact closure'
  );
  assertion(
    canonicalIndependentJson(atoms) === canonicalIndependentJson(exactExpectedAtoms()),
    'typed semantic atom closure'
  );
  for (const conflict of conflicts) mechanicalBlockers.push({ code: 'review-conflict', conflict });
  mechanicalBlockers.sort((left, right) =>
    byteLex(canonicalIndependentJson(left), canonicalIndependentJson(right))
  );
  return { components: [], eligibleChains: [], mechanicalBlockers };
}

export function deriveIndependentOutcome({ coverageComplete, unknowns, eligibleChains }) {
  assertion(Array.isArray(unknowns) && Array.isArray(eligibleChains), 'outcome arrays required');
  if (coverageComplete !== true || unknowns.length > 0) {
    return {
      status: 'inconclusive',
      stage: 'source-admission',
      reasonCode: 'incomplete-ambiguous-or-unknown-coverage',
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
    stage: 'complete-repository-inventory',
    reasonCode: 'complete-zero-eligible-chain-coverage',
  };
}

function manifestSectionFor(type) {
  if (type === 'decision') return 'decisions';
  if (type === 'specification') return 'specifications';
  return 'changes';
}

function validateGovernanceClosure({
  plan,
  manifest,
  governanceRecords,
  decisions,
  specifications,
  changes,
}) {
  assertion(plan.planHash === H047_INDEPENDENT_SUBJECT.planHash, 'compiled plan hash mismatch');
  assertion(
    manifest.contentHash === H047_INDEPENDENT_SUBJECT.manifestContentHash,
    'manifest content hash mismatch'
  );
  assertion(manifest.planHash === plan.planHash, 'manifest-to-plan hash mismatch');
  assertion(
    Array.isArray(plan.decisions) && Array.isArray(plan.specifications),
    'compiled plan shape'
  );
  for (const [records, section] of [
    [decisions, 'decisions'],
    [specifications, 'specifications'],
    [changes, 'changes'],
  ]) {
    assertion(
      sameSet(
        records.map(({ id }) => id),
        Object.keys(manifest[section] ?? {})
      ),
      `manifest ${section} closure`
    );
  }
  for (const record of governanceRecords) {
    const section = manifestSectionFor(record.type);
    assertion(
      manifest[section]?.[record.id] === record.contentSha256,
      `manifest record hash mismatch: ${record.id}`
    );
    if (record.type === 'change') continue;
    const compiled = (record.type === 'decision' ? plan.decisions : plan.specifications).find(
      ({ id }) => id === record.id
    );
    assertion(compiled !== undefined, `compiled record missing: ${record.id}`);
    assertion(compiled.contentHash === record.contentSha256, `compiled content hash: ${record.id}`);
    assertion(compiled.declaredStatus === record.status, `compiled declared status: ${record.id}`);
    assertion(
      ['accepted', 'superseded'].includes(compiled.effectiveStatus),
      `compiled effective status: ${record.id}`
    );
  }
}

export function reconstructIndependentInventory({ snapshot, reviewMap }) {
  assertion(
    independentSha256(snapshot.treeBytes) === H047_INDEPENDENT_SUBJECT.lsTreeSha256,
    'subject ls-tree digest'
  );
  assertion(snapshot.entries.length === H047_INDEPENDENT_SUBJECT.entryCount, 'subject entry count');
  const unknowns = [];
  const contentsByPath = new Map();
  const entries = snapshot.entries.map((entry) => {
    const bytes = snapshot.blobs.get(entry.oid);
    assertion(Buffer.isBuffer(bytes), `subject blob unavailable: ${entry.path}`);
    contentsByPath.set(entry.path, bytes);
    return {
      ...entry,
      available: true,
      byteLength: bytes.length,
      sha256: independentSha256(bytes),
    };
  });
  const entryByPath = new Map(entries.map((entry) => [entry.path, entry]));
  const plan = parseJsonBytes(
    entryBytes(snapshot, '.overlaykit/governance/plan.json').bytes,
    'subject plan'
  );
  const manifest = parseJsonBytes(
    entryBytes(snapshot, '.overlaykit/governance/manifest.json').bytes,
    'subject manifest'
  );

  const governanceRecords = [];
  for (const entry of entries) {
    const type = governanceKind(entry.path);
    if (type === null) continue;
    const value = parseJsonBytes(contentsByPath.get(entry.path), entry.path);
    const expectedId = entry.path
      .split('/')
      .at(-1)
      .replace(/\.json$/u, '');
    assertion(
      value !== null &&
        typeof value === 'object' &&
        value.id === expectedId &&
        typeof value.status === 'string',
      `malformed governance record: ${entry.path}`
    );
    governanceRecords.push({
      path: entry.path,
      type,
      id: value.id,
      status: value.status,
      contentSha256: entry.sha256,
    });
  }
  governanceRecords.sort((left, right) =>
    Buffer.compare(Buffer.from(left.path), Buffer.from(right.path))
  );
  const decisions = governanceRecords.filter(({ type }) => type === 'decision');
  const specifications = governanceRecords.filter(({ type }) => type === 'specification');
  const changes = governanceRecords.filter(({ type }) => type === 'change');
  validateGovernanceClosure({
    plan,
    manifest,
    governanceRecords,
    decisions,
    specifications,
    changes,
  });

  assertion(
    sameSet(
      decisions.filter(({ status }) => status === 'accepted').map(({ id }) => id),
      ACCEPTED_DECISIONS
    ),
    'accepted decision set'
  );
  assertion(
    sameSet(
      specifications.filter(({ status }) => status === 'accepted').map(({ id }) => id),
      ACCEPTED_SPECIFICATIONS
    ),
    'accepted specification set'
  );
  assertion(
    sameSet(
      changes.filter(({ status }) => status === 'implemented').map(({ id }) => id),
      IMPLEMENTED_CHANGES
    ),
    'implemented change set'
  );
  assertion(changes.filter(({ status }) => status === 'proposed').length === 12, 'proposed count');

  const bindingByPath = new Map();
  const acceptedAuthorityPaths = new Set();
  for (const record of governanceRecords) {
    if (record.type === 'decision' || record.type === 'specification') {
      const compiled = (record.type === 'decision' ? plan.decisions : plan.specifications).find(
        ({ id }) => id === record.id
      );
      const binding = {
        source: 'compiled-plan',
        declaredStatus: compiled.declaredStatus,
        effectiveStatus: compiled.effectiveStatus,
        contentHash: compiled.contentHash,
      };
      bindingByPath.set(record.path, binding);
      if (compiled.effectiveStatus === 'accepted') acceptedAuthorityPaths.add(record.path);
    } else {
      bindingByPath.set(record.path, {
        source: 'manifest-and-record-status',
        declaredStatus: record.status,
        effectiveStatus: null,
        contentHash: manifest.changes[record.id],
      });
    }
  }
  assertion(
    sameSet(
      decisions.filter((record) => acceptedAuthorityPaths.has(record.path)).map(({ id }) => id),
      ACCEPTED_DECISIONS
    ),
    'effective accepted decision set'
  );
  assertion(
    sameSet(
      specifications
        .filter((record) => acceptedAuthorityPaths.has(record.path))
        .map(({ id }) => id),
      ACCEPTED_SPECIFICATIONS
    ),
    'effective accepted specification set'
  );
  const roleStatusMap = Object.fromEntries(
    governanceRecords.map((record) => [
      record.path,
      {
        status:
          record.type === 'decision' || record.type === 'specification'
            ? bindingByPath.get(record.path).effectiveStatus
            : record.status,
      },
    ])
  );

  const reference = Buffer.from(IMAGE_REFERENCE);
  const imageId = Buffer.from(IMAGE_ID);
  const targetOccurrences = [];
  for (const entry of entries) {
    const bytes = contentsByPath.get(entry.path);
    const referenceCount = countOccurrences(bytes, reference);
    const imageIdCount = countOccurrences(bytes, imageId);
    if (referenceCount === 0 && imageIdCount === 0) continue;
    targetOccurrences.push({
      path: entry.path,
      referenceCount,
      imageIdCount,
      role: candidateRole(entry.path, roleStatusMap),
    });
  }
  assertion(
    sameSet(
      targetOccurrences.map(({ path: relativePath }) => relativePath),
      IDENTITY_PATHS
    ),
    'identity path set'
  );
  const targetOccurrencePathCounts = {
    referencePaths: targetOccurrences.filter(({ referenceCount }) => referenceCount > 0).length,
    imageIdPaths: targetOccurrences.filter(({ imageIdCount }) => imageIdCount > 0).length,
    bothPaths: targetOccurrences.filter(
      ({ referenceCount, imageIdCount }) => referenceCount > 0 && imageIdCount > 0
    ).length,
    unionPaths: targetOccurrences.length,
  };
  assertion(
    canonicalIndependentJson(targetOccurrencePathCounts) ===
      canonicalIndependentJson({
        referencePaths: 22,
        imageIdPaths: 25,
        bothPaths: 21,
        unionPaths: 26,
      }),
    'identity path counts'
  );

  const deploymentSurfaces = [];
  for (const entry of entries) {
    const classification = classifyDeploymentPath(entry.path);
    if (!classification.deploymentShaped) continue;
    assertion(classification.recognized, `unknown deployment surface: ${entry.path}`);
    deploymentSurfaces.push({ path: entry.path, ...classification });
  }
  assertion(
    sameSet(
      deploymentSurfaces.map(({ path: relativePath }) => relativePath),
      SURFACES.map(({ path: relativePath }) => relativePath)
    ),
    'deployment surface set'
  );

  assertion(
    exactObjectKeys(reviewMap, [
      'schemaVersion',
      'hypothesis',
      'subject',
      'signalPolicyVersion',
      'signalPolicy',
      'humanAcceptanceRef',
      'reviewStatus',
      'directCandidates',
      'paths',
      'conflicts',
      'pendingHumanJudgments',
    ]),
    'review map keys'
  );
  assertion(reviewMap.schemaVersion === SEMANTIC_REVIEW_SCHEMA, 'review map schema');
  assertion(reviewMap.hypothesis === 'H-047', 'review map hypothesis');
  assertion(
    canonicalIndependentJson(reviewMap.subject) ===
      canonicalIndependentJson({
        commit: H047_INDEPENDENT_SUBJECT.commit,
        tree: H047_INDEPENDENT_SUBJECT.tree,
        entryCount: H047_INDEPENDENT_SUBJECT.entryCount,
        lsTreeSha256: H047_INDEPENDENT_SUBJECT.lsTreeSha256,
        planHash: H047_INDEPENDENT_SUBJECT.planHash,
      }),
    'review map subject'
  );
  assertion(reviewMap.signalPolicyVersion === SIGNAL_POLICY_VERSION, 'signal policy version');
  assertion(
    canonicalIndependentJson(reviewMap.signalPolicy) ===
      canonicalIndependentJson(expectedSignalPolicy()),
    'signal policy'
  );
  assertion(
    reviewMap.reviewStatus === 'agent-proposed-pending-human-acceptance',
    'review map status'
  );
  assertion(
    reviewMap.humanAcceptanceRef === null,
    'unreviewed H-047 source cannot declare human acceptance'
  );
  assertion(
    Array.isArray(reviewMap.paths) &&
      Array.isArray(reviewMap.directCandidates) &&
      Array.isArray(reviewMap.conflicts) &&
      Array.isArray(reviewMap.pendingHumanJudgments) &&
      reviewMap.pendingHumanJudgments.every(nonEmptyString),
    'review map arrays'
  );
  assertion(
    new Set(reviewMap.pendingHumanJudgments).size === reviewMap.pendingHumanJudgments.length,
    'pending human judgment uniqueness'
  );

  const receiptPaths = reviewMap.paths.map(({ path: relativePath }) => relativePath);
  const subjectPaths = entries.map(({ path: relativePath }) => relativePath);
  sortedUniqueStrings(receiptPaths, 'review receipt paths');
  assertion(
    canonicalIndependentJson(receiptPaths) === canonicalIndependentJson(subjectPaths),
    'review receipt exact subject closure'
  );

  const archiveInputs = entries
    .filter(({ path: relativePath }) => /\.(?:tar\.gz|tgz)$/iu.test(relativePath))
    .map(({ path: relativePath }) => ({
      path: relativePath,
      bytes: contentsByPath.get(relativePath),
    }));
  assertion(archiveInputs.length === 3, 'exact archive root count');
  const archiveForest = expandIndependentArchiveForest(
    archiveInputs,
    new Map(entries.map((entry) => [entry.path, entry.sha256]))
  );
  const archiveRootByPath = new Map(
    archiveForest.roots.map(({ path: relativePath, expansion }) => [relativePath, expansion])
  );

  const pathReceipts = reviewMap.paths.map((receipt) => {
    assertion(
      exactObjectKeys(receipt, [
        'path',
        'mode',
        'gitOid',
        'byteLength',
        'blobSha256',
        'format',
        'signals',
        'review',
        'citations',
        'atoms',
        'outgoingEdges',
        'indirections',
      ]),
      `path receipt keys: ${receipt?.path ?? 'unknown'}`
    );
    const entry = entryByPath.get(receipt.path);
    const bytes = contentsByPath.get(receipt.path);
    assertion(
      entry !== undefined &&
        Buffer.isBuffer(bytes) &&
        receipt.mode === entry.mode &&
        receipt.gitOid === entry.oid &&
        receipt.byteLength === entry.byteLength &&
        receipt.blobSha256 === entry.sha256 &&
        receipt.format === detectedFormat(receipt.path, bytes),
      `path receipt content binding: ${receipt.path}`
    );
    const expansion = archiveRootByPath.get(receipt.path);
    const expectedSignals =
      expansion === undefined
        ? deriveIndependentSignals({
            relativePath: receipt.path,
            bytes,
            digest: entry.sha256,
            acceptedGovernance: acceptedAuthorityPaths.has(receipt.path),
            planAuthorityIndex: receipt.path === '.overlaykit/governance/plan.json',
            recognizedDeployment: SURFACE_BY_PATH.has(receipt.path),
          })
        : aggregateArchiveSignals(expansion);
    assertion(
      canonicalIndependentJson(receipt.signals) === canonicalIndependentJson(expectedSignals),
      `path signal reconstruction: ${receipt.path}`
    );
    assertion(
      canonicalIndependentJson(receipt.review) ===
        canonicalIndependentJson(pendingReview(expectedSignals)),
      `path review derivation: ${receipt.path}`
    );
    assertion(
      Array.isArray(receipt.citations) &&
        Array.isArray(receipt.atoms) &&
        Array.isArray(receipt.outgoingEdges),
      `path semantic arrays: ${receipt.path}`
    );
    assertion(
      exactObjectKeys(receipt.indirections, ['state', 'edgeIds', 'archiveExpansion']) &&
        ['none', 'closed', 'unresolved'].includes(receipt.indirections.state) &&
        Array.isArray(receipt.indirections.edgeIds),
      `path indirection shape: ${receipt.path}`
    );
    if (expansion !== undefined) {
      assertion(
        canonicalIndependentJson(receipt.indirections.archiveExpansion) ===
          canonicalIndependentJson(expansion),
        `archive expansion reconstruction: ${receipt.path}`
      );
    } else {
      assertion(
        receipt.indirections.archiveExpansion === null,
        `unexpected archive expansion: ${receipt.path}`
      );
    }
    const shouldClose =
      expansion !== undefined ||
      receipt.outgoingEdges.length > 0 ||
      receipt.indirections.edgeIds.length > 0;
    assertion(
      receipt.indirections.state === (shouldClose ? 'closed' : 'none') ||
        receipt.indirections.state === 'unresolved',
      `indirection state derivation: ${receipt.path}`
    );
    return receipt;
  });

  const citationById = new Map();
  for (const receipt of pathReceipts) {
    const bytes = contentsByPath.get(receipt.path);
    for (const citation of receipt.citations) {
      assertion(!citationById.has(citation?.id), `duplicate citation id: ${citation?.id}`);
      validateCitation(citation, receipt, bytes, archiveForest);
      citationById.set(citation.id, citation);
    }
  }

  const expectedDirectCandidates = pathReceipts
    .filter(({ signals }) => signals.length > 0)
    .map(({ path: relativePath, signals }) => ({
      path: relativePath,
      roles: signals.map(({ role }) => role),
    }));
  assertion(
    canonicalIndependentJson(reviewMap.directCandidates) ===
      canonicalIndependentJson(expectedDirectCandidates),
    'direct candidate reconstruction'
  );
  const chainReview = classifyIndependentChains({
    pathReceipts,
    citationById,
    entryByPath,
    contentsByPath,
    conflicts: reviewMap.conflicts,
  });

  const candidateReceiptByPath = new Map(pathReceipts.map((receipt) => [receipt.path, receipt]));
  const acceptedRecordReview = governanceRecords
    .filter((record) =>
      record.type === 'decision' || record.type === 'specification'
        ? bindingByPath.get(record.path).effectiveStatus === 'accepted'
        : record.status === 'implemented'
    )
    .map((record) => {
      const receipt = candidateReceiptByPath.get(record.path);
      return {
        ...record,
        role: candidateRole(record.path, roleStatusMap),
        authorityBinding: bindingByPath.get(record.path),
        reviewDisposition: receipt.review.agentDisposition,
        rationaleCode: receipt.review.rationaleCode,
      };
    });

  const mechanicalCoverageComplete =
    pathReceipts.length === H047_INDEPENDENT_SUBJECT.entryCount &&
    chainReview.mechanicalBlockers.length === 0;
  unknowns.push({
    code: 'human-review-not-accepted',
    reviewStatus: reviewMap.reviewStatus,
    humanAcceptanceRef: null,
  });
  for (const judgment of reviewMap.pendingHumanJudgments) {
    unknowns.push({ code: 'pending-human-judgment', judgment });
  }
  unknowns.push(...chainReview.mechanicalBlockers);
  const coverageComplete =
    mechanicalCoverageComplete &&
    reviewMap.humanAcceptanceRef !== null &&
    reviewMap.pendingHumanJudgments.length === 0 &&
    unknowns.length === 0;
  const eligibleChains = chainReview.eligibleChains;
  const candidates = expectedDirectCandidates.map(({ path: relativePath, roles }) => {
    const receipt = candidateReceiptByPath.get(relativePath);
    return {
      path: relativePath,
      roles,
      agentDisposition: receipt.review.agentDisposition,
      humanDisposition: receipt.review.humanDisposition,
      citationIds: receipt.citations.map(({ id }) => id),
      atomIds: receipt.atoms.map(({ id }) => id),
      outgoingEdgeIds: receipt.outgoingEdges.map(({ id }) => id),
      indirectionState: receipt.indirections.state,
    };
  });
  return {
    sourceMap: {
      subject: {
        commit: H047_INDEPENDENT_SUBJECT.commit,
        tree: H047_INDEPENDENT_SUBJECT.tree,
        entryCount: H047_INDEPENDENT_SUBJECT.entryCount,
        lsTreeSha256: H047_INDEPENDENT_SUBJECT.lsTreeSha256,
        planHash: H047_INDEPENDENT_SUBJECT.planHash,
      },
      entryCount: entries.length,
      entries,
      sourceSetSha256: sourceSetSha256(entries),
    },
    candidateIndex: {
      schemaVersion: 'overlaykit-h047-candidate-index/v1',
      hypothesis: 'H-047',
      governance: {
        counts: {
          decisions: statusCounts(decisions),
          specifications: statusCounts(specifications),
          changes: statusCounts(changes),
        },
        records: governanceRecords,
      },
      acceptedRecordReview,
      targetOccurrences,
      targetOccurrencePathCounts,
      deploymentSurfaces,
      semanticReview: {
        schemaVersion: reviewMap.schemaVersion,
        signalPolicyVersion: reviewMap.signalPolicyVersion,
        reviewStatus: reviewMap.reviewStatus,
        reviewMapSha256: independentSha256(canonicalIndependentJson(reviewMap)),
        humanAcceptanceRef: reviewMap.humanAcceptanceRef,
        pendingHumanJudgments: reviewMap.pendingHumanJudgments,
        pathCount: pathReceipts.length,
        directCandidateCount: expectedDirectCandidates.length,
        archiveForest: archiveForest.audit,
        coverageComplete: mechanicalCoverageComplete,
      },
      candidates,
      chainComponents: chainReview.components,
      unknowns,
      eligibleChains,
      coverageComplete,
      outcome: deriveIndependentOutcome({ coverageComplete, unknowns, eligibleChains }),
      adrAssessment: H047_INDEPENDENT_ADR_ASSESSMENT,
    },
  };
}

function parseNulPaths(bytes) {
  if (bytes.length === 0) return [];
  assertion(bytes.at(-1) === 0, 'delta paths are not NUL terminated');
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const result = [];
  let start = 0;
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] !== 0) continue;
    assertion(index > start, 'empty delta path');
    const relativePath = decoder.decode(bytes.subarray(start, index));
    assertion(safePath(relativePath), `unsafe delta path: ${relativePath}`);
    result.push(relativePath);
    start = index + 1;
  }
  assertion(new Set(result).size === result.length, 'duplicate delta path');
  return result;
}

function commitHeaders(bytes) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const separator = text.indexOf('\n\n');
  assertion(separator > 0, 'commit object has no header terminator');
  return text.slice(0, separator).split('\n');
}

export function verifyIndependentSourceAnchor(anchorCommit, declaredAnchor = undefined) {
  assertion(GIT_OID_PATTERN.test(anchorCommit), 'bad source anchor commit');
  const headers = commitHeaders(git(['cat-file', 'commit', anchorCommit]));
  const parents = headers
    .filter((line) => line.startsWith('parent '))
    .map((line) => line.slice('parent '.length));
  assertion(
    parents.length === 1 && parents[0] === H047_INDEPENDENT_SUBJECT.commit,
    'source anchor must have exactly the subject as its only parent'
  );
  assertion(
    headers.some((line) => line.startsWith('gpgsig ')),
    'source anchor is unsigned'
  );
  git(['verify-commit', anchorCommit]);
  const tree = oneLine(git(['rev-parse', `${anchorCommit}^{tree}`]), 'anchor tree');
  const declaredTree = headers.find((line) => line.startsWith('tree '))?.slice('tree '.length);
  assertion(declaredTree === tree, 'anchor commit tree header mismatch');
  const deltaPaths = parseNulPaths(
    git([
      'diff-tree',
      '--no-commit-id',
      '--name-only',
      '-r',
      '-z',
      H047_INDEPENDENT_SUBJECT.commit,
      anchorCommit,
    ])
  ).sort();
  assertion(
    canonicalIndependentJson(deltaPaths) ===
      canonicalIndependentJson(H047_INDEPENDENT_SOURCE_PATHS),
    'anchor delta mismatch'
  );
  const snapshot = treeSnapshot(anchorCommit);
  const sources = H047_INDEPENDENT_SOURCE_PATHS.map((relativePath) => {
    const { entry, bytes } = entryBytes(snapshot, relativePath);
    return {
      path: relativePath,
      mode: entry.mode,
      oid: entry.oid,
      byteLength: bytes.length,
      sha256: independentSha256(bytes),
    };
  });
  const digest = sourceSetSha256(sources);
  if (declaredAnchor !== undefined) {
    assertion(declaredAnchor.commit === anchorCommit, 'run anchor commit mismatch');
    assertion(declaredAnchor.parent === parents[0], 'run anchor parent mismatch');
    assertion(declaredAnchor.parentCount === 1, 'run anchor parent count mismatch');
    assertion(declaredAnchor.tree === tree, 'run anchor tree mismatch');
    assertion(declaredAnchor.signatureVerified === true, 'run anchor signature receipt mismatch');
    assertion(
      canonicalIndependentJson(declaredAnchor.deltaPaths) === canonicalIndependentJson(deltaPaths),
      'run anchor delta mismatch'
    );
    assertion(
      canonicalIndependentJson(declaredAnchor.sources) === canonicalIndependentJson(sources),
      'run anchor sources mismatch'
    );
    assertion(declaredAnchor.sourceSetSha256 === digest, 'run anchor source-set digest mismatch');
  }

  const verifierSource = sources.find(
    ({ path: relativePath }) => relativePath === 'lab/h047/verify.mjs'
  );
  const schemaSource = sources.find(
    ({ path: relativePath }) =>
      relativePath === 'lab/h047/schemas/repository-desired-state-run.schema.json'
  );
  assertion(
    independentSha256(readFileSync(VERIFIER_PATH)) === verifierSource.sha256,
    'executed verifier drift'
  );
  const schemaPath = path.join(
    LAB_DIRECTORY,
    'schemas',
    'repository-desired-state-run.schema.json'
  );
  assertion(
    independentSha256(readFileSync(schemaPath)) === schemaSource.sha256,
    'executed schema drift'
  );
  const reviewMap = parseJsonBytes(
    entryBytes(snapshot, 'lab/h047/review-map.json').bytes,
    'anchored review map'
  );
  return {
    snapshot,
    sources,
    digest,
    schemaPath,
    reviewMap,
    parent: parents[0],
    parentCount: parents.length,
    tree,
    deltaPaths,
    signatureVerified: true,
  };
}

function readArtifact(runDirectory, name) {
  const filePath = path.join(runDirectory, name);
  const metadata = lstatSync(filePath);
  assertion(metadata.isFile() && !metadata.isSymbolicLink(), `${name} is not a regular file`);
  assertion(realpathSync(filePath) === filePath, `${name} escaped through a symlink`);
  const bytes = readFileSync(filePath);
  const value = parseJsonBytes(bytes, name);
  assertion(
    bytes.equals(Buffer.from(`${canonicalIndependentJson(value)}\n`, 'utf8')),
    `${name} is not canonical JSON`
  );
  return { bytes, value };
}

function artifactIdentity(artifact, expectedFile, bytes) {
  assertion(artifact.file === expectedFile, `${expectedFile} name mismatch`);
  assertion(artifact.byteLength === bytes.length, `${expectedFile} length mismatch`);
  assertion(artifact.sha256 === independentSha256(bytes), `${expectedFile} digest mismatch`);
}

function expectedProducerInvocationCounts(subjectSnapshot, anchorSnapshot) {
  return {
    'cat-file-blob':
      new Set(subjectSnapshot.entries.map(({ oid }) => oid)).size +
      new Set(anchorSnapshot.entries.map(({ oid }) => oid)).size,
    'cat-file-commit': 1,
    'diff-tree': 1,
    'ls-tree': 2,
    'rev-parse': 4,
    status: 1,
    'verify-commit': 1,
  };
}

function expectedSummary(candidateIndex) {
  return {
    acceptedDecisions: candidateIndex.governance.counts.decisions.accepted,
    acceptedSpecifications: candidateIndex.governance.counts.specifications.accepted,
    implementedChanges: candidateIndex.governance.counts.changes.implemented,
    proposedChanges: candidateIndex.governance.counts.changes.proposed,
    identityPaths: candidateIndex.targetOccurrences.length,
    deploymentSurfaces: candidateIndex.deploymentSurfaces.length,
    candidates: candidateIndex.candidates.length,
    unknowns: candidateIndex.unknowns.length,
    eligibleChains: candidateIndex.eligibleChains.length,
    coverageComplete: candidateIndex.coverageComplete,
  };
}

export function verifyH047(runDirectoryInput) {
  const runDirectory = realpathSync(path.resolve(runDirectoryInput));
  const expectedRoot = realpathSync(path.join(REPOSITORY_ROOT, 'artifacts', 'h047'));
  assertion(
    runDirectory.startsWith(`${expectedRoot}${path.sep}`),
    'H-047 run directory escaped the ignored artifact root'
  );
  assertion(statSync(runDirectory).isDirectory(), 'H-047 run path is not a directory');
  const names = readdirSync(runDirectory).sort();
  assertion(
    names.every((name) =>
      ['candidate-index.json', 'run.json', 'source-map.json', 'verification.json'].includes(name)
    ) &&
      ['candidate-index.json', 'run.json', 'source-map.json'].every((name) => names.includes(name)),
    'H-047 run directory contains an unexpected or missing artifact'
  );

  const runArtifact = readArtifact(runDirectory, 'run.json');
  const sourceMapArtifact = readArtifact(runDirectory, 'source-map.json');
  const candidateArtifact = readArtifact(runDirectory, 'candidate-index.json');
  const run = runArtifact.value;
  assertion(GIT_OID_PATTERN.test(run?.sourceAnchor?.commit), 'bad run source anchor');
  const sourceAnchor = verifyIndependentSourceAnchor(run.sourceAnchor.commit, run.sourceAnchor);

  const schema = parseJsonBytes(readFileSync(sourceAnchor.schemaPath), 'H-047 schema');
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(schema);
  assertion(
    validate(run),
    `run schema failed: ${(validate.errors ?? [])
      .map((error) => `${error.instancePath || '/'} ${error.message}`)
      .join('; ')}`
  );
  const { semanticEvidenceSha256, ...semantic } = run;
  assertion(
    independentSha256(canonicalIndependentJson(semantic)) === semanticEvidenceSha256,
    'semantic evidence digest mismatch'
  );
  artifactIdentity(run.artifacts.sourceMap, 'source-map.json', sourceMapArtifact.bytes);
  artifactIdentity(run.artifacts.candidateIndex, 'candidate-index.json', candidateArtifact.bytes);

  const subjectTree = oneLine(
    git(['rev-parse', `${H047_INDEPENDENT_SUBJECT.commit}^{tree}`]),
    'subject tree'
  );
  assertion(subjectTree === H047_INDEPENDENT_SUBJECT.tree, 'subject tree mismatch');
  const subjectSnapshot = treeSnapshot(H047_INDEPENDENT_SUBJECT.commit);
  const reconstructed = reconstructIndependentInventory({
    snapshot: subjectSnapshot,
    reviewMap: sourceAnchor.reviewMap,
  });
  const expectedSourceMap = {
    schemaVersion: 'overlaykit-h047-source-map/v1',
    hypothesis: 'H-047',
    subject: {
      ...H047_INDEPENDENT_SUBJECT,
    },
    entryCount: reconstructed.sourceMap.entryCount,
    entries: reconstructed.sourceMap.entries,
    sourceSetSha256: reconstructed.sourceMap.sourceSetSha256,
  };
  assertion(
    canonicalIndependentJson(sourceMapArtifact.value) ===
      canonicalIndependentJson(expectedSourceMap),
    'source map differs from independent reconstruction'
  );
  assertion(
    canonicalIndependentJson(candidateArtifact.value) ===
      canonicalIndependentJson(reconstructed.candidateIndex),
    'candidate index differs from independent reconstruction'
  );

  const candidateIndex = reconstructed.candidateIndex;
  assertion(
    canonicalIndependentJson(run.summary) ===
      canonicalIndependentJson(expectedSummary(candidateIndex)),
    'summary mismatch'
  );
  assertion(
    canonicalIndependentJson(run.outcome) === canonicalIndependentJson(candidateIndex.outcome),
    'outcome mismatch'
  );
  assertion(
    canonicalIndependentJson(run.adrAssessment) ===
      canonicalIndependentJson(H047_INDEPENDENT_ADR_ASSESSMENT) &&
      canonicalIndependentJson(candidateIndex.adrAssessment) ===
        canonicalIndependentJson(H047_INDEPENDENT_ADR_ASSESSMENT),
    'ADR assessment mismatch'
  );
  assertion(run.authority === 'none' && run.action === null, 'authority or action broadened');
  assertion(
    canonicalIndependentJson(run.claimBoundary) === canonicalIndependentJson(CLAIM_BOUNDARY),
    'claim boundary mismatch'
  );
  assertion(
    canonicalIndependentJson(run.capabilityAudit.commandPolicy) ===
      canonicalIndependentJson(COMMAND_POLICY),
    'producer command policy mismatch'
  );
  assertion(
    canonicalIndependentJson(run.capabilityAudit.observedInvocationCounts) ===
      canonicalIndependentJson(
        expectedProducerInvocationCounts(subjectSnapshot, sourceAnchor.snapshot)
      ),
    'producer invocation counts mismatch'
  );
  assertion(
    run.capabilityAudit.gitNoLazyFetch === true &&
      run.capabilityAudit.gitOptionalLocks === false &&
      run.capabilityAudit.sourceAnchorSignatureVerified === true &&
      run.capabilityAudit.sourceAnchorParentCount === 1,
    'producer Git isolation receipts mismatch'
  );
  assertion(
    run.capabilityAudit.networkObserved === false &&
      run.capabilityAudit.dockerObserved === false &&
      run.capabilityAudit.usbObserved === false &&
      run.capabilityAudit.procfsObserved === false &&
      run.capabilityAudit.sysfsObserved === false &&
      run.capabilityAudit.devfsObserved === false &&
      run.capabilityAudit.systemdObserved === false &&
      run.capabilityAudit.hidrawObserved === false &&
      run.capabilityAudit.signalObserved === false &&
      run.capabilityAudit.productionMutationObserved === false,
    'producer capability boundary broadened'
  );

  return {
    schemaVersion: 'overlaykit-h047-verification/v1',
    hypothesis: 'H-047',
    verified: true,
    subjectCommit: H047_INDEPENDENT_SUBJECT.commit,
    sourceAnchorCommit: run.sourceAnchor.commit,
    sourceAnchorParentCount: sourceAnchor.parentCount,
    sourceAnchorSignatureVerified: sourceAnchor.signatureVerified,
    sourceSetSha256: sourceAnchor.digest,
    semanticEvidenceSha256,
    runSha256: independentSha256(runArtifact.bytes),
    sourceMapSha256: independentSha256(sourceMapArtifact.bytes),
    candidateIndexSha256: independentSha256(candidateArtifact.bytes),
    reviewMapSha256: candidateIndex.semanticReview.reviewMapSha256,
    trackedEntries: reconstructed.sourceMap.entryCount,
    acceptedRecords:
      candidateIndex.governance.counts.decisions.accepted +
      candidateIndex.governance.counts.specifications.accepted +
      candidateIndex.governance.counts.changes.implemented,
    identityPaths: candidateIndex.targetOccurrences.length,
    deploymentSurfaces: candidateIndex.deploymentSurfaces.length,
    reviewedPaths: candidateIndex.semanticReview.pathCount,
    archiveRoots: candidateIndex.semanticReview.archiveForest.rootCount,
    mechanicalCoverageComplete: candidateIndex.semanticReview.coverageComplete,
    candidates: candidateIndex.candidates.length,
    chainComponents: candidateIndex.chainComponents.length,
    eligibleChains: candidateIndex.eligibleChains.length,
    unknowns: candidateIndex.unknowns.length,
    outcome: candidateIndex.outcome,
    adrAssessment: H047_INDEPENDENT_ADR_ASSESSMENT,
    verifierIndependent: true,
    authority: 'none',
    action: null,
    claimBoundary: CLAIM_BOUNDARY,
  };
}

function parseArgs(argv) {
  assertion(
    (argv.length === 1 || argv.length === 2) && (argv.length === 1 || argv[1] === '--write'),
    'Usage: node lab/h047/verify.mjs <run-directory> [--write]'
  );
  return { runDirectory: argv[0], write: argv[1] === '--write' };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === VERIFIER_PATH;
if (isMain) {
  const args = parseArgs(process.argv.slice(2));
  const verification = verifyH047(args.runDirectory);
  const bytes = Buffer.from(`${canonicalIndependentJson(verification)}\n`, 'utf8');
  if (args.write) {
    const outputPath = path.join(realpathSync(args.runDirectory), 'verification.json');
    writeFileSync(outputPath, bytes, { flag: 'wx', mode: 0o600 });
  }
  process.stdout.write(bytes);
}
