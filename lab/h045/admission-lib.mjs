import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const H044_EVIDENCE_SHA256 =
  'c0bfbc3cbb7c7a4f42ed9ba642648b815bff32adaf622fd82663022e167e3610';
export const H044_PUBLIC_RECEIPT_SHA256 =
  'c4147257c8543af6c250c3e59d0e601ced7afd6d5036da84ba10f18c543a462b';
export const H044_PUBLIC_RECEIPT_RELATIVE_PATH = `evidence/h044/${H044_EVIDENCE_SHA256}/README.md`;
export const H044_PUBLIC_RECEIPT_PATH = fileURLToPath(
  new URL(`../../${H044_PUBLIC_RECEIPT_RELATIVE_PATH}`, import.meta.url)
);

export const H045_PROTECTED_MAIN_COMMIT = 'e7c9406dc75d6d8c9cb771d9d62d4fd1359b975d';
export const H045_SOURCE_CONTRACT_COMMIT = '2dc13d02f3d054fe54cb253869134c872e965601';
export const H045_REPOSITORY =
  'https://github.com/OverlayKit/companion-module-overlaykit-server.git';
export const H045_PLAN_HASH = 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4';
export const H045_GOVERNANCE_PLAN_SHA256 =
  '2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243';
export const H045_MANIFEST_CONTENT_HASH =
  'e708f14dcb922d1d5bb7b64a8842d6920a15b2e3d54ad6ad694491c600820110';
export const H045_GOVERNANCE_MANIFEST_SHA256 =
  'bdf427ab00a32910814563778042b1efc17b0341c69dcd9fde586f8943eff1da';
export const H045_CHG_0018_SHA256 =
  '7d8e1f0256d0b6dd94586152cd32bce5f2b3375cb57992cb5f9313966d22028a';
export const H045_CHG_0019_SHA256 =
  '6c83d4b15e82ee3727cc941ffc2b8a9023052ea8a306f2e441953fe044a277fa';
export const H045_CHG_0020_SHA256 =
  'e8c00014e79af95a9a567cbcfca2f054b25c4b807f549df58b7591aca8ae0c6b';
export const H045_ADR_0006_SHA256 =
  '619fbfe60cc8c4c298c6c1eaaa25825b514b1d36bc0b8ec6588d4c3718b9f360';
export const H045_NODE_VERSION = 'v22.20.0';
export const H045_NODE_PLATFORM = 'linux';
export const H045_NODE_ARCH = 'x64';
export const H045_NODE_BINARY_SHA256 =
  'b1cbec894e45a5814b6ab756e1e14f8a76516273197e67e0412b57c1e10d0d9f';
export const H045_NODE_BINARY_BYTE_LENGTH = 123_183_528;

export const H045_ACCEPTED_IMAGE_REFERENCE = 'ghcr.io/bitfocus/companion/companion:v4.3.3';
export const H045_ACCEPTED_IMAGE_ID =
  'sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e';
export const H045_ACCEPTED_VENDOR_ID = '0fd9';
export const H045_ACCEPTED_PRODUCT_ID = '0080';

const H044_RUN_ID = 'h044-2026-07-27T02-46-55-692Z-799230e4';
const H044_PUBLIC_RECEIPT_BYTE_LENGTH = 2_359;
const H045_ACCEPTED_SERIAL_SHA256 =
  '08e7fdb9e9bd371297e96f27f75b77bc3920181d1d448ed2d6f6a1d123548f5f';
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const GIT_COMMIT_PATTERN = /^[0-9a-f]{40}$/u;
const SERIAL_PATTERN = /^[A-Z][A-Z0-9]{13}$/u;

export const H045_ACCEPTED_SERIAL_BINDING = Object.freeze({
  decisionId: 'ADR-0006',
  decisionSha256: H045_ADR_0006_SHA256,
  contextField: 'physical Stream Deck MK.2 serial',
  serialSha256: H045_ACCEPTED_SERIAL_SHA256,
});

export const H045_STABLE_TARGET_INPUT = Object.freeze({
  imageReference: H045_ACCEPTED_IMAGE_REFERENCE,
  imageId: H045_ACCEPTED_IMAGE_ID,
  vendorId: H045_ACCEPTED_VENDOR_ID,
  productId: H045_ACCEPTED_PRODUCT_ID,
  serialBinding: H045_ACCEPTED_SERIAL_BINDING,
});

export const H045_REQUIRED_SOURCE_PATHS = Object.freeze(
  [
    '.overlaykit/governance/manifest.json',
    '.overlaykit/governance/plan.json',
    '.overlaykit/governance/changes/CHG-0018.json',
    '.overlaykit/governance/changes/CHG-0019.json',
    '.overlaykit/governance/changes/CHG-0020.json',
    '.overlaykit/governance/decisions/ADR-0006.json',
    H044_PUBLIC_RECEIPT_RELATIVE_PATH,
    'lab/h041/host-inventory.mjs',
    'lab/h044/observer-lib.mjs',
    'lab/h045/admission-lib.mjs',
    'lab/h045/admission-lib.test.mjs',
    'lab/h045/classifier-lib.mjs',
    'lab/h045/classifier-lib.test.mjs',
    'lab/h045/observer-lib.mjs',
    'lab/h045/observer-lib.test.mjs',
    'lab/h045/run.mjs',
    'lab/h045/run.test.mjs',
    'lab/h045/schema.test.mjs',
    'lab/h045/schemas/live-run.schema.json',
    'lab/h045/verify.mjs',
    'lab/h045/verify.test.mjs',
    'lab/h046/environment-seam.test.mjs',
    'package-lock.json',
    'package.json',
  ].sort()
);

const FORBIDDEN_VOLATILE_TARGET_KEYS = Object.freeze(
  new Set([
    'cgroup',
    'cgroups',
    'container',
    'containerid',
    'descriptor',
    'descriptorid',
    'descriptoridentity',
    'descriptors',
    'devicemajor',
    'deviceminor',
    'devicepath',
    'fd',
    'hostcgroup',
    'hostpid',
    'hidraw',
    'inode',
    'mountnamespace',
    'namespace',
    'namespaces',
    'ns',
    'parentpid',
    'parentstartticks',
    'pid',
    'pid1',
    'pid1startticks',
    'pidnamespace',
    'rdev',
    'startticks',
    'worker',
    'workerpid',
    'workerstartticks',
  ])
);

function admissionError(message, options) {
  return new Error(`H-045 historical admission: ${message}`, options);
}

function asBuffer(value, label) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    throw new TypeError(`${label} must be a Buffer or Uint8Array`);
  }
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function clone(value) {
  return structuredClone(value);
}

function exactKeys(value, keys) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort())
  );
}

function same(left, right) {
  try {
    return JSON.stringify(left) === JSON.stringify(right);
  } catch {
    return false;
  }
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw admissionError(`${label} is not valid JSON`, { cause: error });
  }
}

function captureOne(text, pattern, label) {
  const matches = [...text.matchAll(pattern)];
  if (matches.length !== 1 || typeof matches[0][1] !== 'string') {
    throw admissionError(`public H-044 receipt has no unique ${label}`);
  }
  return matches[0][1];
}

function parsePublicReceipt(bytes) {
  const text = bytes.toString('utf8');
  const candidateReceipts = Number.parseInt(
    captureOne(text, /^- Candidate receipts: `([0-9]+)`$/gmu, 'candidate receipt count'),
    10
  );
  const canonical = {
    runId: captureOne(text, /^- Run: `([^`\r\n]+)`$/gmu, 'canonical run'),
    outcome: captureOne(text, /^- Hypothesis outcome: `([^`\r\n]+)`$/gmu, 'outcome'),
    liveDisposition: captureOne(
      text,
      /^- Live classification: `([^`\r\n]+)`$/gmu,
      'live disposition'
    ),
    stage: captureOne(text, /^- Stage: `([^`\r\n]+)`$/gmu, 'stage'),
    reasonCode: captureOne(text, /^- Reason: `([^`\r\n]+)`$/gmu, 'reason'),
    candidateReceipts,
    semanticEvidenceSha256: captureOne(
      text,
      /^- Semantic evidence SHA-256:\r?\n  `([0-9a-f]{64})`$/gmu,
      'semantic evidence identity'
    ),
  };
  const claimBoundaryExact =
    text.includes('The raw replay bundle is deliberately not tracked.') &&
    text.includes('This receipt grants no signal target, action, watcher, restart,') &&
    text.includes('installation, production policy, product acceptance, or future authority.');
  if (
    canonical.runId !== H044_RUN_ID ||
    canonical.outcome !== 'supported' ||
    canonical.liveDisposition !== 'withheld' ||
    canonical.stage !== 'not-eligible' ||
    canonical.reasonCode !== 'historical-container-absent' ||
    canonical.candidateReceipts !== 0 ||
    canonical.semanticEvidenceSha256 !== H044_EVIDENCE_SHA256 ||
    !claimBoundaryExact
  ) {
    throw admissionError('public H-044 receipt semantics or claim boundary mismatch');
  }
  return canonical;
}

function parseAcceptedDecision(bytes) {
  const decision = parseJson(bytes, 'ADR-0006');
  if (
    decision?.schemaVersion !== 'overlaykit-governance-decision/v1' ||
    decision.id !== 'ADR-0006' ||
    decision.status !== 'accepted' ||
    typeof decision.context !== 'string'
  ) {
    throw admissionError('ADR-0006 accepted-decision identity mismatch');
  }

  const matches = [
    ...decision.context.matchAll(
      /official Companion v4\.3\.3 image reference (\S+) with image ID (sha256:[0-9a-f]{64}), and physical Stream Deck MK\.2 serial ([A-Z][A-Z0-9]+)\./gu
    ),
  ];
  if (matches.length !== 1) {
    throw admissionError('ADR-0006 has no unique accepted target context');
  }
  const [, imageReference, imageId, serial] = matches[0];
  if (
    imageReference !== H045_ACCEPTED_IMAGE_REFERENCE ||
    imageId !== H045_ACCEPTED_IMAGE_ID ||
    !SERIAL_PATTERN.test(serial) ||
    sha256(serial) !== H045_ACCEPTED_SERIAL_SHA256
  ) {
    throw admissionError('ADR-0006 accepted target identity mismatch');
  }

  return {
    decisionReceipt: {
      id: decision.id,
      status: decision.status,
      sha256: H045_ADR_0006_SHA256,
      serialSha256: H045_ACCEPTED_SERIAL_SHA256,
    },
    acceptedTarget: {
      imageReference,
      imageId,
      vendorId: H045_ACCEPTED_VENDOR_ID,
      productId: H045_ACCEPTED_PRODUCT_ID,
      serial,
    },
  };
}

/**
 * Admit only the public, byte-exact H-044 receipt and the accepted, byte-exact
 * ADR-0006 target context. No private H-044 replay member or raw artifact is an
 * input to this function.
 */
export function readHistoricalEvidence(publicReceiptBytes, adr0006Bytes) {
  const receipt = asBuffer(publicReceiptBytes, 'publicReceiptBytes');
  const decision = asBuffer(adr0006Bytes, 'adr0006Bytes');
  const receiptSha256 = sha256(receipt);
  const decisionSha256 = sha256(decision);
  if (receiptSha256 !== H044_PUBLIC_RECEIPT_SHA256) {
    throw admissionError(
      `public H-044 receipt SHA-256 ${receiptSha256} does not match ${H044_PUBLIC_RECEIPT_SHA256}`
    );
  }
  if (decisionSha256 !== H045_ADR_0006_SHA256) {
    throw admissionError(
      `ADR-0006 SHA-256 ${decisionSha256} does not match ${H045_ADR_0006_SHA256}`
    );
  }

  const canonical = parsePublicReceipt(receipt);
  const accepted = parseAcceptedDecision(decision);
  return {
    exact: true,
    publicReceipt: {
      path: H044_PUBLIC_RECEIPT_RELATIVE_PATH,
      sha256: receiptSha256,
      byteLength: receipt.byteLength,
    },
    canonical: clone(canonical),
    decisionReceipt: clone(accepted.decisionReceipt),
    acceptedTarget: clone(accepted.acceptedTarget),
    boundary: {
      rawH044ArtifactsRequired: false,
      authority: 'none',
      action: null,
    },
  };
}

function canonicalExact(value) {
  return (
    exactKeys(value, [
      'runId',
      'outcome',
      'liveDisposition',
      'stage',
      'reasonCode',
      'candidateReceipts',
      'semanticEvidenceSha256',
    ]) &&
    value.runId === H044_RUN_ID &&
    value.outcome === 'supported' &&
    value.liveDisposition === 'withheld' &&
    value.stage === 'not-eligible' &&
    value.reasonCode === 'historical-container-absent' &&
    value.candidateReceipts === 0 &&
    value.semanticEvidenceSha256 === H044_EVIDENCE_SHA256
  );
}

function acceptedTargetExact(value) {
  return (
    exactKeys(value, ['imageReference', 'imageId', 'vendorId', 'productId', 'serial']) &&
    value.imageReference === H045_ACCEPTED_IMAGE_REFERENCE &&
    value.imageId === H045_ACCEPTED_IMAGE_ID &&
    value.vendorId === H045_ACCEPTED_VENDOR_ID &&
    value.productId === H045_ACCEPTED_PRODUCT_ID &&
    typeof value.serial === 'string' &&
    SERIAL_PATTERN.test(value.serial) &&
    sha256(value.serial) === H045_ACCEPTED_SERIAL_SHA256
  );
}

function historicalChecks(historical) {
  const publicReceiptExact =
    exactKeys(historical?.publicReceipt, ['path', 'sha256', 'byteLength']) &&
    historical.publicReceipt.path === H044_PUBLIC_RECEIPT_RELATIVE_PATH &&
    historical.publicReceipt.sha256 === H044_PUBLIC_RECEIPT_SHA256 &&
    historical.publicReceipt.byteLength === H044_PUBLIC_RECEIPT_BYTE_LENGTH;
  const historicalSemanticsExact = canonicalExact(historical?.canonical);
  const acceptedDecisionExact =
    exactKeys(historical?.decisionReceipt, ['id', 'status', 'sha256', 'serialSha256']) &&
    historical.decisionReceipt.id === 'ADR-0006' &&
    historical.decisionReceipt.status === 'accepted' &&
    historical.decisionReceipt.sha256 === H045_ADR_0006_SHA256 &&
    historical.decisionReceipt.serialSha256 === H045_ACCEPTED_SERIAL_SHA256;
  const acceptedTargetContextExact = acceptedTargetExact(historical?.acceptedTarget);
  const historicalBoundaryExact =
    exactKeys(historical?.boundary, ['rawH044ArtifactsRequired', 'authority', 'action']) &&
    historical.boundary.rawH044ArtifactsRequired === false &&
    historical.boundary.authority === 'none' &&
    historical.boundary.action === null &&
    historical?.exact === true;

  return {
    h044PublicReceiptExact: Boolean(publicReceiptExact),
    h044SemanticEvidenceExact: Boolean(historicalSemanticsExact),
    acceptedDecisionExact: Boolean(acceptedDecisionExact),
    acceptedTargetContextExact: Boolean(acceptedTargetContextExact),
    historicalBoundaryExact: Boolean(historicalBoundaryExact),
  };
}

function governanceChecks(governance) {
  const chg0020Exact = governance?.changes?.['CHG-0020'] === H045_CHG_0020_SHA256;
  return {
    governanceVerified: governance?.verified === true,
    governancePlanExact: governance?.planHash === H045_PLAN_HASH,
    governancePlanBytesExact: governance?.planSha256 === H045_GOVERNANCE_PLAN_SHA256,
    governanceManifestExact: governance?.manifestContentHash === H045_MANIFEST_CONTENT_HASH,
    governanceManifestBytesExact: governance?.manifestSha256 === H045_GOVERNANCE_MANIFEST_SHA256,
    governanceChangesExact: Boolean(
      exactKeys(governance?.changes, ['CHG-0018', 'CHG-0019', 'CHG-0020']) &&
      governance.changes['CHG-0018'] === H045_CHG_0018_SHA256 &&
      governance.changes['CHG-0019'] === H045_CHG_0019_SHA256 &&
      chg0020Exact
    ),
    chg0020Exact: Boolean(chg0020Exact),
    governanceDecisionExact: Boolean(
      exactKeys(governance?.decisions, ['ADR-0006']) &&
      governance.decisions['ADR-0006'] === H045_ADR_0006_SHA256
    ),
    governanceSourcePathsExact: same(governance?.requiredSourcePaths, H045_REQUIRED_SOURCE_PATHS),
  };
}

function gitChecks(git) {
  return {
    repositoryRemoteExact: Boolean(
      exactKeys(git, [
        'repositoryRemote',
        'head',
        'protectedMainCommit',
        'sourceContractCommit',
        'protectedMainAncestor',
        'sourceContractAncestor',
      ]) && git.repositoryRemote === H045_REPOSITORY
    ),
    observedHeadWellFormed: GIT_COMMIT_PATTERN.test(git?.head ?? ''),
    protectedMainExact: Boolean(
      GIT_COMMIT_PATTERN.test(git?.protectedMainCommit ?? '') &&
      git.protectedMainCommit === H045_PROTECTED_MAIN_COMMIT
    ),
    sourceContractExact: Boolean(
      GIT_COMMIT_PATTERN.test(git?.sourceContractCommit ?? '') &&
      git.sourceContractCommit === H045_SOURCE_CONTRACT_COMMIT
    ),
    protectedMainAncestor: git?.protectedMainAncestor === true,
    sourceContractAncestor: git?.sourceContractAncestor === true,
  };
}

function runtimeChecks(runtime) {
  return {
    nodeRuntimeExact: Boolean(
      exactKeys(runtime, ['node', 'platform', 'arch', 'binarySha256', 'binaryByteLength']) &&
      runtime.node === H045_NODE_VERSION &&
      runtime.platform === H045_NODE_PLATFORM &&
      runtime.arch === H045_NODE_ARCH &&
      runtime.binarySha256 === H045_NODE_BINARY_SHA256 &&
      runtime.binaryByteLength === H045_NODE_BINARY_BYTE_LENGTH
    ),
  };
}

function normalizedKey(key) {
  return key.toLowerCase().replaceAll(/[^a-z0-9]/gu, '');
}

function containsForbiddenVolatileTarget(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object') return false;
  if (seen.has(value)) return true;
  seen.add(value);
  if (Array.isArray(value)) {
    return value.some((entry) => containsForbiddenVolatileTarget(entry, seen));
  }
  return Object.entries(value).some(
    ([key, nested]) =>
      FORBIDDEN_VOLATILE_TARGET_KEYS.has(normalizedKey(key)) ||
      containsForbiddenVolatileTarget(nested, seen)
  );
}

/**
 * Validate the only admitted H-045 input boundary. The serial literal is not an
 * input: its byte-exact ADR-0006 binding is, and readHistoricalEvidence derives
 * the literal independently from that accepted decision.
 */
export function stableTargetInputExact(value) {
  return Boolean(
    !containsForbiddenVolatileTarget(value) &&
    exactKeys(value, ['imageReference', 'imageId', 'vendorId', 'productId', 'serialBinding']) &&
    value.imageReference === H045_ACCEPTED_IMAGE_REFERENCE &&
    value.imageId === H045_ACCEPTED_IMAGE_ID &&
    value.vendorId === H045_ACCEPTED_VENDOR_ID &&
    value.productId === H045_ACCEPTED_PRODUCT_ID &&
    exactKeys(value.serialBinding, [
      'decisionId',
      'decisionSha256',
      'contextField',
      'serialSha256',
    ]) &&
    same(value.serialBinding, H045_ACCEPTED_SERIAL_BINDING)
  );
}

export function sourceMapExact(sources) {
  if (!Array.isArray(sources) || sources.length !== H045_REQUIRED_SOURCE_PATHS.length) return false;
  return sources.every(
    (entry, index) =>
      exactKeys(entry, ['path', 'sha256']) &&
      entry.path === H045_REQUIRED_SOURCE_PATHS[index] &&
      SHA256_PATTERN.test(entry.sha256)
  );
}

/**
 * Bind an external review to the complete, ordered H-045 source map. Object key
 * order from the caller is deliberately ignored; path order and every file
 * digest remain part of the canonical review identity.
 */
export function sourceSetSha256(sources) {
  if (!sourceMapExact(sources)) {
    throw admissionError('source map is not the exact required source set');
  }
  const canonical = sources.map((entry) => ({
    path: entry.path,
    sha256: entry.sha256,
  }));
  return sha256(Buffer.from(JSON.stringify(canonical), 'utf8'));
}

/**
 * Consolidate pre-observation admission receipts. Any partial, expanded,
 * reordered, drifting, historically volatile, or wrong-runtime input remains
 * inexact and cannot release the accepted target to an observer.
 */
export function buildSourceAdmission({
  historical,
  governance,
  git,
  runtime,
  targetInput,
  sourcesBefore,
  sourcesAfter,
} = {}) {
  const checks = {
    ...historicalChecks(historical),
    ...governanceChecks(governance),
    ...gitChecks(git),
    ...runtimeChecks(runtime),
    stableTargetInputExact: stableTargetInputExact(targetInput),
    sourcesBeforeExact: sourceMapExact(sourcesBefore),
    sourcesAfterExact: sourceMapExact(sourcesAfter),
  };
  const historicalExact =
    checks.h044PublicReceiptExact &&
    checks.h044SemanticEvidenceExact &&
    checks.acceptedDecisionExact &&
    checks.acceptedTargetContextExact &&
    checks.historicalBoundaryExact;
  const governanceExact =
    checks.governanceVerified &&
    checks.governancePlanExact &&
    checks.governancePlanBytesExact &&
    checks.governanceManifestExact &&
    checks.governanceManifestBytesExact &&
    checks.governanceChangesExact &&
    checks.chg0020Exact &&
    checks.governanceDecisionExact &&
    checks.governanceSourcePathsExact;
  const gitExact =
    checks.repositoryRemoteExact &&
    checks.observedHeadWellFormed &&
    checks.protectedMainExact &&
    checks.sourceContractExact &&
    checks.protectedMainAncestor &&
    checks.sourceContractAncestor;
  const runtimeExact = checks.nodeRuntimeExact;
  const targetInputExact = checks.stableTargetInputExact;
  const sourceSetExact = checks.sourcesBeforeExact && checks.sourcesAfterExact;
  const sourceStable =
    sourceSetExact && sourcesBefore !== sourcesAfter && same(sourcesBefore, sourcesAfter);
  const exact =
    historicalExact &&
    governanceExact &&
    gitExact &&
    runtimeExact &&
    targetInputExact &&
    sourceSetExact &&
    sourceStable;

  return {
    historicalExact: Boolean(historicalExact),
    governanceExact: Boolean(governanceExact),
    gitExact: Boolean(gitExact),
    runtimeExact: Boolean(runtimeExact),
    targetInputExact: Boolean(targetInputExact),
    sourceSetExact: Boolean(sourceSetExact),
    sourceStable: Boolean(sourceStable),
    exact: Boolean(exact),
    acceptedTarget: exact ? clone(historical.acceptedTarget) : null,
    checks: clone(checks),
  };
}
