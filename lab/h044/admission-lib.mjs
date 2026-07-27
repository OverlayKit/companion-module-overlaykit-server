import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { readTarGzipMembers } from '../h043/archive-lib.mjs';

export const H043_REPLAY_ARCHIVE_SHA256 =
  'fbe7e841a7319328b253e414f93abd3a17ab47506b783b652c6624aae3b68dec';
export const H043_EVIDENCE_SHA256 =
  '64bf41f30dc2d51a2475e6f2e9b79ddebc225c076a87b83c384b3848b1bbecb8';
export const H043_RUN_SHA256 = '4a5754eddcd5672072d1ce0dc68c7a42694eafdc3eab5cddc4bf3e9ce5a57328';
export const H043_VERIFICATION_SHA256 =
  'f75726992c88d45b9d43bab3443005cdaed05464d303f05a8356e0ccecc81023';
export const H043_CANDIDATE_TOKEN_SHA256 =
  '43f26fc54686331e1d6a4f06d827b92d1975cc1482b2cd2d1795f698a6deac06';
export const H043_RUN_ID = 'h043-2026-07-26T22-13-38-193Z-b4158eab';
export const H043_REPLAY_ARCHIVE_RELATIVE_PATH = `evidence/h043/${H043_EVIDENCE_SHA256}/replay-${H043_REPLAY_ARCHIVE_SHA256}.tar.gz`;
export const H043_REPLAY_ARCHIVE_PATH = fileURLToPath(
  new URL(`../../${H043_REPLAY_ARCHIVE_RELATIVE_PATH}`, import.meta.url)
);
export const H043_RUN_MEMBER_PATH = `artifacts/h043/${H043_RUN_ID}/run.json`;
export const H043_VERIFICATION_MEMBER_PATH = `artifacts/h043/${H043_RUN_ID}/verification.json`;

export const H044_REQUIRED_SOURCE_PATHS = Object.freeze(
  [
    '.overlaykit/governance/changes/CHG-0016.json',
    '.overlaykit/governance/changes/CHG-0017.json',
    '.overlaykit/governance/decisions/ADR-0006.json',
    'lab/h041/container-observer.mjs',
    'lab/h041/host-inventory.mjs',
    'lab/h043/archive-lib.mjs',
    'lab/h043/verify.mjs',
    'lab/h044/admission-lib.mjs',
    'lab/h044/admission-lib.test.mjs',
    'lab/h044/classifier-lib.mjs',
    'lab/h044/classifier-lib.test.mjs',
    'lab/h044/observer-lib.mjs',
    'lab/h044/observer-lib.test.mjs',
    'lab/h044/run.mjs',
    'lab/h044/run.test.mjs',
    'lab/h044/schema.test.mjs',
    'lab/h044/schemas/live-run.schema.json',
    'lab/h044/verify.mjs',
    'lab/h044/verify.test.mjs',
    'package-lock.json',
    'package.json',
  ].sort()
);

const H044_PLAN_HASH = 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4';
const H044_MANIFEST_CONTENT_HASH =
  'b36032589f0d652ceffd6aafee502e551b4f86779149be4b9ac1c38636a17013';
const CHG_0016_SHA256 = 'b8ea5a54c666047c7c44e322b21bc5f24836d172b4712c7483507bc2d4739ae6';
const CHG_0017_SHA256 = '858fcc7fde8bf6abd73e58f56224c3eae238ecf46ae70e92aca92f886937e576';
const ADR_0006_SHA256 = '619fbfe60cc8c4c298c6c1eaaa25825b514b1d36bc0b8ec6588d4c3718b9f360';
const H044_PROTECTED_MAIN_COMMIT = '6c329234caddf9e34126be04149f768673bdb8bf';
const H044_SOURCE_CONTRACT_COMMIT = '9e2156e7ddc38ebe223824a07f682421b7ee0589';
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const GIT_COMMIT_PATTERN = /^[0-9a-f]{40}$/u;

function historicalError(message, options) {
  return new Error(`H-044 historical admission: ${message}`, options);
}

function asBuffer(value) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    throw new TypeError('archiveBytes must be a Buffer or Uint8Array');
  }
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function clone(value) {
  return structuredClone(value);
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch (error) {
    throw historicalError(`${label} is not valid JSON`, { cause: error });
  }
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
  return JSON.stringify(left) === JSON.stringify(right);
}

function member(members, memberPath) {
  const bytes = members.get(memberPath);
  if (!bytes) throw historicalError(`archive is missing canonical member ${memberPath}`);
  return bytes;
}

function candidateSemanticsExact(run) {
  const classification = run?.canonicalClassification;
  if (
    classification?.disposition !== 'candidate' ||
    classification.stage !== 'historical-worker-candidate' ||
    classification.reasonCode !== 'revalidation-required-worker-candidate' ||
    !Array.isArray(classification.candidates) ||
    classification.candidates.length !== 1
  ) {
    return false;
  }

  const candidate = classification.candidates[0];
  return (
    candidate !== null &&
    typeof candidate === 'object' &&
    candidate.kind === 'revalidation-required' &&
    candidate.historical === true &&
    candidate.requiresRevalidation === true &&
    candidate.authority === 'none' &&
    candidate.action === null &&
    candidate.tokenSha256 === H043_CANDIDATE_TOKEN_SHA256
  );
}

function lineageSemanticsExact(run, verification) {
  return (
    run?.schemaVersion === 'overlaykit-h043-offline-worker-eligibility-run/v1' &&
    run.hypothesis === 'H-043' &&
    run.runId === H043_RUN_ID &&
    run.evidenceSha256 === H043_EVIDENCE_SHA256 &&
    run.outcome?.status === 'supported' &&
    run.outcome.stage === 'offline-worker-eligibility' &&
    run.outcome.reasonCode === 'canonical-candidate-and-hostile-matrix-exact' &&
    verification?.schemaVersion === 'overlaykit-h043-verification/v1' &&
    verification.hypothesis === 'H-043' &&
    verification.runId === H043_RUN_ID &&
    verification.evidenceSha256 === H043_EVIDENCE_SHA256 &&
    verification.outcome === 'supported' &&
    verification.stage === 'offline-worker-eligibility' &&
    verification.verified === true &&
    candidateSemanticsExact(run)
  );
}

/**
 * Admit only the byte-exact H-043 bundle accepted by the human principal.
 *
 * The returned run, verification, candidate, and receipts do not share mutable
 * object identities with one another.
 */
export function readHistoricalEvidence(archiveBytes) {
  const compressed = asBuffer(archiveBytes);
  const archiveSha256 = sha256(compressed);
  if (archiveSha256 !== H043_REPLAY_ARCHIVE_SHA256) {
    throw historicalError(
      `archive SHA-256 ${archiveSha256} does not match ${H043_REPLAY_ARCHIVE_SHA256}`
    );
  }

  let members;
  try {
    members = readTarGzipMembers(compressed);
  } catch (error) {
    throw historicalError('archive decoding failed', { cause: error });
  }
  const runBytes = member(members, H043_RUN_MEMBER_PATH);
  const verificationBytes = member(members, H043_VERIFICATION_MEMBER_PATH);
  const runSha256 = sha256(runBytes);
  const verificationSha256 = sha256(verificationBytes);
  if (runSha256 !== H043_RUN_SHA256) {
    throw historicalError(`canonical run SHA-256 ${runSha256} does not match ${H043_RUN_SHA256}`);
  }
  if (verificationSha256 !== H043_VERIFICATION_SHA256) {
    throw historicalError(
      `canonical verification SHA-256 ${verificationSha256} does not match ${H043_VERIFICATION_SHA256}`
    );
  }

  const parsedRun = parseJson(runBytes, 'canonical run');
  const parsedVerification = parseJson(verificationBytes, 'canonical verification');
  if (!lineageSemanticsExact(parsedRun, parsedVerification)) {
    throw historicalError('accepted run, verification, or candidate lineage receipt mismatch');
  }

  const parsedCandidate = parsedRun.canonicalClassification.candidates[0];
  const archiveReceipt = {
    path: H043_REPLAY_ARCHIVE_RELATIVE_PATH,
    sha256: archiveSha256,
    byteLength: compressed.byteLength,
    memberCount: members.size,
  };
  const runReceipt = {
    memberPath: H043_RUN_MEMBER_PATH,
    sha256: runSha256,
    runId: parsedRun.runId,
    evidenceSha256: parsedRun.evidenceSha256,
    outcome: parsedRun.outcome.status,
  };
  const verificationReceipt = {
    memberPath: H043_VERIFICATION_MEMBER_PATH,
    sha256: verificationSha256,
    runId: parsedVerification.runId,
    evidenceSha256: parsedVerification.evidenceSha256,
    outcome: parsedVerification.outcome,
    verified: parsedVerification.verified,
  };
  const candidateReceipt = {
    tokenSha256: parsedCandidate.tokenSha256,
    historical: parsedCandidate.historical,
    requiresRevalidation: parsedCandidate.requiresRevalidation,
    authority: parsedCandidate.authority,
    action: parsedCandidate.action,
  };

  return {
    exact: true,
    archiveReceipt: clone(archiveReceipt),
    runReceipt: clone(runReceipt),
    verificationReceipt: clone(verificationReceipt),
    candidateReceipt: clone(candidateReceipt),
    run: clone(parsedRun),
    verification: clone(parsedVerification),
    candidate: clone(parsedCandidate),
  };
}

function historicalChecks(historical) {
  const archiveReceiptExact =
    exactKeys(historical?.archiveReceipt, ['path', 'sha256', 'byteLength', 'memberCount']) &&
    historical.archiveReceipt.path === H043_REPLAY_ARCHIVE_RELATIVE_PATH &&
    historical.archiveReceipt.sha256 === H043_REPLAY_ARCHIVE_SHA256 &&
    historical.archiveReceipt.byteLength === 389_084 &&
    historical.archiveReceipt.memberCount === 21;
  const runReceiptExact =
    exactKeys(historical?.runReceipt, [
      'memberPath',
      'sha256',
      'runId',
      'evidenceSha256',
      'outcome',
    ]) &&
    historical.runReceipt.memberPath === H043_RUN_MEMBER_PATH &&
    historical.runReceipt.sha256 === H043_RUN_SHA256 &&
    historical.runReceipt.runId === H043_RUN_ID &&
    historical.runReceipt.evidenceSha256 === H043_EVIDENCE_SHA256 &&
    historical.runReceipt.outcome === 'supported';
  const verificationReceiptExact =
    exactKeys(historical?.verificationReceipt, [
      'memberPath',
      'sha256',
      'runId',
      'evidenceSha256',
      'outcome',
      'verified',
    ]) &&
    historical.verificationReceipt.memberPath === H043_VERIFICATION_MEMBER_PATH &&
    historical.verificationReceipt.sha256 === H043_VERIFICATION_SHA256 &&
    historical.verificationReceipt.runId === H043_RUN_ID &&
    historical.verificationReceipt.evidenceSha256 === H043_EVIDENCE_SHA256 &&
    historical.verificationReceipt.outcome === 'supported' &&
    historical.verificationReceipt.verified === true;
  const candidateReceiptExact =
    exactKeys(historical?.candidateReceipt, [
      'tokenSha256',
      'historical',
      'requiresRevalidation',
      'authority',
      'action',
    ]) &&
    historical.candidateReceipt.tokenSha256 === H043_CANDIDATE_TOKEN_SHA256 &&
    historical.candidateReceipt.historical === true &&
    historical.candidateReceipt.requiresRevalidation === true &&
    historical.candidateReceipt.authority === 'none' &&
    historical.candidateReceipt.action === null;
  const historicalDataExact =
    historical?.exact === true &&
    lineageSemanticsExact(historical.run, historical.verification) &&
    same(historical.candidate, historical.run?.canonicalClassification?.candidates?.[0]) &&
    historical.candidate?.tokenSha256 === H043_CANDIDATE_TOKEN_SHA256;

  return {
    historicalArchiveExact: Boolean(archiveReceiptExact),
    historicalRunExact: Boolean(runReceiptExact),
    historicalVerificationExact: Boolean(verificationReceiptExact),
    historicalCandidateExact: Boolean(candidateReceiptExact && historicalDataExact),
  };
}

function governanceChecks(governance) {
  const governanceVerified = governance?.verified === true;
  const governancePlanExact = governance?.planHash === H044_PLAN_HASH;
  const governanceManifestExact = governance?.manifestContentHash === H044_MANIFEST_CONTENT_HASH;
  const governanceChangesExact =
    exactKeys(governance?.changes, ['CHG-0016', 'CHG-0017']) &&
    governance.changes['CHG-0016'] === CHG_0016_SHA256 &&
    governance.changes['CHG-0017'] === CHG_0017_SHA256;
  const governanceDecisionExact =
    exactKeys(governance?.decisions, ['ADR-0006']) &&
    governance.decisions['ADR-0006'] === ADR_0006_SHA256;
  const governanceSourcePathsExact =
    governance?.requiredSourcePaths === undefined ||
    same(governance.requiredSourcePaths, H044_REQUIRED_SOURCE_PATHS);

  return {
    governanceVerified: Boolean(governanceVerified),
    governancePlanExact: Boolean(governancePlanExact),
    governanceManifestExact: Boolean(governanceManifestExact),
    governanceChangesExact: Boolean(governanceChangesExact),
    governanceDecisionExact: Boolean(governanceDecisionExact),
    governanceSourcePathsExact: Boolean(governanceSourcePathsExact),
  };
}

function gitChecks(git) {
  return {
    protectedMainExact: Boolean(
      GIT_COMMIT_PATTERN.test(git?.protectedMainCommit ?? '') &&
      git.protectedMainCommit === H044_PROTECTED_MAIN_COMMIT
    ),
    sourceContractExact: Boolean(
      GIT_COMMIT_PATTERN.test(git?.sourceContractCommit ?? '') &&
      git.sourceContractCommit === H044_SOURCE_CONTRACT_COMMIT
    ),
    protectedMainAncestor: git?.protectedMainAncestor === true,
  };
}

function sourceMapExact(sources) {
  if (!Array.isArray(sources) || sources.length !== H044_REQUIRED_SOURCE_PATHS.length) return false;
  return sources.every(
    (entry, index) =>
      exactKeys(entry, ['path', 'sha256']) &&
      entry.path === H044_REQUIRED_SOURCE_PATHS[index] &&
      SHA256_PATTERN.test(entry.sha256)
  );
}

/**
 * Consolidate pre-observation admission receipts. Invalid, partial, duplicated,
 * reordered, or drifting inputs return false booleans and never become exact.
 */
export function buildSourceAdmission({
  historical,
  governance,
  git,
  sourcesBefore,
  sourcesAfter,
} = {}) {
  const checks = {
    ...historicalChecks(historical),
    ...governanceChecks(governance),
    ...gitChecks(git),
    sourcesBeforeExact: sourceMapExact(sourcesBefore),
    sourcesAfterExact: sourceMapExact(sourcesAfter),
  };
  const historicalExact =
    checks.historicalArchiveExact &&
    checks.historicalRunExact &&
    checks.historicalVerificationExact &&
    checks.historicalCandidateExact;
  const governanceExact =
    checks.governanceVerified &&
    checks.governancePlanExact &&
    checks.governanceManifestExact &&
    checks.governanceChangesExact &&
    checks.governanceDecisionExact &&
    checks.governanceSourcePathsExact;
  const gitExact =
    checks.protectedMainExact && checks.sourceContractExact && checks.protectedMainAncestor;
  const sourceSetExact = checks.sourcesBeforeExact && checks.sourcesAfterExact;
  const sourceStable =
    sourceSetExact && same(sourcesBefore, sourcesAfter) && sourcesBefore !== sourcesAfter;
  const exact = historicalExact && governanceExact && gitExact && sourceSetExact && sourceStable;

  return {
    historicalExact: Boolean(historicalExact),
    governanceExact: Boolean(governanceExact),
    gitExact: Boolean(gitExact),
    sourceSetExact: Boolean(sourceSetExact),
    sourceStable: Boolean(sourceStable),
    exact: Boolean(exact),
    checks: clone(checks),
  };
}
