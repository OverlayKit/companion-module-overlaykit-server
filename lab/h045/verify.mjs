#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { constants as FS_CONSTANTS, createReadStream } from 'node:fs';
import { link, open, readFile, readdir, realpath, stat, unlink } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

const REPOSITORY_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SCHEMA_PATH = fileURLToPath(new URL('./schemas/live-run.schema.json', import.meta.url));
const ARTIFACT_ROOT = path.join(REPOSITORY_ROOT, 'artifacts', 'h045');
const PREDECESSOR_ATTEMPT_DIRECTORY = 'live-attempt';
const PREDECESSOR_RESERVATION_RELATIVE_PATH = 'artifacts/h045/live-attempt/reservation.json';
const PREDECESSOR_FAILURE_RELATIVE_PATH = 'artifacts/h045/live-attempt/failure.json';
const PREDECESSOR_RESERVATION_SHA256 =
  '27ee9aa2c70adb56682564c6ddc80c43cc40e6a5c5e1edacc23327648aad2f24';
const PREDECESSOR_FAILURE_SHA256 =
  '710b3b28760239f5971c961f8b0011a18c439c10a4974f548c435ff2a4507fc0';
const PREDECESSOR_SOURCE_SET_SHA256 =
  '7230be4ed41b469a9e8486ff757c349eff48035e393c4825542c0ad2c201fab2';
const PREDECESSOR_AUTHORIZATION = `CHG-0019:one-readonly-run:sha256:${PREDECESSOR_SOURCE_SET_SHA256}`;
const REPLACEMENT_ATTEMPT_ID = 'h045-chg-0020-attempt-1';
const REPLACEMENT_ATTEMPT_DIRECTORY = REPLACEMENT_ATTEMPT_ID;
const REPLACEMENT_RESERVATION_RELATIVE_PATH = `artifacts/h045/${REPLACEMENT_ATTEMPT_DIRECTORY}/reservation.json`;
const REPLACEMENT_COMPLETION_RELATIVE_PATH = `artifacts/h045/${REPLACEMENT_ATTEMPT_DIRECTORY}/completion.json`;
const MAX_LOCAL_PATH_BYTES = 4_096;
const MAX_RUN_JSON_BYTES = 64 * 1024 * 1024;
const MAX_LEDGER_RECEIPT_BYTES = 64 * 1024;
const MAX_VERIFICATION_JSON_BYTES = 64 * 1024;
const VERIFICATION_FILENAME = 'verification.json';
const VERIFICATION_STAGING_FILENAME = '.verification.pending.json';

const REPOSITORY = 'https://github.com/OverlayKit/companion-module-overlaykit-server.git';
const PROTECTED_MAIN_COMMIT = 'e7c9406dc75d6d8c9cb771d9d62d4fd1359b975d';
const SOURCE_CONTRACT_COMMIT = '2dc13d02f3d054fe54cb253869134c872e965601';
const PLAN_HASH = 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4';
const GOVERNANCE_PLAN_SHA256 = '2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243';
const MANIFEST_CONTENT_HASH = 'e708f14dcb922d1d5bb7b64a8842d6920a15b2e3d54ad6ad694491c600820110';
const GOVERNANCE_MANIFEST_SHA256 =
  'bdf427ab00a32910814563778042b1efc17b0341c69dcd9fde586f8943eff1da';
const CHG_0018_SHA256 = '7d8e1f0256d0b6dd94586152cd32bce5f2b3375cb57992cb5f9313966d22028a';
const CHG_0019_SHA256 = '6c83d4b15e82ee3727cc941ffc2b8a9023052ea8a306f2e441953fe044a277fa';
const CHG_0020_SHA256 = 'e8c00014e79af95a9a567cbcfca2f054b25c4b807f549df58b7591aca8ae0c6b';
const ADR_0006_SHA256 = '619fbfe60cc8c4c298c6c1eaaa25825b514b1d36bc0b8ec6588d4c3718b9f360';
const H044_EVIDENCE_SHA256 = 'c0bfbc3cbb7c7a4f42ed9ba642648b815bff32adaf622fd82663022e167e3610';
const H044_PUBLIC_RECEIPT_SHA256 =
  'c4147257c8543af6c250c3e59d0e601ced7afd6d5036da84ba10f18c543a462b';
const H044_PUBLIC_RECEIPT_RELATIVE_PATH = `evidence/h044/${H044_EVIDENCE_SHA256}/README.md`;
const H044_PUBLIC_RECEIPT_BYTE_LENGTH = 2_359;
const H044_RUN_ID = 'h044-2026-07-27T02-46-55-692Z-799230e4';

const NODE_VERSION = 'v22.20.0';
const NODE_PLATFORM = 'linux';
const NODE_ARCH = 'x64';
const NODE_BINARY_SHA256 = 'b1cbec894e45a5814b6ab756e1e14f8a76516273197e67e0412b57c1e10d0d9f';
const NODE_BINARY_BYTE_LENGTH = 123_183_528;

const ACCEPTED_IMAGE_REFERENCE = 'ghcr.io/bitfocus/companion/companion:v4.3.3';
const ACCEPTED_IMAGE_ID = 'sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e';
const ACCEPTED_VENDOR_ID = '0fd9';
const ACCEPTED_PRODUCT_ID = '0080';
const ACCEPTED_SERIAL = 'A00SA5492OQMLF';
const ACCEPTED_SERIAL_SHA256 = '08e7fdb9e9bd371297e96f27f75b77bc3920181d1d448ed2d6f6a1d123548f5f';
const LIVE_AUTHORIZATION_PREFIX = 'CHG-0020:h045-one-readonly-replacement-attempt:sha256:';

const SERIAL_BINDING = Object.freeze({
  decisionId: 'ADR-0006',
  decisionSha256: ADR_0006_SHA256,
  contextField: 'physical Stream Deck MK.2 serial',
  serialSha256: ACCEPTED_SERIAL_SHA256,
});

export const INDEPENDENT_REQUIRED_SOURCE_PATHS = Object.freeze(
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

export const INDEPENDENT_CASE_IDS = Object.freeze([
  'multiple-image-matches',
  'selector-broadening',
  'descendant-image-mismatch',
  'hidden-container-row',
  'deployment-presence-drift',
  'container-drift',
  'pid1-drift',
  'worker-ambiguity',
  'pid-reuse',
  'parent-drift',
  'namespace-drift',
  'device-absence',
  'device-epoch-drift',
  'descriptor-recovery',
  'marker-change',
  'frame-reorder',
  'exposure-over-limit',
  'missing-command-audit',
  'duplicate-receipts',
  'input-tampering',
  'source-drift',
  'environment-policy-drift',
  'prohibited-capability',
]);

export const INDEPENDENT_CLAIM_BOUNDARY = Object.freeze({
  proves: Object.freeze([
    'one capability-bounded dynamic read-only observation derived only from the exact accepted Companion image and MK.2 identity without a historical volatile target identifier',
    'two adjacent complete frames no more than 5000 milliseconds apart with exact image-filter cardinality, current device epoch, Docker lifecycle, PID 1, SurfaceThread, descriptor, marker, and audit receipts',
    'one cutoff-bound authority-void dynamic tuple receipt only for one stable running non-healthy deployment, or zero receipts with withheld for complete current non-eligibility',
    'fail-closed inconclusive classification for multiplicity, selector ambiguity, contradiction, inaccessible evidence, PID reuse, inter-frame drift, source drift, or incomplete audit',
    'exact audited cardinality of allowed local Git, lsusb, Docker Unix-socket, and filesystem metadata observations with zero prohibited capabilities',
  ]),
  excludes: Object.freeze([
    'validity after the second-frame cutoff, continuity from H-043, atomicity, race freedom, PID-reuse-safe action, or a closed check-action interval',
    'authorization or safety of SIGTERM, pidfd, any signal, command, restart, rescan, retry, executable action, watcher, controller, or supervisor',
    'physical disconnect or reconnect, hidraw open or I/O, Docker lifecycle mutation, namespace entry, configuration change, installation, production policy, publication, or release',
    'configuration continuity, button delivery, rendered pixels, operator perception, OBS truth, product acceptance, security, or acceptable downtime',
    'multiple-device behavior, image upgrade discovery, pre-login behavior, reboot recovery, long-outage recovery, or production recovery policy',
    'an expansion or satisfaction of accepted SPEC-0001 or SPEC-0002',
    'a successor ADR or architectural authority beyond ADR-0006',
  ]),
});

const SOURCE_ADMISSION_KEYS = Object.freeze([
  'h044PublicReceiptExact',
  'h044SemanticEvidenceExact',
  'acceptedDecisionExact',
  'acceptedTargetContextExact',
  'historicalBoundaryExact',
  'chg0018Exact',
  'chg0019Exact',
  'chg0020Exact',
  'adr0006Exact',
  'repositoryRemoteExact',
  'observedHeadWellFormed',
  'protectedMainExact',
  'sourceContractExact',
  'protectedMainAncestryExact',
  'sourceContractAncestryExact',
  'runtimeBinaryExact',
  'targetInputExact',
  'governanceExact',
  'sourceSetExact',
  'sourceStable',
  'allExact',
]);

const TOP_LEVEL_KEYS = Object.freeze([
  'schemaVersion',
  'hypothesis',
  'runId',
  'startedAt',
  'completedAt',
  'outcome',
  'collector',
  'input',
  'sourceAdmission',
  'acceptedTarget',
  'frames',
  'capabilityAudit',
  'liveClassification',
  'hostileMatrix',
  'claimBoundary',
  'evidenceSha256',
]);

const FILESYSTEM_LIMITS = Object.freeze({
  maxReadBytes: 1024 * 1024,
  maxPathBytes: 4096,
  maxDirectoryEntries: 4096,
  maxHidrawEntries: 64,
  maxProcessEntries: 1024,
  maxDescriptorEntries: 1024,
  maxReceiptsPerFrame: 16_384,
});

const GIT_COMMIT_PATTERN = /^[0-9a-f]{40}$/u;

function verificationAssertion(condition, message) {
  if (!condition) throw new Error(`H-045 verification failed: ${message}`);
}

function verifierPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function verifierExactKeys(value, keys) {
  return (
    verifierPlainObject(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function verifierCanonicalize(value) {
  if (Array.isArray(value)) return value.map(verifierCanonicalize);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, verifierCanonicalize(value[key])])
    );
  }
  return value;
}

function verifierCanonicalJson(value) {
  return JSON.stringify(verifierCanonicalize(value));
}

function verifierSame(left, right) {
  try {
    return verifierCanonicalJson(left) === verifierCanonicalJson(right);
  } catch {
    return false;
  }
}

function digestBytes(value) {
  return createHash('sha256').update(value).digest('hex');
}

function digestCanonical(value) {
  return digestBytes(verifierCanonicalJson(value));
}

function prettyJsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function pathByteLength(value) {
  return Buffer.byteLength(value, 'utf8');
}

function effectiveOwnerExact(metadata) {
  return (
    typeof process.geteuid === 'function' &&
    typeof process.getegid === 'function' &&
    metadata.uid === BigInt(process.geteuid()) &&
    metadata.gid === BigInt(process.getegid())
  );
}

function stableMetadataExact(before, after) {
  return ['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs'].every(
    (field) => before[field] === after[field]
  );
}

function assertSecureFileMetadata(metadata, expectedByteLength, label) {
  verificationAssertion(metadata.isFile(), `${label} is not a regular file`);
  verificationAssertion((metadata.mode & 0o777n) === 0o600n, `${label} mode is not 0600`);
  verificationAssertion(effectiveOwnerExact(metadata), `${label} owner is not the verifier`);
  verificationAssertion(metadata.nlink === 1n, `${label} has a hard-link alias`);
  verificationAssertion(
    metadata.size === BigInt(expectedByteLength),
    `${label} byte length changed`
  );
}

function directoryDescriptorPath(receipt, child = '') {
  return path.join('/proc/self/fd', String(receipt.handle.fd), child);
}

async function openSecureDirectory(directory, label, expectedCanonicalPath = directory) {
  const accessPath = path.resolve(directory);
  const canonicalPath = path.resolve(expectedCanonicalPath);
  verificationAssertion(
    pathByteLength(accessPath) <= MAX_LOCAL_PATH_BYTES &&
      pathByteLength(canonicalPath) <= MAX_LOCAL_PATH_BYTES,
    `${label} path exceeds ${MAX_LOCAL_PATH_BYTES} UTF-8 bytes`
  );
  let handle;
  try {
    handle = await open(
      accessPath,
      FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_DIRECTORY | FS_CONSTANTS.O_NOFOLLOW
    );
  } catch (error) {
    throw new Error(`H-045 verification failed: ${label} cannot be opened securely`, {
      cause: error,
    });
  }
  try {
    const [metadata, canonical] = await Promise.all([
      handle.stat({ bigint: true }),
      realpath(`/proc/self/fd/${String(handle.fd)}`),
    ]);
    verificationAssertion(metadata.isDirectory(), `${label} is not a directory`);
    verificationAssertion(canonical === canonicalPath, `${label} is symbolic or non-canonical`);
    verificationAssertion((metadata.mode & 0o777n) === 0o700n, `${label} mode is not 0700`);
    verificationAssertion(effectiveOwnerExact(metadata), `${label} owner is not the verifier`);
    return { path: canonicalPath, metadata, handle };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function assertSecureDirectoryStable(receipt, label) {
  const [metadata, canonical] = await Promise.all([
    receipt.handle.stat({ bigint: true }),
    realpath(`/proc/self/fd/${String(receipt.handle.fd)}`),
  ]);
  verificationAssertion(
    canonical === receipt.path && stableMetadataExact(receipt.metadata, metadata),
    `${label} changed during verification`
  );
}

async function readBoundedFile(handle, maxBytes, label) {
  const chunks = [];
  let total = 0;
  let position = 0;
  while (true) {
    const length = Math.min(64 * 1024, maxBytes - total + 1);
    const buffer = Buffer.allocUnsafe(length);
    const { bytesRead } = await handle.read(buffer, 0, length, position);
    if (bytesRead === 0) break;
    total += bytesRead;
    verificationAssertion(total <= maxBytes, `${label} exceeds its byte limit`);
    chunks.push(buffer.subarray(0, bytesRead));
    position += bytesRead;
  }
  return Buffer.concat(chunks, total);
}

async function secureFile(filePath, label, maxBytes, expectedCanonicalPath = filePath) {
  const accessPath = path.resolve(filePath);
  const canonicalPath = path.resolve(expectedCanonicalPath);
  verificationAssertion(
    pathByteLength(accessPath) <= MAX_LOCAL_PATH_BYTES &&
      pathByteLength(canonicalPath) <= MAX_LOCAL_PATH_BYTES,
    `${label} path exceeds ${MAX_LOCAL_PATH_BYTES} UTF-8 bytes`
  );
  let handle;
  try {
    handle = await open(accessPath, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW);
  } catch (error) {
    throw new Error(`H-045 verification failed: ${label} cannot be opened securely`, {
      cause: error,
    });
  }
  try {
    const [metadata, canonical] = await Promise.all([
      handle.stat({ bigint: true }),
      realpath(`/proc/self/fd/${String(handle.fd)}`),
    ]);
    verificationAssertion(metadata.isFile(), `${label} is not a regular file`);
    verificationAssertion(canonical === canonicalPath, `${label} is symbolic or non-canonical`);
    verificationAssertion((metadata.mode & 0o777n) === 0o600n, `${label} mode is not 0600`);
    verificationAssertion(effectiveOwnerExact(metadata), `${label} owner is not the verifier`);
    verificationAssertion(metadata.nlink === 1n, `${label} has a hard-link alias`);
    verificationAssertion(metadata.size <= BigInt(maxBytes), `${label} exceeds its byte limit`);
    const bytes = await readBoundedFile(handle, maxBytes, label);
    const [metadataAfter, canonicalAfter] = await Promise.all([
      handle.stat({ bigint: true }),
      realpath(`/proc/self/fd/${String(handle.fd)}`),
    ]);
    verificationAssertion(
      canonicalAfter === canonicalPath &&
        stableMetadataExact(metadata, metadataAfter) &&
        metadataAfter.size === BigInt(bytes.byteLength),
      `${label} changed during verification`
    );
    return { path: canonicalPath, metadata, bytes, handle, maxBytes };
  } catch (error) {
    await handle.close();
    throw error;
  }
}

async function assertSecureFileStable(receipt, label) {
  const [metadataBefore, canonicalBefore] = await Promise.all([
    receipt.handle.stat({ bigint: true }),
    realpath(`/proc/self/fd/${String(receipt.handle.fd)}`),
  ]);
  assertSecureFileMetadata(metadataBefore, receipt.bytes.byteLength, label);
  verificationAssertion(canonicalBefore === receipt.path, `${label} changed identity`);
  verificationAssertion(
    stableMetadataExact(receipt.metadata, metadataBefore),
    `${label} changed before final verification`
  );
  const bytes = await readBoundedFile(receipt.handle, receipt.maxBytes, label);
  const [metadataAfter, canonicalAfter] = await Promise.all([
    receipt.handle.stat({ bigint: true }),
    realpath(`/proc/self/fd/${String(receipt.handle.fd)}`),
  ]);
  assertSecureFileMetadata(metadataAfter, receipt.bytes.byteLength, label);
  verificationAssertion(canonicalAfter === receipt.path, `${label} changed identity`);
  verificationAssertion(
    stableMetadataExact(receipt.metadata, metadataAfter) &&
      stableMetadataExact(metadataBefore, metadataAfter) &&
      bytes.equals(receipt.bytes),
    `${label} changed during final verification`
  );
}

async function closeSecureFile(receipt) {
  if (receipt !== undefined) await receipt.handle.close();
}

async function canonicalRunLayout(runPath, expectedArtifactRoot) {
  verificationAssertion(
    typeof runPath === 'string' && path.isAbsolute(runPath),
    'run path must be absolute'
  );
  verificationAssertion(
    typeof expectedArtifactRoot === 'string' && path.isAbsolute(expectedArtifactRoot),
    'artifact root must be absolute'
  );
  const resolvedRunPath = path.resolve(runPath);
  const resolvedArtifactRoot = path.resolve(expectedArtifactRoot);
  verificationAssertion(resolvedRunPath === runPath, 'run path must be normalized');
  verificationAssertion(
    resolvedArtifactRoot === expectedArtifactRoot,
    'artifact root must be normalized'
  );
  verificationAssertion(path.basename(resolvedRunPath) === 'run.json', 'run filename is not exact');
  const runDirectory = path.dirname(resolvedRunPath);
  const artifactRoot = path.dirname(runDirectory);
  verificationAssertion(
    path.basename(artifactRoot) === 'h045' &&
      path.basename(path.dirname(artifactRoot)) === 'artifacts',
    'run is not directly below an artifacts/h045 root'
  );
  verificationAssertion(
    artifactRoot === resolvedArtifactRoot,
    'run is outside the selected artifact root'
  );

  const artifactDirectoryReceipt = await openSecureDirectory(artifactRoot, 'artifact root');
  let runDirectoryReceipt;
  let runFileReceipt;
  try {
    runDirectoryReceipt = await openSecureDirectory(
      directoryDescriptorPath(artifactDirectoryReceipt, path.basename(runDirectory)),
      'run directory',
      runDirectory
    );
    runFileReceipt = await secureFile(
      directoryDescriptorPath(runDirectoryReceipt, 'run.json'),
      'run evidence',
      MAX_RUN_JSON_BYTES,
      resolvedRunPath
    );
    await assertSecureDirectoryStable(runDirectoryReceipt, 'run directory');
    return {
      artifactRoot,
      artifactDirectoryReceipt,
      runDirectory,
      runDirectoryReceipt,
      runFileReceipt,
    };
  } catch (error) {
    await closeSecureFile(runFileReceipt);
    if (runDirectoryReceipt !== undefined) await runDirectoryReceipt.handle.close();
    await artifactDirectoryReceipt.handle.close();
    throw error;
  }
}

async function verifyAttemptLedgerIndependently(run, layout) {
  const ledger = run.collector?.attemptLedger;
  verificationAssertion(
    verifierExactKeys(ledger, [
      'predecessorReservationRelativePath',
      'predecessorFailureRelativePath',
      'predecessorReservationSha256',
      'predecessorFailureSha256',
      'reservationRelativePath',
      'completionRelativePath',
      'reservationSha256',
      'semantics',
    ]),
    'attempt ledger declaration is inexact'
  );
  verificationAssertion(
    ledger.predecessorReservationRelativePath === PREDECESSOR_RESERVATION_RELATIVE_PATH &&
      ledger.predecessorFailureRelativePath === PREDECESSOR_FAILURE_RELATIVE_PATH &&
      ledger.predecessorReservationSha256 === PREDECESSOR_RESERVATION_SHA256 &&
      ledger.predecessorFailureSha256 === PREDECESSOR_FAILURE_SHA256 &&
      ledger.reservationRelativePath === REPLACEMENT_RESERVATION_RELATIVE_PATH &&
      ledger.completionRelativePath === REPLACEMENT_COMPLETION_RELATIVE_PATH &&
      ledger.semantics === 'fixed-local-linked-one-shot-replacement-ledger',
    'attempt ledger declaration changed its linked predecessor and replacement boundary'
  );

  const artifactAnchor = path.dirname(path.dirname(layout.artifactRoot));
  const predecessorDirectory = path.join(layout.artifactRoot, PREDECESSOR_ATTEMPT_DIRECTORY);
  const predecessorReservationPath = path.join(predecessorDirectory, 'reservation.json');
  const predecessorFailurePath = path.join(predecessorDirectory, 'failure.json');
  const replacementDirectory = path.join(layout.artifactRoot, REPLACEMENT_ATTEMPT_DIRECTORY);
  const replacementReservationPath = path.join(replacementDirectory, 'reservation.json');
  const replacementCompletionPath = path.join(replacementDirectory, 'completion.json');
  verificationAssertion(
    path.resolve(artifactAnchor, ledger.predecessorReservationRelativePath) ===
      predecessorReservationPath &&
      path.resolve(artifactAnchor, ledger.predecessorFailureRelativePath) ===
        predecessorFailurePath &&
      path.resolve(artifactAnchor, ledger.reservationRelativePath) === replacementReservationPath &&
      path.resolve(artifactAnchor, ledger.completionRelativePath) === replacementCompletionPath,
    'attempt ledger paths do not resolve to the fixed predecessor and replacement roots'
  );

  let predecessorDirectoryReceipt;
  let predecessorReservationFile;
  let predecessorFailureFile;
  let replacementDirectoryReceipt;
  let replacementReservationFile;
  let replacementCompletionFile;
  try {
    predecessorDirectoryReceipt = await openSecureDirectory(
      directoryDescriptorPath(layout.artifactDirectoryReceipt, PREDECESSOR_ATTEMPT_DIRECTORY),
      'predecessor attempt ledger directory',
      predecessorDirectory
    );
    const predecessorDescriptorPath = directoryDescriptorPath(predecessorDirectoryReceipt);
    let predecessorEntriesBefore;
    try {
      predecessorEntriesBefore = (await readdir(predecessorDescriptorPath)).sort();
    } catch (error) {
      throw new Error(
        'H-045 verification failed: predecessor attempt ledger cannot be enumerated',
        { cause: error }
      );
    }
    verificationAssertion(
      verifierSame(predecessorEntriesBefore, ['failure.json', 'reservation.json']),
      'predecessor attempt ledger must contain exactly reservation and failure with no completion or run'
    );

    predecessorReservationFile = await secureFile(
      directoryDescriptorPath(predecessorDirectoryReceipt, 'reservation.json'),
      'predecessor attempt reservation',
      MAX_LEDGER_RECEIPT_BYTES,
      predecessorReservationPath
    );
    predecessorFailureFile = await secureFile(
      directoryDescriptorPath(predecessorDirectoryReceipt, 'failure.json'),
      'predecessor attempt failure',
      MAX_LEDGER_RECEIPT_BYTES,
      predecessorFailurePath
    );
    let predecessorReservation;
    let predecessorFailure;
    try {
      predecessorReservation = JSON.parse(predecessorReservationFile.bytes.toString('utf8'));
      predecessorFailure = JSON.parse(predecessorFailureFile.bytes.toString('utf8'));
    } catch (error) {
      throw new Error(
        'H-045 verification failed: predecessor attempt ledger contains invalid JSON',
        { cause: error }
      );
    }

    const expectedPredecessorReservation = {
      schemaVersion: 'overlaykit-h045-live-attempt-reservation/v1',
      reservedAt: '2026-07-27T17:19:02.332Z',
      change: 'CHG-0019',
      hypothesis: 'H-045',
      authorization: {
        grant: PREDECESSOR_AUTHORIZATION,
        sourceSetSha256: PREDECESSOR_SOURCE_SET_SHA256,
        semantics: 'one-live-read-only-attempt',
        authority: 'none',
        action: null,
      },
    };
    verificationAssertion(
      predecessorReservationFile.bytes.equals(prettyJsonBytes(expectedPredecessorReservation)) &&
        verifierSame(predecessorReservation, expectedPredecessorReservation) &&
        digestBytes(predecessorReservationFile.bytes) === PREDECESSOR_RESERVATION_SHA256,
      'predecessor attempt reservation bytes are not exact'
    );
    const expectedPredecessorFailure = {
      schemaVersion: 'overlaykit-h045-live-attempt-failure/v1',
      reservationSha256: PREDECESSOR_RESERVATION_SHA256,
      stage: 'runtime-admission',
      observationStarted: true,
    };
    verificationAssertion(
      predecessorFailureFile.bytes.equals(prettyJsonBytes(expectedPredecessorFailure)) &&
        verifierSame(predecessorFailure, expectedPredecessorFailure) &&
        digestBytes(predecessorFailureFile.bytes) === PREDECESSOR_FAILURE_SHA256,
      'predecessor attempt failure bytes are not exact'
    );

    replacementDirectoryReceipt = await openSecureDirectory(
      directoryDescriptorPath(layout.artifactDirectoryReceipt, REPLACEMENT_ATTEMPT_DIRECTORY),
      'replacement attempt ledger directory',
      replacementDirectory
    );
    const replacementDescriptorPath = directoryDescriptorPath(replacementDirectoryReceipt);
    let replacementEntriesBefore;
    try {
      replacementEntriesBefore = (await readdir(replacementDescriptorPath)).sort();
    } catch (error) {
      throw new Error(
        'H-045 verification failed: replacement attempt ledger cannot be enumerated',
        { cause: error }
      );
    }
    verificationAssertion(
      verifierSame(replacementEntriesBefore, ['completion.json', 'reservation.json']),
      'replacement attempt ledger must contain exactly reservation and completion with no failure'
    );

    replacementReservationFile = await secureFile(
      directoryDescriptorPath(replacementDirectoryReceipt, 'reservation.json'),
      'replacement attempt reservation',
      MAX_LEDGER_RECEIPT_BYTES,
      replacementReservationPath
    );
    replacementCompletionFile = await secureFile(
      directoryDescriptorPath(replacementDirectoryReceipt, 'completion.json'),
      'replacement attempt completion',
      MAX_LEDGER_RECEIPT_BYTES,
      replacementCompletionPath
    );
    let replacementReservation;
    let replacementCompletion;
    try {
      replacementReservation = JSON.parse(replacementReservationFile.bytes.toString('utf8'));
      replacementCompletion = JSON.parse(replacementCompletionFile.bytes.toString('utf8'));
    } catch (error) {
      throw new Error(
        'H-045 verification failed: replacement attempt ledger contains invalid JSON',
        { cause: error }
      );
    }

    const expectedReplacementReservation = {
      schemaVersion: 'overlaykit-h045-live-attempt-reservation/v2',
      reservedAt: run.startedAt,
      change: 'CHG-0020',
      hypothesis: 'H-045',
      attempt: REPLACEMENT_ATTEMPT_ID,
      predecessor: {
        reservationSha256: PREDECESSOR_RESERVATION_SHA256,
        failureSha256: PREDECESSOR_FAILURE_SHA256,
      },
      authorization: {
        grant: run.collector.reviewAuthorization.grant,
        sourceSetSha256: run.collector.reviewAuthorization.sourceSetSha256,
        semantics: 'one-live-read-only-replacement-attempt',
        authority: 'none',
        action: null,
      },
    };
    verificationAssertion(
      replacementReservationFile.bytes.equals(prettyJsonBytes(expectedReplacementReservation)) &&
        verifierSame(replacementReservation, expectedReplacementReservation),
      'replacement attempt reservation bytes are not exact'
    );
    const replacementReservationSha256 = digestBytes(replacementReservationFile.bytes);
    verificationAssertion(
      ledger.reservationSha256 === replacementReservationSha256,
      'replacement attempt reservation digest does not match run evidence'
    );

    const expectedReplacementCompletion = {
      schemaVersion: 'overlaykit-h045-live-attempt-completion/v2',
      reservationSha256: replacementReservationSha256,
      completedAt: run.completedAt,
      evidenceSha256: run.evidenceSha256,
    };
    verificationAssertion(
      replacementCompletionFile.bytes.equals(prettyJsonBytes(expectedReplacementCompletion)) &&
        verifierSame(replacementCompletion, expectedReplacementCompletion),
      'replacement attempt completion bytes are not exact'
    );

    let predecessorEntriesAfter;
    let replacementEntriesAfter;
    try {
      [predecessorEntriesAfter, replacementEntriesAfter] = await Promise.all([
        readdir(predecessorDescriptorPath).then((entries) => entries.sort()),
        readdir(replacementDescriptorPath).then((entries) => entries.sort()),
      ]);
    } catch (error) {
      throw new Error('H-045 verification failed: linked attempt ledgers cannot be rescanned', {
        cause: error,
      });
    }
    verificationAssertion(
      verifierSame(predecessorEntriesAfter, predecessorEntriesBefore) &&
        verifierSame(predecessorEntriesAfter, ['failure.json', 'reservation.json']),
      'predecessor attempt ledger changed or gained completion or run after receipt reads'
    );
    verificationAssertion(
      verifierSame(replacementEntriesAfter, replacementEntriesBefore) &&
        verifierSame(replacementEntriesAfter, ['completion.json', 'reservation.json']),
      'replacement attempt ledger changed or contains a failure after receipt reads'
    );
    await assertSecureFileStable(predecessorReservationFile, 'predecessor attempt reservation');
    await assertSecureFileStable(predecessorFailureFile, 'predecessor attempt failure');
    await assertSecureFileStable(replacementReservationFile, 'replacement attempt reservation');
    await assertSecureFileStable(replacementCompletionFile, 'replacement attempt completion');
    await assertSecureDirectoryStable(
      predecessorDirectoryReceipt,
      'predecessor attempt ledger directory'
    );
    await assertSecureDirectoryStable(
      replacementDirectoryReceipt,
      'replacement attempt ledger directory'
    );
    await assertSecureDirectoryStable(layout.artifactDirectoryReceipt, 'artifact root');

    return {
      verification: {
        exact: true,
        artifactLayoutExact: true,
        predecessorExact: true,
        predecessorCompletionAbsent: true,
        predecessorRunAbsent: true,
        predecessorReservationSha256: PREDECESSOR_RESERVATION_SHA256,
        predecessorFailureSha256: PREDECESSOR_FAILURE_SHA256,
        replacementExact: true,
        replacementFailureAbsent: true,
        replacementReservationSha256,
        replacementCompletionSha256: digestBytes(replacementCompletionFile.bytes),
      },
      predecessorDirectoryReceipt,
      predecessorReservationFile,
      predecessorFailureFile,
      replacementDirectoryReceipt,
      replacementReservationFile,
      replacementCompletionFile,
    };
  } catch (error) {
    await Promise.allSettled([
      closeSecureFile(replacementCompletionFile),
      closeSecureFile(replacementReservationFile),
      replacementDirectoryReceipt?.handle.close(),
      closeSecureFile(predecessorFailureFile),
      closeSecureFile(predecessorReservationFile),
      predecessorDirectoryReceipt?.handle.close(),
    ]);
    throw error;
  }
}

async function assertAttemptLedgerStable(session, layout) {
  const predecessorDescriptor = directoryDescriptorPath(session.predecessorDirectoryReceipt);
  const replacementDescriptor = directoryDescriptorPath(session.replacementDirectoryReceipt);
  let predecessorEntries;
  let replacementEntries;
  try {
    [predecessorEntries, replacementEntries] = await Promise.all([
      readdir(predecessorDescriptor).then((entries) => entries.sort()),
      readdir(replacementDescriptor).then((entries) => entries.sort()),
    ]);
  } catch (error) {
    throw new Error(
      'H-045 verification failed: linked attempt ledgers cannot be rescanned at cutoff',
      { cause: error }
    );
  }
  verificationAssertion(
    verifierSame(predecessorEntries, ['failure.json', 'reservation.json']),
    'predecessor attempt ledger changed before verification cutoff'
  );
  verificationAssertion(
    verifierSame(replacementEntries, ['completion.json', 'reservation.json']),
    'replacement attempt ledger changed before verification cutoff'
  );
  await assertSecureFileStable(
    session.predecessorReservationFile,
    'predecessor attempt reservation'
  );
  await assertSecureFileStable(session.predecessorFailureFile, 'predecessor attempt failure');
  await assertSecureFileStable(
    session.replacementReservationFile,
    'replacement attempt reservation'
  );
  await assertSecureFileStable(session.replacementCompletionFile, 'replacement attempt completion');
  await assertSecureDirectoryStable(
    session.predecessorDirectoryReceipt,
    'predecessor attempt ledger directory'
  );
  await assertSecureDirectoryStable(
    session.replacementDirectoryReceipt,
    'replacement attempt ledger directory'
  );
  await assertSecureDirectoryStable(layout.artifactDirectoryReceipt, 'artifact root');
}

async function closeAttemptLedgerSession(session) {
  if (session === undefined) return;
  await Promise.allSettled([
    closeSecureFile(session.replacementCompletionFile),
    closeSecureFile(session.replacementReservationFile),
    session.replacementDirectoryReceipt.handle.close(),
    closeSecureFile(session.predecessorFailureFile),
    closeSecureFile(session.predecessorReservationFile),
    session.predecessorDirectoryReceipt.handle.close(),
  ]);
}

async function refreshSecureDirectoryAfterExpectedMutation(receipt, label) {
  const [metadata, canonical] = await Promise.all([
    receipt.handle.stat({ bigint: true }),
    realpath(`/proc/self/fd/${String(receipt.handle.fd)}`),
  ]);
  verificationAssertion(metadata.isDirectory(), `${label} is no longer a directory`);
  verificationAssertion(canonical === receipt.path, `${label} changed identity`);
  verificationAssertion((metadata.mode & 0o777n) === 0o700n, `${label} mode is not 0700`);
  verificationAssertion(effectiveOwnerExact(metadata), `${label} owner is not the verifier`);
  receipt.metadata = metadata;
}

async function invalidateAndRemoveFailedPublication(
  layout,
  stagingHandle,
  { finalLinked = false } = {}
) {
  const cleanupErrors = [];
  const invalidation = Buffer.from(
    `${JSON.stringify({
      schemaVersion: 'overlaykit-h045-verification-invalid/v1',
      verified: false,
    })}\n`,
    'utf8'
  );
  if (stagingHandle !== undefined) {
    try {
      await stagingHandle.truncate(0);
      await stagingHandle.write(invalidation, 0, invalidation.byteLength, 0);
      await stagingHandle.truncate(invalidation.byteLength);
      await stagingHandle.sync();
    } catch (error) {
      cleanupErrors.push(error);
    }
  }
  const names = [...(finalLinked ? [VERIFICATION_FILENAME] : []), VERIFICATION_STAGING_FILENAME];
  for (const name of names) {
    try {
      await unlink(directoryDescriptorPath(layout.runDirectoryReceipt, name));
    } catch (error) {
      if (error?.code !== 'ENOENT') cleanupErrors.push(error);
    }
  }
  try {
    await layout.runDirectoryReceipt.handle.sync();
  } catch (error) {
    cleanupErrors.push(error);
  }
  return cleanupErrors;
}

async function publishVerificationExclusive(
  layout,
  verification,
  { beforeCommit = async () => {}, afterLink = async () => {} } = {}
) {
  verificationAssertion(
    typeof beforeCommit === 'function' && typeof afterLink === 'function',
    'verification publication hooks are invalid'
  );
  const bytes = prettyJsonBytes(verification);
  verificationAssertion(
    bytes.byteLength <= MAX_VERIFICATION_JSON_BYTES,
    `verification evidence exceeds ${MAX_VERIFICATION_JSON_BYTES} bytes`
  );
  await assertSecureFileStable(layout.runFileReceipt, 'run evidence');
  await assertSecureDirectoryStable(layout.runDirectoryReceipt, 'run directory');
  await assertSecureDirectoryStable(layout.artifactDirectoryReceipt, 'artifact root');

  const directoryPath = directoryDescriptorPath(layout.runDirectoryReceipt);
  const entriesBefore = (await readdir(directoryPath)).sort();
  verificationAssertion(
    verifierSame(entriesBefore, ['run.json']),
    'run directory must contain exactly run.json before verification publication'
  );

  const stagingPath = path.join(layout.runDirectory, VERIFICATION_STAGING_FILENAME);
  const outputPath = path.join(layout.runDirectory, VERIFICATION_FILENAME);
  verificationAssertion(
    pathByteLength(stagingPath) <= MAX_LOCAL_PATH_BYTES &&
      pathByteLength(outputPath) <= MAX_LOCAL_PATH_BYTES,
    `verification evidence path exceeds ${MAX_LOCAL_PATH_BYTES} UTF-8 bytes`
  );
  let stagingHandle;
  let finalReceipt;
  let finalLinked = false;
  try {
    stagingHandle = await open(
      directoryDescriptorPath(layout.runDirectoryReceipt, VERIFICATION_STAGING_FILENAME),
      FS_CONSTANTS.O_RDWR | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_NOFOLLOW,
      0o600
    );
    await stagingHandle.chmod(0o600);
    const [initial, initialCanonical] = await Promise.all([
      stagingHandle.stat({ bigint: true }),
      realpath(`/proc/self/fd/${String(stagingHandle.fd)}`),
    ]);
    verificationAssertion(initial.isFile(), 'staged verification is not a regular file');
    verificationAssertion(initialCanonical === stagingPath, 'staged verification changed identity');
    verificationAssertion(
      (initial.mode & 0o777n) === 0o600n,
      'staged verification mode is not 0600'
    );
    verificationAssertion(
      effectiveOwnerExact(initial),
      'staged verification owner is not the verifier'
    );
    verificationAssertion(initial.nlink === 1n, 'staged verification has a hard-link alias');
    verificationAssertion(initial.size === 0n, 'new staged verification is not empty');

    await stagingHandle.writeFile(bytes);
    await stagingHandle.sync();
    const metadata = await stagingHandle.stat({ bigint: true });
    const stagingReceipt = {
      path: stagingPath,
      metadata,
      bytes,
      handle: stagingHandle,
      maxBytes: MAX_VERIFICATION_JSON_BYTES,
    };
    await assertSecureFileStable(stagingReceipt, 'staged verification');
    await refreshSecureDirectoryAfterExpectedMutation(layout.runDirectoryReceipt, 'run directory');
    const stagedEntries = (await readdir(directoryPath)).sort();
    verificationAssertion(
      verifierSame(stagedEntries, [VERIFICATION_STAGING_FILENAME, 'run.json'].sort()),
      'run directory changed during verification staging'
    );
    await layout.runDirectoryReceipt.handle.sync();

    await assertSecureFileStable(stagingReceipt, 'staged verification');
    await assertSecureDirectoryStable(layout.runDirectoryReceipt, 'run directory');
    await assertSecureDirectoryStable(layout.artifactDirectoryReceipt, 'artifact root');
    await beforeCommit();

    await link(
      directoryDescriptorPath(layout.runDirectoryReceipt, VERIFICATION_STAGING_FILENAME),
      directoryDescriptorPath(layout.runDirectoryReceipt, VERIFICATION_FILENAME)
    );
    finalLinked = true;
    await afterLink({ stagingHandle });
    await unlink(
      directoryDescriptorPath(layout.runDirectoryReceipt, VERIFICATION_STAGING_FILENAME)
    );

    finalReceipt = await secureFile(
      directoryDescriptorPath(layout.runDirectoryReceipt, VERIFICATION_FILENAME),
      'verification evidence',
      MAX_VERIFICATION_JSON_BYTES,
      outputPath
    );
    verificationAssertion(
      finalReceipt.metadata.dev === stagingReceipt.metadata.dev &&
        finalReceipt.metadata.ino === stagingReceipt.metadata.ino &&
        finalReceipt.bytes.equals(bytes),
      'verification publication changed its staged inode or bytes'
    );
    await refreshSecureDirectoryAfterExpectedMutation(layout.runDirectoryReceipt, 'run directory');
    const committedEntries = (await readdir(directoryPath)).sort();
    verificationAssertion(
      verifierSame(committedEntries, ['run.json', VERIFICATION_FILENAME]),
      'run directory changed during verification commit'
    );
    await layout.runDirectoryReceipt.handle.sync();
    await assertSecureFileStable(finalReceipt, 'verification evidence');
    await assertSecureDirectoryStable(layout.runDirectoryReceipt, 'run directory');
    await assertSecureDirectoryStable(layout.artifactDirectoryReceipt, 'artifact root');
    await stagingHandle.close();
    stagingHandle = undefined;
    return { path: outputPath, receipt: finalReceipt };
  } catch (error) {
    const cleanupErrors = await invalidateAndRemoveFailedPublication(layout, stagingHandle, {
      finalLinked,
    });
    await Promise.allSettled([closeSecureFile(finalReceipt), stagingHandle?.close()]);
    if (cleanupErrors.length > 0) {
      throw new AggregateError(
        [error, ...cleanupErrors],
        'H-045 verification publication failed and cleanup was incomplete'
      );
    }
    throw error;
  }
}

async function sha256File(filePath) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filePath)) hash.update(chunk);
  return hash.digest('hex');
}

async function collectSourceReceipts() {
  return Promise.all(
    INDEPENDENT_REQUIRED_SOURCE_PATHS.map(async (relativePath) => ({
      path: relativePath,
      sha256: await sha256File(path.join(REPOSITORY_ROOT, relativePath)),
    }))
  );
}

function uniqueReceiptCapture(text, pattern, label) {
  const matches = [...text.matchAll(pattern)];
  verificationAssertion(
    matches.length === 1 && typeof matches[0][1] === 'string',
    `public H-044 receipt lacks one ${label}`
  );
  return matches[0][1];
}

function independentlyAdmitHistoricalReceipt(receiptBytes, decisionBytes) {
  const receiptHash = digestBytes(receiptBytes);
  const decisionHash = digestBytes(decisionBytes);
  const text = receiptBytes.toString('utf8');
  let decision;
  try {
    decision = JSON.parse(decisionBytes.toString('utf8'));
  } catch {
    decision = null;
  }
  const canonical = {
    runId: uniqueReceiptCapture(text, /^- Run: `([^`\r\n]+)`$/gmu, 'run identity'),
    outcome: uniqueReceiptCapture(
      text,
      /^- Hypothesis outcome: `([^`\r\n]+)`$/gmu,
      'hypothesis outcome'
    ),
    disposition: uniqueReceiptCapture(
      text,
      /^- Live classification: `([^`\r\n]+)`$/gmu,
      'live classification'
    ),
    stage: uniqueReceiptCapture(text, /^- Stage: `([^`\r\n]+)`$/gmu, 'stage'),
    reasonCode: uniqueReceiptCapture(text, /^- Reason: `([^`\r\n]+)`$/gmu, 'reason'),
    candidateReceipts: Number.parseInt(
      uniqueReceiptCapture(
        text,
        /^- Candidate receipts: `([0-9]+)`$/gmu,
        'candidate receipt count'
      ),
      10
    ),
    semanticEvidenceSha256: uniqueReceiptCapture(
      text,
      /^- Semantic evidence SHA-256:\r?\n  `([0-9a-f]{64})`$/gmu,
      'semantic evidence digest'
    ),
  };
  const targetMatches =
    typeof decision?.context === 'string'
      ? [
          ...decision.context.matchAll(
            /official Companion v4\.3\.3 image reference (\S+) with image ID (sha256:[0-9a-f]{64}), and physical Stream Deck MK\.2 serial ([A-Z][A-Z0-9]+)\./gu
          ),
        ]
      : [];
  const target = targetMatches.length === 1 ? targetMatches[0] : null;
  const publicReceiptExact =
    receiptHash === H044_PUBLIC_RECEIPT_SHA256 &&
    receiptBytes.byteLength === H044_PUBLIC_RECEIPT_BYTE_LENGTH;
  const semanticsExact =
    canonical.runId === H044_RUN_ID &&
    canonical.outcome === 'supported' &&
    canonical.disposition === 'withheld' &&
    canonical.stage === 'not-eligible' &&
    canonical.reasonCode === 'historical-container-absent' &&
    canonical.candidateReceipts === 0 &&
    canonical.semanticEvidenceSha256 === H044_EVIDENCE_SHA256;
  const decisionExact =
    decisionHash === ADR_0006_SHA256 &&
    decision?.schemaVersion === 'overlaykit-governance-decision/v1' &&
    decision?.id === 'ADR-0006' &&
    decision?.status === 'accepted';
  const targetExact =
    target !== null &&
    target[1] === ACCEPTED_IMAGE_REFERENCE &&
    target[2] === ACCEPTED_IMAGE_ID &&
    target[3] === ACCEPTED_SERIAL &&
    digestBytes(target[3]) === ACCEPTED_SERIAL_SHA256;
  const boundaryExact =
    text.includes('The raw replay bundle is deliberately not tracked.') &&
    text.includes('This receipt grants no signal target, action, watcher, restart,') &&
    text.includes('installation, production policy, product acceptance, or future authority.');
  return {
    publicReceiptExact,
    semanticsExact,
    decisionExact,
    targetExact,
    boundaryExact,
  };
}

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

function normalizedInputKey(value) {
  return value.toLowerCase().replaceAll(/[^a-z0-9]/gu, '');
}

function containsVolatileTarget(value, seen = new WeakSet()) {
  if (value === null || typeof value !== 'object') return false;
  if (seen.has(value)) return true;
  seen.add(value);
  if (Array.isArray(value)) return value.some((entry) => containsVolatileTarget(entry, seen));
  return Object.entries(value).some(
    ([key, nested]) =>
      FORBIDDEN_VOLATILE_TARGET_KEYS.has(normalizedInputKey(key)) ||
      containsVolatileTarget(nested, seen)
  );
}

function inputExact(input) {
  return (
    !containsVolatileTarget(input) &&
    verifierExactKeys(input, [
      'imageReference',
      'imageId',
      'vendorId',
      'productId',
      'serialBinding',
    ]) &&
    input.imageReference === ACCEPTED_IMAGE_REFERENCE &&
    input.imageId === ACCEPTED_IMAGE_ID &&
    input.vendorId === ACCEPTED_VENDOR_ID &&
    input.productId === ACCEPTED_PRODUCT_ID &&
    verifierSame(input.serialBinding, SERIAL_BINDING)
  );
}

function acceptedTargetExact(target) {
  return (
    verifierExactKeys(target, [
      'imageReference',
      'imageId',
      'vendorId',
      'productId',
      'serial',
      'serialBinding',
    ]) &&
    target.imageReference === ACCEPTED_IMAGE_REFERENCE &&
    target.imageId === ACCEPTED_IMAGE_ID &&
    target.vendorId === ACCEPTED_VENDOR_ID &&
    target.productId === ACCEPTED_PRODUCT_ID &&
    target.serial === ACCEPTED_SERIAL &&
    digestBytes(target.serial) === ACCEPTED_SERIAL_SHA256 &&
    verifierSame(target.serialBinding, SERIAL_BINDING)
  );
}

function sourceMapShapeExact(sources) {
  return (
    Array.isArray(sources) &&
    sources.length === INDEPENDENT_REQUIRED_SOURCE_PATHS.length &&
    sources.every(
      (entry, index) =>
        verifierExactKeys(entry, ['path', 'sha256']) &&
        entry.path === INDEPENDENT_REQUIRED_SOURCE_PATHS[index] &&
        typeof entry.sha256 === 'string' &&
        /^[0-9a-f]{64}$/u.test(entry.sha256)
    )
  );
}

function independentSourceSetSha256(sources) {
  if (!sourceMapShapeExact(sources)) return null;
  return digestBytes(
    Buffer.from(
      JSON.stringify(sources.map(({ path: sourcePath, sha256 }) => ({ path: sourcePath, sha256 }))),
      'utf8'
    )
  );
}

function reviewAuthorizationExact(value, sourcesBefore, sourcesAfter) {
  const beforeDigest = independentSourceSetSha256(sourcesBefore);
  const afterDigest = independentSourceSetSha256(sourcesAfter);
  return (
    beforeDigest !== null &&
    beforeDigest === afterDigest &&
    verifierExactKeys(value, ['grant', 'sourceSetSha256', 'semantics']) &&
    value.grant === `${LIVE_AUTHORIZATION_PREFIX}${beforeDigest}` &&
    value.sourceSetSha256 === beforeDigest &&
    value.semantics === 'one-live-read-only-replacement-attempt'
  );
}

async function repositoryAndSourceEvidence(run) {
  const [
    currentSources,
    manifestBytes,
    planBytes,
    chg0018Bytes,
    chg0019Bytes,
    chg0020Bytes,
    adr0006Bytes,
    publicReceiptBytes,
    currentRuntimeStat,
    currentRuntimeSha256,
  ] = await Promise.all([
    collectSourceReceipts(),
    readFile(path.join(REPOSITORY_ROOT, '.overlaykit/governance/manifest.json')),
    readFile(path.join(REPOSITORY_ROOT, '.overlaykit/governance/plan.json')),
    readFile(path.join(REPOSITORY_ROOT, '.overlaykit/governance/changes/CHG-0018.json')),
    readFile(path.join(REPOSITORY_ROOT, '.overlaykit/governance/changes/CHG-0019.json')),
    readFile(path.join(REPOSITORY_ROOT, '.overlaykit/governance/changes/CHG-0020.json')),
    readFile(path.join(REPOSITORY_ROOT, '.overlaykit/governance/decisions/ADR-0006.json')),
    readFile(path.join(REPOSITORY_ROOT, H044_PUBLIC_RECEIPT_RELATIVE_PATH)),
    stat(process.execPath),
    sha256File(process.execPath),
  ]);
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const plan = JSON.parse(planBytes.toString('utf8'));
  const historical = independentlyAdmitHistoricalReceipt(publicReceiptBytes, adr0006Bytes);
  const governance = run.collector?.governance;
  const governanceReceiptExact =
    verifierExactKeys(governance, ['historical', 'governance']) === false &&
    verifierExactKeys(governance, [
      'verified',
      'planHash',
      'planSha256',
      'manifestContentHash',
      'manifestSha256',
      'changes',
      'decisions',
      'requiredSourcePaths',
    ]) &&
    governance.verified === true &&
    governance.planHash === PLAN_HASH &&
    governance.planSha256 === GOVERNANCE_PLAN_SHA256 &&
    governance.manifestContentHash === MANIFEST_CONTENT_HASH &&
    governance.manifestSha256 === GOVERNANCE_MANIFEST_SHA256 &&
    verifierSame(governance.changes, {
      'CHG-0018': CHG_0018_SHA256,
      'CHG-0019': CHG_0019_SHA256,
      'CHG-0020': CHG_0020_SHA256,
    }) &&
    verifierSame(governance.decisions, { 'ADR-0006': ADR_0006_SHA256 }) &&
    verifierSame(governance.requiredSourcePaths, INDEPENDENT_REQUIRED_SOURCE_PATHS);
  const governanceExact =
    plan.planHash === PLAN_HASH &&
    digestBytes(planBytes) === GOVERNANCE_PLAN_SHA256 &&
    manifest.planHash === PLAN_HASH &&
    manifest.contentHash === MANIFEST_CONTENT_HASH &&
    digestBytes(manifestBytes) === GOVERNANCE_MANIFEST_SHA256 &&
    digestBytes(chg0018Bytes) === CHG_0018_SHA256 &&
    digestBytes(chg0019Bytes) === CHG_0019_SHA256 &&
    digestBytes(chg0020Bytes) === CHG_0020_SHA256 &&
    digestBytes(adr0006Bytes) === ADR_0006_SHA256 &&
    manifest.changes?.['CHG-0018'] === CHG_0018_SHA256 &&
    manifest.changes?.['CHG-0019'] === CHG_0019_SHA256 &&
    manifest.changes?.['CHG-0020'] === CHG_0020_SHA256 &&
    manifest.decisions?.['ADR-0006'] === ADR_0006_SHA256 &&
    governanceReceiptExact;
  const governancePlanBytesExact = digestBytes(planBytes) === GOVERNANCE_PLAN_SHA256;
  const governanceManifestBytesExact = digestBytes(manifestBytes) === GOVERNANCE_MANIFEST_SHA256;
  const runtimeReceiptExact =
    verifierExactKeys(run.collector?.runtime, [
      'node',
      'platform',
      'arch',
      'binarySha256',
      'binaryByteLength',
    ]) &&
    run.collector.runtime.node === NODE_VERSION &&
    run.collector.runtime.platform === NODE_PLATFORM &&
    run.collector.runtime.arch === NODE_ARCH &&
    run.collector.runtime.binarySha256 === NODE_BINARY_SHA256 &&
    run.collector.runtime.binaryByteLength === NODE_BINARY_BYTE_LENGTH;
  const verifierRuntimeExact =
    process.version === NODE_VERSION &&
    process.platform === NODE_PLATFORM &&
    process.arch === NODE_ARCH &&
    currentRuntimeSha256 === NODE_BINARY_SHA256 &&
    currentRuntimeStat.size === NODE_BINARY_BYTE_LENGTH;
  const sourcesBeforeShape = sourceMapShapeExact(run.collector?.sourcesBefore);
  const sourcesAfterShape = sourceMapShapeExact(run.collector?.sourcesAfter);
  const sourcesBeforeExact =
    sourcesBeforeShape && verifierSame(run.collector.sourcesBefore, currentSources);
  const sourcesAfterExact =
    sourcesAfterShape && verifierSame(run.collector.sourcesAfter, currentSources);
  const sourceSetExact = sourcesBeforeExact && sourcesAfterExact;
  const sourceStable =
    sourceSetExact &&
    run.collector.sourceStable === true &&
    verifierSame(run.collector.sourcesBefore, run.collector.sourcesAfter);
  const reviewedSourcesExact = reviewAuthorizationExact(
    run.collector?.reviewAuthorization,
    run.collector?.sourcesBefore,
    run.collector?.sourcesAfter
  );
  const collectorIdentityExact =
    verifierExactKeys(run.collector, [
      'reviewAuthorization',
      'attemptLedger',
      'runtime',
      'repository',
      'observedHead',
      'protectedMain',
      'sourceContract',
      'sourcesBefore',
      'sourcesAfter',
      'sourceStable',
      'governance',
    ]) &&
    reviewedSourcesExact &&
    run.collector.repository === REPOSITORY &&
    GIT_COMMIT_PATTERN.test(run.collector.observedHead ?? '') &&
    verifierSame(run.collector.protectedMain, {
      commit: PROTECTED_MAIN_COMMIT,
      isAncestor: true,
    }) &&
    verifierSame(run.collector.sourceContract, {
      commit: SOURCE_CONTRACT_COMMIT,
      isAncestor: true,
    });
  return {
    currentSources,
    historical,
    governanceExact,
    governancePlanBytesExact,
    governanceManifestBytesExact,
    runtimeReceiptExact,
    verifierRuntimeExact,
    sourceSetExact,
    sourceStable,
    reviewedSourcesExact,
    collectorIdentityExact,
    changesExact: {
      chg0018: digestBytes(chg0018Bytes) === CHG_0018_SHA256,
      chg0019: digestBytes(chg0019Bytes) === CHG_0019_SHA256,
      chg0020: digestBytes(chg0020Bytes) === CHG_0020_SHA256,
      adr0006: digestBytes(adr0006Bytes) === ADR_0006_SHA256,
    },
  };
}

function reconstructSourceAdmission(run, repositoryEvidence, gitReceiptsExact) {
  const value = {
    h044PublicReceiptExact: repositoryEvidence.historical.publicReceiptExact,
    h044SemanticEvidenceExact: repositoryEvidence.historical.semanticsExact,
    acceptedDecisionExact: repositoryEvidence.historical.decisionExact,
    acceptedTargetContextExact: repositoryEvidence.historical.targetExact,
    historicalBoundaryExact: repositoryEvidence.historical.boundaryExact,
    chg0018Exact: repositoryEvidence.changesExact.chg0018,
    chg0019Exact: repositoryEvidence.changesExact.chg0019,
    chg0020Exact: repositoryEvidence.changesExact.chg0020,
    adr0006Exact: repositoryEvidence.changesExact.adr0006,
    repositoryRemoteExact:
      repositoryEvidence.collectorIdentityExact && run.collector.repository === REPOSITORY,
    observedHeadWellFormed: GIT_COMMIT_PATTERN.test(run.collector?.observedHead ?? ''),
    protectedMainExact: run.collector?.protectedMain?.commit === PROTECTED_MAIN_COMMIT,
    sourceContractExact: run.collector?.sourceContract?.commit === SOURCE_CONTRACT_COMMIT,
    protectedMainAncestryExact:
      run.collector?.protectedMain?.isAncestor === true && gitReceiptsExact,
    sourceContractAncestryExact:
      run.collector?.sourceContract?.isAncestor === true && gitReceiptsExact,
    runtimeBinaryExact:
      repositoryEvidence.runtimeReceiptExact && repositoryEvidence.verifierRuntimeExact,
    targetInputExact: inputExact(run.input),
    governanceExact: repositoryEvidence.governanceExact,
    sourceSetExact: repositoryEvidence.sourceSetExact,
    sourceStable: repositoryEvidence.sourceStable,
    allExact: false,
  };
  value.allExact = Object.entries(value)
    .filter(([key]) => key !== 'allExact')
    .every(([, exact]) => exact === true);
  return value;
}

// Independent semantic implementation. It deliberately carries its own literals and
// never imports producer decisions at runtime.
function parserText(value, label) {
  if (typeof value !== 'string') throw new TypeError(`${label} must be exact UTF-8 text`);
  return value;
}

function parserRequiredString(value, label) {
  if (typeof value !== 'string' || value === '' || value.includes('\u0000')) {
    throw new TypeError(`${label} must be a non-empty NUL-free string`);
  }
  return value;
}

function parserDecimal(value, label, { positive = false } = {}) {
  const text = parserRequiredString(String(value), label);
  if (!/^(?:0|[1-9][0-9]*)$/u.test(text)) {
    throw new TypeError(`${label} must be an unsigned decimal integer`);
  }
  const parsed = BigInt(text);
  if ((positive && parsed <= 0n) || parsed > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError(`${label} is outside the supported range`);
  }
  return Number(parsed);
}

function parserUsbId(value, label) {
  const text = parserRequiredString(value, label).toLowerCase();
  if (!/^[0-9a-f]{1,8}$/u.test(text)) throw new TypeError(`${label} must be hexadecimal`);
  const parsed = BigInt(`0x${text}`);
  if (parsed > 0xffffn) throw new RangeError(`${label} exceeds the USB identifier range`);
  return parsed.toString(16).padStart(4, '0');
}

function parseOsRelease(value) {
  const properties = {};
  for (const rawLine of parserText(value, 'os-release').split(/\r?\n/u)) {
    if (rawLine === '' || rawLine.startsWith('#')) continue;
    const separator = rawLine.indexOf('=');
    if (separator <= 0) throw new Error('os-release record is malformed');
    const key = rawLine.slice(0, separator);
    if (Object.hasOwn(properties, key)) throw new Error(`duplicate os-release field ${key}`);
    properties[key] = rawLine.slice(separator + 1);
  }
  function unquote(text) {
    if (text.startsWith('"') && text.endsWith('"')) {
      return text.slice(1, -1).replaceAll('\\"', '"').replaceAll('\\\\', '\\');
    }
    if (/^[A-Za-z0-9._+-]+$/u.test(text)) return text;
    throw new Error('os-release value uses an unsupported encoding');
  }
  for (const key of ['ID', 'VERSION_ID', 'PRETTY_NAME']) {
    if (typeof properties[key] !== 'string' || properties[key] === '') {
      throw new Error('os-release lacks a required field');
    }
  }
  return {
    id: unquote(properties.ID),
    versionId: unquote(properties.VERSION_ID),
    prettyName: unquote(properties.PRETTY_NAME),
  };
}

function parseLsusb(value) {
  const text = parserText(value, 'lsusb output');
  if (text === '') return [];
  const devices = [];
  const seen = new Set();
  for (const line of text.split(/\r?\n/u).filter(Boolean)) {
    const match =
      /^Bus ([0-9]{3}) Device ([0-9]{3}): ID ([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4})(?: (.*))?$/u.exec(
        line
      );
    if (match === null) throw new Error('lsusb output contains a malformed line');
    const busNumber = BigInt(match[1]).toString();
    const deviceNumber = BigInt(match[2]).toString();
    if (busNumber === '0' || deviceNumber === '0') throw new Error('lsusb tuple must be positive');
    const tuple = `${busNumber}:${deviceNumber}`;
    if (seen.has(tuple)) throw new Error('lsusb output contains a duplicate tuple');
    seen.add(tuple);
    devices.push({
      busNumber,
      deviceNumber,
      vendorId: parserUsbId(match[3], 'lsusb vendor'),
      productId: parserUsbId(match[4], 'lsusb product'),
      description: match[5] || null,
      line,
    });
  }
  return devices;
}

function parseProcStat(value) {
  const text = parserText(value, 'proc stat').trim();
  if (text.includes('\n') || text.includes('\r')) throw new Error('proc stat has multiple rows');
  const match = /^([1-9][0-9]*)\s+\((.*)\)\s+([A-Za-z])\s+(.+)$/u.exec(text);
  if (match === null) throw new Error('proc stat record is malformed');
  const fields = match[4].trim().split(/\s+/u);
  if (fields.length < 19) throw new Error('proc stat lacks start time');
  return {
    pid: parserDecimal(match[1], 'proc stat pid', { positive: true }),
    ppid: parserDecimal(fields[0], 'proc stat ppid'),
    startTicks: parserDecimal(fields[18], 'proc stat start ticks', { positive: true }),
    command: match[2],
    state: match[3],
  };
}

function parseProcStatus(value) {
  const properties = {};
  for (const line of parserText(value, 'proc status').split(/\r?\n/u)) {
    const separator = line.indexOf(':');
    if (separator <= 0) continue;
    const key = line.slice(0, separator);
    if (Object.hasOwn(properties, key)) throw new Error(`duplicate proc status field ${key}`);
    properties[key] = line.slice(separator + 1).trim();
  }
  function numbers(key, minimum) {
    if (typeof properties[key] !== 'string') throw new Error(`proc status lacks ${key}`);
    const parsed = properties[key]
      .split(/\s+/u)
      .filter(Boolean)
      .map((entry) => parserDecimal(entry, `proc status ${key}`));
    if (parsed.length < minimum) throw new Error(`proc status ${key} is incomplete`);
    return parsed;
  }
  return {
    uid: numbers('Uid', 4)[0],
    gid: numbers('Gid', 4)[0],
    groups: numbers('Groups', 0),
    namespacePids: numbers('NSpid', 1),
  };
}

function parseCmdline(value) {
  const text = parserText(value, 'proc cmdline');
  if (text === '') return [];
  const payload = text.endsWith('\u0000') ? text.slice(0, -1) : text;
  const entries = payload.split('\u0000');
  if (entries.some((entry) => entry === '')) throw new Error('proc cmdline has an empty argument');
  return entries;
}

function parseCgroup(value) {
  const lines = parserText(value, 'proc cgroup')
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);
  if (lines.length === 0 || lines.some((line) => !/^[0-9]+:[^:]*:.+$/u.test(line))) {
    throw new Error('proc cgroup record is malformed');
  }
  return lines.join('\n');
}

function parseNamespace(value, namespaceType) {
  const type = parserRequiredString(namespaceType, 'namespace type');
  const text = parserRequiredString(value, `${type} namespace`);
  if (!new RegExp(`^${type}:\\[[0-9]+\\]$`, 'u').test(text)) {
    throw new Error(`${type} namespace record is malformed`);
  }
  return text;
}

function isSurfaceThreadCmdline(cmdline) {
  return (
    Array.isArray(cmdline) &&
    cmdline.some(
      (entry) => typeof entry === 'string' && path.posix.basename(entry) === 'SurfaceThread.js'
    )
  );
}

export const H045_ACCEPTED_IMAGE_REFERENCE = 'ghcr.io/bitfocus/companion/companion:v4.3.3';
export const H045_ACCEPTED_IMAGE_ID =
  'sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e';
export const H045_ACCEPTED_SERIAL_SHA256 =
  '08e7fdb9e9bd371297e96f27f75b77bc3920181d1d448ed2d6f6a1d123548f5f';
const H045_ACCEPTED_SERIAL = 'A00SA5492OQMLF';

export const H045_PREDICATE_KEYS = Object.freeze([
  'sourceAdmissionExact',
  'auditExact',
  'framesComplete',
  'frameOrderExact',
  'exposureBounded',
  'hostStable',
  'deviceStable',
  'deviceExact',
  'acceptedImageSelectorExact',
  'deploymentUnique',
  'deploymentStable',
  'deploymentRunning',
  'pid1Stable',
  'workerUnique',
  'workerStable',
  'descriptorStable',
  'descriptorAbsent',
  'markersStable',
]);

export const H045_PROHIBITED_COUNT_KEYS = Object.freeze([
  'externalNetwork',
  'unrestrictedContainerInventory',
  'dockerExec',
  'hidrawOpen',
  'hidrawRead',
  'hidrawWrite',
  'hidrawIoctl',
  'signal',
  'lifecycleMutation',
  'configurationMutation',
  'mountMutation',
  'cgroupMutation',
  'sysfsWrite',
  'productionMutation',
]);

export const H045_COMMAND_ENVIRONMENT_POLICY = Object.freeze({
  mode: 'closed-fixed',
  inheritedKeys: Object.freeze([]),
  fixed: Object.freeze({
    DOCKER_CONFIG: '/nonexistent/overlaykit-h045-docker-config',
    GIT_CONFIG_COUNT: '0',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    LANG: 'C',
    LC_ALL: 'C',
  }),
});

export const H045_ALLOWED_PROCESS_KEYS = Object.freeze([
  'git',
  'lsusb',
  'dockerVersion',
  'dockerPs',
  'dockerInspect',
  'dockerLogs',
]);

const H045_PROTECTED_MAIN_COMMIT = 'e7c9406dc75d6d8c9cb771d9d62d4fd1359b975d';
const H045_SOURCE_CONTRACT_COMMIT = '2dc13d02f3d054fe54cb253869134c872e965601';
const DOCKER_UNIX_HOST = 'unix:///var/run/docker.sock';
const DOCKER_ANCESTOR_FILTER = `ancestor=${H045_ACCEPTED_IMAGE_ID}`;
const DOCKER_VERSION_FORMAT =
  '{"Client":{"Version":{{json .Client.Version}},"ApiVersion":{{json .Client.APIVersion}}},' +
  '"Server":{"Version":{{json .Server.Version}},"ApiVersion":{{json .Server.APIVersion}}}}';
const DOCKER_PS_FORMAT = '{"ID":{{json .ID}},"State":{{json .State}}}';
const DOCKER_INSPECT_FORMAT =
  '{"Id":{{json .Id}},"Image":{{json .Image}},"State":{' +
  '"Status":{{json .State.Status}},"Running":{{json .State.Running}},' +
  '"Pid":{{json .State.Pid}},"StartedAt":{{json .State.StartedAt}}},' +
  '"RestartCount":{{json .RestartCount}},' +
  '"CgroupnsMode":{{json .HostConfig.CgroupnsMode}}}';
const COMMAND_MAX_BUFFER_BYTES = 4 * 1024 * 1024;
const COMMAND_TIMEOUT_MS = null;
const COMMAND_OVERFLOW = 'drain-without-signal';
const FILESYSTEM_MAX_PATH_BYTES = 4_096;
const FILESYSTEM_MAX_READ_BYTES = 1024 * 1024;
const FILESYSTEM_MAX_DIRECTORY_ENTRIES = 4_096;
const FILESYSTEM_MAX_HIDRAW_ENTRIES = 64;
const FILESYSTEM_MAX_PROC_ENTRIES = 1_024;
const FILESYSTEM_MAX_RECEIPTS_PER_FRAME = 16_384;
const FILESYSTEM_MAX_RECEIPTS_PER_RUN = 32_768;
const FILESYSTEM_OPERATIONS = Object.freeze([
  'readFileSync',
  'readdirSync',
  'realpathSync',
  'statSync',
  'lstatSync',
  'readlinkSync',
]);

const INPUT_KEYS = Object.freeze(['frames', 'capabilityAudit', 'sourceAdmissionExact']);
const FRAME_KEYS = Object.freeze([
  'id',
  'complete',
  'startedAt',
  'endedAt',
  'startedMonotonicNs',
  'endedMonotonicNs',
  'observationCutoff',
  'host',
  'device',
  'deploymentInventory',
  'auditBinding',
  'digestSha256',
]);
const DEPLOYMENT_KEYS = Object.freeze([
  'complete',
  'exact',
  'container',
  'lifecycle',
  'pid1',
  'workers',
  'descriptors',
  'markers',
]);
const LIFECYCLE_KEYS = Object.freeze([
  'containerId',
  'imageId',
  'startedAt',
  'restartCount',
  'hostPid',
  'pid1StartTicks',
  'pidNamespace',
  'mountNamespace',
  'cgroup',
  'hostCgroup',
  'cgroupNamespaceMode',
]);
const WORKER_KEYS = Object.freeze([
  'pid',
  'startTicks',
  'ppid',
  'parentStartTicks',
  'uid',
  'gid',
  'groups',
  'cmdline',
  'cgroup',
  'pidNamespace',
  'mountNamespace',
]);
const EPOCH_KEYS = Object.freeze([
  'serial',
  'busNumber',
  'deviceNumber',
  'usbDevicePath',
  'usbDev',
  'hidDevicePath',
  'devicePath',
  'stat',
]);
const STAT_KEYS = Object.freeze([
  'stDev',
  'inode',
  'ctimeNs',
  'mode',
  'uid',
  'gid',
  'rdev',
  'rdevHex',
  'major',
  'minor',
  'isCharacterDevice',
]);
const AUDIT_KEYS = Object.freeze([
  'mode',
  'environmentPolicy',
  'commandReceipts',
  'filesystemReceipts',
  'allowedProcessCounts',
  'commandCount',
  'filesystemReceiptCount',
  'complete',
  'exact',
  'frameCount',
  'lsusbCount',
  'unrecordedObservationCount',
  'prohibitedCounts',
]);

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const IMAGE_ID_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const MONOTONIC_PATTERN = /^(?:0|[1-9][0-9]*)$/u;
const DATE_TIME_PATTERN =
  /^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?Z$/u;
const MAX_EXPOSURE_NS = 5_000_000_000n;
const SURFACE_THREAD_ENTRYPOINT = '/app/SurfaceThread.js';

function clone(value) {
  return structuredClone(value);
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])])
    );
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

export function sha256Canonical(value) {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function plainObject(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function exactKeys(value, keys) {
  return (
    plainObject(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function validSha256(value) {
  return typeof value === 'string' && SHA256_PATTERN.test(value);
}

function sha256Bytes(value) {
  return createHash('sha256').update(value).digest('hex');
}

function sha256Text(value) {
  return typeof value === 'string' ? sha256Bytes(Buffer.from(value, 'utf8')) : null;
}

function imageId(value) {
  return typeof value === 'string' && IMAGE_ID_PATTERN.test(value);
}

function scalarString(value) {
  return typeof value === 'string' && value.length > 0;
}

function dateTime(value) {
  return (
    typeof value === 'string' && DATE_TIME_PATTERN.test(value) && Number.isFinite(Date.parse(value))
  );
}

function monotonic(value) {
  if (typeof value !== 'string' || !MONOTONIC_PATTERN.test(value)) {
    throw new TypeError('invalid monotonic nanosecond value');
  }
  return BigInt(value);
}

function nonNegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function canonicalDecimal(value, { positive = false } = {}) {
  if (typeof value !== 'string' || !MONOTONIC_PATTERN.test(value)) return null;
  const parsed = BigInt(value);
  return positive ? (parsed > 0n ? parsed : null) : parsed;
}

function linuxDeviceIdentity(value) {
  const encoded = canonicalDecimal(value);
  if (encoded === null || encoded > 0xffff_ffff_ffff_ffffn) return null;
  const major =
    ((encoded & 0x0000_0000_000f_ff00n) >> 8n) | ((encoded & 0xffff_f000_0000_0000n) >> 32n);
  const minor = (encoded & 0x0000_0000_0000_00ffn) | ((encoded & 0x0000_0fff_fff0_0000n) >> 12n);
  const majorNumber = Number(major);
  const minorNumber = Number(minor);
  return Number.isSafeInteger(majorNumber) && Number.isSafeInteger(minorNumber)
    ? {
        major: majorNumber,
        minor: minorNumber,
        rdevHex: `${major.toString(16)}:${minor.toString(16)}`,
      }
    : null;
}

function namespaceExact(value, kind) {
  return typeof value === 'string' && new RegExp(`^${kind}:\\[[1-9][0-9]*\\]$`, 'u').test(value);
}

function strictlyIncreasingIndexes(value) {
  return (
    Array.isArray(value) &&
    value.every(
      (entry, index) => nonNegativeInteger(entry) && (index === 0 || entry > value[index - 1])
    )
  );
}

function allFalsePredicates() {
  return Object.fromEntries(H045_PREDICATE_KEYS.map((key) => [key, false]));
}

function classification(disposition, stage, reasonCode, predicates, receipts = []) {
  return { disposition, stage, reasonCode, predicates, receipts };
}

function exactStatShape(value) {
  if (!(
    exactKeys(value, STAT_KEYS) &&
    canonicalDecimal(value.stDev) !== null &&
    canonicalDecimal(value.inode, { positive: true }) !== null &&
    canonicalDecimal(value.ctimeNs) !== null &&
    typeof value.mode === 'string' &&
    /^[0-7]{4}$/u.test(value.mode) &&
    nonNegativeInteger(value.uid) &&
    nonNegativeInteger(value.gid) &&
    canonicalDecimal(value.rdev) !== null &&
    typeof value.rdevHex === 'string' &&
    nonNegativeInteger(value.major) &&
    nonNegativeInteger(value.minor) &&
    typeof value.isCharacterDevice === 'boolean'
  )) {
    return false;
  }
  const decoded = linuxDeviceIdentity(value.rdev);
  return (
    decoded !== null &&
    decoded.major === value.major &&
    decoded.minor === value.minor &&
    decoded.rdevHex === value.rdevHex
  );
}

function exactStat(value) {
  return exactStatShape(value) && value.isCharacterDevice === true && value.major > 0;
}

function exactEpochShape(value) {
  return (
    exactKeys(value, EPOCH_KEYS) &&
    scalarString(value.serial) &&
    scalarString(value.busNumber) &&
    scalarString(value.deviceNumber) &&
    scalarString(value.usbDevicePath) &&
    scalarString(value.usbDev) &&
    scalarString(value.hidDevicePath) &&
    scalarString(value.devicePath) &&
    exactStatShape(value.stat)
  );
}

function exactEpoch(value) {
  return exactEpochShape(value) && exactStat(value.stat);
}

function exactHost(value) {
  return (
    exactKeys(value, ['hostname', 'bootId', 'osRelease']) &&
    scalarString(value.hostname) &&
    scalarString(value.bootId) &&
    scalarString(value.osRelease)
  );
}

function deviceIdentityShape(value) {
  return (
    exactKeys(value, ['serial', 'vendorId', 'productId', 'epoch']) &&
    scalarString(value.serial) &&
    value.vendorId === '0fd9' &&
    value.productId === '0080' &&
    exactEpochShape(value.epoch)
  );
}

function exactDeviceIdentity(value) {
  return (
    deviceIdentityShape(value) &&
    sha256Text(value.serial) === H045_ACCEPTED_SERIAL_SHA256 &&
    value.epoch.serial === value.serial &&
    exactEpoch(value.epoch)
  );
}

function exactDeviceShape(value) {
  if (
    !exactKeys(value, ['complete', 'present', 'identity']) ||
    typeof value.complete !== 'boolean' ||
    typeof value.present !== 'boolean'
  ) {
    return false;
  }
  if (!value.present) return value.identity === null;
  return deviceIdentityShape(value.identity);
}

function exactLifecycle(value) {
  return (
    exactKeys(value, LIFECYCLE_KEYS) &&
    validSha256(value.containerId) &&
    imageId(value.imageId) &&
    dateTime(value.startedAt) &&
    nonNegativeInteger(value.restartCount) &&
    positiveInteger(value.hostPid) &&
    positiveInteger(value.pid1StartTicks) &&
    namespaceExact(value.pidNamespace, 'pid') &&
    namespaceExact(value.mountNamespace, 'mnt') &&
    scalarString(value.cgroup) &&
    scalarString(value.hostCgroup) &&
    scalarString(value.cgroupNamespaceMode)
  );
}

function exactPid1(value) {
  return (
    exactKeys(value, ['hostPid', 'startTicks', 'pidNamespace', 'mountNamespace', 'cgroup']) &&
    positiveInteger(value.hostPid) &&
    positiveInteger(value.startTicks) &&
    namespaceExact(value.pidNamespace, 'pid') &&
    namespaceExact(value.mountNamespace, 'mnt') &&
    scalarString(value.cgroup)
  );
}

function exactWorker(value) {
  return (
    exactKeys(value, WORKER_KEYS) &&
    positiveInteger(value.pid) &&
    positiveInteger(value.startTicks) &&
    nonNegativeInteger(value.ppid) &&
    positiveInteger(value.parentStartTicks) &&
    nonNegativeInteger(value.uid) &&
    nonNegativeInteger(value.gid) &&
    Array.isArray(value.groups) &&
    value.groups.every(nonNegativeInteger) &&
    Array.isArray(value.cmdline) &&
    value.cmdline.length > 0 &&
    value.cmdline.every((entry) => typeof entry === 'string') &&
    value.cmdline.at(-1) === SURFACE_THREAD_ENTRYPOINT &&
    scalarString(value.cgroup) &&
    namespaceExact(value.pidNamespace, 'pid') &&
    namespaceExact(value.mountNamespace, 'mnt')
  );
}

function exactDescriptor(value) {
  return (
    exactKeys(value, ['descriptor', 'target', 'lstat', 'stat']) &&
    typeof value.descriptor === 'string' &&
    /^(?:0|[1-9][0-9]*)$/u.test(value.descriptor) &&
    scalarString(value.target) &&
    exactFilesystemStat(value.lstat) &&
    value.lstat.isSymbolicLink === true &&
    exactFilesystemStat(value.stat) &&
    value.stat.isCharacterDevice === true &&
    value.stat.major > 0
  );
}

function exactMarkers(value) {
  return (
    exactKeys(value, ['opening', 'ready', 'relevantLinesSha256']) &&
    nonNegativeInteger(value.opening) &&
    nonNegativeInteger(value.ready) &&
    validSha256(value.relevantLinesSha256)
  );
}

function exactContainer(value) {
  return (
    exactKeys(value, ['id', 'imageReference', 'imageId', 'state']) &&
    validSha256(value.id) &&
    scalarString(value.imageReference) &&
    imageId(value.imageId) &&
    typeof value.state === 'string' &&
    /^[a-z][a-z0-9_-]*$/u.test(value.state)
  );
}

function exactDeployment(value) {
  return (
    exactKeys(value, DEPLOYMENT_KEYS) &&
    typeof value.complete === 'boolean' &&
    typeof value.exact === 'boolean' &&
    exactContainer(value.container) &&
    (value.lifecycle === null || exactLifecycle(value.lifecycle)) &&
    (value.pid1 === null || exactPid1(value.pid1)) &&
    Array.isArray(value.workers) &&
    value.workers.every(exactWorker) &&
    Array.isArray(value.descriptors) &&
    value.descriptors.every(exactDescriptor) &&
    exactMarkers(value.markers)
  );
}

function exactDeploymentInventory(value) {
  return (
    exactKeys(value, ['complete', 'exact', 'selector', 'rows', 'matches']) &&
    typeof value.complete === 'boolean' &&
    typeof value.exact === 'boolean' &&
    exactKeys(value.selector, ['imageReference', 'imageId']) &&
    scalarString(value.selector.imageReference) &&
    imageId(value.selector.imageId) &&
    Array.isArray(value.rows) &&
    value.rows.every(
      (row) =>
        exactKeys(row, ['containerId', 'state']) &&
        validSha256(row.containerId) &&
        typeof row.state === 'string' &&
        /^[a-z][a-z0-9_-]*$/u.test(row.state)
    ) &&
    Array.isArray(value.matches) &&
    value.matches.every(exactDeployment)
  );
}

function digestFrame(frame) {
  const { digestSha256: _digestSha256, ...body } = frame;
  return sha256Canonical(body);
}

export function independentFrameExactShape(frame) {
  if (
    !exactKeys(frame, FRAME_KEYS) ||
    !scalarString(frame.id) ||
    typeof frame.complete !== 'boolean' ||
    !dateTime(frame.startedAt) ||
    !dateTime(frame.endedAt) ||
    typeof frame.startedMonotonicNs !== 'string' ||
    !MONOTONIC_PATTERN.test(frame.startedMonotonicNs) ||
    typeof frame.endedMonotonicNs !== 'string' ||
    !MONOTONIC_PATTERN.test(frame.endedMonotonicNs) ||
    !exactKeys(frame.observationCutoff, ['at', 'monotonicNs']) ||
    !dateTime(frame.observationCutoff.at) ||
    !MONOTONIC_PATTERN.test(frame.observationCutoff.monotonicNs) ||
    !exactHost(frame.host) ||
    !exactDeviceShape(frame.device) ||
    !exactDeploymentInventory(frame.deploymentInventory) ||
    !exactKeys(frame.auditBinding, ['commandReceiptIndexes', 'filesystemReceiptIndexes']) ||
    !strictlyIncreasingIndexes(frame.auditBinding.commandReceiptIndexes) ||
    !strictlyIncreasingIndexes(frame.auditBinding.filesystemReceiptIndexes) ||
    !validSha256(frame.digestSha256)
  ) {
    return false;
  }
  return digestFrame(frame) === frame.digestSha256;
}

function prohibitedCapabilityObserved(audit) {
  return (
    plainObject(audit?.prohibitedCounts) &&
    Object.values(audit.prohibitedCounts).some((value) => nonNegativeInteger(value) && value > 0)
  );
}

function environmentPolicyExact(value) {
  return (
    exactKeys(value, ['mode', 'inheritedKeys', 'fixed']) &&
    value.mode === H045_COMMAND_ENVIRONMENT_POLICY.mode &&
    same(value.inheritedKeys, H045_COMMAND_ENVIRONMENT_POLICY.inheritedKeys) &&
    exactKeys(value.fixed, Object.keys(H045_COMMAND_ENVIRONMENT_POLICY.fixed)) &&
    same(value.fixed, H045_COMMAND_ENVIRONMENT_POLICY.fixed)
  );
}

function lineCardinality(text) {
  if (text === '') return 0;
  const withoutFinalNewline = text.endsWith('\n') ? text.slice(0, -1) : text;
  return withoutFinalNewline === '' ? 0 : withoutFinalNewline.split('\n').length;
}

function exactBase64(value) {
  if (typeof value !== 'string') return null;
  const bytes = Buffer.from(value, 'base64');
  return bytes.toString('base64') === value ? bytes : null;
}

function exactOutputReceipt(value) {
  if (
    !exactKeys(value, ['encoding', 'text', 'base64', 'byteLength', 'lineCount', 'sha256']) ||
    !['utf8', 'base64'].includes(value.encoding) ||
    !nonNegativeInteger(value.byteLength) ||
    value.byteLength > COMMAND_MAX_BUFFER_BYTES ||
    !validSha256(value.sha256)
  ) {
    return false;
  }
  const bytes = exactBase64(value.base64);
  if (
    bytes === null ||
    bytes.byteLength !== value.byteLength ||
    sha256Bytes(bytes) !== value.sha256
  ) {
    return false;
  }
  const decoded = bytes.toString('utf8');
  const utf8Exact = Buffer.from(decoded, 'utf8').equals(bytes);
  return utf8Exact
    ? value.encoding === 'utf8' &&
        value.text === decoded &&
        value.lineCount === lineCardinality(decoded)
    : value.encoding === 'base64' && value.text === null && value.lineCount === null;
}

function exactReceiptTiming(value) {
  if (
    !dateTime(value.startedAt) ||
    !dateTime(value.endedAt) ||
    typeof value.startedMonotonicNs !== 'string' ||
    typeof value.endedMonotonicNs !== 'string' ||
    typeof value.durationNs !== 'string' ||
    !MONOTONIC_PATTERN.test(value.startedMonotonicNs) ||
    !MONOTONIC_PATTERN.test(value.endedMonotonicNs) ||
    !MONOTONIC_PATTERN.test(value.durationNs)
  ) {
    return false;
  }
  const started = BigInt(value.startedMonotonicNs);
  const ended = BigInt(value.endedMonotonicNs);
  return (
    ended >= started &&
    BigInt(value.durationNs) === ended - started &&
    Date.parse(value.endedAt) >= Date.parse(value.startedAt)
  );
}

function commandOrdinalKey(receipt) {
  return receipt.kind === 'git' ? receipt.observerKind : receipt.kind;
}

function exactCommandReceipt(receipt, index, ordinals) {
  const baseKeys = [
    'index',
    'kind',
    'ordinal',
    'executable',
    'args',
    'startedAt',
    'endedAt',
    'startedMonotonicNs',
    'endedMonotonicNs',
    'durationNs',
    'limits',
    'environmentPolicy',
    'exitCode',
    'signal',
    'stdout',
    'stderr',
    'cardinality',
    'errorCode',
  ];
  const keys = receipt?.kind === 'git' ? [...baseKeys, 'observerKind'] : baseKeys;
  if (
    !exactKeys(receipt, keys) ||
    !H045_ALLOWED_PROCESS_KEYS.includes(receipt.kind) ||
    (receipt.kind === 'git' &&
      !['gitRevParse', 'gitMergeBaseAncestor', 'gitRemoteGetUrl'].includes(receipt.observerKind)) ||
    !scalarString(receipt.executable) ||
    !Array.isArray(receipt.args) ||
    !receipt.args.every((entry) => typeof entry === 'string') ||
    !exactReceiptTiming(receipt) ||
    !exactKeys(receipt.limits, ['maxBufferBytes', 'timeoutMs', 'overflow']) ||
    receipt.limits.maxBufferBytes !== COMMAND_MAX_BUFFER_BYTES ||
    receipt.limits.timeoutMs !== COMMAND_TIMEOUT_MS ||
    receipt.limits.overflow !== COMMAND_OVERFLOW ||
    !environmentPolicyExact(receipt.environmentPolicy) ||
    receipt.exitCode !== 0 ||
    receipt.signal !== null ||
    receipt.errorCode !== null ||
    !exactOutputReceipt(receipt.stdout) ||
    !exactOutputReceipt(receipt.stderr) ||
    !exactKeys(receipt.cardinality, ['global', 'kind']) ||
    receipt.index !== index ||
    receipt.cardinality.global !== index + 1
  ) {
    return false;
  }
  const ordinalKey = commandOrdinalKey(receipt);
  const expectedOrdinal = (ordinals.get(ordinalKey) ?? 0) + 1;
  if (receipt.ordinal !== expectedOrdinal || receipt.cardinality.kind !== expectedOrdinal) {
    return false;
  }
  ordinals.set(ordinalKey, expectedOrdinal);
  return true;
}

function filesystemPathExact(operation, value) {
  if (
    typeof value !== 'string' ||
    value === '' ||
    value.includes('\u0000') ||
    !value.startsWith('/') ||
    value.includes('/../') ||
    value.endsWith('/..') ||
    value.includes('/./') ||
    value.endsWith('/.')
  ) {
    return false;
  }
  if (operation === 'readFileSync') {
    return (
      ['/etc/os-release', '/proc/sys/kernel/random/boot_id', '/proc/sys/kernel/hostname'].includes(
        value
      ) ||
      /^\/sys\/class\/hidraw\/hidraw(?:0|[1-9][0-9]*)\/(?:device\/uevent|dev)$/u.test(value) ||
      /^\/sys\/devices\/.+\/(?:idVendor|idProduct|serial|manufacturer|product|busnum|devnum|devpath|dev)$/u.test(
        value
      ) ||
      /^\/proc\/[1-9][0-9]*\/cgroup$/u.test(value) ||
      /^\/proc\/[1-9][0-9]*\/root\/proc\/[1-9][0-9]*\/(?:stat|status|cmdline|cgroup)$/u.test(value)
    );
  }
  if (operation === 'readdirSync') {
    return (
      value === '/sys/class/hidraw' ||
      /^\/proc\/[1-9][0-9]*\/root\/proc$/u.test(value) ||
      /^\/proc\/[1-9][0-9]*\/root\/proc\/[1-9][0-9]*\/fd$/u.test(value)
    );
  }
  if (operation === 'realpathSync') {
    return /^\/sys\/class\/hidraw\/hidraw(?:0|[1-9][0-9]*)\/device$/u.test(value);
  }
  if (operation === 'statSync' || operation === 'lstatSync') {
    return (
      /^\/(?:dev|host-dev)\/hidraw(?:0|[1-9][0-9]*)$/u.test(value) ||
      /^\/proc\/[1-9][0-9]*\/root\/proc\/[1-9][0-9]*\/fd\/(?:0|[1-9][0-9]*)$/u.test(value)
    );
  }
  return (
    operation === 'readlinkSync' &&
    (/^\/(?:dev|host-dev)\/hidraw(?:0|[1-9][0-9]*)$/u.test(value) ||
      /^\/proc\/[1-9][0-9]*\/root\/proc\/[1-9][0-9]*\/ns\/(?:pid|mnt)$/u.test(value) ||
      /^\/proc\/[1-9][0-9]*\/root\/proc\/[1-9][0-9]*\/fd\/(?:0|[1-9][0-9]*)$/u.test(value))
  );
}

function exactFilesystemStat(value) {
  if (
    !exactKeys(value, [...STAT_KEYS, 'isSymbolicLink']) ||
    typeof value.isSymbolicLink !== 'boolean'
  ) {
    return false;
  }
  const projected = Object.fromEntries(STAT_KEYS.map((key) => [key, value[key]]));
  return exactStatShape(projected);
}

function exactFilesystemReadResult(value) {
  if (
    !exactKeys(value, ['cardinality', 'byteLength', 'bytes', 'encoding', 'text', 'sha256']) ||
    value.cardinality !== 1 ||
    !nonNegativeInteger(value.byteLength) ||
    value.byteLength > FILESYSTEM_MAX_READ_BYTES ||
    !exactKeys(value.bytes, ['encoding', 'base64', 'byteLength', 'sha256']) ||
    value.bytes.encoding !== 'base64' ||
    !nonNegativeInteger(value.bytes.byteLength) ||
    !validSha256(value.bytes.sha256) ||
    !validSha256(value.sha256)
  ) {
    return false;
  }
  const bytes = exactBase64(value.bytes.base64);
  if (
    bytes === null ||
    bytes.byteLength !== value.byteLength ||
    bytes.byteLength !== value.bytes.byteLength ||
    sha256Bytes(bytes) !== value.sha256 ||
    value.sha256 !== value.bytes.sha256
  ) {
    return false;
  }
  const decoded = bytes.toString('utf8');
  const utf8Exact = Buffer.from(decoded, 'utf8').equals(bytes);
  return utf8Exact
    ? value.encoding === 'utf8' && value.text === decoded
    : value.encoding === 'base64' && value.text === null;
}

function filesystemDirectoryLimit(path) {
  if (path === '/sys/class/hidraw') return FILESYSTEM_MAX_HIDRAW_ENTRIES;
  if (
    /^\/proc\/[1-9][0-9]*\/root\/proc$/u.test(path) ||
    /^\/proc\/[1-9][0-9]*\/root\/proc\/[1-9][0-9]*\/fd$/u.test(path)
  ) {
    return FILESYSTEM_MAX_PROC_ENTRIES;
  }
  return FILESYSTEM_MAX_DIRECTORY_ENTRIES;
}

function exactFilesystemResult(receipt) {
  const result = receipt.result;
  if (!plainObject(result)) return false;
  if (receipt.disposition !== 'observed') {
    return (
      ['missing', 'error'].includes(receipt.disposition) &&
      exactKeys(result, ['cardinality', 'sha256']) &&
      result.cardinality === 0 &&
      result.sha256 === sha256Bytes(Buffer.alloc(0))
    );
  }
  if (receipt.operation === 'readFileSync') return exactFilesystemReadResult(result);
  if (receipt.operation === 'readdirSync') {
    return (
      exactKeys(result, ['entries', 'cardinality', 'sha256']) &&
      Array.isArray(result.entries) &&
      result.entries.every((entry) => typeof entry === 'string') &&
      result.cardinality === result.entries.length &&
      result.cardinality <= filesystemDirectoryLimit(receipt.path) &&
      result.sha256 === sha256Bytes(Buffer.from(JSON.stringify(result.entries), 'utf8'))
    );
  }
  if (receipt.operation === 'realpathSync' || receipt.operation === 'readlinkSync') {
    return (
      exactKeys(result, ['value', 'cardinality', 'sha256']) &&
      scalarString(result.value) &&
      Buffer.byteLength(result.value, 'utf8') <= FILESYSTEM_MAX_PATH_BYTES &&
      result.cardinality === 1 &&
      result.sha256 === sha256Bytes(Buffer.from(result.value, 'utf8'))
    );
  }
  return (
    ['statSync', 'lstatSync'].includes(receipt.operation) &&
    exactKeys(result, ['cardinality', 'metadata', 'sha256']) &&
    result.cardinality === 1 &&
    exactFilesystemStat(result.metadata) &&
    result.sha256 === sha256Bytes(Buffer.from(JSON.stringify(result.metadata), 'utf8'))
  );
}

function exactFilesystemReceipt(receipt, index, ordinals) {
  if (
    !exactKeys(receipt, [
      'index',
      'operation',
      'path',
      'startedAt',
      'endedAt',
      'startedMonotonicNs',
      'endedMonotonicNs',
      'durationNs',
      'disposition',
      'result',
      'errorCode',
      'cardinality',
    ]) ||
    !FILESYSTEM_OPERATIONS.includes(receipt.operation) ||
    typeof receipt.path !== 'string' ||
    Buffer.byteLength(receipt.path, 'utf8') > FILESYSTEM_MAX_PATH_BYTES ||
    !filesystemPathExact(receipt.operation, receipt.path) ||
    !exactReceiptTiming(receipt) ||
    !['observed', 'missing', 'error'].includes(receipt.disposition) ||
    (receipt.disposition === 'observed'
      ? receipt.errorCode !== null
      : !scalarString(receipt.errorCode)) ||
    !exactFilesystemResult(receipt) ||
    !exactKeys(receipt.cardinality, ['global', 'operation']) ||
    receipt.index !== index ||
    receipt.cardinality.global !== index + 1
  ) {
    return false;
  }
  const expectedOrdinal = (ordinals.get(receipt.operation) ?? 0) + 1;
  if (receipt.cardinality.operation !== expectedOrdinal) return false;
  ordinals.set(receipt.operation, expectedOrdinal);
  return true;
}

function commandPlanForFrames(frames) {
  const plan = [
    {
      kind: 'git',
      observerKind: 'gitRevParse',
      executable: 'git',
      args: ['rev-parse', 'HEAD'],
    },
    {
      kind: 'git',
      observerKind: 'gitMergeBaseAncestor',
      executable: 'git',
      args: ['merge-base', '--is-ancestor', H045_PROTECTED_MAIN_COMMIT, 'HEAD'],
    },
    {
      kind: 'git',
      observerKind: 'gitMergeBaseAncestor',
      executable: 'git',
      args: ['merge-base', '--is-ancestor', H045_SOURCE_CONTRACT_COMMIT, 'HEAD'],
    },
    {
      kind: 'git',
      observerKind: 'gitRemoteGetUrl',
      executable: 'git',
      args: ['remote', 'get-url', 'origin'],
    },
    {
      kind: 'lsusb',
      executable: 'lsusb',
      args: [],
    },
    {
      kind: 'dockerVersion',
      executable: 'docker',
      args: ['--host', DOCKER_UNIX_HOST, 'version', '--format', DOCKER_VERSION_FORMAT],
    },
  ];
  const framePlans = [];
  for (const frame of frames) {
    const rows = frame.deploymentInventory.rows;
    const matches = frame.deploymentInventory.matches;
    if (
      rows.length === 0
        ? matches.length !== 0
        : rows.length === 1
          ? matches.length !== 1 ||
            rows[0].containerId !== matches[0].container.id ||
            rows[0].state !== matches[0].container.state
          : matches.length !== 0
    ) {
      return null;
    }
    const dynamic = [
      {
        kind: 'dockerPs',
        executable: 'docker',
        args: [
          '--host',
          DOCKER_UNIX_HOST,
          'ps',
          '--all',
          '--no-trunc',
          '--filter',
          DOCKER_ANCESTOR_FILTER,
          '--format',
          DOCKER_PS_FORMAT,
        ],
        phase: 'before-cutoff',
        frame,
      },
    ];
    if (rows.length === 1) {
      dynamic.push({
        kind: 'dockerInspect',
        executable: 'docker',
        args: [
          '--host',
          DOCKER_UNIX_HOST,
          'inspect',
          '--format',
          DOCKER_INSPECT_FORMAT,
          rows[0].containerId,
        ],
        phase: 'before-cutoff',
        frame,
      });
      if (matches[0].container.state === 'running') {
        dynamic.push({
          kind: 'dockerLogs',
          executable: 'docker',
          containerId: rows[0].containerId,
          cutoff: frame.observationCutoff,
          phase: 'at-or-after-cutoff',
          frame,
        });
      }
    }
    const startIndex = plan.length;
    plan.push(...dynamic);
    framePlans.push({
      frame,
      indexes: dynamic.map((_, index) => startIndex + index),
      dynamic,
    });
  }
  return { plan, framePlans };
}

function commandText(receipt, stream = 'stdout') {
  const output = receipt?.[stream];
  return output?.encoding === 'utf8' && typeof output.text === 'string' ? output.text : null;
}

function parseExactJson(value) {
  if (typeof value !== 'string' || value.trim() === '') return null;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function dockerPsOutputExact(receipt, frame) {
  const text = commandText(receipt);
  if (text === null) return false;
  const lines = text.split(/\r?\n/u).filter(Boolean);
  const rows = [];
  for (const line of lines) {
    const entry = parseExactJson(line);
    if (
      !exactKeys(entry, ['ID', 'State']) ||
      !SHA256_PATTERN.test(entry.ID) ||
      typeof entry.State !== 'string' ||
      !/^[a-z][a-z0-9_-]*$/u.test(entry.State)
    ) {
      return false;
    }
    rows.push({
      containerId: entry.ID,
      state: entry.State,
    });
  }
  return same(rows, frame.deploymentInventory.rows);
}

function lsusbEvidenceExact(receipt, frames) {
  try {
    const text = commandText(receipt);
    if (text === null) return false;
    const matches = parseLsusb(text).filter(
      (entry) => entry.vendorId === '0fd9' && entry.productId === '0080'
    );
    return frames.every((frame) => {
      if (!frame.device.present) return matches.length === 0;
      const epoch = frame.device.identity.epoch;
      return (
        matches.filter(
          (entry) =>
            entry.busNumber === epoch.busNumber && entry.deviceNumber === epoch.deviceNumber
        ).length === 1
      );
    });
  } catch {
    return false;
  }
}

function dockerInspectOutputExact(receipt, frame) {
  const entry = parseExactJson(commandText(receipt));
  const row = frame.deploymentInventory.rows[0];
  const selected = frame.deploymentInventory.matches[0];
  if (
    !exactKeys(entry, ['Id', 'Image', 'State', 'RestartCount', 'CgroupnsMode']) ||
    !exactKeys(entry.State, ['Status', 'Running', 'Pid', 'StartedAt']) ||
    entry.Id !== row.containerId ||
    entry.Image !== H045_ACCEPTED_IMAGE_ID ||
    entry.State.Status !== row.state ||
    typeof entry.State.Running !== 'boolean' ||
    (entry.State.Status === 'running') !== entry.State.Running ||
    !nonNegativeInteger(entry.State.Pid) ||
    !dateTime(entry.State.StartedAt) ||
    !nonNegativeInteger(entry.RestartCount) ||
    !scalarString(entry.CgroupnsMode)
  ) {
    return false;
  }
  if (!entry.State.Running) return entry.State.Pid === 0;
  return (
    selected?.lifecycle !== null &&
    selected?.lifecycle !== undefined &&
    entry.State.Pid === selected.lifecycle.hostPid &&
    entry.State.StartedAt === selected.lifecycle.startedAt &&
    entry.RestartCount === selected.lifecycle.restartCount &&
    entry.CgroupnsMode === selected.lifecycle.cgroupNamespaceMode
  );
}

function dockerLogsOutputExact(receipt, frame) {
  const streams = [
    ['stdout', commandText(receipt, 'stdout')],
    ['stderr', commandText(receipt, 'stderr')],
  ];
  if (streams.some(([, text]) => text === null)) return false;
  const entries = [];
  for (const [stream, text] of streams) {
    for (const line of text.split(/\r?\n/u).filter(Boolean)) {
      const separator = line.indexOf(' ');
      if (separator <= 0) return false;
      const at = line.slice(0, separator);
      if (
        !dateTime(at) ||
        Date.parse(at) < Date.parse(receipt.args[5]) ||
        Date.parse(at) > Date.parse(receipt.args[7])
      ) {
        return false;
      }
      entries.push({
        at,
        stream,
        line: line.slice(separator + 1),
      });
    }
  }
  entries.sort(
    (left, right) =>
      Date.parse(left.at) - Date.parse(right.at) ||
      left.at.localeCompare(right.at) ||
      left.stream.localeCompare(right.stream) ||
      left.line.localeCompare(right.line)
  );
  const markers = [
    ['opening', `Opening surface panel: streamdeck:${H045_ACCEPTED_SERIAL}`],
    ['ready', `Surface panel ready: streamdeck:${H045_ACCEPTED_SERIAL}`],
  ];
  const relevant = entries
    .map((entry) => {
      const marker = markers.find(
        ([, text]) =>
          entry.line.includes(text) &&
          (entry.line.endsWith(text) ||
            /\s/u.test(entry.line[entry.line.indexOf(text) + text.length]))
      );
      return { ...entry, markerKind: marker?.[0] ?? null };
    })
    .filter((entry) => entry.markerKind !== null);
  const selected = frame.deploymentInventory.matches[0];
  return (
    selected !== undefined &&
    selected.markers.opening ===
      relevant.filter((entry) => entry.markerKind === 'opening').length &&
    selected.markers.ready === relevant.filter((entry) => entry.markerKind === 'ready').length &&
    selected.markers.relevantLinesSha256 ===
      sha256Bytes(
        Buffer.from(
          relevant.map((entry) => `${entry.at}\t${entry.stream}\t${entry.line}`).join('\n'),
          'utf8'
        )
      )
  );
}

function commandOutputMatches(receipt, expected) {
  const stdout = commandText(receipt);
  const stderr = commandText(receipt, 'stderr');
  if (stdout === null || stderr === null) return false;
  if (expected.observerKind === 'gitRevParse') {
    return /^[0-9a-f]{40}\n?$/u.test(stdout) && stderr === '';
  }
  if (expected.observerKind === 'gitMergeBaseAncestor') {
    return stdout === '' && stderr === '';
  }
  if (expected.observerKind === 'gitRemoteGetUrl') {
    return (
      stdout.trim() === 'https://github.com/OverlayKit/companion-module-overlaykit-server.git' &&
      stderr === ''
    );
  }
  if (expected.kind === 'lsusb') {
    return stderr === '' && typeof stdout === 'string';
  }
  if (expected.kind === 'dockerVersion') {
    const version = parseExactJson(stdout);
    return (
      stderr === '' &&
      exactKeys(version, ['Client', 'Server']) &&
      ['Client', 'Server'].every(
        (key) =>
          exactKeys(version[key], ['Version', 'ApiVersion']) &&
          scalarString(version[key].Version) &&
          scalarString(version[key].ApiVersion)
      )
    );
  }
  if (expected.kind === 'dockerPs') {
    return stderr === '' && dockerPsOutputExact(receipt, expected.frame);
  }
  if (expected.kind === 'dockerInspect') {
    return stderr === '' && dockerInspectOutputExact(receipt, expected.frame);
  }
  return expected.kind === 'dockerLogs' && dockerLogsOutputExact(receipt, expected.frame);
}

function commandMatchesPlan(receipt, expected) {
  if (
    receipt.kind !== expected.kind ||
    receipt.executable !== expected.executable ||
    (expected.observerKind === undefined
      ? Object.hasOwn(receipt, 'observerKind')
      : receipt.observerKind !== expected.observerKind)
  ) {
    return false;
  }
  const argsExact =
    expected.kind !== 'dockerLogs'
      ? same(receipt.args, expected.args)
      : receipt.args.length === 9 &&
        same(receipt.args.slice(0, 5), [
          '--host',
          DOCKER_UNIX_HOST,
          'logs',
          '--timestamps',
          '--since',
        ]) &&
        dateTime(receipt.args[5]) &&
        Date.parse(receipt.args[5]) <= Date.parse(expected.cutoff.at) &&
        receipt.args[6] === '--until' &&
        receipt.args[7] === expected.cutoff.at &&
        receipt.args[8] === expected.containerId;
  return argsExact && commandOutputMatches(receipt, expected);
}

function receiptWithinFrame(receipt, frame) {
  return (
    BigInt(receipt.startedMonotonicNs) >= BigInt(frame.startedMonotonicNs) &&
    BigInt(receipt.endedMonotonicNs) <= BigInt(frame.endedMonotonicNs) &&
    Date.parse(receipt.startedAt) >= Date.parse(frame.startedAt) &&
    Date.parse(receipt.endedAt) <= Date.parse(frame.endedAt)
  );
}

function receiptEndsAtOrBeforeCutoff(receipt, frame) {
  return (
    BigInt(receipt.endedMonotonicNs) <= BigInt(frame.observationCutoff.monotonicNs) &&
    Date.parse(receipt.endedAt) <= Date.parse(frame.observationCutoff.at)
  );
}

function receiptStartsAtOrAfterCutoff(receipt, frame) {
  return (
    BigInt(receipt.startedMonotonicNs) >= BigInt(frame.observationCutoff.monotonicNs) &&
    Date.parse(receipt.startedAt) >= Date.parse(frame.observationCutoff.at)
  );
}

function observedText(receipt) {
  return receipt?.disposition === 'observed' &&
    receipt.operation === 'readFileSync' &&
    receipt.result.encoding === 'utf8' &&
    typeof receipt.result.text === 'string'
    ? receipt.result.text.trim()
    : null;
}

function observedRawText(receipt) {
  return receipt?.disposition === 'observed' &&
    receipt.operation === 'readFileSync' &&
    receipt.result.encoding === 'utf8' &&
    typeof receipt.result.text === 'string'
    ? receipt.result.text
    : null;
}

function observedEntries(receipt) {
  return receipt?.disposition === 'observed' &&
    receipt.operation === 'readdirSync' &&
    Array.isArray(receipt.result.entries)
    ? receipt.result.entries
    : null;
}

function observedPath(receipt) {
  return receipt?.disposition === 'observed' &&
    ['realpathSync', 'readlinkSync'].includes(receipt.operation) &&
    typeof receipt.result.value === 'string'
    ? receipt.result.value
    : null;
}

function parentPath(value) {
  const index = value.lastIndexOf('/');
  return index <= 0 ? '/' : value.slice(0, index);
}

function projectedFilesystemStat(value) {
  return Object.fromEntries(STAT_KEYS.map((key) => [key, value[key]]));
}

function normalizeUsbId(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{1,8}$/iu.test(value)) return null;
  const parsed = BigInt(`0x${value}`);
  return parsed <= 0xffffn ? parsed.toString(16).padStart(4, '0') : null;
}

function parseHidUeventExact(value) {
  if (typeof value !== 'string') return null;
  const properties = {};
  for (const line of value.split(/\r?\n/u)) {
    if (line === '') continue;
    const separator = line.indexOf('=');
    if (separator <= 0 || !/^[A-Z][A-Z0-9_]*$/u.test(line.slice(0, separator))) {
      return null;
    }
    const key = line.slice(0, separator);
    if (Object.hasOwn(properties, key)) return null;
    properties[key] = line.slice(separator + 1);
  }
  const id =
    typeof properties.HID_ID === 'string'
      ? /^([0-9a-f]{1,8}):([0-9a-f]{1,8}):([0-9a-f]{1,8})$/iu.exec(properties.HID_ID)
      : null;
  if (id === null) return null;
  const bus = normalizeUsbId(id[1]);
  const vendorId = normalizeUsbId(id[2]);
  const productId = normalizeUsbId(id[3]);
  if (bus === null || vendorId === null || productId === null) return null;
  return {
    bus,
    vendorId,
    productId,
    unique:
      typeof properties.HID_UNIQ === 'string' && properties.HID_UNIQ !== ''
        ? properties.HID_UNIQ
        : null,
  };
}

function parseDeviceTuple(value) {
  const match =
    typeof value === 'string' ? /^((?:0|[1-9][0-9]*)):((?:0|[1-9][0-9]*))$/u.exec(value) : null;
  if (match === null) return null;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  return Number.isSafeInteger(major) && Number.isSafeInteger(minor) ? { major, minor } : null;
}

function numericDirectoryEntries(receipt) {
  const entries = observedEntries(receipt);
  if (entries === null || new Set(entries).size !== entries.length) return null;
  return entries
    .filter((entry) => /^[1-9][0-9]*$/u.test(entry))
    .map(Number)
    .sort((left, right) => left - right);
}

function descriptorDirectoryEntries(receipt) {
  const entries = observedEntries(receipt);
  if (entries === null || new Set(entries).size !== entries.length) return null;
  const descriptors = entries.filter((entry) => /^(?:0|[1-9][0-9]*)$/u.test(entry));
  if (descriptors.some((entry) => !Number.isSafeInteger(Number(entry)))) return null;
  return descriptors.sort((left, right) => Number(left) - Number(right));
}

function replayFilesystemFrame(frame, receipts) {
  let cursor = 0;
  function take(operation, path) {
    const receipt = receipts[cursor];
    if (receipt?.operation !== operation || receipt.path !== path) {
      throw new Error('filesystem replay mismatch');
    }
    cursor += 1;
    return receipt;
  }
  function takeObserved(operation, path) {
    const receipt = take(operation, path);
    if (receipt.disposition !== 'observed') {
      throw new Error('required filesystem observation is unavailable');
    }
    return receipt;
  }
  function takeOptionalText(path) {
    const receipt = take('readFileSync', path);
    if (receipt.disposition === 'missing') return null;
    const text = observedText(receipt);
    if (text === null) throw new Error('optional filesystem observation is inexact');
    return text;
  }
  function observeProcess(procRoot, pid) {
    const directory = `${procRoot}/${pid}`;
    const statText = observedRawText(takeObserved('readFileSync', `${directory}/stat`));
    const statusText = observedRawText(takeObserved('readFileSync', `${directory}/status`));
    const cmdlineText = observedRawText(takeObserved('readFileSync', `${directory}/cmdline`));
    const cgroupText = observedRawText(takeObserved('readFileSync', `${directory}/cgroup`));
    const pidNamespace = observedPath(takeObserved('readlinkSync', `${directory}/ns/pid`));
    const mountNamespace = observedPath(takeObserved('readlinkSync', `${directory}/ns/mnt`));
    if (
      statText === null ||
      statusText === null ||
      cmdlineText === null ||
      cgroupText === null ||
      pidNamespace === null ||
      mountNamespace === null
    ) {
      throw new Error('process evidence is unavailable');
    }
    const stat = parseProcStat(statText);
    const status = parseProcStatus(statusText);
    if (stat.pid !== pid || status.namespacePids.at(-1) !== pid) {
      throw new Error('process identity mismatch');
    }
    return {
      pid,
      startTicks: stat.startTicks,
      ppid: stat.ppid,
      uid: status.uid,
      gid: status.gid,
      groups: status.groups,
      cmdline: parseCmdline(cmdlineText),
      cgroup: parseCgroup(cgroupText),
      pidNamespace: parseNamespace(pidNamespace, 'pid'),
      mountNamespace: parseNamespace(mountNamespace, 'mnt'),
    };
  }

  try {
    const osReleaseText = observedRawText(takeObserved('readFileSync', '/etc/os-release'));
    const bootId = observedText(takeObserved('readFileSync', '/proc/sys/kernel/random/boot_id'));
    const hostname = observedText(takeObserved('readFileSync', '/proc/sys/kernel/hostname'));
    if (osReleaseText === null) return false;
    const osRelease = parseOsRelease(osReleaseText);
    const projectedOsRelease = JSON.parse(frame.host.osRelease);
    if (
      !same(osRelease, projectedOsRelease) ||
      bootId !== frame.host.bootId ||
      hostname !== frame.host.hostname
    ) {
      return false;
    }

    const classNames = observedEntries(takeObserved('readdirSync', '/sys/class/hidraw'));
    if (
      classNames === null ||
      classNames.some((entry) => !/^hidraw(?:0|[1-9][0-9]*)$/u.test(entry)) ||
      new Set(classNames).size !== classNames.length
    ) {
      return false;
    }
    const names = [...classNames].sort(
      (left, right) => Number(left.slice('hidraw'.length)) - Number(right.slice('hidraw'.length))
    );
    const entries = [];
    for (const name of names) {
      const classPath = `/sys/class/hidraw/${name}`;
      const devicePath = `/dev/${name}`;
      const hidDevicePath = observedPath(takeObserved('realpathSync', `${classPath}/device`));
      if (hidDevicePath === null || !hidDevicePath.startsWith('/sys/devices/')) return false;
      const hid = parseHidUeventExact(
        observedRawText(takeObserved('readFileSync', `${classPath}/device/uevent`))
      );
      const classDevice = parseDeviceTuple(
        observedText(takeObserved('readFileSync', `${classPath}/dev`))
      );
      const statBefore = takeObserved('statSync', devicePath).result.metadata;
      let ancestorPath = hidDevicePath;
      let ancestor = null;
      for (let depth = 0; depth < 64 && ancestorPath.startsWith('/sys/devices'); depth += 1) {
        const vendor = takeOptionalText(`${ancestorPath}/idVendor`);
        const product = takeOptionalText(`${ancestorPath}/idProduct`);
        if (vendor !== null || product !== null) {
          if (vendor === null || product === null) return false;
          ancestor = {
            path: ancestorPath,
            vendorId: normalizeUsbId(vendor),
            productId: normalizeUsbId(product),
            serial: takeOptionalText(`${ancestorPath}/serial`),
            manufacturer: takeOptionalText(`${ancestorPath}/manufacturer`),
            product: takeOptionalText(`${ancestorPath}/product`),
            busNumber: takeOptionalText(`${ancestorPath}/busnum`),
            deviceNumber: takeOptionalText(`${ancestorPath}/devnum`),
            devicePath: takeOptionalText(`${ancestorPath}/devpath`),
          };
          break;
        }
        ancestorPath = parentPath(ancestorPath);
      }
      if (ancestor === null) return false;
      const statAfter = takeObserved('statSync', devicePath).result.metadata;
      if (
        hid === null ||
        classDevice === null ||
        ancestor.vendorId === null ||
        ancestor.productId === null ||
        !same(statBefore, statAfter) ||
        statBefore.major !== classDevice.major ||
        statBefore.minor !== classDevice.minor
      ) {
        return false;
      }
      entries.push({
        name,
        classPath,
        devicePath,
        hidDevicePath,
        hid,
        classDevice,
        stat: statBefore,
        ancestor,
      });
    }

    for (const entry of entries) {
      const lstat = takeObserved('lstatSync', entry.devicePath).result.metadata;
      const finalStat = takeObserved('statSync', entry.devicePath).result.metadata;
      if (!same(finalStat, entry.stat)) return false;
      entry.lstat = lstat;
      entry.linkTarget = null;
      if (lstat.isSymbolicLink === true) {
        entry.linkTarget = observedPath(takeObserved('readlinkSync', entry.devicePath));
        if (entry.linkTarget === null || entry.linkTarget === '') return false;
      }
    }

    const targets = entries.filter((entry) => {
      const serial = entry.ancestor.serial;
      return (
        entry.hid.vendorId === '0fd9' &&
        entry.hid.productId === '0080' &&
        entry.hid.unique === serial &&
        entry.ancestor.vendorId === '0fd9' &&
        entry.ancestor.productId === '0080' &&
        typeof serial === 'string' &&
        sha256Text(serial) === H045_ACCEPTED_SERIAL_SHA256 &&
        entry.stat.isCharacterDevice === true &&
        entry.stat.major > 0
      );
    });
    const serialContradictions = entries.filter(
      (entry) =>
        entry.hid.vendorId === '0fd9' &&
        entry.hid.productId === '0080' &&
        entry.ancestor.vendorId === '0fd9' &&
        entry.ancestor.productId === '0080' &&
        (sha256Text(entry.hid.unique ?? '') === H045_ACCEPTED_SERIAL_SHA256 ||
          sha256Text(entry.ancestor.serial ?? '') === H045_ACCEPTED_SERIAL_SHA256) &&
        entry.hid.unique !== entry.ancestor.serial
    );
    for (const entry of targets) {
      entry.usbDev = observedText(takeObserved('readFileSync', `${entry.ancestor.path}/dev`));
      if (parseDeviceTuple(entry.usbDev) === null) return false;
    }
    if (serialContradictions.length > 0) return false;
    if (frame.device.present) {
      if (targets.length !== 1) return false;
      const identity = frame.device.identity;
      const target = targets[0];
      if (
        target.devicePath !== identity.epoch.devicePath ||
        target.hidDevicePath !== identity.epoch.hidDevicePath ||
        target.ancestor.serial !== identity.serial ||
        target.ancestor.busNumber !== identity.epoch.busNumber ||
        target.ancestor.deviceNumber !== identity.epoch.deviceNumber ||
        target.ancestor.devicePath !== identity.epoch.usbDevicePath ||
        target.usbDev !== identity.epoch.usbDev ||
        !same(projectedFilesystemStat(target.stat), identity.epoch.stat) ||
        target.classDevice.major !== identity.epoch.stat.major ||
        target.classDevice.minor !== identity.epoch.stat.minor ||
        entries.some(
          (entry) =>
            entry !== target &&
            entry.classDevice.major === target.classDevice.major &&
            entry.classDevice.minor === target.classDevice.minor
        )
      ) {
        return false;
      }
    } else if (targets.length !== 0) {
      return false;
    }

    const inventory = frame.deploymentInventory;
    if (inventory.rows.length === 1 && inventory.matches.length === 1) {
      const selected = inventory.matches[0];
      if (selected.container.state === 'running' && selected.lifecycle !== null) {
        const procRoot = `/proc/${selected.lifecycle.hostPid}/root/proc`;
        const processIds = numericDirectoryEntries(takeObserved('readdirSync', procRoot));
        if (processIds === null) return false;
        const processes = processIds.map((pid) => observeProcess(procRoot, pid));
        const processIdsAfter = numericDirectoryEntries(takeObserved('readdirSync', procRoot));
        if (processIdsAfter === null || !same(processIds, processIdsAfter)) return false;
        const byPid = new Map(processes.map((entry) => [entry.pid, entry]));
        const rawPid1 = byPid.get(1) ?? null;
        if (selected.pid1 === null || rawPid1 === null || rawPid1.ppid !== 0) return false;
        const projectedPid1 = {
          hostPid: selected.lifecycle.hostPid,
          startTicks: rawPid1.startTicks,
          pidNamespace: rawPid1.pidNamespace,
          mountNamespace: rawPid1.mountNamespace,
          cgroup: rawPid1.cgroup,
        };
        if (
          !same(projectedPid1, selected.pid1) ||
          selected.lifecycle.pid1StartTicks !== rawPid1.startTicks ||
          selected.lifecycle.pidNamespace !== rawPid1.pidNamespace ||
          selected.lifecycle.mountNamespace !== rawPid1.mountNamespace ||
          selected.lifecycle.cgroup !== rawPid1.cgroup
        ) {
          return false;
        }
        const rawWorkers = processes.filter((entry) => isSurfaceThreadCmdline(entry.cmdline));
        const projectedWorkers = rawWorkers.map((entry) => ({
          pid: entry.pid,
          startTicks: entry.startTicks,
          ppid: entry.ppid,
          parentStartTicks: byPid.get(entry.ppid)?.startTicks ?? null,
          uid: entry.uid,
          gid: entry.gid,
          groups: entry.groups,
          cmdline: entry.cmdline,
          cgroup: entry.cgroup,
          pidNamespace: entry.pidNamespace,
          mountNamespace: entry.mountNamespace,
        }));
        if (!same(projectedWorkers, selected.workers)) return false;

        const descriptors = [];
        if (frame.device.present) {
          const targetMajor = frame.device.identity.epoch.stat.major;
          for (const worker of rawWorkers) {
            const directory = `${procRoot}/${worker.pid}/fd`;
            const before = descriptorDirectoryEntries(takeObserved('readdirSync', directory));
            if (before === null) return false;
            for (const descriptor of before) {
              const descriptorPath = `${directory}/${descriptor}`;
              const lstat = takeObserved('lstatSync', descriptorPath).result.metadata;
              const target = observedPath(takeObserved('readlinkSync', descriptorPath));
              const stat = takeObserved('statSync', descriptorPath).result.metadata;
              if (target === null || lstat.isSymbolicLink !== true) {
                return false;
              }
              if (
                stat.isCharacterDevice === true &&
                (/^\/dev\/hidraw(?:0|[1-9][0-9]*)(?: \(deleted\))?$/u.test(target) ||
                  stat.major === targetMajor)
              ) {
                descriptors.push({ descriptor, target, lstat, stat });
              }
            }
            const after = descriptorDirectoryEntries(takeObserved('readdirSync', directory));
            if (after === null || !same(before, after)) return false;
          }
        }
        if (!same(descriptors, selected.descriptors)) return false;

        const hostCgroupText = observedRawText(
          takeObserved('readFileSync', `/proc/${selected.lifecycle.hostPid}/cgroup`)
        );
        if (
          hostCgroupText === null ||
          parseCgroup(hostCgroupText) !== selected.lifecycle.hostCgroup
        ) {
          return false;
        }
      }
    }
    return cursor === receipts.length;
  } catch {
    return false;
  }
}

function nonRunningInspectEvidenceStable(audit, framePlans) {
  const entries = [];
  for (const { frame, indexes, dynamic } of framePlans) {
    const selected = frame.deploymentInventory.matches[0];
    if (frame.deploymentInventory.rows.length !== 1 || selected?.container.state === 'running') {
      return true;
    }
    const inspectPosition = dynamic.findIndex((entry) => entry.kind === 'dockerInspect');
    if (inspectPosition < 0) return false;
    const entry = parseExactJson(commandText(audit.commandReceipts[indexes[inspectPosition]]));
    if (entry === null) return false;
    entries.push(entry);
  }
  return entries.length === framePlans.length && entries.every((entry) => same(entry, entries[0]));
}

function auditBindingsExact(audit, frames, framePlans) {
  const boundCommands = [];
  const boundFiles = [];
  for (const { frame, indexes, dynamic } of framePlans) {
    if (frame.auditBinding.filesystemReceiptIndexes.length > FILESYSTEM_MAX_RECEIPTS_PER_FRAME) {
      return false;
    }
    if (!same(frame.auditBinding.commandReceiptIndexes, indexes)) return false;
    for (let position = 0; position < indexes.length; position += 1) {
      const receipt = audit.commandReceipts[indexes[position]];
      if (
        !receiptWithinFrame(receipt, frame) ||
        (dynamic[position].phase === 'before-cutoff'
          ? !receiptEndsAtOrBeforeCutoff(receipt, frame)
          : !receiptStartsAtOrAfterCutoff(receipt, frame))
      ) {
        return false;
      }
      boundCommands.push(indexes[position]);
    }
    for (const index of frame.auditBinding.filesystemReceiptIndexes) {
      const receipt = audit.filesystemReceipts[index];
      if (
        receipt === undefined ||
        !receiptWithinFrame(receipt, frame) ||
        !receiptEndsAtOrBeforeCutoff(receipt, frame)
      ) {
        return false;
      }
      boundFiles.push(index);
    }
    const frameFiles = frame.auditBinding.filesystemReceiptIndexes.map(
      (index) => audit.filesystemReceipts[index]
    );
    if (!replayFilesystemFrame(frame, frameFiles)) return false;
  }
  const expectedDynamic = framePlans.flatMap(({ indexes }) => indexes);
  return (
    new Set(boundCommands).size === boundCommands.length &&
    new Set(boundFiles).size === boundFiles.length &&
    nonRunningInspectEvidenceStable(audit, framePlans) &&
    same(boundCommands, expectedDynamic) &&
    same(
      [...boundFiles].sort((left, right) => left - right),
      audit.filesystemReceipts.map((_, index) => index)
    )
  );
}

function capabilityAuditExact(audit, frames) {
  if (
    !exactKeys(audit, AUDIT_KEYS) ||
    audit.mode !== 'live-readonly-dynamic-acquisition-capability-bounded' ||
    !environmentPolicyExact(audit.environmentPolicy) ||
    !Array.isArray(audit.commandReceipts) ||
    !Array.isArray(audit.filesystemReceipts) ||
    audit.filesystemReceipts.length > FILESYSTEM_MAX_RECEIPTS_PER_RUN ||
    !exactKeys(audit.allowedProcessCounts, H045_ALLOWED_PROCESS_KEYS) ||
    !H045_ALLOWED_PROCESS_KEYS.every((key) =>
      nonNegativeInteger(audit.allowedProcessCounts[key])
    ) ||
    !nonNegativeInteger(audit.commandCount) ||
    !nonNegativeInteger(audit.filesystemReceiptCount) ||
    audit.commandReceipts.length !== audit.commandCount ||
    audit.filesystemReceipts.length !== audit.filesystemReceiptCount ||
    audit.complete !== true ||
    audit.exact !== true ||
    audit.frameCount !== 2 ||
    audit.lsusbCount !== 1 ||
    audit.unrecordedObservationCount !== 0 ||
    !exactKeys(audit.prohibitedCounts, H045_PROHIBITED_COUNT_KEYS) ||
    !H045_PROHIBITED_COUNT_KEYS.every(
      (key) => nonNegativeInteger(audit.prohibitedCounts[key]) && audit.prohibitedCounts[key] === 0
    )
  ) {
    return false;
  }

  const commandOrdinals = new Map();
  if (
    !audit.commandReceipts.every((receipt, index) =>
      exactCommandReceipt(receipt, index, commandOrdinals)
    )
  ) {
    return false;
  }
  const filesystemOrdinals = new Map();
  if (
    !audit.filesystemReceipts.every((receipt, index) =>
      exactFilesystemReceipt(receipt, index, filesystemOrdinals)
    )
  ) {
    return false;
  }

  const expected = commandPlanForFrames(frames);
  if (
    expected === null ||
    expected.plan.length !== audit.commandReceipts.length ||
    !expected.plan.every((entry, index) =>
      commandMatchesPlan(audit.commandReceipts[index], entry)
    ) ||
    !lsusbEvidenceExact(
      audit.commandReceipts.find((receipt) => receipt.kind === 'lsusb'),
      frames
    )
  ) {
    return false;
  }
  const receiptCounts = Object.fromEntries(H045_ALLOWED_PROCESS_KEYS.map((key) => [key, 0]));
  for (const receipt of audit.commandReceipts) receiptCounts[receipt.kind] += 1;
  return (
    H045_ALLOWED_PROCESS_KEYS.every(
      (key) => receiptCounts[key] === audit.allowedProcessCounts[key]
    ) &&
    Object.values(audit.allowedProcessCounts).reduce((sum, count) => sum + count, 0) ===
      audit.commandCount &&
    auditBindingsExact(audit, frames, expected.framePlans)
  );
}

function orderedFrames(first, second) {
  const firstStarted = monotonic(first.startedMonotonicNs);
  const firstEnded = monotonic(first.endedMonotonicNs);
  const secondStarted = monotonic(second.startedMonotonicNs);
  const secondEnded = monotonic(second.endedMonotonicNs);
  const firstCutoff = monotonic(first.observationCutoff.monotonicNs);
  const secondCutoff = monotonic(second.observationCutoff.monotonicNs);
  const firstStartedAt = Date.parse(first.startedAt);
  const firstEndedAt = Date.parse(first.endedAt);
  const secondStartedAt = Date.parse(second.startedAt);
  const secondEndedAt = Date.parse(second.endedAt);
  const firstCutoffAt = Date.parse(first.observationCutoff.at);
  const secondCutoffAt = Date.parse(second.observationCutoff.at);
  return (
    first.id !== second.id &&
    firstStarted <= firstEnded &&
    firstStarted <= firstCutoff &&
    firstCutoff <= firstEnded &&
    firstEnded <= secondStarted &&
    secondStarted <= secondEnded &&
    secondStarted <= secondCutoff &&
    secondCutoff <= secondEnded &&
    firstStartedAt <= firstEndedAt &&
    firstStartedAt <= firstCutoffAt &&
    firstCutoffAt <= firstEndedAt &&
    firstEndedAt <= secondStartedAt &&
    secondStartedAt <= secondEndedAt &&
    secondStartedAt <= secondCutoffAt &&
    secondCutoffAt <= secondEndedAt
  );
}

function acceptedSelector(value) {
  return (
    value.imageReference === H045_ACCEPTED_IMAGE_REFERENCE &&
    value.imageId === H045_ACCEPTED_IMAGE_ID
  );
}

function deploymentUsesAcceptedImage(deployment) {
  return (
    deployment.container.imageReference === H045_ACCEPTED_IMAGE_REFERENCE &&
    deployment.container.imageId === H045_ACCEPTED_IMAGE_ID &&
    (deployment.lifecycle === null || deployment.lifecycle.imageId === H045_ACCEPTED_IMAGE_ID)
  );
}

function deploymentCoherent(deployment) {
  if (deployment.lifecycle === null) {
    return (
      deployment.container.state !== 'running' &&
      deployment.pid1 === null &&
      deployment.workers.length === 0 &&
      deployment.descriptors.length === 0
    );
  }

  if (
    deployment.lifecycle.containerId !== deployment.container.id ||
    deployment.lifecycle.imageId !== deployment.container.imageId
  ) {
    return false;
  }

  if (deployment.pid1 !== null) {
    if (
      deployment.pid1.hostPid !== deployment.lifecycle.hostPid ||
      deployment.pid1.startTicks !== deployment.lifecycle.pid1StartTicks ||
      deployment.pid1.pidNamespace !== deployment.lifecycle.pidNamespace ||
      deployment.pid1.mountNamespace !== deployment.lifecycle.mountNamespace ||
      deployment.pid1.cgroup !== deployment.lifecycle.cgroup
    ) {
      return false;
    }
    if (
      deployment.workers.some(
        (worker) =>
          worker.ppid !== 1 ||
          worker.parentStartTicks !== deployment.pid1.startTicks ||
          worker.pidNamespace !== deployment.pid1.pidNamespace ||
          worker.mountNamespace !== deployment.pid1.mountNamespace ||
          worker.cgroup !== deployment.pid1.cgroup
      )
    ) {
      return false;
    }
  } else if (deployment.workers.length > 0) {
    return false;
  }

  return true;
}

function stableContainerAndLifecycle(first, second) {
  return same(first.container, second.container) && same(first.lifecycle, second.lifecycle);
}

function inventoryRowsAndMatchesCoherent(inventory) {
  if (inventory.rows.length === 0) return inventory.matches.length === 0;
  if (inventory.rows.length !== 1 || inventory.matches.length !== 1) return false;
  const row = inventory.rows[0];
  const match = inventory.matches[0];
  return row.containerId === match.container.id && row.state === match.container.state;
}

function receiptFor({ frames, capabilityAudit, exposureNs }) {
  const [first, second] = frames;
  const selected = second.deploymentInventory.matches[0];
  const body = {
    schemaVersion: 'overlaykit-h045-dynamic-tuple-receipt/v1',
    kind: 'cutoff-bound-dynamic-readonly-tuple',
    authority: 'none',
    action: null,
    authorizesAction: false,
    validAtCutoffOnly: true,
    revalidatedAtCutoff: true,
    requiresRevalidation: true,
    cutoff: clone(second.observationCutoff),
    exposure: {
      startedAt: first.startedAt,
      endedAt: second.observationCutoff.at,
      startedMonotonicNs: first.startedMonotonicNs,
      endedMonotonicNs: second.observationCutoff.monotonicNs,
      milliseconds: Number(exposureNs) / 1_000_000,
    },
    identity: {
      host: clone(second.host),
      device: clone(second.device.identity),
      deployment: {
        container: clone(selected.container),
        lifecycle: clone(selected.lifecycle),
        pid1: clone(selected.pid1),
        worker: clone(selected.workers[0]),
        descriptors: clone(selected.descriptors),
      },
    },
    markers: clone(selected.markers),
    sources: {
      acceptedImage: {
        imageReference: H045_ACCEPTED_IMAGE_REFERENCE,
        imageId: H045_ACCEPTED_IMAGE_ID,
      },
      frameDigests: frames.map((frame) => frame.digestSha256),
      capabilityAuditSha256: sha256Canonical(capabilityAudit),
    },
  };
  return { ...body, receiptSha256: sha256Canonical(body) };
}

export function independentlyClassifyDynamicFrames(input = {}) {
  const predicates = allFalsePredicates();

  try {
    predicates.sourceAdmissionExact =
      exactKeys(input, INPUT_KEYS) && input.sourceAdmissionExact === true;
    if (!predicates.sourceAdmissionExact) {
      return classification(
        'inconclusive',
        'source-admission',
        'source-admission-inexact',
        predicates
      );
    }

    const { frames, capabilityAudit } = input;
    if (!Array.isArray(frames) || frames.length !== 2) {
      return classification(
        'inconclusive',
        'frame-admission',
        'two-complete-frames-required',
        predicates
      );
    }

    predicates.framesComplete =
      frames.every(
        (frame) =>
          independentFrameExactShape(frame) &&
          frame.complete === true &&
          frame.device.complete === true &&
          frame.deploymentInventory.complete === true &&
          frame.deploymentInventory.exact === true &&
          frame.deploymentInventory.matches.every(
            (deployment) => deployment.complete === true && deployment.exact === true
          )
      ) && new Set(frames.map((frame) => frame.digestSha256)).size === 2;
    if (!predicates.framesComplete) {
      return classification(
        'inconclusive',
        'frame-admission',
        'incomplete-or-invalid-live-frame',
        predicates
      );
    }

    const presentIdentities = frames
      .filter((frame) => frame.device.present === true)
      .map((frame) => frame.device.identity);
    if (
      presentIdentities.some(
        (identity) =>
          sha256Text(identity.serial) !== H045_ACCEPTED_SERIAL_SHA256 ||
          identity.epoch.serial !== identity.serial
      )
    ) {
      return classification(
        'inconclusive',
        'identity',
        'accepted-device-serial-inexact',
        predicates
      );
    }
    if (
      presentIdentities.some(
        (identity) =>
          identity.epoch.stat.isCharacterDevice !== true ||
          identity.epoch.stat.major <= 0 ||
          !exactDeviceIdentity(identity)
      )
    ) {
      return classification('inconclusive', 'identity', 'accepted-device-node-inexact', predicates);
    }

    predicates.auditExact = capabilityAuditExact(capabilityAudit, frames);
    if (!predicates.auditExact) {
      return classification(
        'inconclusive',
        'capability-audit',
        prohibitedCapabilityObserved(capabilityAudit)
          ? 'prohibited-capability-observed'
          : 'capability-audit-incomplete-or-inexact',
        predicates
      );
    }

    const [first, second] = frames;
    predicates.frameOrderExact = orderedFrames(first, second);
    if (!predicates.frameOrderExact) {
      return classification('inconclusive', 'temporal-boundary', 'frame-order-invalid', predicates);
    }

    const exposureNs =
      monotonic(second.observationCutoff.monotonicNs) - monotonic(first.startedMonotonicNs);
    predicates.exposureBounded = exposureNs >= 0n && exposureNs <= MAX_EXPOSURE_NS;
    if (!predicates.exposureBounded) {
      return classification(
        'inconclusive',
        'temporal-boundary',
        'exposure-window-exceeded',
        predicates
      );
    }

    predicates.hostStable = same(first.host, second.host);
    if (!predicates.hostStable) {
      return classification('inconclusive', 'live-drift', 'host-identity-drift', predicates);
    }

    predicates.deviceStable = same(first.device, second.device);
    if (!predicates.deviceStable) {
      return classification('inconclusive', 'live-drift', 'device-identity-drift', predicates);
    }
    predicates.deviceExact = first.device.present === true && second.device.present === true;

    predicates.acceptedImageSelectorExact =
      acceptedSelector(first.deploymentInventory.selector) &&
      acceptedSelector(second.deploymentInventory.selector);
    if (!predicates.acceptedImageSelectorExact) {
      return classification(
        'inconclusive',
        'selector-boundary',
        'accepted-image-selector-inexact',
        predicates
      );
    }

    const firstRows = first.deploymentInventory.rows;
    const secondRows = second.deploymentInventory.rows;
    const firstMatches = first.deploymentInventory.matches;
    const secondMatches = second.deploymentInventory.matches;
    if (firstRows.length > 1 || secondRows.length > 1) {
      return classification(
        'inconclusive',
        'deployment-selection',
        'multiple-image-matches',
        predicates
      );
    }
    if (firstRows.length !== secondRows.length) {
      return classification('inconclusive', 'live-drift', 'deployment-presence-drift', predicates);
    }
    if (!same(firstRows, secondRows)) {
      return classification('inconclusive', 'live-drift', 'deployment-row-drift', predicates);
    }
    if (
      !inventoryRowsAndMatchesCoherent(first.deploymentInventory) ||
      !inventoryRowsAndMatchesCoherent(second.deploymentInventory)
    ) {
      return classification(
        'inconclusive',
        'deployment-selection',
        'deployment-inventory-inconsistent',
        predicates
      );
    }

    if (firstRows.length === 0) {
      predicates.deploymentStable = true;
      predicates.pid1Stable = true;
      predicates.workerStable = true;
      predicates.descriptorStable = true;
      predicates.descriptorAbsent = true;
      predicates.markersStable = true;
      return classification(
        'withheld',
        'not-eligible',
        'accepted-image-deployment-absent',
        predicates
      );
    }

    const firstDeployment = firstMatches[0];
    const secondDeployment = secondMatches[0];
    if (
      !deploymentUsesAcceptedImage(firstDeployment) ||
      !deploymentUsesAcceptedImage(secondDeployment)
    ) {
      return classification(
        'inconclusive',
        'selector-boundary',
        'accepted-image-match-inexact',
        predicates
      );
    }
    if (!deploymentCoherent(firstDeployment) || !deploymentCoherent(secondDeployment)) {
      return classification(
        'inconclusive',
        'contradictory-evidence',
        'deployment-observation-contradiction',
        predicates
      );
    }

    predicates.deploymentUnique = true;
    predicates.deploymentStable = stableContainerAndLifecycle(firstDeployment, secondDeployment);
    if (!predicates.deploymentStable) {
      return classification(
        'inconclusive',
        'live-drift',
        'deployment-identity-or-lifecycle-drift',
        predicates
      );
    }

    predicates.deploymentRunning =
      firstDeployment.container.state === 'running' &&
      secondDeployment.container.state === 'running';
    predicates.pid1Stable = same(firstDeployment.pid1, secondDeployment.pid1);
    if (!predicates.pid1Stable) {
      return classification('inconclusive', 'live-drift', 'pid1-identity-drift', predicates);
    }

    if (firstDeployment.workers.length > 1 || secondDeployment.workers.length > 1) {
      return classification('inconclusive', 'identity', 'worker-ambiguity', predicates);
    }
    if (firstDeployment.workers.length !== secondDeployment.workers.length) {
      return classification('inconclusive', 'identity', 'worker-presence-drift', predicates);
    }

    predicates.workerUnique =
      firstDeployment.workers.length === 1 && secondDeployment.workers.length === 1;
    predicates.workerStable =
      firstDeployment.workers.length === 0 ||
      same(firstDeployment.workers[0], secondDeployment.workers[0]);
    if (!predicates.workerStable) {
      return classification('inconclusive', 'identity', 'worker-identity-drift', predicates);
    }

    predicates.descriptorStable = same(firstDeployment.descriptors, secondDeployment.descriptors);
    if (!predicates.descriptorStable) {
      return classification('inconclusive', 'live-drift', 'descriptor-state-drift', predicates);
    }
    predicates.descriptorAbsent =
      firstDeployment.descriptors.length === 0 && secondDeployment.descriptors.length === 0;

    predicates.markersStable = same(firstDeployment.markers, secondDeployment.markers);
    if (!predicates.markersStable) {
      return classification('inconclusive', 'live-drift', 'marker-drift', predicates);
    }

    if (!predicates.deploymentRunning) {
      return classification('withheld', 'not-eligible', 'deployment-not-running', predicates);
    }
    if (!predicates.deviceExact) {
      return classification('withheld', 'not-eligible', 'device-absent', predicates);
    }
    if (firstDeployment.pid1 === null || secondDeployment.pid1 === null) {
      return classification(
        'inconclusive',
        'frame-admission',
        'running-deployment-pid1-incomplete',
        predicates
      );
    }
    if (!predicates.workerUnique) {
      return classification('withheld', 'not-eligible', 'surface-worker-absent', predicates);
    }
    if (!predicates.descriptorAbsent) {
      return classification('withheld', 'not-eligible', 'current-descriptor-present', predicates);
    }

    if (!Object.values(predicates).every((value) => value === true)) {
      return classification('inconclusive', 'classification', 'predicate-gap', predicates);
    }

    return classification(
      'candidate',
      'dynamic-readonly-acquisition',
      'cutoff-bound-dynamic-tuple',
      predicates,
      [receiptFor({ frames, capabilityAudit, exposureNs })]
    );
  } catch {
    return classification(
      'inconclusive',
      'input-admission',
      'malformed-live-input',
      allFalsePredicates()
    );
  }
}

function receiptExactShape(value) {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'kind',
      'authority',
      'action',
      'authorizesAction',
      'validAtCutoffOnly',
      'revalidatedAtCutoff',
      'requiresRevalidation',
      'cutoff',
      'exposure',
      'identity',
      'markers',
      'sources',
      'receiptSha256',
    ]) ||
    value.schemaVersion !== 'overlaykit-h045-dynamic-tuple-receipt/v1' ||
    value.kind !== 'cutoff-bound-dynamic-readonly-tuple' ||
    value.authority !== 'none' ||
    value.action !== null ||
    value.authorizesAction !== false ||
    value.validAtCutoffOnly !== true ||
    value.revalidatedAtCutoff !== true ||
    value.requiresRevalidation !== true ||
    !exactKeys(value.cutoff, ['at', 'monotonicNs']) ||
    !dateTime(value.cutoff.at) ||
    !MONOTONIC_PATTERN.test(value.cutoff.monotonicNs) ||
    !exactKeys(value.exposure, [
      'startedAt',
      'endedAt',
      'startedMonotonicNs',
      'endedMonotonicNs',
      'milliseconds',
    ]) ||
    !dateTime(value.exposure.startedAt) ||
    !dateTime(value.exposure.endedAt) ||
    !MONOTONIC_PATTERN.test(value.exposure.startedMonotonicNs) ||
    !MONOTONIC_PATTERN.test(value.exposure.endedMonotonicNs) ||
    !Number.isFinite(value.exposure.milliseconds) ||
    value.exposure.milliseconds < 0 ||
    value.exposure.milliseconds > Number(MAX_EXPOSURE_NS) / 1_000_000 ||
    value.exposure.endedAt !== value.cutoff.at ||
    value.exposure.endedMonotonicNs !== value.cutoff.monotonicNs ||
    !exactKeys(value.identity, ['host', 'device', 'deployment']) ||
    !exactHost(value.identity.host) ||
    !exactDeviceIdentity(value.identity.device) ||
    !exactKeys(value.identity.deployment, [
      'container',
      'lifecycle',
      'pid1',
      'worker',
      'descriptors',
    ]) ||
    !exactContainer(value.identity.deployment.container) ||
    !exactLifecycle(value.identity.deployment.lifecycle) ||
    !exactPid1(value.identity.deployment.pid1) ||
    !exactWorker(value.identity.deployment.worker) ||
    !Array.isArray(value.identity.deployment.descriptors) ||
    value.identity.deployment.descriptors.length !== 0 ||
    !exactMarkers(value.markers) ||
    !exactKeys(value.sources, ['acceptedImage', 'frameDigests', 'capabilityAuditSha256']) ||
    !exactKeys(value.sources.acceptedImage, ['imageReference', 'imageId']) ||
    !acceptedSelector(value.sources.acceptedImage) ||
    !Array.isArray(value.sources.frameDigests) ||
    value.sources.frameDigests.length !== 2 ||
    !value.sources.frameDigests.every(validSha256) ||
    new Set(value.sources.frameDigests).size !== 2 ||
    !validSha256(value.sources.capabilityAuditSha256) ||
    !validSha256(value.receiptSha256)
  ) {
    return false;
  }

  const exposureNs =
    monotonic(value.exposure.endedMonotonicNs) - monotonic(value.exposure.startedMonotonicNs);
  const deployment = value.identity.deployment;
  if (
    exposureNs < 0n ||
    value.exposure.milliseconds !== Number(exposureNs) / 1_000_000 ||
    deployment.container.state !== 'running' ||
    !deploymentUsesAcceptedImage(deployment) ||
    !deploymentCoherent({
      complete: true,
      exact: true,
      container: deployment.container,
      lifecycle: deployment.lifecycle,
      pid1: deployment.pid1,
      workers: [deployment.worker],
      descriptors: deployment.descriptors,
      markers: value.markers,
    })
  ) {
    return false;
  }

  const { receiptSha256, ...body } = value;
  return receiptSha256 === sha256Canonical(body);
}

export function independentClassificationExactShape(value) {
  return (
    exactKeys(value, ['disposition', 'stage', 'reasonCode', 'predicates', 'receipts']) &&
    ['candidate', 'withheld', 'inconclusive'].includes(value.disposition) &&
    scalarString(value.stage) &&
    scalarString(value.reasonCode) &&
    exactKeys(value.predicates, H045_PREDICATE_KEYS) &&
    H045_PREDICATE_KEYS.every((key) => typeof value.predicates[key] === 'boolean') &&
    Array.isArray(value.receipts) &&
    value.receipts.length <= 1 &&
    (value.disposition === 'candidate'
      ? Object.values(value.predicates).every((predicate) => predicate === true) &&
        value.receipts.length === 1 &&
        receiptExactShape(value.receipts[0])
      : value.receipts.length === 0)
  );
}

const INDEPENDENT_COMMAND_ENVIRONMENT_POLICY = Object.freeze({
  mode: 'closed-fixed',
  inheritedKeys: Object.freeze([]),
  fixed: Object.freeze({
    DOCKER_CONFIG: '/nonexistent/overlaykit-h045-docker-config',
    GIT_CONFIG_COUNT: '0',
    GIT_CONFIG_GLOBAL: '/dev/null',
    GIT_CONFIG_NOSYSTEM: '1',
    LANG: 'C',
    LC_ALL: 'C',
  }),
});

function sealIndependentFrame(frame) {
  const body = structuredClone(frame);
  delete body.digestSha256;
  return { ...body, digestSha256: sha256Canonical(body) };
}

// Independently reconstructed hostile fixture and mutation matrix.
function syntheticStat() {
  return {
    stDev: '7',
    inode: '4001',
    ctimeNs: '1900000000000000000',
    mode: '0660',
    uid: 0,
    gid: 1002,
    rdev: '61696',
    rdevHex: 'f1:0',
    major: 241,
    minor: 0,
    isCharacterDevice: true,
  };
}

function syntheticDescriptor(descriptor = '20', target = '/dev/hidraw0') {
  return {
    descriptor,
    target,
    lstat: {
      stDev: '7',
      inode: '5001',
      ctimeNs: '1900000000000000000',
      mode: '0777',
      uid: 0,
      gid: 0,
      rdev: '0',
      rdevHex: '0:0',
      major: 0,
      minor: 0,
      isCharacterDevice: false,
      isSymbolicLink: true,
    },
    stat: {
      ...syntheticStat(),
      isSymbolicLink: false,
    },
  };
}

function syntheticEpoch(serial) {
  return {
    serial,
    busNumber: '1',
    deviceNumber: '42',
    usbDevicePath: '2',
    usbDev: '189:41',
    hidDevicePath: '/sys/devices/usb1/1-2/1-2:1.0/0003:0FD9:0080.0042',
    devicePath: '/dev/hidraw0',
    stat: syntheticStat(),
  };
}

function syntheticLifecycle(containerId = 'c'.repeat(64)) {
  return {
    containerId,
    imageId: H045_ACCEPTED_IMAGE_ID,
    startedAt: '2026-07-27T03:00:00.000Z',
    restartCount: 0,
    hostPid: 4242,
    pid1StartTicks: 7000,
    pidNamespace: 'pid:[4026533001]',
    mountNamespace: 'mnt:[4026533002]',
    cgroup: '0::/',
    hostCgroup: `0::/system.slice/docker-${containerId}.scope`,
    cgroupNamespaceMode: 'private',
  };
}

function syntheticPid1() {
  return {
    hostPid: 4242,
    startTicks: 7000,
    pidNamespace: 'pid:[4026533001]',
    mountNamespace: 'mnt:[4026533002]',
    cgroup: '0::/',
  };
}

function syntheticWorker({ pid = 73, startTicks = 7100 } = {}) {
  return {
    pid,
    startTicks,
    ppid: 1,
    parentStartTicks: 7000,
    uid: 1000,
    gid: 1000,
    groups: [1000, 1002],
    cmdline: [
      '/app/node-runtimes/node22/bin/node',
      '--enable-source-maps',
      '/app/SurfaceThread.js',
    ],
    cgroup: '0::/',
    pidNamespace: 'pid:[4026533001]',
    mountNamespace: 'mnt:[4026533002]',
  };
}

function syntheticMarkerEvidence(serial, opening = 4, ready = 4) {
  const entries = [];
  const append = (kind, count, text) => {
    for (let index = 0; index < count; index += 1) {
      const at = new Date(Date.parse('2026-07-27T03:00:01.000Z') + entries.length).toISOString();
      entries.push({
        at,
        stream: 'stdout',
        line: `${kind} ${index + 1}: ${text}`,
      });
    }
  };
  append('opening', opening, `Opening surface panel: streamdeck:${serial}`);
  append('ready', ready, `Surface panel ready: streamdeck:${serial}`);
  return {
    markers: {
      opening,
      ready,
      relevantLinesSha256: digestBytes(
        Buffer.from(
          entries.map((entry) => `${entry.at}\t${entry.stream}\t${entry.line}`).join('\n'),
          'utf8'
        )
      ),
    },
    stdout: entries
      .map((entry) => `${entry.at} ${entry.line}`)
      .join('\n')
      .concat('\n'),
  };
}

function syntheticDeployment(containerId = 'c'.repeat(64)) {
  return {
    complete: true,
    exact: true,
    container: {
      id: containerId,
      imageReference: H045_ACCEPTED_IMAGE_REFERENCE,
      imageId: H045_ACCEPTED_IMAGE_ID,
      state: 'running',
    },
    lifecycle: syntheticLifecycle(containerId),
    pid1: syntheticPid1(),
    workers: [syntheticWorker()],
    descriptors: [],
    markers: {
      opening: 0,
      ready: 0,
      relevantLinesSha256: digestBytes(Buffer.alloc(0)),
    },
  };
}

function syntheticFrames(acceptedTarget) {
  if (
    !plainObject(acceptedTarget) ||
    typeof acceptedTarget.serial !== 'string' ||
    acceptedTarget.serial === ''
  ) {
    throw new TypeError('acceptedTarget with an admitted serial is required');
  }
  const deployment = syntheticDeployment();
  deployment.markers = syntheticMarkerEvidence(acceptedTarget.serial).markers;
  const common = {
    complete: true,
    host: {
      hostname: 'h045-synthetic-host',
      bootId: '00000000-0000-4000-8000-000000000045',
      osRelease: '{"id":"linux","prettyName":"H-045 synthetic","versionId":"1"}',
    },
    device: {
      complete: true,
      present: true,
      identity: {
        serial: acceptedTarget.serial,
        vendorId: '0fd9',
        productId: '0080',
        epoch: syntheticEpoch(acceptedTarget.serial),
      },
    },
    deploymentInventory: {
      complete: true,
      exact: true,
      selector: {
        imageReference: H045_ACCEPTED_IMAGE_REFERENCE,
        imageId: H045_ACCEPTED_IMAGE_ID,
      },
      rows: [
        {
          containerId: deployment.container.id,
          state: deployment.container.state,
        },
      ],
      matches: [deployment],
    },
  };
  return [
    sealIndependentFrame({
      id: 'hostile-frame-1',
      startedAt: '2026-07-27T03:00:10.000Z',
      endedAt: '2026-07-27T03:00:10.900Z',
      startedMonotonicNs: '200000000000',
      endedMonotonicNs: '200900000000',
      observationCutoff: {
        at: '2026-07-27T03:00:10.800Z',
        monotonicNs: '200800000000',
      },
      ...clone(common),
      auditBinding: {
        commandReceiptIndexes: [6, 7, 8],
        filesystemReceiptIndexes: [0],
      },
    }),
    sealIndependentFrame({
      id: 'hostile-frame-2',
      startedAt: '2026-07-27T03:00:10.900Z',
      endedAt: '2026-07-27T03:00:11.800Z',
      startedMonotonicNs: '200900000000',
      endedMonotonicNs: '201800000000',
      observationCutoff: {
        at: '2026-07-27T03:00:11.700Z',
        monotonicNs: '201700000000',
      },
      ...clone(common),
      auditBinding: {
        commandReceiptIndexes: [9, 10, 11],
        filesystemReceiptIndexes: [1],
      },
    }),
  ];
}

function zeroProhibitedCounts() {
  return {
    externalNetwork: 0,
    unrestrictedContainerInventory: 0,
    dockerExec: 0,
    hidrawOpen: 0,
    hidrawRead: 0,
    hidrawWrite: 0,
    hidrawIoctl: 0,
    signal: 0,
    lifecycleMutation: 0,
    configurationMutation: 0,
    mountMutation: 0,
    cgroupMutation: 0,
    sysfsWrite: 0,
    productionMutation: 0,
  };
}

function syntheticOutputReceipt(value = '') {
  const bytes = Buffer.from(value, 'utf8');
  const text = bytes.toString('utf8');
  const withoutFinalNewline = text.endsWith('\n') ? text.slice(0, -1) : text;
  return {
    encoding: 'utf8',
    text,
    base64: bytes.toString('base64'),
    byteLength: bytes.byteLength,
    lineCount: withoutFinalNewline === '' ? 0 : withoutFinalNewline.split('\n').length,
    sha256: digestBytes(bytes),
  };
}

function syntheticCommandDefinitions(frames) {
  const definitions = [
    {
      kind: 'git',
      observerKind: 'gitRevParse',
      executable: 'git',
      args: ['rev-parse', 'HEAD'],
    },
    {
      kind: 'git',
      observerKind: 'gitMergeBaseAncestor',
      executable: 'git',
      args: ['merge-base', '--is-ancestor', H045_PROTECTED_MAIN_COMMIT, 'HEAD'],
    },
    {
      kind: 'git',
      observerKind: 'gitMergeBaseAncestor',
      executable: 'git',
      args: ['merge-base', '--is-ancestor', H045_SOURCE_CONTRACT_COMMIT, 'HEAD'],
    },
    {
      kind: 'git',
      observerKind: 'gitRemoteGetUrl',
      executable: 'git',
      args: ['remote', 'get-url', 'origin'],
    },
    {
      kind: 'lsusb',
      executable: 'lsusb',
      args: [],
    },
    {
      kind: 'dockerVersion',
      executable: 'docker',
      args: ['--host', DOCKER_UNIX_HOST, 'version', '--format', DOCKER_VERSION_FORMAT],
    },
  ];
  for (const frame of frames) {
    const indexes = [];
    const add = (definition) => {
      indexes.push(definitions.length);
      definitions.push({ ...definition, frame });
    };
    add({
      kind: 'dockerPs',
      executable: 'docker',
      args: [
        '--host',
        DOCKER_UNIX_HOST,
        'ps',
        '--all',
        '--no-trunc',
        '--filter',
        DOCKER_ANCESTOR_FILTER,
        '--format',
        DOCKER_PS_FORMAT,
      ],
      phase: 'before-cutoff',
    });
    const rows = frame.deploymentInventory.rows;
    const selected = frame.deploymentInventory.matches[0];
    if (rows.length === 1) {
      add({
        kind: 'dockerInspect',
        executable: 'docker',
        args: [
          '--host',
          DOCKER_UNIX_HOST,
          'inspect',
          '--format',
          DOCKER_INSPECT_FORMAT,
          rows[0].containerId,
        ],
        phase: 'before-cutoff',
      });
      if (selected?.container.state === 'running' && selected.lifecycle !== null) {
        add({
          kind: 'dockerLogs',
          executable: 'docker',
          args: [
            '--host',
            DOCKER_UNIX_HOST,
            'logs',
            '--timestamps',
            '--since',
            selected.lifecycle.startedAt,
            '--until',
            frame.observationCutoff.at,
            rows[0].containerId,
          ],
          phase: 'at-or-after-cutoff',
        });
      }
    }
    frame.auditBinding.commandReceiptIndexes = indexes;
  }
  return definitions;
}

function syntheticCommandTiming(index, definition) {
  if (definition.frame === undefined) {
    const startedMs = Date.parse('2026-07-27T03:00:09.000Z') + index * 20;
    const startedNs = 199_000_000_000n + BigInt(index) * 20_000_000n;
    return {
      startedAt: new Date(startedMs).toISOString(),
      endedAt: new Date(startedMs + 10).toISOString(),
      startedMonotonicNs: startedNs.toString(),
      endedMonotonicNs: (startedNs + 10_000_000n).toString(),
      durationNs: '10000000',
    };
  }
  const frame = definition.frame;
  const afterCutoff = definition.phase === 'at-or-after-cutoff';
  const startedAt = afterCutoff ? frame.observationCutoff.at : frame.startedAt;
  const startedNs = afterCutoff
    ? BigInt(frame.observationCutoff.monotonicNs)
    : BigInt(frame.startedMonotonicNs) + BigInt(index + 1);
  return {
    startedAt,
    endedAt: startedAt,
    startedMonotonicNs: startedNs.toString(),
    endedMonotonicNs: startedNs.toString(),
    durationNs: '0',
  };
}

function syntheticLsusbStdout(frames, acceptedTarget) {
  const epochs = new Map();
  for (const frame of frames) {
    if (!frame.device.present) continue;
    const epoch = frame.device.identity.epoch;
    epochs.set(`${epoch.busNumber}:${epoch.deviceNumber}`, epoch);
  }
  return [...epochs.values()]
    .map(
      (epoch) =>
        `Bus ${epoch.busNumber.padStart(3, '0')} Device ${epoch.deviceNumber.padStart(3, '0')}: ` +
        `ID ${acceptedTarget.vendorId}:${acceptedTarget.productId} Elgato Stream Deck MK.2`
    )
    .join('\n')
    .concat(epochs.size === 0 ? '' : '\n');
}

function syntheticCommandStdout(definition, acceptedTarget, frames) {
  if (definition.observerKind === 'gitRevParse') return `${'f'.repeat(40)}\n`;
  if (definition.observerKind === 'gitRemoteGetUrl') return `${REPOSITORY}\n`;
  if (definition.kind === 'lsusb') return syntheticLsusbStdout(frames, acceptedTarget);
  if (definition.kind === 'dockerVersion') {
    return `${JSON.stringify({
      Client: { Version: 'fixture', ApiVersion: '1.47' },
      Server: { Version: 'fixture', ApiVersion: '1.47' },
    })}\n`;
  }
  if (definition.kind === 'dockerPs') {
    return definition.frame.deploymentInventory.rows
      .map((row) => JSON.stringify({ ID: row.containerId, State: row.state }))
      .join('\n')
      .concat(definition.frame.deploymentInventory.rows.length === 0 ? '' : '\n');
  }
  if (definition.kind === 'dockerInspect') {
    const selected = definition.frame.deploymentInventory.matches[0];
    const row = definition.frame.deploymentInventory.rows[0];
    const lifecycle = selected?.lifecycle ?? null;
    return `${JSON.stringify({
      Id: row.containerId,
      Image: H045_ACCEPTED_IMAGE_ID,
      State: {
        Status: row.state,
        Running: row.state === 'running',
        Pid: lifecycle?.hostPid ?? 0,
        StartedAt: lifecycle?.startedAt ?? '0001-01-01T00:00:00Z',
      },
      RestartCount: lifecycle?.restartCount ?? 0,
      CgroupnsMode: lifecycle?.cgroupNamespaceMode ?? 'private',
    })}\n`;
  }
  if (definition.kind === 'dockerLogs') {
    const markers = definition.frame.deploymentInventory.matches[0].markers;
    return syntheticMarkerEvidence(acceptedTarget.serial, markers.opening, markers.ready).stdout;
  }
  return '';
}

function syntheticCommandReceipts(frames, acceptedTarget) {
  const ordinals = new Map();
  const receipts = syntheticCommandDefinitions(frames).map((definition, index) => {
    const ordinalKey = definition.kind === 'git' ? definition.observerKind : definition.kind;
    const ordinal = (ordinals.get(ordinalKey) ?? 0) + 1;
    ordinals.set(ordinalKey, ordinal);
    const receipt = {
      index,
      kind: definition.kind,
      ordinal,
      executable: definition.executable,
      args: [...definition.args],
      ...syntheticCommandTiming(index, definition),
      limits: {
        maxBufferBytes: 4 * 1024 * 1024,
        timeoutMs: null,
        overflow: 'drain-without-signal',
      },
      environmentPolicy: clone(INDEPENDENT_COMMAND_ENVIRONMENT_POLICY),
      exitCode: 0,
      signal: null,
      stdout: syntheticOutputReceipt(syntheticCommandStdout(definition, acceptedTarget, frames)),
      stderr: syntheticOutputReceipt(),
      cardinality: {
        global: index + 1,
        kind: ordinal,
      },
      errorCode: null,
    };
    return definition.kind === 'git'
      ? { ...receipt, observerKind: definition.observerKind }
      : receipt;
  });
  for (const frame of frames) Object.assign(frame, sealIndependentFrame(frame));
  return receipts;
}

function syntheticFilesystemReadResult(value) {
  const bytes = Buffer.from(value, 'utf8');
  const digest = digestBytes(bytes);
  return {
    cardinality: 1,
    byteLength: bytes.byteLength,
    bytes: {
      encoding: 'base64',
      base64: bytes.toString('base64'),
      byteLength: bytes.byteLength,
      sha256: digest,
    },
    encoding: 'utf8',
    text: value,
    sha256: digest,
  };
}

function syntheticFilesystemStatResult(value) {
  const metadata = verifierPlainObject(value)
    ? clone(value)
    : {
        ...syntheticStat(),
        isSymbolicLink: false,
      };
  return {
    cardinality: 1,
    metadata,
    sha256: digestBytes(Buffer.from(JSON.stringify(metadata), 'utf8')),
  };
}

function syntheticFilesystemResult(operation, value) {
  if (operation === 'readFileSync') return syntheticFilesystemReadResult(value);
  if (operation === 'readdirSync') {
    const entries = [...value];
    return {
      entries,
      cardinality: entries.length,
      sha256: digestBytes(Buffer.from(JSON.stringify(entries), 'utf8')),
    };
  }
  if (operation === 'realpathSync' || operation === 'readlinkSync') {
    return {
      value,
      cardinality: 1,
      sha256: digestBytes(Buffer.from(value, 'utf8')),
    };
  }
  return syntheticFilesystemStatResult(value);
}

function syntheticFilesystemDefinitions(frame) {
  const definitions = [
    ['readFileSync', '/etc/os-release', 'ID=linux\nVERSION_ID=1\nPRETTY_NAME="H-045 synthetic"\n'],
    ['readFileSync', '/proc/sys/kernel/random/boot_id', `${frame.host.bootId}\n`],
    ['readFileSync', '/proc/sys/kernel/hostname', `${frame.host.hostname}\n`],
    ['readdirSync', '/sys/class/hidraw', frame.device.present ? ['hidraw0'] : []],
  ];
  if (frame.device.present) {
    const epoch = frame.device.identity.epoch;
    const hidrawName = path.basename(epoch.devicePath);
    const classPath = `/sys/class/hidraw/${hidrawName}`;
    const sysfsPath = epoch.hidDevicePath;
    definitions.push(
      ['realpathSync', `${classPath}/device`, sysfsPath],
      [
        'readFileSync',
        `${classPath}/device/uevent`,
        `HID_ID=0003:0FD9:0080\nHID_UNIQ=${frame.device.identity.serial}\nHID_NAME=Stream Deck MK.2\n`,
      ],
      ['readFileSync', `${classPath}/dev`, '241:0\n'],
      ['statSync', epoch.devicePath, null],
      ['readFileSync', `${sysfsPath}/idVendor`, '0fd9\n'],
      ['readFileSync', `${sysfsPath}/idProduct`, '0080\n'],
      ['readFileSync', `${sysfsPath}/serial`, `${frame.device.identity.serial}\n`],
      ['readFileSync', `${sysfsPath}/manufacturer`, 'Elgato\n'],
      ['readFileSync', `${sysfsPath}/product`, 'Stream Deck MK.2\n'],
      ['readFileSync', `${sysfsPath}/busnum`, `${epoch.busNumber}\n`],
      ['readFileSync', `${sysfsPath}/devnum`, `${epoch.deviceNumber}\n`],
      ['readFileSync', `${sysfsPath}/devpath`, `${epoch.usbDevicePath}\n`],
      ['statSync', epoch.devicePath, null],
      ['lstatSync', epoch.devicePath, null],
      ['statSync', epoch.devicePath, null],
      ['readFileSync', `${sysfsPath}/dev`, epoch.usbDev]
    );
  }
  const selected =
    frame.deploymentInventory.rows.length === 1 && frame.deploymentInventory.matches.length === 1
      ? frame.deploymentInventory.matches[0]
      : null;
  if (selected?.container.state === 'running' && selected.lifecycle !== null) {
    const procRoot = `/proc/${selected.lifecycle.hostPid}/root/proc`;
    const processIdentities = [
      ...(selected.pid1 === null ? [] : [{ ...selected.pid1, pid: 1 }]),
      ...selected.workers,
    ].sort((left, right) => left.pid - right.pid);
    const processEntries = processIdentities.map((identity) => String(identity.pid));
    definitions.push(['readdirSync', procRoot, processEntries]);
    for (const processIdentity of processIdentities) {
      const directory = `${procRoot}/${processIdentity.pid}`;
      const worker =
        processIdentity.pid === 1
          ? null
          : selected.workers.find((entry) => entry.pid === processIdentity.pid);
      const ppid = worker === null ? 0 : worker.ppid;
      definitions.push(
        [
          'readFileSync',
          `${directory}/stat`,
          `${processIdentity.pid} (fixture) S ${[
            String(ppid),
            ...Array.from({ length: 17 }, () => '0'),
            String(processIdentity.startTicks),
          ].join(' ')}\n`,
        ],
        [
          'readFileSync',
          `${directory}/status`,
          `Name:\tfixture\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t1000 1002\nNSpid:\t${processIdentity.pid}\n`,
        ],
        [
          'readFileSync',
          `${directory}/cmdline`,
          `${worker === null ? '/sbin/tini' : worker.cmdline.join('\u0000')}\u0000`,
        ],
        ['readFileSync', `${directory}/cgroup`, '0::/\n'],
        ['readlinkSync', `${directory}/ns/pid`, processIdentity.pidNamespace],
        ['readlinkSync', `${directory}/ns/mnt`, processIdentity.mountNamespace]
      );
    }
    definitions.push(['readdirSync', procRoot, processEntries]);
    if (frame.device.present) {
      for (const worker of [...selected.workers].sort((left, right) => left.pid - right.pid)) {
        const directory = `${procRoot}/${worker.pid}/fd`;
        const descriptorEntries = [...selected.descriptors].sort(
          (left, right) => Number(left.descriptor) - Number(right.descriptor)
        );
        const descriptors = descriptorEntries.map((entry) => entry.descriptor);
        definitions.push(['readdirSync', directory, descriptors]);
        for (const descriptorEntry of descriptorEntries) {
          const descriptorPath = `${directory}/${descriptorEntry.descriptor}`;
          definitions.push(
            ['lstatSync', descriptorPath, descriptorEntry.lstat],
            ['readlinkSync', descriptorPath, descriptorEntry.target],
            ['statSync', descriptorPath, descriptorEntry.stat]
          );
        }
        definitions.push(['readdirSync', directory, descriptors]);
      }
    }
    definitions.push([
      'readFileSync',
      `/proc/${selected.lifecycle.hostPid}/cgroup`,
      selected.lifecycle.hostCgroup,
    ]);
  }
  return definitions;
}

function syntheticFilesystemReceipts(frames) {
  const ordinals = new Map();
  const receipts = [];
  for (const frame of frames) {
    const definitions = syntheticFilesystemDefinitions(frame);
    const frameStartIndex = receipts.length;
    for (const [operation, targetPath, value] of definitions) {
      const index = receipts.length;
      const ordinal = (ordinals.get(operation) ?? 0) + 1;
      ordinals.set(operation, ordinal);
      const frameOffset = index - frameStartIndex + 1;
      const startedNs = BigInt(frame.startedMonotonicNs) + BigInt(100 + frameOffset);
      receipts.push({
        index,
        operation,
        path: targetPath,
        startedAt: frame.startedAt,
        endedAt: frame.startedAt,
        startedMonotonicNs: startedNs.toString(),
        endedMonotonicNs: startedNs.toString(),
        durationNs: '0',
        disposition: 'observed',
        result: syntheticFilesystemResult(operation, value),
        errorCode: null,
        cardinality: {
          global: index + 1,
          operation: ordinal,
        },
      });
    }
    frame.auditBinding.filesystemReceiptIndexes = Array.from(
      { length: definitions.length },
      (_, offset) => frameStartIndex + offset
    );
    Object.assign(frame, sealIndependentFrame(frame));
  }
  return receipts;
}

function syntheticCapabilityAudit(frames, acceptedTarget) {
  const commandReceipts = syntheticCommandReceipts(frames, acceptedTarget);
  const filesystemReceipts = syntheticFilesystemReceipts(frames);
  const allowedProcessCounts = Object.fromEntries(
    ['git', 'lsusb', 'dockerVersion', 'dockerPs', 'dockerInspect', 'dockerLogs'].map((kind) => [
      kind,
      commandReceipts.filter((receipt) => receipt.kind === kind).length,
    ])
  );
  return {
    mode: 'live-readonly-dynamic-acquisition-capability-bounded',
    environmentPolicy: clone(INDEPENDENT_COMMAND_ENVIRONMENT_POLICY),
    commandReceipts,
    filesystemReceipts,
    allowedProcessCounts,
    commandCount: commandReceipts.length,
    filesystemReceiptCount: filesystemReceipts.length,
    complete: true,
    exact: true,
    frameCount: 2,
    lsusbCount: 1,
    unrecordedObservationCount: 0,
    prohibitedCounts: zeroProhibitedCounts(),
  };
}

function reseal(frame) {
  Object.assign(frame, sealIndependentFrame(frame));
}

function hostileDefinitions() {
  const definitions = [
    {
      id: 'multiple-image-matches',
      disposition: 'inconclusive',
      reasonCode: 'multiple-image-matches',
      mutate(input) {
        const other = syntheticDeployment('d'.repeat(64));
        for (const frame of input.frames) {
          frame.deploymentInventory.rows.push({
            containerId: other.container.id,
            state: other.container.state,
          });
          frame.deploymentInventory.matches = [];
          reseal(frame);
        }
      },
    },
    {
      id: 'selector-broadening',
      disposition: 'inconclusive',
      reasonCode: 'accepted-image-selector-inexact',
      mutate(input) {
        for (const frame of input.frames) {
          frame.deploymentInventory.selector.imageReference =
            'ghcr.io/bitfocus/companion/companion:latest';
          reseal(frame);
        }
      },
    },
    {
      id: 'descendant-image-mismatch',
      disposition: 'inconclusive',
      reasonCode: 'accepted-image-match-inexact',
      mutate(input) {
        for (const frame of input.frames) {
          const deployment = frame.deploymentInventory.matches[0];
          deployment.container.imageId = `sha256:${'b'.repeat(64)}`;
          deployment.lifecycle.imageId = `sha256:${'b'.repeat(64)}`;
          reseal(frame);
        }
      },
    },
    {
      id: 'hidden-container-row',
      disposition: 'inconclusive',
      reasonCode: 'capability-audit-incomplete-or-inexact',
      mutate(input) {
        for (const receipt of input.capabilityAudit.commandReceipts.filter(
          (entry) => entry.kind === 'dockerPs'
        )) {
          const hidden = `${JSON.stringify({
            ID: 'd'.repeat(64),
            State: 'running',
          })}\n`;
          receipt.stdout = syntheticOutputReceipt(`${receipt.stdout.text}${hidden}`);
        }
      },
    },
    {
      id: 'deployment-presence-drift',
      disposition: 'inconclusive',
      reasonCode: 'deployment-presence-drift',
      mutate(input) {
        input.frames[1].deploymentInventory.rows = [];
        input.frames[1].deploymentInventory.matches = [];
        reseal(input.frames[1]);
      },
    },
    {
      id: 'container-drift',
      disposition: 'inconclusive',
      reasonCode: 'deployment-row-drift',
      mutate(input) {
        const otherId = 'd'.repeat(64);
        const deployment = input.frames[1].deploymentInventory.matches[0];
        input.frames[1].deploymentInventory.rows[0].containerId = otherId;
        deployment.container.id = otherId;
        deployment.lifecycle.containerId = otherId;
        deployment.lifecycle.hostCgroup = `0::/system.slice/docker-${otherId}.scope`;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'pid1-drift',
      disposition: 'inconclusive',
      reasonCode: 'deployment-identity-or-lifecycle-drift',
      mutate(input) {
        const deployment = input.frames[1].deploymentInventory.matches[0];
        deployment.pid1.startTicks += 1;
        deployment.lifecycle.pid1StartTicks += 1;
        deployment.workers[0].parentStartTicks += 1;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'worker-ambiguity',
      disposition: 'inconclusive',
      reasonCode: 'worker-ambiguity',
      mutate(input) {
        for (const frame of input.frames) {
          frame.deploymentInventory.matches[0].workers.push(
            syntheticWorker({ pid: 74, startTicks: 7200 })
          );
          reseal(frame);
        }
      },
    },
    {
      id: 'pid-reuse',
      disposition: 'inconclusive',
      reasonCode: 'worker-identity-drift',
      mutate(input) {
        input.frames[1].deploymentInventory.matches[0].workers[0].startTicks += 1;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'parent-drift',
      disposition: 'inconclusive',
      reasonCode: 'deployment-observation-contradiction',
      mutate(input) {
        const worker = input.frames[1].deploymentInventory.matches[0].workers[0];
        worker.ppid = worker.pid;
        worker.parentStartTicks = worker.startTicks;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'namespace-drift',
      disposition: 'inconclusive',
      reasonCode: 'deployment-observation-contradiction',
      mutate(input) {
        input.frames[1].deploymentInventory.matches[0].workers[0].pidNamespace = 'pid:[4026533999]';
        reseal(input.frames[1]);
      },
    },
    {
      id: 'device-absence',
      disposition: 'withheld',
      reasonCode: 'device-absent',
      mutate(input) {
        for (const frame of input.frames) {
          frame.device = { complete: true, present: false, identity: null };
          reseal(frame);
        }
      },
    },
    {
      id: 'device-epoch-drift',
      disposition: 'inconclusive',
      reasonCode: 'device-identity-drift',
      mutate(input) {
        input.frames[1].device.identity.epoch.deviceNumber = '43';
        reseal(input.frames[1]);
      },
    },
    {
      id: 'descriptor-recovery',
      disposition: 'withheld',
      reasonCode: 'current-descriptor-present',
      mutate(input) {
        for (const frame of input.frames) {
          frame.deploymentInventory.matches[0].descriptors = [
            syntheticDescriptor('20', frame.device.identity.epoch.devicePath),
          ];
          reseal(frame);
        }
      },
    },
    {
      id: 'marker-change',
      disposition: 'inconclusive',
      reasonCode: 'marker-drift',
      mutate(input) {
        const frame = input.frames[1];
        const deployment = frame.deploymentInventory.matches[0];
        deployment.markers = syntheticMarkerEvidence(
          frame.device.identity.serial,
          deployment.markers.opening,
          deployment.markers.ready + 1
        ).markers;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'frame-reorder',
      disposition: 'inconclusive',
      reasonCode: 'frame-order-invalid',
      mutate(input) {
        input.frames[1].startedAt = '2026-07-27T03:00:10.800Z';
        input.frames[1].startedMonotonicNs = '200800000000';
        reseal(input.frames[1]);
      },
    },
    {
      id: 'exposure-over-limit',
      disposition: 'inconclusive',
      reasonCode: 'exposure-window-exceeded',
      mutate(input) {
        input.frames[1].startedAt = '2026-07-27T03:00:15.000Z';
        input.frames[1].endedAt = '2026-07-27T03:00:15.200Z';
        input.frames[1].startedMonotonicNs = '205000000000';
        input.frames[1].endedMonotonicNs = '205200000000';
        input.frames[1].observationCutoff = {
          at: '2026-07-27T03:00:15.100Z',
          monotonicNs: '205100000000',
        };
        reseal(input.frames[1]);
      },
    },
    {
      id: 'missing-command-audit',
      disposition: 'inconclusive',
      reasonCode: 'capability-audit-incomplete-or-inexact',
      mutate(input) {
        input.capabilityAudit.commandReceipts.pop();
      },
    },
    {
      id: 'duplicate-receipts',
      disposition: 'inconclusive',
      reasonCode: 'duplicate-receipts-rejected',
      duplicateOutput: true,
    },
    {
      id: 'input-tampering',
      disposition: 'inconclusive',
      reasonCode: 'source-admission-inexact',
      mutate(input) {
        input.containerId = '0'.repeat(64);
      },
    },
    {
      id: 'source-drift',
      disposition: 'inconclusive',
      reasonCode: 'source-admission-inexact',
      mutate(input) {
        input.sourceAdmissionExact = false;
      },
    },
    {
      id: 'environment-policy-drift',
      disposition: 'inconclusive',
      reasonCode: 'capability-audit-incomplete-or-inexact',
      mutate(input) {
        input.capabilityAudit.environmentPolicy.fixed.LANG = 'en_US.UTF-8';
      },
    },
    {
      id: 'prohibited-capability',
      disposition: 'inconclusive',
      reasonCode: 'prohibited-capability-observed',
      mutate(input) {
        input.capabilityAudit.prohibitedCounts.dockerExec = 1;
      },
    },
  ];
  const semanticCaseIds = new Set([
    'multiple-image-matches',
    'selector-broadening',
    'descendant-image-mismatch',
    'deployment-presence-drift',
    'container-drift',
    'pid1-drift',
    'worker-ambiguity',
    'pid-reuse',
    'parent-drift',
    'namespace-drift',
    'device-absence',
    'device-epoch-drift',
    'descriptor-recovery',
    'marker-change',
    'frame-reorder',
    'exposure-over-limit',
  ]);
  return definitions.map((definition) =>
    semanticCaseIds.has(definition.id)
      ? { ...definition, refreshCapabilityAudit: true }
      : definition
  );
}

export function independentlyBuildHostileMatrix(
  acceptedTarget,
  classify = independentlyClassifyDynamicFrames
) {
  if (typeof classify !== 'function') throw new TypeError('classify must be a function');
  const base = {
    frames: syntheticFrames(acceptedTarget),
    capabilityAudit: null,
    sourceAdmissionExact: true,
  };
  base.capabilityAudit = syntheticCapabilityAudit(base.frames, acceptedTarget);
  const definitions = hostileDefinitions();
  const cases = definitions.map((definition) => {
    const input = clone(base);
    let result;
    let digestInput = input;
    if (definition.duplicateOutput) {
      const canonical = classify(input);
      const corrupted = clone(canonical);
      if (Array.isArray(corrupted.receipts) && corrupted.receipts.length === 1) {
        corrupted.receipts.push(clone(corrupted.receipts[0]));
      }
      digestInput = { classification: corrupted };
      result = independentClassificationExactShape(corrupted)
        ? corrupted
        : {
            disposition: 'inconclusive',
            stage: 'output-admission',
            reasonCode: 'duplicate-receipts-rejected',
            receipts: [],
          };
    } else {
      definition.mutate(input);
      if (definition.refreshCapabilityAudit === true) {
        input.capabilityAudit = syntheticCapabilityAudit(input.frames, acceptedTarget);
      }
      result = classify(input);
    }
    const actualReceiptCount = Array.isArray(result?.receipts) ? result.receipts.length : 0;
    const passed =
      result?.disposition === definition.disposition &&
      result?.reasonCode === definition.reasonCode &&
      actualReceiptCount === 0;
    return {
      id: definition.id,
      inputSha256: sha256Canonical(digestInput),
      expectedDisposition: definition.disposition,
      actualDisposition: result?.disposition ?? 'inconclusive',
      expectedReceiptCount: 0,
      actualReceiptCount,
      stage: typeof result?.stage === 'string' ? result.stage : 'input-admission',
      reasonCode:
        typeof result?.reasonCode === 'string' ? result.reasonCode : 'malformed-hostile-output',
      passed,
    };
  });
  return {
    schemaVersion: 'overlaykit-h045-hostile-matrix/v1',
    requiredCaseIds: [...INDEPENDENT_CASE_IDS],
    caseCount: cases.length,
    passedCount: cases.filter((entry) => entry.passed).length,
    allPassed:
      same(
        cases.map((entry) => entry.id),
        INDEPENDENT_CASE_IDS
      ) && cases.every((entry) => entry.passed),
    cases,
  };
}

export function buildIndependentSyntheticInput(acceptedTarget) {
  const target = acceptedTarget ?? {
    imageReference: H045_ACCEPTED_IMAGE_REFERENCE,
    imageId: H045_ACCEPTED_IMAGE_ID,
    vendorId: '0fd9',
    productId: '0080',
    serial: H045_ACCEPTED_SERIAL,
  };
  const frames = syntheticFrames(target);
  const capabilityAudit = syntheticCapabilityAudit(frames, target);
  return { frames, capabilityAudit, sourceAdmissionExact: true };
}

function independentAuditBaseExact(audit) {
  return (
    exactKeys(audit, AUDIT_KEYS) &&
    audit.mode === 'live-readonly-dynamic-acquisition-capability-bounded' &&
    environmentPolicyExact(audit.environmentPolicy) &&
    Array.isArray(audit.commandReceipts) &&
    Array.isArray(audit.filesystemReceipts) &&
    audit.filesystemReceipts.length <= FILESYSTEM_MAX_RECEIPTS_PER_RUN &&
    exactKeys(audit.allowedProcessCounts, H045_ALLOWED_PROCESS_KEYS) &&
    H045_ALLOWED_PROCESS_KEYS.every((key) => nonNegativeInteger(audit.allowedProcessCounts[key])) &&
    nonNegativeInteger(audit.commandCount) &&
    nonNegativeInteger(audit.filesystemReceiptCount) &&
    audit.commandReceipts.length === audit.commandCount &&
    audit.filesystemReceipts.length === audit.filesystemReceiptCount &&
    audit.complete === true &&
    audit.exact === true &&
    audit.frameCount === 2 &&
    audit.lsusbCount === 1 &&
    audit.unrecordedObservationCount === 0 &&
    exactKeys(audit.prohibitedCounts, H045_PROHIBITED_COUNT_KEYS) &&
    H045_PROHIBITED_COUNT_KEYS.every((key) => nonNegativeInteger(audit.prohibitedCounts[key]))
  );
}

function independentFilesystemBindings(audit, frames) {
  if (!Array.isArray(frames) || frames.length !== 2) return false;
  let cursor = 0;
  for (const frame of frames) {
    const indexes = frame?.auditBinding?.filesystemReceiptIndexes;
    if (
      !Array.isArray(indexes) ||
      indexes.length > FILESYSTEM_MAX_RECEIPTS_PER_FRAME ||
      indexes.some((index, position) => index !== cursor + position)
    ) {
      return false;
    }
    const receipts = indexes.map((index) => audit.filesystemReceipts[index]);
    if (
      receipts.some(
        (receipt) =>
          receipt === undefined ||
          !receiptWithinFrame(receipt, frame) ||
          !receiptEndsAtOrBeforeCutoff(receipt, frame)
      ) ||
      !replayFilesystemFrame(frame, receipts)
    ) {
      return false;
    }
    cursor += indexes.length;
  }
  return cursor === audit.filesystemReceipts.length;
}

function verifyCapabilityAuditIndependently(audit, frames, run) {
  const baseExact = independentAuditBaseExact(audit);
  const commandOrdinals = new Map();
  const commandReceiptsExact =
    baseExact &&
    audit.commandReceipts.every((receipt, index) =>
      exactCommandReceipt(receipt, index, commandOrdinals)
    );
  const plan = Array.isArray(frames) && frames.length === 2 ? commandPlanForFrames(frames) : null;
  const commandPlanExact =
    commandReceiptsExact &&
    plan !== null &&
    plan.plan.length === audit.commandReceipts.length &&
    plan.plan.every((entry, index) => commandMatchesPlan(audit.commandReceipts[index], entry)) &&
    lsusbEvidenceExact(
      audit.commandReceipts.find((receipt) => receipt.kind === 'lsusb'),
      frames
    );
  const observedCounts = Object.fromEntries(H045_ALLOWED_PROCESS_KEYS.map((key) => [key, 0]));
  if (commandReceiptsExact) {
    for (const receipt of audit.commandReceipts) observedCounts[receipt.kind] += 1;
  }
  const commandCountsExact =
    commandReceiptsExact &&
    H045_ALLOWED_PROCESS_KEYS.every(
      (key) => observedCounts[key] === audit.allowedProcessCounts[key]
    ) &&
    Object.values(observedCounts).reduce((sum, count) => sum + count, 0) === audit.commandCount;
  const gitReceiptsExact =
    commandPlanExact &&
    commandText(audit.commandReceipts[0])?.trim() === run.collector?.observedHead &&
    commandText(audit.commandReceipts[1]) === '' &&
    commandText(audit.commandReceipts[2]) === '' &&
    commandText(audit.commandReceipts[3])?.trim() === REPOSITORY;
  const commandExact = commandPlanExact && commandCountsExact && gitReceiptsExact;

  const filesystemOrdinals = new Map();
  const filesystemReceiptsExact =
    baseExact &&
    audit.filesystemReceipts.every((receipt, index) =>
      exactFilesystemReceipt(receipt, index, filesystemOrdinals)
    );
  const framesReconstructed =
    filesystemReceiptsExact && independentFilesystemBindings(audit, frames);
  const bindingExact =
    commandPlanExact &&
    plan !== null &&
    auditBindingsExact(audit, frames, plan.framePlans) &&
    framesReconstructed;
  const filesystemExact = filesystemReceiptsExact && framesReconstructed;
  const prohibitedObserved =
    verifierPlainObject(audit?.prohibitedCounts) &&
    Object.values(audit.prohibitedCounts).some((value) => Number.isSafeInteger(value) && value > 0);
  return {
    commandExact,
    filesystemExact,
    bindingExact,
    framesReconstructed,
    prohibitedObserved,
    exact:
      commandExact &&
      filesystemExact &&
      bindingExact &&
      !prohibitedObserved &&
      capabilityAuditExact(audit, frames),
  };
}

function independentBaseOutcome(
  sourceAdmission,
  auditVerification,
  classification,
  hostileMatrixExact
) {
  if (auditVerification.prohibitedObserved) {
    return {
      status: 'refuted',
      stage: 'capability-boundary',
      reasonCode: 'prohibited-capability-observed',
    };
  }
  if (
    classification.disposition === 'candidate' &&
    !independentClassificationExactShape(classification)
  ) {
    return {
      status: 'refuted',
      stage: 'live-classification',
      reasonCode: 'unsafe-live-classification',
    };
  }
  if (!hostileMatrixExact) {
    return {
      status: 'refuted',
      stage: 'hostile-matrix',
      reasonCode: 'hostile-case-failed',
    };
  }
  if (sourceAdmission.allExact !== true) {
    return {
      status: 'inconclusive',
      stage: 'source-admission',
      reasonCode: 'source-admission-inexact',
    };
  }
  if (!auditVerification.exact) {
    return {
      status: 'inconclusive',
      stage: 'capability-audit',
      reasonCode: 'capability-audit-incomplete-or-inexact',
    };
  }
  if (classification.disposition === 'inconclusive') {
    return {
      status: 'inconclusive',
      stage: classification.stage,
      reasonCode: classification.reasonCode,
    };
  }
  if (
    ['candidate', 'withheld'].includes(classification.disposition) &&
    independentClassificationExactShape(classification)
  ) {
    return {
      status: 'supported',
      stage: 'dynamic-readonly-acquisition',
      reasonCode: 'complete-live-classification-and-hostile-matrix-exact',
    };
  }
  return {
    status: 'inconclusive',
    stage: 'live-classification',
    reasonCode: 'live-classification-invalid',
  };
}

function verificationOutcome(base, producerAgreement) {
  if (base.status === 'refuted') return base;
  if (!producerAgreement) {
    return {
      status: 'refuted',
      stage: 'independent-verification',
      reasonCode: 'producer-verifier-disagreement',
    };
  }
  return base;
}

async function verifyRunAtRoot(runPath, artifactRoot, publishVerification = false) {
  const layout = await canonicalRunLayout(runPath, artifactRoot);
  let attemptLedgerSession;
  let verificationFileReceipt;
  try {
    const schemaBytes = await readFile(SCHEMA_PATH);
    const runBytes = layout.runFileReceipt.bytes;
    let run;
    try {
      run = JSON.parse(runBytes.toString('utf8'));
    } catch (error) {
      throw new Error('H-045 verification failed: run is not valid JSON', { cause: error });
    }
    const schema = JSON.parse(schemaBytes.toString('utf8'));
    const ajv = new Ajv2020({
      allErrors: true,
      strict: true,
      validateFormats: false,
    });
    const validate = ajv.compile(schema);
    verificationAssertion(validate(run), `schema invalid: ${ajv.errorsText(validate.errors)}`);
    verificationAssertion(verifierExactKeys(run, TOP_LEVEL_KEYS), 'top-level field set is inexact');
    verificationAssertion(
      runBytes.equals(prettyJsonBytes(run)),
      'run evidence bytes are not exact pretty JSON'
    );
    verificationAssertion(
      path.basename(layout.runDirectory) === run.runId,
      'run directory does not match run ID'
    );

    const { evidenceSha256, ...body } = run;
    verificationAssertion(digestCanonical(body) === evidenceSha256, 'evidence hash mismatch');
    verificationAssertion(
      dateTime(run.startedAt) &&
        dateTime(run.completedAt) &&
        Date.parse(run.completedAt) >= Date.parse(run.startedAt),
      'run timestamps are invalid or reversed'
    );
    verificationAssertion(
      run.runId ===
        `h045-${run.startedAt.replaceAll(':', '-').replace('.', '-')}-${digestCanonical({
          startedAt: run.startedAt,
          sources: run.collector.sourcesBefore,
        }).slice(0, 8)}`,
      'run ID does not bind its start timestamp and source map'
    );
    attemptLedgerSession = await verifyAttemptLedgerIndependently(run, layout);
    const attemptLedgerVerification = attemptLedgerSession.verification;

    const frameDigestsExact =
      Array.isArray(run.frames) &&
      run.frames.length === 2 &&
      run.frames.every(independentFrameExactShape) &&
      new Set(run.frames.map((frame) => frame.digestSha256)).size === 2;
    const auditVerification = verifyCapabilityAuditIndependently(
      run.capabilityAudit,
      run.frames,
      run
    );
    const repositoryEvidence = await repositoryAndSourceEvidence(run);
    const sourceAdmission = reconstructSourceAdmission(
      run,
      repositoryEvidence,
      auditVerification.commandExact
    );
    const sourceAdmissionReconstructed =
      verifierExactKeys(run.sourceAdmission, SOURCE_ADMISSION_KEYS) &&
      verifierSame(run.sourceAdmission, sourceAdmission);
    const targetExact = acceptedTargetExact(run.acceptedTarget);
    const stableInputExact = inputExact(run.input);
    const liveClassification = independentlyClassifyDynamicFrames({
      frames: run.frames,
      capabilityAudit: run.capabilityAudit,
      sourceAdmissionExact: sourceAdmission.allExact,
    });
    const classificationExact = verifierSame(run.liveClassification, liveClassification);
    const receiptExact =
      classificationExact &&
      (liveClassification.disposition === 'candidate'
        ? liveClassification.receipts.length === 1
        : liveClassification.receipts.length === 0);
    const hostileMatrix = independentlyBuildHostileMatrix(run.acceptedTarget);
    const hostileMatrixExact = verifierSame(run.hostileMatrix, hostileMatrix);
    const claimBoundaryExact = verifierSame(run.claimBoundary, INDEPENDENT_CLAIM_BOUNDARY);
    const framesExact =
      frameDigestsExact && auditVerification.framesReconstructed && auditVerification.bindingExact;
    const base = independentBaseOutcome(
      sourceAdmission,
      auditVerification,
      liveClassification,
      hostileMatrixExact
    );
    const outcomeExact = verifierSame(run.outcome, base);
    const producerAgreement =
      repositoryEvidence.collectorIdentityExact &&
      repositoryEvidence.runtimeReceiptExact &&
      repositoryEvidence.verifierRuntimeExact &&
      repositoryEvidence.governanceExact &&
      repositoryEvidence.reviewedSourcesExact &&
      repositoryEvidence.sourceSetExact &&
      repositoryEvidence.sourceStable &&
      attemptLedgerVerification.exact &&
      sourceAdmissionReconstructed &&
      sourceAdmission.allExact &&
      stableInputExact &&
      targetExact &&
      framesExact &&
      classificationExact &&
      receiptExact &&
      hostileMatrixExact &&
      claimBoundaryExact &&
      outcomeExact;
    const outcome = verificationOutcome(base, producerAgreement);
    const exposureNs =
      monotonic(run.frames[1].observationCutoff.monotonicNs) -
      monotonic(run.frames[0].startedMonotonicNs);

    const verification = {
      schemaVersion: 'overlaykit-h045-verification/v2',
      hypothesis: 'H-045',
      runId: run.runId,
      outcome: outcome.status,
      stage: outcome.stage,
      reasonCode: outcome.reasonCode,
      evidenceSha256,
      schemaExact: true,
      topLevelExact: true,
      artifactLayoutExact: attemptLedgerVerification.artifactLayoutExact,
      attemptLedgerExact: attemptLedgerVerification.exact,
      predecessorAttemptLedgerExact: attemptLedgerVerification.predecessorExact,
      predecessorAttemptLedgerCompletionAbsent:
        attemptLedgerVerification.predecessorCompletionAbsent,
      predecessorAttemptLedgerRunAbsent: attemptLedgerVerification.predecessorRunAbsent,
      predecessorAttemptLedgerReservationSha256:
        attemptLedgerVerification.predecessorReservationSha256,
      predecessorAttemptLedgerFailureSha256: attemptLedgerVerification.predecessorFailureSha256,
      replacementAttemptLedgerExact: attemptLedgerVerification.replacementExact,
      replacementAttemptLedgerFailureAbsent: attemptLedgerVerification.replacementFailureAbsent,
      replacementAttemptLedgerReservationSha256:
        attemptLedgerVerification.replacementReservationSha256,
      replacementAttemptLedgerCompletionSha256:
        attemptLedgerVerification.replacementCompletionSha256,
      collectorIdentityExact: repositoryEvidence.collectorIdentityExact,
      runtimeReceiptExact: repositoryEvidence.runtimeReceiptExact,
      verifierRuntimeExact: repositoryEvidence.verifierRuntimeExact,
      governanceExact: repositoryEvidence.governanceExact,
      governancePlanBytesExact: repositoryEvidence.governancePlanBytesExact,
      governanceManifestBytesExact: repositoryEvidence.governanceManifestBytesExact,
      reviewAuthorizationExact: repositoryEvidence.reviewedSourcesExact,
      sourceSetExact: repositoryEvidence.sourceSetExact,
      sourceStable: repositoryEvidence.sourceStable,
      sourceAdmissionReconstructed,
      sourceAdmissionAllExact: sourceAdmission.allExact,
      inputExact: stableInputExact,
      acceptedTargetExact: targetExact,
      commandAuditExact: auditVerification.commandExact,
      filesystemAuditExact: auditVerification.filesystemExact,
      auditBindingExact: auditVerification.bindingExact,
      capabilityAuditExact: auditVerification.exact,
      prohibitedCapabilityObserved: auditVerification.prohibitedObserved,
      frameDigestsExact,
      framesReconstructed: auditVerification.framesReconstructed,
      framesExact,
      frameOrderExact: orderedFrames(run.frames[0], run.frames[1]),
      exposureMilliseconds: Number(exposureNs) / 1_000_000,
      classificationExact,
      receiptExact,
      liveDisposition: liveClassification.disposition,
      hostileMatrixExact,
      hostileCaseCount: hostileMatrix.caseCount,
      claimBoundaryExact,
      outcomeExact,
      producerAgreement,
      verified: true,
    };
    await assertAttemptLedgerStable(attemptLedgerSession, layout);
    await assertSecureFileStable(layout.runFileReceipt, 'run evidence');
    await assertSecureDirectoryStable(layout.runDirectoryReceipt, 'run directory');
    await assertSecureDirectoryStable(layout.artifactDirectoryReceipt, 'artifact root');

    if (!publishVerification) return verification;

    const published = await publishVerificationExclusive(layout, verification, {
      beforeCommit: async () => {
        await assertAttemptLedgerStable(attemptLedgerSession, layout);
        await assertSecureFileStable(layout.runFileReceipt, 'run evidence');
        await assertSecureDirectoryStable(layout.runDirectoryReceipt, 'run directory');
        await assertSecureDirectoryStable(layout.artifactDirectoryReceipt, 'artifact root');
      },
    });
    verificationFileReceipt = published.receipt;
    return {
      verification,
      verificationPath: published.path,
    };
  } finally {
    await Promise.allSettled([
      closeSecureFile(verificationFileReceipt),
      closeAttemptLedgerSession(attemptLedgerSession),
      closeSecureFile(layout.runFileReceipt),
      layout.runDirectoryReceipt.handle.close(),
      layout.artifactDirectoryReceipt.handle.close(),
    ]);
  }
}

export async function verifyRun(runPath) {
  return verifyRunAtRoot(runPath, ARTIFACT_ROOT);
}

const OFFLINE_PUBLICATION_KEYS = Object.freeze([
  'runPath',
  'artifactRoot',
  'verification',
  'failurePoint',
]);
const OFFLINE_PUBLICATION_FAILURE_POINTS = Object.freeze(
  new Set(['none', 'before-commit', 'after-link', 'after-link-mode-drift'])
);

export async function publishH045OfflineVerificationForTest(options) {
  verificationAssertion(
    verifierExactKeys(options, OFFLINE_PUBLICATION_KEYS),
    'offline publication fixture requires exact options'
  );
  verificationAssertion(
    path.isAbsolute(options.runPath) &&
      path.resolve(options.runPath) === options.runPath &&
      path.isAbsolute(options.artifactRoot) &&
      path.resolve(options.artifactRoot) === options.artifactRoot,
    'offline publication fixture paths must be normalized and absolute'
  );
  verificationAssertion(
    options.artifactRoot !== ARTIFACT_ROOT,
    'offline publication fixture cannot target the canonical artifact root'
  );
  verificationAssertion(
    options.verification !== null &&
      typeof options.verification === 'object' &&
      !Array.isArray(options.verification) &&
      OFFLINE_PUBLICATION_FAILURE_POINTS.has(options.failurePoint),
    'offline publication fixture input is invalid'
  );

  const layout = await canonicalRunLayout(options.runPath, options.artifactRoot);
  let publicationReceipt;
  try {
    const published = await publishVerificationExclusive(layout, options.verification, {
      beforeCommit: async () => {
        if (options.failurePoint === 'before-commit') {
          throw new Error('H-045 injected offline failure before verification commit');
        }
      },
      afterLink: async ({ stagingHandle }) => {
        if (options.failurePoint === 'after-link') {
          throw new Error('H-045 injected offline failure after verification link');
        }
        if (options.failurePoint === 'after-link-mode-drift') {
          await stagingHandle.chmod(0o644);
        }
      },
    });
    publicationReceipt = published.receipt;
    return {
      schemaVersion: 'overlaykit-h045-offline-verification-publication-fixture/v1',
      fixtureBoundary: {
        mode: 'offline-verification-publication-fixture',
        canonical: false,
        authorizing: false,
        live: false,
      },
      verificationPath: published.path,
      verificationSha256: digestBytes(publicationReceipt.bytes),
    };
  } finally {
    await Promise.allSettled([
      closeSecureFile(publicationReceipt),
      closeSecureFile(layout.runFileReceipt),
      layout.runDirectoryReceipt.handle.close(),
      layout.artifactDirectoryReceipt.handle.close(),
    ]);
  }
}

const OFFLINE_VERIFICATION_KEYS = Object.freeze(['runPath', 'artifactRoot']);
const OFFLINE_VERIFICATION_BOUNDARY = Object.freeze({
  mode: 'offline-verification-fixture',
  canonical: false,
  authorizing: false,
  live: false,
});

export async function verifyH045OfflineFixtureForTest(options) {
  verificationAssertion(
    verifierExactKeys(options, OFFLINE_VERIFICATION_KEYS),
    'offline verification fixture requires exactly runPath and artifactRoot'
  );
  verificationAssertion(
    path.isAbsolute(options.runPath) &&
      path.resolve(options.runPath) === options.runPath &&
      path.isAbsolute(options.artifactRoot) &&
      path.resolve(options.artifactRoot) === options.artifactRoot,
    'offline verification fixture paths must be normalized and absolute'
  );
  verificationAssertion(
    options.artifactRoot !== ARTIFACT_ROOT,
    'offline verification fixture cannot target the canonical artifact root'
  );
  const canonicalShape = await verifyRunAtRoot(options.runPath, options.artifactRoot);
  const {
    schemaVersion: discardedCanonicalSchema,
    verified: fixtureVerified,
    ...reconstruction
  } = canonicalShape;
  verificationAssertion(
    discardedCanonicalSchema === 'overlaykit-h045-verification/v2' && fixtureVerified === true,
    'offline reconstruction did not complete'
  );
  return {
    schemaVersion: 'overlaykit-h045-offline-verification-fixture/v1',
    hypothesis: 'H-045',
    fixtureBoundary: { ...OFFLINE_VERIFICATION_BOUNDARY },
    reconstruction: {
      ...reconstruction,
      fixtureVerified: true,
    },
  };
}

function requestedRunPath() {
  const index = process.argv.indexOf('--run');
  verificationAssertion(index !== -1, '--run is required');
  verificationAssertion(process.argv[index + 1], '--run requires a path');
  return path.resolve(REPOSITORY_ROOT, process.argv[index + 1]);
}

function isDirectInvocation() {
  return process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

if (isDirectInvocation()) {
  try {
    const runPath = requestedRunPath();
    const { verification, verificationPath } = await verifyRunAtRoot(runPath, ARTIFACT_ROOT, true);
    process.stdout.write(
      `${JSON.stringify({
        runId: verification.runId,
        verified: verification.verified,
        outcome: verification.outcome,
        stage: verification.stage,
        reasonCode: verification.reasonCode,
        evidenceSha256: verification.evidenceSha256,
        verificationPath: path.relative(REPOSITORY_ROOT, verificationPath),
      })}\n`
    );
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}
