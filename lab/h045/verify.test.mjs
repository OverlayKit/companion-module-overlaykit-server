import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import test, { after, before } from 'node:test';
import { fileURLToPath } from 'node:url';

import { classifyDynamicFrames } from './classifier-lib.mjs';
import { evaluateHostileMatrix, outcomeFor } from './run.mjs';
import {
  INDEPENDENT_CASE_IDS,
  INDEPENDENT_CLAIM_BOUNDARY,
  INDEPENDENT_REQUIRED_SOURCE_PATHS,
  buildIndependentSyntheticInput,
  independentlyBuildHostileMatrix,
  independentlyClassifyDynamicFrames,
  publishH045OfflineVerificationForTest,
  verifyH045OfflineFixtureForTest,
  verifyRun,
} from './verify.mjs';

const REPOSITORY_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const VERIFY_PATH = fileURLToPath(new URL('./verify.mjs', import.meta.url));
const ARTIFACT_ROOT = path.join(REPOSITORY_ROOT, 'artifacts', 'h045');
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
const NODE_BINARY_SHA256 = 'b1cbec894e45a5814b6ab756e1e14f8a76516273197e67e0412b57c1e10d0d9f';
const NODE_BINARY_BYTE_LENGTH = 123_183_528;
const ACCEPTED_IMAGE_REFERENCE = 'ghcr.io/bitfocus/companion/companion:v4.3.3';
const ACCEPTED_IMAGE_ID = 'sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e';
const ACCEPTED_SERIAL = 'A00SA5492OQMLF';
const ACCEPTED_SERIAL_SHA256 = '08e7fdb9e9bd371297e96f27f75b77bc3920181d1d448ed2d6f6a1d123548f5f';
const OBSERVED_HEAD = 'f'.repeat(40);
const LIVE_AUTHORIZATION_PREFIX = 'CHG-0020:h045-one-readonly-replacement-attempt:sha256:';
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
const REPLACEMENT_RESERVATION_RELATIVE_PATH = `artifacts/h045/${REPLACEMENT_ATTEMPT_ID}/reservation.json`;
const REPLACEMENT_COMPLETION_RELATIVE_PATH = `artifacts/h045/${REPLACEMENT_ATTEMPT_ID}/completion.json`;

const SERIAL_BINDING = Object.freeze({
  decisionId: 'ADR-0006',
  decisionSha256: ADR_0006_SHA256,
  contextField: 'physical Stream Deck MK.2 serial',
  serialSha256: ACCEPTED_SERIAL_SHA256,
});

const ACCEPTED_TARGET = Object.freeze({
  imageReference: ACCEPTED_IMAGE_REFERENCE,
  imageId: ACCEPTED_IMAGE_ID,
  vendorId: '0fd9',
  productId: '0080',
  serial: ACCEPTED_SERIAL,
  serialBinding: SERIAL_BINDING,
});

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

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function sha256Canonical(value) {
  return sha256(canonicalJson(value));
}

async function sha256File(filePath) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filePath)) hash.update(chunk);
  return hash.digest('hex');
}

async function sourceMap() {
  return Promise.all(
    INDEPENDENT_REQUIRED_SOURCE_PATHS.map(async (relativePath) => ({
      path: relativePath,
      sha256: await sha256File(path.join(REPOSITORY_ROOT, relativePath)),
    }))
  );
}

function sourceSetSha256(sources) {
  return sha256(
    Buffer.from(
      JSON.stringify(sources.map(({ path: sourcePath, sha256 }) => ({ path: sourcePath, sha256 }))),
      'utf8'
    )
  );
}

function exactSourceAdmission() {
  return {
    h044PublicReceiptExact: true,
    h044SemanticEvidenceExact: true,
    acceptedDecisionExact: true,
    acceptedTargetContextExact: true,
    historicalBoundaryExact: true,
    chg0018Exact: true,
    chg0019Exact: true,
    chg0020Exact: true,
    adr0006Exact: true,
    repositoryRemoteExact: true,
    observedHeadWellFormed: true,
    protectedMainExact: true,
    sourceContractExact: true,
    protectedMainAncestryExact: true,
    sourceContractAncestryExact: true,
    runtimeBinaryExact: true,
    targetInputExact: true,
    governanceExact: true,
    sourceSetExact: true,
    sourceStable: true,
    allExact: true,
  };
}

function sealFrame(frame) {
  const body = clone(frame);
  delete body.digestSha256;
  return { ...body, digestSha256: sha256Canonical(body) };
}

function rebindEvidence(run) {
  const body = clone(run);
  delete body.evidenceSha256;
  Object.assign(run, body, { evidenceSha256: sha256Canonical(body) });
}

function rebindReviewAuthorization(run) {
  const digest = sourceSetSha256(run.collector.sourcesBefore);
  assert.deepEqual(run.collector.sourcesBefore, run.collector.sourcesAfter);
  run.collector.reviewAuthorization = {
    grant: `${LIVE_AUTHORIZATION_PREFIX}${digest}`,
    sourceSetSha256: digest,
    semantics: 'one-live-read-only-replacement-attempt',
  };
  run.runId =
    `h045-${run.startedAt.replaceAll(':', '-').replace('.', '-')}-` +
    sha256Canonical({
      startedAt: run.startedAt,
      sources: run.collector.sourcesBefore,
    }).slice(0, 8);
}

function prettyJsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function bindAttemptLedger(run) {
  const predecessorReservation = {
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
  assert.equal(sha256(prettyJsonBytes(predecessorReservation)), PREDECESSOR_RESERVATION_SHA256);
  const predecessorFailure = {
    schemaVersion: 'overlaykit-h045-live-attempt-failure/v1',
    reservationSha256: PREDECESSOR_RESERVATION_SHA256,
    stage: 'runtime-admission',
    observationStarted: true,
  };
  assert.equal(sha256(prettyJsonBytes(predecessorFailure)), PREDECESSOR_FAILURE_SHA256);

  const reservation = {
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
  const reservationSha256 = sha256(prettyJsonBytes(reservation));
  run.collector.attemptLedger = {
    predecessorReservationRelativePath: PREDECESSOR_RESERVATION_RELATIVE_PATH,
    predecessorFailureRelativePath: PREDECESSOR_FAILURE_RELATIVE_PATH,
    predecessorReservationSha256: PREDECESSOR_RESERVATION_SHA256,
    predecessorFailureSha256: PREDECESSOR_FAILURE_SHA256,
    reservationRelativePath: REPLACEMENT_RESERVATION_RELATIVE_PATH,
    completionRelativePath: REPLACEMENT_COMPLETION_RELATIVE_PATH,
    reservationSha256,
    semantics: 'fixed-local-linked-one-shot-replacement-ledger',
  };
  return {
    predecessorReservation,
    predecessorFailure,
    reservation,
    reservationSha256,
  };
}

function completionReceipt(run, reservationSha256) {
  return {
    schemaVersion: 'overlaykit-h045-live-attempt-completion/v2',
    reservationSha256,
    completedAt: run.completedAt,
    evidenceSha256: run.evidenceSha256,
  };
}

function outputReceipt(text) {
  const bytes = Buffer.from(text, 'utf8');
  return {
    encoding: 'utf8',
    text,
    base64: bytes.toString('base64'),
    byteLength: bytes.byteLength,
    lineCount:
      text === '' ? 0 : (text.endsWith('\n') ? text.slice(0, -1) : text).split('\n').length,
    sha256: sha256(bytes),
  };
}

function filesystemReadResult(text) {
  const bytes = Buffer.from(text, 'utf8');
  return {
    cardinality: 1,
    byteLength: bytes.byteLength,
    bytes: {
      encoding: 'base64',
      base64: bytes.toString('base64'),
      byteLength: bytes.byteLength,
      sha256: sha256(bytes),
    },
    encoding: 'utf8',
    text,
    sha256: sha256(bytes),
  };
}

function filesystemDirectoryResult(entries) {
  return {
    entries: [...entries],
    cardinality: entries.length,
    sha256: sha256(Buffer.from(JSON.stringify(entries), 'utf8')),
  };
}

function filesystemLinkResult(value) {
  return {
    value,
    cardinality: 1,
    sha256: sha256(Buffer.from(value, 'utf8')),
  };
}

function filesystemStatResult(metadata) {
  return {
    cardinality: 1,
    metadata: clone(metadata),
    sha256: sha256(Buffer.from(JSON.stringify(metadata), 'utf8')),
  };
}

function rebuildFilesystemIndexes(run, perFrameReceipts) {
  const receipts = [];
  const operationOrdinals = new Map();
  for (const [frameIndex, frameReceipts] of perFrameReceipts.entries()) {
    const frame = run.frames[frameIndex];
    const start = receipts.length;
    for (const [offset, source] of frameReceipts.entries()) {
      const receipt = clone(source);
      const index = receipts.length;
      const ordinal = (operationOrdinals.get(receipt.operation) ?? 0) + 1;
      operationOrdinals.set(receipt.operation, ordinal);
      const at = (BigInt(frame.startedMonotonicNs) + 100n + BigInt(offset)).toString();
      Object.assign(receipt, {
        index,
        startedAt: frame.startedAt,
        endedAt: frame.startedAt,
        startedMonotonicNs: at,
        endedMonotonicNs: at,
        durationNs: '0',
        cardinality: {
          global: index + 1,
          operation: ordinal,
        },
      });
      receipts.push(receipt);
    }
    frame.auditBinding.filesystemReceiptIndexes = Array.from(
      { length: frameReceipts.length },
      (_, offset) => start + offset
    );
    Object.assign(frame, sealFrame(frame));
  }
  run.capabilityAudit.filesystemReceipts = receipts;
  run.capabilityAudit.filesystemReceiptCount = receipts.length;
}

let temporaryRoot;
let canonicalRun;

before(async () => {
  temporaryRoot = await mkdtemp(path.join(os.tmpdir(), 'overlaykit-h045-verify-'));
  const sources = await sourceMap();
  const classifierInput = buildIndependentSyntheticInput(ACCEPTED_TARGET);
  const liveClassification = classifyDynamicFrames(clone(classifierInput));
  const hostileMatrix = evaluateHostileMatrix(classifyDynamicFrames, ACCEPTED_TARGET);
  const sourceAdmission = exactSourceAdmission();
  const startedAt = classifierInput.frames[0].startedAt;
  const completedAt = classifierInput.frames[1].endedAt;
  const runtime = await stat(process.execPath);
  const reviewedSourceSetSha256 = sourceSetSha256(sources);
  const body = {
    schemaVersion: 'overlaykit-h045-live-run/v2',
    hypothesis: 'H-045',
    runId: `h045-${startedAt.replaceAll(':', '-').replace('.', '-')}-${sha256Canonical({
      startedAt,
      sources,
    }).slice(0, 8)}`,
    startedAt,
    completedAt,
    outcome: outcomeFor(
      sourceAdmission,
      classifierInput.capabilityAudit,
      liveClassification,
      hostileMatrix
    ),
    collector: {
      reviewAuthorization: {
        grant: `${LIVE_AUTHORIZATION_PREFIX}${reviewedSourceSetSha256}`,
        sourceSetSha256: reviewedSourceSetSha256,
        semantics: 'one-live-read-only-replacement-attempt',
      },
      runtime: {
        node: process.version,
        platform: process.platform,
        arch: process.arch,
        binarySha256: await sha256File(process.execPath),
        binaryByteLength: runtime.size,
      },
      repository: 'https://github.com/OverlayKit/companion-module-overlaykit-server.git',
      observedHead: OBSERVED_HEAD,
      protectedMain: {
        commit: PROTECTED_MAIN_COMMIT,
        isAncestor: true,
      },
      sourceContract: {
        commit: SOURCE_CONTRACT_COMMIT,
        isAncestor: true,
      },
      sourcesBefore: clone(sources),
      sourcesAfter: clone(sources),
      sourceStable: true,
      governance: {
        verified: true,
        planHash: PLAN_HASH,
        planSha256: GOVERNANCE_PLAN_SHA256,
        manifestContentHash: MANIFEST_CONTENT_HASH,
        manifestSha256: GOVERNANCE_MANIFEST_SHA256,
        changes: {
          'CHG-0018': CHG_0018_SHA256,
          'CHG-0019': CHG_0019_SHA256,
          'CHG-0020': CHG_0020_SHA256,
        },
        decisions: {
          'ADR-0006': ADR_0006_SHA256,
        },
        requiredSourcePaths: [...INDEPENDENT_REQUIRED_SOURCE_PATHS],
      },
    },
    input: {
      imageReference: ACCEPTED_IMAGE_REFERENCE,
      imageId: ACCEPTED_IMAGE_ID,
      vendorId: '0fd9',
      productId: '0080',
      serialBinding: clone(SERIAL_BINDING),
    },
    sourceAdmission,
    acceptedTarget: clone(ACCEPTED_TARGET),
    frames: clone(classifierInput.frames),
    capabilityAudit: clone(classifierInput.capabilityAudit),
    liveClassification: clone(liveClassification),
    hostileMatrix: clone(hostileMatrix),
    claimBoundary: clone(INDEPENDENT_CLAIM_BOUNDARY),
  };
  bindAttemptLedger(body);
  canonicalRun = { ...body, evidenceSha256: sha256Canonical(body) };
});

after(async () => {
  if (temporaryRoot !== undefined) await rm(temporaryRoot, { recursive: true, force: true });
});

let fixtureOrdinal = 0;

async function writeFixture(
  name,
  mutate = () => {},
  { rebind = true, afterLedger = () => {}, ledgerMutation = () => {}, afterWrite = () => {} } = {}
) {
  const fixture = clone(canonicalRun);
  await mutate(fixture);
  const { predecessorReservation, predecessorFailure, reservation, reservationSha256 } =
    bindAttemptLedger(fixture);
  await afterLedger(fixture);
  if (rebind) rebindEvidence(fixture);
  const completion = completionReceipt(fixture, reservationSha256);
  await ledgerMutation({
    fixture,
    predecessorReservation,
    predecessorFailure,
    reservation,
    completion,
  });

  fixtureOrdinal += 1;
  const fixtureRoot = path.join(
    temporaryRoot,
    `${String(fixtureOrdinal).padStart(3, '0')}-${name}`
  );
  const artifactRoot = path.join(fixtureRoot, 'artifacts', 'h045');
  const predecessorAttemptDirectory = path.join(artifactRoot, PREDECESSOR_ATTEMPT_DIRECTORY);
  const attemptDirectory = path.join(artifactRoot, REPLACEMENT_ATTEMPT_ID);
  const runDirectory = path.join(artifactRoot, fixture.runId);
  const predecessorReservationPath = path.join(predecessorAttemptDirectory, 'reservation.json');
  const predecessorFailurePath = path.join(predecessorAttemptDirectory, 'failure.json');
  const reservationPath = path.join(attemptDirectory, 'reservation.json');
  const completionPath = path.join(attemptDirectory, 'completion.json');
  const runPath = path.join(runDirectory, 'run.json');

  await mkdir(artifactRoot, { recursive: true, mode: 0o700 });
  await chmod(artifactRoot, 0o700);
  await mkdir(predecessorAttemptDirectory, { mode: 0o700 });
  await chmod(predecessorAttemptDirectory, 0o700);
  await writeFile(predecessorReservationPath, prettyJsonBytes(predecessorReservation), {
    flag: 'wx',
    mode: 0o600,
  });
  await chmod(predecessorReservationPath, 0o600);
  await writeFile(predecessorFailurePath, prettyJsonBytes(predecessorFailure), {
    flag: 'wx',
    mode: 0o600,
  });
  await chmod(predecessorFailurePath, 0o600);
  await mkdir(attemptDirectory, { mode: 0o700 });
  await chmod(attemptDirectory, 0o700);
  await writeFile(reservationPath, prettyJsonBytes(reservation), {
    flag: 'wx',
    mode: 0o600,
  });
  await chmod(reservationPath, 0o600);
  await mkdir(runDirectory, { mode: 0o700 });
  await chmod(runDirectory, 0o700);
  await writeFile(runPath, prettyJsonBytes(fixture), { flag: 'wx', mode: 0o600 });
  await chmod(runPath, 0o600);
  await writeFile(completionPath, prettyJsonBytes(completion), {
    flag: 'wx',
    mode: 0o600,
  });
  await chmod(completionPath, 0o600);
  await afterWrite({
    fixture,
    fixtureRoot,
    artifactRoot,
    predecessorAttemptDirectory,
    attemptDirectory,
    runDirectory,
    predecessorReservationPath,
    predecessorFailurePath,
    reservationPath,
    completionPath,
    runPath,
  });
  return runPath;
}

async function verifyFixture(runPath) {
  const artifactRoot = path.dirname(path.dirname(runPath));
  const envelope = await verifyH045OfflineFixtureForTest({ runPath, artifactRoot });
  assert.equal(envelope.schemaVersion, 'overlaykit-h045-offline-verification-fixture/v1');
  assert.deepEqual(envelope.fixtureBoundary, {
    mode: 'offline-verification-fixture',
    canonical: false,
    authorizing: false,
    live: false,
  });
  assert.equal(Object.hasOwn(envelope.reconstruction, 'verified'), false);
  assert.equal(Object.hasOwn(envelope.reconstruction, 'schemaVersion'), false);
  return envelope.reconstruction;
}

test('verifier is runtime-independent from all H-045 producer modules', async () => {
  const source = await readFile(VERIFY_PATH, 'utf8');
  for (const producer of [
    './admission-lib.mjs',
    './classifier-lib.mjs',
    './observer-lib.mjs',
    './run.mjs',
  ]) {
    assert.doesNotMatch(source, new RegExp(`from ['"]${producer.replace('.', '\\.')}['"]`, 'u'));
  }
  assert.equal(process.version, 'v22.20.0');
  assert.equal(process.platform, 'linux');
  assert.equal(process.arch, 'x64');
  assert.equal(await sha256File(process.execPath), NODE_BINARY_SHA256);
  assert.equal((await stat(process.execPath)).size, NODE_BINARY_BYTE_LENGTH);
});

test('independently freezes the 24-source CHG-0020 and H-046 closure', () => {
  assert.equal(INDEPENDENT_REQUIRED_SOURCE_PATHS.length, 24);
  assert.deepEqual(
    INDEPENDENT_REQUIRED_SOURCE_PATHS,
    [...INDEPENDENT_REQUIRED_SOURCE_PATHS].sort()
  );
  assert.equal(
    INDEPENDENT_REQUIRED_SOURCE_PATHS.includes('.overlaykit/governance/changes/CHG-0020.json'),
    true
  );
  assert.equal(
    INDEPENDENT_REQUIRED_SOURCE_PATHS.includes('lab/h046/environment-seam.test.mjs'),
    true
  );
});

test('retains verified file handles and publishes verification fd-relative', async () => {
  const source = await readFile(VERIFY_PATH, 'utf8');
  assert.match(source, /await assertSecureFileStable\(layout\.runFileReceipt/u);
  assert.match(source, /await assertAttemptLedgerStable\(attemptLedgerSession, layout\)/u);
  assert.match(source, /session\.predecessorReservationFile/u);
  assert.match(source, /session\.predecessorFailureFile/u);
  assert.match(source, /session\.replacementReservationFile/u);
  assert.match(source, /session\.replacementCompletionFile/u);
  assert.match(source, /VERIFICATION_STAGING_FILENAME/u);
  assert.match(source, /await link\(/u);
  assert.match(source, /FS_CONSTANTS\.O_EXCL/u);
  assert.match(source, /await stagingHandle\.sync\(\)/u);
  assert.match(source, /await layout\.runDirectoryReceipt\.handle\.sync\(\)/u);
  assert.match(source, /invalidateAndRemoveFailedPublication/u);
  assert.doesNotMatch(source, /writeFile\(outputPath/u);
});

test('publishes an offline verification fixture through staged exclusive commit', async () => {
  const runPath = await writeFixture('offline-publication-success');
  const artifactRoot = path.dirname(path.dirname(runPath));
  const verification = {
    schemaVersion: 'overlaykit-h045-offline-publication-test/v1',
    verified: true,
  };
  const result = await publishH045OfflineVerificationForTest({
    runPath,
    artifactRoot,
    verification,
    failurePoint: 'none',
  });
  assert.equal(result.schemaVersion, 'overlaykit-h045-offline-verification-publication-fixture/v1');
  assert.deepEqual(result.fixtureBoundary, {
    mode: 'offline-verification-publication-fixture',
    canonical: false,
    authorizing: false,
    live: false,
  });
  assert.equal(result.verificationPath, path.join(path.dirname(runPath), 'verification.json'));
  assert.deepEqual(JSON.parse(await readFile(result.verificationPath, 'utf8')), verification);
  const metadata = await stat(result.verificationPath);
  assert.equal(metadata.mode & 0o777, 0o600);
  assert.equal(metadata.uid, process.geteuid());
  assert.equal(metadata.gid, process.getegid());
  assert.equal(metadata.nlink, 1);
  assert.deepEqual((await readdir(path.dirname(runPath))).sort(), [
    'run.json',
    'verification.json',
  ]);
});

for (const failurePoint of ['before-commit', 'after-link', 'after-link-mode-drift']) {
  test(`leaves no positive verification after ${failurePoint} publication failure`, async () => {
    const runPath = await writeFixture(`offline-publication-${failurePoint}`);
    const artifactRoot = path.dirname(path.dirname(runPath));
    await assert.rejects(
      () =>
        publishH045OfflineVerificationForTest({
          runPath,
          artifactRoot,
          verification: {
            schemaVersion: 'overlaykit-h045-offline-publication-test/v1',
            verified: true,
          },
          failurePoint,
        }),
      /injected offline failure|verification evidence mode is not 0600/u
    );
    assert.deepEqual(await readdir(path.dirname(runPath)), ['run.json']);
  });
}

test('independent hostile construction has exact producer parity for all 23 cases', () => {
  const independent = independentlyBuildHostileMatrix(ACCEPTED_TARGET);
  const producer = evaluateHostileMatrix(classifyDynamicFrames, ACCEPTED_TARGET);
  assert.deepEqual(independent.requiredCaseIds, INDEPENDENT_CASE_IDS);
  assert.equal(independent.caseCount, 23);
  assert.equal(independent.passedCount, 23);
  assert.equal(independent.allPassed, true);
  assert.deepEqual(independent, producer);
});

test('independent classifier has candidate and tuple-receipt parity', () => {
  const input = buildIndependentSyntheticInput(ACCEPTED_TARGET);
  const independent = independentlyClassifyDynamicFrames(clone(input));
  const producer = classifyDynamicFrames(clone(input));
  assert.equal(independent.disposition, 'candidate');
  assert.equal(independent.receipts.length, 1);
  assert.deepEqual(independent, producer);
});

test('verifies the complete synthetic producer-parity fixture', async () => {
  const verification = await verifyFixture(await writeFixture('canonical'));
  assert.equal(verification.fixtureVerified, true);
  assert.equal(verification.outcome, 'supported', JSON.stringify(verification));
  assert.equal(verification.producerAgreement, true);
  assert.equal(verification.artifactLayoutExact, true);
  assert.equal(verification.attemptLedgerExact, true);
  assert.equal(verification.predecessorAttemptLedgerExact, true);
  assert.equal(verification.predecessorAttemptLedgerCompletionAbsent, true);
  assert.equal(verification.predecessorAttemptLedgerRunAbsent, true);
  assert.equal(
    verification.predecessorAttemptLedgerReservationSha256,
    PREDECESSOR_RESERVATION_SHA256
  );
  assert.equal(verification.predecessorAttemptLedgerFailureSha256, PREDECESSOR_FAILURE_SHA256);
  assert.equal(verification.replacementAttemptLedgerExact, true);
  assert.equal(verification.replacementAttemptLedgerFailureAbsent, true);
  assert.equal(
    verification.replacementAttemptLedgerReservationSha256,
    canonicalRun.collector.attemptLedger.reservationSha256
  );
  assert.match(verification.replacementAttemptLedgerCompletionSha256, /^[0-9a-f]{64}$/u);
  assert.equal(verification.reviewAuthorizationExact, true);
  assert.equal(verification.governancePlanBytesExact, true);
  assert.equal(verification.governanceManifestBytesExact, true);
  assert.equal(verification.sourceAdmissionReconstructed, true);
  assert.equal(verification.capabilityAuditExact, true);
  assert.equal(verification.framesReconstructed, true);
  assert.equal(verification.classificationExact, true);
  assert.equal(verification.hostileMatrixExact, true);
  assert.equal(verification.claimBoundaryExact, true);
});

test('canonical verifier rejects an otherwise exact live-shaped fixture outside its fixed root', async () => {
  const fixture = await writeFixture('canonical-root-swap');
  await assert.rejects(() => verifyRun(fixture), /run is outside the selected artifact root/u);
});

test('offline verifier cannot target or impersonate the canonical artifact root', async () => {
  const fixture = await writeFixture('offline-canonical-root');
  await assert.rejects(
    () =>
      verifyH045OfflineFixtureForTest({
        runPath: fixture,
        artifactRoot: ARTIFACT_ROOT,
      }),
    /offline verification fixture cannot target the canonical artifact root/u
  );
  await assert.rejects(
    () =>
      verifyH045OfflineFixtureForTest({
        runPath: fixture,
        artifactRoot: path.dirname(path.dirname(fixture)),
        canonical: true,
      }),
    /requires exactly runPath and artifactRoot/u
  );
});

function observedFilesystemReceipt(operation, targetPath, result) {
  return {
    index: 0,
    operation,
    path: targetPath,
    startedAt: '2026-07-27T03:00:10.000Z',
    endedAt: '2026-07-27T03:00:10.000Z',
    startedMonotonicNs: '0',
    endedMonotonicNs: '0',
    durationNs: '0',
    disposition: 'observed',
    result,
    errorCode: null,
    cardinality: {
      global: 1,
      operation: 1,
    },
  };
}

function frameFilesystemReceipts(run) {
  return run.frames.map((frame) =>
    frame.auditBinding.filesystemReceiptIndexes.map(
      (index) => run.capabilityAudit.filesystemReceipts[index]
    )
  );
}

function changeReadReceipt(receipt, text) {
  receipt.result = filesystemReadResult(text);
}

async function assertRefuted(name, mutate, failedField) {
  const verification = await verifyFixture(await writeFixture(name, mutate));
  assert.equal(verification.fixtureVerified, true);
  assert.equal(verification.outcome, 'refuted');
  assert.equal(verification.producerAgreement, false);
  if (failedField !== undefined) assert.equal(verification[failedField], false);
}

async function assertSchemaRejected(name, mutate) {
  const fixture = await writeFixture(name, mutate);
  await assert.rejects(verifyFixture(fixture), /H-045 verification failed: schema invalid/u);
}

test('rejects a digest-consistent hidden raw Docker row', async () => {
  await assertRefuted(
    'hidden-raw-row',
    (run) => {
      const receipt = run.capabilityAudit.commandReceipts.find(
        (entry) => entry.kind === 'dockerPs'
      );
      receipt.stdout = outputReceipt(
        `${receipt.stdout.text}${JSON.stringify({
          ID: 'd'.repeat(64),
          State: 'running',
        })}\n`
      );
    },
    'commandAuditExact'
  );
});

test('rejects a sensitive extra filesystem receipt despite exact bytes and cardinality', async () => {
  await assertSchemaRejected('sensitive-filesystem-receipt', (run) => {
    const perFrame = frameFilesystemReceipts(run);
    perFrame[1].push(
      observedFilesystemReceipt(
        'readFileSync',
        '/etc/shadow',
        filesystemReadResult('root:*:0:0:99999:7:::\n')
      )
    );
    rebuildFilesystemIndexes(run, perFrame);
  });
});

test('rejects a raw device-node character-kind mismatch', async () => {
  await assertRefuted(
    'device-character-mismatch',
    (run) => {
      const receipt = run.capabilityAudit.filesystemReceipts.find(
        (entry) => entry.operation === 'statSync' && entry.path === '/dev/hidraw0'
      );
      const metadata = clone(receipt.result.metadata);
      metadata.isCharacterDevice = false;
      receipt.result = filesystemStatResult(metadata);
    },
    'framesReconstructed'
  );
});

test('rejects a raw device-node rdev mismatch even when the raw stat is self-consistent', async () => {
  await assertRefuted(
    'device-rdev-mismatch',
    (run) => {
      const receipt = run.capabilityAudit.filesystemReceipts.find(
        (entry) => entry.operation === 'statSync' && entry.path === '/dev/hidraw0'
      );
      const metadata = clone(receipt.result.metadata);
      metadata.rdev = '61952';
      metadata.major = 242;
      metadata.minor = 0;
      metadata.rdevHex = 'f2:0';
      receipt.result = filesystemStatResult(metadata);
    },
    'framesReconstructed'
  );
});

test('rejects raw process start-tick drift hidden behind an unchanged normalized worker', async () => {
  await assertRefuted(
    'raw-process-drift',
    (run) => {
      const receipt = run.capabilityAudit.filesystemReceipts.find(
        (entry) => entry.operation === 'readFileSync' && /\/73\/stat$/u.test(entry.path)
      );
      changeReadReceipt(receipt, receipt.result.text.replace(/\s7100\n$/u, ' 7101\n'));
    },
    'framesReconstructed'
  );
});

test('rejects raw namespace drift hidden behind an unchanged normalized worker', async () => {
  await assertRefuted(
    'raw-namespace-drift',
    (run) => {
      const receipt = run.capabilityAudit.filesystemReceipts.find(
        (entry) => entry.operation === 'readlinkSync' && /\/73\/ns\/pid$/u.test(entry.path)
      );
      receipt.result = filesystemLinkResult('pid:[4026533999]');
    },
    'framesReconstructed'
  );
});

test('accepts audited socket, pipe, and regular FDs without projecting them as device descriptors', async () => {
  const verification = await verifyFixture(
    await writeFixture('non-character-fds', (run) => {
      const perFrame = frameFilesystemReceipts(run);
      const observedTargets = [
        ['3', 'socket:[12345]'],
        ['4', 'pipe:[67890]'],
        ['5', '/tmp/overlaykit-h045-regular-file'],
      ];
      for (const [frameIndex, receipts] of perFrame.entries()) {
        const frame = run.frames[frameIndex];
        const fdDirectory = `/proc/${frame.deploymentInventory.matches[0].lifecycle.hostPid}/root/proc/73/fd`;
        const directoryIndexes = receipts
          .map((entry, index) => ({ entry, index }))
          .filter(({ entry }) => entry.operation === 'readdirSync' && entry.path === fdDirectory)
          .map(({ index }) => index);
        assert.equal(directoryIndexes.length, 2);
        for (const index of directoryIndexes) {
          receipts[index].result = filesystemDirectoryResult(
            observedTargets.map(([descriptor]) => descriptor)
          );
        }
        const linkStat = {
          ...clone(frame.device.identity.epoch.stat),
          mode: '0777',
          uid: 0,
          gid: 0,
          rdev: '0',
          rdevHex: '0:0',
          major: 0,
          minor: 0,
          isCharacterDevice: false,
          isSymbolicLink: true,
        };
        const targetStat = {
          ...clone(frame.device.identity.epoch.stat),
          mode: '0600',
          uid: 1000,
          gid: 1000,
          rdev: '0',
          rdevHex: '0:0',
          major: 0,
          minor: 0,
          isCharacterDevice: false,
          isSymbolicLink: false,
        };
        const observations = observedTargets.flatMap(([descriptor, target]) => {
          const descriptorPath = `${fdDirectory}/${descriptor}`;
          return [
            observedFilesystemReceipt('lstatSync', descriptorPath, filesystemStatResult(linkStat)),
            observedFilesystemReceipt('readlinkSync', descriptorPath, filesystemLinkResult(target)),
            observedFilesystemReceipt('statSync', descriptorPath, filesystemStatResult(targetStat)),
          ];
        });
        receipts.splice(directoryIndexes[0] + 1, 0, ...observations);
      }
      rebuildFilesystemIndexes(run, perFrame);
      run.liveClassification = classifyDynamicFrames({
        frames: run.frames,
        capabilityAudit: run.capabilityAudit,
        sourceAdmissionExact: true,
      });
      run.outcome = outcomeFor(
        run.sourceAdmission,
        run.capabilityAudit,
        run.liveClassification,
        run.hostileMatrix
      );
    })
  );
  assert.equal(verification.outcome, 'supported', JSON.stringify(verification));
  assert.equal(verification.filesystemAuditExact, true);
  assert.equal(verification.framesReconstructed, true);
  assert.equal(verification.classificationExact, true);
  assert.equal(verification.producerAgreement, true);
});

test('rejects a hidden accepted-major descriptor when normalized descriptors are empty', async () => {
  await assertRefuted(
    'hidden-accepted-major-fd',
    (run) => {
      const perFrame = frameFilesystemReceipts(run);
      for (const [frameIndex, receipts] of perFrame.entries()) {
        const frame = run.frames[frameIndex];
        const fdDirectory = `/proc/${frame.deploymentInventory.matches[0].lifecycle.hostPid}/root/proc/73/fd`;
        const directoryIndexes = receipts
          .map((entry, index) => ({ entry, index }))
          .filter(({ entry }) => entry.operation === 'readdirSync' && entry.path === fdDirectory)
          .map(({ index }) => index);
        assert.equal(directoryIndexes.length, 2);
        for (const index of directoryIndexes) {
          receipts[index].result = filesystemDirectoryResult(['20']);
        }
        const insertAt = directoryIndexes[0] + 1;
        const descriptorPath = `${fdDirectory}/20`;
        const targetStat = {
          ...clone(frame.device.identity.epoch.stat),
          isSymbolicLink: false,
        };
        const linkStat = {
          ...clone(targetStat),
          isCharacterDevice: false,
          isSymbolicLink: true,
          rdev: '0',
          rdevHex: '0:0',
          major: 0,
          minor: 0,
        };
        receipts.splice(
          insertAt,
          0,
          observedFilesystemReceipt('lstatSync', descriptorPath, filesystemStatResult(linkStat)),
          observedFilesystemReceipt(
            'readlinkSync',
            descriptorPath,
            filesystemLinkResult('/dev/hidraw0')
          ),
          observedFilesystemReceipt('statSync', descriptorPath, filesystemStatResult(targetStat))
        );
      }
      rebuildFilesystemIndexes(run, perFrame);
    },
    'framesReconstructed'
  );
});

test('rejects source-map drift after recomputing the outer evidence digest', async () => {
  await assertRefuted(
    'source-map-drift',
    (run) => {
      run.collector.sourcesAfter[0].sha256 = 'f'.repeat(64);
    },
    'sourceSetExact'
  );
});

test('rejects a forged review authorization even when its grant and digest agree', async () => {
  await assertRefuted(
    'review-authorization-tamper',
    (run) => {
      const forgedDigest = 'f'.repeat(64);
      run.collector.reviewAuthorization = {
        grant: `${LIVE_AUTHORIZATION_PREFIX}${forgedDigest}`,
        sourceSetSha256: forgedDigest,
        semantics: 'one-live-read-only-replacement-attempt',
      };
    },
    'reviewAuthorizationExact'
  );
});

test('rejects a reviewed governance source map that does not match current bytes', async () => {
  const verification = await verifyFixture(
    await writeFixture('governance-source-byte-drift', (run) => {
      for (const sources of [run.collector.sourcesBefore, run.collector.sourcesAfter]) {
        const plan = sources.find((entry) => entry.path === '.overlaykit/governance/plan.json');
        assert.ok(plan);
        plan.sha256 = 'f'.repeat(64);
      }
      rebindReviewAuthorization(run);
    })
  );
  assert.equal(verification.outcome, 'refuted');
  assert.equal(verification.reviewAuthorizationExact, true);
  assert.equal(verification.sourceSetExact, false);
  assert.equal(verification.producerAgreement, false);
});

test('rejects governance byte-hash declaration drift at schema admission', async () => {
  await assertSchemaRejected('governance-byte-hash-drift', (run) => {
    run.collector.governance.planSha256 = 'f'.repeat(64);
  });
});

test('rejects ambient child-environment inheritance and killing command limits', async () => {
  await assertSchemaRejected('ambient-child-environment', (run) => {
    run.capabilityAudit.environmentPolicy.inheritedKeys = ['GIT_DIR'];
  });
  await assertSchemaRejected('command-timeout', (run) => {
    run.capabilityAudit.commandReceipts[0].limits.timeoutMs = 1_500;
  });
  await assertSchemaRejected('command-overflow-kill', (run) => {
    run.capabilityAudit.commandReceipts[0].limits.overflow = 'kill';
  });
});

test('refutes an observed child signal even when the producer reports it coherently', async () => {
  const verification = await verifyFixture(
    await writeFixture('observed-child-signal', (run) => {
      run.capabilityAudit.commandReceipts[0].exitCode = null;
      run.capabilityAudit.commandReceipts[0].signal = 'SIGTERM';
      run.capabilityAudit.prohibitedCounts.signal = 1;
      run.liveClassification = classifyDynamicFrames({
        frames: run.frames,
        capabilityAudit: run.capabilityAudit,
        sourceAdmissionExact: true,
      });
      run.outcome = outcomeFor(
        run.sourceAdmission,
        run.capabilityAudit,
        run.liveClassification,
        run.hostileMatrix
      );
    })
  );
  assert.equal(verification.outcome, 'refuted');
  assert.equal(verification.stage, 'capability-boundary');
  assert.equal(verification.reasonCode, 'prohibited-capability-observed');
  assert.equal(verification.prohibitedCapabilityObserved, true);
});

test('rejects a digest-exact link result beyond the 4096 UTF-8 byte bound', async () => {
  await assertRefuted(
    'oversized-link-result',
    (run) => {
      const receipt = run.capabilityAudit.filesystemReceipts.find(
        (entry) => entry.operation === 'readlinkSync' && /\/73\/ns\/pid$/u.test(entry.path)
      );
      receipt.result = filesystemLinkResult('é'.repeat(2_049));
    },
    'filesystemAuditExact'
  );
});

test('rejects reservation-ledger claims expanded into review authorization', async () => {
  await assertSchemaRejected('review-ledger-expansion', (run) => {
    run.collector.reviewAuthorization.reservationSha256 = 'f'.repeat(64);
  });
});

test('rejects a self-declared source-admission summary that differs from reconstruction', async () => {
  await assertRefuted(
    'source-admission-tamper',
    (run) => {
      run.sourceAdmission.runtimeBinaryExact = false;
      run.sourceAdmission.allExact = false;
      run.liveClassification = {
        ...run.liveClassification,
        disposition: 'inconclusive',
        stage: 'source-admission',
        reasonCode: 'source-admission-inexact',
        receipts: [],
      };
      run.outcome = {
        status: 'inconclusive',
        stage: 'source-admission',
        reasonCode: 'source-admission-inexact',
      };
    },
    'sourceAdmissionReconstructed'
  );
});

test('rejects audit summary tampering after recomputing the outer evidence digest', async () => {
  await assertRefuted(
    'audit-summary-tamper',
    (run) => {
      run.capabilityAudit.commandCount += 1;
    },
    'capabilityAuditExact'
  );
});

test('rejects classification stage and reason tampering', async () => {
  await assertRefuted(
    'classification-tamper',
    (run) => {
      run.liveClassification.stage = 'forged-stage';
      run.liveClassification.reasonCode = 'forged-reason';
    },
    'classificationExact'
  );
});

test('rejects hostile-matrix input digest and summary tampering', async () => {
  await assertRefuted(
    'hostile-matrix-tamper',
    (run) => {
      run.hostileMatrix.cases[0].inputSha256 = 'f'.repeat(64);
    },
    'hostileMatrixExact'
  );
});

test('rejects claim-boundary expansion', async () => {
  const fixture = await writeFixture('claim-boundary-tamper', (run) => {
    run.claimBoundary.proves[0] = 'authorizes a future production action';
  });
  await assert.rejects(() => verifyFixture(fixture), /schema invalid|claim boundary/u);
});

test('rejects top-level expansion before semantic verification', async () => {
  const fixture = await writeFixture('top-level-expansion', (run) => {
    run.unexpectedAuthority = true;
  });
  await assert.rejects(() => verifyFixture(fixture), /schema invalid/u);
});

test('rejects outer evidence digest tampering', async () => {
  const fixture = await writeFixture(
    'evidence-digest-tamper',
    (run) => {
      run.completedAt = '2026-07-27T03:00:12.999Z';
    },
    { rebind: false }
  );
  await assert.rejects(() => verifyFixture(fixture), /evidence hash mismatch/u);
});

test('rejects predecessor ledger membership drift in either direction', async () => {
  const missingFailure = await writeFixture('predecessor-missing-failure', undefined, {
    async afterWrite({ predecessorFailurePath }) {
      await rm(predecessorFailurePath);
    },
  });
  await assert.rejects(
    () => verifyFixture(missingFailure),
    /predecessor attempt ledger must contain exactly reservation and failure/u
  );

  const apparentCompletion = await writeFixture('predecessor-apparent-completion', undefined, {
    async afterWrite({ predecessorAttemptDirectory }) {
      const completionPath = path.join(predecessorAttemptDirectory, 'completion.json');
      await writeFile(completionPath, '{}\n', { flag: 'wx', mode: 0o600 });
      await chmod(completionPath, 0o600);
    },
  });
  await assert.rejects(
    () => verifyFixture(apparentCompletion),
    /predecessor attempt ledger must contain exactly reservation and failure/u
  );
});

test('rejects predecessor reservation and failure tampering independently', async () => {
  const reservationTamper = await writeFixture('predecessor-reservation-tamper', undefined, {
    async afterWrite({ predecessorReservationPath }) {
      const reservation = JSON.parse(await readFile(predecessorReservationPath, 'utf8'));
      reservation.authorization.action = 'forged';
      await writeFile(predecessorReservationPath, prettyJsonBytes(reservation), {
        flag: 'w',
        mode: 0o600,
      });
      await chmod(predecessorReservationPath, 0o600);
    },
  });
  await assert.rejects(
    () => verifyFixture(reservationTamper),
    /predecessor attempt reservation bytes are not exact/u
  );

  const failureTamper = await writeFixture('predecessor-failure-tamper', undefined, {
    async afterWrite({ predecessorFailurePath }) {
      const failure = JSON.parse(await readFile(predecessorFailurePath, 'utf8'));
      failure.observationStarted = false;
      await writeFile(predecessorFailurePath, prettyJsonBytes(failure), {
        flag: 'w',
        mode: 0o600,
      });
      await chmod(predecessorFailurePath, 0o600);
    },
  });
  await assert.rejects(
    () => verifyFixture(failureTamper),
    /predecessor attempt failure bytes are not exact/u
  );
});

test('rejects declared predecessor and replacement ledger path drift', async () => {
  const predecessorPathDrift = await writeFixture('predecessor-ledger-path-drift', undefined, {
    afterLedger(run) {
      run.collector.attemptLedger.predecessorFailureRelativePath =
        'artifacts/h045/live-attempt/alternate-failure.json';
    },
  });
  await assert.rejects(() => verifyFixture(predecessorPathDrift), /schema invalid/u);

  const replacementPathDrift = await writeFixture('replacement-ledger-path-drift', undefined, {
    afterLedger(run) {
      run.collector.attemptLedger.reservationRelativePath =
        'artifacts/h045/live-attempt/reservation.json';
    },
  });
  await assert.rejects(() => verifyFixture(replacementPathDrift), /schema invalid/u);
});

test('rejects a missing completion from the fixed one-shot ledger', async () => {
  const fixture = await writeFixture('ledger-missing-completion', undefined, {
    async afterWrite({ completionPath }) {
      await rm(completionPath);
    },
  });
  await assert.rejects(
    () => verifyFixture(fixture),
    /attempt ledger must contain exactly reservation and completion/u
  );
});

test('rejects a failure receipt beside an apparent successful completion', async () => {
  const fixture = await writeFixture('ledger-failure-present', undefined, {
    async afterWrite({ attemptDirectory }) {
      const failurePath = path.join(attemptDirectory, 'failure.json');
      await writeFile(
        failurePath,
        prettyJsonBytes({
          schemaVersion: 'overlaykit-h045-live-attempt-failure/v2',
          reservationSha256: canonicalRun.collector.attemptLedger.reservationSha256,
          stage: 'forged-success',
          observationStarted: true,
        }),
        { flag: 'wx', mode: 0o600 }
      );
      await chmod(failurePath, 0o600);
    },
  });
  await assert.rejects(
    () => verifyFixture(fixture),
    /attempt ledger must contain exactly reservation and completion/u
  );
});

test('rejects symbolic ledger receipts even when their directory names are exact', async () => {
  const fixture = await writeFixture('ledger-symbolic-completion', undefined, {
    async afterWrite({ completionPath }) {
      await rm(completionPath);
      await symlink('reservation.json', completionPath);
    },
  });
  await assert.rejects(
    () => verifyFixture(fixture),
    /attempt completion cannot be opened securely/u
  );
});

test('rejects ledger receipt permission drift', async () => {
  const fixture = await writeFixture('ledger-mode-drift', undefined, {
    async afterWrite({ reservationPath }) {
      await chmod(reservationPath, 0o644);
    },
  });
  await assert.rejects(() => verifyFixture(fixture), /attempt reservation mode is not 0600/u);
});

test('rejects completion and run evidence permission drift independently', async () => {
  const completionFixture = await writeFixture('ledger-completion-mode-drift', undefined, {
    async afterWrite({ completionPath }) {
      await chmod(completionPath, 0o640);
    },
  });
  await assert.rejects(
    () => verifyFixture(completionFixture),
    /attempt completion mode is not 0600/u
  );

  const runFixture = await writeFixture('run-mode-drift', undefined, {
    async afterWrite({ runPath }) {
      await chmod(runPath, 0o644);
    },
  });
  await assert.rejects(() => verifyFixture(runFixture), /run evidence mode is not 0600/u);
});

test('rejects a symbolic ledger directory before enumerating any receipt', async () => {
  const fixture = await writeFixture('ledger-directory-symlink', undefined, {
    async afterWrite({ artifactRoot, attemptDirectory }) {
      const realDirectory = path.join(artifactRoot, 'live-attempt-real');
      await rename(attemptDirectory, realDirectory);
      await symlink('live-attempt-real', attemptDirectory, 'dir');
    },
  });
  await assert.rejects(
    () => verifyFixture(fixture),
    /attempt ledger directory cannot be opened securely/u
  );
});

test('rejects a hard-linked reservation even when the alias is outside the ledger directory', async () => {
  const fixture = await writeFixture('ledger-hard-link', undefined, {
    async afterWrite({ fixtureRoot, reservationPath }) {
      await link(reservationPath, path.join(fixtureRoot, 'reservation-alias.json'));
    },
  });
  await assert.rejects(() => verifyFixture(fixture), /attempt reservation has a hard-link alias/u);
});

test('rejects a ledger receipt before reading more than its bounded 64 KiB envelope', async () => {
  const fixture = await writeFixture('ledger-byte-limit', undefined, {
    async afterWrite({ reservationPath }) {
      await writeFile(reservationPath, Buffer.alloc(64 * 1024 + 1, 0x20), { mode: 0o600 });
      await chmod(reservationPath, 0o600);
    },
  });
  await assert.rejects(() => verifyFixture(fixture), /attempt reservation exceeds its byte limit/u);
});

test('rejects a run-declared reservation digest that differs from exact ledger bytes', async () => {
  const fixture = await writeFixture('ledger-declared-digest-drift', undefined, {
    afterLedger(run) {
      run.collector.attemptLedger.reservationSha256 = 'f'.repeat(64);
    },
  });
  await assert.rejects(
    () => verifyFixture(fixture),
    /attempt reservation digest does not match run evidence/u
  );
});

test('rejects reservation authorization bytes that disagree with the reviewed source grant', async () => {
  const fixture = await writeFixture('ledger-reservation-authorization-drift', undefined, {
    ledgerMutation({ reservation }) {
      reservation.authorization.authority = 'signal';
    },
  });
  await assert.rejects(() => verifyFixture(fixture), /attempt reservation bytes are not exact/u);
});

test('rejects completion bytes that do not bind the run evidence digest', async () => {
  const fixture = await writeFixture('ledger-completion-evidence-drift', undefined, {
    ledgerMutation({ completion }) {
      completion.evidenceSha256 = 'f'.repeat(64);
    },
  });
  await assert.rejects(() => verifyFixture(fixture), /attempt completion bytes are not exact/u);
});

test('rejects non-canonical JSON bytes in an otherwise semantic reservation', async () => {
  const fixture = await writeFixture('ledger-reservation-byte-drift', undefined, {
    async afterWrite({ reservationPath }) {
      const reservation = JSON.parse(await readFile(reservationPath, 'utf8'));
      await writeFile(reservationPath, JSON.stringify(reservation), { mode: 0o600 });
      await chmod(reservationPath, 0o600);
    },
  });
  await assert.rejects(() => verifyFixture(fixture), /attempt reservation bytes are not exact/u);
});

test('rejects an in-place ledger mutation after the initial receipt read', async () => {
  const fixture = await writeFixture('ledger-cutoff-in-place-mutation');
  const completionPath = path.join(
    path.dirname(path.dirname(fixture)),
    REPLACEMENT_ATTEMPT_ID,
    'completion.json'
  );
  const changed = Buffer.from(await readFile(completionPath));
  const marker = Buffer.from('overlaykit-h045-live-attempt-completion/v2');
  const markerOffset = changed.indexOf(marker);
  assert.notEqual(markerOffset, -1);
  changed[markerOffset] = 'x'.charCodeAt(0);

  const rejection = assert.rejects(
    verifyFixture(fixture),
    /attempt completion (?:bytes are not exact|changed)/u
  );
  await new Promise((resolve) => setTimeout(resolve, 25));
  await writeFile(completionPath, changed, { flag: 'r+' });
  await rejection;
});
