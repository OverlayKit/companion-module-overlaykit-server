import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { BRANCHES, executeSyntheticCase } from './fixtures/synthetic-terminal-cases.mjs';
import {
  canonicalHash,
  canonicalPrettyJson,
  makeReservation,
  produceTerminalEnvelope,
  sha256,
} from './producer.mjs';
import { verifyReplay, verifyTerminal } from './verify.mjs';

const APPARATUS_ROOT = path.dirname(fileURLToPath(import.meta.url));
export const REPOSITORY_ROOT = realpathSync(path.resolve(APPARATUS_ROOT, '../..'));
const SUBJECT_LOCATOR = 'lab/node22-failure-preservation-preflight/subject-lock.json';
const SUBJECT_PATH = path.join(REPOSITORY_ROOT, SUBJECT_LOCATOR);
const CHG0040_LOCATOR = '.overlaykit/governance/changes/CHG-0040.json';
const MANIFEST_LOCATOR = '.overlaykit/governance/manifest.json';
const PLAN_LOCATOR = '.overlaykit/governance/plan.json';
const GITIGNORE_LOCATOR = '.gitignore';
const FIXED_EVIDENCE_ROOT = path.join(
  REPOSITORY_ROOT,
  'artifacts/node22-failure-preservation-preflight'
);
const PINNED_SUBJECT_RAW_SHA256 =
  '32faedd0bf9202190ee9fdbae0c84baff05764dd637dcf4b2dfd6d4487aca144';
const PINNED_GITIGNORE_RAW_SHA256 =
  '2c42503834e61def3bf5840b5c553a73b2d569cee732c69e7420f75ce5e6f1fc';
const PINNED_PLAN_RAW_SHA256 = '2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243';
const RUN_SCHEMA_VERSION = 'overlaykit-node22-failure-preservation-preflight-run/v1';

export const SOURCE_SET_PATHS = Object.freeze([
  'lab/node22-failure-preservation-preflight/contract.test.mjs',
  'lab/node22-failure-preservation-preflight/fixtures/synthetic-terminal-cases.mjs',
  'lab/node22-failure-preservation-preflight/integration.test.mjs',
  'lab/node22-failure-preservation-preflight/package.json',
  'lab/node22-failure-preservation-preflight/producer.mjs',
  'lab/node22-failure-preservation-preflight/producer.test.mjs',
  'lab/node22-failure-preservation-preflight/run.mjs',
  'lab/node22-failure-preservation-preflight/run.test.mjs',
  'lab/node22-failure-preservation-preflight/subject-lock.json',
  'lab/node22-failure-preservation-preflight/verify.mjs',
  'lab/node22-failure-preservation-preflight/verify.test.mjs',
]);

export class FailurePreservationRunError extends Error {
  constructor(code) {
    super(code);
    this.name = 'FailurePreservationRunError';
    this.code = code;
  }
}

function reject(code) {
  throw new FailurePreservationRunError(code);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function exactMode(metadata) {
  return (metadata.mode & 0o7777).toString(8).padStart(4, '0');
}

function currentUid() {
  return typeof process.getuid === 'function' ? process.getuid() : null;
}

function isContained(root, candidate) {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function assertContained(root, candidate) {
  if (!isContained(root, candidate)) reject('artifact-containment-invalid');
}

function fsyncDirectory(directory) {
  const descriptor = openSync(
    directory,
    constants.O_RDONLY | (constants.O_DIRECTORY ?? 0) | constants.O_NOFOLLOW
  );
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function assertOwned(metadata) {
  const uid = currentUid();
  if (uid !== null && metadata.uid !== uid) reject('artifact-owner-invalid');
}

export function assertPrivateDirectory(directory, containmentRoot) {
  assertContained(containmentRoot, directory);
  const metadata = lstatSync(directory);
  if (metadata.isSymbolicLink()) reject('artifact-symlink-invalid');
  if (!metadata.isDirectory()) reject('artifact-roster-invalid');
  if (exactMode(metadata) !== '0700') reject('directory-mode-invalid');
  assertOwned(metadata);
  const realRoot = realpathSync(containmentRoot);
  const realDirectory = realpathSync(directory);
  assertContained(realRoot, realDirectory);
  return {
    mode: exactMode(metadata),
    ownerUid: metadata.uid,
    realPath: realDirectory,
  };
}

function createPrivateDirectory(directory, containmentRoot, { exclusive = false } = {}) {
  assertContained(containmentRoot, directory);
  try {
    mkdirSync(directory, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
    if (exclusive) reject('reservation-already-consumed');
  }
  return assertPrivateDirectory(directory, containmentRoot);
}

function ensureArtifactsRoot(evidenceRoot) {
  const artifactsRoot = path.join(REPOSITORY_ROOT, 'artifacts');
  assertContained(artifactsRoot, evidenceRoot);
  try {
    mkdirSync(artifactsRoot, { mode: 0o700 });
  } catch (error) {
    if (error?.code !== 'EEXIST') throw error;
  }
  const metadata = lstatSync(artifactsRoot);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    reject('artifact-symlink-invalid');
  }
  assertOwned(metadata);
  assertContained(realpathSync(artifactsRoot), path.resolve(evidenceRoot));
  return artifactsRoot;
}

function readStableRegularFile(filePath) {
  const descriptor = openSync(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1) {
      reject(before.nlink === 1 ? 'artifact-roster-invalid' : 'artifact-hardlink-invalid');
    }
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs ||
      bytes.length !== after.size
    ) {
      reject('artifact-changed-during-read');
    }
    return { bytes, metadata: after };
  } finally {
    closeSync(descriptor);
  }
}

export function verifyPrivateEvidenceFile(filePath, expectedBytes, containmentRoot) {
  assertContained(containmentRoot, filePath);
  const lexical = lstatSync(filePath);
  if (lexical.isSymbolicLink()) reject('artifact-symlink-invalid');
  if (!lexical.isFile()) reject('artifact-roster-invalid');
  if (lexical.nlink !== 1) reject('artifact-hardlink-invalid');
  if (exactMode(lexical) !== '0600') reject('file-mode-invalid');
  assertOwned(lexical);
  const { bytes, metadata } = readStableRegularFile(filePath);
  if (!bytes.equals(expectedBytes)) reject('artifact-byte-drift');
  if (realpathSync(filePath) !== path.resolve(filePath)) reject('artifact-containment-invalid');
  return {
    byteLength: bytes.length,
    mode: exactMode(metadata),
    nlink: metadata.nlink,
    ownerUid: metadata.uid,
    sha256: sha256(bytes),
  };
}

export function writeExclusivePrivateFile(filePath, bytes, containmentRoot, options = {}) {
  assertContained(containmentRoot, filePath);
  assertPrivateDirectory(path.dirname(filePath), containmentRoot);
  let descriptor;
  try {
    descriptor = openSync(
      filePath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
      0o600
    );
  } catch (error) {
    if (error?.code === 'EEXIST') reject('exclusive-create-collision');
    throw error;
  }
  try {
    const writeBytes =
      options.injectPartialByteLength === undefined
        ? bytes
        : bytes.subarray(0, options.injectPartialByteLength);
    writeFileSync(descriptor, writeBytes);
    fsyncSync(descriptor);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.nlink !== 1) reject('artifact-hardlink-invalid');
    if (exactMode(metadata) !== '0600') reject('file-mode-invalid');
    assertOwned(metadata);
  } finally {
    closeSync(descriptor);
  }
  fsyncDirectory(path.dirname(filePath));
  if (options.injectPartialByteLength !== undefined) {
    reject('synthetic-partial-write-injected');
  }
  return verifyPrivateEvidenceFile(filePath, bytes, containmentRoot);
}

function writeTarString(header, offset, length, value) {
  const bytes = Buffer.from(value, 'utf8');
  if (bytes.length > length) reject('replay-path-invalid');
  bytes.copy(header, offset);
}

function writeTarOctal(header, offset, length, value) {
  const encoded = value.toString(8).padStart(length - 1, '0');
  if (encoded.length > length - 1) reject('replay-metadata-invalid');
  writeTarString(header, offset, length, `${encoded}\0`);
}

function tarHeader(name, byteLength) {
  if (
    name.length === 0 ||
    name.startsWith('/') ||
    name.includes('\\') ||
    name.split('/').some((part) => part === '' || part === '.' || part === '..') ||
    Buffer.byteLength(name, 'utf8') > 100
  ) {
    reject('replay-path-invalid');
  }
  const header = Buffer.alloc(512);
  writeTarString(header, 0, 100, name);
  writeTarOctal(header, 100, 8, 0o600);
  writeTarOctal(header, 108, 8, 0);
  writeTarOctal(header, 116, 8, 0);
  writeTarOctal(header, 124, 12, byteLength);
  writeTarOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = '0'.charCodeAt(0);
  writeTarString(header, 257, 6, 'ustar\0');
  writeTarString(header, 263, 2, '00');
  const checksum = [...header].reduce((total, byte) => total + byte, 0);
  const checksumOctal = checksum.toString(8).padStart(6, '0');
  if (checksumOctal.length !== 6) reject('replay-metadata-invalid');
  writeTarString(header, 148, 8, `${checksumOctal}\0 `);
  return header;
}

export function buildReplayArchive(members) {
  const names = members.map(({ name }) => name);
  if (new Set(names).size !== names.length) reject('replay-member-collision');
  const ordered = [...members].sort((left, right) => compareUtf8(left.name, right.name));
  const blocks = [];
  for (const { bytes, name } of ordered) {
    if (!Buffer.isBuffer(bytes)) reject('replay-member-invalid');
    blocks.push(tarHeader(name, bytes.length), bytes);
    const remainder = bytes.length % 512;
    if (remainder !== 0) blocks.push(Buffer.alloc(512 - remainder));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

function evidencePaths(evidenceRoot) {
  return {
    evidenceRoot,
    reservationsRoot: path.join(evidenceRoot, 'reservations'),
    runsRoot: path.join(evidenceRoot, 'runs'),
  };
}

function prepareEvidenceRoot(evidenceRoot) {
  const artifactsRoot = ensureArtifactsRoot(evidenceRoot);
  const paths = evidencePaths(evidenceRoot);
  createPrivateDirectory(paths.evidenceRoot, artifactsRoot);
  createPrivateDirectory(paths.reservationsRoot, paths.evidenceRoot);
  createPrivateDirectory(paths.runsRoot, paths.evidenceRoot);
  return paths;
}

function normalizeLaunchError(error) {
  return {
    code: typeof error?.code === 'string' ? error.code : 'SYNTHETIC_LAUNCH_FAILURE',
    syscall: typeof error?.syscall === 'string' ? error.syscall : 'synthetic-node22-fixture-launch',
  };
}

function publicBranchReceipt(materialized) {
  return {
    archive: {
      byteLength: materialized.archiveBytes.length,
      path: materialized.archivePathRelative,
      sha256: sha256(materialized.archiveBytes),
    },
    branchId: materialized.branchId,
    ordinal: materialized.ordinal,
    reservation: {
      byteLength: materialized.reservationBytes.length,
      path: materialized.reservationPathRelative,
      sha256: sha256(materialized.reservationBytes),
    },
    terminal: {
      byteLength: materialized.terminalBytes.length,
      path: materialized.terminalPathRelative,
      semanticSha256: materialized.terminal.semanticSha256,
      sha256: sha256(materialized.terminalBytes),
    },
    verification: materialized.verification,
  };
}

export function materializeTerminalCase({
  branchId,
  evidenceRoot,
  executeCase = executeSyntheticCase,
  hooks = {},
  ordinal,
}) {
  const expectedOrdinal = BRANCHES.indexOf(branchId) + 1;
  if (expectedOrdinal === 0 || ordinal !== expectedOrdinal) reject('branch-roster-invalid');
  const paths = prepareEvidenceRoot(evidenceRoot);
  const subjectBytes = readStableRegularFile(SUBJECT_PATH).bytes;
  const subjectRawSha256 = sha256(subjectBytes);
  if (subjectRawSha256 !== PINNED_SUBJECT_RAW_SHA256) reject('subject-policy-stale');
  const subject = JSON.parse(subjectBytes.toString('utf8'));

  const reservation = makeReservation({
    branchId,
    ordinal,
    sourceAnchor: subject.sourceAnchor,
    subjectRawSha256,
  });
  const reservationBytes = Buffer.from(canonicalPrettyJson(reservation), 'utf8');
  const reservationRawSha256 = sha256(reservationBytes);
  const reservationDirectory = path.join(
    paths.reservationsRoot,
    `${String(ordinal).padStart(2, '0')}-${branchId}-${reservationRawSha256}`
  );
  createPrivateDirectory(reservationDirectory, paths.reservationsRoot, { exclusive: true });
  const reservationPath = path.join(reservationDirectory, 'reservation.json');
  writeExclusivePrivateFile(reservationPath, reservationBytes, paths.reservationsRoot);
  hooks.onReservationDurable?.({ branchId, reservationRawSha256 });

  hooks.onAttemptStart?.({ branchId });
  let transport;
  try {
    transport = executeCase(branchId);
  } catch (error) {
    transport = {
      attempts: [],
      launchError: normalizeLaunchError(error),
    };
  }

  const terminal = produceTerminalEnvelope({
    branchId,
    ordinal,
    reservationRawSha256,
    transport,
  });
  const terminalBytes = Buffer.from(canonicalPrettyJson(terminal), 'utf8');
  const terminalRawSha256 = sha256(terminalBytes);
  const terminalName = `terminal-${terminalRawSha256}.json`;
  const terminalPath = path.join(reservationDirectory, terminalName);
  writeExclusivePrivateFile(terminalPath, terminalBytes, paths.reservationsRoot);

  const archiveBytes = buildReplayArchive([
    { bytes: reservationBytes, name: 'reservation.json' },
    { bytes: terminalBytes, name: 'terminal.json' },
  ]);
  const archiveRawSha256 = sha256(archiveBytes);
  const archiveName = `replay-${archiveRawSha256}.tar`;
  const archivePath = path.join(reservationDirectory, archiveName);
  writeExclusivePrivateFile(archivePath, archiveBytes, paths.reservationsRoot);

  const terminalVerification = verifyTerminal({
    reservationBytes,
    subjectBytes,
    terminalBytes,
  });
  const replayVerification = verifyReplay({
    archiveBytes,
    reservationBytes,
    subjectBytes,
    terminalBytes,
  });
  const verification = {
    branchId: terminalVerification.branchId,
    replaySha256: replayVerification.archiveSha256,
    status: 'independently-reconstructed',
    terminalSemanticSha256: terminalVerification.terminalSemanticSha256,
  };
  const repositoryRelative = (absolutePath) =>
    path.relative(REPOSITORY_ROOT, absolutePath).split(path.sep).join('/');
  return {
    archiveBytes,
    archivePath,
    archivePathRelative: repositoryRelative(archivePath),
    branchId,
    ordinal,
    reservation,
    reservationBytes,
    reservationDirectory,
    reservationPath,
    reservationPathRelative: repositoryRelative(reservationPath),
    terminal,
    terminalBytes,
    terminalPath,
    terminalPathRelative: repositoryRelative(terminalPath),
    verification,
  };
}

function expectRunRejection(operation, expectedCode) {
  try {
    operation();
  } catch (error) {
    if (error?.code === expectedCode) return error.code;
    throw error;
  }
  reject('control-not-rejected');
}

function expectAnyRejection(operation, allowedCodes) {
  try {
    operation();
  } catch (error) {
    if (allowedCodes.includes(error?.code)) return error.code;
    throw error;
  }
  reject('control-not-rejected');
}

function assertBranchRoster(receipts) {
  const ids = receipts.map(({ branchId }) => branchId);
  if (new Set(ids).size !== ids.length) reject('terminal-branch-collision');
  if (JSON.stringify(ids) !== JSON.stringify(BRANCHES)) reject('branch-roster-invalid');
}

function inMemoryCase(branchId, ordinal, subject) {
  const reservation = makeReservation({
    branchId,
    ordinal,
    sourceAnchor: subject.sourceAnchor,
    subjectRawSha256: PINNED_SUBJECT_RAW_SHA256,
  });
  const reservationBytes = Buffer.from(canonicalPrettyJson(reservation), 'utf8');
  const terminal = produceTerminalEnvelope({
    branchId,
    ordinal,
    reservationRawSha256: sha256(reservationBytes),
    transport: executeSyntheticCase(branchId),
  });
  const terminalBytes = Buffer.from(canonicalPrettyJson(terminal), 'utf8');
  const archiveBytes = buildReplayArchive([
    { bytes: reservationBytes, name: 'reservation.json' },
    { bytes: terminalBytes, name: 'terminal.json' },
  ]);
  return { archiveBytes, reservationBytes, terminalBytes };
}

export function runAuthorizedControls({ evidenceRoot, materializedCases }) {
  const subjectBytes = readStableRegularFile(SUBJECT_PATH).bytes;
  const subject = JSON.parse(subjectBytes.toString('utf8'));
  const controls = [];
  const record = (id, expectedReasonCode, observedReasonCode) => {
    controls.push({
      expectedReasonCode,
      id,
      observedReasonCode,
      passed: expectedReasonCode === observedReasonCode,
    });
  };

  const scratchRoot = mkdtempSync(path.join(tmpdir(), 'overlaykit-node22-failure-preservation-'), {
    encoding: 'utf8',
  });
  chmodSync(scratchRoot, 0o700);
  try {
    const partialDirectory = path.join(scratchRoot, 'partial');
    createPrivateDirectory(partialDirectory, scratchRoot);
    const complete = materializedCases[0].terminalBytes;
    const partialPath = path.join(partialDirectory, 'terminal.json');
    const partialWriteCode = expectRunRejection(
      () =>
        writeExclusivePrivateFile(partialPath, complete, scratchRoot, {
          injectPartialByteLength: Math.max(1, complete.length - 7),
        }),
      'synthetic-partial-write-injected'
    );
    const partialVerifyCode = expectRunRejection(
      () => verifyPrivateEvidenceFile(partialPath, complete, scratchRoot),
      'artifact-byte-drift'
    );
    record(
      'partial-write',
      'synthetic-partial-write-injected+artifact-byte-drift',
      `${partialWriteCode}+${partialVerifyCode}`
    );

    let duplicateAttemptCount = 0;
    const duplicateCode = expectRunRejection(
      () =>
        materializeTerminalCase({
          branchId: BRANCHES[0],
          evidenceRoot,
          executeCase() {
            duplicateAttemptCount += 1;
            return executeSyntheticCase(BRANCHES[0]);
          },
          ordinal: 1,
        }),
      'reservation-already-consumed'
    );
    if (duplicateAttemptCount !== 0) reject('duplicate-reservation-executed');
    record('duplicate-reservation', 'reservation-already-consumed', duplicateCode);

    const staleReservation = JSON.parse(materializedCases[1].reservationBytes.toString('utf8'));
    staleReservation.sourceAnchor.mainCommit = '0'.repeat(40);
    const staleBytes = Buffer.from(canonicalPrettyJson(staleReservation), 'utf8');
    const staleCode = expectAnyRejection(
      () =>
        verifyTerminal({
          reservationBytes: staleBytes,
          subjectBytes,
          terminalBytes: materializedCases[1].terminalBytes,
        }),
      ['reservation-digest-drift', 'reservation-source-anchor-mismatch', 'source-anchor-stale']
    );
    record('staleness', staleCode, staleCode);

    const collisionCode = expectRunRejection(
      () =>
        assertBranchRoster([
          ...materializedCases.map(publicBranchReceipt),
          publicBranchReceipt(materializedCases[0]),
        ]),
      'terminal-branch-collision'
    );
    record('collision', 'terminal-branch-collision', collisionCode);

    const targetDirectory = path.join(scratchRoot, 'links');
    createPrivateDirectory(targetDirectory, scratchRoot);
    const targetPath = path.join(targetDirectory, 'target.json');
    const targetBytes = Buffer.from('{}\n', 'utf8');
    writeExclusivePrivateFile(targetPath, targetBytes, scratchRoot);
    const symlinkPath = path.join(targetDirectory, 'symlink.json');
    symlinkSync('target.json', symlinkPath);
    const symlinkCode = expectRunRejection(
      () => verifyPrivateEvidenceFile(symlinkPath, targetBytes, scratchRoot),
      'artifact-symlink-invalid'
    );
    record('symlink', 'artifact-symlink-invalid', symlinkCode);

    const hardlinkPath = path.join(targetDirectory, 'hardlink.json');
    linkSync(targetPath, hardlinkPath);
    const hardlinkCode = expectRunRejection(
      () => verifyPrivateEvidenceFile(targetPath, targetBytes, scratchRoot),
      'artifact-hardlink-invalid'
    );
    record('hardlink', 'artifact-hardlink-invalid', hardlinkCode);

    const containmentCode = expectRunRejection(
      () =>
        verifyPrivateEvidenceFile(
          path.join(path.dirname(scratchRoot), 'outside.json'),
          targetBytes,
          scratchRoot
        ),
      'artifact-containment-invalid'
    );
    record('containment', 'artifact-containment-invalid', containmentCode);

    const looseDirectory = path.join(scratchRoot, 'loose-directory');
    mkdirSync(looseDirectory, { mode: 0o700 });
    chmodSync(looseDirectory, 0o755);
    const directoryModeCode = expectRunRejection(
      () => assertPrivateDirectory(looseDirectory, scratchRoot),
      'directory-mode-invalid'
    );
    record('directory-permission', 'directory-mode-invalid', directoryModeCode);

    const modeDirectory = path.join(scratchRoot, 'mode');
    createPrivateDirectory(modeDirectory, scratchRoot);
    const looseFile = path.join(modeDirectory, 'loose.json');
    writeFileSync(looseFile, targetBytes, { flag: 'wx', mode: 0o600 });
    chmodSync(looseFile, 0o644);
    const fileModeCode = expectRunRejection(
      () => verifyPrivateEvidenceFile(looseFile, targetBytes, scratchRoot),
      'file-mode-invalid'
    );
    record('file-mode', 'file-mode-invalid', fileModeCode);

    const first = BRANCHES.map((branchId, index) => inMemoryCase(branchId, index + 1, subject));
    const second = BRANCHES.map((branchId, index) => inMemoryCase(branchId, index + 1, subject));
    const deterministic = first.every(
      (entry, index) =>
        entry.reservationBytes.equals(second[index].reservationBytes) &&
        entry.terminalBytes.equals(second[index].terminalBytes) &&
        entry.archiveBytes.equals(second[index].archiveBytes)
    );
    if (!deterministic) reject('replay-nondeterministic');
    record('determinism', 'byte-identical', 'byte-identical');
  } finally {
    const requiredPrefix = path.join(tmpdir(), 'overlaykit-node22-failure-preservation-');
    if (!scratchRoot.startsWith(requiredPrefix)) reject('artifact-containment-invalid');
    rmSync(scratchRoot, { force: true, recursive: true });
  }

  if (
    JSON.stringify(controls.map(({ id }) => id)) !== JSON.stringify(subject.controls) ||
    controls.some(({ passed }) => !passed)
  ) {
    reject('control-roster-incomplete');
  }
  return controls;
}

function sourceSet() {
  const descriptors = SOURCE_SET_PATHS.map((locator) => {
    const absolutePath = path.join(REPOSITORY_ROOT, locator);
    const { bytes, metadata } = readStableRegularFile(absolutePath);
    return {
      byteLength: bytes.length,
      mode: exactMode(metadata),
      path: locator,
      sha256: sha256(bytes),
    };
  }).sort((left, right) => compareUtf8(left.path, right.path));
  return {
    descriptors,
    sha256: canonicalHash(descriptors),
  };
}

function governanceAnchors() {
  const chgBytes = readStableRegularFile(path.join(REPOSITORY_ROOT, CHG0040_LOCATOR)).bytes;
  const manifestBytes = readStableRegularFile(path.join(REPOSITORY_ROOT, MANIFEST_LOCATOR)).bytes;
  const planBytes = readStableRegularFile(path.join(REPOSITORY_ROOT, PLAN_LOCATOR)).bytes;
  if (sha256(planBytes) !== PINNED_PLAN_RAW_SHA256) reject('source-anchor-stale');
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const chgRawSha256 = sha256(chgBytes);
  if (manifest.changes?.['CHG-0040'] !== chgRawSha256) reject('source-anchor-stale');
  return {
    chg0040RawSha256: chgRawSha256,
    manifestContentHash: manifest.contentHash,
    manifestRawSha256: sha256(manifestBytes),
    planHash: manifest.planHash,
    planRawSha256: sha256(planBytes),
  };
}

function semanticBody(run) {
  const { runId: _runId, semanticSha256: _semanticSha256, ...body } = run;
  return body;
}

export function buildSyntheticFailurePreservationRun({ evidenceRoot }) {
  const gitignoreBytes = readStableRegularFile(path.join(REPOSITORY_ROOT, GITIGNORE_LOCATOR)).bytes;
  if (
    sha256(gitignoreBytes) !== PINNED_GITIGNORE_RAW_SHA256 ||
    !gitignoreBytes.toString('utf8').split(/\r?\n/u).includes('artifacts/')
  ) {
    reject('raw-evidence-policy-invalid');
  }
  const materializedCases = BRANCHES.map((branchId, index) =>
    materializeTerminalCase({
      branchId,
      evidenceRoot,
      ordinal: index + 1,
    })
  );
  const branchReceipts = materializedCases.map(publicBranchReceipt);
  assertBranchRoster(branchReceipts);
  const controls = runAuthorizedControls({ evidenceRoot, materializedCases });
  const source = sourceSet();
  const run = {
    action: null,
    authority: 'none',
    branches: branchReceipts,
    controls,
    counts: {
      independentlyReconstructed: branchReceipts.filter(
        ({ verification }) => verification.status === 'independently-reconstructed'
      ).length,
      terminalBranches: branchReceipts.length,
    },
    governanceAnchors: governanceAnchors(),
    humanReview: {
      accepted: null,
      required: true,
    },
    interpretation: {
      adrCandidate: null,
      claimBoundary:
        'deterministic synthetic terminal-envelope preservation and reconstruction only',
      deferred:
        'real expectations, immutable payload authority, H-055, tracing, seccomp, loader, kernel, live and production policy',
    },
    normative: false,
    outcome: {
      candidate: 'supported',
      reason: 'five-of-five-terminal-branches-reconstructed-and-all-controls-passed',
      status: 'awaiting-human-review',
    },
    schemaVersion: RUN_SCHEMA_VERSION,
    sourceSet: source,
    study: 'NODE22-FAILURE-PRESERVATION-PREFLIGHT-001',
    synthetic: true,
  };
  const semanticSha256 = canonicalHash(run);
  return {
    materializedCases,
    run: {
      ...run,
      runId: `node22-failure-preservation-${semanticSha256.slice(0, 24)}`,
      semanticSha256,
    },
  };
}

export function preserveSyntheticFailurePreservationRun({ evidenceRoot, run }) {
  const paths = prepareEvidenceRoot(evidenceRoot);
  const expectedSemanticSha256 = canonicalHash(semanticBody(run));
  if (
    run.semanticSha256 !== expectedSemanticSha256 ||
    run.runId !== `node22-failure-preservation-${expectedSemanticSha256.slice(0, 24)}`
  ) {
    reject('run-semantic-drift');
  }
  const runDirectory = path.join(paths.runsRoot, run.semanticSha256);
  createPrivateDirectory(runDirectory, paths.runsRoot, { exclusive: true });
  const runBytes = Buffer.from(canonicalPrettyJson(run), 'utf8');
  const runPath = path.join(runDirectory, 'run.json');
  const metadata = writeExclusivePrivateFile(runPath, runBytes, paths.runsRoot);
  return {
    path: path.relative(REPOSITORY_ROOT, runPath).split(path.sep).join('/'),
    rawSha256: metadata.sha256,
    runId: run.runId,
    semanticSha256: run.semanticSha256,
  };
}

function isMainModule() {
  return process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

if (isMainModule()) {
  const args = process.argv.slice(2);
  if (args.length !== 1 || args[0] !== '--write') reject('cli-arguments-invalid');
  if (path.resolve(FIXED_EVIDENCE_ROOT) !== FIXED_EVIDENCE_ROOT) {
    reject('artifact-containment-invalid');
  }
  const { run } = buildSyntheticFailurePreservationRun({
    evidenceRoot: FIXED_EVIDENCE_ROOT,
  });
  process.stdout.write(
    `${JSON.stringify(
      preserveSyntheticFailurePreservationRun({
        evidenceRoot: FIXED_EVIDENCE_ROOT,
        run,
      })
    )}\n`
  );
}
