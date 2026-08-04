import { createHash } from 'node:crypto';
import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  writeSync,
} from 'node:fs';
import path from 'node:path';

const STUDY = 'NODE22-PRE-ATTEMPT-BINDING-PREFLIGHT-001';
const PRECONTRACT_SCHEMA = 'overlaykit-node22-pre-attempt-binding-preflight-precontract/v1';
const RESERVATION_SCHEMA = 'overlaykit-node22-pre-attempt-binding-preflight-reservation/v1';
const TERMINAL_SCHEMA = 'overlaykit-node22-pre-attempt-binding-preflight-terminal/v1';
const PREDECESSOR_COMMIT = '1121f1dd86114da8560f31122743ae20f8d53b03';
const PREDECESSOR_TREE = '52bf8023a628d85683417bf67c42d7b7effcd912';
const PLAN_RAW_SHA256 = '2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243';
const PLAN_HASH = 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4';
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const GIT_OBJECT_PATTERN = /^[0-9a-f]{40}$/u;
const SOURCE_ROSTER = Object.freeze([
  'lab/node22-pre-attempt-binding-preflight/contract.test.mjs',
  'lab/node22-pre-attempt-binding-preflight/fixtures/synthetic-precontract.mjs',
  'lab/node22-pre-attempt-binding-preflight/integration.test.mjs',
  'lab/node22-pre-attempt-binding-preflight/package.json',
  'lab/node22-pre-attempt-binding-preflight/stage0.mjs',
  'lab/node22-pre-attempt-binding-preflight/stage0.test.mjs',
  'lab/node22-pre-attempt-binding-preflight/stage1.mjs',
  'lab/node22-pre-attempt-binding-preflight/subject-lock.json',
  'lab/node22-pre-attempt-binding-preflight/verify.mjs',
  'lab/node22-pre-attempt-binding-preflight/verify.test.mjs',
]);
const PRECONTRACT_KEYS = Object.freeze([
  'action',
  'apparatusAnchor',
  'authority',
  'branchId',
  'governanceBindings',
  'normative',
  'predecessorAnchor',
  'schemaVersion',
  'sourceSet',
  'study',
  'subjectRawSha256',
  'synthetic',
]);

export class PreAttemptBindingStage0Error extends Error {
  constructor(code, details = null) {
    super(code);
    this.name = 'PreAttemptBindingStage0Error';
    this.code = code;
    this.details = details;
  }
}

function reject(code, details = null) {
  throw new PreAttemptBindingStage0Error(code, details);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, expected, code) {
  if (!isPlainObject(value)) reject(code);
  const actual = Object.keys(value).sort(compareUtf8);
  const wanted = [...expected].sort(compareUtf8);
  if (actual.length !== wanted.length || !actual.every((key, index) => key === wanted[index])) {
    reject(code);
  }
}

function canonicalize(value, seen = new Set()) {
  if (Array.isArray(value)) {
    if (seen.has(value)) reject('canonical-value-cyclic');
    seen.add(value);
    const result = value.map((entry) => canonicalize(entry, seen));
    seen.delete(value);
    return result;
  }
  if (isPlainObject(value)) {
    if (seen.has(value)) reject('canonical-value-cyclic');
    seen.add(value);
    const result = Object.fromEntries(
      Object.keys(value)
        .sort(compareUtf8)
        .map((key) => [key, canonicalize(value[key], seen)])
    );
    seen.delete(value);
    return result;
  }
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean' ||
    (typeof value === 'number' && Number.isSafeInteger(value))
  ) {
    return value;
  }
  reject('canonical-value-invalid');
}

export function canonicalStage0Json(value) {
  return JSON.stringify(canonicalize(value));
}

function canonicalPrettyJson(value) {
  return `${JSON.stringify(canonicalize(value), null, 2)}\n`;
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonicalHash(value) {
  return sha256(Buffer.from(canonicalStage0Json(value), 'utf8'));
}

function validateSourceSet(sourceSet) {
  exactKeys(
    sourceSet,
    ['descriptorCount', 'descriptors', 'sha256'],
    'precontract-source-set-invalid'
  );
  if (
    sourceSet.descriptorCount !== SOURCE_ROSTER.length ||
    !Array.isArray(sourceSet.descriptors) ||
    sourceSet.descriptors.length !== SOURCE_ROSTER.length
  ) {
    reject('precontract-source-set-invalid');
  }
  const seenPaths = new Set();
  for (const [index, descriptor] of sourceSet.descriptors.entries()) {
    exactKeys(
      descriptor,
      ['byteLength', 'gitMode', 'gitOid', 'path', 'rawSha256'],
      'precontract-source-descriptor-invalid'
    );
    if (
      descriptor.path !== SOURCE_ROSTER[index] ||
      seenPaths.has(descriptor.path) ||
      descriptor.gitMode !== '100644' ||
      !GIT_OBJECT_PATTERN.test(descriptor.gitOid) ||
      !SHA256_PATTERN.test(descriptor.rawSha256) ||
      !Number.isSafeInteger(descriptor.byteLength) ||
      descriptor.byteLength <= 0
    ) {
      reject('precontract-source-descriptor-invalid');
    }
    seenPaths.add(descriptor.path);
  }
  if (
    !SHA256_PATTERN.test(sourceSet.sha256) ||
    canonicalHash(sourceSet.descriptors) !== sourceSet.sha256
  ) {
    reject('precontract-source-set-invalid');
  }
  return sourceSet.descriptors;
}

function parseCanonicalBytes(bytes, label) {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
    reject(`${label}-bytes-invalid`);
  }
  const detached = Buffer.from(bytes);
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(detached);
  } catch {
    reject(`${label}-utf8-invalid`);
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    reject(`${label}-json-invalid`);
  }
  if (text !== canonicalPrettyJson(value)) reject(`${label}-noncanonical`);
  return { bytes: detached, value };
}

function validatePrecontract(precontractBytes, grant) {
  const parsed = parseCanonicalBytes(precontractBytes, 'precontract');
  const value = parsed.value;
  exactKeys(value, PRECONTRACT_KEYS, 'precontract-shape-invalid');
  exactKeys(value.apparatusAnchor, ['commit', 'tree'], 'precontract-shape-invalid');
  exactKeys(
    value.governanceBindings,
    ['chg0042RawSha256', 'manifestContentHash', 'manifestRawSha256', 'planHash', 'planRawSha256'],
    'precontract-shape-invalid'
  );
  exactKeys(value.predecessorAnchor, ['commit', 'tree'], 'precontract-shape-invalid');
  const sourceDescriptors = validateSourceSet(value.sourceSet);
  if (
    value.schemaVersion !== PRECONTRACT_SCHEMA ||
    value.study !== STUDY ||
    value.synthetic !== true ||
    value.normative !== false ||
    value.authority !== 'none' ||
    value.action !== null ||
    value.branchId !== 'launch-failure' ||
    value.predecessorAnchor.commit !== PREDECESSOR_COMMIT ||
    value.predecessorAnchor.tree !== PREDECESSOR_TREE ||
    value.governanceBindings.planRawSha256 !== PLAN_RAW_SHA256 ||
    value.governanceBindings.planHash !== PLAN_HASH
  ) {
    reject('precontract-policy-invalid');
  }
  for (const candidate of [
    value.governanceBindings.chg0042RawSha256,
    value.governanceBindings.manifestContentHash,
    value.governanceBindings.manifestRawSha256,
    value.sourceSet.sha256,
    value.subjectRawSha256,
  ]) {
    if (!SHA256_PATTERN.test(candidate)) reject('precontract-digest-invalid');
  }
  const subjectDescriptor = sourceDescriptors.find(
    (descriptor) => descriptor.path === 'lab/node22-pre-attempt-binding-preflight/subject-lock.json'
  );
  if (subjectDescriptor?.rawSha256 !== value.subjectRawSha256) {
    reject('precontract-subject-binding-invalid');
  }
  if (
    !GIT_OBJECT_PATTERN.test(value.apparatusAnchor.commit) ||
    !GIT_OBJECT_PATTERN.test(value.apparatusAnchor.tree)
  ) {
    reject('precontract-git-anchor-invalid');
  }
  const rawSha256 = sha256(parsed.bytes);
  if (grant !== `${STUDY}:one-synthetic-attempt:sha256:${rawSha256}`) {
    reject('precontract-grant-invalid');
  }
  return {
    bytes: parsed.bytes,
    precontract: canonicalize(value),
    rawSha256,
  };
}

export function buildReservationBytes({ grant, precontractBytes } = {}) {
  const receipt = validatePrecontract(precontractBytes, grant);
  const reservation = {
    action: null,
    authority: 'none',
    branchId: 'launch-failure',
    grant,
    normative: false,
    precontract: receipt.precontract,
    precontractRawSha256: receipt.rawSha256,
    schemaVersion: RESERVATION_SCHEMA,
    stage: 'stage-0-durable-before-stage-1',
    study: STUDY,
    synthetic: true,
  };
  return {
    bytes: Buffer.from(canonicalPrettyJson(reservation), 'utf8'),
    precontract: receipt,
    reservation,
  };
}

function exactMode(metadata) {
  return (metadata.mode & 0o7777).toString(8).padStart(4, '0');
}

function assertOwned(metadata) {
  if (typeof process.getuid === 'function' && metadata.uid !== process.getuid()) {
    reject('filesystem-owner-invalid');
  }
}

function assertPrivateDirectory(directory) {
  const metadata = lstatSync(directory);
  if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
    reject('filesystem-directory-invalid');
  }
  if (exactMode(metadata) !== '0700') reject('filesystem-directory-mode-invalid');
  assertOwned(metadata);
  if (realpathSync(directory) !== path.resolve(directory)) {
    reject('filesystem-directory-rebound');
  }
}

function fsyncDirectory(directory) {
  const descriptor = openSync(
    directory,
    constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_DIRECTORY ?? 0)
  );
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
}

function writeAll(descriptor, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(descriptor, bytes, offset, bytes.length - offset);
    if (written <= 0) reject('filesystem-write-incomplete');
    offset += written;
  }
}

function writeExclusivePrivateFile(filePath, bytes, directory, { partialByteLength = null } = {}) {
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
  const selected =
    partialByteLength === null
      ? bytes
      : bytes.subarray(0, Math.min(partialByteLength, bytes.length));
  try {
    writeAll(descriptor, selected);
    fsyncSync(descriptor);
    const metadata = fstatSync(descriptor);
    if (!metadata.isFile() || metadata.nlink !== 1 || exactMode(metadata) !== '0600') {
      reject('filesystem-file-policy-invalid');
    }
    assertOwned(metadata);
  } finally {
    closeSync(descriptor);
  }
  fsyncDirectory(directory);
  if (partialByteLength !== null) {
    reject('synthetic-partial-write-injected', {
      expectedByteLength: bytes.length,
      observedByteLength: selected.length,
      observedRawSha256: sha256(selected),
      path: filePath,
    });
  }
}

function verifyStablePrivateFile(filePath, expectedBytes) {
  const lexical = lstatSync(filePath);
  if (
    lexical.isSymbolicLink() ||
    !lexical.isFile() ||
    lexical.nlink !== 1 ||
    exactMode(lexical) !== '0600'
  ) {
    reject('filesystem-file-policy-invalid');
  }
  assertOwned(lexical);
  const descriptor = openSync(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(descriptor);
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs ||
      before.ctimeMs !== after.ctimeMs
    ) {
      reject('filesystem-file-changed-during-read');
    }
    if (!bytes.equals(expectedBytes)) reject('filesystem-file-byte-drift');
  } finally {
    closeSync(descriptor);
  }
}

function createReservationDirectory(evidenceRoot, reservationRawSha256) {
  const root = path.resolve(evidenceRoot);
  assertPrivateDirectory(root);
  const directory = path.join(root, `reservation-${reservationRawSha256}`);
  try {
    mkdirSync(directory, { mode: 0o700 });
  } catch (error) {
    if (error?.code === 'EEXIST') reject('reservation-already-consumed');
    throw error;
  }
  assertPrivateDirectory(directory);
  fsyncDirectory(root);
  return directory;
}

function normalizeLaunchError(error) {
  if (
    error?.code !== 'SYNTHETIC_STAGE1_LAUNCH_FAILED' ||
    error?.syscall !== 'synthetic-stage1-launch'
  ) {
    reject('stage1-launch-error-invalid');
  }
  return {
    code: 'SYNTHETIC_STAGE1_LAUNCH_FAILED',
    syscall: 'synthetic-stage1-launch',
  };
}

function launchFailureTerminal(reservationBytes, precontractRawSha256, launchError) {
  const body = {
    action: null,
    attempts: [],
    authority: 'none',
    branchId: 'launch-failure',
    launchError,
    normative: false,
    precontractRawSha256,
    reservationRawSha256: sha256(reservationBytes),
    schemaVersion: TERMINAL_SCHEMA,
    study: STUDY,
    synthetic: true,
  };
  return {
    ...body,
    semanticSha256: canonicalHash(body),
  };
}

async function loadDefaultStage1() {
  return import('./stage1.mjs');
}

export async function materializePreAttemptBinding({
  evidenceRoot,
  grant,
  injectPartialByteLength = null,
  loadStage1 = loadDefaultStage1,
  precontractBytes,
} = {}) {
  if (typeof evidenceRoot !== 'string' || evidenceRoot.length === 0) {
    reject('evidence-root-invalid');
  }
  if (typeof loadStage1 !== 'function') reject('stage1-loader-invalid');
  if (
    injectPartialByteLength !== null &&
    (!Number.isSafeInteger(injectPartialByteLength) || injectPartialByteLength <= 0)
  ) {
    reject('partial-write-length-invalid');
  }
  const built = buildReservationBytes({ grant, precontractBytes });
  if (injectPartialByteLength !== null && injectPartialByteLength >= built.bytes.length) {
    reject('partial-write-length-invalid');
  }
  const reservationRawSha256 = sha256(built.bytes);
  const reservationDirectory = createReservationDirectory(evidenceRoot, reservationRawSha256);
  const reservationPath = path.join(reservationDirectory, 'reservation.json');
  writeExclusivePrivateFile(reservationPath, built.bytes, reservationDirectory, {
    partialByteLength: injectPartialByteLength,
  });
  verifyStablePrivateFile(reservationPath, built.bytes);
  fsyncDirectory(reservationDirectory);
  const events = ['reservation-durable'];

  verifyStablePrivateFile(reservationPath, built.bytes);
  let stage1;
  try {
    stage1 = await loadStage1();
  } catch (error) {
    reject('stage1-load-failed', {
      code: typeof error?.code === 'string' ? error.code : null,
    });
  }
  events.push('stage1-load');
  if (typeof stage1?.launchSyntheticStage1 !== 'function') {
    reject('stage1-entrypoint-invalid');
  }
  events.push('stage1-invoke');
  let observedLaunchError = null;
  try {
    await stage1.launchSyntheticStage1();
  } catch (error) {
    observedLaunchError = error;
  }
  if (observedLaunchError === null) reject('launch-failure-not-observed');
  const launchError = normalizeLaunchError(observedLaunchError);

  const terminal = launchFailureTerminal(built.bytes, built.precontract.rawSha256, launchError);
  const terminalBytes = Buffer.from(canonicalPrettyJson(terminal), 'utf8');
  const terminalRawSha256 = sha256(terminalBytes);
  const terminalPath = path.join(reservationDirectory, `terminal-${terminalRawSha256}.json`);
  writeExclusivePrivateFile(terminalPath, terminalBytes, reservationDirectory);
  verifyStablePrivateFile(terminalPath, terminalBytes);
  fsyncDirectory(reservationDirectory);

  return {
    branchId: 'launch-failure',
    events,
    reservationBytes: built.bytes,
    reservationDirectory,
    reservationPath,
    reservationRawSha256,
    terminal,
    terminalBytes,
    terminalPath,
    terminalRawSha256,
  };
}

export const stage0Constants = Object.freeze({
  branchId: 'launch-failure',
  controlId: 'partial-write',
  predecessorCommit: PREDECESSOR_COMMIT,
  predecessorTree: PREDECESSOR_TREE,
  sourceDescriptorCount: SOURCE_ROSTER.length,
  sourceRoster: SOURCE_ROSTER,
  study: STUDY,
});
