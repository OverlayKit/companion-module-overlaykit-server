import { createHash } from 'node:crypto';

const STUDY = 'NODE22-PRE-ATTEMPT-BINDING-PREFLIGHT-001';
const PRECONTRACT_SCHEMA = 'overlaykit-node22-pre-attempt-binding-preflight-precontract/v1';
const RESERVATION_SCHEMA = 'overlaykit-node22-pre-attempt-binding-preflight-reservation/v1';
const TERMINAL_SCHEMA = 'overlaykit-node22-pre-attempt-binding-preflight-terminal/v1';
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

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort(compareUtf8)
        .map((key) => [key, canonicalize(value[key])])
    );
  }
  return value;
}

function canonicalJson(value) {
  return JSON.stringify(canonicalize(value));
}

function canonicalPrettyJson(value) {
  return `${JSON.stringify(canonicalize(value), null, 2)}\n`;
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonicalHash(value) {
  return sha256(Buffer.from(canonicalJson(value), 'utf8'));
}

function makeSyntheticSourceDescriptors() {
  return SOURCE_ROSTER.map((sourcePath, index) => ({
    byteLength: 1000 + index,
    gitMode: '100644',
    gitOid: sha256(Buffer.from(`synthetic-git-blob:${sourcePath}`, 'utf8')).slice(0, 40),
    path: sourcePath,
    rawSha256: sha256(Buffer.from(`synthetic-source:${sourcePath}`, 'utf8')),
  }));
}

export function makeSyntheticPrecontract() {
  const descriptors = makeSyntheticSourceDescriptors();
  const subjectDescriptor = descriptors.find((descriptor) =>
    descriptor.path.endsWith('/subject-lock.json')
  );
  return {
    action: null,
    apparatusAnchor: {
      commit: 'a'.repeat(40),
      tree: 'b'.repeat(40),
    },
    authority: 'none',
    branchId: 'launch-failure',
    governanceBindings: {
      chg0042RawSha256: '3'.repeat(64),
      manifestContentHash: '4'.repeat(64),
      manifestRawSha256: '5'.repeat(64),
      planHash: 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4',
      planRawSha256: '2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243',
    },
    normative: false,
    predecessorAnchor: {
      commit: '1121f1dd86114da8560f31122743ae20f8d53b03',
      tree: '52bf8023a628d85683417bf67c42d7b7effcd912',
    },
    schemaVersion: PRECONTRACT_SCHEMA,
    sourceSet: {
      descriptorCount: descriptors.length,
      descriptors,
      sha256: canonicalHash(descriptors),
    },
    study: STUDY,
    subjectRawSha256: subjectDescriptor.rawSha256,
    synthetic: true,
  };
}

export function syntheticPrecontractBytes() {
  return Buffer.from(canonicalPrettyJson(makeSyntheticPrecontract()), 'utf8');
}

export function syntheticGrant() {
  const digest = sha256(syntheticPrecontractBytes());
  return `${STUDY}:one-synthetic-attempt:sha256:${digest}`;
}

export function makeSyntheticReservation() {
  const precontract = makeSyntheticPrecontract();
  const precontractBytes = syntheticPrecontractBytes();
  return {
    action: null,
    authority: 'none',
    branchId: 'launch-failure',
    grant: syntheticGrant(),
    normative: false,
    precontract,
    precontractRawSha256: sha256(precontractBytes),
    schemaVersion: RESERVATION_SCHEMA,
    stage: 'stage-0-durable-before-stage-1',
    study: STUDY,
    synthetic: true,
  };
}

export function syntheticReservationBytes() {
  return Buffer.from(canonicalPrettyJson(makeSyntheticReservation()), 'utf8');
}

export function makeSyntheticLaunchFailureTerminal() {
  const reservationBytes = syntheticReservationBytes();
  const body = {
    action: null,
    attempts: [],
    authority: 'none',
    branchId: 'launch-failure',
    launchError: {
      code: 'SYNTHETIC_STAGE1_LAUNCH_FAILED',
      syscall: 'synthetic-stage1-launch',
    },
    normative: false,
    precontractRawSha256: sha256(syntheticPrecontractBytes()),
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

export function syntheticLaunchFailureTerminalBytes() {
  return Buffer.from(canonicalPrettyJson(makeSyntheticLaunchFailureTerminal()), 'utf8');
}

export const syntheticPrecontractConstants = Object.freeze({
  branchId: 'launch-failure',
  descriptorCount: 10,
  predecessorCommit: '1121f1dd86114da8560f31122743ae20f8d53b03',
  predecessorTree: '52bf8023a628d85683417bf67c42d7b7effcd912',
  precontractRawSha256: sha256(syntheticPrecontractBytes()),
  reservationRawSha256: sha256(syntheticReservationBytes()),
  study: STUDY,
});
