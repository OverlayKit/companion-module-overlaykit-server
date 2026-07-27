#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

import { readTarGzipMembers } from '../h043/archive-lib.mjs';

const REPOSITORY_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SCHEMA_PATH = fileURLToPath(new URL('./schemas/live-run.schema.json', import.meta.url));
const H043_ARCHIVE_RELATIVE_PATH =
  'evidence/h043/64bf41f30dc2d51a2475e6f2e9b79ddebc225c076a87b83c384b3848b1bbecb8/' +
  'replay-fbe7e841a7319328b253e414f93abd3a17ab47506b783b652c6624aae3b68dec.tar.gz';
const H043_ARCHIVE_PATH = path.join(REPOSITORY_ROOT, H043_ARCHIVE_RELATIVE_PATH);
const H043_ARCHIVE_SHA256 = 'fbe7e841a7319328b253e414f93abd3a17ab47506b783b652c6624aae3b68dec';
const H043_EVIDENCE_SHA256 = '64bf41f30dc2d51a2475e6f2e9b79ddebc225c076a87b83c384b3848b1bbecb8';
const H043_RUN_SHA256 = '4a5754eddcd5672072d1ce0dc68c7a42694eafdc3eab5cddc4bf3e9ce5a57328';
const H043_VERIFICATION_SHA256 = 'f75726992c88d45b9d43bab3443005cdaed05464d303f05a8356e0ccecc81023';
const H043_CANDIDATE_TOKEN_SHA256 =
  '43f26fc54686331e1d6a4f06d827b92d1975cc1482b2cd2d1795f698a6deac06';
const H043_RUN_ID = 'h043-2026-07-26T22-13-38-193Z-b4158eab';
const H043_RUN_MEMBER_PATH = `artifacts/h043/${H043_RUN_ID}/run.json`;
const H043_VERIFICATION_MEMBER_PATH = `artifacts/h043/${H043_RUN_ID}/verification.json`;

const REPOSITORY = 'https://github.com/OverlayKit/companion-module-overlaykit-server.git';
const PROTECTED_MAIN_COMMIT = '6c329234caddf9e34126be04149f768673bdb8bf';
const SOURCE_CONTRACT_COMMIT = '9e2156e7ddc38ebe223824a07f682421b7ee0589';
const PLAN_HASH = 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4';
const MANIFEST_CONTENT_HASH = 'b36032589f0d652ceffd6aafee502e551b4f86779149be4b9ac1c38636a17013';
const CHG_0016_SHA256 = 'b8ea5a54c666047c7c44e322b21bc5f24836d172b4712c7483507bc2d4739ae6';
const CHG_0017_SHA256 = '858fcc7fde8bf6abd73e58f56224c3eae238ecf46ae70e92aca92f886937e576';
const ADR_0006_SHA256 = '619fbfe60cc8c4c298c6c1eaaa25825b514b1d36bc0b8ec6588d4c3718b9f360';

const DOCKER_UNIX_HOST = 'unix:///var/run/docker.sock';
const DOCKER_HOST_PREFIX = Object.freeze(['--host', DOCKER_UNIX_HOST]);
const DOCKER_VERSION_FORMAT =
  '{"Client":{"Version":{{json .Client.Version}},' +
  '"ApiVersion":{{json .Client.APIVersion}}},' +
  '"Server":{"Version":{{json .Server.Version}},' +
  '"ApiVersion":{{json .Server.APIVersion}}}}';
const DOCKER_PS_FORMAT = '{"ID":{{json .ID}},"State":{{json .State}}}';
const DOCKER_INSPECT_FORMAT =
  '{"Id":{{json .Id}},"Image":{{json .Image}},"State":{' +
  '"Status":{{json .State.Status}},"Running":{{json .State.Running}},' +
  '"Pid":{{json .State.Pid}},"StartedAt":{{json .State.StartedAt}}},' +
  '"RestartCount":{{json .RestartCount}},"CgroupnsMode":{{json .HostConfig.CgroupnsMode}}}';
const MAX_EXPOSURE_NS = 5_000_000_000n;
const COMMAND_MAX_BUFFER_BYTES = 8 * 1024 * 1024;
const COMMAND_TIMEOUT_MS = 1_500;
const SHA256_PATTERN = /^[0-9a-f]{64}$/u;
const MONOTONIC_PATTERN = /^(?:0|[1-9][0-9]*)$/u;
const DATE_TIME_PATTERN =
  /^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]{1,9})?Z$/u;
const CONTAINER_ID_PATTERN = /^[0-9a-f]{64}$/u;

export const INDEPENDENT_REQUIRED_SOURCE_PATHS = Object.freeze(
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

export const INDEPENDENT_PREDICATE_KEYS = Object.freeze([
  'sourceAdmissionExact',
  'auditExact',
  'framesComplete',
  'frameOrderExact',
  'exposureBounded',
  'hostStable',
  'deviceExact',
  'lifecycleExact',
  'pid1Exact',
  'workerUnique',
  'workerExact',
  'descriptorAbsent',
  'markersStable',
]);

const ALLOWED_PROCESS_KEYS = Object.freeze([
  'git',
  'lsusb',
  'dockerVersion',
  'dockerPs',
  'dockerInspect',
  'dockerLogs',
]);
const PROHIBITED_COUNT_KEYS = Object.freeze([
  'externalNetwork',
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
const FILESYSTEM_OPERATIONS = Object.freeze([
  'readFileSync',
  'readdirSync',
  'realpathSync',
  'statSync',
  'lstatSync',
  'readlinkSync',
]);

export const INDEPENDENT_CASE_IDS = Object.freeze([
  'pid-reuse',
  'worker-ambiguity',
  'parent-drift',
  'namespace-drift',
  'container-drift',
  'pid1-drift',
  'device-absence',
  'device-epoch-drift',
  'descriptor-recovery',
  'marker-change',
  'frame-reorder',
  'exposure-over-limit',
  'missing-command-audit',
  'duplicate-receipts',
  'input-tampering',
  'prohibited-capability',
]);

// This literal is intentionally not imported from the producer. It is filled by
// the accepted CHG-0017 claim boundary and triple-locked by verifier tests.
export const INDEPENDENT_CLAIM_BOUNDARY = Object.freeze({
  proves: Object.freeze([
    'one capability-bounded read-only observation of the exact accepted H-043 candidate on one authorized post-login Linux host',
    'two adjacent complete frames no more than 5000 milliseconds apart with exact current device, Docker lifecycle, PID 1, SurfaceThread, descriptor, and serial-marker receipts',
    'one cutoff-bound authority-void revalidation receipt only when every historical and live identity matches, or zero receipts with withheld for complete non-eligibility',
    'fail-closed inconclusive classification for incomplete, ambiguous, contradictory, inaccessible, drifting, or unaudited evidence',
    'exact audited cardinality of allowed local Git, lsusb, Docker Unix-socket, and filesystem metadata observations with zero prohibited capabilities',
  ]),
  excludes: Object.freeze([
    'validity after the second-frame cutoff, atomicity, race freedom, PID-reuse-safe action, or a closed check-action interval',
    'authorization or safety of SIGTERM or any other signal, command, restart, rescan, retry, or executable action',
    'a watcher, controller, supervisor, systemd or udev unit, production policy, installation, publication, or release',
    'physical disconnect or reconnect, a new USB epoch, hidraw open or I/O, Docker lifecycle mutation, namespace entry, or configuration change',
    'button delivery, OverlayKit configuration continuity, rendered pixels, operator perception, OBS truth, or product acceptance',
    'security, acceptable downtime, multiple-device behavior, pre-login behavior, reboot recovery, or long-outage recovery',
    'an expansion or satisfaction of accepted SPEC-0001 or SPEC-0002',
    'a successor ADR or architectural authority beyond ADR-0006',
  ]),
});

const HISTORICAL_CANDIDATE_KEYS = Object.freeze([
  'kind',
  'historical',
  'requiresRevalidation',
  'authority',
  'action',
  'observedCutoff',
  'sourceEvidenceSha256',
  'prefixSha256',
  'identity',
  'window',
  'tokenSha256',
]);
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
  'containerObservation',
  'lifecycle',
  'pid1',
  'workers',
  'descriptors',
  'markers',
  'absence',
  'auditBinding',
  'digestSha256',
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

function assertion(condition, message) {
  if (!condition) throw new Error(`H-044 verification failed: ${message}`);
}

function clone(value) {
  return structuredClone(value);
}

function plainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, keys) {
  return (
    plainObject(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
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

function same(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function sha256Text(value) {
  return typeof value === 'string' && SHA256_PATTERN.test(value);
}

function nonNegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function positiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function scalarString(value) {
  return typeof value === 'string' && value.length > 0 && !value.includes('\u0000');
}

function monotonic(value) {
  if (typeof value !== 'string' || !MONOTONIC_PATTERN.test(value)) {
    throw new TypeError('invalid monotonic nanosecond value');
  }
  return BigInt(value);
}

function validCalendarDate(value) {
  const match = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T/u.exec(value);
  if (match === null) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (month < 1 || month > 12 || day < 1) return false;
  return day <= new Date(Date.UTC(year, month, 0)).getUTCDate();
}

function validTimestamp(value) {
  return typeof value === 'string' && DATE_TIME_PATTERN.test(value) && validRfc3339(value);
}

function lineCount(text) {
  if (text === '') return 0;
  const withoutFinalNewline = text.endsWith('\n') ? text.slice(0, -1) : text;
  return withoutFinalNewline === '' ? 0 : withoutFinalNewline.split('\n').length;
}

function member(members, memberPath) {
  const value = members.get(memberPath);
  assertion(value !== undefined, `H-043 archive is missing ${memberPath}`);
  return value;
}

async function collectSourceReceipts() {
  return Promise.all(
    INDEPENDENT_REQUIRED_SOURCE_PATHS.map(async (sourcePath) => ({
      path: sourcePath,
      sha256: sha256(await readFile(path.join(REPOSITORY_ROOT, sourcePath))),
    }))
  );
}

function exactStat(value) {
  return (
    exactKeys(value, STAT_KEYS) &&
    scalarString(value.stDev) &&
    scalarString(value.inode) &&
    MONOTONIC_PATTERN.test(value.ctimeNs) &&
    scalarString(value.mode) &&
    nonNegativeInteger(value.uid) &&
    nonNegativeInteger(value.gid) &&
    scalarString(value.rdev) &&
    scalarString(value.rdevHex) &&
    nonNegativeInteger(value.major) &&
    nonNegativeInteger(value.minor) &&
    typeof value.isCharacterDevice === 'boolean'
  );
}

function exactEpoch(value) {
  return (
    exactKeys(value, EPOCH_KEYS) &&
    scalarString(value.serial) &&
    scalarString(value.busNumber) &&
    scalarString(value.deviceNumber) &&
    scalarString(value.usbDevicePath) &&
    scalarString(value.usbDev) &&
    scalarString(value.hidDevicePath) &&
    /^\/(?:dev|host-dev)\/hidraw(?:0|[1-9][0-9]*)$/u.test(value.devicePath) &&
    exactStat(value.stat)
  );
}

function exactLifecycle(value) {
  return (
    exactKeys(value, LIFECYCLE_KEYS) &&
    CONTAINER_ID_PATTERN.test(value.containerId) &&
    /^sha256:[0-9a-f]{64}$/u.test(value.imageId) &&
    validTimestamp(value.startedAt) &&
    nonNegativeInteger(value.restartCount) &&
    positiveInteger(value.hostPid) &&
    positiveInteger(value.pid1StartTicks) &&
    scalarString(value.pidNamespace) &&
    scalarString(value.mountNamespace) &&
    scalarString(value.cgroup) &&
    scalarString(value.hostCgroup) &&
    scalarString(value.cgroupNamespaceMode)
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
    scalarString(value.cgroup) &&
    scalarString(value.pidNamespace) &&
    scalarString(value.mountNamespace)
  );
}

function exactHistoricalCandidate(candidate) {
  if (
    !exactKeys(candidate, HISTORICAL_CANDIDATE_KEYS) ||
    candidate.kind !== 'revalidation-required' ||
    candidate.historical !== true ||
    candidate.requiresRevalidation !== true ||
    candidate.authority !== 'none' ||
    candidate.action !== null ||
    !exactKeys(candidate.observedCutoff, ['at', 'monotonicNs']) ||
    !validTimestamp(candidate.observedCutoff.at) ||
    !MONOTONIC_PATTERN.test(candidate.observedCutoff.monotonicNs) ||
    !sha256Text(candidate.sourceEvidenceSha256) ||
    !sha256Text(candidate.prefixSha256) ||
    !exactKeys(candidate.identity, ['device', 'lifecycle', 'worker']) ||
    !exactKeys(candidate.identity.device, [
      'serial',
      'vendorId',
      'productId',
      'initialEpoch',
      'returnedEpoch',
      'revalidationEpoch',
    ]) ||
    !scalarString(candidate.identity.device.serial) ||
    candidate.identity.device.vendorId !== '0fd9' ||
    candidate.identity.device.productId !== '0080' ||
    !exactEpoch(candidate.identity.device.initialEpoch) ||
    !exactEpoch(candidate.identity.device.returnedEpoch) ||
    !exactEpoch(candidate.identity.device.revalidationEpoch) ||
    !exactLifecycle(candidate.identity.lifecycle) ||
    !exactWorker(candidate.identity.worker) ||
    !plainObject(candidate.window) ||
    Object.keys(candidate.window).length === 0 ||
    !Object.values(candidate.window).every(
      (value) => typeof value === 'string' && MONOTONIC_PATTERN.test(value)
    ) ||
    !sha256Text(candidate.tokenSha256)
  ) {
    return false;
  }

  const expectedToken = sha256Canonical({
    schemaVersion: 'overlaykit-h043-candidate-token/v1',
    sourceEvidenceSha256: candidate.sourceEvidenceSha256,
    prefixSha256: candidate.prefixSha256,
    device: candidate.identity.device,
    lifecycle: candidate.identity.lifecycle,
    worker: candidate.identity.worker,
    window: candidate.window,
  });
  return candidate.tokenSha256 === expectedToken;
}

function admitHistoricalArchive(archiveBytes) {
  assertion(sha256(archiveBytes) === H043_ARCHIVE_SHA256, 'accepted H-043 archive hash mismatch');
  assertion(archiveBytes.byteLength === 389_084, 'accepted H-043 archive length mismatch');
  const members = readTarGzipMembers(archiveBytes);
  assertion(members.size === 21, 'accepted H-043 archive member count mismatch');
  const runBytes = member(members, H043_RUN_MEMBER_PATH);
  const verificationBytes = member(members, H043_VERIFICATION_MEMBER_PATH);
  assertion(sha256(runBytes) === H043_RUN_SHA256, 'accepted H-043 run hash mismatch');
  assertion(
    sha256(verificationBytes) === H043_VERIFICATION_SHA256,
    'accepted H-043 verification hash mismatch'
  );

  const run = JSON.parse(runBytes.toString('utf8'));
  const verification = JSON.parse(verificationBytes.toString('utf8'));
  const { evidenceSha256, ...record } = run;
  assertion(sha256Canonical(record) === evidenceSha256, 'accepted H-043 evidence hash mismatch');
  assertion(
    run.schemaVersion === 'overlaykit-h043-offline-worker-eligibility-run/v1' &&
      run.hypothesis === 'H-043' &&
      run.runId === H043_RUN_ID &&
      run.evidenceSha256 === H043_EVIDENCE_SHA256 &&
      run.outcome?.status === 'supported' &&
      run.outcome.stage === 'offline-worker-eligibility' &&
      run.outcome.reasonCode === 'canonical-candidate-and-hostile-matrix-exact',
    'accepted H-043 run lineage mismatch'
  );
  assertion(
    verification.schemaVersion === 'overlaykit-h043-verification/v1' &&
      verification.hypothesis === 'H-043' &&
      verification.runId === H043_RUN_ID &&
      verification.evidenceSha256 === H043_EVIDENCE_SHA256 &&
      verification.outcome === 'supported' &&
      verification.stage === 'offline-worker-eligibility' &&
      verification.verified === true,
    'accepted H-043 verification lineage mismatch'
  );
  assertion(
    run.canonicalClassification?.disposition === 'candidate' &&
      run.canonicalClassification.stage === 'historical-worker-candidate' &&
      run.canonicalClassification.reasonCode === 'revalidation-required-worker-candidate' &&
      run.canonicalClassification.candidates?.length === 1,
    'accepted H-043 candidate cardinality mismatch'
  );
  const candidate = run.canonicalClassification.candidates[0];
  assertion(exactHistoricalCandidate(candidate), 'accepted H-043 candidate shape mismatch');
  assertion(
    candidate.tokenSha256 === H043_CANDIDATE_TOKEN_SHA256,
    'accepted H-043 candidate token mismatch'
  );
  return { run, verification, candidate };
}

function rfc3339EpochNs(value) {
  const match =
    typeof value === 'string'
      ? /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(Z|([+-])([0-9]{2}):([0-9]{2}))$/u.exec(
          value
        )
      : null;
  if (match === null || !validCalendarDate(value)) {
    throw new TypeError('invalid RFC3339 timestamp');
  }
  const [
    ,
    year,
    month,
    day,
    hour,
    minute,
    second,
    fraction = '',
    zone,
    sign,
    zoneHour,
    zoneMinute,
  ] = match;
  if (
    Number(hour) > 23 ||
    Number(minute) > 59 ||
    Number(second) > 59 ||
    (zone !== 'Z' && (Number(zoneHour) > 23 || Number(zoneMinute) > 59))
  ) {
    throw new TypeError('invalid RFC3339 timestamp');
  }
  const localMilliseconds = Date.UTC(
    Number(year),
    Number(month) - 1,
    Number(day),
    Number(hour),
    Number(minute),
    Number(second)
  );
  const offsetMinutes =
    zone === 'Z' ? 0 : (sign === '+' ? 1 : -1) * (Number(zoneHour) * 60 + Number(zoneMinute));
  return (
    BigInt(localMilliseconds - offsetMinutes * 60_000) * 1_000_000n +
    BigInt(fraction.padEnd(9, '0') || '0')
  );
}

function validRfc3339(value) {
  try {
    rfc3339EpochNs(value);
    return true;
  } catch {
    return false;
  }
}

function commandKind(executable, args, run) {
  if (!Array.isArray(args) || args.some((entry) => typeof entry !== 'string')) return null;
  const targetContainerId = run?.historicalCandidate?.identity?.lifecycle?.containerId ?? null;
  const logSince = run?.historicalCandidate?.identity?.lifecycle?.startedAt ?? null;
  if (executable === 'lsusb' && args.length === 0) return 'lsusb';
  if (executable === 'git') {
    if (same(args, ['rev-parse', 'HEAD'])) return 'git';
    if (same(args, ['remote', 'get-url', 'origin'])) return 'git';
    if (
      args.length === 4 &&
      args[0] === 'merge-base' &&
      args[1] === '--is-ancestor' &&
      args[2] === PROTECTED_MAIN_COMMIT &&
      args[3] === 'HEAD'
    ) {
      return 'git';
    }
    return null;
  }
  if (executable !== 'docker') return null;
  if (args[0] !== DOCKER_HOST_PREFIX[0] || args[1] !== DOCKER_HOST_PREFIX[1]) {
    return null;
  }
  const dockerArgs = args.slice(DOCKER_HOST_PREFIX.length);
  if (same(dockerArgs, ['version', '--format', DOCKER_VERSION_FORMAT])) {
    return 'dockerVersion';
  }
  if (
    targetContainerId !== null &&
    same(dockerArgs, [
      'ps',
      '--all',
      '--no-trunc',
      '--filter',
      `id=${targetContainerId}`,
      '--format',
      DOCKER_PS_FORMAT,
    ])
  ) {
    return 'dockerPs';
  }
  if (
    dockerArgs.length === 4 &&
    dockerArgs[0] === 'inspect' &&
    dockerArgs[1] === '--format' &&
    dockerArgs[2] === DOCKER_INSPECT_FORMAT &&
    dockerArgs[3] === targetContainerId
  ) {
    return 'dockerInspect';
  }
  if (
    dockerArgs.length === 7 &&
    dockerArgs[0] === 'logs' &&
    dockerArgs[1] === '--timestamps' &&
    dockerArgs[2] === '--since' &&
    validRfc3339(dockerArgs[3]) &&
    dockerArgs[3] === logSince &&
    dockerArgs[4] === '--until' &&
    validRfc3339(dockerArgs[5]) &&
    rfc3339EpochNs(dockerArgs[3]) <= rfc3339EpochNs(dockerArgs[5]) &&
    dockerArgs[6] === targetContainerId
  ) {
    return 'dockerLogs';
  }
  return null;
}

function exactOutputReceipt(value) {
  if (
    !exactKeys(value, ['encoding', 'text', 'base64', 'byteLength', 'lineCount', 'sha256']) ||
    !['utf8', 'base64'].includes(value.encoding) ||
    typeof value.base64 !== 'string' ||
    !nonNegativeInteger(value.byteLength) ||
    !sha256Text(value.sha256)
  ) {
    return false;
  }
  const bytes = Buffer.from(value.base64, 'base64');
  if (bytes.toString('base64') !== value.base64) return false;
  const decoded = bytes.toString('utf8');
  const utf8Exact = Buffer.from(decoded, 'utf8').equals(bytes);
  return (
    value.byteLength === bytes.byteLength &&
    value.sha256 === sha256(bytes) &&
    (utf8Exact
      ? value.encoding === 'utf8' &&
        value.text === decoded &&
        value.lineCount === lineCount(decoded)
      : value.encoding === 'base64' && value.text === null && value.lineCount === null)
  );
}

function commandReceiptExact(receipt, index, perObserverKind, run) {
  const observerKind = receipt?.observerKind ?? receipt?.kind;
  const receiptKeys =
    receipt?.kind === 'git'
      ? [
          'index',
          'kind',
          'observerKind',
          'ordinal',
          'executable',
          'args',
          'startedAt',
          'endedAt',
          'startedMonotonicNs',
          'endedMonotonicNs',
          'durationNs',
          'limits',
          'exitCode',
          'signal',
          'stdout',
          'stderr',
          'cardinality',
          'errorCode',
        ]
      : [
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
          'exitCode',
          'signal',
          'stdout',
          'stderr',
          'cardinality',
          'errorCode',
        ];
  if (
    !exactKeys(receipt, receiptKeys) ||
    receipt.index !== index ||
    !ALLOWED_PROCESS_KEYS.includes(receipt.kind) ||
    (receipt.kind === 'git' &&
      !['gitRevParse', 'gitMergeBaseAncestor', 'gitRemoteGetUrl'].includes(receipt.observerKind)) ||
    !positiveInteger(receipt.ordinal) ||
    !scalarString(receipt.executable) ||
    !Array.isArray(receipt.args) ||
    receipt.args.some((entry) => typeof entry !== 'string') ||
    commandKind(receipt.executable, receipt.args, run) !== receipt.kind ||
    !validTimestamp(receipt.startedAt) ||
    !validTimestamp(receipt.endedAt) ||
    rfc3339EpochNs(receipt.startedAt) < rfc3339EpochNs(run.startedAt) ||
    rfc3339EpochNs(receipt.endedAt) > rfc3339EpochNs(run.completedAt) ||
    rfc3339EpochNs(receipt.endedAt) < rfc3339EpochNs(receipt.startedAt) ||
    !MONOTONIC_PATTERN.test(receipt.startedMonotonicNs) ||
    !MONOTONIC_PATTERN.test(receipt.endedMonotonicNs) ||
    !MONOTONIC_PATTERN.test(receipt.durationNs) ||
    !exactKeys(receipt.limits, ['maxBufferBytes', 'timeoutMs']) ||
    receipt.limits.maxBufferBytes !== COMMAND_MAX_BUFFER_BYTES ||
    receipt.limits.timeoutMs !== COMMAND_TIMEOUT_MS ||
    receipt.exitCode !== 0 ||
    receipt.signal !== null ||
    receipt.errorCode !== null ||
    !exactOutputReceipt(receipt.stdout) ||
    !exactOutputReceipt(receipt.stderr) ||
    !exactKeys(receipt.cardinality, ['global', 'kind']) ||
    receipt.cardinality.global !== index + 1
  ) {
    return false;
  }
  const started = monotonic(receipt.startedMonotonicNs);
  const ended = monotonic(receipt.endedMonotonicNs);
  const expectedOrdinal = (perObserverKind[observerKind] ?? 0) + 1;
  return (
    ended >= started &&
    monotonic(receipt.durationNs) === ended - started &&
    receipt.ordinal === expectedOrdinal &&
    receipt.cardinality.kind === expectedOrdinal
  );
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function parseDockerPs(text) {
  if (text === '') return [];
  const rows = [];
  const seen = new Set();
  for (const line of text.split(/\r?\n/u).filter(Boolean)) {
    const entry = parseJson(line);
    if (!exactKeys(entry, ['ID', 'State'])) return null;
    const containerId = entry.ID;
    if (
      !CONTAINER_ID_PATTERN.test(containerId ?? '') ||
      !scalarString(entry.State) ||
      seen.has(containerId)
    ) {
      return null;
    }
    seen.add(containerId);
    rows.push({
      containerId,
      state: entry.State.toLowerCase(),
    });
  }
  return rows;
}

function parseDockerInspect(text) {
  const entry = parseJson(text.trim());
  if (
    !plainObject(entry) ||
    !exactKeys(entry, ['Id', 'Image', 'State', 'RestartCount', 'CgroupnsMode']) ||
    !plainObject(entry.State) ||
    !exactKeys(entry.State, ['Status', 'Running', 'Pid', 'StartedAt']) ||
    !scalarString(entry.State.Status) ||
    typeof entry.State.Running !== 'boolean' ||
    !CONTAINER_ID_PATTERN.test(entry.Id ?? '') ||
    !/^sha256:[0-9a-f]{64}$/u.test(entry.Image ?? '') ||
    !validRfc3339(entry.State.StartedAt) ||
    !positiveInteger(entry.State.Pid) ||
    !nonNegativeInteger(entry.RestartCount) ||
    !scalarString(entry.CgroupnsMode)
  ) {
    return null;
  }
  return {
    containerId: entry.Id,
    imageId: entry.Image,
    running: entry.State.Running === true,
    status: entry.State.Status,
    startedAt: entry.State.StartedAt,
    hostPid: entry.State.Pid,
    restartCount: entry.RestartCount,
    cgroupNamespaceMode: entry.CgroupnsMode,
  };
}

function markerKind(line, serial) {
  for (const [kind, marker] of [
    ['opening', `Opening surface panel: streamdeck:${serial}`],
    ['ready', `Surface panel ready: streamdeck:${serial}`],
  ]) {
    const markerIndex = line.indexOf(marker);
    if (
      markerIndex !== -1 &&
      (markerIndex + marker.length === line.length || /\s/u.test(line[markerIndex + marker.length]))
    ) {
      return kind;
    }
  }
  return null;
}

function parseDockerLogMarkers(stdout, stderr, serial, since, until) {
  let sinceNs;
  let untilNs;
  try {
    sinceNs = rfc3339EpochNs(since);
    untilNs = rfc3339EpochNs(until);
  } catch {
    return null;
  }
  if (sinceNs > untilNs) return null;
  const entries = [];
  for (const [stream, text] of [
    ['stdout', stdout],
    ['stderr', stderr],
  ]) {
    for (const line of text.split(/\r?\n/u).filter(Boolean)) {
      const separator = line.indexOf(' ');
      if (separator <= 0) return null;
      const at = line.slice(0, separator);
      if (!validRfc3339(at)) return null;
      const atNs = rfc3339EpochNs(at);
      if (atNs < sinceNs || atNs > untilNs) return null;
      entries.push({ at, stream, line: line.slice(separator + 1), atNs });
    }
  }
  entries.sort(
    (left, right) =>
      (left.atNs < right.atNs ? -1 : left.atNs > right.atNs ? 1 : 0) ||
      left.at.localeCompare(right.at) ||
      left.stream.localeCompare(right.stream) ||
      left.line.localeCompare(right.line)
  );
  const relevant = entries.filter((entry) => markerKind(entry.line, serial) !== null);
  return {
    opening: relevant.filter((entry) => markerKind(entry.line, serial) === 'opening').length,
    ready: relevant.filter((entry) => markerKind(entry.line, serial) === 'ready').length,
    relevantLinesSha256: sha256Canonical(relevant.map(({ atNs: _atNs, ...entry }) => entry)),
  };
}

function lsusbRows(text) {
  const rows = [];
  const seen = new Set();
  for (const line of text.split(/\r?\n/u).filter(Boolean)) {
    const match =
      /^Bus ([0-9]{3}) Device ([0-9]{3}): ID ([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4})(?: .*)?$/u.exec(
        line
      );
    if (match === null) return null;
    const row = {
      busNumber: BigInt(match[1]).toString(),
      deviceNumber: BigInt(match[2]).toString(),
      vendorId: match[3].toLowerCase(),
      productId: match[4].toLowerCase(),
    };
    const key = `${row.busNumber}:${row.deviceNumber}`;
    if (seen.has(key)) return null;
    seen.add(key);
    rows.push(row);
  }
  return rows;
}

function dockerSubcommandArgs(receipt) {
  return receipt?.executable === 'docker' &&
    Array.isArray(receipt.args) &&
    receipt.args[0] === DOCKER_HOST_PREFIX[0] &&
    receipt.args[1] === DOCKER_HOST_PREFIX[1]
    ? receipt.args.slice(DOCKER_HOST_PREFIX.length)
    : null;
}

function commandOutputsExact(receipts, run) {
  const gitReceipts = receipts.filter((receipt) => receipt.kind === 'git');
  if (
    gitReceipts.length !== 3 ||
    gitReceipts[0].stdout.text.trim() !== SOURCE_CONTRACT_COMMIT ||
    gitReceipts[1].stdout.text !== '' ||
    gitReceipts[2].stdout.text.trim() !== REPOSITORY
  ) {
    return false;
  }
  const lsusbReceipt = receipts.find((receipt) => receipt.kind === 'lsusb');
  const usbRows = lsusbRows(lsusbReceipt?.stdout?.text ?? '');
  if (usbRows === null) return false;
  for (const frame of run.frames) {
    const targetRows = usbRows.filter(
      (row) =>
        row.vendorId === run.historicalCandidate.identity.device.vendorId &&
        row.productId === run.historicalCandidate.identity.device.productId
    );
    if (
      frame.device.present === true &&
      (targetRows.length !== 1 ||
        !targetRows.some(
          (row) =>
            row.vendorId === frame.device.identity.vendorId &&
            row.productId === frame.device.identity.productId &&
            row.busNumber === BigInt(frame.device.identity.epoch.busNumber).toString() &&
            row.deviceNumber === BigInt(frame.device.identity.epoch.deviceNumber).toString()
        ))
    ) {
      return false;
    }
    if (frame.device.present === false && targetRows.length !== 0) {
      return false;
    }
  }

  const dockerVersion = receipts.find((receipt) => receipt.kind === 'dockerVersion');
  const version = parseJson(dockerVersion?.stdout?.text?.trim() ?? '');
  if (
    !exactKeys(version, ['Client', 'Server']) ||
    !exactKeys(version.Client, ['Version', 'ApiVersion']) ||
    !exactKeys(version.Server, ['Version', 'ApiVersion'])
  ) {
    return false;
  }
  if (
    ![
      version.Client.Version,
      version.Client.ApiVersion,
      version.Server.Version,
      version.Server.ApiVersion,
    ].every(scalarString)
  ) {
    return false;
  }

  const psReceipts = receipts.filter((receipt) => receipt.kind === 'dockerPs');
  const inspectReceipts = receipts.filter((receipt) => receipt.kind === 'dockerInspect');
  const logReceipts = receipts.filter((receipt) => receipt.kind === 'dockerLogs');
  let inspectIndex = 0;
  let logIndex = 0;
  const targetId = run.historicalCandidate.identity.lifecycle.containerId;
  for (let index = 0; index < run.frames.length; index += 1) {
    const frame = run.frames[index];
    const ps = parseDockerPs(psReceipts[index]?.stdout?.text ?? '');
    if (ps === null || ps.length > 1 || ps.some((entry) => entry.containerId !== targetId)) {
      return false;
    }
    const target = ps.find((entry) => entry.containerId === targetId) ?? null;
    const containerObservation = {
      present: target !== null,
      state: target?.state ?? null,
      exact: true,
    };
    if (
      !same(frame.containerObservation, containerObservation) ||
      frame.absence.historicalContainerAbsent !== (target === null) ||
      frame.absence.exact !== true
    ) {
      return false;
    }
    if (frame.lifecycle === null) {
      if (target !== null && target.state === 'running') return false;
      if (
        frame.markers.opening !== 0 ||
        frame.markers.ready !== 0 ||
        frame.markers.relevantLinesSha256 !== sha256Canonical([])
      ) {
        return false;
      }
      continue;
    }
    if (target?.state !== 'running') return false;
    const inspectReceipt = inspectReceipts[inspectIndex];
    const logReceipt = logReceipts[logIndex];
    const inspectArgs = dockerSubcommandArgs(inspectReceipt);
    const logArgs = dockerSubcommandArgs(logReceipt);
    inspectIndex += 1;
    logIndex += 1;
    if (
      inspectArgs?.at(-1) !== targetId ||
      logArgs?.at(-1) !== targetId ||
      logArgs[5] !== frame.observationCutoff.at
    ) {
      return false;
    }
    const inspect = parseDockerInspect(inspectReceipt.stdout.text);
    if (
      inspect === null ||
      inspect.containerId !== frame.lifecycle.containerId ||
      inspect.imageId !== frame.lifecycle.imageId ||
      inspect.running !== true ||
      inspect.status.toLowerCase() !== 'running' ||
      inspect.startedAt !== frame.lifecycle.startedAt ||
      inspect.hostPid !== frame.lifecycle.hostPid ||
      inspect.restartCount !== frame.lifecycle.restartCount ||
      inspect.cgroupNamespaceMode !== frame.lifecycle.cgroupNamespaceMode
    ) {
      return false;
    }
    const markers = parseDockerLogMarkers(
      logReceipt.stdout.text,
      logReceipt.stderr.text,
      run.historicalCandidate.identity.device.serial,
      logArgs[3],
      logArgs[5]
    );
    if (!same(markers, frame.markers)) return false;
  }
  return inspectIndex === inspectReceipts.length && logIndex === logReceipts.length;
}

function expectedCommandSequence(run) {
  const result = ['git', 'git', 'git', 'lsusb', 'dockerVersion'];
  for (const frame of run.frames) {
    result.push('dockerPs');
    if (frame.containerObservation?.state === 'running') {
      result.push('dockerInspect', 'dockerLogs');
    }
  }
  return result;
}

function verifyCommandAudit(audit, run) {
  const receipts = Array.isArray(audit?.commandReceipts) ? audit.commandReceipts : [];
  const prohibited = receipts.some(
    (receipt) => commandKind(receipt?.executable, receipt?.args, run) === null
  );
  try {
    if (!Array.isArray(audit?.commandReceipts)) {
      return { exact: false, prohibited: false, counts: null };
    }
    const counts = Object.fromEntries(ALLOWED_PROCESS_KEYS.map((key) => [key, 0]));
    const observerCounts = {};
    let previousEnd = null;
    let exact = true;
    for (let index = 0; index < receipts.length; index += 1) {
      const receipt = receipts[index];
      if (!commandReceiptExact(receipt, index, observerCounts, run)) exact = false;
      if (!ALLOWED_PROCESS_KEYS.includes(receipt?.kind)) {
        exact = false;
        continue;
      }
      counts[receipt.kind] += 1;
      const observerKind = receipt.observerKind ?? receipt.kind;
      observerCounts[observerKind] = (observerCounts[observerKind] ?? 0) + 1;
      if (MONOTONIC_PATTERN.test(receipt.startedMonotonicNs ?? '')) {
        const started = monotonic(receipt.startedMonotonicNs);
        if (previousEnd !== null && started < previousEnd) exact = false;
      }
      if (MONOTONIC_PATTERN.test(receipt.endedMonotonicNs ?? '')) {
        previousEnd = monotonic(receipt.endedMonotonicNs);
      }
    }
    const expectedSequence = expectedCommandSequence(run);
    exact &&= same(
      receipts.map((receipt) => receipt.kind),
      expectedSequence
    );
    exact &&= counts.git === 3;
    exact &&= counts.lsusb === 1;
    exact &&= counts.dockerVersion === 1;
    exact &&= counts.dockerPs === 2;
    exact &&=
      counts.dockerInspect ===
      run.frames.filter((frame) => frame.containerObservation?.state === 'running').length;
    exact &&= counts.dockerLogs === counts.dockerInspect;
    exact &&= commandOutputsExact(receipts, run);
    return {
      exact,
      prohibited,
      counts,
    };
  } catch {
    return { exact: false, prohibited, counts: null };
  }
}

function filesystemPathAllowed(operation, targetPath) {
  if (
    !FILESYSTEM_OPERATIONS.includes(operation) ||
    typeof targetPath !== 'string' ||
    !path.posix.isAbsolute(targetPath) ||
    path.posix.normalize(targetPath) !== targetPath
  ) {
    return false;
  }
  const ordinaryRoot =
    targetPath === '/etc' ||
    targetPath.startsWith('/etc/') ||
    targetPath === '/proc' ||
    targetPath.startsWith('/proc/') ||
    targetPath === '/sys' ||
    targetPath.startsWith('/sys/');
  const hidrawMetadata =
    ['statSync', 'lstatSync', 'readlinkSync'].includes(operation) &&
    /^\/(?:dev|host-dev)\/hidraw(?:0|[1-9][0-9]*)$/u.test(targetPath);
  return ordinaryRoot || hidrawMetadata;
}

function exactFilesystemResult(receipt) {
  const result = receipt.result;
  if (
    !plainObject(result) ||
    !nonNegativeInteger(result.cardinality) ||
    !sha256Text(result.sha256)
  ) {
    return false;
  }
  if (receipt.disposition !== 'observed') {
    return (
      exactKeys(result, ['cardinality', 'sha256']) &&
      result.cardinality === 0 &&
      result.sha256 === sha256(Buffer.alloc(0))
    );
  }
  if (receipt.operation === 'readFileSync') {
    if (
      !exactKeys(result, ['cardinality', 'byteLength', 'bytes', 'encoding', 'text', 'sha256']) ||
      result.cardinality !== 1 ||
      !plainObject(result.bytes) ||
      !exactKeys(result.bytes, ['encoding', 'base64', 'byteLength', 'sha256']) ||
      result.bytes.encoding !== 'base64' ||
      typeof result.bytes.base64 !== 'string' ||
      !nonNegativeInteger(result.bytes.byteLength) ||
      !sha256Text(result.bytes.sha256) ||
      !['utf8', 'base64'].includes(result.encoding) ||
      !(typeof result.text === 'string' || result.text === null) ||
      !nonNegativeInteger(result.byteLength) ||
      !sha256Text(result.sha256)
    ) {
      return false;
    }
    const bytes = Buffer.from(result.bytes.base64, 'base64');
    const decoded = bytes.toString('utf8');
    const utf8Exact = Buffer.from(decoded, 'utf8').equals(bytes);
    return (
      bytes.toString('base64') === result.bytes.base64 &&
      result.bytes.byteLength === bytes.byteLength &&
      result.byteLength === bytes.byteLength &&
      result.bytes.sha256 === sha256(bytes) &&
      result.sha256 === sha256(bytes) &&
      (utf8Exact
        ? result.encoding === 'utf8' && result.text === decoded
        : result.encoding === 'base64' && result.text === null)
    );
  }
  if (receipt.operation === 'readdirSync') {
    return (
      exactKeys(result, ['entries', 'cardinality', 'sha256']) &&
      Array.isArray(result.entries) &&
      result.entries.every((entry) => typeof entry === 'string') &&
      result.cardinality === result.entries.length &&
      result.sha256 === sha256(Buffer.from(JSON.stringify(result.entries), 'utf8'))
    );
  }
  if (receipt.operation === 'realpathSync' || receipt.operation === 'readlinkSync') {
    return (
      exactKeys(result, ['value', 'cardinality', 'sha256']) &&
      scalarString(result.value) &&
      result.cardinality === 1 &&
      result.sha256 === sha256(Buffer.from(result.value, 'utf8'))
    );
  }
  if (
    !exactKeys(result, ['cardinality', 'metadata', 'sha256']) ||
    result.cardinality !== 1 ||
    !exactKeys(result.metadata, [...STAT_KEYS, 'isSymbolicLink']) ||
    !exactStat(Object.fromEntries(STAT_KEYS.map((key) => [key, result.metadata[key]]))) ||
    typeof result.metadata.isSymbolicLink !== 'boolean'
  ) {
    return false;
  }
  return result.sha256 === sha256(Buffer.from(JSON.stringify(result.metadata), 'utf8'));
}

function filesystemReadBytes(receipt) {
  const result = receipt?.result;
  if (
    receipt?.operation !== 'readFileSync' ||
    receipt.disposition !== 'observed' ||
    !plainObject(result?.bytes) ||
    result.bytes.encoding !== 'base64' ||
    typeof result.bytes.base64 !== 'string'
  ) {
    return null;
  }
  const bytes = Buffer.from(result.bytes.base64, 'base64');
  if (
    bytes.toString('base64') !== result.bytes.base64 ||
    result.bytes.byteLength !== bytes.byteLength ||
    result.bytes.sha256 !== sha256(bytes) ||
    result.byteLength !== bytes.byteLength ||
    result.sha256 !== sha256(bytes)
  ) {
    return null;
  }
  return bytes;
}

function filesystemReadText(receipt) {
  const bytes = filesystemReadBytes(receipt);
  if (bytes === null) return null;
  const text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes)) return null;
  if (receipt.result.encoding !== 'utf8' || receipt.result.text !== text) return null;
  return text;
}

function boundFilesystemReceipts(frame, audit) {
  return (frame.auditBinding?.filesystemReceiptIndexes ?? []).map(
    (index) => audit.filesystemReceipts[index]
  );
}

function uniqueObservedReceipt(receipts, operation, targetPath) {
  const matches = receipts.filter(
    (receipt) =>
      receipt?.operation === operation &&
      receipt.path === targetPath &&
      receipt.disposition === 'observed'
  );
  return matches.length === 1 ? matches[0] : null;
}

function observedReceipts(receipts, operation, targetPath) {
  return receipts.filter(
    (receipt) =>
      receipt?.operation === operation &&
      receipt.path === targetPath &&
      receipt.disposition === 'observed'
  );
}

function propertiesFromText(text) {
  if (typeof text !== 'string') return null;
  const result = {};
  for (const line of text.split(/\r?\n/u)) {
    if (line === '') continue;
    const separator = line.indexOf('=');
    if (separator <= 0) return null;
    const key = line.slice(0, separator);
    if (Object.hasOwn(result, key)) return null;
    result[key] = line.slice(separator + 1);
  }
  return result;
}

function osReleaseFromText(text) {
  const properties = propertiesFromText(text);
  if (
    properties === null ||
    !scalarString(properties.ID) ||
    !scalarString(properties.VERSION_ID) ||
    !scalarString(properties.PRETTY_NAME)
  ) {
    return null;
  }
  function unquote(value) {
    if (value.startsWith('"') && value.endsWith('"')) {
      return value.slice(1, -1).replaceAll('\\"', '"').replaceAll('\\\\', '\\');
    }
    return /^[A-Za-z0-9._+-]+$/u.test(value) ? value : null;
  }
  const id = unquote(properties.ID);
  const versionId = unquote(properties.VERSION_ID);
  const prettyName = unquote(properties.PRETTY_NAME);
  return id === null || versionId === null || prettyName === null
    ? null
    : { id, versionId, prettyName };
}

function reconstructHost(frame, receipts) {
  const osReceipt = uniqueObservedReceipt(receipts, 'readFileSync', '/etc/os-release');
  const bootReceipt = uniqueObservedReceipt(
    receipts,
    'readFileSync',
    '/proc/sys/kernel/random/boot_id'
  );
  const hostnameReceipt = uniqueObservedReceipt(
    receipts,
    'readFileSync',
    '/proc/sys/kernel/hostname'
  );
  const osRelease = osReleaseFromText(filesystemReadText(osReceipt));
  const bootId = filesystemReadText(bootReceipt)?.trim() ?? null;
  const hostname = filesystemReadText(hostnameReceipt)?.trim() ?? null;
  let declaredOsRelease = null;
  try {
    declaredOsRelease = JSON.parse(frame.host.osRelease);
  } catch {
    return false;
  }
  return (
    osRelease !== null &&
    same(declaredOsRelease, osRelease) &&
    bootId === frame.host.bootId &&
    hostname === frame.host.hostname
  );
}

function stripReceiptStat(metadata) {
  if (!plainObject(metadata)) return null;
  const value = Object.fromEntries(STAT_KEYS.map((key) => [key, metadata[key]]));
  return exactStat(value) ? value : null;
}

function parseClassDevice(text) {
  const match = /^([0-9]+):([0-9]+)$/u.exec(text?.trim() ?? '');
  if (match === null) return null;
  return { major: Number(match[1]), minor: Number(match[2]) };
}

function hidIdentityFromUevent(text) {
  const properties = propertiesFromText(text);
  const match =
    typeof properties?.HID_ID === 'string'
      ? /^[0-9A-Fa-f]{1,8}:([0-9A-Fa-f]{1,8}):([0-9A-Fa-f]{1,8})$/u.exec(properties.HID_ID)
      : null;
  if (match === null) return null;
  return {
    vendorId: BigInt(`0x${match[1]}`).toString(16).padStart(4, '0'),
    productId: BigInt(`0x${match[2]}`).toString(16).padStart(4, '0'),
    serial: properties.HID_UNIQ || null,
  };
}

function readTextAt(receipts, targetPath) {
  const receipt = uniqueObservedReceipt(receipts, 'readFileSync', targetPath);
  return filesystemReadText(receipt)?.trim() ?? null;
}

function reconstructDevice(frame, receipts, candidate) {
  try {
    const inventoryReceipt = uniqueObservedReceipt(receipts, 'readdirSync', '/sys/class/hidraw');
    if (
      inventoryReceipt === null ||
      !Array.isArray(inventoryReceipt.result.entries) ||
      inventoryReceipt.result.entries.some((entry) => !/^hidraw(?:0|[1-9][0-9]*)$/u.test(entry))
    ) {
      return false;
    }
    const candidates = [];
    for (const name of inventoryReceipt.result.entries) {
      const classRoot = `/sys/class/hidraw/${name}`;
      const devicePath = `/dev/${name}`;
      const realpathReceipt = uniqueObservedReceipt(
        receipts,
        'realpathSync',
        `${classRoot}/device`
      );
      const ueventReceipt = uniqueObservedReceipt(
        receipts,
        'readFileSync',
        `${classRoot}/device/uevent`
      );
      const classDeviceReceipt = uniqueObservedReceipt(
        receipts,
        'readFileSync',
        `${classRoot}/dev`
      );
      const stats = observedReceipts(receipts, 'statSync', devicePath)
        .map((receipt) => stripReceiptStat(receipt.result.metadata))
        .filter((entry) => entry !== null);
      if (
        realpathReceipt === null ||
        ueventReceipt === null ||
        classDeviceReceipt === null ||
        stats.length < 2 ||
        !stats.every((entry) => same(entry, stats[0]))
      ) {
        return false;
      }
      const hidDevicePath = realpathReceipt.result.value;
      const hid = hidIdentityFromUevent(filesystemReadText(ueventReceipt));
      const classDevice = parseClassDevice(filesystemReadText(classDeviceReceipt));
      if (
        hid === null ||
        classDevice === null ||
        classDevice.major !== stats[0].major ||
        classDevice.minor !== stats[0].minor
      ) {
        return false;
      }
      const vendorReceipts = receipts.filter(
        (receipt) =>
          receipt.operation === 'readFileSync' &&
          receipt.disposition === 'observed' &&
          receipt.path.endsWith('/idVendor') &&
          filesystemReadText(receipt)?.trim().toLowerCase() === hid.vendorId
      );
      for (const vendorReceipt of vendorReceipts) {
        const usbRoot = path.posix.dirname(vendorReceipt.path);
        if (!(hidDevicePath === usbRoot || hidDevicePath.startsWith(`${usbRoot}/`))) continue;
        const productId = readTextAt(receipts, `${usbRoot}/idProduct`)?.toLowerCase();
        const serial = readTextAt(receipts, `${usbRoot}/serial`);
        if (productId !== hid.productId || serial !== hid.serial || !scalarString(serial)) {
          continue;
        }
        const epoch = {
          serial,
          busNumber: readTextAt(receipts, `${usbRoot}/busnum`),
          deviceNumber: readTextAt(receipts, `${usbRoot}/devnum`),
          usbDevicePath: readTextAt(receipts, `${usbRoot}/devpath`),
          usbDev: readTextAt(receipts, `${usbRoot}/dev`),
          hidDevicePath,
          devicePath,
          stat: stats[0],
        };
        if (exactEpoch(epoch)) {
          candidates.push({
            serial,
            vendorId: hid.vendorId,
            productId: hid.productId,
            epoch,
          });
        }
      }
    }
    const matching = candidates.filter(
      (entry) =>
        entry.serial === candidate.identity.device.serial &&
        entry.vendorId === candidate.identity.device.vendorId &&
        entry.productId === candidate.identity.device.productId
    );
    if (frame.device.present === false) {
      return frame.device.identity === null && matching.length === 0;
    }
    return matching.length === 1 && same(frame.device.identity, matching[0]);
  } catch {
    return false;
  }
}

function procStatFromText(text) {
  const match = /^([1-9][0-9]*)\s+\((.*)\)\s+([A-Za-z])\s+(.+)$/u.exec(text?.trim() ?? '');
  if (match === null) return null;
  const fields = match[4].trim().split(/\s+/u);
  if (fields.length < 19) return null;
  const pid = Number(match[1]);
  const ppid = Number(fields[0]);
  const startTicks = Number(fields[18]);
  return positiveInteger(pid) && nonNegativeInteger(ppid) && positiveInteger(startTicks)
    ? { pid, ppid, startTicks }
    : null;
}

function procStatusFromText(text) {
  if (typeof text !== 'string') return null;
  const properties = {};
  for (const line of text.split(/\r?\n/u)) {
    const separator = line.indexOf(':');
    if (separator <= 0) continue;
    const key = line.slice(0, separator);
    if (Object.hasOwn(properties, key)) return null;
    properties[key] = line.slice(separator + 1).trim();
  }
  function numbers(key) {
    return (properties[key] ?? '').split(/\s+/u).filter(Boolean).map(Number);
  }
  const uids = numbers('Uid');
  const gids = numbers('Gid');
  const groups = numbers('Groups');
  const namespacePids = numbers('NSpid');
  if (
    uids.length < 4 ||
    gids.length < 4 ||
    namespacePids.length < 1 ||
    [...uids, ...gids, ...groups, ...namespacePids].some((entry) => !nonNegativeInteger(entry))
  ) {
    return null;
  }
  return { uid: uids[0], gid: gids[0], groups, namespacePids };
}

function cmdlineFromText(text) {
  if (typeof text !== 'string' || text === '') return [];
  const body = text.endsWith('\u0000') ? text.slice(0, -1) : text;
  const args = body.split('\u0000');
  return args.some((entry) => entry === '') ? null : args;
}

function normalizedCgroup(text) {
  const lines = (text ?? '')
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);
  return lines.length > 0 && lines.every((line) => /^[0-9]+:[^:]*:.+$/u.test(line))
    ? lines.join('\n')
    : null;
}

function reconstructProcesses(frame, receipts, candidate) {
  if (frame.lifecycle === null) {
    const procReceipts = receipts.filter((receipt) =>
      /^\/proc\/[1-9][0-9]*\/root\/proc(?:\/|$)/u.test(receipt.path)
    );
    return frame.pid1 === null && frame.workers.length === 0 && procReceipts.length === 0;
  }
  try {
    const hostPid = frame.lifecycle.hostPid;
    const procRoot = `/proc/${hostPid}/root/proc`;
    const listReceipts = observedReceipts(receipts, 'readdirSync', procRoot);
    if (
      listReceipts.length !== 2 ||
      !same(listReceipts[0].result.entries, listReceipts[1].result.entries)
    ) {
      return false;
    }
    const pids = listReceipts[0].result.entries
      .filter((entry) => /^[1-9][0-9]*$/u.test(entry))
      .map(Number)
      .sort((left, right) => left - right);
    const processes = [];
    for (const pid of pids) {
      const directory = `${procRoot}/${pid}`;
      const stat = procStatFromText(
        filesystemReadText(uniqueObservedReceipt(receipts, 'readFileSync', `${directory}/stat`))
      );
      const status = procStatusFromText(
        filesystemReadText(uniqueObservedReceipt(receipts, 'readFileSync', `${directory}/status`))
      );
      const cmdline = cmdlineFromText(
        filesystemReadText(uniqueObservedReceipt(receipts, 'readFileSync', `${directory}/cmdline`))
      );
      const cgroup = normalizedCgroup(
        filesystemReadText(uniqueObservedReceipt(receipts, 'readFileSync', `${directory}/cgroup`))
      );
      const pidNamespace = uniqueObservedReceipt(receipts, 'readlinkSync', `${directory}/ns/pid`)
        ?.result?.value;
      const mountNamespace = uniqueObservedReceipt(receipts, 'readlinkSync', `${directory}/ns/mnt`)
        ?.result?.value;
      if (
        stat === null ||
        stat.pid !== pid ||
        status === null ||
        status.namespacePids.at(-1) !== pid ||
        cmdline === null ||
        cgroup === null ||
        !/^pid:\[[0-9]+\]$/u.test(pidNamespace ?? '') ||
        !/^mnt:\[[0-9]+\]$/u.test(mountNamespace ?? '')
      ) {
        return false;
      }
      processes.push({
        pid,
        startTicks: stat.startTicks,
        ppid: stat.ppid,
        parentStartTicks: null,
        uid: status.uid,
        gid: status.gid,
        groups: status.groups,
        cmdline,
        cgroup,
        pidNamespace,
        mountNamespace,
      });
    }
    const byPid = new Map(processes.map((entry) => [entry.pid, entry]));
    for (const processEntry of processes) {
      if (processEntry.ppid === 0) continue;
      const parent = byPid.get(processEntry.ppid);
      if (parent === undefined) return false;
      processEntry.parentStartTicks = parent.startTicks;
    }
    const pid1 = byPid.get(1);
    if (pid1 === undefined) return false;
    const reconstructedPid1 = {
      hostPid,
      startTicks: pid1.startTicks,
      pidNamespace: pid1.pidNamespace,
      mountNamespace: pid1.mountNamespace,
      cgroup: pid1.cgroup,
    };
    if (!same(frame.pid1, reconstructedPid1)) return false;

    const workers = processes.filter((entry) =>
      entry.cmdline.some(
        (argument) =>
          typeof argument === 'string' && path.posix.basename(argument) === 'SurfaceThread.js'
      )
    );
    if (!same(frame.workers, workers)) return false;
    const hostCgroup = normalizedCgroup(
      filesystemReadText(uniqueObservedReceipt(receipts, 'readFileSync', `/proc/${hostPid}/cgroup`))
    );
    if (
      hostCgroup !== frame.lifecycle.hostCgroup ||
      frame.lifecycle.pid1StartTicks !== pid1.startTicks ||
      frame.lifecycle.pidNamespace !== pid1.pidNamespace ||
      frame.lifecycle.mountNamespace !== pid1.mountNamespace ||
      frame.lifecycle.cgroup !== pid1.cgroup
    ) {
      return false;
    }

    const descriptors = [];
    for (const worker of workers) {
      const fdRoot = `${procRoot}/${worker.pid}/fd`;
      const fdLists = observedReceipts(receipts, 'readdirSync', fdRoot);
      if (fdLists.length !== 2 || !same(fdLists[0].result.entries, fdLists[1].result.entries)) {
        return false;
      }
      const descriptorNames = fdLists[0].result.entries
        .filter((entry) => MONOTONIC_PATTERN.test(entry))
        .sort((left, right) => Number(left) - Number(right));
      for (const descriptor of descriptorNames) {
        const descriptorPath = `${fdRoot}/${descriptor}`;
        const lstat = uniqueObservedReceipt(receipts, 'lstatSync', descriptorPath)?.result
          ?.metadata;
        const stat = uniqueObservedReceipt(receipts, 'statSync', descriptorPath)?.result?.metadata;
        const target = uniqueObservedReceipt(receipts, 'readlinkSync', descriptorPath)?.result
          ?.value;
        if (!plainObject(lstat) || !plainObject(stat) || !scalarString(target)) return false;
        if (
          stat.isCharacterDevice === true &&
          (/^\/dev\/hidraw(?:0|[1-9][0-9]*)(?: \(deleted\))?$/u.test(target) ||
            stat.major === candidate.identity.device.revalidationEpoch.stat.major)
        ) {
          descriptors.push({ descriptor, target, lstat, stat });
        }
      }
    }
    return same(frame.descriptors, descriptors);
  } catch {
    return false;
  }
}

function reconstructFrames(run) {
  try {
    return run.frames.every((frame) => {
      const receipts = boundFilesystemReceipts(frame, run.capabilityAudit);
      return (
        reconstructHost(frame, receipts) &&
        reconstructDevice(frame, receipts, run.historicalCandidate) &&
        reconstructProcesses(frame, receipts, run.historicalCandidate)
      );
    });
  } catch {
    return false;
  }
}

function boundCommandReceipts(frame, audit) {
  return (frame.auditBinding?.commandReceiptIndexes ?? []).map(
    (index) => audit.commandReceipts[index]
  );
}

function independentlyCompleteFrame(frame, run) {
  try {
    const filesystemReceipts = boundFilesystemReceipts(frame, run.capabilityAudit);
    const commandReceipts = boundCommandReceipts(frame, run.capabilityAudit);
    if (
      filesystemReceipts.some((receipt) => receipt?.disposition === 'error') ||
      commandReceipts.some(
        (receipt) =>
          receipt?.exitCode !== 0 || receipt?.signal !== null || receipt?.errorCode !== null
      )
    ) {
      return false;
    }
    if (
      !reconstructHost(frame, filesystemReceipts) ||
      !reconstructDevice(frame, filesystemReceipts, run.historicalCandidate) ||
      !reconstructProcesses(frame, filesystemReceipts, run.historicalCandidate)
    ) {
      return false;
    }

    const psReceipt = commandReceipts.find((receipt) => receipt?.kind === 'dockerPs');
    const ps = parseDockerPs(psReceipt?.stdout?.text ?? '');
    const targetId = run.historicalCandidate.identity.lifecycle.containerId;
    if (ps === null || ps.length > 1 || ps.some((entry) => entry.containerId !== targetId)) {
      return false;
    }
    const target = ps.find((entry) => entry.containerId === targetId) ?? null;
    const absent = target === null;
    const running = target?.state === 'running';
    const exactNonRunning = target !== null && scalarString(target.state) && running === false;
    const containerObservation = {
      present: target !== null,
      state: target?.state ?? null,
      exact: true,
    };
    const markersEmpty =
      frame.markers.opening === 0 &&
      frame.markers.ready === 0 &&
      frame.markers.relevantLinesSha256 === sha256Canonical([]);
    const branchExact =
      frame.lifecycle === null
        ? (absent || exactNonRunning) &&
          frame.pid1 === null &&
          frame.workers.length === 0 &&
          frame.descriptors.length === 0 &&
          markersEmpty
        : running &&
          same(
            commandReceipts.map((receipt) => receipt.kind),
            ['dockerPs', 'dockerInspect', 'dockerLogs']
          );

    return (
      branchExact &&
      same(frame.containerObservation, containerObservation) &&
      frame.absence.historicalContainerAbsent === absent &&
      frame.absence.exact === true &&
      frame.device.complete === true
    );
  } catch {
    return false;
  }
}

function verifyFrameCompleteness(run) {
  try {
    const recomputed = run.frames.map((frame) => independentlyCompleteFrame(frame, run));
    return {
      exact: recomputed.every((complete, index) => run.frames[index].complete === complete),
      recomputed,
    };
  } catch {
    return { exact: false, recomputed: [] };
  }
}

function filesystemReceiptExact(receipt, index, perOperation, run) {
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
    receipt.index !== index ||
    !filesystemPathAllowed(receipt.operation, receipt.path) ||
    !validTimestamp(receipt.startedAt) ||
    !validTimestamp(receipt.endedAt) ||
    rfc3339EpochNs(receipt.startedAt) < rfc3339EpochNs(run.startedAt) ||
    rfc3339EpochNs(receipt.endedAt) > rfc3339EpochNs(run.completedAt) ||
    rfc3339EpochNs(receipt.endedAt) < rfc3339EpochNs(receipt.startedAt) ||
    !MONOTONIC_PATTERN.test(receipt.startedMonotonicNs) ||
    !MONOTONIC_PATTERN.test(receipt.endedMonotonicNs) ||
    !MONOTONIC_PATTERN.test(receipt.durationNs) ||
    !['observed', 'missing', 'error'].includes(receipt.disposition) ||
    !exactFilesystemResult(receipt) ||
    !exactKeys(receipt.cardinality, ['global', 'operation']) ||
    receipt.cardinality.global !== index + 1
  ) {
    return false;
  }
  if (
    receipt.disposition === 'observed'
      ? receipt.errorCode !== null
      : !scalarString(receipt.errorCode)
  ) {
    return false;
  }
  const started = monotonic(receipt.startedMonotonicNs);
  const ended = monotonic(receipt.endedMonotonicNs);
  const expectedOrdinal = (perOperation[receipt.operation] ?? 0) + 1;
  const containedByOneFrame = run.frames.some(
    (frame) =>
      started >= monotonic(frame.startedMonotonicNs) && ended <= monotonic(frame.endedMonotonicNs)
  );
  return (
    ended >= started &&
    monotonic(receipt.durationNs) === ended - started &&
    receipt.cardinality.operation === expectedOrdinal &&
    containedByOneFrame
  );
}

function verifyFilesystemAudit(audit, run) {
  const receipts = Array.isArray(audit?.filesystemReceipts) ? audit.filesystemReceipts : [];
  const prohibited = receipts.some(
    (receipt) => !filesystemPathAllowed(receipt?.operation, receipt?.path)
  );
  try {
    if (!Array.isArray(audit?.filesystemReceipts)) {
      return { exact: false, prohibited: false };
    }
    const perOperation = Object.fromEntries(FILESYSTEM_OPERATIONS.map((key) => [key, 0]));
    let previousEnd = null;
    let exact = audit.filesystemReceipts.length > 0;
    for (let index = 0; index < audit.filesystemReceipts.length; index += 1) {
      const receipt = audit.filesystemReceipts[index];
      if (!filesystemReceiptExact(receipt, index, perOperation, run)) exact = false;
      if (!FILESYSTEM_OPERATIONS.includes(receipt?.operation)) continue;
      perOperation[receipt.operation] += 1;
      if (MONOTONIC_PATTERN.test(receipt.startedMonotonicNs ?? '')) {
        const started = monotonic(receipt.startedMonotonicNs);
        if (previousEnd !== null && started < previousEnd) exact = false;
      }
      if (MONOTONIC_PATTERN.test(receipt.endedMonotonicNs ?? '')) {
        previousEnd = monotonic(receipt.endedMonotonicNs);
      }
    }
    return {
      exact,
      prohibited,
    };
  } catch {
    return { exact: false, prohibited };
  }
}

function orderedUniqueIndexes(value) {
  return (
    Array.isArray(value) &&
    value.every((entry) => nonNegativeInteger(entry)) &&
    value.every((entry, index) => index === 0 || entry > value[index - 1])
  );
}

function receiptInsideFrame(receipt, frame) {
  try {
    return (
      validTimestamp(receipt.startedAt) &&
      validTimestamp(receipt.endedAt) &&
      rfc3339EpochNs(receipt.startedAt) >= rfc3339EpochNs(frame.startedAt) &&
      rfc3339EpochNs(receipt.endedAt) <= rfc3339EpochNs(frame.endedAt) &&
      monotonic(receipt.startedMonotonicNs) >= monotonic(frame.startedMonotonicNs) &&
      monotonic(receipt.endedMonotonicNs) <= monotonic(frame.endedMonotonicNs)
    );
  } catch {
    return false;
  }
}

function receiptEndsAtOrBeforeCutoff(receipt, cutoff) {
  try {
    return (
      rfc3339EpochNs(receipt.endedAt) <= rfc3339EpochNs(cutoff.at) &&
      monotonic(receipt.endedMonotonicNs) <= monotonic(cutoff.monotonicNs)
    );
  } catch {
    return false;
  }
}

function receiptStartsAtOrAfterCutoff(receipt, cutoff) {
  try {
    return (
      rfc3339EpochNs(receipt.startedAt) >= rfc3339EpochNs(cutoff.at) &&
      monotonic(receipt.startedMonotonicNs) >= monotonic(cutoff.monotonicNs)
    );
  } catch {
    return false;
  }
}

function verifyAuditBindings(audit, run) {
  try {
    if (!Array.isArray(run.frames) || run.frames.length !== 2) {
      return { exact: false, commandExact: false, filesystemExact: false };
    }
    const commandOwners = new Map();
    const filesystemOwners = new Map();
    let shapeExact = true;
    for (let frameIndex = 0; frameIndex < run.frames.length; frameIndex += 1) {
      const frame = run.frames[frameIndex];
      const binding = frame.auditBinding;
      if (
        !exactKeys(binding, ['commandReceiptIndexes', 'filesystemReceiptIndexes']) ||
        !orderedUniqueIndexes(binding.commandReceiptIndexes) ||
        !orderedUniqueIndexes(binding.filesystemReceiptIndexes)
      ) {
        shapeExact = false;
        continue;
      }
      for (const receiptIndex of binding.commandReceiptIndexes) {
        if (commandOwners.has(receiptIndex)) shapeExact = false;
        commandOwners.set(receiptIndex, frameIndex);
      }
      for (const receiptIndex of binding.filesystemReceiptIndexes) {
        if (filesystemOwners.has(receiptIndex)) shapeExact = false;
        filesystemOwners.set(receiptIndex, frameIndex);
      }
    }

    const liveCommandIndexes = audit.commandReceipts
      .filter((receipt) => ['dockerPs', 'dockerInspect', 'dockerLogs'].includes(receipt.kind))
      .map((receipt) => receipt.index);
    const preflightCommandIndexes = audit.commandReceipts
      .filter((receipt) => ['git', 'lsusb', 'dockerVersion'].includes(receipt.kind))
      .map((receipt) => receipt.index);
    const boundCommandIndexes = [...commandOwners.keys()].sort((left, right) => left - right);
    const boundFilesystemIndexes = [...filesystemOwners.keys()].sort((left, right) => left - right);
    let commandExact =
      same(boundCommandIndexes, liveCommandIndexes) &&
      preflightCommandIndexes.every((index) => !commandOwners.has(index));
    let filesystemExact = same(
      boundFilesystemIndexes,
      audit.filesystemReceipts.map((receipt) => receipt.index)
    );

    for (const [receiptIndex, frameIndex] of commandOwners) {
      const receipt = audit.commandReceipts[receiptIndex];
      if (receipt?.index !== receiptIndex || !receiptInsideFrame(receipt, run.frames[frameIndex])) {
        commandExact = false;
      }
    }
    for (const [receiptIndex, frameIndex] of filesystemOwners) {
      const receipt = audit.filesystemReceipts[receiptIndex];
      if (receipt?.index !== receiptIndex || !receiptInsideFrame(receipt, run.frames[frameIndex])) {
        filesystemExact = false;
      }
    }

    for (let frameIndex = 0; frameIndex < run.frames.length; frameIndex += 1) {
      const frame = run.frames[frameIndex];
      const kinds = frame.auditBinding.commandReceiptIndexes.map(
        (index) => audit.commandReceipts[index]?.kind
      );
      const expectedKinds =
        frame.containerObservation?.state === 'running'
          ? ['dockerPs', 'dockerInspect', 'dockerLogs']
          : ['dockerPs'];
      if (!same(kinds, expectedKinds)) commandExact = false;
      if (frame.auditBinding.filesystemReceiptIndexes.length === 0) filesystemExact = false;

      const commands = frame.auditBinding.commandReceiptIndexes.map(
        (index) => audit.commandReceipts[index]
      );
      const filesystem = frame.auditBinding.filesystemReceiptIndexes.map(
        (index) => audit.filesystemReceipts[index]
      );
      const cutoff = frame.observationCutoff;
      if (
        !exactObservationCutoff(cutoff) ||
        rfc3339EpochNs(cutoff.at) < rfc3339EpochNs(frame.startedAt) ||
        rfc3339EpochNs(cutoff.at) > rfc3339EpochNs(frame.endedAt) ||
        monotonic(cutoff.monotonicNs) < monotonic(frame.startedMonotonicNs) ||
        monotonic(cutoff.monotonicNs) > monotonic(frame.endedMonotonicNs)
      ) {
        commandExact = false;
        filesystemExact = false;
        continue;
      }
      if (expectedKinds.length === 1) {
        if (
          cutoff.at !== commands[0]?.endedAt ||
          cutoff.monotonicNs !== commands[0]?.endedMonotonicNs ||
          !filesystem.every((receipt) => receiptEndsAtOrBeforeCutoff(receipt, cutoff))
        ) {
          commandExact = false;
          filesystemExact = false;
        }
        continue;
      }
      const logArgs = dockerSubcommandArgs(commands[2]);
      if (
        logArgs?.[5] !== cutoff.at ||
        !commands.slice(0, 2).every((receipt) => receiptEndsAtOrBeforeCutoff(receipt, cutoff)) ||
        !filesystem.every((receipt) => receiptEndsAtOrBeforeCutoff(receipt, cutoff)) ||
        !receiptStartsAtOrAfterCutoff(commands[2], cutoff)
      ) {
        commandExact = false;
        filesystemExact = false;
      }
    }
    return {
      exact: shapeExact && commandExact && filesystemExact,
      commandExact: shapeExact && commandExact,
      filesystemExact: shapeExact && filesystemExact,
    };
  } catch {
    return { exact: false, commandExact: false, filesystemExact: false };
  }
}

function verifyCapabilityAudit(audit, run) {
  const command = verifyCommandAudit(audit, run);
  const filesystem = verifyFilesystemAudit(audit, run);
  const bindings = verifyAuditBindings(audit, run);
  let shapeExact = false;
  let declaredCountsExact = false;
  let prohibitedShapeExact = false;
  let prohibitedObserved = command.prohibited || filesystem.prohibited;
  try {
    shapeExact =
      exactKeys(audit, [
        'mode',
        'complete',
        'exact',
        'frameCount',
        'lsusbCount',
        'unrecordedObservationCount',
        'commandReceipts',
        'filesystemReceipts',
        'allowedProcessCounts',
        'commandCount',
        'filesystemReceiptCount',
        'prohibitedCounts',
      ]) &&
      audit.mode === 'live-readonly-capability-bounded' &&
      Array.isArray(audit.commandReceipts) &&
      Array.isArray(audit.filesystemReceipts) &&
      exactKeys(audit.allowedProcessCounts, ALLOWED_PROCESS_KEYS) &&
      ALLOWED_PROCESS_KEYS.every((key) => nonNegativeInteger(audit.allowedProcessCounts[key])) &&
      nonNegativeInteger(audit.commandCount) &&
      nonNegativeInteger(audit.filesystemReceiptCount) &&
      typeof audit.complete === 'boolean' &&
      typeof audit.exact === 'boolean' &&
      nonNegativeInteger(audit.frameCount) &&
      nonNegativeInteger(audit.lsusbCount) &&
      nonNegativeInteger(audit.unrecordedObservationCount);
    declaredCountsExact =
      shapeExact &&
      command.counts !== null &&
      audit.commandCount === audit.commandReceipts.length &&
      audit.filesystemReceiptCount === audit.filesystemReceipts.length &&
      ALLOWED_PROCESS_KEYS.every(
        (key) => audit.allowedProcessCounts[key] === command.counts[key]
      ) &&
      audit.commandCount ===
        ALLOWED_PROCESS_KEYS.reduce((total, key) => total + audit.allowedProcessCounts[key], 0);
    prohibitedShapeExact =
      exactKeys(audit.prohibitedCounts, PROHIBITED_COUNT_KEYS) &&
      PROHIBITED_COUNT_KEYS.every((key) => nonNegativeInteger(audit.prohibitedCounts[key]));
    prohibitedObserved ||=
      prohibitedShapeExact && PROHIBITED_COUNT_KEYS.some((key) => audit.prohibitedCounts[key] > 0);
  } catch {
    shapeExact = false;
  }
  const exact =
    shapeExact &&
    declaredCountsExact &&
    prohibitedShapeExact &&
    prohibitedObserved === false &&
    command.exact &&
    filesystem.exact &&
    bindings.exact &&
    audit.complete === true &&
    audit.exact === true &&
    audit.frameCount === 2 &&
    audit.lsusbCount === 1 &&
    audit.unrecordedObservationCount === 0;
  return {
    exact,
    commandExact: command.exact,
    filesystemExact: filesystem.exact,
    bindingExact: bindings.exact,
    declaredCountsExact,
    prohibitedShapeExact,
    prohibitedObserved,
  };
}

function exactHost(value) {
  return (
    exactKeys(value, ['hostname', 'bootId', 'osRelease']) &&
    scalarString(value.hostname) &&
    scalarString(value.bootId) &&
    scalarString(value.osRelease)
  );
}

function exactDevice(value) {
  if (
    !exactKeys(value, ['complete', 'present', 'identity']) ||
    typeof value.complete !== 'boolean' ||
    typeof value.present !== 'boolean'
  ) {
    return false;
  }
  if (value.present === false) return value.identity === null;
  return (
    exactKeys(value.identity, ['serial', 'vendorId', 'productId', 'epoch']) &&
    scalarString(value.identity.serial) &&
    value.identity.vendorId === '0fd9' &&
    value.identity.productId === '0080' &&
    exactEpoch(value.identity.epoch)
  );
}

function exactObservationCutoff(value) {
  return (
    exactKeys(value, ['at', 'monotonicNs']) &&
    validTimestamp(value.at) &&
    MONOTONIC_PATTERN.test(value.monotonicNs)
  );
}

function exactContainerObservation(value) {
  if (
    !exactKeys(value, ['present', 'state', 'exact']) ||
    typeof value.present !== 'boolean' ||
    typeof value.exact !== 'boolean'
  ) {
    return false;
  }
  return value.present
    ? typeof value.state === 'string' && /^[a-z][a-z0-9_-]*$/u.test(value.state)
    : value.state === null;
}

function exactPid1(value) {
  return (
    exactKeys(value, ['hostPid', 'startTicks', 'pidNamespace', 'mountNamespace', 'cgroup']) &&
    positiveInteger(value.hostPid) &&
    positiveInteger(value.startTicks) &&
    scalarString(value.pidNamespace) &&
    scalarString(value.mountNamespace) &&
    scalarString(value.cgroup)
  );
}

function exactMarkers(value) {
  return (
    exactKeys(value, ['opening', 'ready', 'relevantLinesSha256']) &&
    nonNegativeInteger(value.opening) &&
    nonNegativeInteger(value.ready) &&
    sha256Text(value.relevantLinesSha256)
  );
}

function frameExact(frame) {
  try {
    if (
      !exactKeys(frame, FRAME_KEYS) ||
      !scalarString(frame.id) ||
      typeof frame.complete !== 'boolean' ||
      !validTimestamp(frame.startedAt) ||
      !validTimestamp(frame.endedAt) ||
      !MONOTONIC_PATTERN.test(frame.startedMonotonicNs) ||
      !MONOTONIC_PATTERN.test(frame.endedMonotonicNs) ||
      !exactObservationCutoff(frame.observationCutoff) ||
      !exactHost(frame.host) ||
      !exactDevice(frame.device) ||
      !exactContainerObservation(frame.containerObservation) ||
      !(frame.lifecycle === null || exactLifecycle(frame.lifecycle)) ||
      !(frame.pid1 === null || exactPid1(frame.pid1)) ||
      !Array.isArray(frame.workers) ||
      !frame.workers.every(exactWorker) ||
      !Array.isArray(frame.descriptors) ||
      !frame.descriptors.every((entry) => plainObject(entry) && Object.keys(entry).length > 0) ||
      !exactMarkers(frame.markers) ||
      !exactKeys(frame.absence, ['historicalContainerAbsent', 'exact']) ||
      typeof frame.absence.historicalContainerAbsent !== 'boolean' ||
      typeof frame.absence.exact !== 'boolean' ||
      !exactKeys(frame.auditBinding, ['commandReceiptIndexes', 'filesystemReceiptIndexes']) ||
      !orderedUniqueIndexes(frame.auditBinding.commandReceiptIndexes) ||
      !orderedUniqueIndexes(frame.auditBinding.filesystemReceiptIndexes) ||
      !sha256Text(frame.digestSha256)
    ) {
      return false;
    }
    const { digestSha256, ...body } = frame;
    return (
      monotonic(frame.endedMonotonicNs) >= monotonic(frame.startedMonotonicNs) &&
      monotonic(frame.observationCutoff.monotonicNs) >= monotonic(frame.startedMonotonicNs) &&
      monotonic(frame.observationCutoff.monotonicNs) <= monotonic(frame.endedMonotonicNs) &&
      rfc3339EpochNs(frame.endedAt) >= rfc3339EpochNs(frame.startedAt) &&
      rfc3339EpochNs(frame.observationCutoff.at) >= rfc3339EpochNs(frame.startedAt) &&
      rfc3339EpochNs(frame.observationCutoff.at) <= rfc3339EpochNs(frame.endedAt) &&
      sha256Canonical(body) === digestSha256
    );
  } catch {
    return false;
  }
}

function framesOrdered(frames) {
  try {
    if (!Array.isArray(frames) || frames.length !== 2) return false;
    const [first, second] = frames;
    return (
      first.id !== second.id &&
      monotonic(first.startedMonotonicNs) <= monotonic(first.endedMonotonicNs) &&
      monotonic(first.endedMonotonicNs) <= monotonic(second.startedMonotonicNs) &&
      monotonic(second.startedMonotonicNs) <= monotonic(second.endedMonotonicNs) &&
      monotonic(first.startedMonotonicNs) <= monotonic(first.observationCutoff.monotonicNs) &&
      monotonic(first.observationCutoff.monotonicNs) <= monotonic(first.endedMonotonicNs) &&
      monotonic(second.startedMonotonicNs) <= monotonic(second.observationCutoff.monotonicNs) &&
      monotonic(second.observationCutoff.monotonicNs) <= monotonic(second.endedMonotonicNs) &&
      rfc3339EpochNs(first.startedAt) <= rfc3339EpochNs(first.endedAt) &&
      rfc3339EpochNs(first.startedAt) <= rfc3339EpochNs(first.observationCutoff.at) &&
      rfc3339EpochNs(first.observationCutoff.at) <= rfc3339EpochNs(first.endedAt) &&
      rfc3339EpochNs(first.endedAt) <= rfc3339EpochNs(second.startedAt) &&
      rfc3339EpochNs(second.startedAt) <= rfc3339EpochNs(second.endedAt) &&
      rfc3339EpochNs(second.startedAt) <= rfc3339EpochNs(second.observationCutoff.at) &&
      rfc3339EpochNs(second.observationCutoff.at) <= rfc3339EpochNs(second.endedAt)
    );
  } catch {
    return false;
  }
}

function frameExposureNs(frames) {
  return (
    monotonic(frames[1].observationCutoff.monotonicNs) - monotonic(frames[0].startedMonotonicNs)
  );
}

function allFalsePredicates() {
  return Object.fromEntries(INDEPENDENT_PREDICATE_KEYS.map((key) => [key, false]));
}

function classification(disposition, stage, reasonCode, predicates, receipts = []) {
  return { disposition, stage, reasonCode, predicates, receipts };
}

function expectedDevice(candidate) {
  return {
    serial: candidate.identity.device.serial,
    vendorId: candidate.identity.device.vendorId,
    productId: candidate.identity.device.productId,
    epoch: clone(candidate.identity.device.revalidationEpoch),
  };
}

function expectedPid1(candidate) {
  const lifecycle = candidate.identity.lifecycle;
  return {
    hostPid: lifecycle.hostPid,
    startTicks: lifecycle.pid1StartTicks,
    pidNamespace: lifecycle.pidNamespace,
    mountNamespace: lifecycle.mountNamespace,
    cgroup: lifecycle.cgroup,
  };
}

function expectedReceipt(candidate, frames, capabilityAudit, exposureNs) {
  const [first, second] = frames;
  const body = {
    schemaVersion: 'overlaykit-h044-live-revalidation-receipt/v1',
    kind: 'cutoff-bound-live-readonly-revalidation',
    authority: 'none',
    action: null,
    authorizesAction: false,
    validAtCutoffOnly: true,
    revalidatedAtCutoff: true,
    requiresRevalidation: true,
    historicalCandidateTokenSha256: candidate.tokenSha256,
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
      containerObservation: clone(second.containerObservation),
      lifecycle: clone(second.lifecycle),
      pid1: clone(second.pid1),
      worker: clone(second.workers[0]),
    },
    markers: clone(second.markers),
    sources: {
      h043EvidenceSha256: candidate.sourceEvidenceSha256,
      h043PrefixSha256: candidate.prefixSha256,
      frameDigests: frames.map((frame) => frame.digestSha256),
      capabilityAuditSha256: sha256Canonical(capabilityAudit),
    },
  };
  return { ...body, receiptSha256: sha256Canonical(body) };
}

function independentClassification({
  historicalCandidate,
  frames,
  capabilityAudit,
  sourceAdmissionExact,
  auditVerification,
} = {}) {
  const predicates = allFalsePredicates();
  try {
    predicates.sourceAdmissionExact =
      sourceAdmissionExact === true && exactHistoricalCandidate(historicalCandidate);
    if (!predicates.sourceAdmissionExact) {
      return classification(
        'inconclusive',
        'source-admission',
        'source-admission-inexact',
        predicates
      );
    }
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
          frameExact(frame) &&
          frame.complete === true &&
          frame.device.complete === true &&
          frame.containerObservation.exact === true &&
          frame.absence.exact === true
      ) && new Set(frames.map((frame) => frame.digestSha256)).size === 2;
    if (!predicates.framesComplete) {
      return classification(
        'inconclusive',
        'frame-admission',
        'incomplete-or-invalid-live-frame',
        predicates
      );
    }
    predicates.auditExact = auditVerification.exact;
    if (!predicates.auditExact) {
      return classification(
        'inconclusive',
        'capability-audit',
        auditVerification.prohibitedObserved
          ? 'prohibited-capability-observed'
          : 'capability-audit-incomplete-or-inexact',
        predicates
      );
    }
    const [first, second] = frames;
    predicates.frameOrderExact = framesOrdered(frames);
    if (!predicates.frameOrderExact) {
      return classification('inconclusive', 'temporal-boundary', 'frame-order-invalid', predicates);
    }
    const exposureNs = frameExposureNs(frames);
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
    if (!same(first.absence, second.absence)) {
      return classification('inconclusive', 'live-drift', 'absence-state-drift', predicates);
    }
    if (
      first.device.present !== second.device.present ||
      !same(first.device.identity, second.device.identity)
    ) {
      return classification('inconclusive', 'live-drift', 'device-identity-drift', predicates);
    }
    if (!same(first.containerObservation, second.containerObservation)) {
      return classification(
        'inconclusive',
        'live-drift',
        'container-or-pid1-identity-drift',
        predicates
      );
    }
    if (!same(first.lifecycle, second.lifecycle) || !same(first.pid1, second.pid1)) {
      return classification(
        'inconclusive',
        'live-drift',
        'container-or-pid1-identity-drift',
        predicates
      );
    }
    if (frames.some((frame) => frame.workers.length > 1)) {
      return classification('inconclusive', 'identity', 'worker-ambiguity', predicates);
    }
    if (first.workers.length !== second.workers.length) {
      return classification('inconclusive', 'identity', 'worker-presence-drift', predicates);
    }
    if (first.workers.length === 1 && !same(first.workers[0], second.workers[0])) {
      return classification('inconclusive', 'identity', 'worker-identity-drift', predicates);
    }
    if (!same(first.descriptors, second.descriptors)) {
      return classification('inconclusive', 'live-drift', 'descriptor-state-drift', predicates);
    }
    predicates.markersStable = same(first.markers, second.markers);
    if (!predicates.markersStable) {
      return classification('inconclusive', 'live-drift', 'marker-drift', predicates);
    }

    predicates.deviceExact =
      first.device.present === true &&
      second.device.present === true &&
      same(first.device.identity, expectedDevice(historicalCandidate)) &&
      same(second.device.identity, expectedDevice(historicalCandidate));
    predicates.lifecycleExact =
      first.lifecycle !== null &&
      second.lifecycle !== null &&
      same(first.lifecycle, historicalCandidate.identity.lifecycle) &&
      same(second.lifecycle, historicalCandidate.identity.lifecycle);
    predicates.pid1Exact =
      first.pid1 !== null &&
      second.pid1 !== null &&
      same(first.pid1, expectedPid1(historicalCandidate)) &&
      same(second.pid1, expectedPid1(historicalCandidate));
    predicates.workerUnique = first.workers.length === 1 && second.workers.length === 1;
    predicates.workerExact =
      predicates.workerUnique &&
      same(first.workers[0], historicalCandidate.identity.worker) &&
      same(second.workers[0], historicalCandidate.identity.worker);
    predicates.descriptorAbsent = first.descriptors.length === 0 && second.descriptors.length === 0;

    if (first.containerObservation.present !== !first.absence.historicalContainerAbsent) {
      return classification(
        'inconclusive',
        'contradictory-evidence',
        'container-observation-contradiction',
        predicates
      );
    }
    if (
      first.absence.historicalContainerAbsent === true ||
      first.containerObservation.present === false ||
      first.containerObservation.state !== 'running' ||
      first.device.present === false ||
      first.lifecycle === null ||
      first.pid1 === null ||
      first.workers.length === 0
    ) {
      return classification(
        'withheld',
        'not-eligible',
        first.absence.historicalContainerAbsent === true
          ? 'historical-container-absent'
          : first.containerObservation.present === false
            ? 'historical-container-absent'
            : first.containerObservation.state !== 'running'
              ? 'container-not-running'
              : first.device.present === false
                ? 'device-absent'
                : first.workers.length === 0
                  ? 'surface-worker-absent'
                  : 'container-or-pid1-absent',
        predicates
      );
    }
    if (
      !predicates.deviceExact ||
      !predicates.lifecycleExact ||
      !predicates.pid1Exact ||
      !predicates.workerExact
    ) {
      return classification(
        'withheld',
        'not-eligible',
        'historical-identity-not-current',
        predicates
      );
    }
    if (!predicates.descriptorAbsent) {
      return classification('withheld', 'not-eligible', 'current-descriptor-present', predicates);
    }
    if (!Object.values(predicates).every((value) => value === true)) {
      return classification('inconclusive', 'classification', 'predicate-gap', predicates);
    }
    return classification(
      'candidate',
      'live-readonly-revalidation',
      'cutoff-bound-candidate-revalidated',
      predicates,
      [expectedReceipt(historicalCandidate, frames, capabilityAudit, exposureNs)]
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

function classifierCapabilityAuditExact(audit) {
  try {
    if (
      !exactKeys(audit, [
        'mode',
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
      ]) ||
      audit.mode !== 'live-readonly-capability-bounded' ||
      !Array.isArray(audit.commandReceipts) ||
      !audit.commandReceipts.every(
        (receipt) => plainObject(receipt) && ALLOWED_PROCESS_KEYS.includes(receipt.kind)
      ) ||
      !Array.isArray(audit.filesystemReceipts) ||
      !audit.filesystemReceipts.every(
        (receipt) => plainObject(receipt) && Object.keys(receipt).length > 0
      ) ||
      !exactKeys(audit.allowedProcessCounts, ALLOWED_PROCESS_KEYS) ||
      !ALLOWED_PROCESS_KEYS.every((key) => nonNegativeInteger(audit.allowedProcessCounts[key])) ||
      !nonNegativeInteger(audit.commandCount) ||
      !nonNegativeInteger(audit.filesystemReceiptCount) ||
      !exactKeys(audit.prohibitedCounts, PROHIBITED_COUNT_KEYS)
    ) {
      return false;
    }
    const counts = Object.fromEntries(ALLOWED_PROCESS_KEYS.map((key) => [key, 0]));
    for (const receipt of audit.commandReceipts) counts[receipt.kind] += 1;
    return (
      audit.commandReceipts.length === audit.commandCount &&
      audit.filesystemReceipts.length === audit.filesystemReceiptCount &&
      ALLOWED_PROCESS_KEYS.every(
        (key) =>
          counts[key] === audit.allowedProcessCounts[key] &&
          nonNegativeInteger(audit.allowedProcessCounts[key])
      ) &&
      audit.commandCount ===
        ALLOWED_PROCESS_KEYS.reduce((total, key) => total + audit.allowedProcessCounts[key], 0) &&
      audit.complete === true &&
      audit.exact === true &&
      audit.frameCount === 2 &&
      audit.lsusbCount === 1 &&
      audit.unrecordedObservationCount === 0 &&
      PROHIBITED_COUNT_KEYS.every(
        (key) =>
          nonNegativeInteger(audit.prohibitedCounts[key]) && audit.prohibitedCounts[key] === 0
      )
    );
  } catch {
    return false;
  }
}

function syntheticCapabilityAudit() {
  const allowedProcessCounts = {
    git: 3,
    lsusb: 1,
    dockerVersion: 1,
    dockerPs: 2,
    dockerInspect: 2,
    dockerLogs: 2,
  };
  const commandReceipts = Object.entries(allowedProcessCounts).flatMap(([kind, count]) =>
    Array.from({ length: count }, (_, receiptIndex) => ({ kind, receiptIndex }))
  );
  return {
    mode: 'live-readonly-capability-bounded',
    commandReceipts,
    filesystemReceipts: [{ operation: 'readFileSync', path: '/proc/synthetic' }],
    allowedProcessCounts,
    commandCount: commandReceipts.length,
    filesystemReceiptCount: 1,
    complete: true,
    exact: true,
    frameCount: 2,
    lsusbCount: 1,
    unrecordedObservationCount: 0,
    prohibitedCounts: Object.fromEntries(PROHIBITED_COUNT_KEYS.map((key) => [key, 0])),
  };
}

function sealFrame(frame) {
  const body = clone(frame);
  delete body.digestSha256;
  return { ...body, digestSha256: sha256Canonical(body) };
}

function syntheticFrames(candidate) {
  const common = {
    complete: true,
    host: {
      hostname: 'h044-synthetic-host',
      bootId: '00000000-0000-4000-8000-000000000044',
      osRelease: '{"id":"linux","prettyName":"H-044 synthetic","versionId":"1"}',
    },
    device: {
      complete: true,
      present: true,
      identity: expectedDevice(candidate),
    },
    containerObservation: {
      present: true,
      state: 'running',
      exact: true,
    },
    lifecycle: clone(candidate.identity.lifecycle),
    pid1: expectedPid1(candidate),
    workers: [clone(candidate.identity.worker)],
    descriptors: [],
    markers: {
      opening: 1,
      ready: 1,
      relevantLinesSha256: sha256Canonical(['synthetic-stable-markers']),
    },
    absence: {
      historicalContainerAbsent: false,
      exact: true,
    },
  };
  return [
    sealFrame({
      id: 'hostile-frame-1',
      startedAt: '2026-07-26T18:00:00.000Z',
      endedAt: '2026-07-26T18:00:00.900Z',
      startedMonotonicNs: '100000000000',
      endedMonotonicNs: '100900000000',
      observationCutoff: {
        at: '2026-07-26T18:00:00.800Z',
        monotonicNs: '100800000000',
      },
      auditBinding: {
        commandReceiptIndexes: [5, 7, 9],
        filesystemReceiptIndexes: [0],
      },
      ...clone(common),
    }),
    sealFrame({
      id: 'hostile-frame-2',
      startedAt: '2026-07-26T18:00:00.900Z',
      endedAt: '2026-07-26T18:00:01.800Z',
      startedMonotonicNs: '100900000000',
      endedMonotonicNs: '101800000000',
      observationCutoff: {
        at: '2026-07-26T18:00:01.700Z',
        monotonicNs: '101700000000',
      },
      auditBinding: {
        commandReceiptIndexes: [6, 8, 10],
        filesystemReceiptIndexes: [],
      },
      ...clone(common),
    }),
  ];
}

function reseal(frame) {
  Object.assign(frame, sealFrame(frame));
}

function hostileClassification(input) {
  const auditVerification = {
    exact: classifierCapabilityAuditExact(input.capabilityAudit),
    prohibitedObserved:
      plainObject(input.capabilityAudit?.prohibitedCounts) &&
      Object.values(input.capabilityAudit.prohibitedCounts).some(
        (value) => nonNegativeInteger(value) && value > 0
      ),
  };
  return independentClassification({ ...input, auditVerification });
}

function independentHostileMatrix(candidate) {
  const base = {
    historicalCandidate: clone(candidate),
    frames: syntheticFrames(candidate),
    capabilityAudit: syntheticCapabilityAudit(),
    sourceAdmissionExact: true,
  };
  const definitions = [
    {
      id: 'pid-reuse',
      disposition: 'inconclusive',
      reasonCode: 'worker-identity-drift',
      mutate(input) {
        input.frames[1].workers[0].startTicks += 1;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'worker-ambiguity',
      disposition: 'inconclusive',
      reasonCode: 'worker-ambiguity',
      mutate(input) {
        input.frames[1].workers.push(clone(input.frames[1].workers[0]));
        reseal(input.frames[1]);
      },
    },
    {
      id: 'parent-drift',
      disposition: 'inconclusive',
      reasonCode: 'worker-identity-drift',
      mutate(input) {
        input.frames[1].workers[0].parentStartTicks += 1;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'namespace-drift',
      disposition: 'inconclusive',
      reasonCode: 'worker-identity-drift',
      mutate(input) {
        input.frames[1].workers[0].pidNamespace += '-drift';
        reseal(input.frames[1]);
      },
    },
    {
      id: 'container-drift',
      disposition: 'inconclusive',
      reasonCode: 'container-or-pid1-identity-drift',
      mutate(input) {
        input.frames[1].lifecycle.restartCount += 1;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'pid1-drift',
      disposition: 'inconclusive',
      reasonCode: 'container-or-pid1-identity-drift',
      mutate(input) {
        input.frames[1].pid1.startTicks += 1;
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
        input.frames[1].device.identity.epoch.deviceNumber += '-drift';
        reseal(input.frames[1]);
      },
    },
    {
      id: 'descriptor-recovery',
      disposition: 'withheld',
      reasonCode: 'current-descriptor-present',
      mutate(input) {
        const descriptor = {
          descriptor: 'synthetic-fd',
          devicePath: input.historicalCandidate.identity.device.revalidationEpoch.devicePath,
        };
        for (const frame of input.frames) {
          frame.descriptors = [clone(descriptor)];
          reseal(frame);
        }
      },
    },
    {
      id: 'marker-change',
      disposition: 'inconclusive',
      reasonCode: 'marker-drift',
      mutate(input) {
        input.frames[1].markers.ready += 1;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'frame-reorder',
      disposition: 'inconclusive',
      reasonCode: 'frame-order-invalid',
      mutate(input) {
        input.frames[1].startedAt = input.frames[0].startedAt;
        input.frames[1].startedMonotonicNs = input.frames[0].startedMonotonicNs;
        reseal(input.frames[1]);
      },
    },
    {
      id: 'exposure-over-limit',
      disposition: 'inconclusive',
      reasonCode: 'exposure-window-exceeded',
      mutate(input) {
        input.frames[1].observationCutoff = {
          at: '2026-07-26T18:00:05.100Z',
          monotonicNs: '105100000000',
        };
        input.frames[1].endedAt = '2026-07-26T18:00:05.200Z';
        input.frames[1].endedMonotonicNs = '105200000000';
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
        input.historicalCandidate.tokenSha256 = '0'.repeat(64);
      },
    },
    {
      id: 'prohibited-capability',
      disposition: 'inconclusive',
      reasonCode: 'prohibited-capability-observed',
      mutate(input) {
        input.capabilityAudit.prohibitedCounts.signal = 1;
      },
    },
  ];
  const cases = definitions.map((definition) => {
    const input = clone(base);
    let result;
    let inputForDigest = input;
    if (definition.duplicateOutput) {
      const canonical = hostileClassification(input);
      const corrupted = clone(canonical);
      corrupted.receipts.push(clone(corrupted.receipts[0]));
      inputForDigest = { classification: corrupted };
      result = {
        disposition: 'inconclusive',
        stage: 'output-admission',
        reasonCode: 'duplicate-receipts-rejected',
        receipts: [],
      };
    } else {
      definition.mutate(input);
      result = hostileClassification(input);
    }
    const actualReceiptCount = Array.isArray(result.receipts) ? result.receipts.length : 0;
    const passed =
      result.disposition === definition.disposition &&
      result.reasonCode === definition.reasonCode &&
      actualReceiptCount === 0;
    return {
      id: definition.id,
      inputSha256: sha256Canonical(inputForDigest),
      expectedDisposition: definition.disposition,
      actualDisposition: result.disposition,
      expectedReceiptCount: 0,
      actualReceiptCount,
      stage: result.stage,
      reasonCode: result.reasonCode,
      passed,
    };
  });
  return {
    schemaVersion: 'overlaykit-h044-hostile-matrix/v1',
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

function exactInput(input, candidate) {
  return same(input, {
    h043ArchivePath: H043_ARCHIVE_RELATIVE_PATH,
    h043ArchiveSha256: H043_ARCHIVE_SHA256,
    h043RunId: H043_RUN_ID,
    h043RunSha256: H043_RUN_SHA256,
    h043VerificationSha256: H043_VERIFICATION_SHA256,
    h043EvidenceSha256: H043_EVIDENCE_SHA256,
    h043CandidateTokenSha256: candidate.tokenSha256,
  });
}

function protectedMainAncestryReceiptExact(audit) {
  const matches = (audit?.commandReceipts ?? []).filter(
    (receipt) =>
      receipt.kind === 'git' &&
      receipt.observerKind === 'gitMergeBaseAncestor' &&
      same(receipt.args, ['merge-base', '--is-ancestor', PROTECTED_MAIN_COMMIT, 'HEAD']) &&
      receipt.exitCode === 0 &&
      receipt.signal === null &&
      receipt.errorCode === null
  );
  return matches.length === 1;
}

async function governanceAndSources(run) {
  const [currentSources, manifestBytes, planBytes, chg0016Bytes, chg0017Bytes, adr0006Bytes] =
    await Promise.all([
      collectSourceReceipts(),
      readFile(path.join(REPOSITORY_ROOT, '.overlaykit/governance/manifest.json')),
      readFile(path.join(REPOSITORY_ROOT, '.overlaykit/governance/plan.json')),
      readFile(path.join(REPOSITORY_ROOT, '.overlaykit/governance/changes/CHG-0016.json')),
      readFile(path.join(REPOSITORY_ROOT, '.overlaykit/governance/changes/CHG-0017.json')),
      readFile(path.join(REPOSITORY_ROOT, '.overlaykit/governance/decisions/ADR-0006.json')),
    ]);
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  const plan = JSON.parse(planBytes.toString('utf8'));
  const chg0016Exact =
    sha256(chg0016Bytes) === CHG_0016_SHA256 && manifest.changes?.['CHG-0016'] === CHG_0016_SHA256;
  const chg0017Exact =
    sha256(chg0017Bytes) === CHG_0017_SHA256 && manifest.changes?.['CHG-0017'] === CHG_0017_SHA256;
  const adr0006Exact =
    sha256(adr0006Bytes) === ADR_0006_SHA256 &&
    manifest.decisions?.['ADR-0006'] === ADR_0006_SHA256;
  const governanceReceiptExact =
    run.collector?.governance?.changeId === 'CHG-0017' &&
    run.collector.governance.changeSha256 === CHG_0017_SHA256 &&
    run.collector.governance.planHash === PLAN_HASH &&
    run.collector.governance.manifestContentHash === MANIFEST_CONTENT_HASH;
  const governanceExact =
    chg0016Exact &&
    chg0017Exact &&
    adr0006Exact &&
    plan.planHash === PLAN_HASH &&
    manifest.planHash === PLAN_HASH &&
    manifest.contentHash === MANIFEST_CONTENT_HASH &&
    governanceReceiptExact;
  const sourceSetExact =
    same(run.collector?.sources, currentSources) &&
    same(
      run.collector?.sources?.map((entry) => entry.path),
      INDEPENDENT_REQUIRED_SOURCE_PATHS
    ) &&
    run.collector.sourceStable === true;
  const collectorIdentityExact =
    run.collector?.node === 'v22.20.0' &&
    run.collector.repository === REPOSITORY &&
    run.collector.baseCommit === PROTECTED_MAIN_COMMIT;
  return {
    currentSources,
    chg0016Exact,
    chg0017Exact,
    adr0006Exact,
    governanceExact,
    sourceSetExact,
    collectorIdentityExact,
  };
}

function expectedSourceAdmission(run, historical, repositoryEvidence) {
  const h043ArchiveExact =
    run.input?.h043ArchivePath === H043_ARCHIVE_RELATIVE_PATH &&
    run.input?.h043ArchiveSha256 === H043_ARCHIVE_SHA256;
  const h043RunExact =
    run.input?.h043RunId === H043_RUN_ID &&
    run.input?.h043RunSha256 === H043_RUN_SHA256 &&
    historical.run.runId === H043_RUN_ID &&
    historical.run.evidenceSha256 === H043_EVIDENCE_SHA256;
  const h043VerificationExact =
    run.input?.h043VerificationSha256 === H043_VERIFICATION_SHA256 &&
    historical.verification.runId === H043_RUN_ID &&
    historical.verification.evidenceSha256 === H043_EVIDENCE_SHA256 &&
    historical.verification.verified === true;
  const h043EvidenceExact =
    run.input?.h043EvidenceSha256 === H043_EVIDENCE_SHA256 && h043RunExact && h043VerificationExact;
  const h043CandidateTokenExact =
    run.input?.h043CandidateTokenSha256 === H043_CANDIDATE_TOKEN_SHA256 &&
    same(run.historicalCandidate, historical.candidate) &&
    run.historicalCandidate.tokenSha256 === H043_CANDIDATE_TOKEN_SHA256;
  const value = {
    h043ArchiveExact,
    h043RunExact,
    h043VerificationExact,
    h043EvidenceExact,
    h043CandidateTokenExact,
    chg0016Exact: repositoryEvidence.chg0016Exact,
    adr0006Exact: repositoryEvidence.adr0006Exact,
    protectedMainAncestryExact: protectedMainAncestryReceiptExact(run.capabilityAudit),
    governanceExact: repositoryEvidence.governanceExact,
    sourceSetExact: repositoryEvidence.sourceSetExact,
    allExact: false,
  };
  value.allExact = Object.entries(value)
    .filter(([key]) => key !== 'allExact')
    .every(([, exact]) => exact === true);
  return value;
}

function baseOutcome(sourceAdmission, auditVerification, liveClassification, matrixExact) {
  if (auditVerification.prohibitedObserved) {
    return {
      status: 'refuted',
      stage: 'capability-boundary',
      reasonCode: 'prohibited-capability-observed',
    };
  }
  if (!matrixExact) {
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
  if (auditVerification.exact !== true) {
    return {
      status: 'inconclusive',
      stage: 'capability-audit',
      reasonCode: 'capability-audit-incomplete-or-inexact',
    };
  }
  if (liveClassification.disposition === 'inconclusive') {
    return {
      status: 'inconclusive',
      stage: liveClassification.stage,
      reasonCode: liveClassification.reasonCode,
    };
  }
  if (['candidate', 'withheld'].includes(liveClassification.disposition)) {
    return {
      status: 'supported',
      stage: 'live-readonly-revalidation',
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

export async function verifyRun(runPath) {
  const [runBytes, schemaBytes, archiveBytes] = await Promise.all([
    readFile(runPath),
    readFile(SCHEMA_PATH),
    readFile(H043_ARCHIVE_PATH),
  ]);
  let run;
  try {
    run = JSON.parse(runBytes.toString('utf8'));
  } catch (error) {
    throw new Error('H-044 verification failed: run is not valid JSON', { cause: error });
  }
  const schema = JSON.parse(schemaBytes.toString('utf8'));
  const ajv = new Ajv2020({
    allErrors: true,
    strict: false,
    validateFormats: false,
  });
  const validate = ajv.compile(schema);
  assertion(validate(run), `schema invalid: ${ajv.errorsText(validate.errors)}`);

  const { evidenceSha256, ...record } = run;
  assertion(sha256Canonical(record) === evidenceSha256, 'evidence hash mismatch');
  assertion(
    validTimestamp(run.startedAt) &&
      validTimestamp(run.completedAt) &&
      rfc3339EpochNs(run.completedAt) >= rfc3339EpochNs(run.startedAt),
    'run timestamps are invalid or reversed'
  );

  const historical = admitHistoricalArchive(archiveBytes);
  assertion(
    run.runId ===
      `h044-${run.startedAt.replaceAll(':', '-').replace('.', '-')}-${sha256(
        `${run.startedAt}:${historical.candidate.tokenSha256}`
      ).slice(0, 8)}`,
    'run ID does not bind the start timestamp and accepted H-043 candidate'
  );

  const repositoryEvidence = await governanceAndSources(run);
  const sourceAdmission = expectedSourceAdmission(run, historical, repositoryEvidence);
  const sourceAdmissionReconstructed = same(run.sourceAdmission, sourceAdmission);
  const inputExact = exactInput(run.input, historical.candidate);
  const historicalCandidateExact = same(run.historicalCandidate, historical.candidate);

  const auditVerification = verifyCapabilityAudit(run.capabilityAudit, run);
  const frameDigestsExact =
    run.frames.length === 2 &&
    run.frames.every(frameExact) &&
    new Set(run.frames.map((frame) => frame.digestSha256)).size === 2;
  const framesReconstructed = frameDigestsExact && reconstructFrames(run);
  const frameCompleteness = verifyFrameCompleteness(run);
  const classificationAudit = {
    ...auditVerification,
    exact: auditVerification.exact && framesReconstructed && frameCompleteness.exact,
  };
  const liveClassification = independentClassification({
    historicalCandidate: historical.candidate,
    frames: run.frames,
    capabilityAudit: run.capabilityAudit,
    sourceAdmissionExact: sourceAdmission.allExact,
    auditVerification: classificationAudit,
  });
  const classificationExact = same(run.liveClassification, liveClassification);
  const receiptExact =
    liveClassification.disposition === 'candidate'
      ? liveClassification.receipts.length === 1 &&
        same(run.liveClassification.receipts, liveClassification.receipts)
      : liveClassification.receipts.length === 0 &&
        Array.isArray(run.liveClassification.receipts) &&
        run.liveClassification.receipts.length === 0;

  const hostileMatrix = independentHostileMatrix(historical.candidate);
  const hostileMatrixExact = same(run.hostileMatrix, hostileMatrix);
  const claimBoundaryExact = same(run.claimBoundary, INDEPENDENT_CLAIM_BOUNDARY);
  const framesExact = frameDigestsExact && framesReconstructed && frameCompleteness.exact;

  const independentlyExpectedOutcome = baseOutcome(
    sourceAdmission,
    classificationAudit,
    liveClassification,
    hostileMatrixExact
  );
  const outcomeExact = same(run.outcome, independentlyExpectedOutcome);
  const producerAgreement =
    sourceAdmissionReconstructed &&
    classificationExact &&
    receiptExact &&
    claimBoundaryExact &&
    outcomeExact &&
    inputExact &&
    historicalCandidateExact &&
    repositoryEvidence.collectorIdentityExact &&
    framesExact;
  const outcome = verificationOutcome(independentlyExpectedOutcome, producerAgreement);

  return {
    schemaVersion: 'overlaykit-h044-verification/v1',
    hypothesis: 'H-044',
    runId: run.runId,
    outcome: outcome.status,
    stage: outcome.stage,
    reasonCode: outcome.reasonCode,
    evidenceSha256,
    historicalArchiveExact: true,
    historicalRunExact: true,
    historicalVerificationExact: true,
    historicalCandidateExact,
    inputExact,
    collectorIdentityExact: repositoryEvidence.collectorIdentityExact,
    governanceExact: repositoryEvidence.governanceExact,
    sourceSetExact: repositoryEvidence.sourceSetExact,
    sourceAdmissionReconstructed,
    sourceAdmissionAllExact: sourceAdmission.allExact,
    commandAuditExact: auditVerification.commandExact,
    filesystemAuditExact: auditVerification.filesystemExact,
    capabilityAuditExact: auditVerification.exact,
    prohibitedCapabilityObserved: auditVerification.prohibitedObserved,
    auditBindingExact: auditVerification.bindingExact,
    frameDigestsExact,
    framesReconstructed,
    frameCompletenessExact: frameCompleteness.exact,
    recomputedFrameCompleteness: frameCompleteness.recomputed,
    framesExact,
    frameOrderExact: framesOrdered(run.frames),
    exposureMilliseconds: Number(frameExposureNs(run.frames)) / 1_000_000,
    classificationExact,
    receiptExact,
    liveDisposition: liveClassification.disposition,
    hostileMatrixExact,
    claimBoundaryExact,
    producerAgreement,
    verified: true,
  };
}

function requestedRunPath() {
  const index = process.argv.indexOf('--run');
  assertion(index !== -1, '--run is required');
  assertion(process.argv[index + 1], '--run requires a path');
  return path.resolve(REPOSITORY_ROOT, process.argv[index + 1]);
}

function isDirectInvocation() {
  return process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
}

if (isDirectInvocation()) {
  try {
    const runPath = requestedRunPath();
    const verification = await verifyRun(runPath);
    const outputPath = path.join(path.dirname(runPath), 'verification.json');
    await writeFile(outputPath, `${JSON.stringify(verification, null, 2)}\n`, {
      flag: 'wx',
    });
    process.stdout.write(
      `${JSON.stringify({
        runId: verification.runId,
        verified: verification.verified,
        outcome: verification.outcome,
        stage: verification.stage,
        reasonCode: verification.reasonCode,
        evidenceSha256: verification.evidenceSha256,
        verificationPath: path.relative(REPOSITORY_ROOT, outputPath),
      })}\n`
    );
  } catch (error) {
    process.stderr.write(`${error.stack ?? error.message}\n`);
    process.exitCode = 1;
  }
}
