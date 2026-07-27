import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
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
import { PassThrough } from 'node:stream';
import test from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';

import {
  H044_PUBLIC_RECEIPT_PATH,
  H045_ACCEPTED_SERIAL_BINDING,
  H045_ADR_0006_SHA256,
  H045_CHG_0018_SHA256,
  H045_CHG_0019_SHA256,
  H045_CHG_0020_SHA256,
  H045_GOVERNANCE_MANIFEST_SHA256,
  H045_GOVERNANCE_PLAN_SHA256,
  H045_MANIFEST_CONTENT_HASH,
  H045_NODE_ARCH,
  H045_NODE_BINARY_BYTE_LENGTH,
  H045_NODE_BINARY_SHA256,
  H045_NODE_PLATFORM,
  H045_NODE_VERSION,
  H045_PLAN_HASH,
  H045_PROTECTED_MAIN_COMMIT,
  H045_REPOSITORY,
  H045_REQUIRED_SOURCE_PATHS,
  H045_SOURCE_CONTRACT_COMMIT,
  H045_STABLE_TARGET_INPUT,
  readHistoricalEvidence,
  sourceSetSha256,
} from './admission-lib.mjs';
import { classifyDynamicFrames, frameExactShape, sha256Canonical } from './classifier-lib.mjs';
import {
  H045_CLAIM_BOUNDARY,
  H045_LIVE_AUTHORIZATION,
  H045_REQUIRED_CASE_IDS,
  MAX_LEDGER_RECEIPT_BYTES,
  MAX_RUN_JSON_BYTES,
  createAbsoluteCommandRunner,
  createOfflineAttemptLedgerForTest,
  evaluateHostileMatrix,
  h045LiveAuthorization,
  h046CanonicalCommandEnvironment,
  normalizeObservationFrame,
  outcomeFor,
  persistRun,
  runH045,
  runH045OfflineFixture,
} from './run.mjs';

const ADR_0006_URL = new URL(
  '../../.overlaykit/governance/decisions/ADR-0006.json',
  import.meta.url
);
const SCHEMA_URL = new URL('./schemas/live-run.schema.json', import.meta.url);
const RUN_URL = new URL('./run.mjs', import.meta.url);
const ARTIFACT_ROOT = fileURLToPath(new URL('../../artifacts/h045/', import.meta.url));
const CONTAINER_ID = 'c'.repeat(64);
const PREDECESSOR_RESERVATION_SHA256 =
  '27ee9aa2c70adb56682564c6ddc80c43cc40e6a5c5e1edacc23327648aad2f24';
const PREDECESSOR_FAILURE_SHA256 =
  '710b3b28760239f5971c961f8b0011a18c439c10a4974f548c435ff2a4507fc0';
const PREDECESSOR_ATTEMPT_DIRECTORY = 'live-attempt';
const REPLACEMENT_ATTEMPT_DIRECTORY = 'h045-chg-0020-attempt-1';

function clone(value) {
  return structuredClone(value);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function prettyJsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

async function seedPredecessorAttempt(root) {
  const reservation = {
    schemaVersion: 'overlaykit-h045-live-attempt-reservation/v1',
    reservedAt: '2026-07-27T17:19:02.332Z',
    change: 'CHG-0019',
    hypothesis: 'H-045',
    authorization: {
      grant:
        'CHG-0019:one-readonly-run:sha256:' +
        '7230be4ed41b469a9e8486ff757c349eff48035e393c4825542c0ad2c201fab2',
      sourceSetSha256: '7230be4ed41b469a9e8486ff757c349eff48035e393c4825542c0ad2c201fab2',
      semantics: 'one-live-read-only-attempt',
      authority: 'none',
      action: null,
    },
  };
  const failure = {
    schemaVersion: 'overlaykit-h045-live-attempt-failure/v1',
    reservationSha256: PREDECESSOR_RESERVATION_SHA256,
    stage: 'runtime-admission',
    observationStarted: true,
  };
  const reservationBytes = prettyJsonBytes(reservation);
  const failureBytes = prettyJsonBytes(failure);
  assert.equal(sha256(reservationBytes), PREDECESSOR_RESERVATION_SHA256);
  assert.equal(sha256(failureBytes), PREDECESSOR_FAILURE_SHA256);
  const directory = path.join(root, PREDECESSOR_ATTEMPT_DIRECTORY);
  await mkdir(root, { recursive: true, mode: 0o700 });
  await chmod(root, 0o700);
  await mkdir(directory, { mode: 0o700 });
  await Promise.all([
    writeFile(path.join(directory, 'reservation.json'), reservationBytes, {
      flag: 'wx',
      mode: 0o600,
    }),
    writeFile(path.join(directory, 'failure.json'), failureBytes, {
      flag: 'wx',
      mode: 0o600,
    }),
  ]);
  return { directory, reservationBytes, failureBytes };
}

function acceptedTarget(serial = 'TEST-MK2-0001') {
  return {
    imageReference: 'ghcr.io/bitfocus/companion/companion:v4.3.3',
    imageId: 'sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e',
    vendorId: '0fd9',
    productId: '0080',
    serial,
    serialBinding: clone(H045_ACCEPTED_SERIAL_BINDING),
  };
}

function statIdentity() {
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

function rawFrame({ frameId = 'frame-1', second = false, serial = 'TEST-MK2-0001' } = {}) {
  const timing = second
    ? {
        startedAt: '2026-07-27T03:00:10.900Z',
        endedAt: '2026-07-27T03:00:11.800Z',
        startedMonotonicNs: '200900000000',
        endedMonotonicNs: '201800000000',
        observationCutoff: {
          at: '2026-07-27T03:00:11.700Z',
          monotonicNs: '201700000000',
        },
      }
    : {
        startedAt: '2026-07-27T03:00:10.000Z',
        endedAt: '2026-07-27T03:00:10.900Z',
        startedMonotonicNs: '200000000000',
        endedMonotonicNs: '200900000000',
        observationCutoff: {
          at: '2026-07-27T03:00:10.800Z',
          monotonicNs: '200800000000',
        },
      };
  return {
    schemaVersion: 'overlaykit-h045-observation-frame/v1',
    frameId,
    ...timing,
    exposureNs: second ? '900000000' : '900000000',
    complete: true,
    errors: [],
    host: {
      hostname: 'fixture-host',
      bootId: '00000000-0000-4000-8000-000000000045',
      osRelease: {
        id: 'linux',
        versionId: '1',
        prettyName: 'Fixture Linux',
      },
    },
    device: {
      selector: {
        serial,
        vendorId: '0fd9',
        productId: '0080',
      },
      complete: true,
      present: true,
      status: 'unique',
      matchCount: 1,
      selectedEpoch: {
        serial,
        vendorId: '0fd9',
        productId: '0080',
        busNumber: '1',
        deviceNumber: '42',
        usbDevicePath: '2',
        usbDev: '189:41',
        hidDevicePath: '/sys/fixtures/0003:0FD9:0080.0042',
        devicePath: '/dev/hidraw0',
        stat: statIdentity(),
        hidrawName: 'hidraw0',
        lsusbMatched: true,
      },
      lsusbMatches: [],
      usbEpochs: [],
      targetSerialContradictionCount: 0,
      hidrawEntries: [],
    },
    docker: {
      version: {
        client: { version: 'fixture', apiVersion: '1.47' },
        server: { version: 'fixture', apiVersion: '1.47' },
      },
      inventory: {
        selector: {
          kind: 'ancestor-image-id',
          imageId: 'sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e',
          filter:
            'ancestor=sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e',
          unixHost: 'unix:///var/run/docker.sock',
          projection: '{"ID":{{json .ID}},"State":{{json .State}}}',
        },
        matches: [{ containerId: CONTAINER_ID, state: 'running' }],
        matchCount: 1,
        status: 'unique',
        exact: true,
        commandReceiptIndex: second ? 9 : 6,
      },
      selected: { containerId: CONTAINER_ID, state: 'running' },
      inspectExact: true,
      lifecycle: {
        containerId: CONTAINER_ID,
        imageId: 'sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e',
        status: 'running',
        running: true,
        hostPid: 4242,
        startedAt: '2026-07-27T03:00:00.000Z',
        restartCount: 0,
        cgroupNamespaceMode: 'private',
        pid1StartTicks: 7000,
        pidNamespace: 'pid:[4026533001]',
        mountNamespace: 'mnt:[4026533002]',
        cgroup: '0::/',
        hostCgroup: `0::/system.slice/docker-${CONTAINER_ID}.scope`,
      },
      logWindow: {
        since: '2026-07-27T03:00:00.000Z',
        until: timing.observationCutoff.at,
      },
      markers: {
        entries: [],
        serialAvailable: true,
        openingCount: 4,
        readyCount: 4,
        relevantLinesSha256: 'a'.repeat(64),
      },
    },
    processes: {
      procRoot: '/proc/4242/root/proc',
      stable: true,
      pid1: {
        pid: 1,
        startTicks: 7000,
        ppid: 0,
        parentStartTicks: null,
        uid: 1000,
        gid: 1000,
        groups: [1000, 1002],
        command: 'tini',
        cmdline: ['/sbin/tini'],
        cgroup: '0::/',
        pidNamespace: 'pid:[4026533001]',
        mountNamespace: 'mnt:[4026533002]',
      },
      all: [],
      surfaceWorkers: [
        {
          pid: 73,
          startTicks: 7100,
          ppid: 1,
          parentStartTicks: 7000,
          uid: 1000,
          gid: 1000,
          groups: [1000, 1002],
          command: 'node',
          cmdline: [
            '/app/node-runtimes/node22/bin/node',
            '--enable-source-maps',
            '/app/SurfaceThread.js',
          ],
          cgroup: '0::/',
          pidNamespace: 'pid:[4026533001]',
          mountNamespace: 'mnt:[4026533002]',
          fileDescriptors: [],
          descriptorTableStable: true,
        },
      ],
    },
    auditBinding: {
      commandReceiptIndexes: second ? [9, 10, 11] : [6, 7, 8],
      filesystemReceiptIndexes: second ? [1] : [0],
    },
    auditCursor: {
      commandCardinality: {},
      filesystemCardinality: {},
      rejectedCommandAttempts: 0,
      rejectedFilesystemAttempts: 0,
    },
  };
}

function rawMultipleFrame({ second = false, serial = 'TEST-MK2-0001' } = {}) {
  const frame = rawFrame({
    frameId: second ? 'frame-2' : 'frame-1',
    second,
    serial,
  });
  frame.complete = false;
  frame.errors = [
    {
      stage: 'docker-inventory',
      code: 'MULTIPLE_IMAGE_MATCHES',
      receiptIndex: second ? 9 : 6,
    },
  ];
  frame.docker.inventory.matches.push({
    containerId: 'd'.repeat(64),
    state: 'running',
  });
  frame.docker.inventory.matchCount = 2;
  frame.docker.inventory.status = 'multiple';
  frame.docker.selected = null;
  frame.docker.inspectExact = false;
  frame.docker.lifecycle = null;
  frame.docker.logWindow.until = null;
  frame.processes = {
    procRoot: null,
    stable: false,
    pid1: null,
    all: [],
    surfaceWorkers: [],
  };
  frame.auditBinding.commandReceiptIndexes = [second ? 9 : 6];
  return frame;
}

function rawDeviceAbsentFrame({
  frameId = 'frame-1',
  second = false,
  serial = 'TEST-MK2-0001',
} = {}) {
  const frame = rawFrame({ frameId, second, serial });
  frame.device = {
    selector: {
      serial,
      vendorId: '0fd9',
      productId: '0080',
    },
    complete: true,
    present: false,
    status: 'none',
    matchCount: 0,
    selectedEpoch: null,
    lsusbMatches: [],
    usbEpochs: [],
    targetSerialContradictionCount: 0,
    hidrawEntries: [],
  };
  frame.processes.surfaceWorkers[0].fileDescriptors = [];
  frame.processes.surfaceWorkers[0].descriptorTableStable = false;
  return frame;
}

function syntheticClassifierFixture(target) {
  let baseline = null;
  let deviceAbsent = null;
  const matrix = evaluateHostileMatrix((input) => {
    const classification = classifyDynamicFrames(input);
    if (classification.disposition === 'candidate' && baseline === null) {
      baseline = {
        frames: clone(input.frames),
        capabilityAudit: clone(input.capabilityAudit),
        classification: clone(classification),
      };
    }
    if (
      classification.disposition === 'withheld' &&
      classification.reasonCode === 'device-absent' &&
      deviceAbsent === null
    ) {
      deviceAbsent = {
        frames: clone(input.frames),
        capabilityAudit: clone(input.capabilityAudit),
        classification: clone(classification),
      };
    }
    return classification;
  }, target);
  assert.notEqual(baseline, null, 'hostile matrix must exercise one exact candidate baseline');
  assert.notEqual(deviceAbsent, null, 'hostile matrix must exercise exact current device absence');
  return { ...baseline, deviceAbsent, matrix };
}

function omitFilesystemReceipt(input, omittedIndex) {
  input.capabilityAudit.filesystemReceipts.splice(omittedIndex, 1);
  const operationOrdinals = new Map();
  input.capabilityAudit.filesystemReceipts.forEach((receipt, index) => {
    const operationOrdinal = (operationOrdinals.get(receipt.operation) ?? 0) + 1;
    operationOrdinals.set(receipt.operation, operationOrdinal);
    receipt.index = index;
    receipt.cardinality.global = index + 1;
    receipt.cardinality.operation = operationOrdinal;
  });
  input.capabilityAudit.filesystemReceiptCount = input.capabilityAudit.filesystemReceipts.length;
  for (const frame of input.frames) {
    frame.auditBinding.filesystemReceiptIndexes = frame.auditBinding.filesystemReceiptIndexes
      .filter((index) => index !== omittedIndex)
      .map((index) => (index > omittedIndex ? index - 1 : index));
    const body = clone(frame);
    delete body.digestSha256;
    frame.digestSha256 = sha256Canonical(body);
  }
}

function sourceMap(suffix = '') {
  return H045_REQUIRED_SOURCE_PATHS.map((relativePath) => ({
    path: relativePath,
    sha256: sha256(`${relativePath}${suffix}`),
  }));
}

async function admissionFixture() {
  const [publicReceipt, decision] = await Promise.all([
    readFile(H044_PUBLIC_RECEIPT_PATH),
    readFile(ADR_0006_URL),
  ]);
  return {
    historical: readHistoricalEvidence(publicReceipt, decision),
    governance: {
      verified: true,
      planHash: H045_PLAN_HASH,
      planSha256: H045_GOVERNANCE_PLAN_SHA256,
      manifestContentHash: H045_MANIFEST_CONTENT_HASH,
      manifestSha256: H045_GOVERNANCE_MANIFEST_SHA256,
      changes: {
        'CHG-0018': H045_CHG_0018_SHA256,
        'CHG-0019': H045_CHG_0019_SHA256,
        'CHG-0020': H045_CHG_0020_SHA256,
      },
      decisions: {
        'ADR-0006': H045_ADR_0006_SHA256,
      },
      requiredSourcePaths: [...H045_REQUIRED_SOURCE_PATHS],
    },
  };
}

function runtimeFixture() {
  return {
    node: H045_NODE_VERSION,
    platform: H045_NODE_PLATFORM,
    arch: H045_NODE_ARCH,
    binarySha256: H045_NODE_BINARY_SHA256,
    binaryByteLength: H045_NODE_BINARY_BYTE_LENGTH,
  };
}

function validatingStub() {
  const validate = () => true;
  validate.errors = null;
  return validate;
}

function completeOfflineDependencies(overrides = {}) {
  const unreachable = (name) => () => {
    throw new Error(`offline dependency ${name} must not be reached`);
  };
  return {
    captureRuntimeReceipt: unreachable('captureRuntimeReceipt'),
    sourceReceipts: unreachable('sourceReceipts'),
    loadAdmission: unreachable('loadAdmission'),
    createCommandAuditor: unreachable('createCommandAuditor'),
    createFilesystemAuditor: unreachable('createFilesystemAuditor'),
    captureGitAdmission: unreachable('captureGitAdmission'),
    captureLsusbAdmission: unreachable('captureLsusbAdmission'),
    captureDockerAdmission: unreachable('captureDockerAdmission'),
    captureObservationFrame: unreachable('captureObservationFrame'),
    buildCapabilityAudit: unreachable('buildCapabilityAudit'),
    classifyDynamicFrames: unreachable('classifyDynamicFrames'),
    evaluateHostileMatrix: unreachable('evaluateHostileMatrix'),
    compileSchema: unreachable('compileSchema'),
    ...overrides,
  };
}

function offlineFixtureOptions({
  reviewedSourceSha256,
  attemptLedger,
  dependencies,
  wallNow = () => '2026-07-27T03:00:00.000Z',
  monotonicNowNs = () => 0n,
  persistFixture = async () => '/offline-fixture/run.json',
} = {}) {
  return {
    reviewedSourceSha256,
    wallNow,
    monotonicNowNs,
    runner: async () => {
      throw new Error('offline fixture runner must not be reached');
    },
    filesystem: {},
    environment: {},
    attemptLedger,
    dependencies,
    persistFixture,
  };
}

async function runFixture({ sourceMaps = [sourceMap(), sourceMap(), sourceMap()] } = {}) {
  const events = [];
  const admitted = await admissionFixture();
  const serial = admitted.historical.acceptedTarget.serial;
  const synthetic = syntheticClassifierFixture(admitted.historical.acceptedTarget);
  let sourceCall = 0;
  const persisted = [];
  const observedTargets = [];
  const attemptReceipts = [];
  const reservationSha256 = '9'.repeat(64);
  const reviewedSourceSha256 = sourceSetSha256(sourceMaps[0]);
  const attemptLedger = {
    async reserve(input) {
      events.push('attempt-reserve');
      attemptReceipts.push({ kind: 'reservation', ...clone(input) });
      return { sha256: reservationSha256 };
    },
    async fail(input) {
      events.push('attempt-failure');
      attemptReceipts.push({ kind: 'failure', ...clone(input) });
      return { sha256: '8'.repeat(64) };
    },
    async complete(input) {
      events.push('attempt-complete');
      attemptReceipts.push({ kind: 'completion', ...clone(input) });
      return { sha256: '7'.repeat(64) };
    },
  };
  const dependencies = {
    async compileSchema() {
      events.push('schema');
      return validatingStub();
    },
    async captureRuntimeReceipt() {
      events.push('runtime');
      return runtimeFixture();
    },
    async sourceReceipts() {
      const current = sourceMaps[sourceCall];
      sourceCall += 1;
      events.push(`sources-${sourceCall}`);
      return clone(current);
    },
    async loadAdmission() {
      events.push('admission-materials');
      return clone(admitted);
    },
    createCommandAuditor() {
      events.push('command-auditor');
      return { kind: 'fake-command-auditor' };
    },
    createFilesystemAuditor() {
      events.push('filesystem-auditor');
      return { kind: 'fake-filesystem-auditor' };
    },
    async captureGitAdmission() {
      events.push('git');
      return {
        head: 'f'.repeat(40),
        protectedMainCommit: H045_PROTECTED_MAIN_COMMIT,
        protectedMainIsAncestor: true,
        sourceContractCommit: H045_SOURCE_CONTRACT_COMMIT,
        sourceContractIsAncestor: true,
        remoteUrl: H045_REPOSITORY,
        commandReceiptIndexes: [0, 1, 2, 3],
      };
    },
    async captureLsusbAdmission() {
      events.push('lsusb');
      return { devices: [], commandReceiptIndex: 4, stdoutSha256: 'a'.repeat(64) };
    },
    async captureDockerAdmission() {
      events.push('docker');
      return {
        version: {},
        commandReceiptIndex: 5,
        stdoutSha256: 'b'.repeat(64),
        unixHost: 'unix:///var/run/docker.sock',
      };
    },
    async captureObservationFrame(options) {
      events.push(options.frameId);
      observedTargets.push(clone(options.target));
      const frame = rawFrame({
        frameId: options.frameId,
        second: options.frameId === 'frame-2',
        serial,
      });
      const index = options.frameId === 'frame-2' ? 1 : 0;
      const expected = synthetic.frames[index];
      frame.host = {
        hostname: expected.host.hostname,
        bootId: expected.host.bootId,
        osRelease: JSON.parse(expected.host.osRelease),
      };
      frame.device.selectedEpoch.hidDevicePath = expected.device.identity.epoch.hidDevicePath;
      frame.docker.markers.openingCount = expected.deploymentInventory.matches[0].markers.opening;
      frame.docker.markers.readyCount = expected.deploymentInventory.matches[0].markers.ready;
      frame.docker.markers.relevantLinesSha256 =
        expected.deploymentInventory.matches[0].markers.relevantLinesSha256;
      frame.auditBinding = clone(expected.auditBinding);
      return frame;
    },
    buildCapabilityAudit() {
      events.push('capability-audit');
      return clone(synthetic.capabilityAudit);
    },
    classifyDynamicFrames(input) {
      return classifyDynamicFrames(input);
    },
    evaluateHostileMatrix(classifier, target) {
      return evaluateHostileMatrix(classifier, target);
    },
  };
  const wallTimes = ['2026-07-27T03:00:00.000Z', '2026-07-27T03:00:12.000Z'];
  const fixture = await runH045OfflineFixture({
    reviewedSourceSha256,
    wallNow: () => wallTimes.shift(),
    monotonicNowNs: () => 0n,
    runner: async () => {
      throw new Error('fake run must not invoke a real command runner');
    },
    filesystem: {},
    environment: {},
    attemptLedger,
    dependencies,
    async persistFixture(run) {
      events.push('persist');
      persisted.push(clone(run));
      return `/offline-fixture/${run.runId}/run.json`;
    },
  });
  const result = fixture.fixtureResult;
  return {
    ...result,
    fixtureBoundary: fixture.fixtureBoundary,
    events,
    admitted,
    persisted,
    observedTargets,
    attemptReceipts,
    reviewedSourceSha256,
  };
}

function childRun(args) {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [fileURLToPath(RUN_URL), ...args],
      { encoding: 'utf8' },
      (error, stdout, stderr) => {
        resolve({
          exitCode: error?.code ?? 0,
          stdout,
          stderr,
        });
      }
    );
  });
}

test('normalizes one exact inspected raw row without accepting a historical volatile input', () => {
  const target = acceptedTarget();
  const normalized = normalizeObservationFrame(rawFrame(), target);

  assert.equal(frameExactShape(normalized), true);
  assert.equal(normalized.complete, true);
  assert.deepEqual(normalized.deploymentInventory.rows, [
    { containerId: CONTAINER_ID, state: 'running' },
  ]);
  assert.equal(normalized.deploymentInventory.matches.length, 1);
  assert.equal(normalized.deploymentInventory.matches[0].container.id, CONTAINER_ID);
  assert.equal(normalized.deploymentInventory.matches[0].workers[0].pid, 73);
  assert.equal(normalized.device.identity.serial, target.serial);
  assert.equal(JSON.stringify(normalized).includes('historical'), false);
});

test('preserves multiple raw rows as complete ambiguity and invents no inspected match', () => {
  const target = acceptedTarget();
  const normalized = normalizeObservationFrame(rawMultipleFrame(), target);

  assert.equal(frameExactShape(normalized), true);
  assert.equal(normalized.complete, true);
  assert.equal(normalized.deploymentInventory.complete, true);
  assert.equal(normalized.deploymentInventory.rows.length, 2);
  assert.deepEqual(normalized.deploymentInventory.matches, []);
  assert.equal(
    normalized.deploymentInventory.rows.every(
      (row) => !Object.hasOwn(row, 'imageId') && !Object.hasOwn(row, 'imageReference')
    ),
    true
  );
});

test('rejects a contradictory raw docker selector projection before classification', () => {
  const target = acceptedTarget();
  const raw = rawFrame();
  raw.docker.inventory.selector.projection = '{{json .ID}}';

  const normalized = normalizeObservationFrame(raw, target);

  assert.equal(normalized.complete, false);
  assert.equal(normalized.deploymentInventory.exact, false);
  assert.deepEqual(normalized.deploymentInventory.matches, []);
});

test('normalizes exact raw device absence and classifies it as withheld', async () => {
  const target = (await admissionFixture()).historical.acceptedTarget;
  const synthetic = syntheticClassifierFixture(target).deviceAbsent;
  const frames = [false, true].map((second, index) => {
    const raw = rawDeviceAbsentFrame({
      frameId: `frame-${index + 1}`,
      second,
      serial: target.serial,
    });
    const expected = synthetic.frames[index];
    raw.host = {
      hostname: expected.host.hostname,
      bootId: expected.host.bootId,
      osRelease: JSON.parse(expected.host.osRelease),
    };
    raw.docker.markers.openingCount = expected.deploymentInventory.matches[0].markers.opening;
    raw.docker.markers.readyCount = expected.deploymentInventory.matches[0].markers.ready;
    raw.docker.markers.relevantLinesSha256 =
      expected.deploymentInventory.matches[0].markers.relevantLinesSha256;
    raw.auditBinding = clone(expected.auditBinding);
    return normalizeObservationFrame(raw, target);
  });

  assert.equal(
    frames.every((frame) => frame.complete),
    true
  );
  assert.equal(
    frames.every(
      (frame) =>
        frame.device.present === false &&
        frame.deploymentInventory.matches[0].descriptors.length === 0
    ),
    true
  );
  const classification = classifyDynamicFrames({
    frames,
    capabilityAudit: synthetic.capabilityAudit,
    sourceAdmissionExact: true,
  });
  assert.equal(classification.disposition, 'withheld');
  assert.equal(classification.stage, 'not-eligible');
  assert.equal(classification.reasonCode, 'device-absent');
  assert.deepEqual(classification.receipts, []);
});

test('produces one exact classifier candidate from a fully audited adjacent-frame baseline', async () => {
  const target = (await admissionFixture()).historical.acceptedTarget;
  const { classification } = syntheticClassifierFixture(target);

  assert.equal(classification.disposition, 'candidate');
  assert.equal(classification.receipts.length, 1);
  assert.equal(classification.receipts[0].authority, 'none');
  assert.equal(classification.receipts[0].action, null);
});

test('matches the observer process-table sequence and rejects a missing second snapshot', async () => {
  const target = (await admissionFixture()).historical.acceptedTarget;
  const synthetic = syntheticClassifierFixture(target);
  const exactInput = {
    frames: clone(synthetic.frames),
    capabilityAudit: clone(synthetic.capabilityAudit),
    sourceAdmissionExact: true,
  };
  const procRoot = `/proc/${exactInput.frames[0].deploymentInventory.matches[0].lifecycle.hostPid}/root/proc`;

  for (const frame of exactInput.frames) {
    const procRootIndexes = frame.auditBinding.filesystemReceiptIndexes.filter((index) => {
      const receipt = exactInput.capabilityAudit.filesystemReceipts[index];
      return receipt.operation === 'readdirSync' && receipt.path === procRoot;
    });
    assert.equal(procRootIndexes.length, 2);
    assert.deepEqual(
      exactInput.capabilityAudit.filesystemReceipts[procRootIndexes[0]].result,
      exactInput.capabilityAudit.filesystemReceipts[procRootIndexes[1]].result
    );
  }
  assert.equal(classifyDynamicFrames(exactInput).disposition, 'candidate');

  const missingSecondSnapshot = clone(exactInput);
  const firstFrame = missingSecondSnapshot.frames[0];
  const secondSnapshotIndex = firstFrame.auditBinding.filesystemReceiptIndexes.filter((index) => {
    const receipt = missingSecondSnapshot.capabilityAudit.filesystemReceipts[index];
    return receipt.operation === 'readdirSync' && receipt.path === procRoot;
  })[1];
  omitFilesystemReceipt(missingSecondSnapshot, secondSnapshotIndex);

  const classification = classifyDynamicFrames(missingSecondSnapshot);
  assert.equal(classification.disposition, 'inconclusive');
  assert.equal(classification.stage, 'capability-audit');
  assert.equal(classification.reasonCode, 'capability-audit-incomplete-or-inexact');
  assert.deepEqual(classification.receipts, []);
});

test('executes the exact ordered 23-case hostile matrix with zero unsafe positives', async () => {
  const target = (await admissionFixture()).historical.acceptedTarget;
  const matrix = evaluateHostileMatrix(classifyDynamicFrames, target);
  assert.deepEqual(matrix.requiredCaseIds, H045_REQUIRED_CASE_IDS);
  assert.equal(matrix.caseCount, 23);
  assert.equal(matrix.passedCount, 23);
  assert.equal(matrix.allPassed, true);
  assert.equal(
    matrix.cases.every((entry) => entry.actualReceiptCount === 0),
    true
  );
});

test('preserves hostile classifier receipt cardinality without truncation', async () => {
  const target = (await admissionFixture()).historical.acceptedTarget;
  const matrix = evaluateHostileMatrix(
    () => ({
      disposition: 'inconclusive',
      stage: 'hostile-fixture',
      reasonCode: 'hostile-fixture',
      predicates: {},
      receipts: [{ forged: 1 }, { forged: 2 }],
    }),
    target
  );

  assert.equal(
    matrix.cases.find((entry) => entry.id === 'multiple-image-matches').actualReceiptCount,
    2
  );
  assert.equal(matrix.allPassed, false);
});

test('fails closed when a bound, digest-exact filesystem receipt targets /etc/shadow', async () => {
  const target = (await admissionFixture()).historical.acceptedTarget;
  const synthetic = syntheticClassifierFixture(target);
  const input = {
    frames: clone(synthetic.frames),
    capabilityAudit: clone(synthetic.capabilityAudit),
    sourceAdmissionExact: true,
  };
  const frame = input.frames[1];
  const template =
    input.capabilityAudit.filesystemReceipts[frame.auditBinding.filesystemReceiptIndexes[0]];
  const extra = clone(template);
  extra.index = input.capabilityAudit.filesystemReceipts.length;
  extra.path = '/etc/shadow';
  extra.cardinality.global = extra.index + 1;
  extra.cardinality.operation =
    input.capabilityAudit.filesystemReceipts.filter(
      (receipt) => receipt.operation === extra.operation
    ).length + 1;
  input.capabilityAudit.filesystemReceipts.push(extra);
  input.capabilityAudit.filesystemReceiptCount += 1;
  frame.auditBinding.filesystemReceiptIndexes.push(extra.index);
  const frameBody = clone(frame);
  delete frameBody.digestSha256;
  frame.digestSha256 = sha256Canonical(frameBody);

  const classification = classifyDynamicFrames(input);
  assert.equal(classification.disposition, 'inconclusive');
  assert.equal(classification.stage, 'capability-audit');
  assert.equal(classification.reasonCode, 'capability-audit-incomplete-or-inexact');
  assert.deepEqual(classification.receipts, []);
});

test('derives outcome without promoting source drift or prohibited capability', async () => {
  const target = (await admissionFixture()).historical.acceptedTarget;
  const { capabilityAudit: audit, classification, matrix } = syntheticClassifierFixture(target);

  assert.deepEqual(outcomeFor({ allExact: true }, audit, classification, matrix), {
    status: 'supported',
    stage: 'dynamic-readonly-acquisition',
    reasonCode: 'complete-live-classification-and-hostile-matrix-exact',
  });
  assert.deepEqual(outcomeFor({ allExact: false }, audit, classification, matrix), {
    status: 'inconclusive',
    stage: 'source-admission',
    reasonCode: 'source-admission-inexact',
  });
  const prohibited = clone(audit);
  prohibited.prohibitedCounts.signal = 1;
  assert.deepEqual(outcomeFor({ allExact: true }, prohibited, classification, matrix), {
    status: 'refuted',
    stage: 'capability-boundary',
    reasonCode: 'prohibited-capability-observed',
  });
});

test('uses absolute binaries and only the environment supplied by the command auditor', async () => {
  let captured = null;
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  const runner = createAbsoluteCommandRunner((executable, args, options) => {
    captured = { executable, args, options };
    queueMicrotask(() => {
      child.stdout.end('ok');
      child.stderr.end();
      child.emit('close', 0, null);
    });
    return child;
  });
  const environment = { SAFE_FIXTURE: '1', LANG: 'C', LC_ALL: 'C' };
  const result = await runner('docker', ['version'], {
    env: environment,
    maxBufferBytes: 1024,
  });

  assert.equal(captured.executable, '/usr/bin/docker');
  assert.deepEqual(captured.options.env, environment);
  assert.equal(captured.options.shell, false);
  assert.deepEqual(captured.options.stdio, ['ignore', 'pipe', 'pipe']);
  assert.equal(Object.hasOwn(captured.options, 'timeout'), false);
  assert.equal(Object.hasOwn(captured.options, 'signal'), false);
  assert.equal(Object.hasOwn(captured.options, 'killSignal'), false);
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout.toString('utf8'), 'ok');
  await assert.rejects(
    () =>
      runner('sh', [], {
        env: environment,
        maxBufferBytes: 1024,
      }),
    /not admitted/u
  );
});

test('never signals a hanging or overflowing child and rejects overflow only after natural exit', async () => {
  let killCalls = 0;
  const children = [];
  const runner = createAbsoluteCommandRunner(() => {
    const child = new EventEmitter();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = () => {
      killCalls += 1;
      return true;
    };
    children.push(child);
    return child;
  });
  const options = {
    env: { LANG: 'C' },
    maxBufferBytes: 4,
  };

  let hangingSettled = false;
  const hanging = runner('git', ['rev-parse', 'HEAD'], options).finally(() => {
    hangingSettled = true;
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(hangingSettled, false);
  assert.equal(killCalls, 0);
  children[0].stdout.end();
  children[0].stderr.end();
  children[0].emit('close', 0, null);
  await hanging;

  let overflowSettled = false;
  const overflowing = runner('lsusb', [], options).finally(() => {
    overflowSettled = true;
  });
  children[1].stdout.write('123456789');
  children[1].stdout.end();
  children[1].stderr.end();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(overflowSettled, false);
  assert.equal(killCalls, 0);
  children[1].emit('close', 0, null);
  await assert.rejects(
    overflowing,
    (error) =>
      error.code === 'COMMAND_OUTPUT_OVERFLOW' &&
      error.stdout.toString('utf8') === '12345' &&
      error.signal === null
  );
  assert.equal(killCalls, 0);

  const implementation = await readFile(RUN_URL, 'utf8');
  assert.doesNotMatch(implementation, /\.kill\s*\(/u);
  assert.doesNotMatch(implementation, /\bkillSignal\b/u);
  assert.doesNotMatch(implementation, /\bAbortSignal\b/u);
});

test('canonical API rejects every override before reading it and cannot choose a second ledger root', async () => {
  const authorization = h045LiveAuthorization(sourceSetSha256(sourceMap()));
  let poisonedOverrideReads = 0;
  const poisoned = { live: true, authorization };
  Object.defineProperty(poisoned, 'attemptLedger', {
    enumerable: true,
    get() {
      poisonedOverrideReads += 1;
      throw new Error('canonical override getter executed');
    },
  });
  await assert.rejects(() => runH045(poisoned), /accepts exactly live and authorization/u);
  assert.equal(poisonedOverrideReads, 0);

  for (const overrides of [
    { outputRoot: '/tmp/ledger-root-a' },
    { outputRoot: '/tmp/ledger-root-b' },
    { attemptLedger: {} },
    { dependencies: {} },
    { runner: async () => {} },
    { filesystem: {} },
    { environment: {} },
    { wallNow: () => '2026-07-27T03:00:00.000Z' },
    { monotonicNowNs: () => 0n },
  ]) {
    await assert.rejects(
      () => runH045({ live: true, authorization, ...overrides }),
      /accepts exactly live and authorization/u
    );
  }
  assert.equal(runH045.length, 1);
  const source = await readFile(RUN_URL, 'utf8');
  assert.match(source, /const CANONICAL_RUN_KEYS = Object\.freeze\(\['live', 'authorization'\]\)/u);
  assert.match(source, /attemptLedger: createCanonicalAttemptLedger\(\)/u);
  assert.match(source, /outputRoot: ARTIFACT_ROOT/u);
  assert.match(source, /environment: h046CanonicalCommandEnvironment\(\)/u);
  assert.doesNotMatch(source, /environment:\s*process\.env/u);
  assert.match(
    source,
    /const runPath = canonical\s*\? await ledger\.persistRun\(run\)\s*: await dependencies\.persistRun\(run, outputRoot\)/u
  );
  assert.match(
    source,
    /predecessorReservationRelativePath: PREDECESSOR_RESERVATION_RELATIVE_PATH[\s\S]*predecessorFailureRelativePath: PREDECESSOR_FAILURE_RELATIVE_PATH[\s\S]*reservationRelativePath: REPLACEMENT_RESERVATION_RELATIVE_PATH[\s\S]*completionRelativePath: REPLACEMENT_COMPLETION_RELATIVE_PATH[\s\S]*semantics: 'fixed-local-linked-one-shot-replacement-ledger'/u
  );
});

test('H-046 canonical command environment is a fresh empty plain record', () => {
  const first = h046CanonicalCommandEnvironment();
  const second = h046CanonicalCommandEnvironment();
  assert.notEqual(first, second);
  assert.deepEqual(first, {});
  assert.deepEqual(second, {});
  assert.equal(Object.getPrototypeOf(first), Object.prototype);
  first.poison = 'must-not-persist';
  assert.deepEqual(second, {});
});

test('only the exact CHG-0020 replacement grant grammar reaches canonical admission', async () => {
  const digest = sourceSetSha256(sourceMap());
  const authorization = h045LiveAuthorization(digest);
  assert.equal(authorization, `CHG-0020:h045-one-readonly-replacement-attempt:sha256:${digest}`);
  await assert.rejects(
    () =>
      runH045({
        live: true,
        authorization: `CHG-0019:one-readonly-run:sha256:${digest}`,
      }),
    /replacement authorization/u
  );
});

test('offline fixture rejects every missing or expanded fake before invoking clocks, ledger, or host seams', async () => {
  const reviewedSourceSha256 = sourceSetSha256(sourceMap());
  let seamCalls = 0;
  const makeOptions = () => {
    const dependencies = completeOfflineDependencies();
    for (const key of Object.keys(dependencies)) {
      dependencies[key] = () => {
        seamCalls += 1;
        throw new Error(`unexpected dependency call: ${key}`);
      };
    }
    return {
      reviewedSourceSha256,
      wallNow() {
        seamCalls += 1;
        return '2026-07-27T03:00:00.000Z';
      },
      monotonicNowNs() {
        seamCalls += 1;
        return 0n;
      },
      runner: async () => {
        seamCalls += 1;
      },
      filesystem: {},
      environment: {},
      attemptLedger: {
        async reserve() {
          seamCalls += 1;
          return { sha256: '9'.repeat(64) };
        },
        async fail() {
          seamCalls += 1;
        },
        async complete() {
          seamCalls += 1;
        },
      },
      dependencies,
      async persistFixture() {
        seamCalls += 1;
      },
    };
  };

  for (const key of Object.keys(makeOptions())) {
    const options = makeOptions();
    delete options[key];
    await assert.rejects(
      () => runH045OfflineFixture(options),
      /requires every exact fake seam/u,
      `missing top-level ${key}`
    );
    assert.equal(seamCalls, 0, `missing top-level ${key}`);
  }
  for (const key of Object.keys(makeOptions().dependencies)) {
    const options = makeOptions();
    delete options.dependencies[key];
    await assert.rejects(
      () => runH045OfflineFixture(options),
      /dependencies must be complete exact fakes/u,
      `missing dependency ${key}`
    );
    assert.equal(seamCalls, 0, `missing dependency ${key}`);
  }
  for (const expanded of [{ live: true }, { authorization: 'forbidden' }, { outputRoot: '/tmp' }]) {
    const options = { ...makeOptions(), ...expanded };
    await assert.rejects(() => runH045OfflineFixture(options), /requires every exact fake seam/u);
    assert.equal(seamCalls, 0);
  }
});

test('persists each local run directory as 0700 and run.json as 0600', async (context) => {
  await mkdir(ARTIFACT_ROOT, { recursive: true, mode: 0o700 });
  const outputRoot = await mkdtemp(path.join(ARTIFACT_ROOT, 'permissions-test-'));
  await chmod(outputRoot, 0o777);
  context.after(async () => {
    await rm(outputRoot, { recursive: true, force: true });
  });
  const run = {
    runId: `permissions-${process.pid}-${Date.now()}`,
    evidenceSha256: 'a'.repeat(64),
  };

  const runPath = await persistRun(run, outputRoot);
  const [rootMetadata, directoryMetadata, fileMetadata, persisted] = await Promise.all([
    stat(outputRoot),
    stat(path.dirname(runPath)),
    stat(runPath),
    readFile(runPath, 'utf8'),
  ]);

  assert.equal(rootMetadata.mode & 0o777, 0o700);
  assert.equal(directoryMetadata.mode & 0o777, 0o700);
  assert.equal(fileMetadata.mode & 0o777, 0o600);
  for (const metadata of [rootMetadata, directoryMetadata, fileMetadata]) {
    assert.equal(metadata.uid, process.geteuid());
    assert.equal(metadata.gid, process.getegid());
  }
  assert.equal(fileMetadata.nlink, 1);
  assert.deepEqual(JSON.parse(persisted), run);
  await assert.rejects(() => persistRun(run, outputRoot), { code: 'EEXIST' });
});

test('offline ledger helper atomically reserves one fixture attempt in an arbitrary test root', async (context) => {
  await mkdir(ARTIFACT_ROOT, { recursive: true, mode: 0o700 });
  const ledgerRoot = await mkdtemp(path.join(ARTIFACT_ROOT, 'ledger-race-test-'));
  context.after(async () => {
    await rm(ledgerRoot, { recursive: true, force: true });
  });
  const predecessor = await seedPredecessorAttempt(ledgerRoot);
  const predecessorBefore = await Promise.all([
    stat(path.join(predecessor.directory, 'reservation.json')),
    stat(path.join(predecessor.directory, 'failure.json')),
  ]);
  const digest = sourceSetSha256(sourceMap());
  const ledgers = [
    createOfflineAttemptLedgerForTest(ledgerRoot),
    createOfflineAttemptLedgerForTest(ledgerRoot),
  ];
  const reserve = (ledger) =>
    ledger.reserve({
      reservedAt: '2026-07-27T03:00:00.000Z',
      sourceSetSha256: digest,
      semantics: 'offline-non-authorizing-fixture',
    });
  const results = await Promise.allSettled(ledgers.map(reserve));
  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
  assert.equal(results.filter((result) => result.status === 'rejected').length, 1);
  const winnerIndex = results.findIndex((result) => result.status === 'fulfilled');
  const reservation = results[winnerIndex].value;
  const run = {
    runId: `ledger-anchored-${process.pid}-${Date.now()}`,
    evidenceSha256: 'a'.repeat(64),
  };
  const runPath = await ledgers[winnerIndex].persistRun(run);
  await ledgers[winnerIndex].complete({
    reservationSha256: reservation.sha256,
    completedAt: '2026-07-27T03:00:01.000Z',
    evidenceSha256: 'a'.repeat(64),
  });
  await assert.rejects(() => reserve(createOfflineAttemptLedgerForTest(ledgerRoot)), {
    code: 'EEXIST',
  });

  const attemptDirectory = path.join(ledgerRoot, REPLACEMENT_ATTEMPT_DIRECTORY);
  const reservationPath = path.join(attemptDirectory, 'reservation.json');
  const completionPath = path.join(attemptDirectory, 'completion.json');
  const [
    rootMetadata,
    directoryMetadata,
    receiptMetadata,
    completionMetadata,
    runMetadata,
    receipt,
  ] = await Promise.all([
    stat(ledgerRoot),
    stat(attemptDirectory),
    stat(reservationPath),
    stat(completionPath),
    stat(runPath),
    readFile(reservationPath, 'utf8'),
  ]);
  for (const metadata of [
    rootMetadata,
    directoryMetadata,
    receiptMetadata,
    completionMetadata,
    runMetadata,
  ]) {
    assert.equal(metadata.uid, process.geteuid());
    assert.equal(metadata.gid, process.getegid());
  }
  assert.equal(rootMetadata.mode & 0o777, 0o700);
  assert.equal(directoryMetadata.mode & 0o777, 0o700);
  assert.equal(receiptMetadata.mode & 0o777, 0o600);
  assert.equal(completionMetadata.mode & 0o777, 0o600);
  assert.equal(receiptMetadata.nlink, 1);
  assert.equal(completionMetadata.nlink, 1);
  assert.equal(runMetadata.nlink, 1);
  assert.deepEqual(JSON.parse(await readFile(runPath, 'utf8')), run);
  const reservationReceipt = JSON.parse(receipt);
  assert.equal(reservationReceipt.schemaVersion, 'overlaykit-h045-offline-attempt-reservation/v2');
  assert.equal(reservationReceipt.attempt, REPLACEMENT_ATTEMPT_DIRECTORY);
  assert.deepEqual(reservationReceipt.predecessor, {
    reservationSha256: PREDECESSOR_RESERVATION_SHA256,
    failureSha256: PREDECESSOR_FAILURE_SHA256,
  });
  assert.deepEqual(reservationReceipt.sourceBinding, {
    sourceSetSha256: digest,
    semantics: 'offline-non-authorizing-fixture',
    authority: 'none',
    action: null,
  });
  assert.deepEqual(await readdir(predecessor.directory), ['failure.json', 'reservation.json']);
  assert.deepEqual(
    await Promise.all([
      readFile(path.join(predecessor.directory, 'reservation.json')),
      readFile(path.join(predecessor.directory, 'failure.json')),
    ]),
    [predecessor.reservationBytes, predecessor.failureBytes]
  );
  const predecessorAfter = await Promise.all([
    stat(path.join(predecessor.directory, 'reservation.json')),
    stat(path.join(predecessor.directory, 'failure.json')),
  ]);
  for (let index = 0; index < predecessorBefore.length; index += 1) {
    for (const field of [
      'dev',
      'ino',
      'mode',
      'nlink',
      'uid',
      'gid',
      'size',
      'mtimeMs',
      'ctimeMs',
    ]) {
      assert.equal(predecessorAfter[index][field], predecessorBefore[index][field], field);
    }
  }
});

test('replacement reservation fails closed before creation for any inexact predecessor', async (context) => {
  await mkdir(ARTIFACT_ROOT, { recursive: true, mode: 0o700 });
  const parent = await mkdtemp(path.join(ARTIFACT_ROOT, 'predecessor-hostile-'));
  context.after(async () => {
    await rm(parent, { recursive: true, force: true });
  });
  const cases = [
    [
      'missing-failure',
      async (root) => {
        await rm(path.join(root, PREDECESSOR_ATTEMPT_DIRECTORY, 'failure.json'));
      },
    ],
    [
      'tampered-reservation',
      async (root) => {
        await writeFile(
          path.join(root, PREDECESSOR_ATTEMPT_DIRECTORY, 'reservation.json'),
          prettyJsonBytes({ tampered: true })
        );
      },
    ],
    [
      'expanded-membership',
      async (root) => {
        await writeFile(
          path.join(root, PREDECESSOR_ATTEMPT_DIRECTORY, 'completion.json'),
          prettyJsonBytes({ forbidden: true }),
          { flag: 'wx', mode: 0o600 }
        );
      },
    ],
    [
      'mode-drift',
      async (root) => {
        await chmod(path.join(root, PREDECESSOR_ATTEMPT_DIRECTORY, 'failure.json'), 0o644);
      },
    ],
    [
      'hardlink-alias',
      async (root) => {
        await link(
          path.join(root, PREDECESSOR_ATTEMPT_DIRECTORY, 'failure.json'),
          path.join(root, PREDECESSOR_ATTEMPT_DIRECTORY, 'failure-alias.json')
        );
      },
    ],
  ];
  for (const [name, mutate] of cases) {
    const root = path.join(parent, name);
    await seedPredecessorAttempt(root);
    await mutate(root);
    await assert.rejects(
      () =>
        createOfflineAttemptLedgerForTest(root).reserve({
          reservedAt: '2026-07-27T03:00:00.000Z',
          sourceSetSha256: sourceSetSha256(sourceMap()),
          semantics: 'offline-non-authorizing-fixture',
        }),
      /predecessor/u,
      name
    );
    await assert.rejects(
      () => stat(path.join(root, REPLACEMENT_ATTEMPT_DIRECTORY)),
      { code: 'ENOENT' },
      name
    );
  }
});

test('invalid terminal receipts close each retained offline ledger session', async (context) => {
  await mkdir(ARTIFACT_ROOT, { recursive: true, mode: 0o700 });
  const parent = await mkdtemp(path.join(ARTIFACT_ROOT, 'invalid-terminal-test-'));
  context.after(async () => {
    await rm(parent, { recursive: true, force: true });
  });
  const digest = sourceSetSha256(sourceMap());

  for (const terminal of ['fail', 'complete']) {
    const ledgerRoot = path.join(parent, terminal);
    await seedPredecessorAttempt(ledgerRoot);
    const ledger = createOfflineAttemptLedgerForTest(ledgerRoot);
    await ledger.reserve({
      reservedAt: '2026-07-27T03:00:00.000Z',
      sourceSetSha256: digest,
      semantics: 'offline-non-authorizing-fixture',
    });
    if (terminal === 'fail') {
      await assert.rejects(
        () =>
          ledger.fail({
            reservationSha256: 'invalid',
            stage: 'offline-test',
            observationStarted: false,
          }),
        /lacks its reservation digest/u
      );
    } else {
      await assert.rejects(
        () =>
          ledger.complete({
            reservationSha256: 'invalid',
            completedAt: '2026-07-27T03:00:01.000Z',
            evidenceSha256: 'a'.repeat(64),
          }),
        /completion receipt is invalid/u
      );
    }
    await assert.rejects(
      () =>
        ledger.persistRun({
          runId: `closed-${terminal}`,
          evidenceSha256: 'a'.repeat(64),
        }),
      /no active reservation/u
    );
  }
});

test('one ledger session refuses split-root persistence after its path is replaced', async (context) => {
  await mkdir(ARTIFACT_ROOT, { recursive: true, mode: 0o700 });
  const parent = await mkdtemp(path.join(ARTIFACT_ROOT, 'shared-anchor-test-'));
  const ledgerRoot = path.join(parent, 'ledger-root');
  const displacedRoot = path.join(parent, 'displaced-root');
  await mkdir(ledgerRoot, { mode: 0o700 });
  await seedPredecessorAttempt(ledgerRoot);
  context.after(async () => {
    await rm(parent, { recursive: true, force: true });
  });

  const ledger = createOfflineAttemptLedgerForTest(ledgerRoot);
  const reservation = await ledger.reserve({
    reservedAt: '2026-07-27T03:00:00.000Z',
    sourceSetSha256: sourceSetSha256(sourceMap()),
    semantics: 'offline-non-authorizing-fixture',
  });
  const run = {
    runId: `split-root-${process.pid}-${Date.now()}`,
    evidenceSha256: 'a'.repeat(64),
  };

  await rename(ledgerRoot, displacedRoot);
  await mkdir(ledgerRoot, { mode: 0o700 });
  await assert.rejects(() => ledger.persistRun(run), /non-canonical or symbolic directory/u);
  await assert.rejects(() => stat(path.join(ledgerRoot, run.runId)), { code: 'ENOENT' });
  await assert.rejects(() => stat(path.join(displacedRoot, run.runId)), { code: 'ENOENT' });

  await rm(ledgerRoot, { recursive: true });
  await rename(displacedRoot, ledgerRoot);
  await ledger.fail({
    reservationSha256: reservation.sha256,
    stage: 'persistence',
    observationStarted: false,
  });
  assert.equal(
    JSON.parse(
      await readFile(path.join(ledgerRoot, REPLACEMENT_ATTEMPT_DIRECTORY, 'failure.json'), 'utf8')
    ).stage,
    'persistence'
  );
});

test('rejects run and ledger JSON beyond their independent byte limits', async (context) => {
  await mkdir(ARTIFACT_ROOT, { recursive: true, mode: 0o700 });
  const outputRoot = await mkdtemp(path.join(ARTIFACT_ROOT, 'size-limit-run-'));
  const ledgerRoot = await mkdtemp(path.join(ARTIFACT_ROOT, 'size-limit-ledger-'));
  context.after(async () => {
    await Promise.all([
      rm(outputRoot, { recursive: true, force: true }),
      rm(ledgerRoot, { recursive: true, force: true }),
    ]);
  });

  const runId = `oversized-${process.pid}-${Date.now()}`;
  await assert.rejects(
    () =>
      persistRun(
        {
          runId,
          payload: 'x'.repeat(MAX_RUN_JSON_BYTES),
        },
        outputRoot
      ),
    new RegExp(`run\\.json exceeds ${String(MAX_RUN_JSON_BYTES)} bytes`, 'u')
  );
  await assert.rejects(() => stat(path.join(outputRoot, runId)), { code: 'ENOENT' });

  await seedPredecessorAttempt(ledgerRoot);
  const ledger = createOfflineAttemptLedgerForTest(ledgerRoot);
  const reservation = await ledger.reserve({
    reservedAt: '2026-07-27T03:00:00.000Z',
    sourceSetSha256: sourceSetSha256(sourceMap()),
    semantics: 'offline-non-authorizing-fixture',
  });
  await assert.rejects(
    () =>
      ledger.fail({
        reservationSha256: reservation.sha256,
        stage: 'x'.repeat(MAX_LEDGER_RECEIPT_BYTES),
        observationStarted: false,
      }),
    new RegExp(`attempt failure receipt exceeds ${String(MAX_LEDGER_RECEIPT_BYTES)} bytes`, 'u')
  );
  await assert.rejects(
    () =>
      ledger.complete({
        reservationSha256: reservation.sha256,
        completedAt: '2026-07-27T03:00:01.000Z',
        evidenceSha256: 'a'.repeat(64),
      }),
    /no active reservation/u
  );
});

test('rejects a hard-link alias added while run.json remains open', async (context) => {
  await mkdir(ARTIFACT_ROOT, { recursive: true, mode: 0o700 });
  const outputRoot = await mkdtemp(path.join(ARTIFACT_ROOT, 'hardlink-race-'));
  context.after(async () => {
    await rm(outputRoot, { recursive: true, force: true });
  });
  const runId = `hardlink-${process.pid}-${Date.now()}`;
  const runPath = path.join(outputRoot, runId, 'run.json');
  const aliasPath = path.join(outputRoot, 'run-alias.json');
  let stop = false;
  let linked = false;
  const linker = (async () => {
    while (!stop && !linked) {
      try {
        await link(runPath, aliasPath);
        linked = true;
      } catch (error) {
        if (!['ENOENT', 'EEXIST'].includes(error?.code)) throw error;
        await new Promise((resolve) => setImmediate(resolve));
      }
    }
  })();

  let persistenceError = null;
  try {
    await persistRun(
      {
        runId,
        payload: 'x'.repeat(8 * 1024 * 1024),
      },
      outputRoot
    );
  } catch (error) {
    persistenceError = error;
  } finally {
    stop = true;
    await linker;
  }
  assert.equal(linked, true);
  assert.match(persistenceError?.message ?? '', /aliased|exactly one link/u);
  assert.equal((await stat(runPath)).nlink, 2);
  assert.equal((await stat(aliasPath)).nlink, 2);
});

test('rejects pre-existing symbolic ledger and run children without following them', async (context) => {
  await mkdir(ARTIFACT_ROOT, { recursive: true, mode: 0o700 });
  const parent = await mkdtemp(path.join(ARTIFACT_ROOT, 'child-symlink-'));
  context.after(async () => {
    await rm(parent, { recursive: true, force: true });
  });
  const target = path.join(parent, 'target');
  const ledgerRoot = path.join(parent, 'ledger');
  const runRoot = path.join(parent, 'runs');
  await Promise.all([
    mkdir(target, { mode: 0o700 }),
    mkdir(ledgerRoot, { mode: 0o700 }),
    mkdir(runRoot, { mode: 0o700 }),
  ]);
  await seedPredecessorAttempt(ledgerRoot);
  await symlink(target, path.join(ledgerRoot, REPLACEMENT_ATTEMPT_DIRECTORY));
  const runId = `symbolic-child-${process.pid}`;
  await symlink(target, path.join(runRoot, runId));

  await assert.rejects(
    () =>
      createOfflineAttemptLedgerForTest(ledgerRoot).reserve({
        reservedAt: '2026-07-27T03:00:00.000Z',
        sourceSetSha256: sourceSetSha256(sourceMap()),
        semantics: 'offline-non-authorizing-fixture',
      }),
    { code: 'EEXIST' }
  );
  await assert.rejects(() => persistRun({ runId, evidenceSha256: 'a'.repeat(64) }, runRoot), {
    code: 'EEXIST',
  });
});

test('a failed source-bound attempt writes failure.json and permanently consumes the attempt', async (context) => {
  await mkdir(ARTIFACT_ROOT, { recursive: true, mode: 0o700 });
  const ledgerRoot = await mkdtemp(path.join(ARTIFACT_ROOT, 'ledger-failure-test-'));
  context.after(async () => {
    await rm(ledgerRoot, { recursive: true, force: true });
  });
  await seedPredecessorAttempt(ledgerRoot);
  const reviewed = sourceMap();
  const drifted = sourceMap();
  drifted[0].sha256 = '0'.repeat(64);
  const reviewedSourceSha256 = sourceSetSha256(reviewed);
  let sourceCalls = 0;
  const invoke = () =>
    runH045OfflineFixture(
      offlineFixtureOptions({
        reviewedSourceSha256,
        attemptLedger: createOfflineAttemptLedgerForTest(ledgerRoot),
        dependencies: completeOfflineDependencies({
          async sourceReceipts() {
            sourceCalls += 1;
            return clone(drifted);
          },
        }),
      })
    );

  await assert.rejects(invoke, /reviewed source authorization does not match/u);
  const failure = JSON.parse(
    await readFile(path.join(ledgerRoot, REPLACEMENT_ATTEMPT_DIRECTORY, 'failure.json'), 'utf8')
  );
  assert.equal(failure.schemaVersion, 'overlaykit-h045-offline-attempt-failure/v2');
  assert.match(failure.reservationSha256, /^[0-9a-f]{64}$/u);
  assert.equal(failure.stage, 'review-source-initial');
  assert.equal(failure.observationStarted, false);
  await assert.rejects(invoke, { code: 'EEXIST' });
  assert.equal(sourceCalls, 1);
});

test('invalid wall or monotonic clocks are rejected before reserving or reading sources', async () => {
  const sources = sourceMap();
  const reviewedSourceSha256 = sourceSetSha256(sources);
  for (const [id, wallNow, monotonicNowNs] of [
    ['wall', () => 'not-a-time', () => 0n],
    ['monotonic', () => '2026-07-27T03:00:00.000Z', () => -1n],
  ]) {
    let reservations = 0;
    let sourceReads = 0;
    await assert.rejects(
      () =>
        runH045OfflineFixture(
          offlineFixtureOptions({
            reviewedSourceSha256,
            wallNow,
            monotonicNowNs,
            attemptLedger: {
              async reserve() {
                reservations += 1;
                return { sha256: '9'.repeat(64) };
              },
              async fail() {},
              async complete() {},
            },
            dependencies: completeOfflineDependencies({
              async sourceReceipts() {
                sourceReads += 1;
                return clone(sources);
              },
            }),
          })
        ),
      /clock|startedAt/u,
      id
    );
    assert.equal(reservations, 0, `${id}:reservation`);
    assert.equal(sourceReads, 0, `${id}:sources`);
  }
});

test('ledger and persistence reject symbolic or escaping artifact paths', async (context) => {
  await mkdir(ARTIFACT_ROOT, { recursive: true, mode: 0o700 });
  const parent = await mkdtemp(path.join(ARTIFACT_ROOT, 'containment-test-'));
  const realLedgerRoot = path.join(parent, 'real-ledger');
  const linkedLedgerRoot = path.join(parent, 'linked-ledger');
  await mkdir(realLedgerRoot, { mode: 0o700 });
  await seedPredecessorAttempt(realLedgerRoot);
  await symlink(realLedgerRoot, linkedLedgerRoot);
  context.after(async () => {
    await rm(parent, { recursive: true, force: true });
  });
  const digest = sourceSetSha256(sourceMap());
  await assert.rejects(
    () =>
      createOfflineAttemptLedgerForTest(linkedLedgerRoot).reserve({
        reservedAt: '2026-07-27T03:00:00.000Z',
        sourceSetSha256: digest,
        semantics: 'offline-non-authorizing-fixture',
      }),
    /non-canonical or symbolic/u
  );
  await assert.rejects(
    () => persistRun({ runId: '../escape', evidenceSha256: 'a'.repeat(64) }, parent),
    /one safe path component/u
  );

  const realOutput = path.join(parent, 'real-output');
  const linkedOutput = path.join(parent, 'linked-output');
  await mkdir(realOutput, { mode: 0o700 });
  await symlink(realOutput, linkedOutput);
  await assert.rejects(
    () =>
      persistRun(
        { runId: `symbolic-${process.pid}`, evidenceSha256: 'a'.repeat(64) },
        linkedOutput
      ),
    /non-canonical or symbolic/u
  );
});

test('offline fixture exercises ordering but remains explicitly non-canonical and non-authorizing', async () => {
  const result = await runFixture();
  const {
    run,
    events,
    admitted,
    observedTargets,
    attemptReceipts,
    reviewedSourceSha256,
    fixtureBoundary,
  } = result;

  assert.deepEqual(fixtureBoundary, {
    mode: 'offline-fixture',
    canonical: false,
    authorizing: false,
    live: false,
    persistence: 'explicit-fixture-only',
  });
  assert.equal(run.schemaVersion, 'overlaykit-h045-offline-fixture/v1');
  assert.equal(events[0], 'attempt-reserve');
  assert.equal(events.indexOf('sources-2') < events.indexOf('runtime'), true);
  assert.equal(events.indexOf('sources-2') < events.indexOf('git'), true);
  assert.equal(events.indexOf('sources-2') < events.indexOf('lsusb'), true);
  assert.equal(events.indexOf('sources-2') < events.indexOf('docker'), true);
  assert.equal(events.indexOf('docker') < events.indexOf('frame-1'), true);
  assert.equal(events.indexOf('frame-1') < events.indexOf('frame-2'), true);
  assert.equal(events.indexOf('frame-2') < events.indexOf('sources-3'), true);
  assert.equal(events.at(-2), 'persist');
  assert.equal(events.at(-1), 'attempt-complete');
  assert.equal(run.sourceAdmission.allExact, true);
  assert.equal(run.outcome.status, 'supported');
  assert.equal(run.liveClassification.disposition, 'candidate');
  assert.deepEqual(Object.keys(run.input).sort(), Object.keys(H045_STABLE_TARGET_INPUT).sort());
  assert.equal(Object.hasOwn(run.input, 'serial'), false);
  assert.equal(run.acceptedTarget.serial, admitted.historical.acceptedTarget.serial);
  assert.deepEqual(run.collector.offlineSourceBinding, {
    sourceSetSha256: reviewedSourceSha256,
    semantics: 'offline-non-authorizing-source-binding',
  });
  assert.equal(reviewedSourceSha256, sourceSetSha256(run.collector.sourcesBefore));
  assert.deepEqual(run.collector.offlineAttemptLedger, {
    reservationSha256: '9'.repeat(64),
    semantics: 'explicit-offline-fixture-ledger',
  });
  assert.equal(Object.hasOwn(run.collector, 'reviewAuthorization'), false);
  assert.equal(Object.hasOwn(run.collector, 'attemptLedger'), false);
  assert.deepEqual(
    attemptReceipts.map((receipt) => receipt.kind),
    ['reservation', 'completion']
  );
  assert.equal(attemptReceipts[1].reservationSha256, '9'.repeat(64));
  assert.equal(attemptReceipts[1].evidenceSha256, run.evidenceSha256);
  assert.deepEqual(
    observedTargets,
    Array.from({ length: 2 }, () => ({
      serial: admitted.historical.acceptedTarget.serial,
      vendorId: '0fd9',
      productId: '0080',
    }))
  );
  const { evidenceSha256, ...body } = run;
  assert.equal(evidenceSha256, sha256Canonical(body));

  const schema = JSON.parse(await readFile(SCHEMA_URL, 'utf8'));
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema);
  assert.equal(validate(run), false);
});

test('final source drift degrades only the outcome and does not reinterpret captured frames', async () => {
  const initial = sourceMap();
  const final = sourceMap();
  final[0].sha256 = '0'.repeat(64);
  const { run } = await runFixture({
    sourceMaps: [initial, clone(initial), final],
  });

  assert.equal(run.collector.sourceStable, false);
  assert.equal(run.sourceAdmission.sourceStable, false);
  assert.equal(run.sourceAdmission.allExact, false);
  assert.equal(run.liveClassification.disposition, 'candidate');
  assert.equal(run.liveClassification.receipts.length, 1);
  assert.deepEqual(run.outcome, {
    status: 'inconclusive',
    stage: 'source-admission',
    reasonCode: 'source-admission-inexact',
  });
});

test('pre-live source drift stops before lsusb, Docker, frames, or persistence', async () => {
  const initial = sourceMap();
  const beforeLive = sourceMap();
  beforeLive[0].sha256 = '0'.repeat(64);
  const events = [];
  const admitted = await admissionFixture();
  let sourceCall = 0;
  let failureReceipt = null;
  const reservationSha256 = '9'.repeat(64);
  const attemptLedger = {
    async reserve() {
      events.push('reserve');
      return { sha256: reservationSha256 };
    },
    async fail(receipt) {
      events.push('failure');
      failureReceipt = clone(receipt);
      return { sha256: '8'.repeat(64) };
    },
    async complete() {
      throw new Error('must not complete');
    },
  };

  await assert.rejects(
    () =>
      runH045OfflineFixture(
        offlineFixtureOptions({
          reviewedSourceSha256: sourceSetSha256(initial),
          attemptLedger,
          dependencies: completeOfflineDependencies({
            async compileSchema() {
              return validatingStub();
            },
            async captureRuntimeReceipt() {
              events.push('runtime');
              throw new Error('must not be reached');
            },
            async sourceReceipts() {
              const map = sourceCall === 0 ? initial : beforeLive;
              sourceCall += 1;
              events.push(`source-${sourceCall}`);
              return clone(map);
            },
            async loadAdmission() {
              return clone(admitted);
            },
            createCommandAuditor() {
              return {};
            },
            createFilesystemAuditor() {
              return {};
            },
            async captureGitAdmission() {
              events.push('git');
              return {
                head: 'f'.repeat(40),
                protectedMainCommit: H045_PROTECTED_MAIN_COMMIT,
                protectedMainIsAncestor: true,
                sourceContractCommit: H045_SOURCE_CONTRACT_COMMIT,
                sourceContractIsAncestor: true,
                remoteUrl: H045_REPOSITORY,
                commandReceiptIndexes: [0, 1, 2, 3],
              };
            },
            async captureLsusbAdmission() {
              events.push('lsusb');
              throw new Error('must not be reached');
            },
            async captureDockerAdmission() {
              events.push('docker');
              throw new Error('must not be reached');
            },
            async captureObservationFrame() {
              events.push('frame');
              throw new Error('must not be reached');
            },
            buildCapabilityAudit() {
              events.push('audit');
              throw new Error('must not be reached');
            },
          }),
        })
      ),
    /reviewed sources drifted before live observation/u
  );
  assert.deepEqual(events, ['reserve', 'source-1', 'source-2', 'failure']);
  assert.deepEqual(failureReceipt, {
    reservationSha256,
    stage: 'review-source-before-observation',
    observationStarted: false,
  });
});

test('governance byte drift with intact self fields consumes the attempt before host observation', async () => {
  const sources = sourceMap();
  const admitted = await admissionFixture();
  admitted.governance.planSha256 = '0'.repeat(64);
  const events = [];
  let failureReceipt = null;
  const attemptLedger = {
    async reserve() {
      events.push('reserve');
      return { sha256: '9'.repeat(64) };
    },
    async fail(receipt) {
      events.push('failure');
      failureReceipt = clone(receipt);
      return { sha256: '8'.repeat(64) };
    },
    async complete() {
      throw new Error('must not complete');
    },
  };
  await assert.rejects(
    () =>
      runH045OfflineFixture(
        offlineFixtureOptions({
          reviewedSourceSha256: sourceSetSha256(sources),
          attemptLedger,
          dependencies: completeOfflineDependencies({
            async sourceReceipts() {
              events.push('sources');
              return clone(sources);
            },
            async loadAdmission() {
              events.push('admission');
              return clone(admitted);
            },
            async captureRuntimeReceipt() {
              events.push('runtime');
              throw new Error('must not observe runtime');
            },
            async captureGitAdmission() {
              events.push('git');
              throw new Error('must not invoke Git');
            },
          }),
        })
      ),
    /byte-exact governance admission failed/u
  );
  assert.deepEqual(events, ['reserve', 'sources', 'admission', 'failure']);
  assert.deepEqual(failureReceipt, {
    reservationSha256: '9'.repeat(64),
    stage: 'historical-and-governance-admission',
    observationStarted: false,
  });
});

test('CLI remains inert unless both exact one-run flags are present', async () => {
  const validAuthorization = h045LiveAuthorization(sourceSetSha256(sourceMap()));
  for (const args of [
    [],
    ['--live'],
    [`--authorization=${validAuthorization}`],
    ['--live', `--authorization=${H045_LIVE_AUTHORIZATION}`],
    ['--live', `--authorization=${validAuthorization.toUpperCase()}`],
  ]) {
    const result = await childRun(args);
    assert.equal(result.exitCode, 2, args.join(' '));
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /H-045 is inert/u);
  }
});

test('claim boundary is an exact local literal rather than a schema-derived import', async () => {
  assert.equal(H045_CLAIM_BOUNDARY.proves.length, 5);
  assert.equal(H045_CLAIM_BOUNDARY.excludes.length, 7);
  const source = await readFile(RUN_URL, 'utf8');
  assert.equal(source.includes(H045_CLAIM_BOUNDARY.proves[0]), true);
  assert.equal(source.includes(H045_CLAIM_BOUNDARY.excludes[0]), true);
});
