import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

const SHA256 = 'a'.repeat(64);
const COMMIT = 'b'.repeat(40);
const CONTAINER_ID = 'c'.repeat(64);

function hostSnapshot(state) {
  const present = state === 'present';
  return {
    capturedAt: '2026-07-25T22:00:00.000Z',
    monotonicNs: '100',
    expectedSerial: 'A00SA5492OQMLF',
    scope: { bootId: 'boot-id', mountNamespace: 'mnt:[1]' },
    lsusb: {
      observed: true,
      exitCode: 0,
      errorCode: null,
      matches: present ? ['Bus 001 Device 002: ID 0fd9:0080 Stream Deck MK.2'] : [],
      stderr: '',
    },
    usb: present ? [{ serial: 'A00SA5492OQMLF' }] : [],
    hidraw: present ? [{ devicePath: '/dev/hidraw0' }] : [],
    priorPath: {},
    errors: [],
    state,
  };
}

function value(path) {
  return {
    kind: 'value',
    path,
    value: {
      stDev: '7',
      inode: '244',
      ctimeNs: '1000',
      rdev: '61696',
      rdevHex: 'f1:0',
      major: 241,
      minor: 0,
      isCharacterDevice: true,
    },
  };
}

function missing(path) {
  return { kind: 'missing', path, code: 'ENOENT' };
}

function window(stage) {
  return {
    stage,
    challenge: 'abcdef012345',
    openedAt: '2026-07-25T22:00:00.000Z',
    openedMonotonicNs: '100',
    timeoutSeconds: 60,
    instruction: stage,
    closedAt: '2026-07-25T22:01:00.000Z',
    closedMonotonicNs: '200',
  };
}

function auditEntries() {
  const name = 'h040-probe-abcdef012345';
  const stat = (view, path) => ({
    kind: 'docker-stat',
    view,
    path,
    operation: 'fs.statSync',
    metadataOnly: true,
  });
  return [
    {
      kind: 'docker-run',
      name,
      imageReference: 'node:22',
      staticHostPath: '/dev/hidraw0',
      staticContainerPath: '/tmp/h040-static-hidraw',
      staticCgroupPermissions: 'm',
      dynamicHostPath: '/dev',
      dynamicContainerPath: '/host-dev',
      dynamicReadOnly: true,
      user: '65534:65534',
      network: 'none',
      readOnlyRootfs: true,
      capDrop: ['ALL'],
      noNewPrivileges: true,
      command: ['sleep', 'infinity'],
      metadataOnly: true,
    },
    { kind: 'docker-inspect', target: name, metadataOnly: true },
    stat('initial-static', '/tmp/h040-static-hidraw'),
    stat('initial-dynamic', '/host-dev/hidraw0'),
    stat('absent-static', '/tmp/h040-static-hidraw'),
    stat('absent-dynamic', '/host-dev/hidraw0'),
    stat('returned-static', '/tmp/h040-static-hidraw'),
    stat('returned-dynamic', '/host-dev/hidraw0'),
    { kind: 'docker-inspect', target: name, metadataOnly: true },
    {
      kind: 'docker-stop',
      target: name,
      timeoutSeconds: 5,
      metadataOnly: true,
    },
  ];
}

function supportedRun() {
  return {
    schemaVersion: 'overlaykit-h040-docker-mapping-run/v1',
    hypothesis: 'H-040',
    runId: 'h040-test',
    startedAt: '2026-07-25T22:00:00.000Z',
    completedAt: '2026-07-25T22:02:00.000Z',
    outcome: {
      status: 'supported',
      stage: 'complete',
      reason: 'all bounded mapping predicates passed',
    },
    collector: {
      node: 'v22.20.0',
      commit: COMMIT,
      sourceSha256: {
        'lab/h040/run.mjs': SHA256,
        'lab/h040/schemas/docker-mapping-run.schema.json': SHA256,
      },
      sourceStable: true,
      governance: {
        manifestSnapshotPath: 'governance-manifest.json',
        manifestFileSha256: SHA256,
        manifestContentHash: SHA256,
        changeSha256: SHA256,
        verifyReceiptPath: 'governance-verify.txt',
        verifyReceiptSha256: SHA256,
        planHash: SHA256,
      },
    },
    inputs: {
      h039Path: 'artifacts/h039/run.json',
      h039FileSha256: SHA256,
      h039EvidenceSha256: SHA256,
      h039VerifyReceipt: { path: 'h039-verification.json', sha256: SHA256 },
    },
    host: {
      observedAt: '2026-07-25T22:00:00.000Z',
      osId: 'fedora',
      osVersion: '43',
      kernel: '7.1.4-104.fc43.x86_64',
      architecture: 'x64',
      machine: 'x86_64',
      principal: { user: 'rod' },
      graphicalSession: { Active: 'yes' },
    },
    device: {
      vendorId: '0fd9',
      productId: '0080',
      model: 'Elgato Stream Deck MK.2',
      serial: 'A00SA5492OQMLF',
      major: 241,
      minor: 0,
      initialPath: '/dev/hidraw0',
      returnedPath: '/dev/hidraw0',
      transition: 'same-path-same-rdev',
    },
    probe: {
      name: 'h040-probe-abcdef012345',
      containerId: CONTAINER_ID,
      imageReference: 'node:22',
      imageId: `sha256:${SHA256}`,
      repoDigests: [`node@sha256:${SHA256}`],
      privileged: false,
      staticPath: '/tmp/h040-static-hidraw',
      dynamicRoot: '/host-dev',
      lifecycleBefore: probeLifecycle(),
      lifecycleAfter: probeLifecycle(),
      lifecycleUnchanged: true,
      security: {
        network: 'none',
        readOnlyRootfs: true,
        capDrop: ['ALL'],
        noNewPrivileges: true,
        user: '65534:65534',
        staticCgroupPermissions: 'm',
        dynamicReadOnly: true,
      },
    },
    windows: {
      disconnect: window('disconnect'),
      reconnect: window('reconnect'),
    },
    observations: {
      initial: {
        capturedAt: '2026-07-25T22:00:00.000Z',
        monotonicNs: '100',
        host: hostSnapshot('present'),
        static: value('/tmp/h040-static-hidraw'),
        dynamic: value('/host-dev/hidraw0'),
      },
      absent: {
        capturedAt: '2026-07-25T22:00:30.000Z',
        monotonicNs: '150',
        host: hostSnapshot('absent'),
        static: value('/tmp/h040-static-hidraw'),
        dynamic: missing('/host-dev/hidraw0'),
      },
      returned: {
        capturedAt: '2026-07-25T22:01:00.000Z',
        monotonicNs: '200',
        host: hostSnapshot('present'),
        static: value('/tmp/h040-static-hidraw'),
        dynamic: value('/host-dev/hidraw0'),
      },
      hostPollArtifact: { path: 'host-poll.jsonl', sha256: SHA256 },
    },
    predicates: {
      complete: true,
      metadataOnly: true,
      dynamicInitialMatchesHost: true,
      dynamicReturnedMatchesHost: true,
      dynamicAbsent: true,
      staticPersists: true,
      staticUnchanged: true,
      hostEpochChanged: true,
    },
    invocationAudit: {
      mode: 'metadata-only',
      metadataOnly: true,
      deviceReads: 0,
      deviceWrites: 0,
      virtualInvocationCount: 0,
      entries: auditEntries(),
      forbidden: [],
      passed: true,
    },
    claimBoundary: {
      proves: ['bounded Docker namespace mapping behavior'],
      excludes: ['Companion functional reacquisition'],
    },
    cleanup: {
      startedAt: '2026-07-25T22:02:00.000Z',
      completedAt: '2026-07-25T22:02:01.000Z',
      containerId: CONTAINER_ID,
      containerRemoved: true,
      host: hostSnapshot('present'),
      owners: [{ devicePath: '/dev/hidraw0', owner: { observed: true, pids: [] } }],
      hostConfigurationChanged: false,
      successful: true,
      error: null,
    },
    evidenceSha256: SHA256,
  };
}

function probeLifecycle() {
  return {
    containerId: CONTAINER_ID,
    name: 'h040-probe-abcdef012345',
    imageId: `sha256:${SHA256}`,
    running: true,
    startedAt: '2026-07-25T22:00:00.000Z',
    restartCount: 0,
    hostPid: 1234,
    pid1StartTicks: 100,
    restartPolicy: 'no',
    autoRemove: true,
    networkMode: 'none',
    privileged: false,
    readOnlyRootfs: true,
    capDrop: ['ALL'],
    securityOpt: ['no-new-privileges'],
    groupAdd: [],
    pidsLimit: 32,
    memory: 134217728,
    deviceCgroupRules: null,
    user: '65534:65534',
    command: ['sleep', 'infinity'],
    devices: [
      {
        pathOnHost: '/dev/hidraw0',
        pathInContainer: '/tmp/h040-static-hidraw',
        cgroupPermissions: 'm',
      },
    ],
    mounts: [{ type: 'bind', source: '/dev', destination: '/host-dev', rw: false }],
  };
}

test('H-040 schema compiles and accepts the complete supported mapping pattern', async () => {
  const schema = JSON.parse(
    await readFile(new URL('./schemas/docker-mapping-run.schema.json', import.meta.url), 'utf8')
  );
  const validate = new Ajv2020({ strict: false }).compile(schema);
  const run = supportedRun();
  assert.equal(validate(run), true, JSON.stringify(validate.errors));
  assert.equal(schema.properties.cleanup.properties.successful.const, true);
  assert.equal(schema.properties.cleanup.properties.containerRemoved.const, true);
});

test('supported requires every probe predicate and the metadata-only audit', async () => {
  const schema = JSON.parse(
    await readFile(new URL('./schemas/docker-mapping-run.schema.json', import.meta.url), 'utf8')
  );
  const validate = new Ajv2020({ strict: false }).compile(schema);
  for (const key of Object.keys(supportedRun().predicates)) {
    const run = supportedRun();
    run.predicates[key] = false;
    assert.equal(validate(run), false, `${key} unexpectedly allowed supported evidence`);
  }
  const nonMetadata = supportedRun();
  nonMetadata.invocationAudit.metadataOnly = false;
  assert.equal(validate(nonMetadata), false);
});

test('supported requires dynamic value/missing/value and persistent static value receipts', async () => {
  const schema = JSON.parse(
    await readFile(new URL('./schemas/docker-mapping-run.schema.json', import.meta.url), 'utf8')
  );
  const validate = new Ajv2020({ strict: false }).compile(schema);
  const dynamicDidNotDisappear = supportedRun();
  dynamicDidNotDisappear.observations.absent.dynamic = value('/host-dev/hidraw0');
  assert.equal(validate(dynamicDidNotDisappear), false);
  const staticDisappeared = supportedRun();
  staticDisappeared.observations.absent.static = missing('/tmp/h040-static-hidraw');
  assert.equal(validate(staticDisappeared), false);
});

test('refuted requires complete metadata-only capture and at least one false result', async () => {
  const schema = JSON.parse(
    await readFile(new URL('./schemas/docker-mapping-run.schema.json', import.meta.url), 'utf8')
  );
  const validate = new Ajv2020({ strict: false }).compile(schema);
  const refuted = supportedRun();
  refuted.outcome = {
    status: 'refuted',
    stage: 'mapping-observation',
    reason: 'dynamic mapping stayed visible while absent',
  };
  refuted.predicates.dynamicAbsent = false;
  refuted.observations.absent.dynamic = value('/host-dev/hidraw0');
  assert.equal(validate(refuted), true, JSON.stringify(validate.errors));

  const allTrue = supportedRun();
  allTrue.outcome = {
    status: 'refuted',
    stage: 'mapping-observation',
    reason: 'invalid all-true refutation',
  };
  assert.equal(validate(allTrue), false);

  const incomplete = structuredClone(refuted);
  incomplete.predicates.complete = false;
  assert.equal(validate(incomplete), false);

  const nonMetadata = structuredClone(refuted);
  nonMetadata.predicates.metadataOnly = false;
  assert.equal(validate(nonMetadata), false);
});

test('probe stat unions and cleanup fail closed', async () => {
  const schema = JSON.parse(
    await readFile(new URL('./schemas/docker-mapping-run.schema.json', import.meta.url), 'utf8')
  );
  const validate = new Ajv2020({ strict: false }).compile(schema);
  const invalidStat = supportedRun();
  invalidStat.observations.initial.dynamic = {
    kind: 'missing',
    path: '/dev/hidraw0',
    code: 'ENOENT',
  };
  assert.equal(validate(invalidStat), false);

  const dirtyCleanup = supportedRun();
  dirtyCleanup.cleanup.containerRemoved = false;
  assert.equal(validate(dirtyCleanup), false);
});

test('runner audit, isolation, device identity, and cleanup receipts fail closed', async () => {
  const schema = JSON.parse(
    await readFile(new URL('./schemas/docker-mapping-run.schema.json', import.meta.url), 'utf8')
  );
  const validate = new Ajv2020({ strict: false }).compile(schema);

  const shortAudit = supportedRun();
  shortAudit.invocationAudit.entries.pop();
  assert.equal(validate(shortAudit), false);

  const wrongOperation = supportedRun();
  wrongOperation.invocationAudit.entries[2].operation = 'fs.readSync';
  assert.equal(validate(wrongOperation), false);

  const privileged = supportedRun();
  privileged.probe.privileged = true;
  assert.equal(validate(privileged), false);

  const incompleteLifecycle = supportedRun();
  delete incompleteLifecycle.probe.lifecycleAfter.pidsLimit;
  assert.equal(validate(incompleteLifecycle), false);

  const incompleteDevice = supportedRun();
  delete incompleteDevice.device.major;
  assert.equal(validate(incompleteDevice), false);

  const inexactCleanup = supportedRun();
  inexactCleanup.cleanup.containerId = 'container-prefix';
  assert.equal(validate(inexactCleanup), false);
});
