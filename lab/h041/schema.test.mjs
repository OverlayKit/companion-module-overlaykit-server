import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

const SHA256 = 'a'.repeat(64);
const COMMIT = 'b'.repeat(40);
const CONTAINER_ID = 'c'.repeat(64);
const SERIAL = 'A00SA5492OQMLF';
const INITIAL_STAT = Object.freeze({
  stDev: '7',
  inode: '1402',
  ctimeNs: '1785017681209719431',
  mode: '0660',
  uid: 0,
  gid: 1002,
  rdev: '61696',
  rdevHex: 'f1:0',
  major: 241,
  minor: 0,
  isCharacterDevice: true,
  isSymbolicLink: false,
});
const RETURNED_STAT = Object.freeze({
  ...INITIAL_STAT,
  inode: '1417',
  ctimeNs: '1785020103123456789',
});

function statValue(overrides = {}) {
  return { ...INITIAL_STAT, ...overrides };
}

function value(path, stat = INITIAL_STAT) {
  return {
    kind: 'value',
    path,
    value: { ...stat },
  };
}

function missing(path) {
  return { kind: 'missing', path, code: 'ENOENT' };
}

function lifecycle() {
  return {
    containerId: CONTAINER_ID,
    imageId: 'sha256:e7d24e3b0e32b0edb799f262493536cb1a47d307af4e6527551427e09266bf10',
    startedAt: '2026-07-25T23:00:00.000Z',
    restartCount: 0,
    hostPid: 410_000,
    pid1StartTicks: 1_600_000,
    pidNamespace: 'pid:[4026533000]',
    mountNamespace: 'mnt:[4026533001]',
    cgroup: '0::/',
    hostCgroup: `0::/system.slice/docker-${CONTAINER_ID}.scope`,
    cgroupNamespaceMode: 'private',
  };
}

function descriptor(stat = INITIAL_STAT) {
  return {
    descriptor: '20',
    target: '/dev/hidraw0',
    stat: { ...stat },
    fdinfoSha256: SHA256,
  };
}

function worker(fileDescriptors = []) {
  return {
    pid: 56,
    startTicks: 1_600_042,
    ppid: 1,
    parentStartTicks: 1_600_000,
    uid: 1000,
    gid: 1000,
    groups: [1000, 1002],
    command: 'node',
    cmdline: ['/app/node-runtimes/main/bin/node', '/app/dist/SurfaceThread.js'],
    cgroup: '0::/system.slice/docker-h041.scope',
    pidNamespace: 'pid:[4026533000]',
    mountNamespace: 'mnt:[4026533001]',
    fileDescriptors: structuredClone(fileDescriptors),
  };
}

function pid1() {
  return {
    pid: 1,
    startTicks: 1_600_000,
    ppid: 0,
    parentStartTicks: null,
    uid: 1000,
    gid: 1000,
    groups: [1000, 1002],
    command: 'node',
    cmdline: ['/app/node-runtimes/main/bin/node', '/app/dist/main.js'],
    cgroup: '0::/system.slice/docker-h041.scope',
    pidNamespace: 'pid:[4026533000]',
    mountNamespace: 'mnt:[4026533001]',
  };
}

function containerReceipt() {
  return {
    containerId: CONTAINER_ID,
    name: 'h041-companion-abcdef012345',
    imageId: 'sha256:e7d24e3b0edb799f262493536cb1a47d307af4e6527551427e09266bf10',
    running: true,
    healthy: false,
    healthStatus: null,
    startedAt: '2026-07-25T23:00:00.000Z',
    restartCount: 0,
    hostPid: 410_000,
    hostPidStartTicks: 1_600_000,
    hostPidNamespace: 'pid:[4026533000]',
    hostMountNamespace: 'mnt:[4026533001]',
    hostCgroup: `0::/system.slice/docker-${CONTAINER_ID}.scope`,
    cgroupNamespaceMode: 'private',
    restartPolicy: 'no',
    autoRemove: true,
    networkMode: 'none',
    privileged: false,
    readOnlyRootfs: true,
    capAdd: ['CAP_SETGID', 'CAP_SETUID'],
    capDrop: ['ALL'],
    securityOpt: ['no-new-privileges'],
    groupAdd: ['1002'],
    pidsLimit: 128,
    memory: 1_073_741_824,
    deviceCgroupRules: ['c 241:0 rw'],
    devices: [],
    tmpfs: {
      '/companion': 'rw,nosuid,nodev,noexec,size=268435456,uid=1000,gid=1000,mode=0700',
      '/tmp': 'rw,nosuid,nodev,size=67108864,uid=1000,gid=1000,mode=1777',
    },
    user: '0:0',
    environment: [
      'COMPANION_CONFIG_BASEDIR=/companion',
      'H041_UID=1000',
      'H041_GID=1000',
      'H041_DEVICE_GID=1002',
      'H041_DYNAMIC_PATH=/host-dev/hidraw0',
      'H041_COMPAT_PATH=/dev/hidraw0',
    ],
    labels: { 'dev.overlaykit.hypothesis': 'H-041' },
    entrypoint: ['/bin/bash'],
    command: ['/h041-entrypoint.sh'],
    mounts: [
      {
        type: 'bind',
        source: '/dev',
        destination: '/host-dev',
        rw: false,
        propagation: 'rprivate',
      },
      {
        type: 'bind',
        source: '/tmp/h041-entrypoint.sh',
        destination: '/h041-entrypoint.sh',
        rw: false,
        propagation: 'rprivate',
      },
      {
        type: 'bind',
        source: '/tmp/h041-container-observer.mjs',
        destination: '/h041-container-observer.mjs',
        rw: false,
        propagation: 'rprivate',
      },
    ],
    declaredMounts: [
      {
        type: 'bind',
        source: '/dev',
        target: '/host-dev',
        readOnly: true,
        bindOptions: { NonRecursive: true },
      },
    ],
  };
}

function markers(opening, ready) {
  return {
    opening,
    ready,
    openFailed: 0,
    relevantLines: [
      ...Array.from({ length: opening }, () => `Opening surface panel: streamdeck:${SERIAL}`),
      ...Array.from({ length: ready }, () => `Surface panel ready: streamdeck:${SERIAL}`),
    ],
  };
}

function observer({ present, returned = false }) {
  const currentStat = returned ? RETURNED_STAT : INITIAL_STAT;
  const currentWorker = worker(present ? [descriptor(currentStat)] : []);
  const { fileDescriptors: _fileDescriptors, ...workerProcess } = currentWorker;
  const primary = pid1();
  const compatibilityLstat = value(
    '/dev/hidraw0',
    statValue({
      inode: '25',
      ctimeNs: '1785017681209000000',
      mode: '0777',
      gid: 1000,
      rdev: '0',
      rdevHex: '0:0',
      major: 0,
      minor: 0,
      isCharacterDevice: false,
      isSymbolicLink: true,
    })
  );
  return {
    schemaVersion: 'overlaykit-h041-container-observation/v1',
    capturedAt: returned
      ? '2026-07-25T23:02:00.000Z'
      : present
        ? '2026-07-25T23:00:10.000Z'
        : '2026-07-25T23:01:00.000Z',
    monotonicNs: returned ? '3000' : present ? '1000' : '2000',
    metadataOnly: true,
    paths: {
      dynamic: {
        path: '/host-dev/hidraw0',
        lstat: present ? value('/host-dev/hidraw0', currentStat) : missing('/host-dev/hidraw0'),
        stat: present ? value('/host-dev/hidraw0', currentStat) : missing('/host-dev/hidraw0'),
      },
      compat: {
        path: '/dev/hidraw0',
        linkTarget: '/host-dev/hidraw0',
        lstat: compatibilityLstat,
        stat: present ? value('/dev/hidraw0', currentStat) : missing('/dev/hidraw0'),
      },
    },
    target: { major: 241, minor: 0 },
    pid1: primary,
    processes: [primary, workerProcess],
    surfaceWorkers: [currentWorker],
  };
}

function runtime(phase) {
  const present = phase !== 'absent-poll';
  const returned = phase === 'reacquisition-poll';
  return {
    capturedAt: returned
      ? '2026-07-25T23:02:00.000Z'
      : present
        ? '2026-07-25T23:00:10.000Z'
        : '2026-07-25T23:01:00.000Z',
    monotonicNs: returned ? '3000' : present ? '1000' : '2000',
    phase,
    container: containerReceipt(),
    lifecycle: lifecycle(),
    observer: observer({ present, returned }),
    markers: returned ? markers(2, 2) : markers(1, 1),
  };
}

function hostSnapshot(state, { returned = false, includeOwner = false } = {}) {
  const present = state === 'present';
  const currentStat = returned ? RETURNED_STAT : INITIAL_STAT;
  const deviceNumber = returned ? '14' : '13';
  const hidDevicePath = `/sys/devices/pci0000:00/usb1/1-2/0003:0FD9:0080.${
    returned ? '0012' : '0011'
  }`;
  const owner = {
    applicable: true,
    observed: true,
    usageError: false,
    pids: [],
    stderr: '',
  };
  return {
    capturedAt: returned
      ? '2026-07-25T23:02:00.000Z'
      : present
        ? '2026-07-25T23:00:10.000Z'
        : '2026-07-25T23:01:00.000Z',
    monotonicNs: returned ? '3000' : present ? '1000' : '2000',
    expectedSerial: SERIAL,
    scope: {
      mountNamespace: 'mnt:[4026531832]',
      bootId: '30b83905-13f4-439a-9c1e-5c8424023fd7',
    },
    lsusb: {
      observed: true,
      exitCode: 0,
      errorCode: null,
      matches: present ? [`Bus 001 Device ${deviceNumber}: ID 0fd9:0080 Stream Deck MK.2`] : [],
      stderr: '',
    },
    usb: present
      ? [
          {
            sysfsPath: '/sys/devices/pci0000:00/usb1/1-2',
            vendorId: '0fd9',
            productId: '0080',
            serial: SERIAL,
            deviceNumber,
            serialMatches: true,
          },
        ]
      : [],
    hidraw: present
      ? [
          {
            name: 'hidraw0',
            devicePath: '/dev/hidraw0',
            hidDevicePath,
            serialMatches: true,
            hid: { unique: SERIAL },
            usbAncestor: { serial: SERIAL, deviceNumber },
            stat: { ...currentStat },
            ...(includeOwner ? { owner } : {}),
          },
        ]
      : [],
    priorPath: {
      path: '/dev/hidraw0',
      stat: { kind: 'value', value: { ...INITIAL_STAT } },
    },
    errors: [],
    state,
  };
}

function inventoryEntry({ returned = false } = {}) {
  const currentStat = returned ? RETURNED_STAT : INITIAL_STAT;
  const deviceNumber = returned ? '14' : '13';
  return {
    name: 'hidraw0',
    classPath: '/sys/class/hidraw/hidraw0',
    devicePath: '/dev/hidraw0',
    hidDevicePath: `/sys/devices/pci0000:00/usb1/1-2/0003:0FD9:0080.${returned ? '0012' : '0011'}`,
    hid: {
      vendorId: '0fd9',
      productId: '0080',
      unique: SERIAL,
      name: 'Elgato Stream Deck MK.2',
    },
    classDevice: { devName: 'hidraw0', major: 241, minor: 0 },
    usbAncestor: {
      vendorId: '0fd9',
      productId: '0080',
      serial: SERIAL,
      deviceNumber,
    },
    stat: {
      before: { kind: 'value', value: { ...currentStat } },
      after: { kind: 'value', value: { ...currentStat } },
      stable: true,
      value: { ...currentStat },
      matchesClass: true,
    },
    errors: [],
  };
}

function humanWindow(stage, openedMonotonicNs, closedMonotonicNs) {
  return {
    stage,
    challenge: stage === 'disconnect' ? 'abcdef012345' : '123456abcdef',
    timeoutSeconds: 60,
    instruction: `${stage} the exact MK.2 only`,
    openedAt: stage === 'disconnect' ? '2026-07-25T23:00:20.000Z' : '2026-07-25T23:01:10.000Z',
    openedMonotonicNs,
    closedAt: stage === 'disconnect' ? '2026-07-25T23:01:00.000Z' : '2026-07-25T23:02:00.000Z',
    closedMonotonicNs,
  };
}

function auditEntries() {
  const sequence = [
    ['docker-run', 'setup'],
    ['docker-observe', 'baseline-poll'],
    ['docker-logs', 'baseline-poll'],
    ['docker-inspect', 'baseline-poll'],
    ['physical-disconnect-window', 'disconnect'],
    ['docker-observe', 'absent-poll'],
    ['docker-logs', 'absent-poll'],
    ['docker-inspect', 'absent-poll'],
    ['physical-reconnect-window', 'reconnect'],
    ['docker-observe', 'reacquisition-poll'],
    ['docker-logs', 'reacquisition-poll'],
    ['docker-inspect', 'reacquisition-poll'],
    ['docker-stop', 'cleanup'],
  ];
  return sequence.map(([kind, phase], index) => ({
    at: '2026-07-25T23:00:00.000Z',
    monotonicNs: String(1000 + index),
    kind,
    phase,
  }));
}

function sourceSha256() {
  return Object.fromEntries(
    [
      '.overlaykit/governance/changes/CHG-0012.json',
      'lab/h037/acquisition-lib.mjs',
      'lab/h039/host-observer.mjs',
      'lab/h039/reconnect-lib.mjs',
      'lab/h040/probe-lib.mjs',
      'lab/h040/schemas/docker-mapping-run.schema.json',
      'lab/h040/verify.mjs',
      'lab/h041/container-observer.mjs',
      'lab/h041/entrypoint.sh',
      'lab/h041/host-inventory.mjs',
      'lab/h041/reacquisition-lib.mjs',
      'lab/h041/run.mjs',
      'lab/h041/schema.test.mjs',
      'lab/h041/schemas/dynamic-reacquisition-run.schema.json',
    ].map((path) => [path, SHA256])
  );
}

function predecessor(path, receiptName, receiptKind) {
  return {
    path,
    fileSha256: SHA256,
    evidenceSha256: SHA256,
    [receiptKind]: { path: receiptName, sha256: SHA256 },
  };
}

function supportedRun() {
  const initialMarkers = markers(1, 1);
  const absentMarkers = markers(1, 1);
  const finalMarkers = markers(2, 2);
  return {
    schemaVersion: 'overlaykit-h041-dynamic-reacquisition-run/v1',
    hypothesis: 'H-041',
    runId: 'h041-2026-07-25T23-00-00-000Z-deadbeef',
    startedAt: '2026-07-25T23:00:00.000Z',
    completedAt: '2026-07-25T23:03:00.000Z',
    outcome: {
      status: 'supported',
      stage: 'complete',
      reason: 'both bounded post-return observations were recorded',
    },
    collector: {
      node: 'v22.20.0',
      repository: 'https://github.com/OverlayKit/companion-module-overlaykit-server.git',
      commit: COMMIT,
      sourceSha256: sourceSha256(),
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
      h037: predecessor(
        'artifacts/h037/acquisition-2026-07-25.json',
        'h037-validation.json',
        'validationReceipt'
      ),
      h039: predecessor(
        'artifacts/h039/h039-2026-07-25/run.json',
        'h039-verification.json',
        'verificationReceipt'
      ),
      h040: predecessor(
        'artifacts/h040/h040-2026-07-25/run.json',
        'h040-verification.json',
        'verificationReceipt'
      ),
    },
    host: {
      observedAt: '2026-07-25T23:00:00.000Z',
      osId: 'fedora',
      osVersion: '43',
      kernel: '7.1.4-104.fc43.x86_64',
      architecture: 'x64',
      machine: 'x86_64',
      principal: {
        user: 'rod',
        uid: 1000,
        gid: 1000,
        groups: [1000, 1002],
        home: '/home/rod',
      },
      graphicalSession: {
        Id: '2',
        User: '1000',
        Name: 'rod',
        Seat: 'seat0',
        Active: 'yes',
        Remote: 'no',
        Type: 'wayland',
      },
      docker: {
        version: {
          Client: { Version: '28.3.3' },
          Server: { Version: '28.3.3' },
        },
        info: { ServerVersion: '28.3.3' },
      },
    },
    device: {
      vendorId: '0fd9',
      productId: '0080',
      model: 'Elgato Stream Deck MK.2',
      serial: SERIAL,
      initialPath: '/dev/hidraw0',
      returnedPath: '/dev/hidraw0',
      initialRdevHex: 'f1:0',
      returnedRdevHex: 'f1:0',
      transition: 'same-path-same-rdev',
      initialInventory: [inventoryEntry()],
      returnedInventory: [inventoryEntry({ returned: true })],
    },
    companion: {
      name: 'h041-companion-abcdef012345',
      containerId: CONTAINER_ID,
      imageReference:
        'ghcr.io/bitfocus/companion/companion:v4.3.3@sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e',
      imageId: 'sha256:e7d24e3b0e32b0edb799f262493536cb1a47d307af4e6527551427e09266bf10',
      repoDigests: [
        'ghcr.io/bitfocus/companion/companion@sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e',
      ],
      version: 'v4.3.3',
      revision: '06a7406709d6a858039333a8988047296ef3aa4a',
      dynamicRoot: '/host-dev',
      dynamicPath: '/host-dev/hidraw0',
      compatibilityPath: '/dev/hidraw0',
      deviceCgroupRule: 'c 241:0 rw',
      deviceGid: 1002,
      staticDevices: [],
      initialLifecycle: lifecycle(),
      absentLifecycle: lifecycle(),
      finalLifecycle: lifecycle(),
      workerLifecycle: {
        initial: [worker([descriptor(INITIAL_STAT)])],
        absent: [worker([])],
        final: [worker([descriptor(RETURNED_STAT)])],
      },
    },
    windows: {
      disconnect: humanWindow('disconnect', '1100', '2000'),
      reconnect: humanWindow('reconnect', '2100', '3000'),
      reacquisition: {
        startedAt: '2026-07-25T23:02:00.000Z',
        startedMonotonicNs: '3000',
        completedAt: '2026-07-25T23:02:01.000Z',
        completedMonotonicNs: '3100',
        timeoutSeconds: 30,
        deadlineExpired: false,
      },
    },
    observations: {
      preflight: {
        host: hostSnapshot('present', { includeOwner: true }),
      },
      initial: {
        host: hostSnapshot('present'),
        runtime: runtime('baseline-poll'),
      },
      absent: {
        host: hostSnapshot('absent'),
        runtime: runtime('absent-poll'),
      },
      returned: {
        host: hostSnapshot('present', { returned: true }),
        runtime: runtime('reacquisition-poll'),
      },
      reacquisition: {
        currentDescriptorObserved: true,
        postReturnLogMarkersObserved: true,
        initialMarkers,
        absentMarkers,
        finalMarkers,
      },
      artifacts: {
        hostPoll: { path: 'host-poll.jsonl', sha256: SHA256 },
        runtimePoll: { path: 'runtime-poll.jsonl', sha256: SHA256 },
        initialLogs: { path: 'logs-initial.txt', sha256: SHA256 },
        absentLogs: { path: 'logs-absent.txt', sha256: SHA256 },
        finalLogs: { path: 'logs-final.txt', sha256: SHA256 },
      },
    },
    predicates: {
      complete: true,
      interventionFree: true,
      permissionBoundaryExact: true,
      hostEpochChanged: true,
      dynamicViewTracksHost: true,
      topLevelLifecycleUnchanged: true,
      baselineAcquired: true,
      descriptorAbsent: true,
      postReturnDescriptorObserved: true,
      postReturnLogMarkersObserved: true,
      deadlineBoundaryConsistent: true,
    },
    invocationAudit: {
      mode: 'runner-metadata-observation-with-bounded-companion-target-io',
      runnerDeviceOpenCount: 0,
      runnerDeviceReadCount: 0,
      runnerDeviceWriteCount: 0,
      virtualInvocationCount: 0,
      restartRescanReconfigureCount: 0,
      productionConfigurationMutationCount: 0,
      interventionFree: true,
      entries: auditEntries(),
      forbidden: [],
      passed: true,
    },
    claimBoundary: {
      proves: ['one bounded dynamic-view descriptor-reacquisition observation'],
      excludes: ['physical button delivery and production architecture approval'],
    },
    cleanup: {
      startedAt: '2026-07-25T23:02:30.000Z',
      completedAt: '2026-07-25T23:03:00.000Z',
      containerId: CONTAINER_ID,
      containerRemoved: true,
      host: hostSnapshot('present', { returned: true, includeOwner: true }),
      owners: [
        {
          devicePath: '/dev/hidraw0',
          owner: {
            applicable: true,
            observed: true,
            usageError: false,
            pids: [],
            stderr: '',
          },
        },
      ],
      hostConfigurationChanged: false,
      productionConfigurationChanged: false,
      successful: true,
      error: null,
    },
    evidenceSha256: SHA256,
  };
}

function setPostReturnDescriptor(run, observed) {
  run.predicates.postReturnDescriptorObserved = observed;
  run.observations.reacquisition.currentDescriptorObserved = observed;
  const finalWorker = worker(observed ? [descriptor(RETURNED_STAT)] : []);
  const { fileDescriptors: _fileDescriptors, ...workerProcess } = finalWorker;
  run.companion.workerLifecycle.final = [structuredClone(finalWorker)];
  run.observations.returned.runtime.observer.surfaceWorkers = [structuredClone(finalWorker)];
  run.observations.returned.runtime.observer.processes = [pid1(), structuredClone(workerProcess)];
}

function setPostReturnMarkers(run, observed) {
  run.predicates.postReturnLogMarkersObserved = observed;
  run.observations.reacquisition.postReturnLogMarkersObserved = observed;
  const finalMarkers = observed
    ? markers(2, 2)
    : structuredClone(run.observations.reacquisition.absentMarkers);
  run.observations.reacquisition.finalMarkers = structuredClone(finalMarkers);
  run.observations.returned.runtime.markers = structuredClone(finalMarkers);
}

function refutedRun() {
  const run = supportedRun();
  run.outcome = {
    status: 'refuted',
    stage: 'companion-reacquisition',
    reason: 'neither bounded post-return observation appeared before the deadline',
  };
  setPostReturnDescriptor(run, false);
  setPostReturnMarkers(run, false);
  run.windows.reacquisition.deadlineExpired = true;
  return run;
}

const schema = JSON.parse(
  await readFile(
    new URL('./schemas/dynamic-reacquisition-run.schema.json', import.meta.url),
    'utf8'
  )
);
const validate = new Ajv2020({
  strict: false,
  allErrors: true,
  validateFormats: false,
}).compile(schema);

function assertAccepted(run, message) {
  assert.equal(validate(run), true, `${message}: ${JSON.stringify(validate.errors)}`);
}

function assertRejected(run, message) {
  assert.equal(validate(run), false, message);
}

test('H-041 schema compiles and accepts a complete supported runner-shaped fixture', () => {
  assertAccepted(supportedRun(), 'supported H-041 fixture was rejected');
});

test('refuted evidence requires both post-return observations false and an expired deadline', () => {
  assertAccepted(refutedRun(), 'complete bounded refutation was rejected');

  const descriptorObserved = refutedRun();
  setPostReturnDescriptor(descriptorObserved, true);
  assertRejected(descriptorObserved, 'refutation accepted a post-return descriptor');

  const markersObserved = refutedRun();
  setPostReturnMarkers(markersObserved, true);
  assertRejected(markersObserved, 'refutation accepted post-return acquisition markers');

  const deadlineNotExpired = refutedRun();
  deadlineNotExpired.windows.reacquisition.deadlineExpired = false;
  assertRejected(deadlineNotExpired, 'refutation accepted an open reacquisition window');
});

test('contradictory post-return evidence is accepted only as inconclusive', () => {
  const run = supportedRun();
  run.outcome = {
    status: 'inconclusive',
    stage: 'contradictory-reacquisition',
    reason: 'the descriptor and log observations disagree',
  };
  setPostReturnMarkers(run, false);
  run.windows.reacquisition.deadlineExpired = true;
  assertAccepted(run, 'contradictory inconclusive evidence was rejected');

  run.outcome.status = 'supported';
  run.outcome.stage = 'complete';
  assertRejected(run, 'contradictory evidence was accepted as support');
});

test('overclaims and weakened operational receipts fail closed', () => {
  const overclaim = supportedRun();
  overclaim.predicates.topLevelLifecycleUnchanged = false;
  assertRejected(overclaim, 'supported evidence accepted lifecycle drift');

  const missingCleanup = supportedRun();
  delete missingCleanup.cleanup;
  assertRejected(missingCleanup, 'evidence without cleanup was accepted');

  const intervention = supportedRun();
  intervention.invocationAudit.restartRescanReconfigureCount = 1;
  assertRejected(intervention, 'nonzero restart, rescan, or reconfiguration was accepted');

  const staticDevice = supportedRun();
  staticDevice.companion.staticDevices.push({
    pathOnHost: '/dev/hidraw0',
    pathInContainer: '/dev/hidraw0',
    cgroupPermissions: 'rwm',
  });
  assertRejected(staticDevice, 'a static Docker device mapping was accepted');

  const unstableSource = supportedRun();
  unstableSource.collector.sourceStable = false;
  assertRejected(unstableSource, 'source instability was accepted');
});
