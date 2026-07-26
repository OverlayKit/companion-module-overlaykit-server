import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import { H042_REQUIRED_SOURCES } from './runtime-lib.mjs';
import { H042_CLAIM_BOUNDARY } from './signal-lib.mjs';

const SHA256 = 'a'.repeat(64);
const CONTAINER_ID = 'b'.repeat(64);
const INITIAL_STAT = Object.freeze({
  stDev: '7',
  inode: '1417',
  ctimeNs: '1785020102949329753',
  mode: '0660',
  uid: 0,
  gid: 1002,
  rdev: '61696',
  rdevHex: 'f1:0',
  major: 241,
  minor: 0,
  isCharacterDevice: true,
});
const RETURNED_STAT = Object.freeze({
  ...INITIAL_STAT,
  inode: '1432',
  ctimeNs: '1785020432671957921',
});
const CMDLINE = Object.freeze([
  '/app/node-runtimes/node22/bin/node',
  '--enable-source-maps',
  '/app/SurfaceThread.js',
]);

function workerIdentity(pid = 73, startTicks = 2274363) {
  return {
    pid,
    startTicks,
    ppid: 1,
    parentStartTicks: 2274319,
    uid: 1000,
    gid: 1000,
    groups: [1000, 1002],
    cmdline: [...CMDLINE],
    cgroup: '0::/',
    pidNamespace: 'pid:[4026533607]',
    mountNamespace: 'mnt:[4026533386]',
  };
}

function descriptor(stats = RETURNED_STAT) {
  return {
    descriptor: '20',
    target: '/host-dev/hidraw0',
    stat: structuredClone(stats),
    fdinfoSha256: SHA256,
  };
}

function worker({ pid = 73, startTicks = 2274363, descriptors = [] } = {}) {
  return {
    ...workerIdentity(pid, startTicks),
    command: '/app/node-runtimes/node22/bin/node',
    fileDescriptors: structuredClone(descriptors),
  };
}

function pid1() {
  return {
    pid: 1,
    startTicks: 2274319,
    ppid: 0,
    parentStartTicks: null,
    uid: 1000,
    gid: 1000,
    groups: [1000, 1002],
    command: 'node',
    cmdline: ['/app/node-runtimes/node22/bin/node', '/app/companion.js'],
    cgroup: '0::/',
    pidNamespace: 'pid:[4026533607]',
    mountNamespace: 'mnt:[4026533386]',
  };
}

function lifecycle() {
  return {
    containerId: CONTAINER_ID,
    imageId: 'sha256:e7d24e3b0e32b0edb799f262493536cb1a47d307af4e6527551427e09266bf10',
    startedAt: '2026-07-26T01:00:00.000Z',
    restartCount: 0,
    hostPid: 555353,
    pid1StartTicks: 2274319,
    pidNamespace: 'pid:[4026533607]',
    mountNamespace: 'mnt:[4026533386]',
    cgroup: '0::/',
    hostCgroup: `0::/system.slice/docker-${CONTAINER_ID}.scope`,
    cgroupNamespaceMode: 'private',
  };
}

function inventory(stats, usbDeviceNumber) {
  return {
    name: 'hidraw0',
    classPath: '/sys/class/hidraw/hidraw0',
    devicePath: '/dev/hidraw0',
    hidDevicePath: '/sys/devices/pci0000:00/usb1/hidraw0',
    hid: {
      id: '0003:00000FD9:00000080',
      bus: '0003',
      vendorId: '0fd9',
      productId: '0080',
      unique: 'A00SA5492OQMLF',
      name: 'Elgato Stream Deck MK.2',
      physicalPath: 'usb-0000:00:14.0-2/input0',
    },
    classDevice: {
      major: 241,
      minor: 0,
    },
    usbAncestor: {
      sysfsPath: '/sys/devices/pci0000:00/usb1/1-2',
      vendorId: '0fd9',
      productId: '0080',
      serial: 'A00SA5492OQMLF',
      manufacturer: 'Elgato',
      product: 'Stream Deck MK.2',
      busNumber: '1',
      deviceNumber: usbDeviceNumber,
      devicePath: '2',
    },
    stat: {
      before: { kind: 'value', value: structuredClone(stats) },
      after: { kind: 'value', value: structuredClone(stats) },
      stable: true,
      value: structuredClone(stats),
      matchesClass: true,
    },
    errors: [],
  };
}

function hostSnapshot(state, { returned = false } = {}) {
  const stats = returned ? RETURNED_STAT : INITIAL_STAT;
  const usbDeviceNumber = returned ? '15' : '14';
  const owner = {
    applicable: true,
    observed: true,
    usageError: false,
    pids: [],
    exitCode: 1,
    errorCode: null,
    stdout: '',
    stderr: '',
    processes: [],
  };
  return {
    capturedAt: returned ? '2026-07-26T01:02:00.000Z' : '2026-07-26T01:00:00.000Z',
    monotonicNs: returned ? '3000' : state === 'absent' ? '2000' : '1000',
    expectedSerial: 'A00SA5492OQMLF',
    scope: {
      bootId: '30b83905-13f4-439a-9c1e-5c8424023fd7',
      mountNamespace: 'mnt:[4026531832]',
    },
    lsusb: {
      observed: true,
      exitCode: 0,
      errorCode: null,
      matches:
        state === 'present'
          ? [`Bus 001 Device ${usbDeviceNumber}: ID 0fd9:0080 Elgato Systems GmbH Stream Deck MK.2`]
          : [],
      stderr: '',
    },
    usb:
      state === 'present'
        ? [
            {
              sysfsPath: '/sys/devices/pci0000:00/usb1/1-2',
              vendorId: '0fd9',
              productId: '0080',
              serial: 'A00SA5492OQMLF',
              product: 'Stream Deck MK.2',
              manufacturer: 'Elgato',
              busNumber: '1',
              deviceNumber: usbDeviceNumber,
              devicePath: '2',
              dev: '189:13',
              ueventSha256: SHA256,
              serialMatches: true,
            },
          ]
        : [],
    hidraw:
      state === 'present'
        ? [
            {
              name: 'hidraw0',
              classPath: '/sys/class/hidraw/hidraw0',
              hidDevicePath: '/sys/devices/pci0000:00/usb1/hidraw0',
              devicePath: '/dev/hidraw0',
              serialMatches: true,
              hid: {
                id: '0003:00000FD9:00000080',
                unique: 'A00SA5492OQMLF',
                name: 'Elgato Stream Deck MK.2',
                physicalPath: 'usb-0000:00:14.0-2/input0',
                ueventSha256: SHA256,
              },
              classDevice: {
                devName: 'hidraw0',
                major: 241,
                minor: 0,
                ueventSha256: SHA256,
              },
              usbAncestor: {
                sysfsPath: '/sys/devices/pci0000:00/usb1/1-2',
                vendorId: '0fd9',
                productId: '0080',
                serial: 'A00SA5492OQMLF',
                product: 'Stream Deck MK.2',
                manufacturer: 'Elgato',
                busNumber: '1',
                deviceNumber: usbDeviceNumber,
                devicePath: '2',
                dev: '189:13',
                ueventSha256: SHA256,
              },
              before: { kind: 'value', value: structuredClone(stats) },
              owner,
              after: { kind: 'value', value: structuredClone(stats) },
              nodeStable: true,
              nodeMatchesClass: true,
              stat: structuredClone(stats),
              udev: {
                observed: true,
                exitCode: 0,
                errorCode: null,
                properties: { DEVNAME: '/dev/hidraw0' },
                stderr: '',
              },
            },
          ]
        : [],
    priorPath: {
      path: '/dev/hidraw0',
      stat:
        state === 'present'
          ? { kind: 'value', value: structuredClone(stats) }
          : { kind: 'missing', code: 'ENOENT' },
    },
    state,
    errors: [],
  };
}

function pathReceipt(path, state, stats) {
  return state === 'present'
    ? {
        kind: 'value',
        path,
        value: structuredClone(stats),
      }
    : {
        kind: 'missing',
        path,
        code: 'ENOENT',
      };
}

function markers(opening, ready, lines = []) {
  return {
    opening,
    ready,
    openFailed: 0,
    relevantLines: lines,
  };
}

const INITIAL_MARKERS = Object.freeze(
  markers(1, 1, [
    '2026-07-26T01:00:01.000000001Z Opening surface panel: streamdeck:A00SA5492OQMLF',
    '2026-07-26T01:00:01.000000002Z Surface panel ready: streamdeck:A00SA5492OQMLF',
  ])
);
const FINAL_MARKERS = Object.freeze(
  markers(2, 2, [
    ...INITIAL_MARKERS.relevantLines,
    '2026-07-26T01:02:31.000000001Z Opening surface panel: streamdeck:A00SA5492OQMLF',
    '2026-07-26T01:02:31.000000002Z Surface panel ready: streamdeck:A00SA5492OQMLF',
  ])
);

function container() {
  return {
    containerId: CONTAINER_ID,
    name: 'h042-companion-123456abcdef',
    imageId: 'sha256:e7d24e3b0e32b0edb799f262493536cb1a47d307af4e6527551427e09266bf10',
    running: true,
    healthy: true,
    healthStatus: 'healthy',
    startedAt: '2026-07-26T01:00:00.000Z',
    restartCount: 0,
    hostPid: 555353,
    hostPidStartTicks: 2274319,
    hostPidNamespace: 'pid:[4026533607]',
    hostMountNamespace: 'mnt:[4026533386]',
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
    memory: 1073741824,
    deviceCgroupRules: ['c 241:0 rw'],
    devices: [],
    tmpfs: {
      '/companion': 'rw,nosuid,nodev,noexec,size=268435456,uid=1000,gid=1000,mode=0700',
      '/tmp': 'rw,nosuid,nodev,size=67108864,uid=1000,gid=1000,mode=1777',
    },
    user: '0:0',
    environment: [
      'H041_UID=1000',
      'H041_GID=1000',
      'H041_DEVICE_GID=1002',
      'H041_DYNAMIC_PATH=/host-dev/hidraw0',
      'H041_COMPAT_PATH=/dev/hidraw0',
      'PATH=/app/node-runtimes/main/bin',
      'COMPANION_CONFIG_BASEDIR=/companion',
    ],
    labels: {
      'dev.overlaykit.hypothesis': 'H-042',
      'org.opencontainers.image.revision': '06a7406709d6a858039333a8988047296ef3aa4a',
      'org.opencontainers.image.version': 'v4.3.3',
    },
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
        source: '/repo/lab/h041/entrypoint.sh',
        destination: '/h041-entrypoint.sh',
        rw: false,
        propagation: 'rprivate',
      },
      {
        type: 'bind',
        source: '/repo/lab/h041/container-observer.mjs',
        destination: '/h041-container-observer.mjs',
        rw: false,
        propagation: 'rprivate',
      },
      {
        type: 'bind',
        source: '/repo/lab/h042/signal-helper.mjs',
        destination: '/h042-signal-helper.mjs',
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
      {
        type: 'bind',
        source: '/repo/lab/h041/entrypoint.sh',
        target: '/h041-entrypoint.sh',
        readOnly: true,
        bindOptions: null,
      },
      {
        type: 'bind',
        source: '/repo/lab/h041/container-observer.mjs',
        target: '/h041-container-observer.mjs',
        readOnly: true,
        bindOptions: null,
      },
      {
        type: 'bind',
        source: '/repo/lab/h042/signal-helper.mjs',
        target: '/h042-signal-helper.mjs',
        readOnly: true,
        bindOptions: null,
      },
    ],
  };
}

function observer(state, workers) {
  const stats = state === 'present' ? RETURNED_STAT : null;
  const dynamic = pathReceipt('/host-dev/hidraw0', state, stats);
  const compat = pathReceipt('/dev/hidraw0', state, stats);
  return {
    schemaVersion: 'overlaykit-h041-container-observation/v1',
    capturedAt: '2026-07-26T01:02:31.000Z',
    monotonicNs: '6100',
    metadataOnly: true,
    paths: {
      dynamic: {
        path: '/host-dev/hidraw0',
        lstat: structuredClone(dynamic),
        stat: structuredClone(dynamic),
      },
      compat: {
        path: '/dev/hidraw0',
        lstat: structuredClone(compat),
        stat: structuredClone(compat),
        linkTarget: '/host-dev/hidraw0',
      },
    },
    target: { major: 241, minor: 0 },
    pid1: pid1(),
    processes: [
      pid1(),
      ...workers.map(({ fileDescriptors: _fileDescriptors, ...process_ }) =>
        structuredClone(process_)
      ),
    ],
    surfaceWorkers: structuredClone(workers),
  };
}

function runtime(phase, state, workers, markerReceipt) {
  return {
    capturedAt: '2026-07-26T01:02:31.000Z',
    monotonicNs: '6100',
    phase,
    container: container(),
    lifecycle: lifecycle(),
    observer: observer(state, workers),
    markers: structuredClone(markerReceipt),
  };
}

function humanWindow(stage, opened, closed) {
  return {
    stage,
    challenge: 'abcdef012345',
    timeoutSeconds: 120,
    instruction: `${stage} the exact Stream Deck`,
    openedAt: '2026-07-26T01:00:00.000Z',
    openedMonotonicNs: opened,
    closedAt: '2026-07-26T01:01:00.000Z',
    closedMonotonicNs: closed,
  };
}

function preSignalWindow(started, completed, deadlineExpired) {
  return {
    startedAt: '2026-07-26T01:02:00.000Z',
    startedMonotonicNs: started,
    completedAt: '2026-07-26T01:02:30.100Z',
    completedMonotonicNs: completed,
    timeoutSeconds: 30,
    deadlineExpired,
    boundaryNegative: true,
  };
}

function postSignalWindow(started, completed, deadlineExpired, supportObserved) {
  return {
    startedAt: '2026-07-26T01:02:30.202Z',
    startedMonotonicNs: started,
    completedAt: '2026-07-26T01:02:31.000Z',
    completedMonotonicNs: completed,
    timeoutSeconds: 30,
    deadlineExpired,
    supportObserved,
  };
}

function signalReceipt(oldWorker) {
  const observed = {
    ...structuredClone(oldWorker),
    targetHidrawDescriptors: [],
    revalidation: {
      initial: {
        pid: oldWorker.pid,
        startTicks: oldWorker.startTicks,
        ppid: oldWorker.ppid,
        parentStartTicks: oldWorker.parentStartTicks,
      },
      final: {
        pid: oldWorker.pid,
        startTicks: oldWorker.startTicks,
        ppid: oldWorker.ppid,
        parentStartTicks: oldWorker.parentStartTicks,
      },
    },
  };
  return {
    schemaVersion: 'overlaykit-h042-signal-receipt/v1',
    signal: 'SIGTERM',
    processKillCallCount: 1,
    startedAt: '2026-07-26T01:02:30.200Z',
    startedMonotonicNs: '6100',
    receivedAt: '2026-07-26T01:02:30.201Z',
    receivedMonotonicNs: '6200',
    expected: structuredClone(oldWorker),
    observed,
  };
}

function signalWindow(oldWorker) {
  return {
    command: ['/app/node-runtimes/main/bin/node', '/h042-signal-helper.mjs'],
    user: '1000:1000',
    target: structuredClone(oldWorker),
    startedAt: '2026-07-26T01:02:30.200Z',
    startedMonotonicNs: '6100',
    receivedAt: '2026-07-26T01:02:30.201Z',
    receivedMonotonicNs: '6200',
    exitCode: 0,
    receipt: signalReceipt(oldWorker),
  };
}

function auditEntries() {
  const entries = [
    ['docker-run', 'setup'],
    ['physical-disconnect-window', 'disconnect'],
    ['physical-reconnect-window', 'reconnect'],
    ['docker-exec-signal', 'signal'],
    ['docker-events-experiment', 'classification'],
    ['experiment-classified', 'classification'],
    ['docker-stop', 'cleanup'],
    ['docker-ps-cleanup', 'cleanup'],
    ['docker-events-cleanup', 'cleanup'],
  ].map(([kind, phase], index) => ({
    at: `2026-07-26T01:0${index}:00.000Z`,
    monotonicNs: String(index + 1),
    kind,
    phase,
  }));
  Object.assign(entries[0], {
    target: 'h042-companion-123456abcdef',
    imageReference:
      'ghcr.io/bitfocus/companion/companion:v4.3.3@sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e',
    arguments: ['run', '--rm', '--name', 'h042-companion-123456abcdef'],
    runnerDeviceIo: false,
  });
  Object.assign(entries[1], {
    challenge: '123456abcdef',
    expectedActor: 'human-principal',
  });
  Object.assign(entries[2], {
    challenge: 'abcdef123456',
    expectedActor: 'human-principal',
  });
  Object.assign(entries[3], {
    target: 'h042-companion-123456abcdef',
    user: '1000:1000',
    signal: 'SIGTERM',
    processTarget: workerIdentity(),
    command: ['/app/node-runtimes/main/bin/node', '/h042-signal-helper.mjs'],
    exitCode: 0,
    receiptSha256: SHA256,
  });
  Object.assign(entries[4], {
    target: CONTAINER_ID,
    since: '2026-07-26T01:00:00.000Z',
    until: '2026-07-26T01:02:50.000Z',
  });
  Object.assign(entries[5], {
    experimentBoundaryAt: '2026-07-26T01:02:50.000Z',
    outcome: 'supported',
    stage: 'surface-worker-reacquisition',
  });
  Object.assign(entries[6], {
    target: 'h042-companion-123456abcdef',
    timeoutSeconds: 5,
  });
  entries[7].target = 'h042-companion-123456abcdef';
  Object.assign(entries[8], {
    target: CONTAINER_ID,
    since: '2026-07-26T01:02:50.000Z',
    until: '2026-07-26T01:03:50.000Z',
  });
  return entries;
}

function dockerEventsAnalysis() {
  return {
    passed: true,
    experimentStartedAt: '2026-07-26T01:00:00.000Z',
    experimentBoundaryAt: '2026-07-26T01:02:50.000Z',
    execId: 'c'.repeat(64),
    helperCreateCount: 1,
    helperStartCount: 1,
    helperDieZeroCount: 1,
    ordered: true,
    forbiddenActions: [],
    containerStartExact: true,
    healthStatusEvents: [],
    unexpectedActions: [],
    execCreateCount: 9,
    observerExecCount: 8,
    healthcheck: {
      command: 'sh -c curl -fSsq http://localhost:${COMPANION_ADMIN_PORT:-8000}/',
      createCount: 0,
      tripletCount: 0,
      execIds: [],
      complete: true,
    },
    unknownExecEvents: [],
    incompleteExecIds: [],
    unscopedEvents: [],
    timestampsWithinWindow: true,
    execBoundaryExact: true,
  };
}

function cleanupEventsAnalysis() {
  const healthcheck = {
    command: 'sh -c curl -fSsq http://localhost:${COMPANION_ADMIN_PORT:-8000}/',
    createCount: 0,
    tripletCount: 0,
    execIds: [],
    complete: true,
  };
  return {
    passed: true,
    experimentBoundaryAt: '2026-07-26T01:02:50.000Z',
    classifiedAt: '2026-07-26T01:03:00.000Z',
    eventsUntilAt: '2026-07-26T01:03:50.000Z',
    eventCount: 5,
    timestampsValid: true,
    unscopedEvents: [],
    gap: {
      eventCount: 0,
      healthcheck: structuredClone(healthcheck),
      healthStatusEvents: [],
      unknownExecEvents: [],
      incompleteExecIds: [],
      unknownActions: [],
      boundaryExact: true,
    },
    cleanup: {
      eventCount: 5,
      stopCount: 1,
      dieCount: 1,
      destroyCount: 1,
      killCount: 2,
      kill15Count: 1,
      kill9Count: 1,
      dieExitCode: '137',
      healthcheck: structuredClone(healthcheck),
      healthStatusEvents: [],
      unknownExecEvents: [],
      incompleteExecIds: [],
      unknownActions: [],
      lifecycleOrdered: true,
      boundaryExact: true,
    },
  };
}

function sourceHashes() {
  return Object.fromEntries(H042_REQUIRED_SOURCES.map((source) => [source, SHA256]));
}

function predecessor(hypothesis) {
  const receiptKey = hypothesis === 'h037' ? 'validationReceipt' : 'verificationReceipt';
  const receiptName =
    hypothesis === 'h037' ? 'h037-validation.json' : `${hypothesis}-verification.json`;
  const result = {
    path: `artifacts/${hypothesis}/run.json`,
    fileSha256: SHA256,
    evidenceSha256: SHA256,
    [receiptKey]: {
      path: receiptName,
      sha256: SHA256,
    },
  };
  if (hypothesis === 'h041') {
    result.reverificationReceipt = {
      path: 'h041-reverification.json',
      sha256: SHA256,
    };
  }
  return result;
}

function supportedPredicates() {
  return {
    complete: true,
    permissionBoundaryExact: true,
    hostEpochChanged: true,
    dynamicViewTracksHost: true,
    baselineAcquired: true,
    preSignalWindowComplete: true,
    preSignalNegative: true,
    signalTargetUnique: true,
    signalTargetRevalidated: true,
    exactlyOneSigterm: true,
    signalSucceeded: true,
    invocationAuditExact: true,
    topLevelLifecycleUnchanged: true,
    oldWorkerExited: true,
    replacementWorkerUnique: true,
    singleReplacementGeneration: true,
    replacementWorkerChanged: true,
    postSignalObservationComplete: true,
    postSignalDescriptorObserved: true,
    postSignalOpeningObserved: true,
    postSignalReadyObserved: true,
    postSignalMarkersOrdered: true,
    postSignalWithinDeadline: true,
    deadlineBoundaryConsistent: true,
    latePositiveObserved: false,
  };
}

function supportedRun() {
  const oldIdentity = workerIdentity();
  const oldWorker = worker({ descriptors: [] });
  const replacementWorker = worker({
    pid: 160,
    startTicks: 2275000,
    descriptors: [descriptor()],
  });
  const initialWorker = worker({ descriptors: [descriptor(INITIAL_STAT)] });
  return {
    schemaVersion: 'overlaykit-h042-surface-worker-recycle-run/v1',
    hypothesis: 'H-042',
    runId: 'h042-2026-07-26T01-00-00-000Z-1234abcd',
    startedAt: '2026-07-26T01:00:00.000Z',
    completedAt: '2026-07-26T01:04:00.000Z',
    outcome: {
      status: 'supported',
      stage: 'surface-worker-reacquisition',
      reason: 'one exact worker replacement reacquired the current device',
    },
    collector: {
      node: 'v22.20.0',
      repository: 'https://github.com/OverlayKit/companion-module-overlaykit-server.git',
      commit: 'd'.repeat(40),
      requiredSources: [...H042_REQUIRED_SOURCES],
      sourceSha256: sourceHashes(),
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
      h037: predecessor('h037'),
      h039: predecessor('h039'),
      h040: predecessor('h040'),
      h041: predecessor('h041'),
    },
    host: {
      observedAt: '2026-07-26T01:00:00.000Z',
      osId: 'fedora',
      osVersion: '43',
      kernel: '7.1.4-104.fc43.x86_64',
      architecture: 'x64',
      machine: 'x86_64',
      principal: {
        user: 'rod',
        uid: 1000,
        primaryGroup: 'rod',
        gid: 1000,
        groups: [
          { gid: 1000, name: 'rod' },
          { gid: 1002, name: 'plugdev' },
        ],
      },
      graphicalSession: {
        Id: '2',
        Name: 'rod',
        Seat: 'seat0',
        TTY: 'tty2',
        Active: 'yes',
        State: 'active',
        Class: 'user',
        Remote: 'no',
        Type: 'wayland',
      },
      docker: {
        version: {
          Client: { Version: '29.0.0' },
          Server: { Version: '29.0.0' },
        },
        info: {
          ServerVersion: '29.0.0',
        },
      },
    },
    device: {
      vendorId: '0fd9',
      productId: '0080',
      model: 'Elgato Stream Deck MK.2',
      serial: 'A00SA5492OQMLF',
      initialPath: '/dev/hidraw0',
      returnedPath: '/dev/hidraw0',
      initialRdevHex: 'f1:0',
      returnedRdevHex: 'f1:0',
      transition: 'same-path-same-rdev',
      initialInventory: [inventory(INITIAL_STAT, '14')],
      returnedInventory: [inventory(RETURNED_STAT, '15')],
    },
    companion: {
      name: 'h042-companion-123456abcdef',
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
      preSignalLifecycle: lifecycle(),
      postSignalLifecycle: lifecycle(),
      workerLifecycle: {
        initial: [structuredClone(initialWorker)],
        absent: [structuredClone(oldWorker)],
        preSignal: [structuredClone(oldWorker)],
        postSignal: [structuredClone(replacementWorker)],
      },
    },
    windows: {
      disconnect: humanWindow('disconnect', '1100', '2000'),
      reconnect: humanWindow('reconnect', '2100', '3000'),
      preSignal: preSignalWindow('3000', '6100', true),
      signal: signalWindow(oldIdentity),
      postSignal: postSignalWindow('6300', '6400', false, true),
    },
    observations: {
      preflight: {
        host: hostSnapshot('present'),
      },
      initial: {
        host: hostSnapshot('present'),
        runtime: runtime('baseline-poll', 'present', [initialWorker], INITIAL_MARKERS),
      },
      absent: {
        host: hostSnapshot('absent'),
        runtime: runtime('absent-poll', 'absent', [oldWorker], INITIAL_MARKERS),
      },
      returned: {
        host: hostSnapshot('present', { returned: true }),
        runtime: runtime('pre-signal-poll', 'present', [oldWorker], INITIAL_MARKERS),
      },
      preSignal: {
        host: hostSnapshot('present', { returned: true }),
        runtime: runtime('signal-target-revalidate', 'present', [oldWorker], INITIAL_MARKERS),
        markers: {
          baseline: structuredClone(INITIAL_MARKERS),
          final: structuredClone(INITIAL_MARKERS),
        },
        control: {
          descriptorObserved: false,
          openingObserved: false,
          readyObserved: false,
          boundaryNegative: true,
        },
      },
      postSignal: {
        runtime: runtime('post-signal-poll', 'present', [replacementWorker], FINAL_MARKERS),
        markerDelta: {
          prefixValid: true,
          openingObserved: true,
          readyObserved: true,
          ordered: true,
          allAfterSignal: true,
          lines: FINAL_MARKERS.relevantLines.slice(2),
        },
        replacement: {
          oldWorkerExited: true,
          replacementWorkerUnique: true,
          singleReplacementGeneration: true,
          replacementWorkerChanged: true,
          replacement: structuredClone(replacementWorker),
        },
        descriptorObserved: true,
        latePositiveObserved: false,
        dockerEvents: dockerEventsAnalysis(),
      },
      artifacts: {
        hostPoll: { path: 'host-poll.jsonl', sha256: SHA256 },
        runtimePoll: { path: 'runtime-poll.jsonl', sha256: SHA256 },
        initialLogs: { path: 'logs-initial.txt', sha256: SHA256 },
        absentLogs: { path: 'logs-absent.txt', sha256: SHA256 },
        preSignalLogs: { path: 'logs-pre-signal.txt', sha256: SHA256 },
        finalLogs: { path: 'logs-final.txt', sha256: SHA256 },
        signalReceipt: { path: 'signal-receipt.json', sha256: SHA256 },
        experimentEvents: { path: 'docker-events-experiment.jsonl', sha256: SHA256 },
        cleanupEvents: { path: 'docker-events-cleanup.jsonl', sha256: SHA256 },
      },
    },
    predicates: supportedPredicates(),
    invocationAudit: {
      mode: 'metadata-observation-plus-one-source-bound-surface-sigterm',
      entries: auditEntries(),
      forbidden: [],
      signalCount: 1,
      signalExact: true,
      exactCardinality: true,
      strictChronology: true,
      causalOrder: true,
      cleanupAfterClassification: true,
      runnerDeviceOpenCount: 0,
      runnerDeviceReadCount: 0,
      runnerDeviceWriteCount: 0,
      virtualInvocationCount: 0,
      forbiddenLifecycleCount: 0,
      passed: true,
    },
    claimBoundary: structuredClone(H042_CLAIM_BOUNDARY),
    cleanup: {
      startedAt: '2026-07-26T01:03:30.000Z',
      completedAt: '2026-07-26T01:04:00.000Z',
      experimentBoundaryAt: '2026-07-26T01:02:50.000Z',
      classificationCompletedAt: '2026-07-26T01:03:00.000Z',
      eventsUntilAt: '2026-07-26T01:03:50.000Z',
      containerId: CONTAINER_ID,
      containerRemoved: true,
      dockerEventsAnalysis: cleanupEventsAnalysis(),
      returnedNodeAccess: {
        reference: {
          devicePath: '/dev/hidraw0',
          stat: structuredClone(RETURNED_STAT),
        },
        observed: {
          devicePath: '/dev/hidraw0',
          stat: structuredClone(RETURNED_STAT),
        },
        exact: true,
      },
      host: hostSnapshot('present', { returned: true }),
      owners: [
        {
          devicePath: '/dev/hidraw0',
          owner: {
            applicable: true,
            observed: true,
            usageError: false,
            pids: [],
            exitCode: 1,
            errorCode: null,
            stdout: '',
            stderr: '',
            processes: [],
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

function makeNegativePostSignal(run) {
  run.windows.postSignal.deadlineExpired = true;
  run.windows.postSignal.supportObserved = false;
  run.predicates.postSignalDescriptorObserved = false;
  run.predicates.postSignalOpeningObserved = false;
  run.predicates.postSignalReadyObserved = false;
  run.predicates.postSignalMarkersOrdered = false;
  run.predicates.postSignalWithinDeadline = false;
  run.observations.postSignal.descriptorObserved = false;
  run.observations.postSignal.runtime.markers = structuredClone(INITIAL_MARKERS);
  run.observations.postSignal.markerDelta = {
    prefixValid: true,
    openingObserved: false,
    readyObserved: false,
    ordered: false,
    allAfterSignal: false,
    lines: [],
  };
}

function makePositiveMarkersWithoutReacquisition(run) {
  run.predicates.postSignalOpeningObserved = true;
  run.predicates.postSignalReadyObserved = true;
  run.predicates.postSignalMarkersOrdered = true;
  run.observations.postSignal.runtime.markers = structuredClone(FINAL_MARKERS);
  run.observations.postSignal.markerDelta = {
    prefixValid: true,
    openingObserved: true,
    readyObserved: true,
    ordered: true,
    allAfterSignal: true,
    lines: FINAL_MARKERS.relevantLines.slice(2),
  };
}

function refutedRun(stage) {
  const run = supportedRun();
  run.outcome = {
    status: 'refuted',
    stage,
    reason: `complete negative ${stage} observation`,
  };
  makeNegativePostSignal(run);
  if (stage === 'worker-termination') {
    run.predicates.oldWorkerExited = false;
    run.predicates.replacementWorkerUnique = false;
    run.predicates.replacementWorkerChanged = false;
    run.observations.postSignal.replacement = {
      oldWorkerExited: false,
      replacementWorkerUnique: false,
      singleReplacementGeneration: true,
      replacementWorkerChanged: false,
      replacement: null,
    };
    run.companion.workerLifecycle.postSignal = [
      worker({ pid: 73, startTicks: 2274363, descriptors: [] }),
    ];
    run.observations.postSignal.runtime = runtime(
      'post-signal-poll',
      'present',
      run.companion.workerLifecycle.postSignal,
      INITIAL_MARKERS
    );
  } else if (stage === 'worker-respawn') {
    run.predicates.replacementWorkerUnique = false;
    run.predicates.replacementWorkerChanged = false;
    run.observations.postSignal.replacement = {
      oldWorkerExited: true,
      replacementWorkerUnique: false,
      singleReplacementGeneration: true,
      replacementWorkerChanged: false,
      replacement: null,
    };
    run.companion.workerLifecycle.postSignal = [];
    run.observations.postSignal.runtime = runtime(
      'post-signal-poll',
      'present',
      [],
      INITIAL_MARKERS
    );
  } else {
    const replacement = worker({ pid: 160, startTicks: 2275000, descriptors: [] });
    run.companion.workerLifecycle.postSignal = [replacement];
    run.observations.postSignal.runtime = runtime(
      'post-signal-poll',
      'present',
      [replacement],
      INITIAL_MARKERS
    );
  }
  return run;
}

const schema = JSON.parse(
  await readFile(
    new URL('./schemas/surface-worker-recycle-run.schema.json', import.meta.url),
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

test('H-042 schema accepts the complete supported runner envelope', () => {
  assertAccepted(supportedRun(), 'supported H-042 fixture was rejected');
});

test('H-042 schema admits the full producer domain for human transition windows', () => {
  const minimum = supportedRun();
  minimum.windows.disconnect.timeoutSeconds = 20;
  minimum.windows.reconnect.timeoutSeconds = 20;
  assertAccepted(minimum, 'minimum producer transition timeout was rejected');

  const maximum = supportedRun();
  maximum.windows.disconnect.timeoutSeconds = 300;
  maximum.windows.reconnect.timeoutSeconds = 300;
  assertAccepted(maximum, 'maximum producer transition timeout was rejected');

  const belowMinimum = supportedRun();
  belowMinimum.windows.disconnect.timeoutSeconds = 19;
  assertRejected(belowMinimum, 'transition timeout below the producer domain was accepted');

  const aboveMaximum = supportedRun();
  aboveMaximum.windows.reconnect.timeoutSeconds = 301;
  assertRejected(aboveMaximum, 'transition timeout above the producer domain was accepted');
});

test('H-042 schema models early refutations before the final reacquisition matrix', () => {
  for (const stage of ['worker-termination', 'worker-respawn', 'surface-worker-reacquisition']) {
    assertAccepted(refutedRun(stage), `${stage} refutation was rejected`);
  }

  for (const stage of ['worker-termination', 'worker-respawn']) {
    const earlyRefutation = refutedRun(stage);
    makePositiveMarkersWithoutReacquisition(earlyRefutation);
    assertAccepted(
      earlyRefutation,
      `${stage} refutation was rejected after bounded positive marker evidence`
    );
  }

  const incomplete = refutedRun('surface-worker-reacquisition');
  incomplete.windows.postSignal.deadlineExpired = false;
  assertRejected(incomplete, 'refutation was accepted before its deadline boundary');

  const transientDescriptor = refutedRun('worker-respawn');
  transientDescriptor.observations.postSignal.descriptorObserved = true;
  transientDescriptor.predicates.postSignalDescriptorObserved = true;
  assertAccepted(
    transientDescriptor,
    'worker-respawn refutation rejected a descriptor owned by a transient replacement'
  );

  const impossibleTerminationDescriptor = refutedRun('worker-termination');
  impossibleTerminationDescriptor.observations.postSignal.descriptorObserved = true;
  impossibleTerminationDescriptor.predicates.postSignalDescriptorObserved = true;
  assertRejected(
    impossibleTerminationDescriptor,
    'worker-termination refutation accepted a descriptor without any replacement'
  );

  const mixedReacquisition = refutedRun('surface-worker-reacquisition');
  makePositiveMarkersWithoutReacquisition(mixedReacquisition);
  mixedReacquisition.observations.postSignal.descriptorObserved = true;
  mixedReacquisition.predicates.postSignalDescriptorObserved = true;
  assertRejected(
    mixedReacquisition,
    'surface-worker-reacquisition refutation was accepted with mixed positive evidence'
  );
});

test('mixed, late, and multi-generation evidence cannot be represented as support or refutation', () => {
  const mixed = supportedRun();
  mixed.outcome = {
    status: 'inconclusive',
    stage: 'mixed-reacquisition',
    reason: 'descriptor appeared without a complete marker pair',
  };
  mixed.predicates.postSignalOpeningObserved = false;
  mixed.predicates.postSignalReadyObserved = false;
  mixed.predicates.postSignalMarkersOrdered = false;
  mixed.observations.postSignal.markerDelta.openingObserved = false;
  mixed.observations.postSignal.markerDelta.readyObserved = false;
  mixed.observations.postSignal.markerDelta.ordered = false;
  assertAccepted(mixed, 'mixed evidence was not admitted as inconclusive');
  mixed.outcome.status = 'supported';
  mixed.outcome.stage = 'surface-worker-reacquisition';
  assertRejected(mixed, 'mixed evidence was accepted as support');

  const late = supportedRun();
  late.outcome = {
    status: 'inconclusive',
    stage: 'deadline-boundary',
    reason: 'the first positive observation crossed the deadline',
  };
  late.predicates.postSignalWithinDeadline = false;
  late.predicates.deadlineBoundaryConsistent = false;
  late.predicates.latePositiveObserved = true;
  late.windows.postSignal.deadlineExpired = true;
  assertAccepted(late, 'late evidence was not admitted as inconclusive');
  late.outcome.status = 'refuted';
  late.outcome.stage = 'surface-worker-reacquisition';
  assertRejected(late, 'late positive evidence was accepted as refutation');

  const multi = supportedRun();
  const second = workerIdentity(161, 2275100);
  multi.outcome = {
    status: 'inconclusive',
    stage: 'worker-replacement',
    reason: 'more than one replacement generation was observed',
  };
  multi.predicates.replacementWorkerUnique = false;
  multi.predicates.singleReplacementGeneration = false;
  multi.predicates.replacementWorkerChanged = false;
  multi.observations.postSignal.replacement = {
    oldWorkerExited: true,
    replacementWorkerUnique: false,
    singleReplacementGeneration: false,
    replacementWorkerChanged: false,
    replacement: null,
  };
  multi.companion.workerLifecycle.postSignal.push(
    worker({ pid: 161, startTicks: 2275100, descriptors: [] })
  );
  assertAccepted(multi, 'multi-generation evidence was not admitted as inconclusive');
  multi.outcome.status = 'supported';
  multi.outcome.stage = 'surface-worker-reacquisition';
  assertRejected(multi, 'multiple replacement generations were accepted as support');
});

test('pre-signal automatic recovery and lifecycle drift fail closed as inconclusive', () => {
  const automatic = supportedRun();
  automatic.outcome = {
    status: 'inconclusive',
    stage: 'precondition',
    reason: 'automatic recovery occurred before the intervention',
  };
  automatic.predicates.preSignalNegative = false;
  automatic.observations.preSignal.control.descriptorObserved = true;
  automatic.observations.preSignal.control.openingObserved = true;
  automatic.observations.preSignal.control.readyObserved = true;
  automatic.observations.preSignal.control.boundaryNegative = false;
  automatic.windows.preSignal.boundaryNegative = false;
  assertAccepted(automatic, 'pre-signal confound was not admitted as inconclusive');
  automatic.outcome.status = 'supported';
  automatic.outcome.stage = 'surface-worker-reacquisition';
  assertRejected(automatic, 'pre-signal automatic recovery was accepted as support');

  const drift = supportedRun();
  drift.outcome = {
    status: 'inconclusive',
    stage: 'worker-replacement',
    reason: 'PID 1 or container lifecycle drifted',
  };
  drift.predicates.topLevelLifecycleUnchanged = false;
  drift.companion.postSignalLifecycle.pid1StartTicks += 1;
  drift.observations.postSignal.runtime.lifecycle.pid1StartTicks += 1;
  assertAccepted(drift, 'lifecycle drift was not admitted as inconclusive');
  drift.outcome.status = 'supported';
  drift.outcome.stage = 'surface-worker-reacquisition';
  assertRejected(drift, 'lifecycle drift was accepted as support');
});

test('source, signal, artifact, chronology, overclaim, and cleanup boundaries reject weakened evidence', () => {
  const unstable = supportedRun();
  unstable.collector.sourceStable = false;
  assertRejected(unstable, 'source instability was accepted');

  const incompleteClosure = supportedRun();
  incompleteClosure.collector.requiredSources.shift();
  delete incompleteClosure.collector.sourceSha256['.overlaykit/governance/changes/CHG-0012.json'];
  assertRejected(incompleteClosure, 'an incomplete source closure was accepted');

  const duplicateSignal = supportedRun();
  duplicateSignal.invocationAudit.signalCount = 2;
  assertRejected(duplicateSignal, 'duplicate signal invocations were accepted');

  const badArtifact = supportedRun();
  badArtifact.observations.artifacts.experimentEvents.sha256 = 'not-a-hash';
  assertRejected(badArtifact, 'an unbound Docker event artifact was accepted');

  const unknownExec = supportedRun();
  unknownExec.observations.postSignal.dockerEvents.unknownExecEvents.push({
    type: 'container',
    action: 'exec_create: unexpected command',
    status: null,
    id: CONTAINER_ID,
    time: 1785020102,
    timeNano: '1785020102000000000',
    attributes: { execID: 'e'.repeat(64) },
  });
  assertRejected(unknownExec, 'an unexpected Docker exec was accepted as conclusive');

  const incompleteHealthcheck = supportedRun();
  incompleteHealthcheck.observations.postSignal.dockerEvents.healthcheck.complete = false;
  incompleteHealthcheck.observations.postSignal.dockerEvents.incompleteExecIds.push('f'.repeat(64));
  assertRejected(
    incompleteHealthcheck,
    'an incomplete healthcheck exec triplet was accepted as conclusive'
  );

  const reordered = supportedRun();
  delete reordered.windows.signal.receivedMonotonicNs;
  assertRejected(reordered, 'an incomplete causal signal chronology was accepted');

  const overclaim = supportedRun();
  overclaim.claimBoundary.proves.push('production recovery is approved');
  assertRejected(overclaim, 'an expanded production claim was accepted');

  const ambiguousCleanupEvents = supportedRun();
  ambiguousCleanupEvents.cleanup.dockerEventsAnalysis.cleanup.kill9Count = 0;
  assertRejected(
    ambiguousCleanupEvents,
    'an incomplete cleanup lifecycle event envelope was accepted'
  );

  const failedCleanup = supportedRun();
  failedCleanup.cleanup.successful = false;
  failedCleanup.cleanup.containerRemoved = false;
  failedCleanup.cleanup.error = 'container remained';
  assertRejected(failedCleanup, 'cleanup failure was accepted as canonical evidence');
});
