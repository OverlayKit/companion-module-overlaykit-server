import assert from 'node:assert/strict';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { recomputePredicates, verifyChronology, verifyLifecycleBindings } from './verify.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const SERIAL = 'A00SA5492OQMLF';
const CONTAINER_ID = 'c'.repeat(64);
const IMAGE_ID = 'sha256:e7d24e3b0e32b0edb799f262493536cb1a47d307af4e6527551427e09266bf10';
const OFFICIAL_IMAGE =
  'ghcr.io/bitfocus/companion/companion:v4.3.3@sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e';
const INITIAL_STAT = Object.freeze({
  stDev: '7',
  inode: '1402',
  ctimeNs: '1785017681209719431',
  mode: '0660',
  uid: 0,
  gid: 1002,
  rdev: '61696',
  major: 241,
  minor: 0,
  rdevHex: 'f1:0',
  isCharacterDevice: true,
});
const RETURNED_STAT = Object.freeze({
  ...INITIAL_STAT,
  inode: '1417',
  ctimeNs: '1785020103123456789',
});
const PREDICATE_KEYS = [
  'complete',
  'interventionFree',
  'permissionBoundaryExact',
  'hostEpochChanged',
  'dynamicViewTracksHost',
  'topLevelLifecycleUnchanged',
  'baselineAcquired',
  'descriptorAbsent',
  'postReturnDescriptorObserved',
  'postReturnLogMarkersObserved',
  'deadlineBoundaryConsistent',
];

function chronologyFixture() {
  const sameWallClockMillisecond = '2026-07-25T23:00:00.000Z';
  return {
    startedAt: sameWallClockMillisecond,
    windows: {
      disconnect: {
        openedAt: sameWallClockMillisecond,
        openedMonotonicNs: '200',
        closedAt: sameWallClockMillisecond,
        closedMonotonicNs: '500',
      },
      reconnect: {
        openedAt: sameWallClockMillisecond,
        openedMonotonicNs: '600',
        closedAt: sameWallClockMillisecond,
        closedMonotonicNs: '800',
      },
      reacquisition: {
        startedAt: sameWallClockMillisecond,
        startedMonotonicNs: '700',
        completedAt: sameWallClockMillisecond,
        completedMonotonicNs: '1000',
        timeoutSeconds: 30,
      },
    },
    observations: {
      preflight: {
        host: {
          capturedAt: sameWallClockMillisecond,
          monotonicNs: '50',
        },
      },
      initial: {
        runtime: {
          capturedAt: sameWallClockMillisecond,
          monotonicNs: '100',
        },
        host: {
          capturedAt: sameWallClockMillisecond,
          monotonicNs: '150',
        },
      },
      absent: {
        host: {
          capturedAt: sameWallClockMillisecond,
          monotonicNs: '300',
        },
        runtime: {
          capturedAt: sameWallClockMillisecond,
          monotonicNs: '400',
        },
      },
      returned: {
        host: {
          capturedAt: sameWallClockMillisecond,
          monotonicNs: '700',
        },
        runtime: {
          capturedAt: sameWallClockMillisecond,
          monotonicNs: '900',
        },
      },
    },
  };
}

function value(path, stat) {
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
    imageId: IMAGE_ID,
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

function containerReceipt() {
  return {
    containerId: CONTAINER_ID,
    imageId: IMAGE_ID,
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
      },
      {
        type: 'bind',
        source: path.join(LAB_DIRECTORY, 'entrypoint.sh'),
        destination: '/h041-entrypoint.sh',
        rw: false,
      },
      {
        type: 'bind',
        source: path.join(LAB_DIRECTORY, 'container-observer.mjs'),
        destination: '/h041-container-observer.mjs',
        rw: false,
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
        source: path.join(LAB_DIRECTORY, 'entrypoint.sh'),
        target: '/h041-entrypoint.sh',
        readOnly: true,
        bindOptions: null,
      },
      {
        type: 'bind',
        source: path.join(LAB_DIRECTORY, 'container-observer.mjs'),
        target: '/h041-container-observer.mjs',
        readOnly: true,
        bindOptions: null,
      },
    ],
  };
}

function descriptor(stat) {
  return {
    descriptor: '20',
    target: '/dev/hidraw0',
    stat: { ...stat },
  };
}

function runtime({ phase, monotonicNs, stat, present, opening, ready }) {
  const fileDescriptors = present ? [descriptor(stat)] : [];
  return {
    phase,
    monotonicNs,
    lifecycle: lifecycle(),
    container: containerReceipt(),
    observer: {
      pid1: {
        uid: 1000,
        gid: 1000,
        groups: [1000, 1002],
      },
      paths: {
        dynamic: {
          stat: present ? value('/host-dev/hidraw0', stat) : missing('/host-dev/hidraw0'),
        },
        compat: {
          linkTarget: '/host-dev/hidraw0',
          lstat: value('/dev/hidraw0', {
            ...INITIAL_STAT,
            isCharacterDevice: false,
            isSymbolicLink: true,
          }),
          stat: present ? value('/dev/hidraw0', stat) : missing('/dev/hidraw0'),
        },
      },
      surfaceWorkers: [{ fileDescriptors }],
    },
    markers: {
      opening,
      ready,
    },
  };
}

function hostNode({ returned = false } = {}) {
  const stat = returned ? RETURNED_STAT : INITIAL_STAT;
  return {
    devicePath: '/dev/hidraw0',
    hidDevicePath: `/sys/devices/pci0000:00/usb1/1-2/0003:0FD9:0080.${returned ? '0012' : '0011'}`,
    usbAncestor: {
      serial: SERIAL,
      deviceNumber: returned ? '14' : '13',
    },
    stat: { ...stat },
  };
}

function hostSnapshot({ returned = false } = {}) {
  const node = hostNode({ returned });
  const deviceNumber = returned ? '14' : '13';
  return {
    monotonicNs: returned ? '4000' : '1000',
    state: 'present',
    expectedSerial: SERIAL,
    scope: {
      bootId: '30b83905-13f4-439a-9c1e-5c8424023fd7',
      mountNamespace: 'mnt:[4026531832]',
    },
    errors: [],
    usb: [
      {
        serialMatches: true,
        serial: SERIAL,
        deviceNumber,
      },
    ],
    hidraw: [
      {
        ...node,
        serialMatches: true,
        hid: { unique: SERIAL },
      },
    ],
  };
}

function inventoryEntry({ returned = false } = {}) {
  const stat = returned ? RETURNED_STAT : INITIAL_STAT;
  return {
    name: 'hidraw0',
    classPath: '/sys/class/hidraw/hidraw0',
    devicePath: '/dev/hidraw0',
    hidDevicePath: `/sys/devices/pci0000:00/usb1/1-2/0003:0FD9:0080.${returned ? '0012' : '0011'}`,
    hid: {
      vendorId: '0fd9',
      productId: '0080',
      unique: SERIAL,
    },
    classDevice: { major: 241, minor: 0 },
    usbAncestor: {
      vendorId: '0fd9',
      productId: '0080',
      serial: SERIAL,
      deviceNumber: returned ? '14' : '13',
    },
    stat: {
      before: { kind: 'value', value: { ...stat } },
      after: { kind: 'value', value: { ...stat } },
      stable: true,
      value: { ...stat },
      matchesClass: true,
    },
    errors: [],
  };
}

function invocationAudit(run) {
  const entries = [
    {
      kind: 'docker-run',
      monotonicNs: '10',
      target: run.companion.name,
      imageReference: OFFICIAL_IMAGE,
      dynamicSource: '/dev',
      dynamicDestination: '/host-dev',
      dynamicReadOnly: true,
      bindRecursive: false,
      cgroupRule: run.companion.deviceCgroupRule,
      staticDevices: [],
      runnerDeviceIo: false,
      companionTargetIoExpected: true,
      configBaseDirectory: '/companion',
      ephemeralConfig: true,
      labLabel: 'dev.overlaykit.hypothesis=H-041',
    },
    {
      kind: 'physical-disconnect-window',
      monotonicNs: '20',
      challenge: run.windows.disconnect.challenge,
    },
    {
      kind: 'physical-reconnect-window',
      monotonicNs: '30',
      challenge: run.windows.reconnect.challenge,
    },
    {
      kind: 'docker-stop',
      monotonicNs: '40',
      target: run.companion.name,
    },
  ];
  return {
    mode: 'runner-metadata-observation-with-bounded-companion-target-io',
    runnerDeviceOpenCount: 0,
    runnerDeviceReadCount: 0,
    runnerDeviceWriteCount: 0,
    virtualInvocationCount: 0,
    restartRescanReconfigureCount: 0,
    productionConfigurationMutationCount: 0,
    interventionFree: true,
    entries,
    forbidden: [],
    passed: true,
  };
}

function predicateFixture() {
  const initialRuntime = runtime({
    phase: 'baseline-poll',
    monotonicNs: '1000',
    stat: INITIAL_STAT,
    present: true,
    opening: 1,
    ready: 1,
  });
  const absentRuntime = runtime({
    phase: 'absent-poll',
    monotonicNs: '3000',
    stat: INITIAL_STAT,
    present: false,
    opening: 1,
    ready: 1,
  });
  const returnedRuntime = runtime({
    phase: 'reacquisition-poll',
    monotonicNs: '5000',
    stat: RETURNED_STAT,
    present: true,
    opening: 2,
    ready: 2,
  });
  const run = {
    device: {
      serial: SERIAL,
      initialInventory: [inventoryEntry()],
      returnedInventory: [inventoryEntry({ returned: true })],
    },
    companion: {
      name: 'h041-companion-abcdef012345',
      containerId: CONTAINER_ID,
      dynamicPath: '/host-dev/hidraw0',
      compatibilityPath: '/dev/hidraw0',
      deviceCgroupRule: 'c 241:0 rw',
      deviceGid: 1002,
      staticDevices: [],
      initialLifecycle: initialRuntime.lifecycle,
      absentLifecycle: absentRuntime.lifecycle,
      finalLifecycle: returnedRuntime.lifecycle,
      workerLifecycle: {
        initial: initialRuntime.observer.surfaceWorkers,
        absent: absentRuntime.observer.surfaceWorkers,
        final: returnedRuntime.observer.surfaceWorkers,
      },
    },
    windows: {
      disconnect: { challenge: 'abcdef012345' },
      reconnect: { challenge: '123456abcdef' },
      reacquisition: {
        startedMonotonicNs: '4000',
        completedMonotonicNs: '6000',
        timeoutSeconds: 30,
      },
    },
    observations: {
      initial: {
        host: hostSnapshot(),
        runtime: initialRuntime,
      },
      absent: {
        host: { state: 'absent' },
        runtime: absentRuntime,
      },
      returned: {
        host: hostSnapshot({ returned: true }),
        runtime: returnedRuntime,
      },
      reacquisition: {
        absentMarkers: { opening: 1, ready: 1 },
      },
    },
    predicates: Object.fromEntries(PREDICATE_KEYS.map((key) => [key, true])),
  };
  run.invocationAudit = invocationAudit(run);
  return {
    run,
    context: {
      initial: { node: hostNode() },
      returned: { node: hostNode({ returned: true }) },
      runtimePoll: [returnedRuntime],
    },
  };
}

test('accepts strict monotonic chronology when every wall-clock receipt shares one millisecond', () => {
  assert.doesNotThrow(() => verifyChronology(chronologyFixture()));
});

test('rejects reordered disconnect observations on the monotonic clock', () => {
  const run = chronologyFixture();
  run.observations.absent.host.monotonicNs = run.windows.disconnect.openedMonotonicNs;
  assert.throws(() => verifyChronology(run), /H-041 monotonic chronology is invalid/u);
});

test('rejects reconnect opening before the disconnect window has closed', () => {
  const run = chronologyFixture();
  run.windows.reconnect.openedMonotonicNs = run.windows.disconnect.closedMonotonicNs;
  assert.throws(() => verifyChronology(run), /H-041 monotonic chronology is invalid/u);
});

test('rejects a reacquisition start detached from the returned-host observation', () => {
  const run = chronologyFixture();
  run.windows.reacquisition.startedMonotonicNs = '799';
  assert.throws(() => verifyChronology(run), /H-041 monotonic chronology is invalid/u);
});

test('rejects non-canonical reacquisition windows instead of accepting 5 or 120 seconds', () => {
  for (const timeoutSeconds of [5, 120]) {
    const run = chronologyFixture();
    run.windows.reacquisition.timeoutSeconds = timeoutSeconds;
    assert.throws(
      () => verifyChronology(run),
      undefined,
      `accepted ${timeoutSeconds}-second reacquisition window`
    );
  }
});

test('rejects wall-clock reordering even when monotonic chronology is valid', () => {
  const run = chronologyFixture();
  run.windows.reconnect.openedAt = '2026-07-25T23:00:00.001Z';
  run.observations.returned.host.capturedAt = '2026-07-25T23:00:00.000Z';
  assert.throws(() => verifyChronology(run), /H-041 wall-clock chronology is invalid/u);
});

test('recomputes every predicate from primary receipts instead of declared booleans', () => {
  const { run, context } = predicateFixture();
  const expected = Object.fromEntries(PREDICATE_KEYS.map((key) => [key, true]));
  assert.deepEqual(recomputePredicates(run, context), expected);

  run.predicates = Object.fromEntries(PREDICATE_KEYS.map((key) => [key, false]));
  assert.deepEqual(recomputePredicates(run, context), expected);
});

test('recomputation exposes lifecycle, permission, and descriptor tampering independently', () => {
  {
    const { run, context } = predicateFixture();
    run.observations.returned.runtime.lifecycle.restartCount = 1;
    const recomputed = recomputePredicates(run, context);
    assert.equal(run.predicates.topLevelLifecycleUnchanged, true);
    assert.equal(recomputed.topLevelLifecycleUnchanged, false);
  }

  {
    const { run, context } = predicateFixture();
    run.observations.returned.runtime.container.privileged = true;
    const recomputed = recomputePredicates(run, context);
    assert.equal(run.predicates.permissionBoundaryExact, true);
    assert.equal(recomputed.permissionBoundaryExact, false);
  }

  {
    const { run, context } = predicateFixture();
    run.observations.returned.runtime.container.mounts.push({
      type: 'bind',
      source: '/tmp/forged-config',
      destination: '/companion/v4.3',
      rw: false,
    });
    const recomputed = recomputePredicates(run, context);
    assert.equal(recomputed.permissionBoundaryExact, false);
  }

  {
    const { run, context } = predicateFixture();
    context.runtimePoll[0].observer.surfaceWorkers[0].fileDescriptors[0].stat = {
      ...INITIAL_STAT,
    };
    const recomputed = recomputePredicates(run, context);
    assert.equal(run.predicates.postReturnDescriptorObserved, true);
    assert.equal(recomputed.postReturnDescriptorObserved, false);
    assert.equal(recomputed.postReturnLogMarkersObserved, true);
  }
});

test('binds duplicated lifecycle and worker summaries to primary runtime receipts', () => {
  const { run } = predicateFixture();
  assert.equal(verifyLifecycleBindings(run), true);

  run.companion.workerLifecycle.final = structuredClone(run.companion.workerLifecycle.final);
  run.companion.workerLifecycle.final[0].fileDescriptors = [];
  assert.throws(
    () => verifyLifecycleBindings(run),
    /final workers does not match its primary runtime receipt/u
  );
});
