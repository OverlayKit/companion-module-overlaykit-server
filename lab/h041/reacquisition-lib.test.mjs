import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  H041_CLAIM_BOUNDARY,
  classifyH041Outcome,
  countAcquisitionMarkers,
  descriptorMatchesDynamicNode,
  dynamicStageMatchesHost,
  hostEpochChanged,
  runId,
  sameSurfaceWorker,
  sameTopLevelLifecycle,
  statIdentityEqual,
} from './reacquisition-lib.mjs';

const SERIAL = 'A00SA5492OQMLF';
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

function stat(overrides = {}) {
  return {
    stDev: '7',
    inode: '1402',
    ctimeNs: '1785017681209719431',
    rdevHex: 'f1:0',
    ...overrides,
  };
}

function dynamicValue(path = '/host-dev/hidraw0', value = stat()) {
  return { kind: 'value', path, value };
}

function hostNode(overrides = {}) {
  return {
    devicePath: '/dev/hidraw0',
    stat: stat(),
    ...overrides,
  };
}

function hostSnapshot(overrides = {}) {
  const serial = overrides.expectedSerial ?? SERIAL;
  const deviceNumber = overrides.deviceNumber ?? '13';
  const nodeStat = overrides.stat ?? stat();
  return {
    state: 'present',
    expectedSerial: serial,
    scope: {
      bootId: '30b83905-13f4-439a-9c1e-5c8424023fd7',
      mountNamespace: 'mnt:[4026531832]',
      ...overrides.scope,
    },
    errors: [],
    usb: [
      {
        serialMatches: true,
        serial,
        deviceNumber,
      },
    ],
    hidraw: [
      {
        serialMatches: true,
        hid: { unique: serial },
        hidDevicePath:
          overrides.hidDevicePath ?? '/sys/devices/pci/usb/0003:0FD9:0080.0011/hidraw/hidraw0',
        usbAncestor: { serial, deviceNumber },
        stat: nodeStat,
      },
    ],
  };
}

function lifecycle() {
  return {
    containerId: 'container-identity',
    imageId: 'sha256:image-identity',
    startedAt: '2026-07-25T23:00:00.000Z',
    restartCount: 0,
    hostPid: 410_000,
    pid1StartTicks: 1_600_000,
    pidNamespace: 'pid:[4026533000]',
    mountNamespace: 'mnt:[4026533001]',
    cgroup: '0::/',
    hostCgroup: '0::/system.slice/docker-container.scope',
    cgroupNamespaceMode: 'private',
  };
}

function surfaceWorker() {
  return {
    pid: 56,
    startTicks: 1_600_042,
    ppid: 1,
    parentStartTicks: 1_600_000,
    pidNamespace: 'pid:[4026533000]',
    mountNamespace: 'mnt:[4026533001]',
    cgroup: '0::/system.slice/docker-container.scope',
  };
}

function predicates(value = true) {
  return Object.fromEntries(PREDICATE_KEYS.map((key) => [key, value]));
}

test('exports the bounded H-041 claim and creates unique H-041 run identities', () => {
  assert.ok(H041_CLAIM_BOUNDARY.proves.length > 0);
  assert.ok(H041_CLAIM_BOUNDARY.excludes.length > 0);
  assert.match(runId(), /^h041-[0-9TZ-]+-[0-9a-f]{8}$/u);
});

test('compares the full same-namespace stat identity and fails closed', () => {
  assert.equal(
    statIdentityEqual(
      stat({
        stDev: '0007',
        inode: '001402',
        ctimeNs: '01785017681209719431',
        rdevHex: '0F1:00',
      }),
      stat()
    ),
    true
  );
  for (const [key, value] of [
    ['stDev', '8'],
    ['inode', '1403'],
    ['ctimeNs', '1785017681209719432'],
    ['rdevHex', 'f1:1'],
  ]) {
    assert.equal(statIdentityEqual(stat(), stat({ [key]: value })), false, key);
  }
  for (const malformed of [
    null,
    [],
    {},
    { ...stat(), inode: 1402 },
    { ...stat(), inode: '0' },
    { ...stat(), ctimeNs: '-1' },
    { ...stat(), rdevHex: 'not-a-device' },
  ]) {
    assert.equal(statIdentityEqual(stat(), malformed), false);
  }
});

test('matches present and absent dynamic-view stages to the exact host node', () => {
  assert.equal(
    dynamicStageMatchesHost({
      hostNode: hostNode(),
      dynamic: dynamicValue(),
    }),
    true
  );
  assert.equal(
    dynamicStageMatchesHost({
      hostNode: null,
      dynamic: { kind: 'missing', path: '/host-dev/hidraw0', code: 'ENOENT' },
    }),
    true
  );
  for (const malformed of [
    {
      hostNode: hostNode(),
      dynamic: dynamicValue('/host-dev/hidraw1'),
    },
    {
      hostNode: hostNode(),
      dynamic: dynamicValue('/host-dev/hidraw0', stat({ inode: '1403' })),
    },
    {
      hostNode: hostNode(),
      dynamic: { kind: 'missing', path: '/host-dev/hidraw0', code: 'ENOENT' },
    },
    {
      hostNode: null,
      dynamic: dynamicValue(),
    },
    {
      hostNode: null,
      dynamic: { kind: 'missing', path: '/host-dev/hidraw0', code: 'EACCES' },
    },
    {
      hostNode: null,
      dynamic: {
        kind: 'missing',
        path: '/host-dev/hidraw0',
        code: 'ENOENT',
        extra: true,
      },
    },
    {
      hostNode: hostNode(),
      dynamic: dynamicValue(),
      extra: true,
    },
  ]) {
    assert.equal(dynamicStageMatchesHost(malformed), false);
  }
});

test('detects a new epoch only from two exact same-scope host snapshots', () => {
  const before = hostSnapshot();
  assert.equal(hostEpochChanged(before, structuredClone(before)), false);

  const deviceNumber = hostSnapshot({ deviceNumber: '14' });
  assert.equal(hostEpochChanged(before, deviceNumber), true);

  const hid = hostSnapshot({
    hidDevicePath: '/sys/devices/pci/usb/0003:0FD9:0080.0012/hidraw/hidraw0',
  });
  assert.equal(hostEpochChanged(before, hid), true);

  assert.equal(hostEpochChanged(before, hostSnapshot({ stat: stat({ inode: '1403' }) })), true);
  assert.equal(
    hostEpochChanged(before, hostSnapshot({ stat: stat({ ctimeNs: '1785017681209719432' }) })),
    true
  );
  assert.equal(
    hostEpochChanged(before, hostSnapshot({ stat: stat({ stDev: '8', rdevHex: 'f2:0' }) })),
    false
  );

  const changedScope = hostSnapshot({
    scope: { mountNamespace: 'mnt:[4026539999]' },
    deviceNumber: '14',
  });
  assert.equal(hostEpochChanged(before, changedScope), false);

  const duplicateTarget = hostSnapshot({ deviceNumber: '14' });
  duplicateTarget.hidraw.push(structuredClone(duplicateTarget.hidraw[0]));
  assert.equal(hostEpochChanged(before, duplicateTarget), false);

  const incomplete = hostSnapshot({ deviceNumber: '14' });
  delete incomplete.hidraw[0].stat.ctimeNs;
  assert.equal(hostEpochChanged(before, incomplete), false);
});

test('requires complete top-level identity and defeats PID reuse', () => {
  const before = lifecycle();
  assert.equal(sameTopLevelLifecycle(before, structuredClone(before)), true);
  for (const [key, value] of [
    ['containerId', 'replacement-container'],
    ['imageId', 'sha256:replacement-image'],
    ['startedAt', '2026-07-25T23:00:01.000Z'],
    ['restartCount', 1],
    ['hostPid', 410_001],
    ['pid1StartTicks', 1_600_001],
    ['pidNamespace', 'pid:[4026533002]'],
    ['mountNamespace', 'mnt:[4026533002]'],
    ['cgroup', '0::/replacement'],
    ['hostCgroup', '0::/system.slice/docker-replacement.scope'],
    ['cgroupNamespaceMode', 'host'],
  ]) {
    assert.equal(
      sameTopLevelLifecycle(before, { ...structuredClone(before), [key]: value }),
      false,
      key
    );
  }
  const reusedPid = structuredClone(before);
  reusedPid.pid1StartTicks += 1;
  assert.equal(reusedPid.hostPid, before.hostPid);
  assert.equal(sameTopLevelLifecycle(before, reusedPid), false);

  const incomplete = structuredClone(before);
  delete incomplete.pidNamespace;
  assert.equal(sameTopLevelLifecycle(before, incomplete), false);
  assert.equal(sameTopLevelLifecycle({}, {}), false);
});

test('requires complete SurfaceThread ancestry and defeats worker and parent PID reuse', () => {
  const before = surfaceWorker();
  assert.equal(sameSurfaceWorker(before, structuredClone(before)), true);

  const reusedWorkerPid = structuredClone(before);
  reusedWorkerPid.startTicks += 1;
  assert.equal(reusedWorkerPid.pid, before.pid);
  assert.equal(sameSurfaceWorker(before, reusedWorkerPid), false);

  const reusedParentPid = structuredClone(before);
  reusedParentPid.parentStartTicks += 1;
  assert.equal(reusedParentPid.ppid, before.ppid);
  assert.equal(sameSurfaceWorker(before, reusedParentPid), false);

  for (const key of ['ppid', 'pidNamespace', 'mountNamespace', 'cgroup']) {
    const changed = structuredClone(before);
    changed[key] = typeof changed[key] === 'number' ? changed[key] + 1 : `${changed[key]}-changed`;
    assert.equal(sameSurfaceWorker(before, changed), false, key);
  }

  const incomplete = structuredClone(before);
  delete incomplete.parentStartTicks;
  assert.equal(sameSurfaceWorker(before, incomplete), false);
  assert.equal(sameSurfaceWorker(null, null), false);
});

test('counts only serial-specific acquisition and exact-path failure markers', () => {
  const markers = countAcquisitionMarkers(
    [
      `\u001b[32mcompanion | Opening surface panel: streamdeck:${SERIAL} - Elgato Stream Deck MK.2\u001b[0m`,
      `companion | Surface panel ready: streamdeck:${SERIAL}`,
      `companion | Error opening discovered surface streamdeck:${SERIAL}: cannot open device with path /dev/hidraw0`,
      'companion | Surface panel ready: streamdeck:ANOTHER-SERIAL',
      `companion | Error opening discovered surface streamdeck:${SERIAL}: cannot open device with path /dev/hidraw9`,
    ].join('\n'),
    SERIAL,
    ['/dev/hidraw0', '/host-dev/hidraw0']
  );
  assert.deepEqual(
    {
      opening: markers.opening,
      ready: markers.ready,
      openFailed: markers.openFailed,
    },
    { opening: 1, ready: 1, openFailed: 1 }
  );
  assert.equal(markers.relevantLines.length, 3);
  assert.deepEqual(countAcquisitionMarkers('', SERIAL, ['/dev/hidraw0']), {
    opening: 0,
    ready: 0,
    openFailed: 0,
    relevantLines: [],
  });
  assert.throws(() => countAcquisitionMarkers(null, SERIAL, ['/dev/hidraw0']), /logs/u);
  assert.throws(() => countAcquisitionMarkers('logs', '', ['/dev/hidraw0']), /serial/u);
  assert.throws(() => countAcquisitionMarkers('logs', SERIAL, []), /at least one/u);
  assert.throws(
    () => countAcquisitionMarkers('logs', SERIAL, ['/host-dev/../dev/hidraw0']),
    /normalized/u
  );
});

test('matches a descriptor to the full dynamic-node identity, not pathname or rdev alone', () => {
  const descriptor = { target: '/dev/hidraw0', stat: stat() };
  assert.equal(descriptorMatchesDynamicNode(descriptor, dynamicValue()), true);
  assert.equal(
    descriptorMatchesDynamicNode({ ...descriptor, target: '/host-dev/hidraw0' }, dynamicValue()),
    true
  );
  for (const [key, value] of [
    ['stDev', '8'],
    ['inode', '1403'],
    ['ctimeNs', '1785017681209719432'],
    ['rdevHex', 'f1:1'],
  ]) {
    assert.equal(
      descriptorMatchesDynamicNode(
        { target: '/dev/hidraw0', stat: stat({ [key]: value }) },
        dynamicValue()
      ),
      false,
      key
    );
  }
  assert.equal(
    descriptorMatchesDynamicNode({ target: '/dev/hidraw1', stat: stat() }, dynamicValue()),
    false
  );
  assert.equal(
    descriptorMatchesDynamicNode(descriptor, {
      kind: 'missing',
      path: '/host-dev/hidraw0',
      code: 'ENOENT',
    }),
    false
  );
  assert.equal(descriptorMatchesDynamicNode({ target: '/dev/hidraw0' }, dynamicValue()), false);
});

test('classifies the exhaustive eleven-predicate matrix fail closed', () => {
  for (let mask = 0; mask < 2 ** PREDICATE_KEYS.length; mask += 1) {
    const observed = Object.fromEntries(
      PREDICATE_KEYS.map((key, index) => [key, Boolean(mask & (1 << index))])
    );
    const classified = classifyH041Outcome(observed);
    const prerequisites = PREDICATE_KEYS.slice(0, 8).every((key) => observed[key]);
    if (!prerequisites) {
      assert.deepEqual(
        { status: classified.status, stage: classified.stage },
        { status: 'inconclusive', stage: 'preconditions' }
      );
    } else if (!observed.deadlineBoundaryConsistent) {
      assert.deepEqual(
        { status: classified.status, stage: classified.stage },
        { status: 'inconclusive', stage: 'contradictory-reacquisition' }
      );
    } else if (observed.postReturnDescriptorObserved && observed.postReturnLogMarkersObserved) {
      assert.deepEqual(
        { status: classified.status, stage: classified.stage },
        { status: 'supported', stage: 'complete' }
      );
    } else if (!observed.postReturnDescriptorObserved && !observed.postReturnLogMarkersObserved) {
      assert.deepEqual(
        { status: classified.status, stage: classified.stage },
        { status: 'refuted', stage: 'companion-reacquisition' }
      );
    } else {
      assert.deepEqual(
        { status: classified.status, stage: classified.stage },
        { status: 'inconclusive', stage: 'contradictory-reacquisition' }
      );
    }
    assert.equal(typeof classified.reason, 'string');
    assert.ok(classified.reason.length > 0);
  }
});

test('classifies malformed, partial, or expanded predicate envelopes as precondition failures', () => {
  const valid = predicates();
  for (const malformed of [
    null,
    [],
    {},
    { ...valid, complete: null },
    { ...valid, interventionFree: 'true' },
    { ...valid, permissionBoundaryExact: 1 },
    Object.fromEntries(
      Object.entries(valid).filter(([key]) => key !== 'topLevelLifecycleUnchanged')
    ),
    { ...valid, extra: true },
  ]) {
    assert.deepEqual(classifyH041Outcome(malformed), {
      status: 'inconclusive',
      stage: 'preconditions',
      reason: 'H-041 prerequisites are incomplete, malformed, or false.',
    });
  }
});
