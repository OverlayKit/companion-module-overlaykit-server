import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  HostInventorySelectionError,
  decodeLinuxDeviceNumber,
  inventoryHostHidraw,
  parseClassDeviceNumber,
  parseHidUevent,
  selectExactTargetHidraw,
} from './host-inventory.mjs';

function encodeLinuxDeviceNumber(major, minor) {
  const majorBigInt = BigInt(major);
  const minorBigInt = BigInt(minor);
  return (
    ((majorBigInt & 0xfffn) << 8n) |
    (minorBigInt & 0xffn) |
    ((majorBigInt & ~0xfffn) << 32n) |
    ((minorBigInt & ~0xffn) << 12n)
  );
}

function fakeStat({
  major,
  minor,
  inode,
  ctimeNs = 1_785_020_000_000_000_000n,
  characterDevice = true,
}) {
  return {
    dev: 7n,
    ino: BigInt(inode),
    ctimeNs: BigInt(ctimeNs),
    mode: 0o20660n,
    uid: 0n,
    gid: 1002n,
    rdev: encodeLinuxDeviceNumber(major, minor),
    isCharacterDevice: () => characterDevice,
  };
}

function missing(filePath) {
  const error = new Error(`fixture has no ${filePath}`);
  error.code = 'ENOENT';
  return error;
}

function deviceFixture({
  name,
  hidId,
  serial,
  usbVendorId,
  usbProductId,
  major = 241,
  minor,
  inode,
  classDev = `${major}:${minor}`,
  statSequence,
}) {
  const suffix = name.slice('hidraw'.length);
  const usbPath = `/sys/devices/pci0000:00/0000:00:14.0/usb1/1-${suffix}`;
  const hidDevicePath = `${usbPath}/1-${suffix}:1.0/${hidId.replaceAll(':', '-')}.0001`;
  return {
    name,
    hidDevicePath,
    usbPath,
    files: {
      [`/sys/class/hidraw/${name}/device/uevent`]: [
        `HID_ID=${hidId}`,
        `HID_UNIQ=${serial}`,
        `HID_NAME=${name} fixture`,
        `HID_PHYS=usb-fixture-${suffix}/input0`,
      ].join('\n'),
      [`/sys/class/hidraw/${name}/dev`]: `${classDev}\n`,
      [`${usbPath}/idVendor`]: `${usbVendorId}\n`,
      [`${usbPath}/idProduct`]: `${usbProductId}\n`,
      [`${usbPath}/serial`]: `${serial}\n`,
      [`${usbPath}/manufacturer`]: 'Fixture Manufacturer\n',
      [`${usbPath}/product`]: `${name} USB device\n`,
      [`${usbPath}/busnum`]: '1\n',
      [`${usbPath}/devnum`]: `${Number(suffix) + 10}\n`,
      [`${usbPath}/devpath`]: `${suffix}\n`,
    },
    stats: statSequence ?? [fakeStat({ major, minor, inode }), fakeStat({ major, minor, inode })],
  };
}

function standardDevices() {
  return [
    deviceFixture({
      name: 'hidraw0',
      hidId: '0003:0000046D:0000C534',
      serial: 'keyboard-serial',
      usbVendorId: '046d',
      usbProductId: 'c534',
      minor: 0,
      inode: 1400,
    }),
    deviceFixture({
      name: 'hidraw2',
      hidId: '0003:00000FD9:00000080',
      serial: 'A00SA5492OQMLF',
      usbVendorId: '0FD9',
      usbProductId: '0080',
      minor: 2,
      inode: 1402,
    }),
    deviceFixture({
      name: 'hidraw10',
      hidId: '0003:00001234:00005678',
      serial: 'other-serial',
      usbVendorId: '1234',
      usbProductId: '5678',
      minor: 10,
      inode: 1410,
    }),
  ];
}

function fixtureFilesystem(devices, names = devices.map((device) => device.name)) {
  const calls = [];
  const files = new Map();
  const realpaths = new Map();
  const stats = new Map();
  const statIndexes = new Map();
  for (const device of devices) {
    for (const [filePath, value] of Object.entries(device.files)) files.set(filePath, value);
    realpaths.set(`/sys/class/hidraw/${device.name}/device`, device.hidDevicePath);
    stats.set(`/dev/${device.name}`, device.stats);
  }

  const filesystem = {
    readdirSync(filePath) {
      calls.push({ operation: 'readdirSync', path: filePath });
      assert.equal(filePath, '/sys/class/hidraw');
      return [...names];
    },
    readFileSync(filePath, encoding) {
      calls.push({ operation: 'readFileSync', path: filePath, encoding });
      if (!files.has(filePath)) throw missing(filePath);
      return files.get(filePath);
    },
    realpathSync(filePath) {
      calls.push({ operation: 'realpathSync', path: filePath });
      if (!realpaths.has(filePath)) throw missing(filePath);
      return realpaths.get(filePath);
    },
    statSync(filePath, options) {
      calls.push({ operation: 'statSync', path: filePath, options });
      const sequence = stats.get(filePath);
      if (sequence === undefined) throw missing(filePath);
      const index = statIndexes.get(filePath) ?? 0;
      statIndexes.set(filePath, index + 1);
      return sequence[Math.min(index, sequence.length - 1)];
    },
  };
  return { filesystem, calls, files };
}

function inventory(devices = standardDevices()) {
  const fixture = fixtureFilesystem(devices, devices.map((device) => device.name).reverse());
  return {
    ...fixture,
    entries: inventoryHostHidraw({ filesystem: fixture.filesystem }),
  };
}

function expectSelectionError(code, operation) {
  assert.throws(
    operation,
    (error) => error instanceof HostInventorySelectionError && error.code === code
  );
}

function select(entries) {
  return selectExactTargetHidraw(entries, {
    vendorId: '0fd9',
    productId: '0080',
    serial: 'A00SA5492OQMLF',
  });
}

test('pure parsers normalize the exact HID identity and class major:minor', () => {
  assert.deepEqual(
    parseHidUevent(
      [
        'HID_ID=0003:00000FD9:00000080',
        'HID_UNIQ=A00SA5492OQMLF',
        'HID_NAME=Elgato Stream Deck MK.2',
        'HID_PHYS=usb-fixture/input0',
      ].join('\n')
    ),
    {
      id: '0003:00000FD9:00000080',
      bus: '0003',
      vendorId: '0fd9',
      productId: '0080',
      unique: 'A00SA5492OQMLF',
      name: 'Elgato Stream Deck MK.2',
      physicalPath: 'usb-fixture/input0',
    }
  );
  assert.deepEqual(parseClassDeviceNumber('241:17\n'), { major: 241, minor: 17 });
  assert.deepEqual(decodeLinuxDeviceNumber(encodeLinuxDeviceNumber(241, 17)), {
    major: 241,
    minor: 17,
  });
  assert.equal(parseClassDeviceNumber('241:-1'), null);
  assert.equal(parseClassDeviceNumber('241:1:2'), null);
  assert.equal(
    parseHidUevent('HID_ID=0003:00000FD9:00000080\nHID_ID=0003:00000FD9:00000080'),
    null
  );
  assert.equal(parseHidUevent('HID_ID=0003:00010FD9:00000080'), null);
});

test('inventories every hidraw entry with linked HID, USB, class-dev, and stable stat metadata', () => {
  const { entries, calls } = inventory();

  assert.deepEqual(
    entries.map((entry) => entry.name),
    ['hidraw0', 'hidraw2', 'hidraw10']
  );
  assert(entries.every((entry) => entry.errors.length === 0));

  const target = entries[1];
  assert.equal(target.devicePath, '/dev/hidraw2');
  assert.equal(target.hid.id, '0003:00000FD9:00000080');
  assert.equal(target.hid.unique, 'A00SA5492OQMLF');
  assert.deepEqual(target.classDevice, { major: 241, minor: 2 });
  assert.deepEqual(
    {
      vendorId: target.usbAncestor.vendorId,
      productId: target.usbAncestor.productId,
      serial: target.usbAncestor.serial,
      deviceNumber: target.usbAncestor.deviceNumber,
    },
    {
      vendorId: '0fd9',
      productId: '0080',
      serial: 'A00SA5492OQMLF',
      deviceNumber: '12',
    }
  );
  assert.equal(target.stat.stable, true);
  assert.equal(target.stat.matchesClass, true);
  assert.equal(target.stat.value.isCharacterDevice, true);
  assert.equal(target.stat.value.rdevHex, 'f1:2');

  assert.equal(calls.filter((call) => call.operation === 'statSync').length, entries.length * 2);
  assert(
    calls
      .filter((call) => call.operation === 'statSync')
      .every((call) => call.options?.bigint === true)
  );
  assert.deepEqual([...new Set(calls.map((call) => call.operation))].sort(), [
    'readFileSync',
    'readdirSync',
    'realpathSync',
    'statSync',
  ]);
});

test('surfaces malformed entry metadata instead of dropping the hidraw entry', () => {
  const devices = standardDevices();
  devices[1].files['/sys/class/hidraw/hidraw2/dev'] = 'not-a-device\n';
  const { filesystem } = fixtureFilesystem(devices, [
    'hidraw2',
    'unexpected-entry',
    'hidraw0',
    'hidraw10',
  ]);
  const entries = inventoryHostHidraw({ filesystem });

  assert.equal(entries.length, 4);
  assert.deepEqual(entries.find((entry) => entry.name === 'hidraw2').errors, [
    {
      stage: 'class-dev-parse',
      path: '/sys/class/hidraw/hidraw2/dev',
      code: 'EINVAL',
    },
  ]);
  assert.deepEqual(entries.find((entry) => entry.name === 'unexpected-entry').errors, [
    {
      stage: 'entry-name',
      path: '/sys/class/hidraw',
      code: 'EINVAL',
    },
  ]);
});

test('selects one exact serial only when HID and USB ancestry agree', () => {
  const { entries } = inventory();
  const before = JSON.stringify(entries);
  const selected = selectExactTargetHidraw(entries, {
    vendorId: '0FD9',
    productId: '0080',
    serial: 'A00SA5492OQMLF',
  });

  assert.equal(selected.name, 'hidraw2');
  assert.equal(JSON.stringify(entries), before);

  const ancestorMismatch = structuredClone(entries);
  ancestorMismatch[1].usbAncestor.serial = 'different';
  expectSelectionError('TARGET_NOT_FOUND', () => select(ancestorMismatch));
  expectSelectionError('INVALID_SELECTION_INPUT', () =>
    selectExactTargetHidraw(entries, {
      vendorId: '0fd9',
      productId: '0080',
    })
  );
});

test('rejects absent and ambiguous exact target identities', () => {
  const { entries } = inventory();
  expectSelectionError('TARGET_NOT_FOUND', () =>
    selectExactTargetHidraw(entries, {
      vendorId: '0fd9',
      productId: '0080',
      serial: 'absent-serial',
    })
  );

  const ambiguous = structuredClone(entries);
  const duplicate = structuredClone(ambiguous[1]);
  duplicate.name = 'hidraw3';
  duplicate.devicePath = '/dev/hidraw3';
  ambiguous.push(duplicate);
  expectSelectionError('TARGET_AMBIGUOUS', () => select(ambiguous));
});

test('recomputes stable character-node and class-device predicates fail closed', () => {
  const { entries } = inventory();

  const unstable = structuredClone(entries);
  unstable[1].stat.after.value.inode = '9999';
  expectSelectionError('TARGET_NODE_UNSTABLE', () => select(unstable));

  const notCharacter = structuredClone(entries);
  notCharacter[1].stat.before.value.isCharacterDevice = false;
  notCharacter[1].stat.after.value.isCharacterDevice = false;
  expectSelectionError('TARGET_NODE_NOT_CHARACTER', () => select(notCharacter));

  const classMismatch = structuredClone(entries);
  classMismatch[1].classDevice.minor = 99;
  expectSelectionError('TARGET_NODE_CLASS_MISMATCH', () => select(classMismatch));

  const malformedStat = structuredClone(entries);
  delete malformedStat[1].stat.after.value.ctimeNs;
  expectSelectionError('TARGET_STAT_INVALID', () => select(malformedStat));
});

test('rejects a target major:minor claimed by any other inventoried hidraw', () => {
  const { entries } = inventory();

  const classAlias = structuredClone(entries);
  classAlias[0].classDevice = { major: 241, minor: 2 };
  expectSelectionError('DEVICE_NUMBER_NOT_UNIQUE', () => select(classAlias));

  const nodeAlias = structuredClone(entries);
  for (const receipt of [nodeAlias[2].stat.before, nodeAlias[2].stat.after]) {
    Object.assign(receipt.value, {
      rdev: encodeLinuxDeviceNumber(241, 2).toString(),
      major: 241,
      minor: 2,
      rdevHex: 'f1:2',
    });
  }
  expectSelectionError('DEVICE_NUMBER_NOT_UNIQUE', () => select(nodeAlias));
});

test('rejects incomplete inventories even when the exact target entry is complete', () => {
  const { entries } = inventory();

  const surfacedError = structuredClone(entries);
  surfacedError[0].errors.push({
    stage: 'device-stat-after',
    path: '/dev/hidraw0',
    code: 'ENOENT',
  });
  expectSelectionError('INVENTORY_INCOMPLETE', () => select(surfacedError));

  const hiddenMalformedEntry = structuredClone(entries);
  hiddenMalformedEntry[2].classDevice = null;
  expectSelectionError('INVENTORY_INCOMPLETE', () => select(hiddenMalformedEntry));

  expectSelectionError('INVALID_INVENTORY', () => select([{ name: 'hidraw0', errors: null }]));
});
