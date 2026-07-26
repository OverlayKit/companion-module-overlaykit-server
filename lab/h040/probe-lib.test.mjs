import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  classifyMappingOutcome,
  dynamicMatchesHost,
  hostEpochChanged,
  normalizeProbeStat,
  staticIdentityUnchanged,
} from './probe-lib.mjs';

const expectedValue = {
  stDev: '7',
  inode: '1402',
  ctimeNs: '1785017681209719431',
  rdev: '61696',
  rdevHex: 'f1:0',
  major: 241,
  minor: 0,
  isCharacterDevice: true,
};

function valueReceipt(path = '/dev/hidraw0', value = expectedValue) {
  return { kind: 'value', path, value: structuredClone(value) };
}

function hostNode() {
  return {
    devicePath: '/dev/hidraw0',
    hidDevicePath: '/sys/devices/pci/usb/0003:0FD9:0080.0011',
    usbAncestor: { deviceNumber: '13' },
    stat: {
      ...structuredClone(expectedValue),
      mode: '0660',
      uid: 0,
      gid: 1002,
    },
  };
}

test('normalizes a complete character-device stat receipt and an ENOENT receipt', () => {
  assert.deepEqual(
    normalizeProbeStat(
      valueReceipt('/dev/hidraw0', {
        ...expectedValue,
        stDev: '0007',
        inode: '001402',
        rdev: '061696',
        rdevHex: '0F1:00',
      })
    ),
    valueReceipt()
  );
  assert.deepEqual(normalizeProbeStat({ kind: 'missing', path: '/dev/hidraw0' }), {
    kind: 'missing',
    path: '/dev/hidraw0',
    code: 'ENOENT',
  });
  assert.deepEqual(normalizeProbeStat({ kind: 'missing', path: '/dev/hidraw0', code: 'ENOENT' }), {
    kind: 'missing',
    path: '/dev/hidraw0',
    code: 'ENOENT',
  });
});

test('rejects every missing or malformed stat identity field', () => {
  for (const key of Object.keys(expectedValue)) {
    const receipt = valueReceipt();
    delete receipt.value[key];
    assert.equal(normalizeProbeStat(receipt), null, `missing ${key}`);
  }
  const mutations = {
    stDev: null,
    inode: '0',
    ctimeNs: '-1',
    rdev: '61697',
    rdevHex: 'f1:1',
    major: 242,
    minor: 1,
    isCharacterDevice: false,
  };
  for (const [key, mutation] of Object.entries(mutations)) {
    const receipt = valueReceipt();
    receipt.value[key] = mutation;
    assert.equal(normalizeProbeStat(receipt), null, `malformed ${key}`);
  }
  for (const malformed of [
    null,
    [],
    {},
    { kind: 'pending', path: '/dev/hidraw0' },
    { kind: 'missing', path: 'dev/hidraw0' },
    { kind: 'missing', path: '/dev/hidraw0', code: 'EACCES' },
    { kind: 'missing', path: '/dev/hidraw0', extra: true },
    { ...valueReceipt(), extra: true },
    valueReceipt('/dev/../hidraw0'),
    valueReceipt('/dev/hidraw0', { ...expectedValue, extra: true }),
  ]) {
    assert.equal(normalizeProbeStat(malformed), null);
  }
});

test('matches a dynamic view to the complete current host-node epoch', () => {
  const host = hostNode();
  assert.equal(dynamicMatchesHost(valueReceipt('/host-dev/hidraw0'), host), true);
  assert.equal(
    dynamicMatchesHost(
      valueReceipt('/host-dev/hidraw0', { ...expectedValue, inode: '1401' }),
      host
    ),
    false
  );
  assert.equal(
    dynamicMatchesHost(
      valueReceipt('/host-dev/hidraw0', {
        ...expectedValue,
        ctimeNs: '1785017681209719430',
      }),
      host
    ),
    false
  );
  assert.equal(
    dynamicMatchesHost({ kind: 'missing', path: '/host-dev/hidraw0', code: 'ENOENT' }, host),
    false
  );
  assert.equal(dynamicMatchesHost(valueReceipt('/host-dev/hidraw1'), host), false);
  assert.equal(dynamicMatchesHost(valueReceipt('/host-dev/../dev/hidraw0'), host), null);
  assert.equal(dynamicMatchesHost({ kind: 'value', path: '/host-dev/hidraw0' }, host), null);
  assert.equal(
    dynamicMatchesHost(valueReceipt('/host-dev/hidraw0'), { ...host, stat: null }),
    null
  );
});

test('detects a host enumeration epoch change through each independent identity', () => {
  const before = hostNode();
  assert.equal(hostEpochChanged(before, structuredClone(before)), false);
  const mutations = [
    (node) => {
      node.usbAncestor.deviceNumber = '14';
    },
    (node) => {
      node.hidDevicePath = '/sys/devices/pci/usb/0003:0FD9:0080.0012';
    },
    (node) => {
      node.stat.inode = '1403';
    },
    (node) => {
      node.stat.ctimeNs = '1785017681209719432';
    },
  ];
  for (const mutate of mutations) {
    const after = structuredClone(before);
    mutate(after);
    assert.equal(hostEpochChanged(before, after), true);
  }
  assert.equal(hostEpochChanged(before, { ...structuredClone(before), usbAncestor: null }), null);
  assert.equal(hostEpochChanged(before, { ...structuredClone(before), stat: null }), null);
});

test('requires the static mapping to persist with one exact immutable identity', () => {
  const initial = valueReceipt('/tmp/h040-static-hidraw');
  assert.equal(
    staticIdentityUnchanged(initial, structuredClone(initial), structuredClone(initial)),
    true
  );
  for (const mutate of [
    (receipt) => {
      receipt.path = '/tmp/h040-static-hidraw-other';
    },
    (receipt) => {
      receipt.value.stDev = '8';
    },
    (receipt) => {
      receipt.value.inode = '1403';
    },
    (receipt) => {
      receipt.value.ctimeNs = '1785017681209719432';
    },
    (receipt) => {
      Object.assign(receipt.value, {
        rdev: '61952',
        rdevHex: 'f2:0',
        major: 242,
      });
    },
  ]) {
    const returned = structuredClone(initial);
    mutate(returned);
    assert.equal(staticIdentityUnchanged(initial, structuredClone(initial), returned), false);
  }
  assert.equal(
    staticIdentityUnchanged(
      initial,
      { kind: 'missing', path: '/tmp/h040-static-hidraw', code: 'ENOENT' },
      structuredClone(initial)
    ),
    false
  );
  assert.equal(staticIdentityUnchanged(initial, { kind: 'value' }, structuredClone(initial)), null);
});

test('classifies the exhaustive complete metadata-only predicate matrix', () => {
  const resultKeys = [
    'dynamicInitialMatchesHost',
    'dynamicReturnedMatchesHost',
    'dynamicAbsent',
    'staticPersists',
    'staticUnchanged',
    'hostEpochChanged',
  ];
  for (let mask = 0; mask < 2 ** resultKeys.length; mask += 1) {
    const predicates = { complete: true, metadataOnly: true };
    resultKeys.forEach((key, index) => {
      predicates[key] = Boolean(mask & (1 << index));
    });
    assert.equal(
      classifyMappingOutcome(predicates),
      mask === 2 ** resultKeys.length - 1 ? 'supported' : 'refuted'
    );
  }
});

test('classifies incomplete, intervention-bearing, or malformed predicates as inconclusive', () => {
  const complete = {
    complete: true,
    metadataOnly: true,
    dynamicInitialMatchesHost: true,
    dynamicReturnedMatchesHost: true,
    dynamicAbsent: true,
    staticPersists: true,
    staticUnchanged: true,
    hostEpochChanged: true,
  };
  for (const malformed of [
    null,
    [],
    {},
    { ...complete, complete: false },
    { ...complete, metadataOnly: false },
    { ...complete, dynamicAbsent: null },
    { ...complete, hostEpochChanged: 'true' },
    Object.fromEntries(Object.entries(complete).filter(([key]) => key !== 'staticUnchanged')),
    { ...complete, extra: true },
  ]) {
    assert.equal(classifyMappingOutcome(malformed), 'inconclusive');
  }
});
