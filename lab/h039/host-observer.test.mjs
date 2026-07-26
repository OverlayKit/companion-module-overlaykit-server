import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  classifyHostSnapshot,
  currentMountNamespace,
  decodeLinuxDeviceNumber,
} from './host-observer.mjs';

test('reads the mount namespace as a kernel identity rather than a filesystem path', () => {
  assert.match(currentMountNamespace(), /^mnt:\[[0-9]+\]$/u);
});

test('decodes the Linux hidraw device number without path assumptions', () => {
  assert.deepEqual(decodeLinuxDeviceNumber(61696), { major: 241, minor: 0 });
});

function snapshot({
  usb = [],
  hidraw = [],
  priorKind = 'missing',
  errors = [],
  lsusbMatches = [],
} = {}) {
  return {
    expectedSerial: 'serial',
    errors,
    lsusb: { observed: true, matches: lsusbMatches },
    usb,
    hidraw,
    priorPath: { stat: { kind: priorKind } },
  };
}

test('classifies only an exact linked USB/HID/character-node tuple as present', () => {
  const usb = [{ serialMatches: true, serial: 'serial' }];
  const hidraw = [
    {
      serialMatches: true,
      usbAncestor: { serial: 'serial' },
      nodeStable: true,
      nodeMatchesClass: true,
    },
  ];
  assert.equal(classifyHostSnapshot(snapshot({ usb, hidraw })), 'present');
  assert.equal(
    classifyHostSnapshot(snapshot({ usb, hidraw: [{ ...hidraw[0], nodeMatchesClass: false }] })),
    'transitional'
  );
});

test('does not collapse a hidden or stale device node into disconnect evidence', () => {
  assert.equal(classifyHostSnapshot(snapshot()), 'absent');
  assert.equal(classifyHostSnapshot(snapshot({ priorKind: 'value' })), 'transitional');
  assert.equal(
    classifyHostSnapshot(snapshot({ errors: [{ code: 'EACCES' }] })),
    'observation-error'
  );
});

test('requires lsusb to stop enumerating the target before classifying it as absent', () => {
  assert.equal(
    classifyHostSnapshot(
      snapshot({
        lsusbMatches: ['Bus 001 Device 002: ID 0fd9:0080 Elgato Systems GmbH Stream Deck MK.2'],
      })
    ),
    'transitional'
  );
  assert.equal(classifyHostSnapshot(snapshot({ lsusbMatches: [] })), 'absent');
});
