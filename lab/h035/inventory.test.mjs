import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  CLAIM_BOUNDARY,
  canonicalJson,
  classifyFuserResult,
  matchesTargetHid,
  parseFuserPids,
  parseHidId,
  parseProperties,
  sha256Canonical,
  stableDeviceSnapshot,
} from './inventory-lib.mjs';

test('parses and matches the exact MK.2 HID identity without assuming a hidraw index', () => {
  const properties = parseProperties(
    [
      'DRIVER=',
      'HID_ID=0003:00000FD9:00000080',
      'HID_NAME=Elgato Stream Deck MK.2',
      'HID_PHYS=usb-0000:00:14.0-1/input0',
    ].join('\n')
  );

  assert.deepEqual(parseHidId(properties.HID_ID), {
    bus: '0003',
    vendorId: '0fd9',
    productId: '0080',
  });
  assert.equal(matchesTargetHid(properties), true);
  assert.equal(matchesTargetHid({ ...properties, HID_ID: '0003:00000FD9:00000060' }), false);
});

test('canonical evidence hashes do not depend on object insertion order', () => {
  const left = { z: 1, a: { d: 4, b: 2 }, list: [{ y: 2, x: 1 }] };
  const right = { list: [{ x: 1, y: 2 }], a: { b: 2, d: 4 }, z: 1 };
  assert.equal(canonicalJson(left), canonicalJson(right));
  assert.equal(sha256Canonical(left), sha256Canonical(right));
});

test('fuser parsing distinguishes an observed empty set from owner pids', () => {
  assert.deepEqual(parseFuserPids('', ''), []);
  assert.deepEqual(
    parseFuserPids('/dev/hidraw0:  122 9\n', '                     USER PID ACCESS COMMAND\n'),
    [9, 122]
  );
});

test('fuser classification fails closed on usage output', () => {
  assert.deepEqual(
    classifyFuserResult({
      exitCode: 1,
      errorCode: null,
      stdout: '',
      stderr: 'No process specification given\nUsage: fuser [options] NAME...',
    }),
    { observed: false, usageError: true, pids: [] }
  );
  assert.deepEqual(
    classifyFuserResult({
      exitCode: 1,
      errorCode: null,
      stdout: '',
      stderr: '',
    }),
    { observed: true, usageError: false, pids: [] }
  );
});

test('stable snapshots intentionally exclude timestamps and volatile observations', () => {
  assert.deepEqual(
    stableDeviceSnapshot({
      mode: '0660',
      uid: 0,
      gid: 1002,
      rdev: 61696,
      ueventSha256: 'a'.repeat(64),
      ignored: 'value',
    }),
    {
      mode: '0660',
      uid: 0,
      gid: 1002,
      rdev: 61696,
      ueventSha256: 'a'.repeat(64),
    }
  );
});

test('claim boundary does not turn host access into a product or physical claim', () => {
  assert(CLAIM_BOUNDARY.proves.some((claim) => claim.includes('open capability')));
  assert(CLAIM_BOUNDARY.excludes.some((claim) => claim.includes('Companion acquisition')));
  assert(CLAIM_BOUNDARY.excludes.some((claim) => claim.includes('physical key')));
  assert(CLAIM_BOUNDARY.excludes.some((claim) => claim.includes('reconnect')));
});
