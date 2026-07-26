import assert from 'node:assert/strict';
import { test } from 'node:test';
import { acquisitionSignals, parseFdListing, parseProcessTable } from './acquisition-lib.mjs';

test('distinguishes discovered-but-denied from acquired-and-ready logs', () => {
  const serial = 'A00SA5492OQMLF';
  const denied = acquisitionSignals(
    `Error opening discovered surface streamdeck:${serial}: cannot open device with path /dev/hidraw0`,
    '/dev/hidraw0',
    serial
  );
  assert.equal(denied.serialDiscovered, true);
  assert.equal(denied.openFailed, true);
  assert.equal(denied.panelReady, false);

  const acquired = acquisitionSignals(
    [
      'StreamDeck firmware version: 1.02.000',
      `Opening surface panel: streamdeck:${serial} - Elgato Stream Deck MK.2`,
      `Surface panel ready: streamdeck:${serial}`,
    ].join('\n'),
    '/dev/hidraw0',
    serial
  );
  assert.equal(acquired.openFailed, false);
  assert.equal(acquired.firmware, '1.02.000');
  assert.equal(acquired.panelOpening, true);
  assert.equal(acquired.panelReady, true);
});

test('binds the surface process and its exact hidraw descriptor', () => {
  const processes = parseProcessTable(
    '56 1 1000 1000 node /app/node-runtimes/node22/bin/node /app/SurfaceThread.js'
  );
  assert.deepEqual(processes[0], {
    pid: 56,
    ppid: 1,
    uid: 1000,
    gid: 1000,
    command: 'node',
    args: '/app/node-runtimes/node22/bin/node /app/SurfaceThread.js',
  });
  const descriptors = parseFdListing(
    'lrwx------ 1 companion companion 64 Jul 25 19:41 20 -> /dev/hidraw0\n'
  );
  assert.deepEqual(descriptors, [{ descriptor: '20', target: '/dev/hidraw0' }]);
});
