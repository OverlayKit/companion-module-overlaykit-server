import assert from 'node:assert/strict';
import { test } from 'node:test';
import { executeSignal, parseExpectedTarget, parseProcStat, sameTarget } from './signal-helper.mjs';

function target() {
  return {
    pid: 73,
    startTicks: 130,
    ppid: 1,
    parentStartTicks: 100,
    uid: 1000,
    gid: 1000,
    groups: [1000, 1002],
    cmdline: [
      '/app/node-runtimes/node22/bin/node',
      '--enable-source-maps',
      '/app/SurfaceThread.js',
    ],
    cgroup: '0::/',
    pidNamespace: 'pid:[1]',
    mountNamespace: 'mnt:[2]',
  };
}

function environment(value = target()) {
  return { H042_EXPECTED_TARGET: JSON.stringify(value), H042_DEVICE_GID: '1002' };
}

test('parses proc stat field 22 without confusing spaces in comm', () => {
  const fields = ['1', ...Array.from({ length: 17 }, () => '0'), '123', '0'];
  assert.deepEqual(parseProcStat(`73 (Surface Thread) S ${fields.join(' ')}`), {
    pid: 73,
    ppid: 1,
    startTicks: 123,
  });
});

test('requires the exact target envelope and dynamic device group', () => {
  assert.deepEqual(parseExpectedTarget(environment()), target());
  assert.throws(() => parseExpectedTarget(environment({ ...target(), pid: 1 })));
  assert.throws(() => parseExpectedTarget({ ...environment(), H042_DEVICE_GID: '1003' }));
});

test('revalidates once and invokes exactly one SIGTERM', () => {
  const calls = [];
  const expected = target();
  const receipt = executeSignal({
    environment: environment(expected),
    observe: () => ({
      ...expected,
      targetHidrawDescriptors: [],
      revalidation: {
        initial: { pid: 73, startTicks: 130 },
        final: { pid: 73, startTicks: 130 },
      },
    }),
    kill: (...args) => calls.push(args),
    now: (() => {
      const values = ['2026-07-26T00:00:30.000Z', '2026-07-26T00:00:30.001Z'];
      return () => values.shift();
    })(),
    monotonic: (() => {
      const values = ['1000', '2000'];
      return () => values.shift();
    })(),
  });
  assert.deepEqual(calls, [[73, 'SIGTERM']]);
  assert.equal(receipt.processKillCallCount, 1);
  assert.equal(receipt.receivedMonotonicNs, '2000');
  assert.equal(sameTarget(receipt.expected, receipt.observed), true);
});

test('refuses stale tuples and a regained hidraw descriptor without signaling', () => {
  let calls = 0;
  assert.throws(() =>
    executeSignal({
      environment: environment(),
      observe: () => ({ ...target(), startTicks: 131, targetHidrawDescriptors: [] }),
      kill: () => {
        calls += 1;
      },
    })
  );
  assert.throws(() =>
    executeSignal({
      environment: environment(),
      observe: () => ({
        ...target(),
        targetHidrawDescriptors: [{ descriptor: '20', target: '/host-dev/hidraw0' }],
      }),
      kill: () => {
        calls += 1;
      },
    })
  );
  assert.equal(calls, 0);
});
