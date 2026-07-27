import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import process from 'node:process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  OBSERVER_COMMAND_ENVIRONMENT_POLICY,
  OBSERVER_DOCKER_UNIX_HOST,
  OBSERVER_DOCKER_VERSION_FORMAT,
  createCommandAuditor,
} from '../h045/observer-lib.mjs';
import { h046CanonicalCommandEnvironment } from '../h045/run.mjs';

const RUN_SOURCE_PATH = fileURLToPath(new URL('../h045/run.mjs', import.meta.url));

function clock() {
  let wallMilliseconds = Date.parse('2026-07-27T18:00:00.000Z');
  let monotonicNanoseconds = 0n;
  return {
    wallNow() {
      const value = new Date(wallMilliseconds).toISOString();
      wallMilliseconds += 1;
      return value;
    },
    monotonicNowNs() {
      const value = monotonicNanoseconds;
      monotonicNanoseconds += 1_000_000n;
      return value;
    },
  };
}

test('H-046 supplies a fresh empty plain record instead of retaining the exotic host environment', () => {
  assert.notEqual(Object.getPrototypeOf(process.env), Object.prototype);
  assert.notEqual(Object.getPrototypeOf(process.env), null);

  const first = h046CanonicalCommandEnvironment();
  const second = h046CanonicalCommandEnvironment();
  assert.notEqual(first, second);
  assert.equal(Object.getPrototypeOf(first), Object.prototype);
  assert.equal(Object.getPrototypeOf(second), Object.prototype);
  assert.deepEqual(first, {});
  assert.deepEqual(second, {});
});

test('H-046 constructs the auditor without invoking a runner or reading host environment keys', () => {
  const clocks = clock();
  let runnerCalls = 0;
  const auditor = createCommandAuditor({
    runner: async () => {
      runnerCalls += 1;
      return { exitCode: 0, signal: null, stdout: '', stderr: '' };
    },
    wallNow: clocks.wallNow,
    monotonicNowNs: clocks.monotonicNowNs,
    environment: h046CanonicalCommandEnvironment(),
  });

  assert.equal(runnerCalls, 0);
  assert.deepEqual(auditor.snapshot().receipts, []);
  assert.deepEqual(auditor.snapshot().environmentPolicy, OBSERVER_COMMAND_ENVIRONMENT_POLICY);
});

test('H-046 still passes only the exact closed fixed child environment', async () => {
  const clocks = clock();
  let observedEnvironment = null;
  const auditor = createCommandAuditor({
    runner: async (_executable, _args, options) => {
      observedEnvironment = options.env;
      return {
        exitCode: 0,
        signal: null,
        stdout: JSON.stringify({
          Server: {
            Version: 'test',
            ApiVersion: 'test',
            Os: 'linux',
            Arch: 'amd64',
          },
        }),
        stderr: '',
      };
    },
    wallNow: clocks.wallNow,
    monotonicNowNs: clocks.monotonicNowNs,
    environment: h046CanonicalCommandEnvironment(),
  });

  await auditor.invoke('docker', [
    '--host',
    OBSERVER_DOCKER_UNIX_HOST,
    'version',
    '--format',
    OBSERVER_DOCKER_VERSION_FORMAT,
  ]);

  assert.deepEqual(observedEnvironment, OBSERVER_COMMAND_ENVIRONMENT_POLICY.fixed);
  assert.deepEqual(auditor.snapshot().environmentPolicy, {
    mode: 'closed-fixed',
    inheritedKeys: [],
    fixed: OBSERVER_COMMAND_ENVIRONMENT_POLICY.fixed,
  });
});

test('the canonical H-045 entry point is wired to the H-046 adapter without process.env copying', async () => {
  const source = await readFile(RUN_SOURCE_PATH, 'utf8');
  assert.match(source, /environment:\s*h046CanonicalCommandEnvironment\(\)/u);
  assert.doesNotMatch(source, /environment:\s*process\.env/u);
  assert.doesNotMatch(source, /environment:\s*\{\s*\.\.\.process\.env\s*\}/u);
});
