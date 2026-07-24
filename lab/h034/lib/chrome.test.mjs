import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { access, mkdir, mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { test } from 'node:test';
import { removeChromeProfile, stopChrome } from './chrome.mjs';
import { waitFor } from './util.mjs';

test('removes Chrome profiles with bounded retries for transient Linux races', async () => {
  const calls = [];
  await removeChromeProfile('/tmp/h034-chrome-profile', {
    remove: async (profile, options) => {
      calls.push({ profile, options });
    },
    access: async () => {
      const error = new Error('missing');
      error.code = 'ENOENT';
      throw error;
    },
    settleMs: 0,
  });

  assert.deepEqual(calls, [
    {
      profile: '/tmp/h034-chrome-profile',
      options: {
        recursive: true,
        force: true,
        maxRetries: 5,
        retryDelay: 100,
      },
    },
  ]);
});

test(
  'stops the complete Chrome process group before removing its profile',
  { skip: process.platform === 'win32' },
  async () => {
    const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), 'h034-chrome-group-'));
    const profile = path.join(temporaryRoot, 'profile');
    const writer = [
      "const { mkdirSync, writeFileSync } = require('node:fs');",
      `const profile = ${JSON.stringify(profile)};`,
      'setInterval(() => {',
      '  mkdirSync(profile, { recursive: true });',
      "  writeFileSync(profile + '/descendant.txt', 'alive');",
      '}, 10);',
    ].join('\n');
    const parent = [
      "const { spawn } = require('node:child_process');",
      `spawn(process.execPath, ['-e', ${JSON.stringify(writer)}], { stdio: 'ignore' });`,
      'setInterval(() => {}, 1000);',
    ].join('\n');
    const child = spawn(process.execPath, ['-e', parent], {
      detached: true,
      stdio: 'ignore',
    });

    try {
      await waitFor(
        async () => {
          try {
            await access(path.join(profile, 'descendant.txt'));
            return true;
          } catch {
            return false;
          }
        },
        { timeoutMs: 2_000, message: 'Chrome descendant fixture did not start' }
      );
      await stopChrome(child, 1_000);
      await removeChromeProfile(profile, { settleMs: 100 });
      await assert.rejects(access(profile), { code: 'ENOENT' });
    } finally {
      try {
        process.kill(-child.pid, 'SIGKILL');
      } catch (error) {
        if (error?.code !== 'ESRCH') throw error;
      }
      await rm(temporaryRoot, { recursive: true, force: true });
    }
  }
);
