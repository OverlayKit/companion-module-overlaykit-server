import assert from 'node:assert/strict';
import { test } from 'node:test';
import process from 'node:process';
import { command } from './util.mjs';

test('terminates a child command when its explicit deadline expires', async () => {
  await assert.rejects(
    command(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { timeoutMs: 50 }),
    /timed out after 50ms/u
  );
});
