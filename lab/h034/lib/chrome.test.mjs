import assert from 'node:assert/strict';
import { test } from 'node:test';
import { removeChromeProfile } from './chrome.mjs';

test('removes Chrome profiles with bounded retries for transient Linux races', async () => {
  const calls = [];
  await removeChromeProfile('/tmp/h034-chrome-profile', async (profile, options) => {
    calls.push({ profile, options });
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
