import assert from 'node:assert/strict';
import { cp, mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { verifyLicensing } from './verify-licensing.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const requiredFiles = ['LICENSE', 'NOTICE', 'README.md', 'THIRD_PARTY_NOTICES.md', 'package.json'];

async function fixture() {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'overlaykit-companion-license-'));
  for (const relativePath of requiredFiles) {
    await cp(path.join(root, relativePath), path.join(directory, relativePath));
  }
  await cp(path.join(root, 'companion'), path.join(directory, 'companion'), { recursive: true });
  return directory;
}

describe('licensing verifier', () => {
  it('accepts the canonical legal surface', async () => {
    await assert.doesNotReject(verifyLicensing(root));
  });

  it('rejects missing Rodrigo Vicente attribution', async () => {
    const directory = await fixture();
    await writeFile(
      path.join(directory, 'NOTICE'),
      'OverlayKit Companion Module\nCopyright 2026 Unknown\n',
      'utf8'
    );
    await assert.rejects(verifyLicensing(directory), /Rodrigo Vicente/);
  });

  it('rejects a modified Apache license', async () => {
    const directory = await fixture();
    await writeFile(path.join(directory, 'LICENSE'), 'Apache-ish\n', 'utf8');
    await assert.rejects(verifyLicensing(directory), /official Apache-2.0 text/);
  });
});
