import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const APACHE_2_HASH = 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30';

async function text(root, relativePath) {
  return readFile(path.join(root, relativePath), 'utf8');
}

export async function verifyLicensing(root) {
  const manifest = JSON.parse(await text(root, 'package.json'));
  assert.equal(manifest.license, 'Apache-2.0', 'package.json must declare Apache-2.0');
  assert.deepEqual(manifest.author, {
    name: 'Rodrigo Vicente',
    url: 'https://x.com/rodrigoteamx',
  });

  const license = await text(root, 'LICENSE');
  const licenseHash = createHash('sha256').update(license).digest('hex');
  assert.equal(licenseHash, APACHE_2_HASH, 'LICENSE must match the official Apache-2.0 text');

  const notice = await text(root, 'NOTICE');
  assert.match(notice, /Copyright 2026 Rodrigo Vicente/);
  assert.match(notice, /https:\/\/x\.com\/rodrigoteamx/);
  assert.match(notice, /Copyright \(c\) 2022 Bitfocus AS - Open Source/);

  const thirdParty = await text(root, 'THIRD_PARTY_NOTICES.md');
  assert.match(thirdParty, /MIT License/);
  assert.match(thirdParty, /f2c31912a398f4b61706a7323ba7e1074cb56561/);
  assert.match(thirdParty, /Copyright \(c\) 2022 Bitfocus AS - Open Source/);

  const readme = await text(root, 'README.md');
  assert.match(readme, /Apache License 2\.0/);
  assert.match(readme, /https:\/\/x\.com\/rodrigoteamx/);

  return { licenseHash };
}

const isMain = import.meta.url === pathToFileURL(process.argv[1] ?? '').href;
if (isMain) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const result = await verifyLicensing(root);
  console.log(`licensing ok Apache-2.0 ${result.licenseHash}`);
}
