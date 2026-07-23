import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const packageDirectory = new URL('../pkg/', import.meta.url);
const entries = await readdir(packageDirectory);
const archives = entries.filter((entry) => entry.endsWith('.tgz') || entry.endsWith('.tar.gz'));

if (archives.length !== 1) {
  throw new Error(`Expected one Companion package archive, received ${archives.length}`);
}

const archive = new URL(archives[0], packageDirectory);
if ((await stat(archive)).size === 0) throw new Error('Companion package archive is empty');
const archivePath = fileURLToPath(archive);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const manifest = JSON.parse(
  await readFile(new URL('../companion/manifest.json', import.meta.url), 'utf8')
);
if (
  manifest.id !== 'overlaykit-server' ||
  manifest.license !== 'Apache-2.0' ||
  manifest.runtime?.type !== 'node22' ||
  manifest.runtime?.apiVersion !== '2.0.0'
) {
  throw new Error('Companion manifest does not match the approved module boundary');
}

const archiveEntries = execFileSync('tar', ['-tzf', archivePath], { encoding: 'utf8' })
  .trim()
  .split('\n');
for (const entry of archiveEntries) {
  assert.ok(entry.startsWith('overlaykit-server/'), `unexpected archive prefix ${entry}`);
  assert.equal(entry.includes('..'), false, `archive path traversal ${entry}`);
  assert.equal(entry.includes('node_modules'), false, `raw node_modules leaked into ${entry}`);
  assert.equal(entry.endsWith('.map'), false, `source map leaked into ${entry}`);
}

const requiredEntries = [
  'overlaykit-server/companion/HELP.md',
  'overlaykit-server/companion/LICENSE',
  'overlaykit-server/companion/NOTICE',
  'overlaykit-server/companion/THIRD_PARTY_NOTICES.md',
  'overlaykit-server/companion/manifest.json',
  'overlaykit-server/main.js',
  'overlaykit-server/package.json',
];
for (const entry of requiredEntries) {
  assert.ok(archiveEntries.includes(entry), `module archive is missing ${entry}`);
}

function archiveText(relativePath) {
  return execFileSync('tar', ['-xOzf', archivePath, `overlaykit-server/${relativePath}`], {
    encoding: 'utf8',
    maxBuffer: 2 * 1024 * 1024,
  });
}

const packedManifest = JSON.parse(archiveText('package.json'));
assert.equal(packedManifest.license, 'Apache-2.0');
assert.deepEqual(packedManifest.dependencies, {});

for (const file of ['LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md']) {
  assert.equal(
    archiveText(`companion/${file}`),
    await readFile(path.join(root, file), 'utf8'),
    `${file} in the module archive must match the repository legal surface`
  );
}

const main = archiveText('main.js');
assert.ok(main.length > 0, 'compiled module entrypoint is empty');
for (const marker of ['server/src', '/Users/rod/Web/', 'workspace:', 'vendor/']) {
  assert.equal(main.includes(marker), false, `compiled module leaked forbidden marker ${marker}`);
}

const digest = createHash('sha256')
  .update(await readFile(archive))
  .digest('hex');
process.stdout.write(`module package ok ${archives[0]} sha256=${digest}\n`);
