import assert from 'node:assert/strict';
import { readdir, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const FORBIDDEN_SOURCE_MARKERS = ['server/src', '/Users/rod/Web/overlaykit-oss', 'workspace:'];

async function filesUnder(directory) {
  const files = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await filesUnder(entryPath)));
    else files.push(entryPath);
  }
  return files;
}

export async function verifySourceBoundary(root) {
  const canonicalRoot = await realpath(root);
  const packageManifest = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
  const packageLock = JSON.parse(await readFile(path.join(root, 'package-lock.json'), 'utf8'));
  const protocolManifest = JSON.parse(
    await readFile(path.join(root, 'node_modules/@overlaykit/protocol/package.json'), 'utf8')
  );

  assert.equal(
    packageManifest.dependencies?.['@overlaykit/protocol'],
    'file:vendor/overlaykit-protocol-0.1.0.tgz',
    'protocol dependency must resolve from the committed exact tarball'
  );
  assert.equal(
    packageLock.packages?.['node_modules/@overlaykit/protocol']?.resolved,
    'file:vendor/overlaykit-protocol-0.1.0.tgz',
    'package lock must preserve the exact protocol tarball boundary'
  );

  const inspectedFiles = [
    path.join(root, 'package.json'),
    path.join(root, 'package-lock.json'),
    ...(await filesUnder(path.join(root, 'src'))),
    ...(await filesUnder(path.join(root, 'tests'))),
  ].filter((file) => /\.(?:json|mjs|ts)$/.test(file));

  for (const file of inspectedFiles) {
    const source = await readFile(file, 'utf8');
    for (const marker of FORBIDDEN_SOURCE_MARKERS) {
      assert.equal(
        source.includes(marker),
        false,
        `${path.relative(root, file)} contains forbidden source marker ${marker}`
      );
    }
  }

  const sourceFiles = (await filesUnder(path.join(root, 'src'))).filter((file) =>
    file.endsWith('.ts')
  );
  const protocolImports = new Set();
  for (const file of sourceFiles) {
    const source = await readFile(file, 'utf8');
    for (const match of source.matchAll(/(?:from\s+|import\s*\()\s*['"]([^'"]+)['"]/g)) {
      const specifier = match[1];
      if (specifier.startsWith('@overlaykit/protocol')) {
        protocolImports.add(specifier);
        const exportKey =
          specifier === '@overlaykit/protocol'
            ? '.'
            : `.${specifier.slice('@overlaykit/protocol'.length)}`;
        assert.ok(
          Object.hasOwn(protocolManifest.exports ?? {}, exportKey),
          `${specifier} is not a public @overlaykit/protocol export`
        );
      }
      if (specifier.startsWith('.')) {
        const target = path.resolve(path.dirname(file), specifier);
        assert.ok(
          target === canonicalRoot || target.startsWith(`${canonicalRoot}${path.sep}`),
          `${path.relative(root, file)} imports outside the repository`
        );
      }
      assert.equal(path.isAbsolute(specifier), false, `${specifier} is an absolute source import`);
    }
  }

  assert.ok(protocolImports.size > 0, 'module source must consume public protocol exports');
  return { protocolImports: [...protocolImports].sort() };
}

const isMain = import.meta.url === pathToFileURL(process.argv[1] ?? '').href;
if (isMain) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const result = await verifySourceBoundary(root);
  console.log(`source boundary ok ${result.protocolImports.length} public protocol exports`);
}
