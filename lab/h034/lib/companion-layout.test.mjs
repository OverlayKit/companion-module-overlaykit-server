import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { test } from 'node:test';

const execFileAsync = promisify(execFile);
const installer = fileURLToPath(new URL('../install-companion-module.sh', import.meta.url));

test('installs the package using Companion 4 packaged-development layout', async () => {
  const temporaryRoot = await mkdtemp(path.join(tmpdir(), 'overlaykit-h034-layout-'));
  const archiveRoot = path.join(temporaryRoot, 'archive', 'overlaykit-server');
  const archive = path.join(temporaryRoot, 'module.tgz');
  const moduleRoot = path.join(temporaryRoot, 'module-local-dev', 'overlaykit-server');

  try {
    await mkdir(path.join(archiveRoot, 'companion'), { recursive: true });
    await writeFile(path.join(archiveRoot, 'companion', 'manifest.json'), '{}\n');
    await writeFile(path.join(archiveRoot, 'main.js'), 'export {};\n');
    await execFileAsync('tar', [
      '-czf',
      archive,
      '-C',
      path.dirname(archiveRoot),
      'overlaykit-server',
    ]);

    await execFileAsync(installer, [archive, moduleRoot]);

    assert.equal(await readFile(path.join(moduleRoot, 'DEBUG-PACKAGED'), 'utf8'), '');
    assert.equal(
      await readFile(path.join(moduleRoot, 'pkg', 'companion', 'manifest.json'), 'utf8'),
      '{}\n'
    );
    assert.equal(await readFile(path.join(moduleRoot, 'pkg', 'main.js'), 'utf8'), 'export {};\n');
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});
