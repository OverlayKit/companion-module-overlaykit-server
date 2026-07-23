import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const root = new URL('../', import.meta.url);
const lock = JSON.parse(await readFile(new URL('vendor/protocol-lock.json', root), 'utf8'));
const artifact = await readFile(new URL(`vendor/${lock.filename}`, root));

function digest(algorithm) {
  return createHash(algorithm).update(artifact).digest('hex');
}

const failures = [];
if (lock.schemaVersion !== 'overlaykit-protocol-artifact-lock/v1') {
  failures.push('protocol lock schema is invalid');
}
if (lock.package !== '@overlaykit/protocol' || lock.version !== '0.1.0') {
  failures.push('protocol package identity is invalid');
}
if (!/^[a-f0-9]{40}$/.test(lock.sourceCommit) || lock.sourceCommitVerified !== true) {
  failures.push('protocol source commit is not pinned and verified');
}
if (digest('sha256') !== lock.sha256) failures.push('protocol SHA-256 differs');
if (digest('sha512') !== lock.sha512) failures.push('protocol SHA-512 differs');
if (`sha512-${createHash('sha512').update(artifact).digest('base64')}` !== lock.npmIntegrity) {
  failures.push('protocol npm integrity differs');
}

if (failures.length > 0) {
  for (const failure of failures) process.stderr.write(`${failure}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`protocol artifact ok ${lock.sha256}\n`);
}
