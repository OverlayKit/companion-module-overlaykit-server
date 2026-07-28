import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  H054_EVIDENCE_PATHS,
  buildH054Evidence,
  encodeH054Evidence,
  sha256,
  validateH054RunIdentity,
} from './inventory-lib.mjs';

function assertion(condition, message) {
  if (!condition) {
    throw new Error(`H054_WRITE_REFUSED: ${message}`);
  }
}

function containedRelative(parent, target) {
  const relative = path.relative(path.resolve(parent), path.resolve(target));
  assertion(
    relative !== '' &&
      relative !== '..' &&
      !relative.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(relative),
    `path escapes fixed evidence root: ${target}`
  );
  return relative;
}

function assertDirectory(directory, expectedMode, containmentRoot = null) {
  const metadata = lstatSync(directory);
  assertion(metadata.isDirectory() && !metadata.isSymbolicLink(), `unsafe directory ${directory}`);
  assertion(
    expectedMode === null || (metadata.mode & 0o777) === expectedMode,
    `directory mode drift at ${directory}`
  );
  if (containmentRoot !== null) {
    const realRoot = realpathSync(containmentRoot);
    const realDirectory = realpathSync(directory);
    if (realDirectory !== realRoot) {
      containedRelative(realRoot, realDirectory);
    }
  }
  return metadata;
}

function assertNoSymlinkComponents(root, target) {
  const absoluteRoot = path.resolve(root);
  const absoluteTarget = path.resolve(target);
  const relative = containedRelative(absoluteRoot, absoluteTarget);
  let current = absoluteRoot;
  for (const component of relative.split(path.sep)) {
    current = path.join(current, component);
    const metadata = lstatSync(current);
    assertion(!metadata.isSymbolicLink(), `symlink path component ${current}`);
  }
}

function createExclusiveDirectory(directory, expectedMode, containmentRoot) {
  mkdirSync(directory, { mode: expectedMode });
  const metadata = assertDirectory(directory, expectedMode, containmentRoot);
  assertion(metadata.nlink >= 1, `unsafe directory link count at ${directory}`);
  assertNoSymlinkComponents(containmentRoot, directory);
}

function createOrInspectPrivateDirectory(directory, containmentRoot) {
  try {
    createExclusiveDirectory(directory, 0o700, containmentRoot);
    return { created: true };
  } catch (error) {
    if (error?.code !== 'EEXIST') {
      throw error;
    }
    const metadata = assertDirectory(directory, 0o700, containmentRoot);
    assertion(metadata.nlink >= 1, `unsafe directory link count at ${directory}`);
    assertNoSymlinkComponents(containmentRoot, directory);
    return { created: false };
  }
}

function inspectRawFile(filePath, evidenceRoot) {
  assertNoSymlinkComponents(evidenceRoot, filePath);
  const descriptor = openSync(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const metadata = fstatSync(descriptor);
    const pathnameMetadata = lstatSync(filePath);
    assertion(
      metadata.isFile() &&
        pathnameMetadata.isFile() &&
        !pathnameMetadata.isSymbolicLink() &&
        metadata.nlink === 1 &&
        pathnameMetadata.nlink === 1 &&
        metadata.dev === pathnameMetadata.dev &&
        metadata.ino === pathnameMetadata.ino,
      `unsafe evidence file ${filePath}`
    );
    assertion((metadata.mode & 0o777) === 0o600, `file mode drift at ${filePath}`);
    const bytes = readFileSync(descriptor);
    assertion(bytes.length === metadata.size, `file changed while read ${filePath}`);
    return { bytes, metadata };
  } finally {
    closeSync(descriptor);
  }
}

function writeExclusiveRawFile(filePath, bytes, evidenceRoot) {
  const descriptor = openSync(
    filePath,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    0o600
  );
  try {
    writeFileSync(descriptor, bytes);
    const metadata = fstatSync(descriptor);
    assertion(
      metadata.isFile() && metadata.nlink === 1 && (metadata.mode & 0o777) === 0o600,
      `unsafe evidence file after write ${filePath}`
    );
  } finally {
    closeSync(descriptor);
  }
  const observed = inspectRawFile(filePath, evidenceRoot);
  assertion(observed.bytes.equals(bytes), `raw evidence differs after write ${filePath}`);
}

export function preserveH054Evidence(
  run = buildH054Evidence(),
  evidencePaths = H054_EVIDENCE_PATHS
) {
  const semanticSha256 = validateH054RunIdentity(run);
  const bytes = encodeH054Evidence(run);
  const repositoryRoot = realpathSync(evidencePaths.repositoryRoot);
  const artifactsRoot = evidencePaths.artifactsRoot;
  assertDirectory(artifactsRoot, null, repositoryRoot);
  assertNoSymlinkComponents(repositoryRoot, artifactsRoot);

  createOrInspectPrivateDirectory(evidencePaths.h054Root, artifactsRoot);
  createOrInspectPrivateDirectory(evidencePaths.runsRoot, evidencePaths.h054Root);

  const runDirectory = path.join(evidencePaths.runsRoot, semanticSha256);
  containedRelative(evidencePaths.runsRoot, runDirectory);
  createExclusiveDirectory(runDirectory, 0o700, evidencePaths.runsRoot);

  const runPath = path.join(runDirectory, 'run.json');
  containedRelative(runDirectory, runPath);
  writeExclusiveRawFile(runPath, bytes, evidencePaths.runsRoot);

  return {
    runId: run.runId,
    semanticSha256,
    rawSha256: sha256(bytes),
    byteLength: bytes.length,
    path: path.relative(repositoryRoot, runPath),
    creation: 'exclusive',
    directoryMode: '0700',
    fileMode: '0600',
    authority: 'none',
    action: null,
  };
}

function main() {
  const args = process.argv.slice(2);
  assertion(
    args.length === 0 || (args.length === 1 && args[0] === '--write'),
    'usage: node lab/h054/run.mjs [--write]'
  );
  const run = buildH054Evidence();
  if (args[0] === '--write') {
    process.stdout.write(`${JSON.stringify(preserveH054Evidence(run))}\n`);
    return;
  }
  process.stdout.write(encodeH054Evidence(run));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
