import assert from 'node:assert/strict';
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { buildH054Evidence, encodeH054Evidence } from './inventory-lib.mjs';
import { preserveH054Evidence } from './run.mjs';

const TEMPORARY_PREFIX = path.join(os.tmpdir(), 'overlaykit-h054-writer-test-');

let cachedRun;

function h054Run() {
  cachedRun ??= buildH054Evidence();
  return cachedRun;
}

function temporaryEvidencePaths(t) {
  const repositoryRoot = mkdtempSync(TEMPORARY_PREFIX);
  chmodSync(repositoryRoot, 0o700);
  t.after(() => {
    assert.ok(repositoryRoot.startsWith(TEMPORARY_PREFIX));
    rmSync(repositoryRoot, { recursive: true, force: true });
  });
  const artifactsRoot = path.join(repositoryRoot, 'artifacts');
  mkdirSync(artifactsRoot, { mode: 0o700 });
  return {
    repositoryRoot,
    artifactsRoot,
    h054Root: path.join(artifactsRoot, 'h054'),
    runsRoot: path.join(artifactsRoot, 'h054', 'runs'),
  };
}

function mode(metadata) {
  return metadata.mode & 0o777;
}

test('the injected writer creates canonical evidence with 0700/0600 and one link', (t) => {
  const evidencePaths = temporaryEvidencePaths(t);
  const run = h054Run();
  const receipt = preserveH054Evidence(run, evidencePaths);
  const runPath = path.join(evidencePaths.repositoryRoot, receipt.path);
  const runDirectory = path.dirname(runPath);

  assert.equal(receipt.semanticSha256, run.semanticSha256);
  assert.equal(receipt.creation, 'exclusive');
  assert.equal(receipt.directoryMode, '0700');
  assert.equal(receipt.fileMode, '0600');
  assert.equal(receipt.authority, 'none');
  assert.equal(receipt.action, null);
  assert.equal(mode(statSync(evidencePaths.h054Root)), 0o700);
  assert.equal(mode(statSync(evidencePaths.runsRoot)), 0o700);
  assert.equal(mode(statSync(runDirectory)), 0o700);
  assert.equal(mode(statSync(runPath)), 0o600);
  assert.equal(statSync(runPath).nlink, 1);
  assert.ok(readFileSync(runPath).equals(encodeH054Evidence(run)));
});

test('O_EXCL semantics refuse a second write without changing the first evidence', (t) => {
  const evidencePaths = temporaryEvidencePaths(t);
  const run = h054Run();
  const first = preserveH054Evidence(run, evidencePaths);
  const runPath = path.join(evidencePaths.repositoryRoot, first.path);
  const original = readFileSync(runPath);

  assert.throws(
    () => preserveH054Evidence(run, evidencePaths),
    (error) => {
      assert.equal(error?.code, 'EEXIST');
      return true;
    }
  );
  assert.ok(readFileSync(runPath).equals(original));
  assert.equal(mode(statSync(runPath)), 0o600);
  assert.equal(statSync(runPath).nlink, 1);
});

test('O_NOFOLLOW boundary refuses a symlink ancestor before writing outside it', (t) => {
  const evidencePaths = temporaryEvidencePaths(t);
  const outside = path.join(evidencePaths.repositoryRoot, 'outside');
  mkdirSync(outside, { mode: 0o700 });
  symlinkSync(outside, evidencePaths.h054Root);

  assert.throws(
    () => preserveH054Evidence(h054Run(), evidencePaths),
    /H054_WRITE_REFUSED: unsafe directory/u
  );
  assert.ok(lstatSync(evidencePaths.h054Root).isSymbolicLink());
  assert.deepEqual(readdirSync(outside), []);
});

test('writer source retains O_EXCL, O_NOFOLLOW, and a fixed-path CLI call', () => {
  const source = readFileSync(new URL('./run.mjs', import.meta.url), 'utf8');
  assert.match(source, /constants\.O_EXCL/u);
  assert.match(source, /constants\.O_NOFOLLOW/u);
  assert.match(source, /preserveH054Evidence\(run\)/u);
  assert.doesNotMatch(source, /process\.argv.*evidencePaths/u);
});
