import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import { SOURCE_SET_PATHS } from './run.mjs';

const LAB_ROOT = path.dirname(fileURLToPath(import.meta.url));
const SUBJECT_PATH = path.join(LAB_ROOT, 'subject-lock.json');
const PRODUCER_PATH = path.join(LAB_ROOT, 'producer.mjs');
const VERIFIER_PATH = path.join(LAB_ROOT, 'verify.mjs');
const FIXTURE_PATH = path.join(LAB_ROOT, 'fixtures/synthetic-terminal-cases.mjs');
const RUN_PATH = path.join(LAB_ROOT, 'run.mjs');

function source(filePath) {
  return readFileSync(filePath, 'utf8');
}

function rawSha256(filePath) {
  return createHash('sha256').update(readFileSync(filePath)).digest('hex');
}

function importsOf(text) {
  return [...text.matchAll(/^\s*import\s+.+?\s+from\s+['"]([^'"]+)['"];?\s*$/gm)].map(
    (match) => match[1]
  );
}

test('subject pins the accepted boundary, exact partition, modes and exclusions', () => {
  const subject = JSON.parse(source(SUBJECT_PATH));
  assert.equal(
    rawSha256(SUBJECT_PATH),
    '32faedd0bf9202190ee9fdbae0c84baff05764dd637dcf4b2dfd6d4487aca144'
  );
  assert.deepEqual(subject.sourceAnchor.mainCommit, 'd1caa3bff1b47b61c661e4ec4582add4f9c795c3');
  assert.deepEqual(subject.sourceAnchor.mainTree, 'd83fa14a3c25189260921a0c08862e6540a52baf');
  assert.deepEqual(subject.terminalPartition.precedence, [
    'launch-failure',
    'malformed-output',
    'divergent-attempts',
    'exact-incompatibility',
    'success',
  ]);
  assert.equal(subject.persistencePolicy.reservationBeforeAttempt, true);
  assert.equal(subject.persistencePolicy.exclusiveCreate, true);
  assert.equal(subject.persistencePolicy.directoryMode, '0700');
  assert.equal(subject.persistencePolicy.fileMode, '0600');
  assert.equal(subject.authority, 'none');
  assert.equal(subject.action, null);
  assert.equal(subject.h055Opened, false);
  assert.match(subject.prohibited.join('\n'), /commit, push, merge, or publication/u);
});

test('producer, fixture and verifier have no real-source or network capability', () => {
  const modules = [
    ['fixture', source(FIXTURE_PATH)],
    ['producer', source(PRODUCER_PATH)],
    ['verifier', source(VERIFIER_PATH)],
  ];
  const forbidden = [
    'node:child_process',
    'node:http',
    'node:https',
    'node:net',
    'node:dgram',
    'fetch(',
    '/usr/bin',
    '/lib64',
    'node_modules/',
    'hidraw',
    'docker',
  ];
  for (const [name, text] of modules) {
    for (const token of forbidden) {
      assert.equal(text.toLowerCase().includes(token), false, `${name}:${token}`);
    }
  }
});

test('verifier imports neither producer, fixture nor runner', () => {
  const imports = importsOf(source(VERIFIER_PATH));
  assert.ok(imports.every((specifier) => specifier.startsWith('node:')));
  assert.equal(
    imports.some((specifier) => specifier.includes('producer')),
    false
  );
  assert.equal(
    imports.some((specifier) => specifier.includes('fixture')),
    false
  );
  assert.equal(
    imports.some((specifier) => specifier.includes('run')),
    false
  );
});

test('runner exposes only the fixed ignored evidence root to its CLI', () => {
  const run = source(RUN_PATH);
  assert.match(run, /artifacts\/node22-failure-preservation-preflight/u);
  assert.match(run, /args\.length !== 1 \|\| args\[0\] !== '--write'/u);
  assert.doesNotMatch(run, /--output/u);
  assert.match(run, /onReservationDurable/u);
  assert.ok(
    SOURCE_SET_PATHS.every((locator) =>
      locator.startsWith('lab/node22-failure-preservation-preflight/')
    )
  );
  assert.equal(new Set(SOURCE_SET_PATHS).size, SOURCE_SET_PATHS.length);
});
