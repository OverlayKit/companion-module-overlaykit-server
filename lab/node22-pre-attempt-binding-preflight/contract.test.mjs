import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const LAB_ROOT = path.dirname(fileURLToPath(import.meta.url));
const SUBJECT_PATH = path.join(LAB_ROOT, 'subject-lock.json');
const STAGE0_PATH = path.join(LAB_ROOT, 'stage0.mjs');
const STAGE1_PATH = path.join(LAB_ROOT, 'stage1.mjs');
const VERIFIER_PATH = path.join(LAB_ROOT, 'verify.mjs');
const EXPECTED_ROSTER = Object.freeze([
  'lab/node22-pre-attempt-binding-preflight/contract.test.mjs',
  'lab/node22-pre-attempt-binding-preflight/fixtures/synthetic-precontract.mjs',
  'lab/node22-pre-attempt-binding-preflight/integration.test.mjs',
  'lab/node22-pre-attempt-binding-preflight/package.json',
  'lab/node22-pre-attempt-binding-preflight/stage0.mjs',
  'lab/node22-pre-attempt-binding-preflight/stage0.test.mjs',
  'lab/node22-pre-attempt-binding-preflight/stage1.mjs',
  'lab/node22-pre-attempt-binding-preflight/subject-lock.json',
  'lab/node22-pre-attempt-binding-preflight/verify.mjs',
  'lab/node22-pre-attempt-binding-preflight/verify.test.mjs',
]);

function source(filePath) {
  return readFileSync(filePath, 'utf8');
}

function staticImports(text) {
  return [
    ...text.matchAll(/^\s*import\s+(?:(?:[\w*{},\s]+)\s+from\s+)?['"]([^'"]+)['"]\s*;/gmu),
  ].map((match) => match[1]);
}

test('subject is source-only, unanchored, not executed and exactly bounded', () => {
  const subject = JSON.parse(source(SUBJECT_PATH));
  assert.equal(subject.predecessorAnchor.commit, '1121f1dd86114da8560f31122743ae20f8d53b03');
  assert.equal(subject.predecessorAnchor.tree, '52bf8023a628d85683417bf67c42d7b7effcd912');
  assert.equal(
    subject.apparatusAnchor.state,
    'source-defined-unanchored-pending-separate-git-transition'
  );
  for (const field of [
    'commit',
    'tree',
    'chg0042RawSha256',
    'manifestRawSha256',
    'manifestContentHash',
    'subjectRawSha256',
    'sourceSetSha256',
  ]) {
    assert.equal(subject.apparatusAnchor[field], null, field);
  }
  assert.equal(subject.apparatusAnchor.executionEligible, false);
  assert.equal(subject.hypothesisOutcome, 'not-executed');
  assert.equal(subject.execution.canonicalRun, null);
  assert.equal(subject.execution.rawEvidence, null);
  assert.deepEqual(subject.branchBoundary.branches, ['launch-failure']);
  assert.deepEqual(subject.controlBoundary.controls, ['partial-write']);
  assert.deepEqual(subject.sourceRoster, EXPECTED_ROSTER);
  assert.equal(subject.sourceRoster.length, 10);
  assert.equal(subject.authority, 'none');
  assert.equal(subject.action, null);
});

test('stage-0 has only node static imports and defers stage-1 dynamically', () => {
  const stage0 = source(STAGE0_PATH);
  assert.ok(staticImports(stage0).every((specifier) => specifier.startsWith('node:')));
  assert.equal(
    staticImports(stage0).some((specifier) => specifier.includes('stage1')),
    false
  );
  assert.match(stage0, /return import\('\.\/stage1\.mjs'\)/u);
  assert.match(stage0, /events = \['reservation-durable'\]/u);
  assert.match(stage0, /stage1 = await loadStage1\(\)/u);
  assert.ok(
    stage0.indexOf("events = ['reservation-durable']") <
      stage0.indexOf('stage1 = await loadStage1()')
  );
  assert.doesNotMatch(stage0, /process\.argv|isMainModule|artifacts\//u);
});

test('stage-1 is inert and the verifier shares no executable module', () => {
  const stage1 = source(STAGE1_PATH);
  const verifier = source(VERIFIER_PATH);
  assert.deepEqual(staticImports(stage1), []);
  assert.deepEqual(staticImports(verifier), ['node:crypto']);
  for (const forbidden of ['./stage0', './stage1', './fixtures/', 'process.argv', 'artifacts/']) {
    assert.equal(verifier.includes(forbidden), false, forbidden);
  }
  assert.match(stage1, /SYNTHETIC_STAGE1_LAUNCH_FAILED/u);
  assert.match(verifier, /verifyPartialWriteControl/u);
  assert.match(verifier, /verifyLaunchFailure/u);
});

test('the apparatus exposes no canonical runner or root script surface', () => {
  const packageDocument = JSON.parse(source(path.join(LAB_ROOT, 'package.json')));
  assert.deepEqual(Object.keys(packageDocument).sort(), ['name', 'private', 'type']);
  assert.equal(packageDocument.private, true);
  assert.equal(packageDocument.type, 'module');
  assert.equal(
    EXPECTED_ROSTER.some((locator) => locator.endsWith('/run.mjs')),
    false
  );
});
