import {
  chmodSync,
  cpSync,
  readFileSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { H049_REPOSITORY_ROOT, runH049 } from './run.mjs';
import { verifyH049 } from './verify.mjs';

const fixtureName = `verify-fixture-${process.pid}`;
const fixturePath = `artifacts/h049/${fixtureName}`;
const fixtureAbsolute = path.join(H049_REPOSITORY_ROOT, fixturePath);
const tamperPath = `artifacts/h049/${fixtureName}-tamper`;
const tamperAbsolute = path.join(H049_REPOSITORY_ROOT, tamperPath);

before(() => {
  rmSync(fixtureAbsolute, { recursive: true, force: true });
  rmSync(tamperAbsolute, { recursive: true, force: true });
  runH049(fixturePath);
});

after(() => {
  rmSync(fixtureAbsolute, { recursive: true, force: true });
  rmSync(tamperAbsolute, { recursive: true, force: true });
});

function resetTamper() {
  rmSync(tamperAbsolute, { recursive: true, force: true });
  cpSync(fixtureAbsolute, tamperAbsolute, { recursive: true });
  chmodSync(tamperAbsolute, 0o700);
}

describe('H-049 independent verifier', () => {
  test('independently verifies the canonical producer bundle', () => {
    const result = verifyH049(fixturePath);
    assert.equal(result.verification.verified, true);
    assert.equal(result.verification.outcome.status, 'inconclusive');
    assert.equal(result.verification.projectedOutcomeIfExactMapAccepted.status, 'refuted');
    assert.equal(
      result.verification.projectedOutcomeIfExactMapAccepted.condition,
      'only-after-exact-map-content-addressed-human-acceptance-and-zero-pending-judgments'
    );
    assert.equal(result.verification.summary.eligibleChains, 0);
    assert.equal(result.verification.review.status, 'agent-proposed-pending-human-acceptance');
    assert.equal(result.verification.review.humanAcceptanceRef, null);
    assert.equal(result.verification.review.pendingHumanJudgments, 9);
    assert.equal(result.verification.checks.exactPendingReviewMapPreserved, true);
    assert.equal(Object.hasOwn(result.verification.checks, 'noCartesianChainMixing'), false);
    assert.equal(result.verification.authority, 'none');
    assert.equal(result.verification.action, null);
  });

  test('rejects a changed candidate classification', () => {
    resetTamper();
    const target = path.join(tamperAbsolute, 'candidate-index.json');
    const value = JSON.parse(readFileSync(target, 'utf8'));
    value.candidates[0].predicates.physicalStreamDeckMk2Scope = true;
    writeFileSync(target, `${JSON.stringify(value)}\n`, { mode: 0o600 });
    chmodSync(target, 0o600);
    assert.throws(() => verifyH049(tamperPath), /candidate index bytes differ/u);
  });

  test('rejects a premature refuted run', () => {
    resetTamper();
    const target = path.join(tamperAbsolute, 'run.json');
    const value = JSON.parse(readFileSync(target, 'utf8'));
    value.outcome = value.projectedOutcomeIfExactMapAccepted;
    writeFileSync(target, `${JSON.stringify(value)}\n`, { mode: 0o600 });
    chmodSync(target, 0o600);
    assert.throws(() => verifyH049(tamperPath), /run bytes differ/u);
  });

  test('rejects a source-map byte mutation', () => {
    resetTamper();
    const target = path.join(tamperAbsolute, 'source-map.json');
    writeFileSync(target, Buffer.concat([readFileSync(target), Buffer.from(' ')]), { mode: 0o600 });
    chmodSync(target, 0o600);
    assert.throws(() => verifyH049(tamperPath), /source map bytes differ/u);
  });

  test('rejects a symlinked artifact', () => {
    resetTamper();
    const target = path.join(tamperAbsolute, 'run.json');
    const source = path.join(tamperAbsolute, 'source-map.json');
    unlinkSync(target);
    symlinkSync(source, target);
    assert.throws(() => verifyH049(tamperPath), /unsafe artifact run.json/u);
  });

  test('rejects an artifact with widened permissions', () => {
    resetTamper();
    const target = path.join(tamperAbsolute, 'run.json');
    chmodSync(target, 0o644);
    assert.throws(() => verifyH049(tamperPath), /unsafe artifact run.json/u);
  });

  test('rejects a run directory with widened permissions', () => {
    resetTamper();
    chmodSync(tamperAbsolute, 0o755);
    assert.throws(() => verifyH049(tamperPath), /unsafe run directory/u);
  });

  test('verifier imports neither producer nor classifier', () => {
    const source = readFileSync(new URL('./verify.mjs', import.meta.url), 'utf8');
    assert.equal(/from ['"]\.\/inventory-lib\.mjs['"]/u.test(source), false);
    assert.equal(/from ['"]\.\/run\.mjs['"]/u.test(source), false);
  });
});
