import { readFileSync } from 'node:fs';
import { before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import Ajv2020 from 'ajv/dist/2020.js';
import { buildH049Bundle } from './run.mjs';

let validate;
let canonicalRun;

before(() => {
  const schema = JSON.parse(
    readFileSync(
      new URL('./schemas/normative-recovery-obligation-run.schema.json', import.meta.url),
      'utf8'
    )
  );
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  validate = ajv.compile(schema);
  canonicalRun = buildH049Bundle().documents.run;
});

function clone() {
  return structuredClone(canonicalRun);
}

describe('H-049 run schema', () => {
  test('admits the canonical run', () => {
    assert.equal(validate(canonicalRun), true, JSON.stringify(validate.errors));
  });

  for (const [name, mutate] of [
    ['additional property', (run) => (run.extra = true)],
    ['different subject', (run) => (run.subject.commit = '0'.repeat(40))],
    ['missing clause', (run) => (run.summary.clauses = 900)],
    ['premature refutation', (run) => (run.outcome.status = 'refuted')],
    ['action authority', (run) => (run.action = { kind: 'restart' })],
    ['agent authority', (run) => (run.authority = 'agent')],
    ['hidden pending judgment', (run) => (run.summary.pendingHumanJudgments = 8)],
    [
      'weakened projected-outcome condition',
      (run) => (run.projectedOutcomeIfExactMapAccepted.condition = 'after-human-acceptance'),
    ],
    ['changed review hash', (run) => (run.harness.reviewMapRawSha256 = '0'.repeat(64))],
    ['capability omission', (run) => run.capabilityAudit.prohibitedCapabilities.pop()],
  ]) {
    test(`rejects ${name}`, () => {
      const run = clone();
      mutate(run);
      assert.equal(validate(run), false);
    });
  }
});
