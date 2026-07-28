import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import Ajv2020 from 'ajv/dist/2020.js';
import {
  H050_PREDICATES,
  canonicalArtifact,
  createH050GitReader,
  sha256,
  verifyH050,
  verifyH050Safe,
} from './verify.mjs';

const docketBytes = readFileSync(new URL('./product-intent-docket.json', import.meta.url));
const docket = JSON.parse(docketBytes);
const subjectLock = JSON.parse(
  readFileSync(new URL('./subject-lock.json', import.meta.url), 'utf8')
);
const schema = JSON.parse(
  readFileSync(new URL('./schemas/product-intent-docket.schema.json', import.meta.url), 'utf8')
);

function bytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

function motion(productIntent, predicateIds = []) {
  return {
    schemaVersion: 'overlaykit-h050-human-product-intent-motion/v1',
    hypothesis: 'H-050',
    principal: '@rodrigoteamx',
    subjectCommit: '2810e63defe37025f575ebea37be7e1c5e97c18e',
    docketRawSha256: sha256(docketBytes),
    productIntent,
    predicateDecisions: predicateIds.map((id) => ({
      id,
      decision: 'selected',
      value: `human-selected product boundary for ${id}`,
    })),
    decisionsExplicitUnambiguousConflictFree: true,
    mechanismSelected: false,
    specificationAuthorized: false,
    adrAuthorized: false,
    implementationAuthorized: false,
    authority: 'none',
    action: null,
  };
}

function verifyMotion(value, options = {}) {
  const humanMotionBytes = options.rawBytes ?? canonicalArtifact(value);
  const nominatedMotionSha256 = options.nominatedSha256 ?? sha256(humanMotionBytes);
  return verifyH050({ humanMotionBytes, nominatedMotionSha256 });
}

test('strict schema admits only the exact pending non-normative docket', () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  const validate = ajv.compile(schema);
  assert.equal(validate(docket), true, JSON.stringify(validate.errors));

  for (const mutate of [
    (value) => (value.extra = true),
    (value) => (value.status = 'approved'),
    (value) => (value.normative = true),
    (value) => (value.predicates[0].decision = 'require-automatic'),
    (value) => value.predicates.reverse(),
    (value) => value.predicates.pop(),
    (value) => (value.humanDecision = { principal: '@rodrigoteamx' }),
    (value) => (value.authority = 'agent'),
    (value) => (value.action = { kind: 'implement' }),
  ]) {
    const hostile = structuredClone(docket);
    mutate(hostile);
    assert.equal(validate(hostile), false);
  }
});

test('canonical verification closes thirteen Git blobs and remains inconclusive', () => {
  const result = verifyH050();
  assert.equal(result.verified, true);
  assert.deepEqual(result.outcome, {
    status: 'inconclusive',
    stage: 'human-product-intent',
    reasonCode: 'exact-human-motion-absent',
  });
  assert.equal(result.subject.sourceCount, 13);
  assert.equal(
    result.subject.sourceSetSha256,
    'a9b0c3a354fbdea6867f4343d69a051763395a882ae2dea8c76ff8ff6c20732b'
  );
  assert.equal(result.docket.predicateCount, 9);
  assert.equal(result.docket.decidedPredicateCount, 0);
  assert.equal(result.docket.humanDecision, null);
  assert.deepEqual(result.capabilityAudit.commandCounts, {
    revParse: 2,
    lsTree: 1,
    catFile: 13,
  });
  assert.equal(result.capabilityAudit.network, false);
  assert.equal(result.capabilityAudit.liveHost, false);
  assert.equal(result.capabilityAudit.writes, false);
  assert.equal(result.authority, 'none');
  assert.equal(result.action, null);
});

test('source-lock or docket drift is invalid rather than inconclusive', () => {
  const changedLock = structuredClone(subjectLock);
  changedLock.sources[0].sha256 = '0'.repeat(64);
  const lockResult = verifyH050Safe({ subjectLockBytes: bytes(changedLock) });
  assert.equal(lockResult.verified, false);
  assert.equal(lockResult.outcome.status, 'invalid');

  const changedDocket = structuredClone(docket);
  changedDocket.predicates[0].question = 'agent-selected shortcut';
  const docketResult = verifyH050Safe({ docketBytes: bytes(changedDocket) });
  assert.equal(docketResult.verified, false);
  assert.equal(docketResult.outcome.status, 'invalid');

  const lockWhitespace = verifyH050Safe({
    subjectLockBytes: Buffer.concat([
      readFileSync(new URL('./subject-lock.json', import.meta.url)),
      Buffer.from(' '),
    ]),
  });
  assert.equal(lockWhitespace.outcome.status, 'invalid');

  const docketWhitespace = verifyH050Safe({
    docketBytes: Buffer.concat([docketBytes, Buffer.from(' ')]),
  });
  assert.equal(docketWhitespace.outcome.status, 'invalid');
});

test('docket authority, action, implementation, ADR, or SPEC overclaim is invalid', () => {
  for (const mutate of [
    (value) => (value.authority = 'agent'),
    (value) => (value.action = { kind: 'signal' }),
    (value) => (value.implementationAuthorized = true),
    (value) => (value.adrAuthorized = true),
    (value) => (value.specificationAuthorized = true),
  ]) {
    const hostile = structuredClone(docket);
    mutate(hostile);
    const result = verifyH050Safe({ docketBytes: bytes(hostile) });
    assert.equal(result.verified, false);
    assert.equal(result.outcome.status, 'invalid');
  }
});

test('require-automatic is supported only with an exact nine-of-nine human motion', () => {
  const complete = verifyMotion(motion('require-automatic', H050_PREDICATES));
  assert.equal(complete.verified, true);
  assert.deepEqual(complete.outcome, {
    status: 'supported',
    stage: 'closed-human-product-intent',
    reasonCode: 'human-require-automatic-nine-of-nine',
  });
  assert.equal(complete.humanMotion.selectedPredicateCount, 9);
  assert.equal(complete.authority, 'none');
  assert.equal(complete.action, null);

  const partial = verifyMotion(motion('require-automatic', H050_PREDICATES.slice(0, 8)));
  assert.equal(partial.verified, true);
  assert.equal(partial.outcome.status, 'inconclusive');
  assert.equal(partial.outcome.reasonCode, 'require-automatic-missing-predicate-decisions');
  assert.deepEqual(partial.outcome.missingPredicates, ['specificationRelationship']);
});

test('refutation requires an exact explicit no-obligation human motion', () => {
  const explicit = verifyMotion(motion('no-obligation'));
  assert.equal(explicit.verified, true);
  assert.deepEqual(explicit.outcome, {
    status: 'refuted',
    stage: 'closed-human-product-intent',
    reasonCode: 'human-explicitly-selected-no-obligation',
  });

  const contradictory = verifyMotion(motion('no-obligation', ['automaticRecoveryObligation']));
  assert.equal(contradictory.verified, true);
  assert.equal(contradictory.outcome.status, 'inconclusive');
  assert.equal(contradictory.outcome.reasonCode, 'human-motion-self-ambiguous');
});

test('missing, partial, or undecided human intent remains inconclusive', () => {
  const missingBytes = verifyH050({ nominatedMotionSha256: '0'.repeat(64) });
  assert.equal(missingBytes.outcome.status, 'inconclusive');
  assert.equal(missingBytes.outcome.reasonCode, 'exact-human-motion-incomplete');

  const missingNomination = verifyH050({
    humanMotionBytes: canonicalArtifact(motion('no-obligation')),
  });
  assert.equal(missingNomination.outcome.status, 'inconclusive');
  assert.equal(missingNomination.outcome.reasonCode, 'exact-human-motion-incomplete');

  const undecided = verifyMotion(motion('undecided'));
  assert.equal(undecided.outcome.status, 'inconclusive');
  assert.equal(undecided.outcome.reasonCode, 'human-product-intent-undecided');
});

test('motion digest drift, noncanonical bytes, duplicate decisions, and unknown IDs are invalid', () => {
  const valid = motion('require-automatic', H050_PREDICATES);
  const validBytes = canonicalArtifact(valid);
  const digestDrift = verifyMotion(valid, { nominatedSha256: '0'.repeat(64) });
  assert.equal(digestDrift.verified, false);
  assert.equal(digestDrift.outcome.status, 'invalid');
  assert.equal(digestDrift.outcome.reasonCode, 'human-motion-digest-mismatch');

  const noncanonical = verifyMotion(valid, {
    rawBytes: Buffer.from(`${JSON.stringify(valid, null, 2)}\n`, 'utf8'),
  });
  assert.equal(noncanonical.verified, false);
  assert.equal(noncanonical.outcome.status, 'invalid');
  assert.equal(noncanonical.outcome.reasonCode, 'human-motion-noncanonical');

  const duplicate = motion('require-automatic', H050_PREDICATES);
  duplicate.predicateDecisions[8].id = H050_PREDICATES[0];
  assert.equal(verifyMotion(duplicate).outcome.status, 'invalid');

  const unknown = motion('require-automatic', H050_PREDICATES);
  unknown.predicateDecisions[8].id = 'agentInventedPredicate';
  assert.equal(verifyMotion(unknown).outcome.status, 'invalid');

  assert.equal(sha256(validBytes), sha256(canonicalArtifact(valid)));
});

test('motion cannot smuggle authority, action, implementation, SPEC, or ADR authorization', () => {
  for (const mutate of [
    (value) => (value.authority = 'human'),
    (value) => (value.action = { kind: 'implement' }),
    (value) => (value.implementationAuthorized = true),
    (value) => (value.specificationAuthorized = true),
    (value) => (value.adrAuthorized = true),
    (value) => (value.mechanismSelected = true),
    (value) => (value.decisionsExplicitUnambiguousConflictFree = false),
  ]) {
    const hostile = motion('require-automatic', H050_PREDICATES);
    mutate(hostile);
    const result = verifyMotion(hostile);
    assert.equal(result.verified, false);
    assert.equal(result.outcome.status, 'invalid');
    assert.equal(
      [
        'authority-action-or-implementation-overclaim',
        'human-motion-decisions-not-explicit-unambiguous-conflict-free',
      ].includes(result.outcome.reasonCode),
      true
    );
  }
});

test('nominal predicate strings cannot manufacture nine-of-nine support', () => {
  const hostile = motion('require-automatic', H050_PREDICATES);
  hostile.predicateDecisions[0].value = 'x';
  const result = verifyMotion(hostile);
  assert.equal(result.verified, false);
  assert.equal(result.outcome.status, 'invalid');
  assert.match(result.outcome.detail, /nominal/u);
});

test('Git reader rejects every command outside the exact local object allowlist', () => {
  let spawnCount = 0;
  const reader = createH050GitReader({
    spawn(executable, args, options) {
      spawnCount += 1;
      assert.equal(executable, '/usr/bin/git');
      assert.equal(options.cwd.endsWith('companion-module-overlaykit-server'), true);
      assert.deepEqual(Object.keys(options.env).sort(), [
        'GIT_CONFIG_COUNT',
        'GIT_CONFIG_GLOBAL',
        'GIT_CONFIG_NOSYSTEM',
        'GIT_NO_LAZY_FETCH',
        'GIT_NO_REPLACE_OBJECTS',
        'GIT_OPTIONAL_LOCKS',
        'GIT_TERMINAL_PROMPT',
        'LANG',
        'LC_ALL',
        'PATH',
      ]);
      assert.deepEqual(args, ['rev-parse', '2810e63defe37025f575ebea37be7e1c5e97c18e^{commit}']);
      return {
        status: 0,
        stdout: Buffer.from('2810e63defe37025f575ebea37be7e1c5e97c18e\n'),
        stderr: Buffer.alloc(0),
        error: undefined,
      };
    },
  });
  assert.throws(() => reader.git(['status', '--short']), /not allowed/u);
  assert.equal(spawnCount, 0);
  reader.git(['rev-parse', '2810e63defe37025f575ebea37be7e1c5e97c18e^{commit}']);
  assert.equal(spawnCount, 1);
});

test('verifier is independent and contains no writer or alternate process executable', () => {
  const source = readFileSync(new URL('./verify.mjs', import.meta.url), 'utf8');
  assert.equal(/from ['"]\.\/(?:run|inventory-lib)\.mjs['"]/u.test(source), false);
  assert.equal(/\b(?:writeFile|mkdir|rm|chmod|rename|unlink)Sync\b/u.test(source), false);
  assert.deepEqual(
    [...source.matchAll(/const GIT_EXECUTABLE = '([^']+)'/gu)].map((match) => match[1]),
    ['/usr/bin/git']
  );
});
