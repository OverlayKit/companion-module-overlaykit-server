import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

import {
  fixtureCanonicalHash,
  makeCandidateExpectation,
  makeExpectedEvidence,
  makeObservationSnapshot,
} from './fixtures/synthetic-boundary.mjs';

const LAB_ROOT = dirname(fileURLToPath(import.meta.url));
const SUBJECT_PATH = join(LAB_ROOT, 'subject-lock.json');
const FIXTURE_PATH = join(LAB_ROOT, 'fixtures', 'synthetic-boundary.mjs');
const PRODUCER_PATH = join(LAB_ROOT, 'producer.mjs');
const VERIFIER_PATH = join(LAB_ROOT, 'verify.mjs');

function rawSha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function source(path) {
  return readFileSync(path, 'utf8');
}

function importsOf(text) {
  return [...text.matchAll(/^\s*import\s+.+?\s+from\s+['"]([^'"]+)['"];?\s*$/gm)].map(
    (match) => match[1]
  );
}

test('subject binds the exact predecessor and synthetic topology without claiming execution', () => {
  const subject = JSON.parse(source(SUBJECT_PATH));

  assert.deepEqual(subject.predecessorAnchor, {
    commit: 'd63172f80c9a4a5ec4b27363e0ec4f956c1badcf',
    tree: '0f2cfb6eac7c359e900efc467e2fb7c3407f93bd',
  });
  assert.equal(
    subject.discoveryDocket.sha256,
    '91f486bd1de994ace58e12f6df61c29a4ee4efd325dd9a6c84043bddebf3523e'
  );
  assert.equal(subject.discoveryDocket.bytesMaterialized, false);
  assert.equal(
    subject.apparatusAnchor.state,
    'source-defined-unanchored-pending-separate-git-transition'
  );
  assert.equal(subject.apparatusAnchor.realSourceUseEligible, false);
  assert.equal(subject.syntheticOnly, true);
  assert.equal(subject.realSourceClosureClaim, false);
  assert.equal(subject.hypothesisOutcome, 'not-executed');
  assert.equal(subject.authority, 'none');
  assert.equal(subject.action, null);
  assert.deepEqual(
    {
      descriptors: subject.exactTopology.descriptors,
      directories: subject.exactTopology.directories,
      indirections: subject.exactTopology.indirectionOccurrences,
      layers: subject.exactTopology.layers,
      mounts: subject.exactTopology.mounts,
      regularFiles: subject.exactTopology.regularFiles,
    },
    {
      descriptors: 687,
      directories: 74,
      indirections: 26,
      layers: 25,
      mounts: 25,
      regularFiles: 613,
    }
  );
  assert.equal(subject.exactTopology.sharedPrefixOccurrences, 15);
  assert.equal(subject.exactTopology.uniqueTerminalOccurrences, 11);
});

test('subject content-addresses the fixture, producer, verifier, expectation, and baseline', () => {
  const subject = JSON.parse(source(SUBJECT_PATH));

  assert.equal(subject.apparatusBindings.fixtureModule.rawSha256, rawSha256(FIXTURE_PATH));
  assert.equal(subject.apparatusBindings.producer.rawSha256, rawSha256(PRODUCER_PATH));
  assert.equal(subject.apparatusBindings.verifier.rawSha256, rawSha256(VERIFIER_PATH));
  assert.equal(
    subject.apparatusBindings.candidateExpectationCanonicalSha256,
    fixtureCanonicalHash(makeCandidateExpectation())
  );
  assert.equal(
    subject.apparatusBindings.syntheticObservationCanonicalSha256,
    fixtureCanonicalHash(makeObservationSnapshot())
  );
  assert.equal(
    subject.apparatusBindings.baselineEvidenceSemanticSha256,
    makeExpectedEvidence().semanticSha256
  );
});

test('core modules have no filesystem, process, network, raw, or automatic-main surface', () => {
  const core = [
    ['fixture', source(FIXTURE_PATH)],
    ['producer', source(PRODUCER_PATH)],
    ['verifier', source(VERIFIER_PATH)],
  ];
  const forbidden = [
    'node:fs',
    'node:child_process',
    'node:http',
    'node:https',
    'node:net',
    'node:dgram',
    'process.argv',
    'writeFile',
    'appendFile',
    'mkdir',
    'spawn',
    'execFile',
    'fetch(',
    'artifacts/',
  ];

  for (const [name, text] of core) {
    assert.deepEqual(importsOf(text), ['node:crypto'], `${name} imports only node:crypto`);
    for (const token of forbidden) {
      assert.equal(text.includes(token), false, `${name} must not contain ${token}`);
    }
  }
});

test('producer and verifier share no executable module and verifier owns the candidate pin', () => {
  const producer = source(PRODUCER_PATH);
  const verifier = source(VERIFIER_PATH);

  assert.equal(producer.includes('./verify'), false);
  assert.equal(producer.includes('./fixtures/'), false);
  assert.equal(verifier.includes('./producer'), false);
  assert.equal(verifier.includes('./fixtures/'), false);
  assert.match(
    verifier,
    /const PINNED_CANDIDATE_EXPECTATION_SHA256 =\s*'1605865d02f6d462e99038df2e1c1b776b3fc9bf8fb0581982b69f2a5f518df2';/
  );
});

test('subject keeps every prohibited transition explicit', () => {
  const subject = JSON.parse(source(SUBJECT_PATH));
  const prohibited = subject.prohibited.join('\n');

  for (const required of [
    'real-source producer execution',
    'raw creation',
    'payload preservation',
    'H-055',
    'failure-branch implementation',
    'plan mutation',
    'ADR or SPEC creation',
    'network or live observation',
    'USB or hidraw access',
    'Docker',
    'commit, push, merge, or publication',
  ]) {
    assert.match(prohibited, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
});
