import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import {
  BRANCHES as FIXTURE_BRANCHES,
  EXPECTED_PROTOCOL,
  executeSyntheticCase,
} from './fixtures/synthetic-terminal-cases.mjs';
import {
  BRANCHES,
  FailurePreservationProducerError,
  canonicalHash,
  canonicalJson,
  canonicalPrettyJson,
  makeReservation,
  produceTerminalEnvelope,
  sha256,
} from './producer.mjs';

const SUBJECT_RAW_SHA256 = '32faedd0bf9202190ee9fdbae0c84baff05764dd637dcf4b2dfd6d4487aca144';
const SOURCE_ANCHOR = Object.freeze({
  blockingRunnerRawSha256: '5c5bd2b73500c98779e8b0fea8b9d149f7d66815ef601a2bd5944b54f8bf457b',
  chg0036RawSha256: '2ff88d94d8768b23548e64d066922aec3e1d0b8ba7aaab27907f8af0432bf492',
  chg0038RawSha256: '3b0a2fb3dfbfa08d59df881df5f097bf66758eb6563e223012f790aaa8c8d77e',
  chg0039RawSha256: '6d062d4a1aa236d441481845549bea65d3a2b3b11498b34361b9a18c4a6d5a85',
  mainCommit: 'd1caa3bff1b47b61c661e4ec4582add4f9c795c3',
  mainTree: 'd83fa14a3c25189260921a0c08862e6540a52baf',
  planHash: 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4',
  planRawSha256: '2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243',
  predecessorManifestContentHash:
    'efa010a5c268dca8b364d0efe669f8315d415ad19ead95b75e8b155d664d92a1',
  predecessorManifestRawSha256: 'dc2666418b273d752f3f9d06ebe354515dad5eb06ec5d1aa597732806bf2b465',
  profileHash: '9b55c034c16a653d497672374c12d94f6f609c77f23aecd0f0d437e230cb4ebd',
});

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function reservationFor(branchId) {
  return makeReservation({
    branchId,
    ordinal: BRANCHES.indexOf(branchId) + 1,
    sourceAnchor: SOURCE_ANCHOR,
    subjectRawSha256: SUBJECT_RAW_SHA256,
  });
}

function terminalFor(branchId, transport = executeSyntheticCase(branchId)) {
  const ordinal = BRANCHES.indexOf(branchId) + 1;
  return produceTerminalEnvelope({
    branchId,
    ordinal,
    reservationRawSha256: sha256(Buffer.from(canonicalPrettyJson(reservationFor(branchId)))),
    transport,
  });
}

function expectProducerError(fn, code) {
  assert.throws(
    fn,
    (error) => error instanceof FailurePreservationProducerError && error.code === code
  );
}

test('fixture exposes the exact terminal partition and deterministic protocol', () => {
  assert.deepEqual(FIXTURE_BRANCHES, [
    'launch-failure',
    'malformed-output',
    'divergent-attempts',
    'exact-incompatibility',
    'success',
  ]);
  assert.deepEqual(BRANCHES, FIXTURE_BRANCHES);
  assert.deepEqual(EXPECTED_PROTOCOL, {
    compatibility: 'compatible',
    marker: 'node22-failure-preservation-v1',
  });

  for (const branchId of BRANCHES) {
    assert.deepEqual(executeSyntheticCase(branchId), executeSyntheticCase(branchId));
  }
});

test('fixture materializes the exact mechanical attempt cardinalities', () => {
  const expectedCounts = [0, 1, 2, 2, 2];
  for (const [index, branchId] of BRANCHES.entries()) {
    const transport = executeSyntheticCase(branchId);
    assert.equal(transport.attempts.length, expectedCounts[index]);
    assert.equal(transport.launchError === null, branchId !== 'launch-failure');
    for (const [attemptIndex, attempt] of transport.attempts.entries()) {
      assert.equal(attempt.ordinal, attemptIndex + 1);
      assert.equal(attempt.exitCode, 0);
      assert.equal(attempt.signal, null);
      assert.ok(Buffer.isBuffer(attempt.stdout));
      assert.ok(Buffer.isBuffer(attempt.stderr));
    }
  }
});

test('reservation is deterministic, source-bound, detached, and non-authoritative', () => {
  const first = reservationFor('success');
  const second = reservationFor('success');

  assert.deepEqual(first, second);
  assert.notEqual(first.sourceAnchor, SOURCE_ANCHOR);
  assert.deepEqual(first, {
    action: null,
    authority: 'none',
    branchId: 'success',
    normative: false,
    ordinal: 5,
    schemaVersion: 'overlaykit-node22-failure-preservation-preflight-reservation/v1',
    sourceAnchor: SOURCE_ANCHOR,
    study: 'NODE22-FAILURE-PRESERVATION-PREFLIGHT-001',
    subjectRawSha256: SUBJECT_RAW_SHA256,
    synthetic: true,
  });
  assert.equal(canonicalHash(first), canonicalHash(second));
  assert.equal(canonicalPrettyJson(first).endsWith('\n'), true);
});

test('producer encodes all five terminal transports without semantic parsing', () => {
  for (const branchId of BRANCHES) {
    const terminal = terminalFor(branchId);
    const { semanticSha256, ...body } = terminal;
    assert.equal(semanticSha256, canonicalHash(body));
    assert.equal(terminal.branchId, branchId);
    assert.equal(terminal.authority, 'none');
    assert.equal(terminal.action, null);
    assert.equal(terminal.normative, false);
    assert.equal(terminal.synthetic, true);

    for (const attempt of terminal.attempts) {
      for (const field of ['stdout', 'stderr']) {
        const decoded = Buffer.from(attempt[field].base64, 'base64');
        assert.equal(decoded.length, attempt[field].byteLength);
        assert.equal(sha256(decoded), attempt[field].sha256);
        assert.deepEqual(Object.keys(attempt[field]).sort(), ['base64', 'byteLength', 'sha256']);
      }
    }
  }

  assert.equal(terminalFor('malformed-output').attempts.length, 1);
  assert.deepEqual(terminalFor('launch-failure').launchError, {
    code: 'SYNTHETIC_LAUNCH_FAILED',
    syscall: 'synthetic-launch',
  });
});

test('terminal output is detached from mutable transport buffers and objects', () => {
  const transport = executeSyntheticCase('success');
  const terminal = terminalFor('success', transport);
  const before = canonicalJson(terminal);

  transport.attempts[0].stdout.fill(0x78);
  transport.attempts[0].stderr = Buffer.from('later mutation');
  transport.attempts[1].signal = 'SIGTERM';

  assert.equal(canonicalJson(terminal), before);
});

test('producer source has no semantic parser, filesystem, process, network, or automatic main', () => {
  const source = readFileSync(new URL('./producer.mjs', import.meta.url), 'utf8');
  const imports = [...source.matchAll(/^import .+ from '([^']+)';$/gmu)].map((match) => match[1]);

  assert.deepEqual(imports, ['node:crypto']);
  for (const forbidden of [
    'JSON.parse',
    'node:fs',
    'node:child_process',
    'node:http',
    'node:https',
    'node:net',
    'process.',
    'artifacts/',
  ]) {
    assert.equal(source.includes(forbidden), false, forbidden);
  }
});

test('reservation refuses authority, shape, ordinal, subject, and source drift', () => {
  const baseline = {
    branchId: 'success',
    ordinal: 5,
    sourceAnchor: SOURCE_ANCHOR,
    subjectRawSha256: SUBJECT_RAW_SHA256,
  };

  expectProducerError(
    () => makeReservation({ ...baseline, authority: 'producer' }),
    'reservation-input-shape-invalid'
  );
  expectProducerError(() => makeReservation({ ...baseline, ordinal: 4 }), 'branch-ordinal-invalid');
  expectProducerError(
    () => makeReservation({ ...baseline, subjectRawSha256: '0'.repeat(64) }),
    'subject-anchor-drift'
  );
  expectProducerError(
    () =>
      makeReservation({
        ...baseline,
        sourceAnchor: { ...SOURCE_ANCHOR, planHash: '0'.repeat(64) },
      }),
    'source-anchor-drift'
  );
});

test('terminal producer refuses malformed transport without interpreting stdout', () => {
  const base = {
    branchId: 'success',
    ordinal: 5,
    reservationRawSha256: '1'.repeat(64),
    transport: executeSyntheticCase('success'),
  };

  expectProducerError(
    () => produceTerminalEnvelope({ ...base, authority: 'producer' }),
    'terminal-input-shape-invalid'
  );

  const extraTransport = executeSyntheticCase('success');
  extraTransport.claimedBranch = 'success';
  expectProducerError(
    () => produceTerminalEnvelope({ ...base, transport: extraTransport }),
    'transport-shape-invalid'
  );

  const wrongCount = executeSyntheticCase('success');
  wrongCount.attempts.pop();
  expectProducerError(
    () => produceTerminalEnvelope({ ...base, transport: wrongCount }),
    'attempt-roster-invalid'
  );

  const wrongBytes = executeSyntheticCase('success');
  wrongBytes.attempts[0].stdout = '{"accepted":true}';
  expectProducerError(
    () => produceTerminalEnvelope({ ...base, transport: wrongBytes }),
    'attempt-bytes-invalid'
  );

  const unexpectedAttemptField = executeSyntheticCase('success');
  unexpectedAttemptField.attempts[0].semantic = 'success';
  expectProducerError(
    () => produceTerminalEnvelope({ ...base, transport: unexpectedAttemptField }),
    'attempt-shape-invalid'
  );

  const malformedTransport = executeSyntheticCase('malformed-output');
  assert.doesNotThrow(() =>
    produceTerminalEnvelope({
      branchId: 'malformed-output',
      ordinal: 2,
      reservationRawSha256: '2'.repeat(64),
      transport: malformedTransport,
    })
  );
});

test('canonical and binary hashes are byte-stable and reject unsupported values', () => {
  assert.equal(
    sha256(Buffer.from('synthetic')),
    createHash('sha256').update('synthetic').digest('hex')
  );
  assert.equal(canonicalJson({ z: 1, a: 2 }), '{"a":2,"z":1}');
  expectProducerError(() => canonicalJson({ invalid: undefined }), 'canonical-value-invalid');
  expectProducerError(() => sha256({ bytes: 'not-binary' }), 'sha256-input-invalid');
});
