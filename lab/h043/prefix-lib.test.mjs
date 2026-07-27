import assert from 'node:assert/strict';
import test from 'node:test';
import { H042_RUN_MEMBER_PATH, readH042ReplayArchive } from './archive-lib.mjs';
import {
  H043_CANONICAL_PREFIX_RECEIPTS,
  buildH042Prefix,
  canonicalPrefixReceiptsExact,
  parseJsonLines,
  prefixManifest,
  prefixShapeExact,
  sha256Canonical,
  sourceDescriptorExact,
} from './prefix-lib.mjs';

const members = await readH042ReplayArchive();
const memberRoot = H042_RUN_MEMBER_PATH.slice(0, -'run.json'.length);
const memberText = (name) => {
  const value = members.get(`${memberRoot}${name}`);
  assert.ok(value, `missing H-042 replay member ${name}`);
  return value.toString('utf8');
};
const canonicalRun = JSON.parse(memberText('run.json'));

function build(run = canonicalRun) {
  return buildH042Prefix({
    run,
    runtimePollText: memberText('runtime-poll.jsonl'),
    hostPollText: memberText('host-poll.jsonl'),
    logsInitialText: memberText('logs-initial.txt'),
    logsAbsentText: memberText('logs-absent.txt'),
    logsPreSignalText: memberText('logs-pre-signal.txt'),
  });
}

test('projects the exact accepted pre-signal receipt boundary', () => {
  const prefix = build();
  const manifest = prefixManifest(prefix);

  assert.equal(prefixShapeExact(prefix), true);
  assert.equal(sourceDescriptorExact(prefix), true);
  assert.equal(canonicalPrefixReceiptsExact(prefix), true);
  assert.deepEqual(
    {
      runtimePoll: manifest.runtimePoll,
      hostPoll: manifest.hostPoll,
      invocationAudit: manifest.invocationAudit,
      cutoffMonotonicNs: manifest.cutoffMonotonicNs,
    },
    {
      runtimePoll: H043_CANONICAL_PREFIX_RECEIPTS.runtimePoll,
      hostPoll: H043_CANONICAL_PREFIX_RECEIPTS.hostPoll,
      invocationAudit: H043_CANONICAL_PREFIX_RECEIPTS.invocationAudit,
      cutoffMonotonicNs: H043_CANONICAL_PREFIX_RECEIPTS.cutoffMonotonicNs,
    }
  );
});

test('cuts runtime, host, and invocation evidence strictly at the recorded host cutoff', () => {
  const prefix = build();
  const cutoff = BigInt(prefix.cutoffMonotonicNs);
  const runtime = parseJsonLines(prefix.raw.runtimePoll.text, 'runtime');
  const host = parseJsonLines(prefix.raw.hostPoll.text, 'host');

  assert.equal(runtime.length, 55);
  assert.equal(host.length, 476);
  assert.equal(prefix.context.invocationAuditPrefix.length, 223);
  assert.equal(
    runtime.every((entry) => BigInt(entry.monotonicNs) < cutoff),
    true
  );
  assert.equal(host.at(-1).monotonicNs, prefix.cutoffMonotonicNs);
  assert.equal(
    prefix.context.invocationAuditPrefix.every((entry) => BigInt(entry.monotonicNs) <= cutoff),
    true
  );
  assert.equal(
    prefix.context.invocationAuditPrefix.some((entry) => entry.kind === 'docker-exec-signal'),
    false
  );
});

test('does not project H-042 signal, post-signal, outcome, cleanup, or completed tail fields', () => {
  const prefix = build();
  for (const forbidden of [
    'claimBoundary',
    'predicates',
    'outcome',
    'cleanup',
    'completedAt',
    'evidenceSha256',
  ]) {
    assert.equal(Object.hasOwn(prefix.context, forbidden), false, forbidden);
  }
  assert.deepEqual(Object.keys(prefix.context.windows).sort(), [
    'disconnect',
    'preSignal',
    'reconnect',
  ]);
  assert.equal(Object.hasOwn(prefix.context.observations, 'postSignal'), false);
  assert.equal(
    prefix.context.invocationAuditPrefix.some((entry) => entry.kind === 'docker-exec-signal'),
    false
  );
});

test('is byte-independent from arbitrary post-cutoff H-042 tail changes', () => {
  const original = build();
  const mutatedRun = structuredClone(canonicalRun);
  mutatedRun.windows.signal = { arbitrary: 'changed' };
  mutatedRun.windows.postSignal = { arbitrary: 'deleted-and-replaced' };
  mutatedRun.observations.postSignal = { arbitrary: true };
  mutatedRun.predicates = { future: false };
  mutatedRun.outcome = { status: 'refuted' };
  mutatedRun.cleanup = { mutated: true };
  mutatedRun.completedAt = '2099-01-01T00:00:00.000Z';
  mutatedRun.invocationAudit.entries = mutatedRun.invocationAudit.entries.map((entry) =>
    BigInt(entry.monotonicNs) > BigInt(original.cutoffMonotonicNs)
      ? { ...entry, kind: 'arbitrary-future-tail' }
      : entry
  );
  const mutated = build(mutatedRun);

  assert.equal(sha256Canonical(mutated), sha256Canonical(original));
  assert.deepEqual(prefixManifest(mutated), prefixManifest(original));
});

test('detects source descriptor or canonical raw-prefix drift', () => {
  const sourceDrift = build();
  sourceDrift.source.h042RunSha256 = '0'.repeat(64);
  assert.equal(sourceDescriptorExact(sourceDrift), false);

  const rawDrift = build();
  rawDrift.raw.runtimePoll.text = rawDrift.raw.runtimePoll.text.replace(
    '"baseline-poll"',
    '"tampered-poll"'
  );
  assert.equal(canonicalPrefixReceiptsExact(rawDrift), false);
});

test('rejects malformed or non-newline-terminated JSONL', () => {
  assert.throws(() => parseJsonLines('{}', 'fixture'), /newline-terminated/u);
  assert.throws(() => parseJsonLines('{}\n\n', 'fixture'), /empty JSONL/u);
  assert.throws(() => parseJsonLines('[]\n', 'fixture'), /not an object/u);
  assert.throws(() => parseJsonLines('{oops}\n', 'fixture'), /invalid/u);
});

test('does not mutate the accepted H-042 run while projecting', () => {
  const before = sha256Canonical(canonicalRun);
  build();
  assert.equal(sha256Canonical(canonicalRun), before);
});
