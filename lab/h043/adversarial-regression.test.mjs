import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { H042_RUN_MEMBER_PATH, readH042ReplayArchive } from './archive-lib.mjs';
import { classifyPrefix } from './eligibility-lib.mjs';
import {
  buildH042Prefix,
  parseJsonLines,
  rebuildPrefixRaw,
  sha256Canonical,
} from './prefix-lib.mjs';
import { H043_REQUIRED_SOURCES, buildRun } from './run.mjs';
import { INDEPENDENT_REQUIRED_SOURCES, verifyRun } from './verify.mjs';

const members = await readH042ReplayArchive();
const memberRoot = H042_RUN_MEMBER_PATH.slice(0, -'run.json'.length);
const memberText = (name) => {
  const value = members.get(`${memberRoot}${name}`);
  assert.ok(value, `missing H-042 replay member ${name}`);
  return value.toString('utf8');
};
const h042Run = JSON.parse(memberText('run.json'));

function canonicalPrefix() {
  return buildH042Prefix({
    run: h042Run,
    runtimePollText: memberText('runtime-poll.jsonl'),
    hostPollText: memberText('host-poll.jsonl'),
    logsInitialText: memberText('logs-initial.txt'),
    logsAbsentText: memberText('logs-absent.txt'),
    logsPreSignalText: memberText('logs-pre-signal.txt'),
  });
}

const contextOnlyWithheldMutations = [
  [
    'descriptor',
    (prefix) => {
      const stat = prefix.context.observations.preSignal.host.hidraw.find(
        (entry) => entry.serialMatches
      ).stat;
      prefix.context.observations.preSignal.runtime.observer.surfaceWorkers[0].fileDescriptors.push(
        {
          descriptor: '20',
          target: '/host-dev/hidraw0',
          stat: structuredClone(stat),
          fdinfoSha256: 'a'.repeat(64),
        }
      );
    },
  ],
  [
    'markers',
    (prefix) => {
      prefix.context.observations.preSignal.runtime.markers.opening += 1;
      prefix.context.observations.preSignal.runtime.markers.ready += 1;
    },
  ],
  [
    'device',
    (prefix) => {
      prefix.context.observations.preSignal.host.state = 'absent';
      prefix.context.observations.preSignal.host.usb = [];
      prefix.context.observations.preSignal.host.hidraw = [];
    },
  ],
  [
    'window',
    (prefix) => {
      const started = BigInt(prefix.context.windows.preSignal.startedMonotonicNs);
      prefix.context.windows.preSignal.completedMonotonicNs = (
        started + 29_999_999_999n
      ).toString();
      prefix.context.windows.preSignal.deadlineExpired = false;
    },
  ],
];

for (const [label, mutate] of contextOnlyWithheldMutations) {
  test(`raw/context ${label} incoherence is inconclusive, never withheld`, () => {
    const prefix = canonicalPrefix();
    const rawBefore = sha256Canonical(prefix.raw);
    mutate(prefix);

    assert.equal(sha256Canonical(prefix.raw), rawBefore, 'the raw receipt unexpectedly changed');
    const classification = classifyPrefix(prefix);
    assert.equal(classification.disposition, 'inconclusive');
    assert.notEqual(classification.disposition, 'withheld');
    assert.deepEqual(classification.candidates, []);
  });
}

test('incomplete pre-cutoff audit is inconclusive before a coherent withheld branch', () => {
  const canonical = canonicalPrefix();
  const runtimeEntries = parseJsonLines(
    canonical.raw.runtimePoll.text,
    'H-043 incomplete-audit runtime'
  );
  const finalRuntime = runtimeEntries.at(-1);
  const finalHost = canonical.context.observations.preSignal.host;
  const currentStat = finalHost.hidraw.find((entry) => entry.serialMatches).stat;
  finalRuntime.observer.surfaceWorkers[0].fileDescriptors.push({
    descriptor: '20',
    target: '/host-dev/hidraw0',
    stat: structuredClone(currentStat),
    fdinfoSha256: 'a'.repeat(64),
  });

  const prefix = rebuildPrefixRaw(canonical, {
    runtimeEntries,
    auditEntries: [],
  });
  prefix.context.observations.preSignal.runtime = structuredClone(finalRuntime);
  prefix.context.observations.preSignal.control = {
    descriptorObserved: true,
    openingObserved: false,
    readyObserved: false,
    boundaryNegative: false,
  };

  const classification = classifyPrefix(prefix);
  assert.equal(classification.predicates.historicalAuditExact, false);
  assert.equal(classification.disposition, 'inconclusive');
  assert.equal(classification.stage, 'source-admission');
  assert.notEqual(classification.disposition, 'withheld');
  assert.deepEqual(classification.candidates, []);
});

const temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'overlaykit-h043-adversarial-'));
after(async () => {
  await rm(temporaryDirectory, { recursive: true, force: true });
});

const canonicalRun = await buildRun({ startedAt: '2026-07-26T19:10:00.000Z' });

async function writeTamperedRun(name, mutate) {
  const candidate = structuredClone(canonicalRun);
  mutate(candidate);
  delete candidate.evidenceSha256;
  candidate.evidenceSha256 = sha256Canonical(candidate);
  const runPath = path.join(temporaryDirectory, `${name}.json`);
  await writeFile(runPath, `${JSON.stringify(candidate, null, 2)}\n`);
  return runPath;
}

for (const [field, forgedValue] of [
  ['inputSha256', '0'.repeat(64)],
  ['stage', 'forged-stage'],
  ['reasonCode', 'forged-reason-code'],
]) {
  test(`verifyRun rejects hostile-matrix ${field} tampering after outer hash recomputation`, async () => {
    const runPath = await writeTamperedRun(`matrix-${field}`, (run) => {
      const hostileCase = run.hostileMatrix.cases.find(
        (entry) => entry.id === 'worker-startticks-changed'
      );
      assert.ok(hostileCase, 'missing worker-startticks-changed hostile case');
      hostileCase[field] = forgedValue;
    });

    await assert.rejects(() => verifyRun(runPath));
  });
}

test('source closure excludes mutable compiled governance outputs', () => {
  assert.deepEqual(INDEPENDENT_REQUIRED_SOURCES, H043_REQUIRED_SOURCES);
  assert.equal(
    H043_REQUIRED_SOURCES.includes('lab/h043/adversarial-regression.test.mjs'),
    true,
    'the adversarial regression source must itself be evidence-bound'
  );
  for (const mutablePath of [
    '.overlaykit/governance/manifest.json',
    '.overlaykit/governance/plan.json',
    '.overlaykit/governance/profile.json',
  ]) {
    assert.equal(
      H043_REQUIRED_SOURCES.includes(mutablePath),
      false,
      `${mutablePath} must remain a historical governance receipt, not a current-HEAD source`
    );
  }
});
