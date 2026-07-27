import assert from 'node:assert/strict';
import test from 'node:test';
import { H042_RUN_MEMBER_PATH, readH042ReplayArchive } from './archive-lib.mjs';
import {
  H043_PREDICATE_KEYS,
  classifyPrefix,
  classificationExactShape,
} from './eligibility-lib.mjs';
import {
  buildH042Prefix,
  parseJsonLines,
  rebuildPrefixRaw,
  sha256Canonical,
} from './prefix-lib.mjs';

const members = await readH042ReplayArchive();
const memberRoot = H042_RUN_MEMBER_PATH.slice(0, -'run.json'.length);
const memberText = (name) => {
  const value = members.get(`${memberRoot}${name}`);
  assert.ok(value, `missing H-042 replay member ${name}`);
  return value.toString('utf8');
};
const canonicalRun = JSON.parse(memberText('run.json'));

function canonicalPrefix() {
  return buildH042Prefix({
    run: canonicalRun,
    runtimePollText: memberText('runtime-poll.jsonl'),
    hostPollText: memberText('host-poll.jsonl'),
    logsInitialText: memberText('logs-initial.txt'),
    logsAbsentText: memberText('logs-absent.txt'),
    logsPreSignalText: memberText('logs-pre-signal.txt'),
  });
}

function classifyMutation(mutate) {
  const prefix = canonicalPrefix();
  mutate(prefix);
  return classifyPrefix(prefix);
}

function currentNodeDescriptor(prefix) {
  const stat = prefix.context.observations.preSignal.host.hidraw.find(
    (entry) => entry.serialMatches
  ).stat;
  return {
    descriptor: '20',
    target: '/host-dev/hidraw0',
    stat: structuredClone(stat),
    fdinfoSha256: 'a'.repeat(64),
  };
}

function synchronizePreSignalSummary(prefix) {
  const observation = prefix.context.observations.preSignal;
  const initialMarkers = prefix.context.observations.initial.runtime.markers;
  const finalMarkers = observation.runtime.markers;
  const currentStat = observation.host.hidraw.find((entry) => entry.serialMatches)?.stat;
  const descriptorObserved = observation.runtime.observer.surfaceWorkers.some((worker) =>
    worker.fileDescriptors.some(
      (descriptor) =>
        descriptor.stat?.inode === currentStat?.inode &&
        descriptor.stat?.rdev === currentStat?.rdev &&
        descriptor.stat?.major === currentStat?.major &&
        descriptor.stat?.minor === currentStat?.minor &&
        descriptor.stat?.isCharacterDevice === true
    )
  );
  const openingObserved = finalMarkers.opening > initialMarkers.opening;
  const readyObserved = finalMarkers.ready > initialMarkers.ready;
  observation.markers = {
    baseline: structuredClone(initialMarkers),
    final: structuredClone(finalMarkers),
  };
  observation.control = {
    descriptorObserved,
    openingObserved,
    readyObserved,
    boundaryNegative:
      prefix.context.windows.preSignal.deadlineExpired === true &&
      !descriptorObserved &&
      !openingObserved &&
      !readyObserved,
  };
}

function mutateFinalRuntime(prefix, mutateWorker, mutateRuntime) {
  const entries = parseJsonLines(prefix.raw.runtimePoll.text, 'H-043 test runtime');
  const final = entries.at(-1);
  mutateWorker?.(final.observer.surfaceWorkers, final);
  mutateRuntime?.(final);
  const candidate = rebuildPrefixRaw(prefix, { runtimeEntries: entries });
  candidate.context.observations.preSignal.runtime = structuredClone(final);
  synchronizePreSignalSummary(candidate);
  return candidate;
}

function mutateFinalHost(prefix, mutateHost) {
  const entries = parseJsonLines(prefix.raw.hostPoll.text, 'H-043 test host');
  const final = entries.at(-1);
  mutateHost(final);
  const candidate = rebuildPrefixRaw(prefix, { hostEntries: entries });
  candidate.context.observations.preSignal.host = structuredClone(final);
  synchronizePreSignalSummary(candidate);
  return candidate;
}

function openNegativeWindow(prefix) {
  const candidate = structuredClone(prefix);
  const started = BigInt(candidate.context.windows.preSignal.startedMonotonicNs);
  const runtime = parseJsonLines(candidate.raw.runtimePoll.text, 'H-043 open-window runtime');
  const finalRuntime = runtime.find((entry) => BigInt(entry.monotonicNs) >= started);
  assert.ok(finalRuntime, 'missing post-return runtime observation');
  const cutoff = BigInt(finalRuntime.monotonicNs) + 1n;
  const runtimeEntries = runtime.filter(
    (entry) => BigInt(entry.monotonicNs) <= BigInt(finalRuntime.monotonicNs)
  );
  const hostEntries = parseJsonLines(candidate.raw.hostPoll.text, 'H-043 open-window host').filter(
    (entry) => BigInt(entry.monotonicNs) < cutoff
  );
  const finalHost = structuredClone(candidate.context.observations.returned.host);
  finalHost.capturedAt = finalRuntime.capturedAt;
  finalHost.monotonicNs = cutoff.toString();
  hostEntries.push(finalHost);
  const auditEntries = candidate.context.invocationAuditPrefix.filter(
    (entry) => BigInt(entry.monotonicNs) <= cutoff
  );

  const rebuilt = rebuildPrefixRaw(candidate, {
    runtimeEntries,
    hostEntries,
    auditEntries,
  });
  rebuilt.cutoffMonotonicNs = cutoff.toString();
  rebuilt.context.observations.preSignal.host = structuredClone(finalHost);
  rebuilt.context.observations.preSignal.runtime = structuredClone(finalRuntime);
  rebuilt.context.companion.preSignalLifecycle = structuredClone(finalRuntime.lifecycle);
  rebuilt.context.companion.workerLifecycle.preSignal = structuredClone(
    finalRuntime.observer.surfaceWorkers
  );
  rebuilt.context.windows.preSignal.completedAt = finalHost.capturedAt;
  rebuilt.context.windows.preSignal.completedMonotonicNs = cutoff.toString();
  rebuilt.context.windows.preSignal.deadlineExpired = false;
  rebuilt.context.windows.preSignal.boundaryNegative = false;
  synchronizePreSignalSummary(rebuilt);
  return rebuilt;
}

test('classifies the accepted H-042 prefix as one historical revalidation-required candidate', () => {
  const classification = classifyPrefix(canonicalPrefix());
  assert.equal(classificationExactShape(classification), true);
  assert.equal(classification.disposition, 'candidate');
  assert.equal(classification.reasonCode, 'revalidation-required-worker-candidate');
  assert.deepEqual(Object.keys(classification.predicates), H043_PREDICATE_KEYS);
  assert.equal(Object.values(classification.predicates).every(Boolean), true);
  assert.equal(classification.candidates.length, 1);

  const candidate = classification.candidates[0];
  assert.equal(candidate.kind, 'revalidation-required');
  assert.equal(candidate.historical, true);
  assert.equal(candidate.requiresRevalidation, true);
  assert.equal(candidate.authority, 'none');
  assert.equal(candidate.action, null);
  assert.match(candidate.tokenSha256, /^[0-9a-f]{64}$/u);
  assert.equal(candidate.identity.worker.pid, 73);
  assert.equal(candidate.identity.worker.startTicks, 7808716);
  assert.equal(candidate.identity.lifecycle.pid1StartTicks, 7808679);
  assert.equal(candidate.identity.device.initialEpoch.deviceNumber, '17');
  assert.equal(candidate.identity.device.returnedEpoch.deviceNumber, '18');
});

test('is deterministic and does not mutate its input', () => {
  const prefix = canonicalPrefix();
  const before = sha256Canonical(prefix);
  const first = classifyPrefix(prefix);
  const second = classifyPrefix(prefix);
  assert.deepEqual(second, first);
  assert.equal(sha256Canonical(prefix), before);
});

test('withholds while the complete negative window is still open', () => {
  const classification = classifyPrefix(openNegativeWindow(canonicalPrefix()));
  assert.equal(classification.disposition, 'withheld');
  assert.equal(classification.reasonCode, 'negative-window-open');
  assert.deepEqual(classification.candidates, []);
});

test('withholds when the device is still absent at the recorded cutoff', () => {
  const prefix = canonicalPrefix();
  const absent = prefix.context.observations.absent.host;
  const classification = classifyPrefix(
    mutateFinalHost(prefix, (host) => {
      for (const key of ['lsusb', 'usb', 'hidraw', 'priorPath', 'errors', 'state']) {
        host[key] = structuredClone(absent[key]);
      }
    })
  );
  assert.equal(classification.disposition, 'withheld');
  assert.equal(classification.reasonCode, 'device-absent-at-cutoff');
  assert.deepEqual(classification.candidates, []);
});

test('withholds when a current-node descriptor has already returned', () => {
  const prefix = canonicalPrefix();
  const classification = classifyPrefix(
    mutateFinalRuntime(prefix, (workers) => {
      workers[0].fileDescriptors = [currentNodeDescriptor(prefix)];
    })
  );
  assert.equal(classification.disposition, 'withheld');
  assert.equal(classification.reasonCode, 'automatic-reacquisition-observed');
  assert.deepEqual(classification.candidates, []);
});

test('withholds when complete opening and ready markers already returned', () => {
  const classification = classifyPrefix(
    mutateFinalRuntime(canonicalPrefix(), null, (runtime) => {
      runtime.markers.opening += 1;
      runtime.markers.ready += 1;
    })
  );
  assert.equal(classification.disposition, 'withheld');
  assert.equal(classification.reasonCode, 'automatic-reacquisition-observed');
});

test('treats a coherent partial marker change as contradictory rather than eligible', () => {
  const classification = classifyPrefix(
    mutateFinalRuntime(canonicalPrefix(), null, (runtime) => {
      runtime.markers.opening += 1;
    })
  );
  assert.equal(classification.disposition, 'inconclusive');
  assert.equal(classification.reasonCode, 'partial-or-mixed-reacquisition');
  assert.deepEqual(classification.candidates, []);
});

for (const [label, mutate] of [
  [
    'negative-window metadata',
    (prefix) => {
      const started = BigInt(prefix.context.windows.preSignal.startedMonotonicNs);
      prefix.context.windows.preSignal.completedMonotonicNs = (
        started + 29_999_999_999n
      ).toString();
      prefix.context.windows.preSignal.deadlineExpired = false;
    },
  ],
  [
    'final host absence',
    (prefix) => {
      prefix.context.observations.preSignal.host.state = 'absent';
      prefix.context.observations.preSignal.host.usb = [];
      prefix.context.observations.preSignal.host.hidraw = [];
    },
  ],
  [
    'current-node descriptor',
    (prefix) => {
      prefix.context.observations.preSignal.runtime.observer.surfaceWorkers[0].fileDescriptors = [
        currentNodeDescriptor(prefix),
      ];
    },
  ],
  [
    'opening and ready markers',
    (prefix) => {
      prefix.context.observations.preSignal.runtime.markers.opening += 1;
      prefix.context.observations.preSignal.runtime.markers.ready += 1;
    },
  ],
  [
    'partial marker',
    (prefix) => {
      prefix.context.observations.preSignal.runtime.markers.opening += 1;
    },
  ],
]) {
  test(`fails closed on context-only ${label}`, () => {
    const classification = classifyMutation(mutate);
    assert.equal(classification.disposition, 'inconclusive');
    assert.equal(classification.reasonCode, 'untrusted-or-contradictory-prefix');
    assert.deepEqual(classification.candidates, []);
  });
}

for (const [label, mutate, expectedReason] of [
  [
    'missing worker',
    (prefix) => {
      const entries = parseJsonLines(prefix.raw.runtimePoll.text, 'runtime');
      entries.at(-1).observer.surfaceWorkers = [];
      prefix.context.observations.preSignal.runtime.observer.surfaceWorkers = [];
      return rebuildPrefixRaw(prefix, { runtimeEntries: entries });
    },
  ],
  [
    'multiple workers',
    (prefix) => {
      const entries = parseJsonLines(prefix.raw.runtimePoll.text, 'runtime');
      const workers = entries.at(-1).observer.surfaceWorkers;
      workers.push({ ...structuredClone(workers[0]), pid: 999, startTicks: 999 });
      prefix.context.observations.preSignal.runtime.observer.surfaceWorkers =
        structuredClone(workers);
      return rebuildPrefixRaw(prefix, { runtimeEntries: entries });
    },
  ],
  [
    'container lifecycle drift',
    (prefix) => {
      const entries = parseJsonLines(prefix.raw.runtimePoll.text, 'runtime');
      entries.at(-1).lifecycle.restartCount = 1;
      prefix.context.companion.preSignalLifecycle.restartCount = 1;
      return rebuildPrefixRaw(prefix, { runtimeEntries: entries });
    },
  ],
  [
    'PID 1 drift',
    (prefix) => {
      const entries = parseJsonLines(prefix.raw.runtimePoll.text, 'runtime');
      entries.at(-1).lifecycle.pid1StartTicks += 1;
      prefix.context.companion.preSignalLifecycle.pid1StartTicks += 1;
      return rebuildPrefixRaw(prefix, { runtimeEntries: entries });
    },
  ],
  [
    'worker PID reuse',
    (prefix) => {
      const entries = parseJsonLines(prefix.raw.runtimePoll.text, 'runtime');
      entries.at(-1).observer.surfaceWorkers[0].startTicks += 1;
      prefix.context.observations.preSignal.runtime.observer.surfaceWorkers[0].startTicks += 1;
      return rebuildPrefixRaw(prefix, { runtimeEntries: entries });
    },
  ],
  [
    'worker parent PID drift',
    (prefix) =>
      mutateFinalRuntime(prefix, (workers) => {
        workers[0].ppid += 1;
      }),
    'identity-ambiguity-or-drift',
  ],
  [
    'worker parent start-ticks drift',
    (prefix) =>
      mutateFinalRuntime(prefix, (workers) => {
        workers[0].parentStartTicks += 1;
      }),
    'identity-ambiguity-or-drift',
  ],
  [
    'worker PID namespace drift',
    (prefix) =>
      mutateFinalRuntime(prefix, (workers) => {
        workers[0].pidNamespace = 'pid:[999]';
      }),
    'identity-ambiguity-or-drift',
  ],
  [
    'full worker tuple drift',
    (prefix) => {
      const entries = parseJsonLines(prefix.raw.runtimePoll.text, 'runtime');
      entries.at(-1).observer.surfaceWorkers[0].mountNamespace = 'mnt:[999]';
      prefix.context.observations.preSignal.runtime.observer.surfaceWorkers[0].mountNamespace =
        'mnt:[999]';
      return rebuildPrefixRaw(prefix, { runtimeEntries: entries });
    },
  ],
]) {
  test(`fails closed on ${label}`, () => {
    let prefix = canonicalPrefix();
    prefix = mutate(prefix) ?? prefix;
    const classification = classifyPrefix(prefix);
    assert.equal(classification.disposition, 'inconclusive');
    if (expectedReason) assert.equal(classification.reasonCode, expectedReason);
    assert.deepEqual(classification.candidates, []);
  });
}

test('fails closed when exact absence is contradicted', () => {
  let prefix = canonicalPrefix();
  const hostEntries = parseJsonLines(prefix.raw.hostPoll.text, 'H-043 absence host');
  const absent = prefix.context.observations.absent.host;
  const rawAbsent = hostEntries.find((entry) => entry.monotonicNs === absent.monotonicNs);
  const rawPresent = hostEntries.find(
    (entry) => entry.state === 'present' && entry.usb.some((device) => device.serial)
  );
  assert.ok(rawAbsent, 'missing raw absence observation');
  assert.ok(rawPresent, 'missing raw present observation');
  rawAbsent.state = 'present';
  rawAbsent.usb = structuredClone(rawPresent.usb);
  prefix = rebuildPrefixRaw(prefix, { hostEntries });
  prefix.context.observations.absent.host.state = 'present';
  prefix.context.observations.absent.host.usb = structuredClone(
    prefix.context.observations.initial.host.usb
  );
  const classification = classifyPrefix(prefix);
  assert.equal(classification.disposition, 'inconclusive');
  assert.equal(classification.reasonCode, 'device-epoch-or-node-mismatch');
});

test('fails closed on a same-epoch return or serial mismatch', () => {
  for (const mutate of [
    (prefix) => {
      prefix.context.observations.returned.host.usb[0].deviceNumber =
        prefix.context.observations.initial.host.usb[0].deviceNumber;
    },
    (prefix) => {
      prefix.context.observations.preSignal.host.hidraw[0].hid.unique = 'ANOTHER-SERIAL';
    },
  ]) {
    const classification = classifyMutation(mutate);
    assert.equal(classification.disposition, 'inconclusive');
    assert.deepEqual(classification.candidates, []);
  }
});

test('fails closed on returned-node drift', () => {
  const classification = classifyPrefix(
    mutateFinalHost(canonicalPrefix(), (host) => {
      host.hidraw[0].stat.inode = '9999';
    })
  );
  assert.equal(classification.disposition, 'inconclusive');
  assert.equal(classification.reasonCode, 'device-epoch-or-node-mismatch');
});

test('fails closed when the deadline boundary poll is missing', () => {
  let prefix = canonicalPrefix();
  const deadline = BigInt(prefix.context.windows.preSignal.startedMonotonicNs) + 30_000_000_000n;
  const entries = parseJsonLines(prefix.raw.runtimePoll.text, 'runtime').filter(
    (entry) => entry.phase === 'signal-target-revalidate' || BigInt(entry.monotonicNs) < deadline
  );
  prefix = rebuildPrefixRaw(prefix, { runtimeEntries: entries });
  const classification = classifyPrefix(prefix);
  assert.equal(classification.disposition, 'inconclusive');
  assert.deepEqual(classification.candidates, []);
});

test('fails closed on an unapproved pre-cutoff command', () => {
  let prefix = canonicalPrefix();
  const audit = structuredClone(prefix.context.invocationAuditPrefix);
  const prior = audit.at(-1);
  audit.push({
    at: prior.at,
    monotonicNs: (BigInt(prior.monotonicNs) + 1n).toString(),
    kind: 'docker-exec-signal',
    phase: 'fault-injection',
  });
  prefix = rebuildPrefixRaw(prefix, { auditEntries: audit });
  const classification = classifyPrefix(prefix);
  assert.equal(classification.disposition, 'inconclusive');
  assert.deepEqual(classification.candidates, []);
});

test('fails closed on source, prefix, and future-field tampering', () => {
  for (const mutate of [
    (prefix) => {
      prefix.source.h042RunSha256 = '0'.repeat(64);
    },
    (prefix) => {
      prefix.raw.logs.preSignal.text += 'tamper';
    },
    (prefix) => {
      prefix.futureSignal = { signal: 'SIGTERM' };
    },
  ]) {
    const classification = classifyMutation(mutate);
    assert.equal(classification.disposition, 'inconclusive');
    assert.deepEqual(classification.candidates, []);
    assert.equal(classificationExactShape(classification), true);
  }
});
