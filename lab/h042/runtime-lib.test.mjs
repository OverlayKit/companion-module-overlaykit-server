import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  CONTAINER_OBSERVER,
  CONTAINER_SIGNAL_HELPER,
  HEALTHCHECK_COMMAND,
  analyzeCleanupEvents,
  analyzeExperimentEvents,
  buildDockerRunArguments,
  invocationAudit,
  normalizeDockerLogs,
  parseDockerEvents,
} from './runtime-lib.mjs';

test('builds an exact dynamic-only container boundary with a read-only signal helper', () => {
  const args = buildDockerRunArguments({
    containerName: 'h042-test',
    dynamicPath: '/host-dev/hidraw0',
    compatibilityPath: '/dev/hidraw0',
    deviceGid: 1002,
    cgroupRule: 'c 241:0 rw',
  });
  assert.equal(args.filter((entry) => entry === '--device').length, 0);
  assert.equal(args.includes('--device-cgroup-rule'), true);
  assert.equal(
    args.some((entry) => entry.includes(`dst=${CONTAINER_SIGNAL_HELPER},readonly`)),
    true
  );
  assert.equal(args.includes('dev.overlaykit.hypothesis=H-042'), true);
  assert.equal(args.includes('none'), true);
});

test('normalizes stdout and stderr by exact Docker timestamp', () => {
  const result = normalizeDockerLogs(
    '2026-07-26T00:00:00.000000002Z stdout second\n',
    '2026-07-26T00:00:00.000000001Z stderr first\n'
  );
  assert.deepEqual(result.text.split('\n').filter(Boolean), [
    '2026-07-26T00:00:00.000000001Z stderr first',
    '2026-07-26T00:00:00.000000002Z stdout second',
  ]);
  assert.throws(() => normalizeDockerLogs('untimestamped\n', ''));
});

test('audit requires one exact signal and cleanup after classification', () => {
  const entries = [
    { kind: 'docker-run', monotonicNs: '10' },
    { kind: 'physical-disconnect-window', monotonicNs: '20' },
    { kind: 'physical-reconnect-window', monotonicNs: '30' },
    {
      kind: 'docker-exec-signal',
      monotonicNs: '40',
      signal: 'SIGTERM',
      user: '1000:1000',
      exitCode: 0,
      command: ['node', CONTAINER_SIGNAL_HELPER],
    },
    { kind: 'docker-events-experiment', monotonicNs: '50' },
    { kind: 'experiment-classified', monotonicNs: '60' },
    { kind: 'docker-stop', monotonicNs: '70' },
    { kind: 'docker-ps-cleanup', monotonicNs: '80' },
    { kind: 'docker-events-cleanup', monotonicNs: '90' },
  ];
  assert.equal(invocationAudit(entries).passed, true);
  assert.equal(invocationAudit([...entries, { ...entries[3], monotonicNs: '100' }]).passed, false);
  assert.equal(
    invocationAudit(
      entries.map((entry) =>
        entry.kind === 'experiment-classified' ? { ...entry, monotonicNs: '75' } : entry
      )
    ).passed,
    false
  );
});

test('preserves Docker timeNano as an exact decimal string', () => {
  const [event] = parseDockerEvents(
    '{"Type":"container","Action":"start","Actor":{"ID":"abc","Attributes":{}},"timeNano":1785024000000000001}\n'
  );
  assert.equal(event.timeNano, '1785024000000000001');
});

const containerId = 'a'.repeat(64);
const experimentStartedAt = '2026-07-26T00:00:00.000Z';
const experimentBoundaryAt = '2026-07-26T00:01:00.000Z';
const classifiedAt = '2026-07-26T00:01:01.000Z';
const eventsUntilAt = '2026-07-26T00:01:10.000Z';
const baseNs = BigInt(Date.parse(experimentStartedAt)) * 1_000_000n;
const event = (action, offsetNs, attributes = {}, id = containerId) => ({
  type: 'container',
  action,
  status: null,
  id,
  time: null,
  timeNano: (baseNs + BigInt(offsetNs)).toString(),
  attributes,
});
const execTriplet = (command, execId, offsetNs) => [
  event(`exec_create: ${command}`, offsetNs, { execID: execId }),
  event(`exec_start: ${command}`, offsetNs + 1, { execID: execId }),
  event('exec_die', offsetNs + 2, { execID: execId, exitCode: '0' }),
];

test('accepts only complete known observer, helper, and healthcheck exec triplets', () => {
  const helperCommand = `/app/node-runtimes/main/bin/node ${CONTAINER_SIGNAL_HELPER}`;
  const observerCommand = `/app/node-runtimes/main/bin/node ${CONTAINER_OBSERVER}`;
  const events = [
    event('create', 1),
    event('start', 2),
    event('health_status: starting', 3),
    ...execTriplet(observerCommand, 'observer', 10),
    ...execTriplet(HEALTHCHECK_COMMAND, 'health', 20),
    ...execTriplet(helperCommand, 'helper', 30),
    event('health_status: healthy', 40),
  ];
  const options = {
    containerId,
    helperCommand,
    observerCommand,
    expectedObserverExecCount: 1,
    experimentStartedAt,
    experimentBoundaryAt,
  };
  const analysis = analyzeExperimentEvents(events, options);
  assert.equal(analysis.passed, true);
  assert.equal(analysis.healthcheck.tripletCount, 1);
  assert.equal(analysis.unknownExecEvents.length, 0);
  assert.equal(
    analyzeExperimentEvents(events.slice(0, -2), options).passed,
    false,
    'an incomplete helper triplet must fail closed'
  );
  assert.equal(
    analyzeExperimentEvents([...events, ...execTriplet('sh -c unknown', 'unknown', 50)], options)
      .passed,
    false
  );
  assert.equal(analyzeExperimentEvents([...events, event('top', 50)], options).passed, false);
  assert.equal(
    analyzeExperimentEvents(
      [...events, event('health_status: healthy', 50, {}, 'b'.repeat(64))],
      options
    ).passed,
    false
  );
});

test('partitions cleanup gap events from the exact post-classification stop lifecycle', () => {
  const boundaryOffset = 60_000_000_000;
  const classifiedOffset = 61_000_000_000;
  const events = [
    ...execTriplet(HEALTHCHECK_COMMAND, 'gap-health', boundaryOffset + 1),
    event('health_status: healthy', boundaryOffset + 10),
    event('kill', classifiedOffset + 1, { signal: '15' }),
    event('kill', classifiedOffset + 2, { signal: '9' }),
    event('stop', classifiedOffset + 3),
    event('die', classifiedOffset + 4, { exitCode: '137' }),
    event('destroy', classifiedOffset + 5),
  ];
  const options = {
    containerId,
    experimentBoundaryAt,
    classifiedAt,
    eventsUntilAt,
  };
  const analysis = analyzeCleanupEvents(events, options);
  assert.equal(analysis.passed, true);
  assert.equal(analysis.gap.healthcheck.tripletCount, 1);
  assert.equal(analysis.cleanup.kill15Count, 1);
  assert.equal(analysis.cleanup.kill9Count, 1);
  assert.equal(
    analyzeCleanupEvents(
      events.map((entry) =>
        entry.action === 'stop'
          ? { ...entry, timeNano: (baseNs + BigInt(classifiedOffset + 5)).toString() }
          : entry
      ),
      options
    ).passed,
    false
  );
  assert.equal(
    analyzeCleanupEvents([...events, event('restart', classifiedOffset + 6)], options).passed,
    false
  );
});
