import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  classifyPostReconnectOutcome,
  classifyDeviceTransition,
  commandsBetween,
  fileDescriptorMatchesDevice,
  logMarkers,
  parseProcStartTicks,
  parseStatIdentity,
  runId,
  sameTopLevelLifecycle,
  validateControlConfiguration,
} from './reconnect-lib.mjs';

test('parses stat device identity and fails closed on ambiguous records', () => {
  assert.deepEqual(parseStatIdentity('0F3:00|4815162342|character special file\n'), {
    rdevHex: 'f3:0',
    major: 243,
    minor: 0,
    inode: 4_815_162_342,
    type: 'character special file',
  });
  assert.throws(() => parseStatIdentity('f3:0|12'), /rdev, inode, and type/u);
  assert.throws(() => parseStatIdentity('not-hex:0|12|character special file'), /hexadecimal/u);
  assert.throws(
    () => parseStatIdentity('f3:0|9007199254740992|character special file'),
    /safe integer/u
  );
  assert.throws(
    () => parseStatIdentity('f3:0|12|character special file\nf3:1|13|character special file'),
    /exactly one/u
  );
});

test('reads proc field 22 when the process name contains spaces and parentheses', () => {
  const fields4Through21 = Array.from({ length: 18 }, (_, index) => String(index + 1));
  const stat = `4242 (Surface Thread (MK.2) worker) S ${[
    ...fields4Through21,
    '987654',
    'ignored-field-23',
  ].join(' ')}`;
  assert.equal(parseProcStartTicks(stat), 987_654);
  assert.throws(() => parseProcStartTicks('4242 (Surface Thread) S 1 2 3'), /field 22/u);
  assert.throws(
    () =>
      parseProcStartTicks(
        `4242 (Surface Thread) S ${[...fields4Through21, '9007199254740992'].join(' ')}`
      ),
    /safe integer/u
  );
});

test('classifies path and device-number transitions independently', () => {
  const node = (devicePath, rdevHex) => ({ devicePath, stat: { rdevHex } });
  assert.equal(
    classifyDeviceTransition(node('/dev/hidraw0', 'f3:0'), node('/dev/hidraw0', 'f3:0')),
    'same-path-same-rdev'
  );
  assert.equal(
    classifyDeviceTransition(node('/dev/hidraw0', 'f3:0'), node('/dev/hidraw0', 'f3:1')),
    'same-path-changed-rdev'
  );
  assert.equal(
    classifyDeviceTransition(node('/dev/hidraw0', 'f3:0'), node('/dev/hidraw1', 'f3:0')),
    'changed-path-same-rdev'
  );
  assert.equal(
    classifyDeviceTransition(node('/dev/hidraw0', 'f3:0'), node('/dev/hidraw1', 'f3:1')),
    'changed-path-changed-rdev'
  );
  assert.throws(
    () => classifyDeviceTransition(node('/dev/hidraw0', 'f3:0'), { devicePath: '/dev/hidraw0' }),
    /rdevHex/u
  );
});

test('counts only exact-device Companion acquisition markers', () => {
  const serial = 'A00SA5492OQMLF';
  const markers = logMarkers(
    [
      `companion | Opening surface panel: streamdeck:${serial} - Elgato Stream Deck MK.2`,
      `companion | Surface panel ready: streamdeck:${serial}`,
      `companion | Error opening discovered surface streamdeck:${serial}: cannot open device with path /dev/hidraw1`,
      'companion | Surface panel ready: streamdeck:ANOTHER-SERIAL',
      `companion | Error opening discovered surface streamdeck:${serial}: cannot open device with path /dev/hidraw9`,
    ].join('\n'),
    serial,
    ['/dev/hidraw0', '/dev/hidraw1']
  );
  assert.deepEqual(
    { opening: markers.opening, ready: markers.ready, openFailed: markers.openFailed },
    { opening: 1, ready: 1, openFailed: 1 }
  );
  assert.equal(markers.relevantLines.length, 3);
  assert.throws(() => logMarkers('logs', serial, []), /at least one/u);
});

test('matches a surface descriptor by rdev rather than a stale or reused path', () => {
  const snapshot = {
    surfaceProcesses: [
      {
        fileDescriptors: [
          { target: '/dev/hidraw0', stat: { rdevHex: 'f3:0' } },
          { target: '/dev/null', stat: { rdevHex: '1:3' } },
        ],
      },
    ],
  };
  assert.equal(
    fileDescriptorMatchesDevice(snapshot, {
      devicePath: '/dev/hidraw7',
      stat: { rdevHex: '0F3:00' },
    }),
    true
  );
  assert.equal(
    fileDescriptorMatchesDevice(snapshot, {
      devicePath: '/dev/hidraw0',
      stat: { rdevHex: 'f3:1' },
    }),
    false
  );
  assert.equal(fileDescriptorMatchesDevice({}, { stat: { rdevHex: 'f3:0' } }), false);
});

test('requires complete unchanged top-level lifecycle identities', () => {
  const before = {
    overlaykit: {
      containerId: 'overlaykit-id',
      startedAt: '2026-07-25T21:00:00Z',
      restartCount: 0,
      pid1StartTicks: 100,
    },
    companion: {
      containerId: 'companion-id',
      startedAt: '2026-07-25T21:00:01Z',
      restartCount: 0,
      pid1StartTicks: 200,
    },
  };
  assert.equal(sameTopLevelLifecycle(before, structuredClone(before)), true);
  assert.equal(
    sameTopLevelLifecycle(before, {
      ...structuredClone(before),
      companion: { ...before.companion, restartCount: 1 },
    }),
    false
  );
  assert.equal(
    sameTopLevelLifecycle(before, {
      ...structuredClone(before),
      overlaykit: { ...before.overlaykit, pid1StartTicks: undefined },
    }),
    false
  );
  assert.equal(sameTopLevelLifecycle({}, {}), false);
});

test('filters command events after an exclusive and through an inclusive boundary', () => {
  const command = (eventSequence) => ({
    eventSequence,
    messageType: 'device.command.execute',
    operationId: `op-${eventSequence}`,
  });
  const selected = commandsBetween(
    [
      command(10),
      command(11),
      { eventSequence: 11, messageType: 'device.state.ack' },
      command(12),
      command(13),
    ],
    10,
    12
  );
  assert.deepEqual(
    selected.map(({ eventSequence }) => eventSequence),
    [11, 12]
  );
  assert.throws(
    () => commandsBetween([{ messageType: 'device.command.execute' }], 10, 12),
    /eventSequence/u
  );
  assert.throws(() => commandsBetween([], 12, 10), /ordered/u);
});

test('validates the exact Companion 4.3.3 toggle action and state feedback configuration', () => {
  const expected = {
    actionId: 'action-h039',
    feedbackId: 'feedback-h039',
    connectionId: 'connection-h039',
    binding: 'lower-third.visibility',
  };
  const controlConfig = {
    type: 'button',
    steps: {
      'step-h039': {
        action_sets: {
          down: [
            {
              id: expected.actionId,
              type: 'action',
              definitionId: 'visibility.toggle',
              connectionId: expected.connectionId,
              options: {
                binding: { isExpression: false, value: expected.binding },
              },
            },
          ],
          up: [],
          rotate_left: undefined,
          rotate_right: undefined,
        },
        options: { runWhileHeld: [] },
      },
    },
    feedbacks: [
      {
        id: expected.feedbackId,
        type: 'feedback',
        definitionId: 'visibility.state',
        connectionId: expected.connectionId,
        options: {
          binding: { isExpression: false, value: expected.binding },
        },
      },
    ],
  };
  assert.equal(validateControlConfiguration(controlConfig, expected), true);

  const actionMutations = [
    (entity) => {
      entity.id = 'another-action';
    },
    (entity) => {
      entity.type = 'feedback';
    },
    (entity) => {
      entity.definitionId = 'visibility.show';
    },
    (entity) => {
      entity.connectionId = 'another-connection';
    },
    (entity) => {
      delete entity.options.binding;
    },
    (entity) => {
      entity.options.binding.isExpression = true;
    },
    (entity) => {
      entity.options.binding.value = 'another-binding';
    },
    (entity) => {
      entity.options.binding.extra = true;
    },
  ];
  for (const mutate of actionMutations) {
    const changed = structuredClone(controlConfig);
    mutate(changed.steps['step-h039'].action_sets.down[0]);
    assert.equal(validateControlConfiguration(changed, expected), false);
  }

  const feedbackMutations = [
    (entity) => {
      entity.id = 'another-feedback';
    },
    (entity) => {
      entity.type = 'action';
    },
    (entity) => {
      entity.definitionId = 'visibility.changed';
    },
    (entity) => {
      entity.connectionId = 'another-connection';
    },
    (entity) => {
      delete entity.options.binding;
    },
    (entity) => {
      entity.options.binding.isExpression = true;
    },
    (entity) => {
      entity.options.binding.value = 'another-binding';
    },
    (entity) => {
      entity.options.binding.extra = true;
    },
  ];
  for (const mutate of feedbackMutations) {
    const changed = structuredClone(controlConfig);
    mutate(changed.feedbacks[0]);
    assert.equal(validateControlConfiguration(changed, expected), false);
  }
});

test('rejects missing, duplicate, and malformed Companion control entities', () => {
  const expected = {
    actionId: 'action-h039',
    feedbackId: 'feedback-h039',
    connectionId: 'connection-h039',
    binding: 'lower-third.visibility',
  };
  const action = {
    id: expected.actionId,
    type: 'action',
    definitionId: 'visibility.toggle',
    connectionId: expected.connectionId,
    options: { binding: { isExpression: false, value: expected.binding } },
  };
  const feedback = {
    id: expected.feedbackId,
    type: 'feedback',
    definitionId: 'visibility.state',
    connectionId: expected.connectionId,
    options: { binding: { isExpression: false, value: expected.binding } },
  };
  const valid = {
    type: 'button',
    steps: {
      step: {
        action_sets: { down: [action] },
      },
    },
    feedbacks: [feedback],
  };
  const invalidConfigurations = [
    null,
    [],
    {},
    { ...valid, type: 'trigger' },
    { ...valid, steps: [] },
    { ...valid, steps: { step: null } },
    { ...valid, steps: { step: {} } },
    { ...valid, steps: { step: { action_sets: [] } } },
    { ...valid, steps: { step: { action_sets: { down: {} } } } },
    { ...valid, steps: { step: { action_sets: { down: null } } } },
    { ...valid, steps: { step: { action_sets: { down: [null] } } } },
    { ...valid, steps: { step: { action_sets: { down: [] } } } },
    { ...valid, feedbacks: {} },
    { ...valid, feedbacks: [] },
    {
      ...valid,
      steps: { step: { action_sets: { down: [action, structuredClone(action)] } } },
    },
    { ...valid, feedbacks: [feedback, structuredClone(feedback)] },
    {
      ...valid,
      feedbacks: [{ ...feedback, id: expected.actionId }],
    },
  ];
  for (const invalid of invalidConfigurations) {
    assert.equal(validateControlConfiguration(invalid, expected), false);
  }

  for (const invalidExpected of [
    null,
    {},
    { ...expected, actionId: '' },
    { ...expected, feedbackId: null },
    { ...expected, connectionId: undefined },
    { ...expected, binding: [] },
    { ...expected, feedbackId: expected.actionId },
  ]) {
    assert.equal(validateControlConfiguration(valid, invalidExpected), false);
  }
});

test('classifies the exhaustive post-reconnect settled-result matrix fail-closed', () => {
  const fulfilled = { status: 'fulfilled', value: { observed: true } };
  const rejected = { status: 'rejected', reason: new Error('bounded failure') };
  const matrix = [
    {
      satellite: fulfilled,
      causal: fulfilled,
      expected: 'supported',
    },
    {
      satellite: fulfilled,
      causal: rejected,
      expected: 'refuted',
    },
    {
      satellite: rejected,
      causal: fulfilled,
      expected: 'inconclusive',
    },
    {
      satellite: rejected,
      causal: rejected,
      expected: 'inconclusive',
    },
  ];
  for (const { satellite, causal, expected } of matrix) {
    assert.equal(classifyPostReconnectOutcome(satellite, causal), expected);
  }
});

test('classifies malformed or unsettled post-reconnect evidence as inconclusive', () => {
  const fulfilled = { status: 'fulfilled', value: undefined };
  for (const malformed of [
    null,
    undefined,
    {},
    [],
    { status: 'pending' },
    { status: 'FULFILLED' },
  ]) {
    assert.equal(classifyPostReconnectOutcome(malformed, fulfilled), 'inconclusive');
    assert.equal(classifyPostReconnectOutcome(fulfilled, malformed), 'inconclusive');
  }
});

test('uses an H-039-prefixed unique run identity', () => {
  assert.match(runId(), /^h039-[0-9TZ-]+-[0-9a-f]{8}$/u);
});
