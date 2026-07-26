import { randomBytes } from 'node:crypto';

export { canonicalJson, sha256, sha256Canonical } from '../h038/physical-lib.mjs';

export const H039_CLAIM_BOUNDARY = Object.freeze({
  proves: [
    'post-login behavior on the exact Fedora 43 host and physical MK.2 identity',
    'one human-bounded USB disappearance and return while the configured stack remains continuously alive',
    'before-and-after hidraw identity by device number rather than path alone',
    'either automatic reacquisition followed by causally acknowledged physical input or a bounded recovery refutation',
    'release of temporary containers, configuration, and currently enumerable matching hidraw nodes after the run',
  ],
  excludes: [
    'pre-login startup or availability',
    'rendered hardware pixels or operator perception',
    'reboot recovery or persistence across process restart',
    'native Fedora packaging or production container, udev, or service architecture',
    'multiple Stream Deck devices, long outages, or support beyond the exact tested identities',
    'OBS output truth or complete production support',
  ],
});

export function runId() {
  return `h039-${new Date().toISOString().replaceAll(/[:.]/gu, '-')}-${randomBytes(4).toString('hex')}`;
}

function requiredString(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty string`);
  }
  return value;
}

function normalizeRdevHex(value, label = 'rdevHex') {
  const match = /^([0-9a-f]+):([0-9a-f]+)$/iu.exec(requiredString(value, label));
  if (!match) throw new Error(`${label} must contain hexadecimal major:minor device numbers`);
  const major = Number.parseInt(match[1], 16);
  const minor = Number.parseInt(match[2], 16);
  if (!Number.isSafeInteger(major) || !Number.isSafeInteger(minor)) {
    throw new Error(`${label} exceeds the safe integer range`);
  }
  return `${major.toString(16)}:${minor.toString(16)}`;
}

export function parseStatIdentity(value) {
  const text = requiredString(value, 'stat identity').trim();
  if (text.includes('\n') || text.includes('\r')) {
    throw new Error('stat identity must contain exactly one record');
  }
  const fields = text.split('|');
  if (fields.length !== 3) {
    throw new Error('stat identity must have rdev, inode, and type fields');
  }
  const rdevHex = normalizeRdevHex(fields[0], 'stat rdev');
  if (!/^[0-9]+$/u.test(fields[1])) {
    throw new Error('stat inode must be an unsigned decimal integer');
  }
  const inode = Number(fields[1]);
  if (!Number.isSafeInteger(inode)) {
    throw new Error('stat inode exceeds the safe integer range');
  }
  const type = fields[2].trim();
  if (type.length === 0) throw new Error('stat type must be present');
  const [majorHex, minorHex] = rdevHex.split(':');
  return {
    rdevHex,
    major: Number.parseInt(majorHex, 16),
    minor: Number.parseInt(minorHex, 16),
    inode,
    type,
  };
}

export function parseProcStartTicks(value) {
  const text = requiredString(value, 'proc stat').trim();
  if (text.includes('\n') || text.includes('\r')) {
    throw new Error('proc stat must contain exactly one record');
  }
  const match = /^([1-9][0-9]*)\s+\((.*)\)\s+([A-Za-z])\s+(.+)$/u.exec(text);
  if (!match) throw new Error('proc stat record is malformed');
  const pid = Number(match[1]);
  if (!Number.isSafeInteger(pid)) throw new Error('proc stat pid exceeds the safe integer range');
  if (!/^[RSDZTWtXxKWPIN]$/u.test(match[3])) {
    throw new Error(`proc stat has an unknown process state: ${match[3]}`);
  }
  const fieldsAfterState = match[4].trim().split(/\s+/u);
  const startTicks = fieldsAfterState[18];
  if (fieldsAfterState.length < 19 || !/^[0-9]+$/u.test(startTicks ?? '')) {
    throw new Error('proc stat lacks a valid field 22 start time');
  }
  const parsed = Number(startTicks);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error('proc stat start time exceeds the safe integer range');
  }
  return parsed;
}

function deviceNodeIdentity(node, label) {
  if (node === null || typeof node !== 'object' || Array.isArray(node)) {
    throw new TypeError(`${label} must be a device-node object`);
  }
  const devicePath = requiredString(node.devicePath, `${label}.devicePath`);
  const rdevHex = normalizeRdevHex(node.stat?.rdevHex, `${label}.stat.rdevHex`);
  return { devicePath, rdevHex };
}

export function classifyDeviceTransition(beforeNode, afterNode) {
  const before = deviceNodeIdentity(beforeNode, 'beforeNode');
  const after = deviceNodeIdentity(afterNode, 'afterNode');
  const path = before.devicePath === after.devicePath ? 'same-path' : 'changed-path';
  const rdev = before.rdevHex === after.rdevHex ? 'same-rdev' : 'changed-rdev';
  return `${path}-${rdev}`;
}

export function logMarkers(logs, serial, paths) {
  requiredString(logs, 'logs');
  requiredString(serial, 'serial');
  if (!Array.isArray(paths) || paths.length === 0) {
    throw new TypeError('paths must contain at least one device path');
  }
  const exactPaths = paths.map((path, index) => requiredString(path, `paths[${index}]`));
  const identity = `streamdeck:${serial}`;
  const relevantLines = [];
  let opening = 0;
  let ready = 0;
  let openFailed = 0;
  for (const rawLine of logs.replace(/\u001b\[[0-9;]*m/gu, '').split(/\r?\n/u)) {
    const line = rawLine.trim();
    if (line.length === 0 || !line.includes(identity)) continue;
    const isOpening = line.includes(`Opening surface panel: ${identity}`);
    const isReady = line.includes(`Surface panel ready: ${identity}`);
    const isOpenFailure = exactPaths.some((path) =>
      line.includes(`cannot open device with path ${path}`)
    );
    if (isOpening) opening += 1;
    if (isReady) ready += 1;
    if (isOpenFailure) openFailed += 1;
    if (isOpening || isReady || isOpenFailure) relevantLines.push(line);
  }
  return { opening, ready, openFailed, relevantLines };
}

export function fileDescriptorMatchesDevice(surfaceSnapshot, hostNode) {
  let expectedRdev;
  try {
    expectedRdev = normalizeRdevHex(hostNode?.stat?.rdevHex, 'hostNode.stat.rdevHex');
  } catch {
    return false;
  }
  if (!Array.isArray(surfaceSnapshot?.surfaceProcesses)) return false;
  return surfaceSnapshot.surfaceProcesses.some(
    (process) =>
      Array.isArray(process?.fileDescriptors) &&
      process.fileDescriptors.some((descriptor) => {
        try {
          return (
            normalizeRdevHex(descriptor?.stat?.rdevHex, 'descriptor.stat.rdevHex') === expectedRdev
          );
        } catch {
          return false;
        }
      })
  );
}

function completeLifecycle(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    typeof value.containerId === 'string' &&
    value.containerId.length > 0 &&
    typeof value.startedAt === 'string' &&
    value.startedAt.length > 0 &&
    Number.isSafeInteger(value.restartCount) &&
    value.restartCount >= 0 &&
    Number.isSafeInteger(value.pid1StartTicks) &&
    value.pid1StartTicks >= 0
  );
}

export function sameTopLevelLifecycle(before, after) {
  for (const service of ['overlaykit', 'companion']) {
    const left = before?.[service];
    const right = after?.[service];
    if (!completeLifecycle(left) || !completeLifecycle(right)) return false;
    if (
      left.containerId !== right.containerId ||
      left.startedAt !== right.startedAt ||
      left.restartCount !== right.restartCount ||
      left.pid1StartTicks !== right.pid1StartTicks
    ) {
      return false;
    }
  }
  return true;
}

export function commandsBetween(events, afterExclusive, throughInclusive) {
  if (!Array.isArray(events)) throw new TypeError('events must be an array');
  if (
    !Number.isSafeInteger(afterExclusive) ||
    !Number.isSafeInteger(throughInclusive) ||
    throughInclusive < afterExclusive
  ) {
    throw new Error('command event bounds must be ordered safe integers');
  }
  return events.filter((event) => {
    if (event?.messageType !== 'device.command.execute') return false;
    if (!Number.isSafeInteger(event.eventSequence)) {
      throw new Error('device.command.execute lacks a valid eventSequence');
    }
    return event.eventSequence > afterExclusive && event.eventSequence <= throughInclusive;
  });
}

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isEntityModel(value, type) {
  return (
    isPlainRecord(value) &&
    typeof value.id === 'string' &&
    value.id.length > 0 &&
    value.type === type &&
    typeof value.definitionId === 'string' &&
    value.definitionId.length > 0 &&
    typeof value.connectionId === 'string' &&
    value.connectionId.length > 0 &&
    isPlainRecord(value.options)
  );
}

function exactLiteralBinding(value, expectedValue) {
  if (!isPlainRecord(value)) return false;
  const keys = Object.keys(value).sort();
  return (
    keys.length === 2 &&
    keys[0] === 'isExpression' &&
    keys[1] === 'value' &&
    value.isExpression === false &&
    value.value === expectedValue
  );
}

export function validateControlConfiguration(controlConfig, expected) {
  try {
    if (
      !isPlainRecord(controlConfig) ||
      controlConfig.type !== 'button' ||
      !isPlainRecord(expected)
    ) {
      return false;
    }
    for (const key of ['actionId', 'feedbackId', 'connectionId', 'binding']) {
      if (typeof expected[key] !== 'string' || expected[key].length === 0) return false;
    }
    if (expected.actionId === expected.feedbackId) return false;
    if (!isPlainRecord(controlConfig.steps) || !Array.isArray(controlConfig.feedbacks)) {
      return false;
    }

    const actions = [];
    for (const step of Object.values(controlConfig.steps)) {
      if (!isPlainRecord(step) || !isPlainRecord(step.action_sets)) return false;
      for (const actionSet of Object.values(step.action_sets)) {
        if (actionSet === undefined) continue;
        if (!Array.isArray(actionSet)) return false;
        for (const entity of actionSet) {
          if (!isEntityModel(entity, 'action')) return false;
          actions.push(entity);
        }
      }
    }

    const feedbacks = [];
    for (const entity of controlConfig.feedbacks) {
      if (!isEntityModel(entity, 'feedback')) return false;
      feedbacks.push(entity);
    }

    const entityIds = new Set();
    for (const entity of [...actions, ...feedbacks]) {
      if (entityIds.has(entity.id)) return false;
      entityIds.add(entity.id);
    }

    const matchingActions = actions.filter((entity) => entity.id === expected.actionId);
    const matchingFeedbacks = feedbacks.filter((entity) => entity.id === expected.feedbackId);
    if (matchingActions.length !== 1 || matchingFeedbacks.length !== 1) return false;
    const action = matchingActions[0];
    const feedback = matchingFeedbacks[0];
    return (
      action.definitionId === 'visibility.toggle' &&
      action.connectionId === expected.connectionId &&
      exactLiteralBinding(action.options.binding, expected.binding) &&
      feedback.definitionId === 'visibility.state' &&
      feedback.connectionId === expected.connectionId &&
      exactLiteralBinding(feedback.options.binding, expected.binding)
    );
  } catch {
    return false;
  }
}

function settledStatus(result) {
  if (result === null || typeof result !== 'object' || Array.isArray(result)) return null;
  if (result.status === 'fulfilled' || result.status === 'rejected') return result.status;
  return null;
}

export function classifyPostReconnectOutcome(satelliteResult, causalResult) {
  const satelliteStatus = settledStatus(satelliteResult);
  const causalStatus = settledStatus(causalResult);
  if (satelliteStatus === 'fulfilled' && causalStatus === 'fulfilled') return 'supported';
  if (satelliteStatus === 'fulfilled' && causalStatus === 'rejected') return 'refuted';
  return 'inconclusive';
}
