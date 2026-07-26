#!/usr/bin/env node

import Ajv2020 from 'ajv/dist/2020.js';
import { readFileSync } from 'node:fs';
import { mkdir, readFile, readdir, rename, unlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { command } from '../h034/lib/util.mjs';
import { selectGraphicalSession } from '../h038/physical-lib.mjs';
import {
  captureHostSnapshot,
  ownerObservation,
  waitForStableHostState,
} from '../h039/host-observer.mjs';
import { classifyDeviceTransition, sha256, sha256Canonical } from '../h039/reconnect-lib.mjs';
import { inventoryHostHidraw, selectExactTargetHidraw } from '../h041/host-inventory.mjs';
import {
  descriptorMatchesDynamicNode,
  dynamicStageMatchesHost,
  hostEpochChanged,
  sameTopLevelLifecycle,
} from '../h041/reacquisition-lib.mjs';
import { verifyDynamicReacquisitionRun } from '../h041/verify.mjs';
import {
  CONTAINER_OBSERVER,
  CONTAINER_SIGNAL_HELPER,
  DYNAMIC_ROOT,
  EXPECTED_IMAGE_ID,
  EXPECTED_IMAGE_REVISION,
  H042_REQUIRED_SOURCES,
  LAB_DIRECTORY,
  OFFICIAL_IMAGE,
  REPOSITORY_ROOT,
  analyzeCleanupEvents,
  analyzeExperimentEvents,
  auditEntry,
  baselineAcquired,
  buildDockerRunArguments,
  descriptorAbsent,
  invocationAudit,
  normalizeDockerLogs,
  observeContainer,
  parseDockerEvents,
  permissionBoundaryExact,
  runtimePollText,
  targetDescriptors,
} from './runtime-lib.mjs';
import {
  H042_CLAIM_BOUNDARY,
  POST_SIGNAL_SECONDS,
  PRE_SIGNAL_SECONDS,
  classifyH042Outcome,
  exactWorkerIdentity,
  markerDelta,
  replacementTimeline,
  rfc3339NanoToEpochNs,
  runId as createRunId,
  sameWorker,
  selectUniqueWorker,
} from './signal-lib.mjs';

const EXPECTED_H041_EVIDENCE = 'c430a034e684dd3d492e1a750aa8ff0fdd6fa5d53f3772ee63b5876040f1392a';
const EXPECTED_H041_FILE = 'b1bc36cb4c480ca0e34ae9a5810d9ea890e1d44242b2525789da443fa720acd4';
const DEFAULT_H041 = 'artifacts/h041/h041-2026-07-26T00-56-42-118Z-0423725f/run.json';
const TARGET_VENDOR_ID = '0fd9';
const TARGET_PRODUCT_ID = '0080';
const DEVICE_ACCESS_KEYS = [
  'mode',
  'uid',
  'gid',
  'rdev',
  'major',
  'minor',
  'rdevHex',
  'isCharacterDevice',
];
const H041_ARTIFACT_DIRECTORY = path.join(REPOSITORY_ROOT, 'artifacts/h041');

export function parseArgs(argv) {
  const options = {
    h041: DEFAULT_H041,
    evidenceDirectory: null,
    transitionWindowSeconds: 120,
    baselineWindowSeconds: 30,
    absentDescriptorWindowSeconds: 5,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--h041') options.h041 = argv[++index] ?? '';
    else if (argument === '--evidence-dir') options.evidenceDirectory = argv[++index] ?? '';
    else if (argument === '--transition-seconds') {
      options.transitionWindowSeconds = Number(argv[++index]);
    } else if (argument === '--baseline-seconds') {
      options.baselineWindowSeconds = Number(argv[++index]);
    } else if (argument === '--absent-descriptor-seconds') {
      options.absentDescriptorWindowSeconds = Number(argv[++index]);
    } else {
      throw new Error(`Unknown H-042 argument: ${argument}`);
    }
  }
  for (const [value, minimum, maximum, label] of [
    [options.transitionWindowSeconds, 20, 300, 'transition'],
    [options.baselineWindowSeconds, 10, 90, 'baseline'],
    [options.absentDescriptorWindowSeconds, 1, 30, 'absent descriptor'],
  ]) {
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
      throw new Error(`H-042 ${label} window must be between ${minimum} and ${maximum} seconds`);
    }
  }
  return options;
}

function repositoryPath(relativePath, label) {
  const absolute = path.resolve(REPOSITORY_ROOT, relativePath);
  if (!absolute.startsWith(`${REPOSITORY_ROOT}${path.sep}`)) {
    throw new Error(`${label} must remain inside the repository`);
  }
  return absolute;
}

export function canonicalH041Path(candidate) {
  const absolute = repositoryPath(candidate, 'H-041 input');
  if (
    !absolute.startsWith(`${H041_ARTIFACT_DIRECTORY}${path.sep}`) ||
    path.extname(absolute) !== '.json'
  ) {
    throw new Error('H-042 H-041 input must resolve inside artifacts/h041 as JSON');
  }
  return absolute;
}

export function collectSourceHashes() {
  return Object.fromEntries(
    H042_REQUIRED_SOURCES.map((relativePath) => [
      relativePath,
      sha256(readFileSync(path.join(REPOSITORY_ROOT, relativePath))),
    ])
  );
}

function parseOsRelease(text) {
  return Object.fromEntries(
    text
      .split(/\r?\n/u)
      .filter((line) => line.includes('='))
      .map((line) => {
        const separator = line.indexOf('=');
        const key = line.slice(0, separator);
        const raw = line.slice(separator + 1);
        const value =
          raw.length >= 2 &&
          ((raw.startsWith('"') && raw.endsWith('"')) || (raw.startsWith("'") && raw.endsWith("'")))
            ? raw.slice(1, -1)
            : raw;
        return [key, value];
      })
  );
}

async function observePrincipal(expectedUser) {
  const [user, uid, primaryGroup, gid, gids, groupNames] = await Promise.all([
    command('id', ['-un', expectedUser]),
    command('id', ['-u', expectedUser]),
    command('id', ['-gn', expectedUser]),
    command('id', ['-g', expectedUser]),
    command('id', ['-G', expectedUser]),
    command('id', ['-Gn', expectedUser]),
  ]);
  const observedGids = gids.stdout.trim().split(/\s+/u).map(Number);
  const observedNames = groupNames.stdout.trim().split(/\s+/u);
  if (
    observedGids.length !== observedNames.length ||
    observedGids.some((value) => !Number.isSafeInteger(value) || value < 0)
  ) {
    throw new Error('H-042 could not bind principal groups');
  }
  return {
    user: user.stdout.trim(),
    uid: Number(uid.stdout.trim()),
    primaryGroup: primaryGroup.stdout.trim(),
    gid: Number(gid.stdout.trim()),
    groups: observedGids
      .map((observedGid, index) => ({ gid: observedGid, name: observedNames[index] }))
      .sort((left, right) => left.gid - right.gid),
  };
}

async function observeHostIdentity(expectedUser) {
  const [osReleaseText, kernel, machine, principal] = await Promise.all([
    readFile('/etc/os-release', 'utf8'),
    command('uname', ['-r']),
    command('uname', ['-m']),
    observePrincipal(expectedUser),
  ]);
  const release = parseOsRelease(osReleaseText);
  return {
    observedAt: new Date().toISOString(),
    osId: release.ID,
    osVersion: release.VERSION_ID,
    kernel: kernel.stdout.trim(),
    architecture: os.arch(),
    machine: machine.stdout.trim(),
    principal,
  };
}

async function graphicalSession(principal) {
  const listed = await command('loginctl', ['list-sessions', '--no-legend', '--no-pager']);
  const ids = listed.stdout
    .split(/\r?\n/u)
    .map((line) => line.trim().split(/\s+/u)[0])
    .filter(Boolean);
  const sessions = [];
  for (const id of ids) {
    const observed = await command('loginctl', [
      'show-session',
      id,
      '--property=Id',
      '--property=Name',
      '--property=Active',
      '--property=State',
      '--property=Class',
      '--property=Remote',
      '--property=Type',
      '--property=Seat',
      '--property=TTY',
    ]);
    sessions.push(
      Object.fromEntries(
        observed.stdout
          .split(/\r?\n/u)
          .filter((line) => line.includes('='))
          .map((line) => {
            const separator = line.indexOf('=');
            return [line.slice(0, separator), line.slice(separator + 1)];
          })
      )
    );
  }
  const selected = selectGraphicalSession(sessions, principal);
  if (!selected) throw new Error(`No active local graphical session exists for ${principal}`);
  return { selected, observed: sessions };
}

function exactNode(snapshot, label) {
  const matches = snapshot.hidraw.filter((entry) => entry.serialMatches);
  if (snapshot.state !== 'present' || matches.length !== 1 || matches[0].stat === null) {
    throw new Error(`H-042 expected one exact present node at ${label}`);
  }
  return matches[0];
}

function sameDeviceAccessBoundary(reference, candidate) {
  return (
    reference !== null &&
    candidate !== null &&
    typeof reference === 'object' &&
    typeof candidate === 'object' &&
    reference.isCharacterDevice === true &&
    DEVICE_ACCESS_KEYS.every(
      (key) => Object.hasOwn(reference, key) && reference[key] === candidate[key]
    )
  );
}

function samePresentHostEpoch(reference, candidate) {
  if (
    reference?.state !== 'present' ||
    candidate?.state !== 'present' ||
    reference.expectedSerial !== candidate.expectedSerial ||
    reference.scope?.bootId !== candidate.scope?.bootId ||
    reference.scope?.mountNamespace !== candidate.scope?.mountNamespace ||
    !Array.isArray(reference.hidraw) ||
    !Array.isArray(candidate.hidraw) ||
    !Array.isArray(reference.errors) ||
    reference.errors.length !== 0 ||
    !Array.isArray(candidate.errors) ||
    candidate.errors.length !== 0
  ) {
    return false;
  }
  const referenceNodes = reference.hidraw.filter((entry) => entry.serialMatches);
  const candidateNodes = candidate.hidraw.filter((entry) => entry.serialMatches);
  return (
    referenceNodes.length === 1 &&
    candidateNodes.length === 1 &&
    referenceNodes[0].devicePath === candidateNodes[0].devicePath &&
    sha256Canonical(referenceNodes[0].stat) === sha256Canonical(candidateNodes[0].stat) &&
    !hostEpochChanged(reference, candidate)
  );
}

function openWindow(stage, challenge, timeoutSeconds, instruction) {
  return {
    stage,
    challenge,
    timeoutSeconds,
    instruction,
    openedAt: new Date().toISOString(),
    openedMonotonicNs: process.hrtime.bigint().toString(),
    closedAt: null,
    closedMonotonicNs: null,
  };
}

function closeWindow(window) {
  window.closedAt = new Date().toISOString();
  window.closedMonotonicNs = process.hrtime.bigint().toString();
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function withoutLogs({ logText: _logText, logRecords: _logRecords, ...runtime }) {
  return runtime;
}

function compactHostTimeline(entries) {
  return `${entries.map((entry) => JSON.stringify(entry)).join('\n')}\n`;
}

async function waitForBaseline(options) {
  const deadline = process.hrtime.bigint() + BigInt(options.timeoutSeconds) * 1_000_000_000n;
  while (process.hrtime.bigint() < deadline) {
    const runtime = await observeContainer(
      options.containerName,
      { ...options.runtime, phase: 'baseline-poll' },
      options.entries
    );
    options.polls.push(runtime);
    if (baselineAcquired(runtime)) return runtime;
    await sleep(500);
  }
  throw new Error('H-042 baseline acquisition did not complete');
}

async function waitForAbsent(options) {
  const deadline = process.hrtime.bigint() + BigInt(options.timeoutSeconds) * 1_000_000_000n;
  let runtime = null;
  while (process.hrtime.bigint() < deadline) {
    runtime = await observeContainer(
      options.containerName,
      { ...options.runtime, phase: 'absent-poll' },
      options.entries
    );
    options.polls.push(runtime);
    if (descriptorAbsent(runtime)) return runtime;
    await sleep(250);
  }
  throw new Error('H-042 did not observe descriptor absence');
}

export function markersUnchanged(reference, candidate) {
  return (
    candidate.opening === reference.opening &&
    candidate.ready === reference.ready &&
    candidate.openFailed === reference.openFailed &&
    sha256Canonical(candidate.relevantLines) === sha256Canonical(reference.relevantLines)
  );
}

async function runPreSignalControl(options) {
  const startedNs = BigInt(options.startedMonotonicNs);
  const deadline = startedNs + BigInt(PRE_SIGNAL_SECONDS) * 1_000_000_000n;
  const local = [];
  let first = null;
  let final = null;
  let boundaryNegative = false;
  do {
    final = await observeContainer(
      options.containerName,
      { ...options.runtime, phase: 'pre-signal-poll' },
      options.entries
    );
    first ??= final;
    local.push(final);
    options.polls.push(final);
    const worker = selectUniqueWorker(final, { deviceGid: options.deviceGid });
    const negative =
      targetDescriptors(final).length === 0 &&
      markersUnchanged(options.baselineMarkers, final.markers);
    if (
      worker === null ||
      !sameWorker(options.oldWorker, worker) ||
      !sameTopLevelLifecycle(options.initialLifecycle, final.lifecycle) ||
      !dynamicStageMatchesHost({
        hostNode: options.returnedNode,
        dynamic: final.observer.paths.dynamic.stat,
      }) ||
      !permissionBoundaryExact(final, {
        deviceGid: options.deviceGid,
        cgroupRule: options.cgroupRule,
        dynamicPath: options.runtime.dynamicPath,
      })
    ) {
      throw new Error('H-042 pre-signal worker or top-level identity drifted');
    }
    if (!negative) {
      throw new Error(
        'H-042 automatic recovery appeared during the negative control; no signal was issued'
      );
    }
    if (BigInt(final.monotonicNs) >= deadline) boundaryNegative = true;
    if (BigInt(final.monotonicNs) < deadline) await sleep(500);
  } while (BigInt(final.monotonicNs) < deadline);
  const completedNs = process.hrtime.bigint();
  return {
    first,
    final,
    polls: local,
    window: {
      startedAt: options.startedAt,
      startedMonotonicNs: startedNs.toString(),
      completedAt: new Date().toISOString(),
      completedMonotonicNs: completedNs.toString(),
      timeoutSeconds: PRE_SIGNAL_SECONDS,
      deadlineExpired: completedNs >= deadline,
      boundaryNegative,
    },
  };
}

function replacementOwnsCurrentDescriptor(replacement, runtime) {
  return (
    replacement !== null &&
    replacement.fileDescriptors.some((descriptor) =>
      descriptorMatchesDynamicNode(descriptor, runtime.observer.paths.dynamic.stat)
    )
  );
}

function markerLinesWithinDeadline(delta, deadlineNs) {
  return (
    delta.lines.length > 0 &&
    delta.lines.every((line) => {
      const separator = line.indexOf(' ');
      const observed = rfc3339NanoToEpochNs(separator > 0 ? line.slice(0, separator) : '');
      return observed !== null && observed <= deadlineNs;
    })
  );
}

async function runPostSignalObservation(options) {
  const startedNs = BigInt(options.signal.receivedMonotonicNs);
  const deadline = startedNs + BigInt(POST_SIGNAL_SECONDS) * 1_000_000_000n;
  const wallDeadline =
    rfc3339NanoToEpochNs(options.signal.receivedAt) + BigInt(POST_SIGNAL_SECONDS) * 1_000_000_000n;
  const local = [];
  let final = null;
  let supportObserved = false;
  let boundedDescriptor = false;
  let boundedOpening = false;
  let boundedReady = false;
  let boundedOrdered = false;
  do {
    final = await observeContainer(
      options.containerName,
      { ...options.runtime, phase: 'post-signal-poll' },
      options.entries
    );
    local.push(final);
    options.polls.push(final);
    if (
      !sameTopLevelLifecycle(options.initialLifecycle, final.lifecycle) ||
      !dynamicStageMatchesHost({
        hostNode: options.returnedNode,
        dynamic: final.observer.paths.dynamic.stat,
      }) ||
      !sameDeviceAccessBoundary(
        options.returnedNode.stat,
        final.observer.paths.dynamic.stat.value
      ) ||
      !sameDeviceAccessBoundary(
        options.returnedNode.stat,
        final.observer.paths.compat.stat.value
      ) ||
      !permissionBoundaryExact(final, {
        deviceGid: options.deviceGid,
        cgroupRule: options.cgroupRule,
        dynamicPath: options.runtime.dynamicPath,
      })
    ) {
      throw new Error('H-042 post-signal host proxy or top-level boundary drifted');
    }
    const observedNs = BigInt(final.monotonicNs);
    const timeline = replacementTimeline(options.oldWorker, local, {
      deviceGid: options.deviceGid,
    });
    const delta = markerDelta(options.preSignalMarkers, final.markers, options.signal.receivedAt);
    const descriptor = replacementOwnsCurrentDescriptor(timeline.replacement, final);
    const markersWithin =
      delta.prefixValid && delta.allAfterSignal && markerLinesWithinDeadline(delta, wallDeadline);
    if (observedNs <= deadline) {
      boundedDescriptor ||= descriptor;
      boundedOpening ||= delta.openingObserved && delta.allAfterSignal;
      boundedReady ||= delta.readyObserved && delta.allAfterSignal;
      boundedOrdered ||= delta.ordered && markersWithin;
      supportObserved =
        timeline.oldWorkerExited &&
        timeline.replacementWorkerUnique &&
        timeline.singleReplacementGeneration &&
        timeline.replacementWorkerChanged &&
        descriptor &&
        delta.openingObserved &&
        delta.readyObserved &&
        delta.ordered &&
        markersWithin;
    }
    if (supportObserved) break;
    if (observedNs < deadline) await sleep(500);
  } while (BigInt(final.monotonicNs) < deadline);

  const completedNs = process.hrtime.bigint();
  const boundedPolls = local.filter((runtime) => BigInt(runtime.monotonicNs) <= deadline);
  const boundedTimeline = replacementTimeline(options.oldWorker, boundedPolls, {
    deviceGid: options.deviceGid,
  });
  const fullTimeline = replacementTimeline(options.oldWorker, local, {
    deviceGid: options.deviceGid,
  });
  const finalDelta = markerDelta(
    options.preSignalMarkers,
    final.markers,
    options.signal.receivedAt
  );
  const latePositiveObserved =
    !supportObserved &&
    ((!boundedTimeline.oldWorkerExited && fullTimeline.oldWorkerExited) ||
      (!boundedTimeline.replacementWorkerUnique && fullTimeline.replacementWorkerUnique) ||
      (!boundedDescriptor && replacementOwnsCurrentDescriptor(fullTimeline.replacement, final)) ||
      (!boundedOpening && finalDelta.openingObserved) ||
      (!boundedReady && finalDelta.readyObserved));
  return {
    final,
    polls: local,
    replacement: fullTimeline,
    markerDelta: finalDelta,
    descriptorObserved: boundedDescriptor,
    openingObserved: boundedOpening,
    readyObserved: boundedReady,
    markersOrdered: boundedOrdered,
    latePositiveObserved,
    window: {
      startedAt: options.signal.receivedAt,
      startedMonotonicNs: options.signal.receivedMonotonicNs,
      completedAt: new Date().toISOString(),
      completedMonotonicNs: completedNs.toString(),
      timeoutSeconds: POST_SIGNAL_SECONDS,
      deadlineExpired: completedNs >= deadline,
      supportObserved,
    },
  };
}

async function dockerEvents(containerId, since, until) {
  const receipt = await command('docker', [
    'events',
    '--since',
    since,
    '--until',
    until,
    '--filter',
    `container=${containerId}`,
    '--format',
    '{{json .}}',
  ]);
  return receipt.stdout;
}

async function writeArtifact(directory, name, contents) {
  await writeFile(path.join(directory, name), contents, { mode: 0o600 });
  return { path: name, sha256: sha256(contents) };
}

async function writeFailureArtifact(failurePath, { id, message, draft = null, cleanup = null }) {
  await writeFile(
    failurePath,
    `${JSON.stringify(
      {
        schemaVersion: 'overlaykit-h042-failure/v1',
        hypothesis: 'H-042',
        runId: id,
        classification: 'inconclusive',
        failedAt: new Date().toISOString(),
        message,
        provisional:
          draft === null ? null : { outcome: draft.outcome, predicates: draft.predicates },
        cleanup,
      },
      null,
      2
    )}\n`,
    { mode: 0o600 }
  );
}

export function createFailureContext() {
  let draft = null;
  let cleanup = null;
  return Object.freeze({
    preserve(nextDraft, nextCleanup) {
      draft = nextDraft;
      cleanup = nextCleanup;
    },
    write(failurePath, id, message) {
      return writeFailureArtifact(failurePath, { id, message, draft, cleanup });
    },
  });
}

export function compileEvidenceSchema(schema) {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  ajv.addFormat('date-time', (value) => rfc3339NanoToEpochNs(value) !== null);
  return ajv.compile(schema);
}

export function runStartPrecedesReceipt(startedAt, receiptAt) {
  const startedNs = rfc3339NanoToEpochNs(startedAt);
  const receiptNs = rfc3339NanoToEpochNs(receiptAt);
  return startedNs !== null && receiptNs !== null && startedNs <= receiptNs;
}

export async function runH042(argv = process.argv.slice(2)) {
  const options = parseArgs(argv);
  const [nodeMajor, nodeMinor] = process.versions.node.split('.').map(Number);
  if (nodeMajor !== 22 || nodeMinor < 20) {
    throw new Error('H-042 requires Node >=22.20 and <23');
  }
  const evidenceSchema = JSON.parse(
    await readFile(
      path.join(LAB_DIRECTORY, 'schemas/surface-worker-recycle-run.schema.json'),
      'utf8'
    )
  );
  const validateEvidence = compileEvidenceSchema(evidenceSchema);
  const id = createRunId();
  const startedAt = new Date().toISOString();
  const evidenceDirectory = path.resolve(
    REPOSITORY_ROOT,
    options.evidenceDirectory ?? path.join('artifacts/h042', id)
  );
  if (!evidenceDirectory.startsWith(`${REPOSITORY_ROOT}${path.sep}`)) {
    throw new Error('H-042 evidence directory must remain inside the repository');
  }
  await mkdir(evidenceDirectory, { recursive: true });
  if ((await readdir(evidenceDirectory)).length > 0) {
    throw new Error('H-042 evidence directory must be empty');
  }
  const candidatePath = path.join(evidenceDirectory, 'run.candidate.json');
  const runPath = path.join(evidenceDirectory, 'run.json');
  const verificationPath = path.join(evidenceDirectory, 'verification.json');
  const failurePath = path.join(evidenceDirectory, 'failure.json');
  const verifierFailureContext = createFailureContext();

  const h041Path = canonicalH041Path(options.h041);
  const h041Bytes = await readFile(h041Path);
  const h041 = JSON.parse(h041Bytes);
  const { evidenceSha256: h041Evidence, ...h041Canonical } = h041;
  if (
    sha256(h041Bytes) !== EXPECTED_H041_FILE ||
    h041Evidence !== EXPECTED_H041_EVIDENCE ||
    sha256Canonical(h041Canonical) !== h041Evidence
  ) {
    throw new Error('H-042 rejected stale or invalid H-041 evidence');
  }
  const h041Verification = await verifyDynamicReacquisitionRun(h041Path);
  const storedH041VerificationBytes = await readFile(
    path.join(path.dirname(h041Path), 'verification.json')
  );
  const storedH041Verification = JSON.parse(storedH041VerificationBytes);
  if (
    h041Verification.outcome !== 'refuted' ||
    h041Verification.workerMechanism !== 'same-worker' ||
    h041Verification.cleaned !== true ||
    h041Verification.verified !== true ||
    h041.inputs?.h037?.evidenceSha256 !==
      '22d8f1d440a521af2ec8dd75cbfa68db09b7140c85f90bc48310aa78d27d6e9c' ||
    h041.inputs?.h039?.evidenceSha256 !==
      'e78ed04dd10469e863b33e4fa497ddc745a20574fb18095c2bde7cf3fdb594ce' ||
    h041.inputs?.h040?.evidenceSha256 !==
      '04b3b9aedeb51e1bd5d6c1bd4e68e9d284951d2b21276aea3f5a180f0fe2a108' ||
    sha256(storedH041VerificationBytes) !==
      '7217b3d80f80c8b509388a941c9a6e3752b5036eb0a545cfeafb0a4ffb599426' ||
    storedH041Verification.evidenceSha256 !== EXPECTED_H041_EVIDENCE ||
    storedH041Verification.outcome !== 'refuted' ||
    storedH041Verification.verified !== true ||
    sha256Canonical(storedH041Verification) !== sha256Canonical(h041Verification)
  ) {
    throw new Error('H-042 H-041 predecessor receipt is incomplete');
  }
  const h041VerificationText = `${JSON.stringify(h041Verification, null, 2)}\n`;
  const h041Directory = path.dirname(h041Path);
  const predecessorReceiptSpecs = {
    h037: {
      source: h041.inputs.h037.validationReceipt,
      output: 'h037-validation.json',
      field: 'validationReceipt',
    },
    h039: {
      source: h041.inputs.h039.verificationReceipt,
      output: 'h039-verification.json',
      field: 'verificationReceipt',
    },
    h040: {
      source: h041.inputs.h040.verificationReceipt,
      output: 'h040-verification.json',
      field: 'verificationReceipt',
    },
  };
  const predecessorReceipts = {};
  for (const [key, specification] of Object.entries(predecessorReceiptSpecs)) {
    const bytes = await readFile(path.join(h041Directory, specification.source.path));
    if (sha256(bytes) !== specification.source.sha256) {
      throw new Error(`H-042 rejected the archived ${key.toUpperCase()} receipt`);
    }
    predecessorReceipts[key] = {
      bytes,
      output: specification.output,
      field: specification.field,
    };
  }
  await Promise.all([
    writeFile(path.join(evidenceDirectory, 'h041-verification.json'), storedH041VerificationBytes, {
      mode: 0o600,
    }),
    writeFile(path.join(evidenceDirectory, 'h041-reverification.json'), h041VerificationText, {
      mode: 0o600,
    }),
    ...Object.values(predecessorReceipts).map(({ bytes, output }) =>
      writeFile(path.join(evidenceDirectory, output), bytes, { mode: 0o600 })
    ),
  ]);

  const observedHost = await observeHostIdentity(h041.host.principal.user);
  if (!runStartPrecedesReceipt(startedAt, observedHost.observedAt)) {
    throw new Error('H-042 host identity receipt precedes the run start');
  }
  if (
    observedHost.osId !== h041.host.osId ||
    observedHost.osVersion !== h041.host.osVersion ||
    observedHost.kernel !== h041.host.kernel ||
    observedHost.architecture !== h041.host.architecture ||
    observedHost.machine !== h041.host.machine ||
    sha256Canonical(observedHost.principal) !== sha256Canonical(h041.host.principal)
  ) {
    throw new Error('H-042 current host differs from H-041');
  }
  const session = await graphicalSession(observedHost.principal.user);
  const serial = h041.device.serial;
  const hostTimeline = [];
  const preflightStable = await waitForStableHostState('present', serial, {
    timeoutMs: 10_000,
    previousDevicePath: h041.device.returnedPath,
    timeline: hostTimeline,
  });
  const preflightHost = preflightStable.snapshot;
  if (!runStartPrecedesReceipt(startedAt, preflightHost.capturedAt)) {
    throw new Error('H-042 preflight receipt precedes the run start');
  }
  const preflightNode = exactNode(preflightHost, 'preflight');
  if (!preflightNode.owner?.observed || preflightNode.owner.pids.length > 0) {
    throw new Error('H-042 requires no host-scope owner before the run');
  }
  const initialInventory = await inventoryHostHidraw();
  const selected = selectExactTargetHidraw(initialInventory, {
    vendorId: TARGET_VENDOR_ID,
    productId: TARGET_PRODUCT_ID,
    serial,
  });
  const h041ReturnedSelection = selectExactTargetHidraw(h041.device.returnedInventory, {
    vendorId: TARGET_VENDOR_ID,
    productId: TARGET_PRODUCT_ID,
    serial,
  });
  if (
    selected.devicePath !== preflightNode.devicePath ||
    selected.stat.stable !== true ||
    selected.stat.matchesClass !== true ||
    !sameDeviceAccessBoundary(preflightNode.stat, selected.stat.value) ||
    preflightNode.stat.mode !== '0660' ||
    preflightNode.stat.uid !== 0 ||
    preflightNode.stat.gid !== h041.companion.deviceGid ||
    h041ReturnedSelection.devicePath !== h041.device.returnedPath ||
    h041ReturnedSelection.stat.stable !== true ||
    h041ReturnedSelection.stat.matchesClass !== true ||
    !sameDeviceAccessBoundary(h041ReturnedSelection.stat.value, selected.stat.value)
  ) {
    throw new Error('H-042 target inventory is not exact');
  }
  const deviceGid = preflightNode.stat.gid;
  if (!observedHost.principal.groups.some((group) => group.gid === deviceGid)) {
    throw new Error('H-042 principal lacks the exact device group');
  }

  const initialSourceSha256 = collectSourceHashes();
  const governanceVerify = await command('npm', ['run', 'governance:verify'], {
    cwd: REPOSITORY_ROOT,
  });
  const governanceVerifyText = `${governanceVerify.stdout}${governanceVerify.stderr}`;
  const manifestBytes = await readFile(
    path.join(REPOSITORY_ROOT, '.overlaykit/governance/manifest.json')
  );
  const manifest = JSON.parse(manifestBytes);
  if (
    manifest.changes?.['CHG-0013'] !==
    initialSourceSha256['.overlaykit/governance/changes/CHG-0013.json']
  ) {
    throw new Error('H-042 contract is not manifest-bound');
  }
  await Promise.all([
    writeFile(path.join(evidenceDirectory, 'governance-manifest.json'), manifestBytes, {
      mode: 0o600,
    }),
    writeFile(path.join(evidenceDirectory, 'governance-verify.txt'), governanceVerifyText, {
      mode: 0o600,
    }),
  ]);

  const [imageReceipt, dockerVersionReceipt, dockerInfoReceipt] = await Promise.all([
    command('docker', ['image', 'inspect', OFFICIAL_IMAGE]),
    command('docker', ['version', '--format', '{{json .}}']),
    command('docker', ['info', '--format', '{{json .}}']),
  ]);
  const image = JSON.parse(imageReceipt.stdout)[0];
  const dockerVersion = JSON.parse(dockerVersionReceipt.stdout);
  const dockerInfo = JSON.parse(dockerInfoReceipt.stdout);
  if (
    image.Id !== EXPECTED_IMAGE_ID ||
    image.Config?.Labels?.['org.opencontainers.image.revision'] !== EXPECTED_IMAGE_REVISION ||
    !image.RepoDigests?.includes(
      'ghcr.io/bitfocus/companion/companion@sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e'
    ) ||
    typeof dockerVersion.Server?.Version !== 'string' ||
    typeof dockerInfo.ServerVersion !== 'string'
  ) {
    throw new Error('H-042 official image identity is invalid');
  }

  const basename = path.basename(preflightNode.devicePath);
  if (!/^hidraw[0-9]+$/u.test(basename)) throw new Error('H-042 node basename is invalid');
  const dynamicPath = `${DYNAMIC_ROOT}/${basename}`;
  const compatibilityPath = `/dev/${basename}`;
  const cgroupRule = `c ${preflightNode.stat.major}:${preflightNode.stat.minor} rw`;
  const containerName = `h042-companion-${sha256(id).slice(0, 12)}`;
  const entries = [];
  const runtimePolls = [];
  let containerCreated = false;
  let containerId = null;
  let draft = null;
  let primaryError = null;
  let experimentEventsText = '';
  let cleanupEventsText = '';
  let experimentBoundaryAt = null;
  let classifiedAt = null;
  let returnedHostForCleanup = null;
  let returnedNodeForCleanup = null;

  try {
    const runArguments = buildDockerRunArguments({
      containerName,
      dynamicPath,
      compatibilityPath,
      deviceGid,
      cgroupRule,
    });
    auditEntry(entries, {
      kind: 'docker-run',
      phase: 'setup',
      target: containerName,
      imageReference: OFFICIAL_IMAGE,
      arguments: runArguments,
      runnerDeviceIo: false,
    });
    const created = await command('docker', runArguments);
    containerCreated = true;
    containerId = created.stdout.trim();
    if (!/^[0-9a-f]{64}$/u.test(containerId)) {
      throw new Error('H-042 docker run returned an invalid container ID');
    }
    const runtimeOptions = {
      dynamicPath,
      compatibilityPath,
      major: preflightNode.stat.major,
      minor: preflightNode.stat.minor,
      serial,
    };
    const initialRuntime = await waitForBaseline({
      containerName,
      runtime: runtimeOptions,
      timeoutSeconds: options.baselineWindowSeconds,
      entries,
      polls: runtimePolls,
    });
    const initialHost = captureHostSnapshot(serial, {
      includeOwners: true,
      previousDevicePath: preflightNode.devicePath,
    });
    const initialNode = exactNode(initialHost, 'initial');
    if (
      initialRuntime.container.containerId !== containerId ||
      !permissionBoundaryExact(initialRuntime, { deviceGid, cgroupRule, dynamicPath }) ||
      !samePresentHostEpoch(preflightHost, initialHost) ||
      !sameDeviceAccessBoundary(initialNode.stat, initialRuntime.observer.paths.dynamic.stat.value)
    ) {
      throw new Error('H-042 baseline boundary is invalid');
    }
    const oldWorker = selectUniqueWorker(initialRuntime, { deviceGid });
    if (oldWorker === null) throw new Error('H-042 baseline lacks one exact SurfaceThread');

    const disconnectChallenge = sha256(`${id}:${serial}:disconnect`).slice(0, 12);
    const disconnectWindow = openWindow(
      'disconnect',
      disconnectChallenge,
      options.transitionWindowSeconds,
      'DESCONECTA físicamente el cable USB del Stream Deck MK.2'
    );
    auditEntry(entries, {
      kind: 'physical-disconnect-window',
      phase: 'disconnect',
      challenge: disconnectChallenge,
      expectedActor: 'human-principal',
    });
    process.stdout.write(
      `H-042 ${disconnectChallenge}: ${disconnectWindow.instruction} (${options.transitionWindowSeconds}s).\n`
    );
    const absentStable = await waitForStableHostState('absent', serial, {
      timeoutMs: options.transitionWindowSeconds * 1000,
      previousDevicePath: initialNode.devicePath,
      timeline: hostTimeline,
    });
    const absentHost = absentStable.snapshot;
    const absentRuntime = await waitForAbsent({
      containerName,
      runtime: runtimeOptions,
      timeoutSeconds: options.absentDescriptorWindowSeconds,
      entries,
      polls: runtimePolls,
    });
    closeWindow(disconnectWindow);
    const absentWorker = selectUniqueWorker(absentRuntime, { deviceGid });
    if (
      absentWorker === null ||
      !sameWorker(oldWorker, absentWorker) ||
      !sameTopLevelLifecycle(initialRuntime.lifecycle, absentRuntime.lifecycle) ||
      !dynamicStageMatchesHost({
        hostNode: null,
        dynamic: absentRuntime.observer.paths.dynamic.stat,
      }) ||
      !permissionBoundaryExact(absentRuntime, {
        deviceGid,
        cgroupRule,
        dynamicPath,
      }) ||
      !descriptorAbsent(absentRuntime)
    ) {
      throw new Error('H-042 absent-stage worker, device view, or permission boundary drifted');
    }

    const reconnectChallenge = sha256(
      `${id}:${serial}:reconnect:${disconnectWindow.closedMonotonicNs}`
    ).slice(0, 12);
    const reconnectWindow = openWindow(
      'reconnect',
      reconnectChallenge,
      options.transitionWindowSeconds,
      'RECONECTA físicamente el cable USB del mismo Stream Deck MK.2'
    );
    auditEntry(entries, {
      kind: 'physical-reconnect-window',
      phase: 'reconnect',
      challenge: reconnectChallenge,
      expectedActor: 'human-principal',
    });
    process.stdout.write(
      `H-042 ${reconnectChallenge}: ${reconnectWindow.instruction} (${options.transitionWindowSeconds}s).\n`
    );
    const returnedStable = await waitForStableHostState('present', serial, {
      timeoutMs: options.transitionWindowSeconds * 1000,
      previousDevicePath: initialNode.devicePath,
      timeline: hostTimeline,
    });
    const returnedHost = returnedStable.snapshot;
    const returnedNode = exactNode(returnedHost, 'returned');
    returnedHostForCleanup = returnedHost;
    returnedNodeForCleanup = returnedNode;
    const returnedInventory = await inventoryHostHidraw();
    const returnedSelection = selectExactTargetHidraw(returnedInventory, {
      vendorId: TARGET_VENDOR_ID,
      productId: TARGET_PRODUCT_ID,
      serial,
    });
    closeWindow(reconnectWindow);
    if (
      returnedSelection.devicePath !== returnedNode.devicePath ||
      returnedSelection.stat.stable !== true ||
      returnedSelection.stat.matchesClass !== true ||
      returnedNode.devicePath !== initialNode.devicePath ||
      !hostEpochChanged(initialHost, returnedHost) ||
      !sameDeviceAccessBoundary(initialNode.stat, returnedNode.stat) ||
      !sameDeviceAccessBoundary(initialNode.stat, returnedSelection.stat.value)
    ) {
      throw new Error('H-042 returned device permission or inventory boundary changed');
    }

    const preSignal = await runPreSignalControl({
      containerName,
      runtime: runtimeOptions,
      entries,
      polls: runtimePolls,
      deviceGid,
      oldWorker,
      initialLifecycle: initialRuntime.lifecycle,
      baselineMarkers: absentRuntime.markers,
      returnedNode,
      cgroupRule,
      startedAt: returnedHost.capturedAt,
      startedMonotonicNs: returnedHost.monotonicNs,
    });
    const signalTargetRuntime = await observeContainer(
      containerName,
      { ...runtimeOptions, phase: 'signal-target-revalidate' },
      entries
    );
    runtimePolls.push(signalTargetRuntime);
    const signalTargetHost = captureHostSnapshot(serial, {
      includeOwners: true,
      previousDevicePath: returnedNode.devicePath,
    });
    hostTimeline.push(signalTargetHost);
    const signalTargetNode = exactNode(signalTargetHost, 'signal-target');
    const signalTargetWorker = selectUniqueWorker(signalTargetRuntime, { deviceGid });
    if (
      signalTargetWorker === null ||
      !sameWorker(oldWorker, signalTargetWorker) ||
      !samePresentHostEpoch(returnedHost, signalTargetHost) ||
      signalTargetNode.devicePath !== returnedNode.devicePath ||
      !sameDeviceAccessBoundary(returnedNode.stat, signalTargetNode.stat) ||
      !signalTargetNode.owner?.observed ||
      signalTargetNode.owner.pids.length > 0 ||
      targetDescriptors(signalTargetRuntime).length !== 0 ||
      !markersUnchanged(absentRuntime.markers, signalTargetRuntime.markers) ||
      !sameTopLevelLifecycle(initialRuntime.lifecycle, signalTargetRuntime.lifecycle) ||
      !permissionBoundaryExact(signalTargetRuntime, {
        deviceGid,
        cgroupRule,
        dynamicPath,
      }) ||
      !dynamicStageMatchesHost({
        hostNode: signalTargetNode,
        dynamic: signalTargetRuntime.observer.paths.dynamic.stat,
      }) ||
      !sameDeviceAccessBoundary(
        signalTargetNode.stat,
        signalTargetRuntime.observer.paths.dynamic.stat.value
      ) ||
      !sameDeviceAccessBoundary(
        signalTargetNode.stat,
        signalTargetRuntime.observer.paths.compat.stat.value
      )
    ) {
      throw new Error('H-042 signal target changed after the negative control');
    }
    returnedHostForCleanup = signalTargetHost;
    returnedNodeForCleanup = signalTargetNode;
    const target = exactWorkerIdentity(signalTargetWorker);
    const helperCommand = `/app/node-runtimes/main/bin/node ${CONTAINER_SIGNAL_HELPER}`;
    const signalAudit = {
      kind: 'docker-exec-signal',
      phase: 'fault-injection',
      target: containerName,
      user: '1000:1000',
      signal: 'SIGTERM',
      processTarget: target,
      command: ['/app/node-runtimes/main/bin/node', CONTAINER_SIGNAL_HELPER],
      exitCode: null,
      receiptSha256: null,
    };
    auditEntry(entries, signalAudit);
    const signalEntry = entries.at(-1);
    const signalCommand = await command('docker', [
      'exec',
      '--user',
      '1000:1000',
      '--env',
      `H042_EXPECTED_TARGET=${JSON.stringify(target)}`,
      '--env',
      `H042_DEVICE_GID=${deviceGid}`,
      containerName,
      '/app/node-runtimes/main/bin/node',
      CONTAINER_SIGNAL_HELPER,
    ]);
    signalEntry.exitCode = 0;
    const signalReceiptText = signalCommand.stdout;
    const signalReceipt = JSON.parse(signalReceiptText);
    signalEntry.receiptSha256 = sha256(signalReceiptText);
    const revalidationTuple = {
      pid: target.pid,
      startTicks: target.startTicks,
      ppid: target.ppid,
      parentStartTicks: target.parentStartTicks,
    };
    if (
      signalCommand.stderr !== '' ||
      signalReceipt.schemaVersion !== 'overlaykit-h042-signal-receipt/v1' ||
      signalReceipt.signal !== 'SIGTERM' ||
      signalReceipt.processKillCallCount !== 1 ||
      sha256Canonical(signalReceipt.expected) !== sha256Canonical(target) ||
      sha256Canonical(
        Object.fromEntries(Object.keys(target).map((key) => [key, signalReceipt.observed[key]]))
      ) !== sha256Canonical(target) ||
      signalReceipt.observed.targetHidrawDescriptors.length !== 0 ||
      sha256Canonical(signalReceipt.observed.revalidation?.initial) !==
        sha256Canonical(revalidationTuple) ||
      sha256Canonical(signalReceipt.observed.revalidation?.final) !==
        sha256Canonical(revalidationTuple) ||
      rfc3339NanoToEpochNs(signalReceipt.startedAt) === null ||
      rfc3339NanoToEpochNs(signalReceipt.receivedAt) === null ||
      rfc3339NanoToEpochNs(signalReceipt.receivedAt) <
        rfc3339NanoToEpochNs(signalReceipt.startedAt) ||
      !/^[0-9]+$/u.test(signalReceipt.startedMonotonicNs) ||
      !/^[0-9]+$/u.test(signalReceipt.receivedMonotonicNs) ||
      BigInt(signalReceipt.startedMonotonicNs) <= BigInt(signalTargetRuntime.monotonicNs) ||
      BigInt(signalReceipt.receivedMonotonicNs) <= BigInt(signalReceipt.startedMonotonicNs)
    ) {
      throw new Error('H-042 signal helper receipt is invalid');
    }

    const postSignal = await runPostSignalObservation({
      containerName,
      runtime: runtimeOptions,
      entries,
      polls: runtimePolls,
      deviceGid,
      oldWorker,
      initialLifecycle: initialRuntime.lifecycle,
      returnedNode: signalTargetNode,
      cgroupRule,
      preSignalMarkers: signalTargetRuntime.markers,
      signal: signalReceipt,
    });
    experimentBoundaryAt = new Date().toISOString();
    auditEntry(entries, {
      kind: 'docker-events-experiment',
      phase: 'classification-receipt',
      target: containerId,
      since: startedAt,
      until: experimentBoundaryAt,
    });
    experimentEventsText = await dockerEvents(containerId, startedAt, experimentBoundaryAt);
    const experimentEvents = parseDockerEvents(experimentEventsText);
    const expectedObserverExecCount = entries.filter(
      (entry) => entry.kind === 'docker-exec-observer'
    ).length;
    const eventAnalysis = analyzeExperimentEvents(experimentEvents, {
      containerId,
      helperCommand,
      observerCommand: `/app/node-runtimes/main/bin/node ${CONTAINER_OBSERVER}`,
      expectedObserverExecCount,
      experimentStartedAt: startedAt,
      experimentBoundaryAt,
    });
    const allRuntimes = [
      initialRuntime,
      absentRuntime,
      ...preSignal.polls,
      signalTargetRuntime,
      ...postSignal.polls,
    ];
    const topLevelStable = allRuntimes.every((runtime) =>
      sameTopLevelLifecycle(initialRuntime.lifecycle, runtime.lifecycle)
    );
    const permissionExact = allRuntimes.every((runtime) =>
      permissionBoundaryExact(runtime, { deviceGid, cgroupRule, dynamicPath })
    );
    const predicates = {
      complete: true,
      permissionBoundaryExact: permissionExact,
      hostEpochChanged: hostEpochChanged(initialHost, returnedHost),
      dynamicViewTracksHost:
        dynamicStageMatchesHost({
          hostNode: initialNode,
          dynamic: initialRuntime.observer.paths.dynamic.stat,
        }) &&
        dynamicStageMatchesHost({
          hostNode: null,
          dynamic: absentRuntime.observer.paths.dynamic.stat,
        }) &&
        dynamicStageMatchesHost({
          hostNode: returnedNode,
          dynamic: signalTargetRuntime.observer.paths.dynamic.stat,
        }) &&
        dynamicStageMatchesHost({
          hostNode: returnedNode,
          dynamic: postSignal.final.observer.paths.dynamic.stat,
        }),
      baselineAcquired: baselineAcquired(initialRuntime),
      preSignalWindowComplete:
        preSignal.window.deadlineExpired && preSignal.window.boundaryNegative,
      preSignalNegative:
        preSignal.polls.every(
          (runtime) =>
            targetDescriptors(runtime).length === 0 &&
            markersUnchanged(absentRuntime.markers, runtime.markers)
        ) && descriptorAbsent(absentRuntime),
      signalTargetUnique: signalTargetWorker !== null,
      signalTargetRevalidated:
        sameWorker(target, signalReceipt.observed) &&
        signalReceipt.observed.targetHidrawDescriptors.length === 0,
      exactlyOneSigterm:
        entries.filter((entry) => entry.kind === 'docker-exec-signal').length === 1 &&
        eventAnalysis.helperCreateCount === 1 &&
        eventAnalysis.helperStartCount === 1 &&
        eventAnalysis.helperDieZeroCount === 1,
      signalSucceeded: signalEntry.exitCode === 0 && eventAnalysis.ordered,
      invocationAuditExact: eventAnalysis.passed,
      topLevelLifecycleUnchanged: topLevelStable,
      oldWorkerExited: postSignal.replacement.oldWorkerExited,
      replacementWorkerUnique: postSignal.replacement.replacementWorkerUnique,
      singleReplacementGeneration: postSignal.replacement.singleReplacementGeneration,
      replacementWorkerChanged: postSignal.replacement.replacementWorkerChanged,
      postSignalObservationComplete:
        postSignal.window.supportObserved || postSignal.window.deadlineExpired,
      postSignalDescriptorObserved: postSignal.descriptorObserved,
      postSignalOpeningObserved: postSignal.openingObserved,
      postSignalReadyObserved: postSignal.readyObserved,
      postSignalMarkersOrdered: postSignal.markersOrdered,
      postSignalWithinDeadline: postSignal.window.supportObserved,
      deadlineBoundaryConsistent:
        postSignal.markerDelta.prefixValid &&
        (postSignal.window.supportObserved ||
          (postSignal.window.deadlineExpired && !postSignal.latePositiveObserved)),
      latePositiveObserved: postSignal.latePositiveObserved,
    };
    const outcome = classifyH042Outcome(predicates);
    classifiedAt = new Date().toISOString();
    auditEntry(entries, {
      kind: 'experiment-classified',
      phase: 'classification',
      experimentBoundaryAt,
      outcome: outcome.status,
      stage: outcome.stage,
    });
    draft = {
      outcome,
      inputs: {
        h037: {
          ...h041.inputs.h037,
          validationReceipt: {
            path: predecessorReceipts.h037.output,
            sha256: sha256(predecessorReceipts.h037.bytes),
          },
        },
        h039: {
          ...h041.inputs.h039,
          verificationReceipt: {
            path: predecessorReceipts.h039.output,
            sha256: sha256(predecessorReceipts.h039.bytes),
          },
        },
        h040: {
          ...h041.inputs.h040,
          verificationReceipt: {
            path: predecessorReceipts.h040.output,
            sha256: sha256(predecessorReceipts.h040.bytes),
          },
        },
        h041: {
          path: path.relative(REPOSITORY_ROOT, h041Path),
          fileSha256: sha256(h041Bytes),
          evidenceSha256: h041.evidenceSha256,
          verificationReceipt: {
            path: 'h041-verification.json',
            sha256: sha256(storedH041VerificationBytes),
          },
          reverificationReceipt: {
            path: 'h041-reverification.json',
            sha256: sha256(h041VerificationText),
          },
        },
      },
      host: {
        ...observedHost,
        graphicalSession: session.selected,
        docker: { version: dockerVersion, info: dockerInfo },
      },
      device: {
        vendorId: TARGET_VENDOR_ID,
        productId: TARGET_PRODUCT_ID,
        model: h041.device.model,
        serial,
        initialPath: initialNode.devicePath,
        returnedPath: returnedNode.devicePath,
        initialRdevHex: initialNode.stat.rdevHex,
        returnedRdevHex: returnedNode.stat.rdevHex,
        transition: classifyDeviceTransition(initialNode, returnedNode),
        initialInventory,
        returnedInventory,
      },
      companion: {
        name: containerName,
        containerId,
        imageReference: OFFICIAL_IMAGE,
        imageId: image.Id,
        repoDigests: image.RepoDigests,
        version: image.Config.Labels['org.opencontainers.image.version'],
        revision: image.Config.Labels['org.opencontainers.image.revision'],
        dynamicRoot: DYNAMIC_ROOT,
        dynamicPath,
        compatibilityPath,
        deviceCgroupRule: cgroupRule,
        deviceGid,
        staticDevices: [],
        initialLifecycle: initialRuntime.lifecycle,
        absentLifecycle: absentRuntime.lifecycle,
        preSignalLifecycle: signalTargetRuntime.lifecycle,
        postSignalLifecycle: postSignal.final.lifecycle,
        workerLifecycle: {
          initial: initialRuntime.observer.surfaceWorkers,
          absent: absentRuntime.observer.surfaceWorkers,
          preSignal: signalTargetRuntime.observer.surfaceWorkers,
          postSignal: postSignal.final.observer.surfaceWorkers,
        },
      },
      windows: {
        disconnect: disconnectWindow,
        reconnect: reconnectWindow,
        preSignal: preSignal.window,
        signal: {
          command: ['/app/node-runtimes/main/bin/node', CONTAINER_SIGNAL_HELPER],
          user: '1000:1000',
          target,
          startedAt: signalReceipt.startedAt,
          startedMonotonicNs: signalReceipt.startedMonotonicNs,
          receivedAt: signalReceipt.receivedAt,
          receivedMonotonicNs: signalReceipt.receivedMonotonicNs,
          exitCode: 0,
          receipt: signalReceipt,
        },
        postSignal: postSignal.window,
      },
      observations: {
        preflight: { host: preflightHost },
        initial: { host: initialHost, runtime: withoutLogs(initialRuntime) },
        absent: { host: absentHost, runtime: withoutLogs(absentRuntime) },
        returned: { host: returnedHost, runtime: withoutLogs(preSignal.first) },
        preSignal: {
          host: signalTargetHost,
          runtime: withoutLogs(signalTargetRuntime),
          markers: { baseline: absentRuntime.markers, final: signalTargetRuntime.markers },
          control: {
            descriptorObserved: false,
            openingObserved: false,
            readyObserved: false,
            boundaryNegative: preSignal.window.boundaryNegative,
          },
        },
        postSignal: {
          runtime: withoutLogs(postSignal.final),
          markerDelta: postSignal.markerDelta,
          replacement: postSignal.replacement,
          descriptorObserved: postSignal.descriptorObserved,
          latePositiveObserved: postSignal.latePositiveObserved,
          dockerEvents: eventAnalysis,
        },
      },
      predicates,
      raw: {
        hostTimeline,
        runtimePolls,
        logs: {
          initial: initialRuntime.logText,
          absent: absentRuntime.logText,
          preSignal: signalTargetRuntime.logText,
          final: postSignal.final.logText,
        },
        signalReceiptText,
      },
    };
  } catch (error) {
    primaryError = error;
  } finally {
    const cleanupStartedAt = new Date().toISOString();
    let cleanupError = null;
    if (containerCreated) {
      try {
        auditEntry(entries, {
          kind: 'docker-stop',
          phase: 'cleanup',
          target: containerName,
          timeoutSeconds: 5,
        });
        await command('docker', ['stop', '--timeout', '5', containerName]);
      } catch (error) {
        cleanupError = error instanceof Error ? error.message : String(error);
      }
    }
    let containerRemoved = false;
    try {
      auditEntry(entries, {
        kind: 'docker-ps-cleanup',
        phase: 'cleanup',
        target: containerName,
      });
      const remaining = await command('docker', [
        'ps',
        '--all',
        '--filter',
        `name=^/${containerName}$`,
        '--format',
        '{{.ID}}',
      ]);
      containerRemoved = remaining.stdout.trim() === '';
    } catch (error) {
      cleanupError ??= error instanceof Error ? error.message : String(error);
    }
    const eventsUntilAt = new Date().toISOString();
    let cleanupEventsAnalysis = {
      passed: false,
      reason: 'cleanup-events-were-not-finalized',
    };
    if (containerId !== null && experimentBoundaryAt !== null && classifiedAt !== null) {
      try {
        auditEntry(entries, {
          kind: 'docker-events-cleanup',
          phase: 'cleanup',
          target: containerId,
          since: experimentBoundaryAt,
          until: eventsUntilAt,
        });
        cleanupEventsText = await dockerEvents(containerId, experimentBoundaryAt, eventsUntilAt);
        cleanupEventsAnalysis = analyzeCleanupEvents(parseDockerEvents(cleanupEventsText), {
          containerId,
          experimentBoundaryAt,
          classifiedAt,
          eventsUntilAt,
        });
        if (!cleanupEventsAnalysis.passed) {
          cleanupError ??= 'H-042 cleanup Docker event boundary is not exact';
        }
      } catch (error) {
        cleanupError ??= error instanceof Error ? error.message : String(error);
      }
    }
    let cleanupHost = null;
    let cleanupNode = null;
    let cleanupOwners = [];
    try {
      cleanupHost = captureHostSnapshot(serial, {
        includeOwners: true,
        previousDevicePath: returnedNodeForCleanup?.devicePath ?? preflightNode.devicePath,
      });
      cleanupNode = exactNode(cleanupHost, 'cleanup');
      hostTimeline.push(cleanupHost);
      cleanupOwners = cleanupHost.hidraw
        .filter((entry) => entry.serialMatches)
        .map((entry) => ({
          devicePath: entry.devicePath,
          owner: entry.owner ?? ownerObservation(entry.devicePath),
        }));
    } catch (error) {
      cleanupError ??= error instanceof Error ? error.message : String(error);
    }
    const cleanupCompletedAt = new Date().toISOString();
    const returnedNodeAccessExact =
      returnedHostForCleanup !== null &&
      returnedNodeForCleanup !== null &&
      cleanupHost !== null &&
      cleanupNode !== null &&
      samePresentHostEpoch(returnedHostForCleanup, cleanupHost) &&
      cleanupNode.devicePath === returnedNodeForCleanup.devicePath &&
      sameDeviceAccessBoundary(returnedNodeForCleanup.stat, cleanupNode.stat);
    const cleanupChronology = [
      experimentBoundaryAt,
      classifiedAt,
      cleanupStartedAt,
      eventsUntilAt,
      cleanupCompletedAt,
    ].every((timestamp) => rfc3339NanoToEpochNs(timestamp) !== null);
    const cleanupChronologyOrdered =
      cleanupChronology &&
      rfc3339NanoToEpochNs(experimentBoundaryAt) <= rfc3339NanoToEpochNs(classifiedAt) &&
      rfc3339NanoToEpochNs(classifiedAt) <= rfc3339NanoToEpochNs(cleanupStartedAt) &&
      rfc3339NanoToEpochNs(cleanupStartedAt) <= rfc3339NanoToEpochNs(eventsUntilAt) &&
      rfc3339NanoToEpochNs(eventsUntilAt) <= rfc3339NanoToEpochNs(cleanupCompletedAt);
    const cleanup = {
      startedAt: cleanupStartedAt,
      completedAt: cleanupCompletedAt,
      experimentBoundaryAt,
      classificationCompletedAt: classifiedAt,
      eventsUntilAt,
      containerId,
      containerRemoved,
      dockerEventsAnalysis: cleanupEventsAnalysis,
      returnedNodeAccess: {
        reference:
          returnedNodeForCleanup === null
            ? null
            : {
                devicePath: returnedNodeForCleanup.devicePath,
                stat: returnedNodeForCleanup.stat,
              },
        observed:
          cleanupNode === null
            ? null
            : { devicePath: cleanupNode.devicePath, stat: cleanupNode.stat },
        exact: returnedNodeAccessExact,
      },
      host: cleanupHost,
      owners: cleanupOwners,
      hostConfigurationChanged: false,
      productionConfigurationChanged: false,
      successful:
        draft !== null &&
        experimentBoundaryAt !== null &&
        classifiedAt !== null &&
        containerRemoved &&
        cleanupError === null &&
        cleanupEventsAnalysis.passed === true &&
        cleanupChronologyOrdered &&
        returnedNodeAccessExact &&
        cleanupHost?.state === 'present' &&
        cleanupOwners.length === 1 &&
        cleanupOwners.every(({ owner }) => owner.observed && owner.pids.length === 0),
      error: cleanupError,
    };
    verifierFailureContext.preserve(draft, cleanup);

    if (draft !== null && cleanup.successful) {
      const finalSourceSha256 = collectSourceHashes();
      const sourceStable =
        sha256Canonical(initialSourceSha256) === sha256Canonical(finalSourceSha256);
      const hostPoll = compactHostTimeline(draft.raw.hostTimeline);
      const runtimePoll = runtimePollText(draft.raw.runtimePolls);
      const artifactContents = {
        'host-poll.jsonl': hostPoll,
        'runtime-poll.jsonl': runtimePoll,
        'logs-initial.txt': draft.raw.logs.initial,
        'logs-absent.txt': draft.raw.logs.absent,
        'logs-pre-signal.txt': draft.raw.logs.preSignal,
        'logs-final.txt': draft.raw.logs.final,
        'signal-receipt.json': draft.raw.signalReceiptText,
        'docker-events-experiment.jsonl': experimentEventsText,
        'docker-events-cleanup.jsonl': cleanupEventsText,
      };
      const artifacts = Object.fromEntries(
        await Promise.all(
          Object.entries(artifactContents).map(async ([name, contents]) => [
            name,
            await writeArtifact(evidenceDirectory, name, contents),
          ])
        )
      );
      const audit = invocationAudit(entries);
      const observations = {
        ...draft.observations,
        artifacts: {
          hostPoll: artifacts['host-poll.jsonl'],
          runtimePoll: artifacts['runtime-poll.jsonl'],
          initialLogs: artifacts['logs-initial.txt'],
          absentLogs: artifacts['logs-absent.txt'],
          preSignalLogs: artifacts['logs-pre-signal.txt'],
          finalLogs: artifacts['logs-final.txt'],
          signalReceipt: artifacts['signal-receipt.json'],
          experimentEvents: artifacts['docker-events-experiment.jsonl'],
          cleanupEvents: artifacts['docker-events-cleanup.jsonl'],
        },
      };
      const run = {
        schemaVersion: 'overlaykit-h042-surface-worker-recycle-run/v1',
        hypothesis: 'H-042',
        runId: id,
        startedAt,
        completedAt: cleanup.completedAt,
        outcome: draft.outcome,
        collector: {
          node: process.version,
          repository: (
            await command('git', ['config', '--get', 'remote.origin.url'], {
              cwd: REPOSITORY_ROOT,
            })
          ).stdout.trim(),
          commit: (
            await command('git', ['rev-parse', 'HEAD'], { cwd: REPOSITORY_ROOT })
          ).stdout.trim(),
          requiredSources: [...H042_REQUIRED_SOURCES],
          sourceSha256: finalSourceSha256,
          sourceStable,
          governance: {
            manifestSnapshotPath: 'governance-manifest.json',
            manifestFileSha256: sha256(manifestBytes),
            manifestContentHash: manifest.contentHash,
            changeSha256: manifest.changes['CHG-0013'],
            verifyReceiptPath: 'governance-verify.txt',
            verifyReceiptSha256: sha256(governanceVerifyText),
            planHash: manifest.planHash,
          },
        },
        inputs: draft.inputs,
        host: draft.host,
        device: draft.device,
        companion: draft.companion,
        windows: draft.windows,
        observations,
        predicates: draft.predicates,
        invocationAudit: audit,
        claimBoundary: H042_CLAIM_BOUNDARY,
        cleanup,
      };
      if (!sourceStable || !audit.passed) {
        primaryError ??= new Error('H-042 source or invocation audit failed closed');
      } else {
        const evidence = { ...run, evidenceSha256: sha256Canonical(run) };
        if (!validateEvidence(evidence)) {
          const errors = (validateEvidence.errors ?? [])
            .map((entry) => `${entry.instancePath || '/'} ${entry.message}`)
            .join('; ');
          primaryError ??= new Error(`H-042 candidate schema validation failed: ${errors}`);
        } else {
          await writeFile(candidatePath, `${JSON.stringify(evidence, null, 2)}\n`, {
            mode: 0o600,
          });
        }
      }
      if (primaryError !== null) {
        await writeFailureArtifact(failurePath, {
          id,
          message: primaryError instanceof Error ? primaryError.message : String(primaryError),
          draft,
          cleanup,
        });
      }
    } else {
      const message =
        primaryError instanceof Error
          ? primaryError.message
          : 'H-042 did not complete a canonical observation and cleanup';
      await writeFailureArtifact(failurePath, { id, message, draft, cleanup });
    }
  }

  if (primaryError !== null) throw primaryError;
  try {
    const verification = await command(
      process.execPath,
      [path.join(LAB_DIRECTORY, 'verify.mjs'), candidatePath],
      { cwd: REPOSITORY_ROOT }
    );
    const receipt = JSON.parse(verification.stdout);
    if (
      receipt.schemaVersion !== 'overlaykit-h042-verification/v1' ||
      receipt.hypothesis !== 'H-042' ||
      receipt.cleaned !== true ||
      receipt.verified !== true
    ) {
      throw new Error('H-042 verifier returned a malformed receipt');
    }
    await writeFile(verificationPath, `${JSON.stringify(receipt, null, 2)}\n`, {
      mode: 0o600,
    });
    await rename(candidatePath, runPath);
    process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n${runPath}\n`);
    return receipt;
  } catch (error) {
    await unlink(candidatePath).catch(() => {});
    const message = `H-042 independent verification failed: ${
      error instanceof Error ? error.message : String(error)
    }`;
    await verifierFailureContext.write(failurePath, id, message);
    throw new Error(message, { cause: error });
  }
}

const modulePath = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === modulePath) {
  await runH042();
}
