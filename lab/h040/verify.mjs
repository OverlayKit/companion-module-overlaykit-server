#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { classifyDeviceTransition, sha256, sha256Canonical } from '../h039/reconnect-lib.mjs';
import {
  classifyMappingOutcome,
  dynamicMatchesHost,
  hostEpochChanged,
  normalizeProbeStat,
  staticIdentityUnchanged,
} from './probe-lib.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const H039_EVIDENCE_SHA256 = 'e78ed04dd10469e863b33e4fa497ddc745a20574fb18095c2bde7cf3fdb594ce';
const PREDICATE_KEYS = [
  'complete',
  'dynamicAbsent',
  'dynamicInitialMatchesHost',
  'dynamicReturnedMatchesHost',
  'hostEpochChanged',
  'metadataOnly',
  'staticPersists',
  'staticUnchanged',
];
const REQUIRED_SOURCE_PATHS = [
  '.overlaykit/governance/changes/CHG-0011.json',
  'lab/h039/host-observer.mjs',
  'lab/h039/reconnect-lib.mjs',
  'lab/h040/probe-lib.mjs',
  'lab/h040/run.mjs',
  'lab/h040/schemas/docker-mapping-run.schema.json',
  'lab/h040/verify.mjs',
];

function assertion(condition, message) {
  if (!condition) throw new Error(message);
}

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function hasExactKeys(value, keys) {
  return (
    isPlainRecord(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort())
  );
}

function validDateTime(value) {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

function dateTimeMs(value, label) {
  assertion(validDateTime(value), `${label} is not a valid UTC date-time`);
  return Date.parse(value);
}

function monotonicNs(value, label) {
  assertion(typeof value === 'string' && /^[0-9]+$/u.test(value), `${label} is invalid`);
  return BigInt(value);
}

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, 'utf8'));
}

function safeRepositoryPath(relativePath, label) {
  assertion(
    typeof relativePath === 'string' && relativePath.length > 0 && !path.isAbsolute(relativePath),
    `${label} is not repository-relative`
  );
  const absolutePath = path.resolve(REPOSITORY_ROOT, relativePath);
  assertion(
    absolutePath.startsWith(`${REPOSITORY_ROOT}${path.sep}`),
    `${label} escaped the repository: ${relativePath}`
  );
  return absolutePath;
}

function safeEvidencePath(runPath, relativePath, label) {
  assertion(
    typeof relativePath === 'string' && relativePath.length > 0 && !path.isAbsolute(relativePath),
    `${label} is not evidence-relative`
  );
  const directory = path.dirname(runPath);
  const absolutePath = path.resolve(directory, relativePath);
  assertion(
    absolutePath.startsWith(`${directory}${path.sep}`),
    `${label} escaped the evidence directory: ${relativePath}`
  );
  return absolutePath;
}

function compileSchema(schema) {
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  ajv.addFormat('date-time', validDateTime);
  return ajv.compile(schema);
}

function assertSchema(validate, value, label) {
  assertion(
    validate(value),
    `${label} schema failed: ${(validate.errors ?? [])
      .map((error) => `${error.instancePath || '/'} ${error.message}`)
      .join('; ')}`
  );
}

function exactPresentHostTuple(snapshot, serial, label) {
  assertion(snapshot.state === 'present', `${label} host snapshot is not present`);
  assertion(snapshot.expectedSerial === serial, `${label} expected a different serial`);
  assertion(
    snapshot.lsusb?.observed === true &&
      snapshot.lsusb.exitCode === 0 &&
      snapshot.lsusb.errorCode === null &&
      Array.isArray(snapshot.errors) &&
      snapshot.errors.length === 0,
    `${label} host observation is incomplete`
  );
  const usb = snapshot.usb.filter(
    (entry) =>
      entry.vendorId === '0fd9' &&
      entry.productId === '0080' &&
      entry.serial === serial &&
      entry.serialMatches === true
  );
  const hidraw = snapshot.hidraw.filter(
    (entry) =>
      entry.serialMatches === true &&
      entry.hid?.unique === serial &&
      entry.usbAncestor?.vendorId === '0fd9' &&
      entry.usbAncestor?.productId === '0080' &&
      entry.usbAncestor?.serial === serial
  );
  assertion(usb.length === 1, `${label} lacks one exact USB serial`);
  assertion(hidraw.length === 1, `${label} lacks one exact HID serial`);
  const node = hidraw[0];
  assertion(
    node.nodeStable === true &&
      node.nodeMatchesClass === true &&
      node.stat?.isCharacterDevice === true &&
      node.stat.major === node.classDevice?.major &&
      node.stat.minor === node.classDevice?.minor &&
      node.stat.rdevHex ===
        `${node.classDevice.major.toString(16)}:${node.classDevice.minor.toString(16)}`,
    `${label} HID, class device, and character node do not match`
  );
  return { usb: usb[0], node };
}

function assertAbsentHostSnapshot(snapshot, serial) {
  assertion(
    snapshot.state === 'absent' &&
      snapshot.expectedSerial === serial &&
      snapshot.lsusb?.observed === true &&
      snapshot.lsusb.exitCode === 0 &&
      snapshot.lsusb.errorCode === null &&
      snapshot.lsusb.matches.length === 0 &&
      snapshot.usb.length === 0 &&
      snapshot.hidraw.length === 0 &&
      snapshot.priorPath?.stat?.kind === 'missing' &&
      snapshot.priorPath.stat.code === 'ENOENT' &&
      snapshot.errors.length === 0,
    'H-040 did not prove exact physical absence'
  );
}

function verifyWindow(window, label) {
  const openedNs = monotonicNs(window.openedMonotonicNs, `${label} opened monotonic time`);
  const closedNs = monotonicNs(window.closedMonotonicNs, `${label} closed monotonic time`);
  assertion(openedNs < closedNs, `${label} window did not advance monotonically`);
  assertion(
    dateTimeMs(window.openedAt, `${label} openedAt`) <
      dateTimeMs(window.closedAt, `${label} closedAt`),
    `${label} wall-clock window did not advance`
  );
  return { openedNs, closedNs };
}

function collectArtifactReceipts(value, location = '/', receipts = []) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      collectArtifactReceipts(entry, `${location}${index}/`, receipts)
    );
    return receipts;
  }
  if (!isPlainRecord(value)) return receipts;
  if (
    typeof value.path === 'string' &&
    typeof value.sha256 === 'string' &&
    /^[0-9a-f]{64}$/u.test(value.sha256)
  ) {
    receipts.push({ location, path: value.path, sha256: value.sha256 });
  }
  for (const [key, entry] of Object.entries(value)) {
    collectArtifactReceipts(entry, `${location}${key}/`, receipts);
  }
  return receipts;
}

async function verifyArtifactReceipts(runPath, run) {
  const receipts = collectArtifactReceipts(run);
  const verified = new Map();
  for (const receipt of receipts) {
    const key = `${receipt.path}\0${receipt.sha256}`;
    if (verified.has(key)) continue;
    const bytes = await readFile(
      safeEvidencePath(runPath, receipt.path, `artifact at ${receipt.location}`)
    );
    assertion(
      sha256(bytes) === receipt.sha256,
      `H-040 artifact hash mismatch at ${receipt.location}`
    );
    verified.set(key, bytes);
  }
  return { receipts, verified };
}

function verifyH039Receipt(receipt, historical, expectedEvidenceSha256) {
  assertion(
    receipt.schemaVersion === 'overlaykit-h039-verification/v1' &&
      receipt.hypothesis === 'H-039' &&
      receipt.outcome === 'refuted' &&
      receipt.stage === 'companion-reacquisition' &&
      receipt.evidenceSha256 === expectedEvidenceSha256 &&
      receipt.deviceTransition === historical.device.transition &&
      receipt.topLevelLifecycleUnchanged === true &&
      receipt.configurationUnchanged === true &&
      receipt.virtualInvocationCount === 0 &&
      receipt.cleaned === true &&
      receipt.verified === true,
    'H-040 H-039 verification receipt lacks the required historical guarantees'
  );
}

async function verifyHistoricalH039(runPath, run, artifactVerification) {
  const inputPath = safeRepositoryPath(run.inputs.h039Path, 'H-039 input');
  const bytes = await readFile(inputPath);
  assertion(sha256(bytes) === run.inputs.h039FileSha256, 'H-040 H-039 file hash mismatch');
  const historical = JSON.parse(bytes);
  const h039Schema = await readJson(
    path.join(REPOSITORY_ROOT, 'lab/h039/schemas/reconnect-run.schema.json')
  );
  assertSchema(compileSchema(h039Schema), historical, 'historical H-039');
  const { evidenceSha256, ...evidence } = historical;
  assertion(
    run.inputs.h039EvidenceSha256 === H039_EVIDENCE_SHA256 &&
      evidenceSha256 === run.inputs.h039EvidenceSha256 &&
      sha256Canonical(evidence) === evidenceSha256,
    'H-040 historical H-039 canonical evidence is stale or invalid'
  );

  const receiptKey = `${run.inputs.h039VerifyReceipt.path}\0${run.inputs.h039VerifyReceipt.sha256}`;
  const receiptBytes = artifactVerification.verified.get(receiptKey);
  assertion(receiptBytes !== undefined, 'H-040 H-039 verification receipt was not verified');
  let receipt;
  try {
    receipt = JSON.parse(receiptBytes.toString('utf8'));
  } catch {
    throw new Error('H-040 H-039 verification receipt is not JSON');
  }
  verifyH039Receipt(receipt, historical, evidenceSha256);
  assertion(
    historical.outcome.status === 'refuted' &&
      historical.outcome.stage === 'companion-reacquisition' &&
      historical.device.vendorId === '0fd9' &&
      historical.device.productId === '0080' &&
      historical.lifecycle.unchangedFinal === true &&
      historical.configuration.final.observed === true &&
      historical.configuration.final.unchanged === true &&
      historical.observations.reacquisition.currentDeviceDescriptorObserved === false &&
      typeof historical.observations.reacquisition.timeout === 'string' &&
      historical.invocationAudit.passed === true &&
      historical.invocationAudit.virtualInvocationCount === 0 &&
      historical.invocationAudit.forbidden.length === 0 &&
      historical.cleanup.composeRemoved === true &&
      historical.cleanup.successful === true &&
      historical.cleanup.error === null,
    'H-040 H-039 input does not preserve the bounded reacquisition refutation'
  );
  if (Object.hasOwn(run.inputs, 'h039Outcome')) {
    assertion(
      run.inputs.h039Outcome.status === historical.outcome.status &&
        run.inputs.h039Outcome.stage === historical.outcome.stage,
      'H-040 H-039 outcome receipt does not match the historical evidence'
    );
  }
  if (Object.hasOwn(run.inputs, 'lockedInputs')) {
    assertion(
      sha256Canonical(run.inputs.lockedInputs) === sha256Canonical(historical.inputs.lockedInputs),
      'H-040 locked product inputs differ from H-039'
    );
  }
  return historical;
}

async function verifyCollector(runPath, run) {
  assertion(run.collector.sourceStable === true, 'H-040 collector source was not stable');
  for (const requiredPath of REQUIRED_SOURCE_PATHS) {
    assertion(
      Object.hasOwn(run.collector.sourceSha256, requiredPath),
      `H-040 collector omitted source identity: ${requiredPath}`
    );
  }
  for (const [relativePath, expected] of Object.entries(run.collector.sourceSha256)) {
    const bytes = await readFile(safeRepositoryPath(relativePath, 'H-040 source'));
    assertion(sha256(bytes) === expected, `H-040 source hash mismatch: ${relativePath}`);
  }

  const governance = run.collector.governance;
  const manifestBytes = await readFile(
    safeEvidencePath(runPath, governance.manifestSnapshotPath, 'governance manifest')
  );
  const manifest = JSON.parse(manifestBytes);
  assertion(
    sha256(manifestBytes) === governance.manifestFileSha256 &&
      manifest.contentHash === governance.manifestContentHash &&
      manifest.planHash === governance.planHash &&
      manifest.changes?.['CHG-0011'] === governance.changeSha256 &&
      governance.changeSha256 ===
        run.collector.sourceSha256['.overlaykit/governance/changes/CHG-0011.json'],
    'H-040 archived governance manifest is invalid'
  );
  const verifyReceipt = await readFile(
    safeEvidencePath(runPath, governance.verifyReceiptPath, 'governance verify receipt')
  );
  assertion(
    sha256(verifyReceipt) === governance.verifyReceiptSha256 &&
      verifyReceipt.toString('utf8').includes(`governance ok ${governance.planHash}`),
    'H-040 archived governance verification receipt is invalid'
  );
}

function metadataOnlyAudit(audit, run) {
  if (
    audit.mode !== 'metadata-only' ||
    audit.metadataOnly !== true ||
    audit.passed !== true ||
    !Array.isArray(audit.entries) ||
    audit.entries.length === 0 ||
    !Array.isArray(audit.forbidden) ||
    audit.forbidden.length !== 0 ||
    audit.deviceReads !== 0 ||
    audit.deviceWrites !== 0 ||
    audit.virtualInvocationCount !== 0
  ) {
    return false;
  }
  const allowedKinds = new Set(['docker-run', 'docker-inspect', 'docker-stat', 'docker-stop']);
  if (
    audit.entries.some(
      (entry) =>
        !isPlainRecord(entry) ||
        !allowedKinds.has(entry.kind) ||
        entry.metadataOnly !== true ||
        (entry.kind === 'docker-stat' && entry.operation !== 'fs.statSync')
    )
  ) {
    return false;
  }
  const runs = audit.entries.filter((entry) => entry.kind === 'docker-run');
  const inspections = audit.entries.filter((entry) => entry.kind === 'docker-inspect');
  const stats = audit.entries.filter((entry) => entry.kind === 'docker-stat');
  const stops = audit.entries.filter((entry) => entry.kind === 'docker-stop');
  const expectedViews = [
    'absent-dynamic',
    'absent-static',
    'initial-dynamic',
    'initial-static',
    'returned-dynamic',
    'returned-static',
  ];
  const expectedStatPaths = new Map([
    ['initial-static', run.observations.initial.static.path],
    ['initial-dynamic', run.observations.initial.dynamic.path],
    ['absent-static', run.observations.absent.static.path],
    ['absent-dynamic', run.observations.absent.dynamic.path],
    ['returned-static', run.observations.returned.static.path],
    ['returned-dynamic', run.observations.returned.dynamic.path],
  ]);
  return (
    runs.length === 1 &&
    runs[0].name === run.probe.name &&
    runs[0].imageReference === run.probe.imageReference &&
    runs[0].staticHostPath === run.device.initialPath &&
    runs[0].staticContainerPath === '/tmp/h040-static-hidraw' &&
    runs[0].staticCgroupPermissions === 'm' &&
    runs[0].dynamicHostPath === '/dev' &&
    runs[0].dynamicContainerPath === '/host-dev' &&
    runs[0].dynamicReadOnly === true &&
    runs[0].network === 'none' &&
    runs[0].readOnlyRootfs === true &&
    runs[0].noNewPrivileges === true &&
    runs[0].user === '65534:65534' &&
    JSON.stringify(runs[0].capDrop) === JSON.stringify(['ALL']) &&
    JSON.stringify(runs[0].command) === JSON.stringify(['sleep', 'infinity']) &&
    inspections.length === 2 &&
    inspections.every((entry) => entry.target === run.probe.name) &&
    stats.length === 6 &&
    JSON.stringify(stats.map((entry) => entry.view).sort()) === JSON.stringify(expectedViews) &&
    stats.every((entry) => entry.path === expectedStatPaths.get(entry.view)) &&
    stops.length === 1 &&
    stops[0].target === run.probe.name &&
    stops[0].timeoutSeconds === 5 &&
    audit.entries.length === 10
  );
}

function recomputePredicates(run, initialNode, returnedNode) {
  const initialStatic = normalizeProbeStat(run.observations.initial.static);
  const absentStatic = normalizeProbeStat(run.observations.absent.static);
  const returnedStatic = normalizeProbeStat(run.observations.returned.static);
  const absentDynamic = normalizeProbeStat(run.observations.absent.dynamic);
  const result = {
    dynamicInitialMatchesHost: dynamicMatchesHost(run.observations.initial.dynamic, initialNode),
    dynamicReturnedMatchesHost: dynamicMatchesHost(run.observations.returned.dynamic, returnedNode),
    dynamicAbsent: absentDynamic === null ? null : absentDynamic.kind === 'missing',
    staticPersists: [initialStatic, absentStatic, returnedStatic].some(
      (receipt) => receipt === null
    )
      ? null
      : [initialStatic, absentStatic, returnedStatic].every((receipt) => receipt.kind === 'value'),
    staticUnchanged: staticIdentityUnchanged(
      run.observations.initial.static,
      run.observations.absent.static,
      run.observations.returned.static
    ),
    hostEpochChanged: hostEpochChanged(initialNode, returnedNode),
  };
  return {
    complete: Object.values(result).every((value) => typeof value === 'boolean'),
    metadataOnly: metadataOnlyAudit(run.invocationAudit, run),
    ...result,
  };
}

function verifyPredicates(run, computed) {
  assertion(
    hasExactKeys(run.predicates, PREDICATE_KEYS),
    'H-040 predicate receipt has missing or extra predicates'
  );
  for (const key of PREDICATE_KEYS) {
    assertion(
      run.predicates[key] === computed[key],
      `H-040 predicate does not match independent recomputation: ${key}`
    );
  }
  const classification = classifyMappingOutcome(computed);
  assertion(
    classification !== 'inconclusive' && run.outcome.status === classification,
    'H-040 outcome does not match the complete metadata-only predicate matrix'
  );
  if (Object.hasOwn(run.outcome, 'complete')) {
    assertion(run.outcome.complete === computed.complete, 'H-040 outcome completeness is invalid');
  }
  return classification;
}

export function verifyChronology(run) {
  const disconnect = verifyWindow(run.windows.disconnect, 'disconnect');
  const reconnect = verifyWindow(run.windows.reconnect, 'reconnect');
  const initial = run.observations.initial.host;
  const absent = run.observations.absent.host;
  const returned = run.observations.returned.host;
  const initialNs = monotonicNs(initial.monotonicNs, 'initial host monotonic time');
  const absentNs = monotonicNs(absent.monotonicNs, 'absent host monotonic time');
  const returnedNs = monotonicNs(returned.monotonicNs, 'returned host monotonic time');
  const initialStageNs = monotonicNs(
    run.observations.initial.monotonicNs,
    'initial stage monotonic time'
  );
  const absentStageNs = monotonicNs(
    run.observations.absent.monotonicNs,
    'absent stage monotonic time'
  );
  const returnedStageNs = monotonicNs(
    run.observations.returned.monotonicNs,
    'returned stage monotonic time'
  );
  assertion(
    initialNs <= initialStageNs &&
      initialStageNs < disconnect.openedNs &&
      disconnect.openedNs < absentNs &&
      absentNs <= absentStageNs &&
      absentStageNs <= disconnect.closedNs &&
      disconnect.closedNs < reconnect.openedNs &&
      reconnect.openedNs < returnedNs &&
      returnedNs <= returnedStageNs &&
      returnedStageNs <= reconnect.closedNs,
    'H-040 disconnect/reconnect monotonic chronology is invalid'
  );
  assertion(
    dateTimeMs(run.startedAt, 'run startedAt') <=
      dateTimeMs(initial.capturedAt, 'initial capturedAt') &&
      dateTimeMs(initial.capturedAt, 'initial capturedAt') <=
        dateTimeMs(run.observations.initial.capturedAt, 'initial stage capturedAt') &&
      dateTimeMs(run.observations.initial.capturedAt, 'initial stage capturedAt') <=
        dateTimeMs(run.windows.disconnect.openedAt, 'disconnect openedAt') &&
      dateTimeMs(run.windows.disconnect.openedAt, 'disconnect openedAt') <=
        dateTimeMs(absent.capturedAt, 'absent capturedAt') &&
      dateTimeMs(absent.capturedAt, 'absent capturedAt') <=
        dateTimeMs(run.observations.absent.capturedAt, 'absent stage capturedAt') &&
      dateTimeMs(run.observations.absent.capturedAt, 'absent stage capturedAt') <=
        dateTimeMs(run.windows.disconnect.closedAt, 'disconnect closedAt') &&
      dateTimeMs(run.windows.disconnect.closedAt, 'disconnect closedAt') <=
        dateTimeMs(run.windows.reconnect.openedAt, 'reconnect openedAt') &&
      dateTimeMs(run.windows.reconnect.openedAt, 'reconnect openedAt') <=
        dateTimeMs(returned.capturedAt, 'returned capturedAt') &&
      dateTimeMs(returned.capturedAt, 'returned capturedAt') <=
        dateTimeMs(run.observations.returned.capturedAt, 'returned stage capturedAt') &&
      dateTimeMs(run.observations.returned.capturedAt, 'returned stage capturedAt') <=
        dateTimeMs(run.windows.reconnect.closedAt, 'reconnect closedAt'),
    'H-040 disconnect/reconnect wall-clock chronology is invalid'
  );
}

function verifyHostAndScope(run, historical) {
  const serial = run.device.serial;
  assertion(
    run.device.vendorId === '0fd9' &&
      run.device.productId === '0080' &&
      serial === historical.device.serial &&
      run.device.model === historical.device.model,
    'H-040 device is not the exact H-039 MK.2 identity'
  );
  assertion(
    run.host.osId === 'fedora' &&
      run.host.osVersion === '43' &&
      run.host.osVersion === historical.host.osVersion &&
      run.host.kernel === historical.host.kernel &&
      run.host.architecture === historical.host.architecture &&
      run.host.machine === historical.host.machine &&
      sha256Canonical(run.host.principal) === sha256Canonical(historical.host.principal) &&
      run.host.graphicalSession.Name === run.host.principal.user &&
      run.host.graphicalSession.Active === 'yes' &&
      run.host.graphicalSession.State === 'active' &&
      run.host.graphicalSession.Class === 'user' &&
      run.host.graphicalSession.Remote === 'no' &&
      ['wayland', 'x11'].includes(run.host.graphicalSession.Type),
    'H-040 did not bind the exact post-login Fedora host'
  );
  const initial = exactPresentHostTuple(run.observations.initial.host, serial, 'initial');
  assertAbsentHostSnapshot(run.observations.absent.host, serial);
  const returned = exactPresentHostTuple(run.observations.returned.host, serial, 'returned');
  assertion(
    run.device.initialPath === initial.node.devicePath &&
      run.device.returnedPath === returned.node.devicePath &&
      run.device.transition === classifyDeviceTransition(initial.node, returned.node) &&
      (!Object.hasOwn(run.device, 'major') || run.device.major === initial.node.stat.major) &&
      (!Object.hasOwn(run.device, 'minor') || run.device.minor === initial.node.stat.minor),
    'H-040 declared device transition does not match the host observations'
  );
  const scopes = [
    run.observations.initial.host.scope,
    run.observations.absent.host.scope,
    run.observations.returned.host.scope,
  ];
  assertion(
    scopes.every(
      (scope) =>
        scope.bootId === scopes[0].bootId && scope.mountNamespace === scopes[0].mountNamespace
    ),
    'H-040 host scope changed during the experiment'
  );
  return { initial, returned };
}

function verifyHostPoll(receipts, artifactVerification, run) {
  const candidates = receipts.filter(({ path: receiptPath }) => /host[-_]poll/iu.test(receiptPath));
  assertion(candidates.length === 1, 'H-040 lacks one exact host-poll artifact');
  const candidate = candidates[0];
  const bytes = artifactVerification.verified.get(`${candidate.path}\0${candidate.sha256}`);
  assertion(bytes !== undefined, 'H-040 host-poll artifact was not verified');
  let entries;
  try {
    entries = bytes
      .toString('utf8')
      .trim()
      .split(/\r?\n/u)
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch {
    throw new Error('H-040 host-poll artifact is not valid JSON Lines');
  }
  function verifyStableTransition(stage, expectedState, window, observation) {
    const openedNs = BigInt(window.openedMonotonicNs);
    const closedNs = BigInt(window.closedMonotonicNs);
    const fullIndices = entries
      .map((entry, index) => ({ entry, index }))
      .filter(
        ({ entry }) =>
          entry.stage === `${stage}-full` &&
          typeof entry.monotonicNs === 'string' &&
          BigInt(entry.monotonicNs) >= openedNs &&
          BigInt(entry.monotonicNs) <= closedNs
      );
    assertion(
      fullIndices.length === 1,
      `H-040 host polling lacks one ${stage}-full snapshot inside its window`
    );
    const { entry: full, index } = fullIndices[0];
    const consecutive = entries.slice(index - 3, index);
    assertion(
      consecutive.length === 3 &&
        consecutive.every(
          (entry) =>
            entry.stage === stage &&
            entry.state === expectedState &&
            Array.isArray(entry.errors) &&
            entry.errors.length === 0
        ) &&
        full.state === expectedState &&
        Array.isArray(full.errors) &&
        full.errors.length === 0 &&
        full.capturedAt === observation.capturedAt &&
        full.monotonicNs === observation.monotonicNs,
      `H-040 host polling lacks three consecutive ${stage} snapshots plus its full snapshot`
    );
    const transition = [...consecutive, full];
    const monotonic = transition.map((entry) => BigInt(entry.monotonicNs));
    assertion(
      monotonic.every(
        (value, entryIndex) =>
          value >= openedNs &&
          value <= closedNs &&
          (entryIndex === 0 || value > monotonic[entryIndex - 1])
      ) &&
        transition.every(
          (entry) =>
            dateTimeMs(entry.capturedAt, `${stage} poll capturedAt`) >=
              dateTimeMs(window.openedAt, `${stage} window openedAt`) &&
            dateTimeMs(entry.capturedAt, `${stage} poll capturedAt`) <=
              dateTimeMs(window.closedAt, `${stage} window closedAt`)
        ),
      `H-040 ${stage} stability observations escaped their physical window`
    );
    if (expectedState === 'absent') {
      assertion(
        transition.every((entry) => entry.usb.length === 0 && entry.hidraw.length === 0),
        'H-040 absent host polling retained the exact device'
      );
    } else {
      assertion(
        transition.every(
          (entry) =>
            entry.usb.filter(({ serial }) => serial === run.device.serial).length === 1 &&
            entry.hidraw.filter(({ serial }) => serial === run.device.serial).length === 1
        ),
        'H-040 returned host polling lacks the exact serial'
      );
    }
    return full;
  }

  const absentFull = verifyStableTransition(
    'absent',
    'absent',
    run.windows.disconnect,
    run.observations.absent.host
  );
  const returnedFull = verifyStableTransition(
    'present',
    'present',
    run.windows.reconnect,
    run.observations.returned.host
  );
  if (typeof absentFull.monotonicNs === 'string' && typeof returnedFull.monotonicNs === 'string') {
    assertion(
      BigInt(absentFull.monotonicNs) < BigInt(returnedFull.monotonicNs),
      'H-040 host polling did not order absence before return'
    );
  }
}

function verifyClaimBoundary(run) {
  const proves = run.claimBoundary.proves.join(' ').toLowerCase();
  const excludes = run.claimBoundary.excludes.join(' ').toLowerCase();
  assertion(
    proves.includes('static') &&
      proves.includes('dynamic') &&
      proves.includes('metadata') &&
      proves.includes('post-login'),
    'H-040 positive claim boundary exceeds or omits the structural Slice'
  );
  for (const excluded of ['companion', 'recovery', 'udev', 'systemd', 'supervisor', 'reboot']) {
    assertion(excludes.includes(excluded), `H-040 claim boundary does not exclude ${excluded}`);
  }
  assertion(
    excludes.includes('read') && excludes.includes('write'),
    'H-040 claim boundary does not exclude HID reads and writes'
  );
}

function verifyProbe(run) {
  assertion(
    /^[0-9a-f]{64}$/u.test(run.probe.containerId) &&
      /^sha256:[0-9a-f]{64}$/u.test(run.probe.imageId) &&
      run.probe.imageReference === 'node:22' &&
      Array.isArray(run.probe.repoDigests) &&
      run.probe.repoDigests.length > 0 &&
      run.probe.repoDigests.every((digest) => /^[^@]+@sha256:[0-9a-f]{64}$/u.test(digest)) &&
      run.probe.staticPath === '/tmp/h040-static-hidraw' &&
      run.probe.dynamicRoot === '/host-dev' &&
      run.probe.privileged === false,
    'H-040 probe identity or declared mapping boundary is invalid'
  );
  if (run.probe.lifecycleBefore && run.probe.lifecycleAfter) {
    const before = run.probe.lifecycleBefore;
    const after = run.probe.lifecycleAfter;
    const exactSecurity = (lifecycle) =>
      lifecycle.restartPolicy === 'no' &&
      lifecycle.autoRemove === true &&
      lifecycle.networkMode === 'none' &&
      lifecycle.privileged === false &&
      lifecycle.readOnlyRootfs === true &&
      JSON.stringify(lifecycle.capDrop) === JSON.stringify(['ALL']) &&
      JSON.stringify(lifecycle.securityOpt) === JSON.stringify(['no-new-privileges']) &&
      Array.isArray(lifecycle.groupAdd) &&
      lifecycle.groupAdd.length === 0 &&
      lifecycle.pidsLimit === 32 &&
      lifecycle.memory === 128 * 1024 * 1024 &&
      lifecycle.deviceCgroupRules === null &&
      lifecycle.user === '65534:65534' &&
      JSON.stringify(lifecycle.command) === JSON.stringify(['sleep', 'infinity']);
    assertion(
      run.probe.lifecycleUnchanged === true &&
        before.containerId === run.probe.containerId &&
        after.containerId === before.containerId &&
        before.name === run.probe.name &&
        after.name === before.name &&
        before.imageId === run.probe.imageId &&
        after.imageId === before.imageId &&
        before.startedAt === after.startedAt &&
        before.restartCount === 0 &&
        after.restartCount === 0 &&
        before.hostPid === after.hostPid &&
        Number.isSafeInteger(before.hostPid) &&
        before.hostPid > 0 &&
        before.pid1StartTicks === after.pid1StartTicks &&
        Number.isSafeInteger(before.pid1StartTicks) &&
        before.pid1StartTicks > 0 &&
        before.running === true &&
        after.running === true &&
        exactSecurity(before) &&
        exactSecurity(after) &&
        before.devices.length === 1 &&
        before.devices[0].pathOnHost === run.device.initialPath &&
        before.devices[0].pathInContainer === run.probe.staticPath &&
        before.devices[0].cgroupPermissions === 'm' &&
        sha256Canonical(after.devices) === sha256Canonical(before.devices) &&
        sha256Canonical(after.mounts) === sha256Canonical(before.mounts) &&
        before.mounts.filter(
          (entry) =>
            entry.type === 'bind' &&
            entry.source === '/dev' &&
            entry.destination === run.probe.dynamicRoot &&
            entry.rw === false
        ).length === 1,
      'H-040 probe lifecycle or Docker mapping receipt is invalid'
    );
  }
  if (run.probe.security) {
    assertion(
      run.probe.security.network === 'none' &&
        run.probe.security.readOnlyRootfs === true &&
        run.probe.security.noNewPrivileges === true &&
        run.probe.security.user === '65534:65534' &&
        run.probe.security.staticCgroupPermissions === 'm' &&
        run.probe.security.dynamicReadOnly === true &&
        JSON.stringify(run.probe.security.capDrop) === JSON.stringify(['ALL']),
      'H-040 probe security receipt exceeds the metadata-only boundary'
    );
  }
}

function verifyCleanup(run) {
  const probeContainerId =
    run.probe.containerId ?? run.probe.container?.containerId ?? run.probe.inspect?.Id;
  assertion(
    typeof probeContainerId === 'string' &&
      probeContainerId.length > 0 &&
      run.cleanup.containerId === probeContainerId &&
      run.cleanup.containerRemoved === true &&
      run.cleanup.successful === true &&
      run.cleanup.error === null,
    'H-040 cleanup did not remove the exact lab-owned probe container'
  );
  assertion(
    dateTimeMs(run.windows.reconnect.closedAt, 'reconnect closedAt') <=
      dateTimeMs(run.cleanup.startedAt, 'cleanup startedAt') &&
      dateTimeMs(run.cleanup.startedAt, 'cleanup startedAt') <=
        dateTimeMs(run.cleanup.completedAt, 'cleanup completedAt') &&
      dateTimeMs(run.cleanup.completedAt, 'cleanup completedAt') ===
        dateTimeMs(run.completedAt, 'run completedAt'),
    'H-040 cleanup chronology is invalid'
  );
  if (run.cleanup.host) {
    const cleanupTuple = exactPresentHostTuple(run.cleanup.host, run.device.serial, 'cleanup');
    assertion(
      run.cleanup.hostConfigurationChanged === false &&
        run.cleanup.host.scope.bootId === run.observations.initial.host.scope.bootId &&
        run.cleanup.host.scope.mountNamespace ===
          run.observations.initial.host.scope.mountNamespace &&
        run.cleanup.owners.length === 1 &&
        run.cleanup.owners[0].devicePath === cleanupTuple.node.devicePath &&
        run.cleanup.owners.every(
          ({ owner }) =>
            owner.observed === true && owner.usageError === false && owner.pids.length === 0
        ),
      'H-040 cleanup did not leave the current exact device present with an empty host-namespace owner observation'
    );
  }
}

export async function verifyDockerMappingRun(filePath) {
  const runPath = path.resolve(filePath);
  const run = await readJson(runPath);
  const schema = await readJson(path.join(LAB_DIRECTORY, 'schemas/docker-mapping-run.schema.json'));
  assertSchema(compileSchema(schema), run, 'H-040');

  const { evidenceSha256, ...evidence } = run;
  assertion(sha256Canonical(evidence) === evidenceSha256, 'H-040 canonical hash mismatch');
  const artifactVerification = await verifyArtifactReceipts(runPath, run);
  await verifyCollector(runPath, run);
  const historical = await verifyHistoricalH039(runPath, run, artifactVerification);
  const host = verifyHostAndScope(run, historical);
  verifyChronology(run);
  verifyProbe(run);
  const computed = recomputePredicates(run, host.initial.node, host.returned.node);
  const outcome = verifyPredicates(run, computed);
  verifyHostPoll(artifactVerification.receipts, artifactVerification, run);
  verifyClaimBoundary(run);
  verifyCleanup(run);

  return {
    schemaVersion: 'overlaykit-h040-verification/v1',
    hypothesis: 'H-040',
    outcome,
    evidenceSha256,
    h039EvidenceSha256: historical.evidenceSha256,
    deviceSerial: run.device.serial,
    predicates: computed,
    metadataOnly: computed.metadataOnly,
    cleaned: true,
    verified: true,
  };
}

const modulePath = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === modulePath) {
  const inputPath = process.argv[2];
  if (!inputPath) throw new Error('Usage: node lab/h040/verify.mjs <run.json>');
  process.stdout.write(
    `${JSON.stringify(await verifyDockerMappingRun(path.resolve(inputPath)), null, 2)}\n`
  );
}
