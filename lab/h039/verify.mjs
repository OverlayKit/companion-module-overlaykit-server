#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import {
  fileDescriptorMatchesDevice,
  sameTopLevelLifecycle,
  sha256,
  sha256Canonical,
  validateControlConfiguration,
} from './reconnect-lib.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');

function assertion(condition, message) {
  if (!condition) throw new Error(message);
}

function validDateTime(value) {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

function expectedConfigurationValid(receipt, expectedBearerSha256) {
  const connection = receipt?.connection;
  return (
    typeof receipt?.controlId === 'string' &&
    receipt.controlId.length > 0 &&
    connection !== null &&
    typeof connection?.id === 'string' &&
    connection.id.length > 0 &&
    connection.moduleType === 'connection' &&
    connection.moduleId === 'overlaykit-server' &&
    connection.moduleVersionId === 'dev' &&
    connection.updatePolicy === 'stable' &&
    connection.enabled === true &&
    connection.config?.endpoint === 'ws://172.30.38.10:8081/device' &&
    connection.config?.allowInsecureLan === true &&
    typeof connection.config?.trustBundle === 'string' &&
    connection.config.trustBundle.length > 0 &&
    connection.bearerSha256 === expectedBearerSha256 &&
    Array.isArray(connection.secretKeys) &&
    JSON.stringify(connection.secretKeys) === JSON.stringify(['bearer']) &&
    validateControlConfiguration(receipt.controlConfig, {
      connectionId: connection.id,
      actionId: receipt.actionId,
      feedbackId: receipt.feedbackId,
      binding: 'component.visibility/preview/lower-third',
    })
  );
}

function verifyConfigurationObservation(observation, freeze, expectedBearerSha256, label) {
  if (!observation.observed) {
    assertion(
      observation.current === null &&
        observation.currentSha256 === null &&
        !observation.expectedConfigurationValid &&
        !observation.unchanged &&
        typeof observation.error === 'string' &&
        observation.error.length > 0,
      `${label} unobserved configuration is not fail-closed`
    );
    return;
  }
  const currentSha256 = sha256Canonical(observation.current);
  const expectedValid = expectedConfigurationValid(observation.current, expectedBearerSha256);
  const unchanged =
    expectedValid &&
    currentSha256 === freeze.configurationSha256 &&
    observation.auditEntryCount === freeze.auditEntryCount;
  assertion(
    observation.error === null &&
      observation.currentSha256 === currentSha256 &&
      observation.expectedConfigurationValid === expectedValid &&
      observation.unchanged === unchanged,
    `${label} configuration flags do not match the observed control and connection`
  );
}

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, 'utf8'));
}

function safeRepositoryPath(relativePath, label) {
  const absolutePath = path.resolve(REPOSITORY_ROOT, relativePath);
  assertion(
    absolutePath.startsWith(`${REPOSITORY_ROOT}${path.sep}`),
    `${label} escaped the repository: ${relativePath}`
  );
  return absolutePath;
}

function safeEvidencePath(runPath, relativePath, label) {
  const directory = path.dirname(runPath);
  const absolutePath = path.resolve(directory, relativePath);
  assertion(
    absolutePath.startsWith(`${directory}${path.sep}`),
    `${label} escaped the evidence directory: ${relativePath}`
  );
  return absolutePath;
}

function exactHostTuple(snapshot, serial, label) {
  assertion(snapshot.state === 'present', `${label} host snapshot is not present`);
  const usb = snapshot.usb.filter((entry) => entry.serial === serial && entry.serialMatches);
  const hidraw = snapshot.hidraw.filter(
    (entry) => entry.hid.unique === serial && entry.serialMatches
  );
  assertion(usb.length === 1, `${label} lacks one exact USB serial`);
  assertion(hidraw.length === 1, `${label} lacks one exact HID serial`);
  const node = hidraw[0];
  assertion(
    node.usbAncestor?.serial === serial &&
      node.nodeStable &&
      node.nodeMatchesClass &&
      node.stat?.isCharacterDevice &&
      node.stat.major === node.classDevice.major &&
      node.stat.minor === node.classDevice.minor &&
      node.stat.rdevHex ===
        `${node.classDevice.major.toString(16)}:${node.classDevice.minor.toString(16)}`,
    `${label} HID, USB ancestor, class device, and character node do not match`
  );
  return { usb: usb[0], node };
}

function epochChanged(before, after) {
  return (
    before.usb.deviceNumber !== after.usb.deviceNumber ||
    before.usb.sysfsPath !== after.usb.sysfsPath ||
    before.node.hidDevicePath !== after.node.hidDevicePath ||
    before.node.stat.stDev !== after.node.stat.stDev ||
    before.node.stat.inode !== after.node.stat.inode ||
    before.node.stat.ctimeNs !== after.node.stat.ctimeNs ||
    before.node.stat.rdevHex !== after.node.stat.rdevHex
  );
}

function verifyWindow(window, label) {
  assertion(
    BigInt(window.openedMonotonicNs) < BigInt(window.closedMonotonicNs),
    `${label} window did not advance monotonically`
  );
}

function verifyPressCycle(cycle, window, expectedText, label) {
  assertion(
    cycle.pressed.command === 'SUB-STATE' &&
      cycle.pressed.values.PRESSED === '1' &&
      cycle.pressed.values.TEXT === expectedText &&
      cycle.released.command === 'SUB-STATE' &&
      cycle.released.values.PRESSED === '0' &&
      cycle.released.values.TEXT === expectedText &&
      BigInt(cycle.pressed.monotonicNs) > BigInt(window.openedMonotonicNs) &&
      BigInt(cycle.released.monotonicNs) > BigInt(cycle.pressed.monotonicNs),
    `${label} lacks an ordered physical press/release cycle`
  );
}

function verifyCausalReceipt(receipt, window, expectedValue, label) {
  const { command, result, serverEvent, acknowledgement } = receipt;
  assertion(
    command.eventSequence < result.eventSequence &&
      command.eventSequence < serverEvent.eventSequence &&
      serverEvent.eventSequence < acknowledgement.eventSequence &&
      BigInt(command.monotonicNs) > BigInt(window.openedMonotonicNs) &&
      BigInt(command.monotonicNs) < BigInt(window.closedMonotonicNs) &&
      BigInt(result.monotonicNs) > BigInt(command.monotonicNs) &&
      BigInt(serverEvent.monotonicNs) > BigInt(command.monotonicNs) &&
      BigInt(acknowledgement.monotonicNs) > BigInt(serverEvent.monotonicNs) &&
      command.messageType === 'device.command.execute' &&
      command.direction === 'companion-to-server' &&
      result.messageType === 'device.command.result' &&
      result.operationId === command.operationId &&
      result.correlationMatches === true &&
      result.outcome === 'applied' &&
      serverEvent.direction === 'server-to-companion' &&
      serverEvent.observations.some(
        (observation) =>
          observation.controlId === 'lower-third.visibility' && observation.value === expectedValue
      ) &&
      acknowledgement.messageType === 'device.state.ack' &&
      acknowledgement.sequence === serverEvent.sequence &&
      acknowledgement.evidenceSha256 === serverEvent.evidenceSha256 &&
      acknowledgement.status === 'applied',
    `${label} command/result/state/ACK chain is invalid`
  );
  return { command, result, serverEvent, acknowledgement };
}

async function verifyArtifact(runPath, receipt, label) {
  const bytes = await readFile(safeEvidencePath(runPath, receipt.path, label));
  assertion(sha256(bytes) === receipt.sha256, `${label} artifact hash mismatch`);
  return bytes;
}

async function verifyHistoricalH038(run) {
  const inputPath = safeRepositoryPath(run.inputs.h038Path, 'H-038 input');
  const bytes = await readFile(inputPath);
  const historical = JSON.parse(bytes);
  const { evidenceSha256, ...evidence } = historical;
  assertion(
    sha256(bytes) === run.inputs.h038FileSha256 &&
      evidenceSha256 === run.inputs.h038EvidenceSha256 &&
      sha256Canonical(evidence) === evidenceSha256 &&
      historical.hypothesis === 'H-038' &&
      historical.cleanup?.successful &&
      historical.invocationAudit?.virtualInvocationCount === 0,
    'H-039 historical H-038 input is stale or invalid'
  );
  assertion(
    historical.collector.governanceManifestContentHash ===
      run.inputs.h038HistoricalManifestContentHash,
    'H-039 historical manifest identity changed'
  );
  for (const [relativePath, expected] of Object.entries(historical.collector.sourceSha256)) {
    assertion(
      sha256(await readFile(safeRepositoryPath(relativePath, 'H-038 source'))) === expected,
      `H-039 historical H-038 source mismatch: ${relativePath}`
    );
  }
  return historical;
}

export async function verifyReconnectRun(filePath) {
  const runPath = path.resolve(filePath);
  const run = await readJson(runPath);
  const schema = await readJson(path.join(LAB_DIRECTORY, 'schemas/reconnect-run.schema.json'));
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  ajv.addFormat('date-time', validDateTime);
  const validate = ajv.compile(schema);
  assertion(
    validate(run),
    `H-039 schema failed: ${(validate.errors ?? [])
      .map((error) => `${error.instancePath || '/'} ${error.message}`)
      .join('; ')}`
  );

  const { evidenceSha256, ...evidence } = run;
  assertion(sha256Canonical(evidence) === evidenceSha256, 'H-039 canonical hash mismatch');
  for (const [relativePath, expected] of Object.entries(run.collector.sourceSha256)) {
    assertion(
      sha256(await readFile(safeRepositoryPath(relativePath, 'H-039 source'))) === expected,
      `H-039 source hash mismatch: ${relativePath}`
    );
  }

  const manifestBytes = await readFile(
    safeEvidencePath(runPath, run.collector.governance.manifestSnapshotPath, 'governance manifest')
  );
  const manifest = JSON.parse(manifestBytes);
  assertion(
    sha256(manifestBytes) === run.collector.governance.manifestFileSha256 &&
      manifest.contentHash === run.collector.governance.manifestContentHash &&
      manifest.planHash === run.collector.governance.planHash &&
      manifest.changes?.['CHG-0010'] === run.collector.governance.changeSha256 &&
      run.collector.governance.changeSha256 ===
        run.collector.sourceSha256['.overlaykit/governance/changes/CHG-0010.json'],
    'H-039 archived governance manifest is invalid'
  );
  const verifyReceipt = await readFile(
    safeEvidencePath(
      runPath,
      run.collector.governance.verifyReceiptPath,
      'governance verify receipt'
    )
  );
  assertion(
    sha256(verifyReceipt) === run.collector.governance.verifyReceiptSha256 &&
      verifyReceipt.toString('utf8').includes(`governance ok ${run.collector.governance.planHash}`),
    'H-039 archived governance verification receipt is invalid'
  );
  const historicalH038 = await verifyHistoricalH038(run);
  const companionRuntime = await verifyArtifact(
    runPath,
    run.runtimeIdentities.companion.receipt,
    'Companion runtime identity'
  );
  const overlaykitRuntime = await verifyArtifact(
    runPath,
    run.runtimeIdentities.overlaykit.receipt,
    'OverlayKit runtime identity'
  );
  const moduleArchive = await verifyArtifact(
    runPath,
    run.runtimeIdentities.companion.moduleArchive,
    'governed module archive'
  );
  assertion(
    companionRuntime.toString('utf8').includes('node=v22.22.2') &&
      companionRuntime.toString('utf8').includes('os=ubuntu\nversion=24.04') &&
      overlaykitRuntime.toString('utf8').includes('node=v24.6.0') &&
      run.runtimeIdentities.overlaykit.values.commit ===
        run.inputs.lockedInputs.overlaykit.commit &&
      run.runtimeIdentities.companion.values.module_sha256 === sha256(moduleArchive) &&
      run.runtimeIdentities.companion.moduleArchive.sha256 === sha256(moduleArchive),
    'H-039 runtime product or module identity is invalid'
  );

  assertion(
    run.host.osId === 'fedora' &&
      run.host.osVersion === historicalH038.host.osVersion &&
      run.host.kernel === historicalH038.host.kernel &&
      run.host.architecture === historicalH038.host.architecture &&
      sha256Canonical(run.host.principal) === sha256Canonical(historicalH038.host.principal) &&
      run.host.graphicalSession.Name === run.host.principal.user &&
      run.host.graphicalSession.Active === 'yes' &&
      run.host.graphicalSession.State === 'active' &&
      run.host.graphicalSession.Class === 'user' &&
      run.host.graphicalSession.Remote === 'no' &&
      ['wayland', 'x11'].includes(run.host.graphicalSession.Type),
    'H-039 did not execute after an exact local graphical login'
  );
  const initial = exactHostTuple(run.observations.initial, run.device.serial, 'initial');
  const reconnected = exactHostTuple(
    run.observations.reconnected,
    run.device.serial,
    'reconnected'
  );
  assertion(
    run.observations.disconnected.state === 'absent' &&
      run.observations.disconnected.lsusb.matches.length === 0 &&
      run.observations.disconnected.usb.length === 0 &&
      run.observations.disconnected.hidraw.length === 0 &&
      run.observations.disconnected.priorPath.stat.kind === 'missing',
    'H-039 did not prove exact physical disappearance'
  );
  assertion(
    run.observations.initial.scope.bootId === run.observations.disconnected.scope.bootId &&
      run.observations.initial.scope.bootId === run.observations.reconnected.scope.bootId &&
      run.observations.initial.scope.mountNamespace ===
        run.observations.disconnected.scope.mountNamespace &&
      run.observations.initial.scope.mountNamespace ===
        run.observations.reconnected.scope.mountNamespace,
    'H-039 host scope changed during the experiment'
  );
  assertion(epochChanged(initial, reconnected), 'H-039 lacks a new enumeration epoch');

  for (const [label, window] of Object.entries({
    baseline: run.windows.baseline,
    disconnect: run.windows.disconnect,
    reconnect: run.windows.reconnect,
  })) {
    verifyWindow(window, label);
  }
  assertion(
    BigInt(run.windows.baseline.closedMonotonicNs) <
      BigInt(run.windows.disconnect.openedMonotonicNs) &&
      BigInt(run.windows.disconnect.openedMonotonicNs) <
        BigInt(run.observations.disconnected.monotonicNs) &&
      BigInt(run.observations.disconnected.monotonicNs) <=
        BigInt(run.windows.disconnect.closedMonotonicNs) &&
      BigInt(run.windows.disconnect.closedMonotonicNs) <
        BigInt(run.windows.reconnect.openedMonotonicNs) &&
      BigInt(run.windows.reconnect.openedMonotonicNs) <
        BigInt(run.observations.reconnected.monotonicNs) &&
      BigInt(run.observations.reconnected.monotonicNs) <=
        BigInt(run.windows.reconnect.closedMonotonicNs),
    'H-039 disconnect/reconnect chronology is invalid'
  );

  const pollBytes = await verifyArtifact(runPath, run.observations.hostPollArtifact, 'host poll');
  const poll = pollBytes
    .toString('utf8')
    .trim()
    .split(/\r?\n/u)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  const absentIndex = poll.findIndex((entry) => entry.state === 'absent');
  const presentAfterIndex = poll.findIndex(
    (entry, index) => index > absentIndex && entry.state === 'present'
  );
  assertion(
    absentIndex >= 0 && presentAfterIndex > absentIndex,
    'H-039 polling lacks ordered absence and return'
  );

  for (const [label, runtime] of Object.entries({
    before: run.observations.runtimeBefore,
    disconnected: run.observations.runtimeDisconnected,
    reconnected: run.observations.runtimeReconnected,
    reacquisition: run.observations.reacquisition.runtime,
    final: run.observations.runtimeFinal,
  })) {
    await verifyArtifact(runPath, runtime.logArtifact, `${label} Companion log`);
  }
  assertion(
    run.observations.runtimeBefore.matchesCurrentDevice &&
      fileDescriptorMatchesDevice(run.observations.runtimeBefore, initial.node) &&
      run.observations.runtimeBefore.logMarkers.ready >= 1,
    'H-039 initial current-device acquisition receipt is invalid'
  );

  assertion(
    sameTopLevelLifecycle(run.lifecycle.before, run.lifecycle.before),
    'H-039 initial top-level lifecycle is incomplete'
  );
  assertion(
    sameTopLevelLifecycle(run.lifecycle.before, run.lifecycle.afterReconnect) ===
      run.lifecycle.unchangedAfterReconnect &&
      sameTopLevelLifecycle(run.lifecycle.before, run.lifecycle.final) ===
        run.lifecycle.unchangedFinal,
    'H-039 lifecycle flags do not match process evidence'
  );
  assertion(
    sha256Canonical(run.configuration.freeze.configuration) ===
      run.configuration.freeze.configurationSha256,
    'H-039 frozen configuration hash is invalid'
  );
  assertion(
    expectedConfigurationValid(
      run.configuration.freeze.configuration,
      run.provisioning.bearerSha256
    ),
    'H-039 frozen receipt lacks the exact real Companion control or connection'
  );
  verifyConfigurationObservation(
    run.configuration.afterReconnect,
    run.configuration.freeze,
    run.provisioning.bearerSha256,
    'post-reconnect'
  );
  verifyConfigurationObservation(
    run.configuration.final,
    run.configuration.freeze,
    run.provisioning.bearerSha256,
    'final'
  );

  const baseline = verifyCausalReceipt(
    run.baseline.causalReceipt,
    run.windows.baseline,
    'active',
    'baseline'
  );
  verifyPressCycle(run.baseline.pressCycle, run.windows.baseline, 'ACTIVE', 'baseline');
  assertion(
    run.quietAudit.commandCount === 0 &&
      run.quietAudit.commands.length === 0 &&
      run.quietAudit.afterEventSequence === baseline.acknowledgement.eventSequence &&
      run.quietAudit.throughEventSequence >= run.quietAudit.afterEventSequence,
    'H-039 quiet disconnect/reconnect command audit failed'
  );
  assertion(
    run.invocationAudit.passed &&
      run.invocationAudit.virtualInvocationCount === 0 &&
      run.invocationAudit.forbidden.length === 0 &&
      run.configuration.freeze.auditEntryCount === run.invocationAudit.entries.length,
    'H-039 bounded runner invocation or configuration audit failed'
  );

  if (run.outcome.status === 'supported') {
    assertion(
      run.lifecycle.unchangedAfterReconnect &&
        run.lifecycle.unchangedFinal &&
        run.configuration.afterReconnect.observed &&
        run.configuration.afterReconnect.unchanged &&
        run.configuration.final.observed &&
        run.configuration.final.unchanged &&
        run.observations.reacquisition.currentDeviceDescriptorObserved &&
        run.observations.reacquisition.timeout === null &&
        fileDescriptorMatchesDevice(run.observations.reacquisition.runtime, reconnected.node) &&
        run.observations.runtimeFinal.matchesCurrentDevice &&
        fileDescriptorMatchesDevice(run.observations.runtimeFinal, reconnected.node),
      'H-039 supported outcome lacks unchanged lifecycle/configuration/current FD'
    );
    verifyWindow(run.windows.postReconnect, 'post-reconnect');
    const recovered = verifyCausalReceipt(
      run.postReconnect.causalReceipt,
      run.windows.postReconnect,
      'inactive',
      'post-reconnect'
    );
    verifyPressCycle(
      run.postReconnect.pressCycle,
      run.windows.postReconnect,
      'INACTIVE',
      'post-reconnect'
    );
    assertion(
      recovered.command.operationId !== baseline.command.operationId &&
        recovered.command.eventSequence > run.quietAudit.throughEventSequence &&
        recovered.result.resultingRevision > baseline.result.resultingRevision &&
        recovered.serverEvent.frameRevision > baseline.serverEvent.frameRevision,
      'H-039 recovered physical action is not a new authoritative transition'
    );
  } else if (run.outcome.stage === 'post-reconnect-physical-input') {
    assertion(
      run.lifecycle.unchangedAfterReconnect &&
        run.lifecycle.unchangedFinal &&
        run.configuration.afterReconnect.observed &&
        run.configuration.afterReconnect.unchanged &&
        run.configuration.final.observed &&
        run.configuration.final.unchanged &&
        run.observations.reacquisition.currentDeviceDescriptorObserved &&
        run.observations.reacquisition.timeout === null,
      'H-039 physical-input refutation lacks unchanged stack/configuration'
    );
    verifyWindow(run.windows.postReconnect, 'refuted post-reconnect');
    const elapsed =
      BigInt(run.windows.postReconnect.closedMonotonicNs) -
      BigInt(run.windows.postReconnect.openedMonotonicNs);
    verifyPressCycle(
      run.postReconnect.pressCycle,
      run.windows.postReconnect,
      'INACTIVE',
      'refuted post-reconnect'
    );
    assertion(
      elapsed >= BigInt(run.windows.postReconnect.timeoutSeconds) * 1_000_000_000n &&
        run.postReconnect.waitResults.causal.status === 'rejected' &&
        run.postReconnect.waitResults.satellite.status === 'fulfilled' &&
        run.postReconnect.causalReceipt === null,
      'H-039 physical-input refutation lacks a witnessed press and expired causal deadline'
    );
  } else if (run.outcome.stage === 'companion-reacquisition') {
    const elapsed =
      BigInt(run.observations.reacquisition.completedMonotonicNs) -
      BigInt(run.observations.reacquisition.startedMonotonicNs);
    assertion(
      run.lifecycle.unchangedAfterReconnect &&
        run.lifecycle.unchangedFinal &&
        run.configuration.afterReconnect.observed &&
        run.configuration.afterReconnect.unchanged &&
        run.configuration.final.observed &&
        run.configuration.final.unchanged &&
        !run.observations.reacquisition.currentDeviceDescriptorObserved &&
        typeof run.observations.reacquisition.timeout === 'string' &&
        !fileDescriptorMatchesDevice(run.observations.reacquisition.runtime, reconnected.node) &&
        elapsed >= BigInt(run.observations.reacquisition.timeoutSeconds) * 1_000_000_000n,
      'H-039 reacquisition refutation lacks an expired current-device deadline'
    );
  } else if (run.outcome.stage === 'top-level-lifecycle') {
    assertion(
      !run.lifecycle.unchangedAfterReconnect,
      'H-039 lifecycle refutation does not show a changed top-level identity'
    );
  } else {
    assertion(
      run.lifecycle.unchangedAfterReconnect &&
        run.configuration.afterReconnect.observed &&
        !run.configuration.afterReconnect.unchanged,
      'H-039 configuration refutation lacks observed configuration change'
    );
  }

  const cleanupTuple = exactHostTuple(run.cleanup.host, run.device.serial, 'cleanup');
  assertion(
    run.cleanup.composeRemoved &&
      run.cleanup.successful &&
      run.cleanup.host.scope.bootId === run.observations.initial.scope.bootId &&
      run.cleanup.host.scope.mountNamespace === run.observations.initial.scope.mountNamespace &&
      run.cleanup.owners.length === 1 &&
      run.cleanup.owners[0].devicePath === cleanupTuple.node.devicePath &&
      run.cleanup.owners.every(
        ({ owner }) => owner.observed && owner.usageError === false && owner.pids.length === 0
      ),
    'H-039 cleanup did not release all current exact-device resources'
  );
  assertion(
    run.claimBoundary.excludes.some((claim) => claim.includes('reboot')) &&
      run.claimBoundary.excludes.some((claim) => claim.includes('pixels')) &&
      run.claimBoundary.excludes.some((claim) => claim.includes('production container')),
    'H-039 claim boundary is incomplete'
  );

  return {
    schemaVersion: 'overlaykit-h039-verification/v1',
    hypothesis: 'H-039',
    outcome: run.outcome.status,
    stage: run.outcome.stage,
    evidenceSha256,
    deviceTransition: run.device.transition,
    topLevelLifecycleUnchanged: run.lifecycle.unchangedFinal,
    configurationUnchanged: run.configuration.final.unchanged,
    virtualInvocationCount: 0,
    cleaned: true,
    verified: true,
  };
}

const inputPath = process.argv[2];
if (!inputPath) throw new Error('Usage: node lab/h039/verify.mjs <run.json>');
process.stdout.write(
  `${JSON.stringify(await verifyReconnectRun(path.resolve(inputPath)), null, 2)}\n`
);
