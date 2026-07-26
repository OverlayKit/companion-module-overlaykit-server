#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { sha256, sha256Canonical } from './physical-lib.mjs';

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

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, 'utf8'));
}

export async function verifyPhysicalRun(filePath) {
  const run = await readJson(filePath);
  const schema = await readJson(path.join(LAB_DIRECTORY, 'schemas/physical-run.schema.json'));
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  ajv.addFormat('date-time', validDateTime);
  const validate = ajv.compile(schema);
  assertion(
    validate(run),
    `H-038 schema failed: ${(validate.errors ?? [])
      .map((error) => `${error.instancePath || '/'} ${error.message}`)
      .join('; ')}`
  );
  const { evidenceSha256, ...evidence } = run;
  assertion(sha256Canonical(evidence) === evidenceSha256, 'H-038 canonical hash mismatch');
  for (const [relativePath, expected] of Object.entries(run.collector.sourceSha256)) {
    const absolutePath = path.resolve(REPOSITORY_ROOT, relativePath);
    assertion(
      absolutePath.startsWith(`${REPOSITORY_ROOT}${path.sep}`),
      `H-038 source escaped repository: ${relativePath}`
    );
    assertion(
      sha256(await readFile(absolutePath)) === expected,
      `H-038 source hash mismatch: ${relativePath}`
    );
  }
  const manifest = await readJson(
    path.join(REPOSITORY_ROOT, '.overlaykit/governance/manifest.json')
  );
  assertion(
    manifest.contentHash === run.collector.governanceManifestContentHash,
    'H-038 governance manifest mismatch'
  );
  for (const input of [
    {
      path: run.inputs.h035Path,
      fileHash: run.inputs.h035FileSha256,
      evidenceHash: run.inputs.h035EvidenceSha256,
      hypothesis: 'H-035',
    },
    {
      path: run.inputs.h037Path,
      fileHash: run.inputs.h037FileSha256,
      evidenceHash: run.inputs.h037EvidenceSha256,
      hypothesis: 'H-037',
    },
  ]) {
    const bytes = await readFile(path.resolve(REPOSITORY_ROOT, input.path));
    const parsed = JSON.parse(bytes);
    assertion(
      sha256(bytes) === input.fileHash &&
        parsed.evidenceSha256 === input.evidenceHash &&
        parsed.hypothesis === input.hypothesis,
      `H-038 stale or mismatched ${input.hypothesis} input`
    );
  }
  assertion(
    run.host.osVersion === '43' &&
      run.host.graphicalSession.Active === 'yes' &&
      run.host.graphicalSession.State === 'active' &&
      run.host.graphicalSession.Class === 'user' &&
      run.host.graphicalSession.Remote === 'no' &&
      ['wayland', 'x11'].includes(run.host.graphicalSession.Type),
    'H-038 did not execute after a local graphical login'
  );
  assertion(
    run.device.vendorId === '0fd9' &&
      run.device.productId === '0080' &&
      run.companion.version === '4.3.3',
    'H-038 device or Companion identity mismatch'
  );
  const surface = run.companion.surface;
  assertion(
    !surface.privileged &&
      surface.groupAdd.includes(String(run.device.gid)) &&
      surface.surface.groups.includes(run.device.gid) &&
      surface.ownsDevice &&
      surface.signals.panelReady &&
      !surface.signals.openFailed,
    'H-038 did not bind an unprivileged acquired physical surface'
  );
  assertion(
    run.companion.location.pageNumber === 1 &&
      run.companion.location.row === 0 &&
      run.companion.location.column === 0 &&
      run.physicalWindow.instruction.includes('top-left'),
    'H-038 physical location or challenge is not exact'
  );
  assertion(
    run.invocationAudit.passed &&
      run.invocationAudit.virtualInvocationCount === 0 &&
      run.invocationAudit.forbidden.length === 0,
    'H-038 virtual invocation audit failed'
  );
  const { command, result, serverEvent, acknowledgement } = run.causalReceipt;
  assertion(
    command.eventSequence < result.eventSequence &&
      command.eventSequence < serverEvent.eventSequence &&
      serverEvent.eventSequence < acknowledgement.eventSequence &&
      BigInt(command.monotonicNs) > BigInt(run.physicalWindow.openedMonotonicNs) &&
      BigInt(result.monotonicNs) > BigInt(command.monotonicNs) &&
      BigInt(serverEvent.monotonicNs) > BigInt(command.monotonicNs) &&
      BigInt(acknowledgement.monotonicNs) > BigInt(serverEvent.monotonicNs) &&
      command.messageType === 'device.command.execute' &&
      command.direction === 'companion-to-server' &&
      result.operationId === command.operationId &&
      result.correlationMatches === true &&
      serverEvent.observations.some(
        (observation) =>
          observation.controlId === 'lower-third.visibility' && observation.value === 'active'
      ) &&
      acknowledgement.status === 'applied',
    'H-038 causal command/result/state/ACK chain is invalid'
  );
  assertion(
    run.companionObservation.command === 'SUB-STATE' &&
      run.companionObservation.values.SUBID === 'physical' &&
      run.companionObservation.values.TEXT === 'ACTIVE' &&
      BigInt(run.companionObservation.monotonicNs) > BigInt(run.physicalWindow.openedMonotonicNs),
    'H-038 Companion observation is not causally after the physical window'
  );
  assertion(
    run.before.owner.observed &&
      run.before.owner.pids.length === 0 &&
      run.cleanup.composeRemoved &&
      run.cleanup.successful &&
      run.cleanup.owner.observed &&
      run.cleanup.owner.pids.length === 0,
    'H-038 clean boundary or cleanup failed'
  );
  assertion(
    run.claimBoundary.excludes.some((claim) => claim.includes('pre-login')) &&
      run.claimBoundary.excludes.some((claim) => claim.includes('reconnect')) &&
      run.claimBoundary.excludes.some((claim) => claim.includes('pixels')),
    'H-038 claim boundary is incomplete'
  );
  return {
    schemaVersion: 'overlaykit-h038-verification/v1',
    hypothesis: 'H-038',
    evidenceSha256,
    verified: true,
    challenge: run.physicalWindow.challenge,
    operationId: command.operationId,
    authoritativeValue: 'active',
    virtualInvocationCount: 0,
    cleaned: true,
  };
}

const inputPath = process.argv[2];
if (!inputPath) throw new Error('Usage: node lab/h038/verify.mjs <run.json>');
process.stdout.write(
  `${JSON.stringify(await verifyPhysicalRun(path.resolve(inputPath)), null, 2)}\n`
);
