#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { classifyDeviceTransition, sha256, sha256Canonical } from '../h039/reconnect-lib.mjs';
import { selectExactTargetHidraw } from './host-inventory.mjs';
import {
  H041_CLAIM_BOUNDARY,
  classifyH041Outcome,
  countAcquisitionMarkers,
  descriptorMatchesDynamicNode,
  dynamicStageMatchesHost,
  hostEpochChanged,
  sameSurfaceWorker,
  sameTopLevelLifecycle,
  statIdentityEqual,
} from './reacquisition-lib.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const EXPECTED_H037_SHA256 = '22d8f1d440a521af2ec8dd75cbfa68db09b7140c85f90bc48310aa78d27d6e9c';
const EXPECTED_H039_SHA256 = 'e78ed04dd10469e863b33e4fa497ddc745a20574fb18095c2bde7cf3fdb594ce';
const EXPECTED_H040_SHA256 = '04b3b9aedeb51e1bd5d6c1bd4e68e9d284951d2b21276aea3f5a180f0fe2a108';
const OFFICIAL_IMAGE =
  'ghcr.io/bitfocus/companion/companion:v4.3.3@sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e';
const EXPECTED_IMAGE_ID = 'sha256:e7d24e3b0e32b0edb799f262493536cb1a47d307af4e6527551427e09266bf10';
const EXPECTED_IMAGE_REVISION = '06a7406709d6a858039333a8988047296ef3aa4a';
const PREDICATE_KEYS = [
  'complete',
  'interventionFree',
  'permissionBoundaryExact',
  'hostEpochChanged',
  'dynamicViewTracksHost',
  'topLevelLifecycleUnchanged',
  'baselineAcquired',
  'descriptorAbsent',
  'postReturnDescriptorObserved',
  'postReturnLogMarkersObserved',
  'deadlineBoundaryConsistent',
];
const REQUIRED_SOURCE_PATHS = [
  '.overlaykit/governance/changes/CHG-0012.json',
  'lab/h034/lib/util.mjs',
  'lab/h035/inventory-lib.mjs',
  'lab/h037/acquisition-lib.mjs',
  'lab/h038/physical-lib.mjs',
  'lab/h039/host-observer.mjs',
  'lab/h039/reconnect-lib.mjs',
  'lab/h039/schemas/reconnect-run.schema.json',
  'lab/h039/verify.mjs',
  'lab/h040/probe-lib.mjs',
  'lab/h040/schemas/docker-mapping-run.schema.json',
  'lab/h040/verify.mjs',
  'lab/h041/container-observer.mjs',
  'lab/h041/container-observer.test.mjs',
  'lab/h041/entrypoint.sh',
  'lab/h041/host-inventory.mjs',
  'lab/h041/host-inventory.test.mjs',
  'lab/h041/reacquisition-lib.mjs',
  'lab/h041/reacquisition-lib.test.mjs',
  'lab/h041/run.mjs',
  'lab/h041/schema.test.mjs',
  'lab/h041/schemas/dynamic-reacquisition-run.schema.json',
  'lab/h041/verify.mjs',
  'lab/h041/verify.test.mjs',
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
    `${label} escaped the repository`
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
    `${label} escaped the evidence directory`
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
  assertion(snapshot.expectedSerial === serial, `${label} expected another serial`);
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
    `${label} HID and character-node identities disagree`
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
    'H-041 did not prove exact physical absence'
  );
}

async function verifiedArtifact(runPath, receipt, label) {
  const bytes = await readFile(safeEvidencePath(runPath, receipt.path, label));
  assertion(sha256(bytes) === receipt.sha256, `${label} hash mismatch`);
  return bytes;
}

function parseJsonLines(bytes, label) {
  try {
    const text = bytes.toString('utf8').trim();
    assertion(text.length > 0, `${label} is empty`);
    return text
      .split(/\r?\n/u)
      .filter(Boolean)
      .map((line) => JSON.parse(line));
  } catch (error) {
    if (error instanceof Error && error.message === `${label} is empty`) throw error;
    throw new Error(`${label} is not valid JSON Lines`);
  }
}

async function verifyCollector(runPath, run) {
  assertion(run.collector.sourceStable === true, 'H-041 collector source was not stable');
  for (const requiredPath of REQUIRED_SOURCE_PATHS) {
    assertion(
      Object.hasOwn(run.collector.sourceSha256, requiredPath),
      `H-041 collector omitted source identity: ${requiredPath}`
    );
  }
  assertion(
    Object.keys(run.collector.sourceSha256).length === REQUIRED_SOURCE_PATHS.length,
    'H-041 collector has an unexpected source identity'
  );
  for (const [relativePath, expected] of Object.entries(run.collector.sourceSha256)) {
    const bytes = await readFile(safeRepositoryPath(relativePath, 'H-041 source'));
    assertion(sha256(bytes) === expected, `H-041 source hash mismatch: ${relativePath}`);
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
      manifest.changes?.['CHG-0012'] === governance.changeSha256 &&
      governance.changeSha256 ===
        run.collector.sourceSha256['.overlaykit/governance/changes/CHG-0012.json'],
    'H-041 archived governance manifest is invalid'
  );
  const verifyReceipt = await readFile(
    safeEvidencePath(runPath, governance.verifyReceiptPath, 'governance verify receipt')
  );
  assertion(
    sha256(verifyReceipt) === governance.verifyReceiptSha256 &&
      verifyReceipt.toString('utf8').includes(`governance ok ${governance.planHash}`),
    'H-041 archived governance verification receipt is invalid'
  );
}

function canonicalEvidence(run, expected) {
  const { evidenceSha256, ...evidence } = run;
  assertion(
    run.schemaVersion === expected.schemaVersion &&
      run.hypothesis === expected.hypothesis &&
      evidenceSha256 === expected.evidenceSha256 &&
      sha256Canonical(evidence) === evidenceSha256,
    `${expected.hypothesis} canonical evidence is invalid`
  );
}

async function verifyInputs(runPath, run) {
  const h037Bytes = await readFile(safeRepositoryPath(run.inputs.h037.path, 'H-037 input'));
  const h039Bytes = await readFile(safeRepositoryPath(run.inputs.h039.path, 'H-039 input'));
  const h040Bytes = await readFile(safeRepositoryPath(run.inputs.h040.path, 'H-040 input'));
  assertion(
    sha256(h037Bytes) === run.inputs.h037.fileSha256 &&
      sha256(h039Bytes) === run.inputs.h039.fileSha256 &&
      sha256(h040Bytes) === run.inputs.h040.fileSha256,
    'H-041 predecessor file hash mismatch'
  );
  const h037 = JSON.parse(h037Bytes);
  const h039 = JSON.parse(h039Bytes);
  const h040 = JSON.parse(h040Bytes);
  canonicalEvidence(h037, {
    schemaVersion: 'overlaykit-h037-acquisition/v1',
    hypothesis: 'H-037',
    evidenceSha256: EXPECTED_H037_SHA256,
  });
  canonicalEvidence(h039, {
    schemaVersion: 'overlaykit-h039-reconnect-run/v1',
    hypothesis: 'H-039',
    evidenceSha256: EXPECTED_H039_SHA256,
  });
  canonicalEvidence(h040, {
    schemaVersion: 'overlaykit-h040-docker-mapping-run/v1',
    hypothesis: 'H-040',
    evidenceSha256: EXPECTED_H040_SHA256,
  });
  assertion(
    run.inputs.h037.evidenceSha256 === EXPECTED_H037_SHA256 &&
      run.inputs.h039.evidenceSha256 === EXPECTED_H039_SHA256 &&
      run.inputs.h040.evidenceSha256 === EXPECTED_H040_SHA256 &&
      h037.input.device.serial === h039.device.serial &&
      h039.device.serial === h040.device.serial &&
      h037.input.companion.image === OFFICIAL_IMAGE &&
      h037.input.companion.imageId === EXPECTED_IMAGE_ID &&
      h037.positive.signals.panelOpening === true &&
      h037.positive.signals.panelReady === true &&
      h037.positive.process.ownsDevice === true,
    'H-041 predecessor identities or positive control are invalid'
  );

  const [h037ValidationBytes, h039ReceiptBytes, h040ReceiptBytes] = await Promise.all([
    verifiedArtifact(runPath, run.inputs.h037.validationReceipt, 'H-037 validation receipt'),
    verifiedArtifact(runPath, run.inputs.h039.verificationReceipt, 'H-039 verification receipt'),
    verifiedArtifact(runPath, run.inputs.h040.verificationReceipt, 'H-040 verification receipt'),
  ]);
  const h037Validation = JSON.parse(h037ValidationBytes);
  const h039Receipt = JSON.parse(h039ReceiptBytes);
  const h040Receipt = JSON.parse(h040ReceiptBytes);
  assertion(
    h037Validation.schemaVersion === 'overlaykit-h041-h037-validation/v1' &&
      h037Validation.hypothesis === 'H-037' &&
      h037Validation.fileSha256 === run.inputs.h037.fileSha256 &&
      h037Validation.evidenceSha256 === EXPECTED_H037_SHA256 &&
      h037Validation.imageId === EXPECTED_IMAGE_ID &&
      h037Validation.deviceSerial === h037.input.device.serial &&
      h037Validation.canonicalHashValid === true &&
      h037Validation.sourceHashesValid === true &&
      h037Validation.positiveAcquisitionValid === true &&
      h037Validation.verified === true,
    'H-041 H-037 validation receipt is invalid'
  );
  assertion(
    h039Receipt.schemaVersion === 'overlaykit-h039-verification/v1' &&
      h039Receipt.hypothesis === 'H-039' &&
      h039Receipt.outcome === 'refuted' &&
      h039Receipt.stage === 'companion-reacquisition' &&
      h039Receipt.evidenceSha256 === EXPECTED_H039_SHA256 &&
      h039Receipt.topLevelLifecycleUnchanged === true &&
      h039Receipt.configurationUnchanged === true &&
      h039Receipt.virtualInvocationCount === 0 &&
      h039Receipt.cleaned === true &&
      h039Receipt.verified === true,
    'H-041 H-039 verification receipt is invalid'
  );
  assertion(
    h040Receipt.schemaVersion === 'overlaykit-h040-verification/v1' &&
      h040Receipt.hypothesis === 'H-040' &&
      h040Receipt.outcome === 'supported' &&
      h040Receipt.evidenceSha256 === EXPECTED_H040_SHA256 &&
      h040Receipt.h039EvidenceSha256 === EXPECTED_H039_SHA256 &&
      Object.values(h040Receipt.predicates).every((value) => value === true) &&
      h040Receipt.metadataOnly === true &&
      h040Receipt.cleaned === true &&
      h040Receipt.verified === true,
    'H-041 H-040 verification receipt is invalid'
  );
  return { h037, h039, h040 };
}

function exactWorkerIdentity(worker) {
  return {
    pid: worker.pid,
    startTicks: worker.startTicks,
    ppid: worker.ppid,
    parentStartTicks: worker.parentStartTicks,
    pidNamespace: worker.pidNamespace,
    mountNamespace: worker.mountNamespace,
    cgroup: worker.cgroup,
  };
}

function verifyRuntime(runtime, run, label) {
  const observer = runtime.observer;
  const container = runtime.container;
  const pid1Processes = observer.processes.filter((processReceipt) => processReceipt.pid === 1);
  assertion(
    observer.schemaVersion === 'overlaykit-h041-container-observation/v1' &&
      observer.metadataOnly === true &&
      observer.paths.dynamic.path === run.companion.dynamicPath &&
      observer.paths.compat.path === run.companion.compatibilityPath &&
      observer.paths.compat.linkTarget === run.companion.dynamicPath &&
      observer.target.major === Number(run.companion.deviceCgroupRule.split(/[ :]/u)[1]) &&
      observer.target.minor === Number(run.companion.deviceCgroupRule.split(/[ :]/u)[2]) &&
      observer.pid1.pid === 1 &&
      observer.pid1.uid === 1000 &&
      observer.pid1.gid === 1000 &&
      pid1Processes.length === 1 &&
      sha256Canonical(pid1Processes[0]) === sha256Canonical(observer.pid1) &&
      JSON.stringify([...observer.pid1.groups].sort((left, right) => left - right)) ===
        JSON.stringify([1000, run.companion.deviceGid]) &&
      observer.surfaceWorkers.every((worker) => {
        const { fileDescriptors: _fileDescriptors, ...workerProcess } = worker;
        const matches = observer.processes.filter(
          (processReceipt) =>
            processReceipt.pid === worker.pid && processReceipt.startTicks === worker.startTicks
        );
        return (
          worker.uid === 1000 &&
          worker.gid === 1000 &&
          worker.groups.includes(run.companion.deviceGid) &&
          worker.ppid === observer.pid1.pid &&
          worker.parentStartTicks === observer.pid1.startTicks &&
          worker.cmdline.some((entry) => entry.endsWith('/SurfaceThread.js')) &&
          matches.length === 1 &&
          sha256Canonical(matches[0]) === sha256Canonical(workerProcess)
        );
      }),
    `${label} container observer identity is invalid`
  );
  const expectedLifecycle = {
    containerId: container.containerId,
    imageId: container.imageId,
    startedAt: container.startedAt,
    restartCount: container.restartCount,
    hostPid: container.hostPid,
    pid1StartTicks: observer.pid1.startTicks,
    pidNamespace: observer.pid1.pidNamespace,
    mountNamespace: observer.pid1.mountNamespace,
    cgroup: observer.pid1.cgroup,
    hostCgroup: container.hostCgroup,
    cgroupNamespaceMode: container.cgroupNamespaceMode,
  };
  const expectedHostCgroup = `0::/system.slice/docker-${container.containerId}.scope`;
  assertion(
    sha256Canonical(runtime.lifecycle) === sha256Canonical(expectedLifecycle) &&
      container.hostPidStartTicks === observer.pid1.startTicks &&
      container.hostPidNamespace === observer.pid1.pidNamespace &&
      container.hostMountNamespace === observer.pid1.mountNamespace &&
      container.cgroupNamespaceMode === 'private' &&
      container.hostCgroup === expectedHostCgroup &&
      observer.pid1.cgroup === '0::/',
    `${label} flattened lifecycle is invalid`
  );
  for (const worker of observer.surfaceWorkers) {
    for (const descriptor of worker.fileDescriptors) {
      assertion(
        descriptor.stat.isCharacterDevice === true &&
          (descriptor.stat.major === observer.target.major ||
            /^\/(?:dev|host-dev)\/hidraw[0-9]+(?: \(deleted\))?$/u.test(descriptor.target)),
        `${label} observer admitted a non-hidraw descriptor`
      );
    }
  }
}

export function verifyLifecycleBindings(run) {
  const bindings = [
    [
      run.companion.initialLifecycle,
      run.observations.initial.runtime.lifecycle,
      'initial lifecycle',
    ],
    [run.companion.absentLifecycle, run.observations.absent.runtime.lifecycle, 'absent lifecycle'],
    [run.companion.finalLifecycle, run.observations.returned.runtime.lifecycle, 'final lifecycle'],
    [
      run.companion.workerLifecycle.initial,
      run.observations.initial.runtime.observer.surfaceWorkers,
      'initial workers',
    ],
    [
      run.companion.workerLifecycle.absent,
      run.observations.absent.runtime.observer.surfaceWorkers,
      'absent workers',
    ],
    [
      run.companion.workerLifecycle.final,
      run.observations.returned.runtime.observer.surfaceWorkers,
      'final workers',
    ],
  ];
  for (const [declared, observed, label] of bindings) {
    assertion(
      sha256Canonical(declared) === sha256Canonical(observed),
      `H-041 ${label} does not match its primary runtime receipt`
    );
  }
  return true;
}

function targetDescriptors(runtime) {
  return runtime.observer.surfaceWorkers.flatMap((worker) =>
    worker.fileDescriptors.filter((descriptor) =>
      descriptorMatchesDynamicNode(descriptor, runtime.observer.paths.dynamic.stat)
    )
  );
}

function baselineAcquired(runtime) {
  return (
    runtime.observer.surfaceWorkers.length === 1 &&
    runtime.markers.opening > 0 &&
    runtime.markers.ready > 0 &&
    targetDescriptors(runtime).length > 0 &&
    runtime.observer.pid1.uid === 1000 &&
    runtime.observer.pid1.gid === 1000
  );
}

function descriptorAbsent(runtime) {
  return (
    runtime.observer.paths.dynamic.stat.kind === 'missing' &&
    runtime.observer.paths.compat.stat.kind === 'missing' &&
    runtime.observer.surfaceWorkers.every((worker) => worker.fileDescriptors.length === 0)
  );
}

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

function permissionBoundaryExact(runtime, run, initialNode, currentNode) {
  const { container, observer } = runtime;
  const environment = Object.fromEntries(
    container.environment.map((entry) => {
      const separator = entry.indexOf('=');
      return [entry.slice(0, separator), entry.slice(separator + 1)];
    })
  );
  const optionSet = (value) =>
    typeof value === 'string' ? [...value.split(',')].sort().join(',') : null;
  const dynamicMounts = container.mounts.filter(
    (entry) =>
      entry.type === 'bind' &&
      entry.source === '/dev' &&
      entry.destination === '/host-dev' &&
      entry.rw === false
  );
  const declaredDynamicMounts = container.declaredMounts.filter(
    (entry) =>
      entry.type === 'bind' &&
      entry.source === '/dev' &&
      entry.target === '/host-dev' &&
      entry.readOnly === true &&
      entry.bindOptions?.NonRecursive === true
  );
  const scriptMounts = container.mounts.filter(
    (entry) =>
      entry.type === 'bind' &&
      ['/h041-entrypoint.sh', '/h041-container-observer.mjs'].includes(entry.destination) &&
      entry.rw === false
  );
  const declaredScriptMounts = container.declaredMounts.filter(
    (entry) =>
      entry.type === 'bind' &&
      ['/h041-entrypoint.sh', '/h041-container-observer.mjs'].includes(entry.target) &&
      entry.readOnly === true
  );
  return (
    run.companion.staticDevices.length === 0 &&
    run.companion.deviceCgroupRule === `c ${initialNode.stat.major}:${initialNode.stat.minor} rw` &&
    initialNode.stat.uid === 0 &&
    initialNode.stat.gid === run.companion.deviceGid &&
    initialNode.stat.mode === '0660' &&
    sameDeviceAccessBoundary(initialNode.stat, currentNode.stat) &&
    observer.paths.dynamic.stat.kind === 'value' &&
    sameDeviceAccessBoundary(currentNode.stat, observer.paths.dynamic.stat.value) &&
    observer.paths.compat.stat.kind === 'value' &&
    sameDeviceAccessBoundary(currentNode.stat, observer.paths.compat.stat.value) &&
    container.containerId === run.companion.containerId &&
    container.imageId === EXPECTED_IMAGE_ID &&
    container.restartPolicy === 'no' &&
    container.autoRemove === true &&
    container.networkMode === 'none' &&
    container.cgroupNamespaceMode === 'private' &&
    container.privileged === false &&
    container.readOnlyRootfs === true &&
    JSON.stringify([...container.capAdd].sort()) === JSON.stringify(['CAP_SETGID', 'CAP_SETUID']) &&
    JSON.stringify(container.capDrop) === JSON.stringify(['ALL']) &&
    container.securityOpt.includes('no-new-privileges') &&
    container.groupAdd.map(Number).includes(run.companion.deviceGid) &&
    container.pidsLimit === 128 &&
    container.memory === 1024 * 1024 * 1024 &&
    JSON.stringify(container.deviceCgroupRules) ===
      JSON.stringify([run.companion.deviceCgroupRule]) &&
    container.devices.length === 0 &&
    JSON.stringify(Object.keys(container.tmpfs).sort()) ===
      JSON.stringify(['/companion', '/tmp']) &&
    optionSet(container.tmpfs['/companion']) ===
      optionSet('rw,nosuid,nodev,noexec,size=268435456,uid=1000,gid=1000,mode=0700') &&
    optionSet(container.tmpfs['/tmp']) ===
      optionSet('rw,nosuid,nodev,size=67108864,uid=1000,gid=1000,mode=1777') &&
    container.user === '0:0' &&
    environment.COMPANION_CONFIG_BASEDIR === '/companion' &&
    environment.H041_UID === '1000' &&
    environment.H041_GID === '1000' &&
    environment.H041_DEVICE_GID === String(run.companion.deviceGid) &&
    environment.H041_DYNAMIC_PATH === run.companion.dynamicPath &&
    environment.H041_COMPAT_PATH === run.companion.compatibilityPath &&
    !Object.keys(environment).some((key) => key.includes('OVERLAYKIT')) &&
    container.labels['dev.overlaykit.hypothesis'] === 'H-041' &&
    JSON.stringify(container.entrypoint) === JSON.stringify(['/bin/bash']) &&
    JSON.stringify(container.command) === JSON.stringify(['/h041-entrypoint.sh']) &&
    dynamicMounts.length === 1 &&
    declaredDynamicMounts.length === 1 &&
    scriptMounts.length === 2 &&
    declaredScriptMounts.length === 2 &&
    container.mounts.length === 3 &&
    container.declaredMounts.length === 3 &&
    scriptMounts.every((entry) => {
      const relativePath =
        entry.destination === '/h041-entrypoint.sh'
          ? 'lab/h041/entrypoint.sh'
          : 'lab/h041/container-observer.mjs';
      return entry.source === path.join(REPOSITORY_ROOT, relativePath);
    }) &&
    declaredScriptMounts.every((entry) => {
      const relativePath =
        entry.target === '/h041-entrypoint.sh'
          ? 'lab/h041/entrypoint.sh'
          : 'lab/h041/container-observer.mjs';
      return entry.source === path.join(REPOSITORY_ROOT, relativePath);
    }) &&
    observer.pid1.uid === 1000 &&
    observer.pid1.gid === 1000 &&
    JSON.stringify([...observer.pid1.groups].sort((left, right) => left - right)) ===
      JSON.stringify([1000, run.companion.deviceGid]) &&
    observer.paths.compat.lstat.kind === 'value' &&
    observer.paths.compat.lstat.value.isSymbolicLink === true &&
    observer.paths.compat.linkTarget === run.companion.dynamicPath
  );
}

function verifyInvocationAudit(run) {
  const audit = run.invocationAudit;
  const allowedKinds = new Set([
    'docker-run',
    'docker-inspect',
    'docker-observe',
    'docker-logs',
    'physical-disconnect-window',
    'physical-reconnect-window',
    'docker-stop',
  ]);
  const forbidden = audit.entries.filter((entry) => !allowedKinds.has(entry.kind));
  const derived = {
    runnerDeviceOpenCount: audit.entries.filter((entry) => entry.kind === 'device-open').length,
    runnerDeviceReadCount: audit.entries.filter((entry) => entry.kind === 'device-read').length,
    runnerDeviceWriteCount: audit.entries.filter((entry) => entry.kind === 'device-write').length,
    virtualInvocationCount: audit.entries.filter((entry) => entry.kind === 'virtual-press').length,
    restartRescanReconfigureCount: audit.entries.filter((entry) =>
      ['docker-restart', 'docker-recreate', 'companion-rescan', 'companion-reconfigure'].includes(
        entry.kind
      )
    ).length,
    productionConfigurationMutationCount: audit.entries.filter(
      (entry) => entry.kind === 'production-configuration-mutation'
    ).length,
  };
  const interventionFree =
    forbidden.length === 0 && Object.values(derived).every((value) => value === 0);
  assertion(
    audit.mode === 'runner-metadata-observation-with-bounded-companion-target-io' &&
      audit.passed === interventionFree &&
      audit.interventionFree === interventionFree &&
      audit.forbidden.length === 0 &&
      Object.entries(derived).every(([key, value]) => audit[key] === value) &&
      audit.entries.filter((entry) => entry.kind === 'docker-run').length === 1 &&
      audit.entries.filter((entry) => entry.kind === 'docker-stop').length === 1 &&
      audit.entries.filter((entry) => entry.kind === 'physical-disconnect-window').length === 1 &&
      audit.entries.filter((entry) => entry.kind === 'physical-reconnect-window').length === 1 &&
      audit.entries[0].kind === 'docker-run' &&
      audit.entries.at(-1).kind === 'docker-stop' &&
      audit.entries
        .slice(1)
        .every(
          (entry, index) => BigInt(entry.monotonicNs) > BigInt(audit.entries[index].monotonicNs)
        ),
    'H-041 intervention audit is invalid'
  );
  const runEntry = audit.entries.find((entry) => entry.kind === 'docker-run');
  const disconnect = audit.entries.find((entry) => entry.kind === 'physical-disconnect-window');
  const reconnect = audit.entries.find((entry) => entry.kind === 'physical-reconnect-window');
  assertion(
    runEntry.target === run.companion.name &&
      runEntry.imageReference === OFFICIAL_IMAGE &&
      runEntry.dynamicSource === '/dev' &&
      runEntry.dynamicDestination === '/host-dev' &&
      runEntry.dynamicReadOnly === true &&
      runEntry.bindRecursive === false &&
      runEntry.cgroupRule === run.companion.deviceCgroupRule &&
      runEntry.staticDevices.length === 0 &&
      runEntry.runnerDeviceIo === false &&
      runEntry.companionTargetIoExpected === true &&
      runEntry.configBaseDirectory === '/companion' &&
      runEntry.ephemeralConfig === true &&
      runEntry.labLabel === 'dev.overlaykit.hypothesis=H-041' &&
      disconnect.challenge === run.windows.disconnect.challenge &&
      reconnect.challenge === run.windows.reconnect.challenge &&
      audit.entries
        .filter((entry) => entry.kind === 'docker-observe')
        .every((entry) => entry.operation === 'proc-fd-stat-only') &&
      audit.entries
        .filter((entry) => entry.kind === 'docker-stop')
        .every((entry) => entry.target === run.companion.name),
    'H-041 audit does not match the declared bounded invocation'
  );
  return interventionFree;
}

export function verifyChronology(run) {
  const preflightHostNs = monotonicNs(
    run.observations.preflight.host.monotonicNs,
    'preflight host monotonic time'
  );
  const initialHostNs = monotonicNs(
    run.observations.initial.host.monotonicNs,
    'initial host monotonic time'
  );
  const initialRuntimeNs = monotonicNs(
    run.observations.initial.runtime.monotonicNs,
    'initial runtime monotonic time'
  );
  const disconnectOpen = monotonicNs(run.windows.disconnect.openedMonotonicNs, 'disconnect open');
  const absentHostNs = monotonicNs(
    run.observations.absent.host.monotonicNs,
    'absent host monotonic time'
  );
  const absentRuntimeNs = monotonicNs(
    run.observations.absent.runtime.monotonicNs,
    'absent runtime monotonic time'
  );
  const disconnectClose = monotonicNs(run.windows.disconnect.closedMonotonicNs, 'disconnect close');
  const reconnectOpen = monotonicNs(run.windows.reconnect.openedMonotonicNs, 'reconnect open');
  const returnedHostNs = monotonicNs(
    run.observations.returned.host.monotonicNs,
    'returned host monotonic time'
  );
  const reconnectClose = monotonicNs(run.windows.reconnect.closedMonotonicNs, 'reconnect close');
  const reacquisitionStart = monotonicNs(
    run.windows.reacquisition.startedMonotonicNs,
    'reacquisition start'
  );
  const returnedRuntimeNs = monotonicNs(
    run.observations.returned.runtime.monotonicNs,
    'returned runtime monotonic time'
  );
  const reacquisitionComplete = monotonicNs(
    run.windows.reacquisition.completedMonotonicNs,
    'reacquisition complete'
  );
  assertion(
    run.windows.reacquisition.timeoutSeconds === 30,
    'H-041 reacquisition window must be exactly 30 seconds'
  );
  assertion(
    preflightHostNs < initialRuntimeNs &&
      initialRuntimeNs <= initialHostNs &&
      initialHostNs < disconnectOpen &&
      disconnectOpen < absentHostNs &&
      absentHostNs <= absentRuntimeNs &&
      absentRuntimeNs <= disconnectClose &&
      disconnectClose < reconnectOpen &&
      reconnectOpen < returnedHostNs &&
      returnedHostNs === reacquisitionStart &&
      reacquisitionStart <= reconnectClose &&
      reconnectClose <= returnedRuntimeNs &&
      returnedRuntimeNs <= reacquisitionComplete,
    'H-041 monotonic chronology is invalid'
  );
  assertion(
    dateTimeMs(run.observations.preflight.host.capturedAt, 'preflight host') <=
      dateTimeMs(run.startedAt, 'run start') &&
      dateTimeMs(run.startedAt, 'run start') <=
        dateTimeMs(run.observations.initial.runtime.capturedAt, 'initial runtime') &&
      dateTimeMs(run.observations.initial.runtime.capturedAt, 'initial runtime') <=
        dateTimeMs(run.observations.initial.host.capturedAt, 'initial host') &&
      dateTimeMs(run.observations.initial.host.capturedAt, 'initial host') <=
        dateTimeMs(run.windows.disconnect.openedAt, 'disconnect open') &&
      dateTimeMs(run.windows.disconnect.openedAt, 'disconnect open') <=
        dateTimeMs(run.observations.absent.host.capturedAt, 'absent host') &&
      dateTimeMs(run.observations.absent.host.capturedAt, 'absent host') <=
        dateTimeMs(run.observations.absent.runtime.capturedAt, 'absent runtime') &&
      dateTimeMs(run.observations.absent.runtime.capturedAt, 'absent runtime') <=
        dateTimeMs(run.windows.disconnect.closedAt, 'disconnect close') &&
      dateTimeMs(run.windows.disconnect.closedAt, 'disconnect close') <=
        dateTimeMs(run.windows.reconnect.openedAt, 'reconnect open') &&
      dateTimeMs(run.windows.reconnect.openedAt, 'reconnect open') <=
        dateTimeMs(run.observations.returned.host.capturedAt, 'returned host') &&
      dateTimeMs(run.observations.returned.host.capturedAt, 'returned host') ===
        dateTimeMs(run.windows.reacquisition.startedAt, 'reacquisition start') &&
      dateTimeMs(run.windows.reacquisition.startedAt, 'reacquisition start') <=
        dateTimeMs(run.windows.reconnect.closedAt, 'reconnect close') &&
      dateTimeMs(run.windows.reconnect.closedAt, 'reconnect close') <=
        dateTimeMs(run.observations.returned.runtime.capturedAt, 'returned runtime') &&
      dateTimeMs(run.observations.returned.runtime.capturedAt, 'returned runtime') <=
        dateTimeMs(run.windows.reacquisition.completedAt, 'reacquisition complete'),
    'H-041 wall-clock chronology is invalid'
  );
}

function verifyHostPoll(entries, run) {
  function stableTransition(stage, state, window, observation) {
    const opened = BigInt(window.openedMonotonicNs);
    const closed = BigInt(window.closedMonotonicNs);
    const full = entries
      .map((entry, index) => ({ entry, index }))
      .filter(
        ({ entry }) =>
          entry.stage === `${stage}-full` &&
          BigInt(entry.monotonicNs) >= opened &&
          BigInt(entry.monotonicNs) <= closed
      );
    assertion(full.length === 1, `H-041 lacks one ${stage}-full host observation`);
    const { entry: fullEntry, index: fullIndex } = full[0];
    const prior = entries.slice(fullIndex - 3, fullIndex);
    assertion(
      prior.length === 3 &&
        prior.every(
          (entry) =>
            entry.stage === stage &&
            entry.state === state &&
            Array.isArray(entry.errors) &&
            entry.errors.length === 0
        ) &&
        fullEntry.state === state &&
        Array.isArray(fullEntry.errors) &&
        fullEntry.errors.length === 0 &&
        fullEntry.capturedAt === observation.capturedAt &&
        fullEntry.monotonicNs === observation.monotonicNs,
      `H-041 ${stage} host stability proof is invalid`
    );
    const transition = [...prior, fullEntry];
    const monotonic = transition.map((entry) => BigInt(entry.monotonicNs));
    assertion(
      monotonic.every(
        (value, index) =>
          value >= opened && value <= closed && (index === 0 || value > monotonic[index - 1])
      ) &&
        transition.every(
          (entry) =>
            dateTimeMs(entry.capturedAt, `${stage} poll capturedAt`) >=
              dateTimeMs(window.openedAt, `${stage} window openedAt`) &&
            dateTimeMs(entry.capturedAt, `${stage} poll capturedAt`) <=
              dateTimeMs(window.closedAt, `${stage} window closedAt`)
        ),
      `H-041 ${stage} stability observations escaped their physical window`
    );
    if (state === 'absent') {
      assertion(
        transition.every((entry) => entry.usb.length === 0 && entry.hidraw.length === 0),
        'H-041 absent host polling retained the exact device'
      );
    } else {
      assertion(
        transition.every(
          (entry) =>
            entry.usb.filter(({ serial }) => serial === run.device.serial).length === 1 &&
            entry.hidraw.filter(({ serial }) => serial === run.device.serial).length === 1
        ),
        'H-041 returned host polling lacks the exact serial'
      );
    }
  }
  stableTransition('absent', 'absent', run.windows.disconnect, run.observations.absent.host);
  stableTransition('present', 'present', run.windows.reconnect, run.observations.returned.host);
}

function verifyRuntimePoll(entries, run) {
  assertion(entries.length > 0, 'H-041 runtime polling is empty');
  const completed = BigInt(run.windows.reacquisition.completedMonotonicNs);
  for (let index = 0; index < entries.length; index += 1) {
    verifyRuntime(entries[index], run, `runtime poll ${index}`);
    assertion(
      BigInt(entries[index].monotonicNs) <= completed,
      'H-041 runtime polling extends beyond the declared completion'
    );
    if (index > 0) {
      assertion(
        BigInt(entries[index].monotonicNs) > BigInt(entries[index - 1].monotonicNs),
        'H-041 runtime poll chronology is not strict'
      );
    }
  }
  for (const [label, runtime] of [
    ['initial', run.observations.initial.runtime],
    ['absent', run.observations.absent.runtime],
    ['returned', run.observations.returned.runtime],
  ]) {
    assertion(
      entries.some((entry) => sha256Canonical(entry) === sha256Canonical(runtime)),
      `H-041 runtime polling omitted the embedded ${label} observation`
    );
  }
  assertion(
    entries.some((entry) => entry.phase === 'baseline-poll') &&
      entries.some((entry) => entry.phase === 'absent-poll') &&
      entries.some((entry) => entry.phase === 'reacquisition-poll'),
    'H-041 runtime polling omitted a required phase'
  );
  return entries;
}

function boundedPostReturnObservations(runtimePoll, run) {
  const started = BigInt(run.windows.reacquisition.startedMonotonicNs);
  const deadline = started + BigInt(run.windows.reacquisition.timeoutSeconds) * 1_000_000_000n;
  const completed = BigInt(run.windows.reacquisition.completedMonotonicNs);
  const polls = runtimePoll.filter(
    (entry) =>
      entry.phase === 'reacquisition-poll' &&
      BigInt(entry.monotonicNs) >= started &&
      BigInt(entry.monotonicNs) <= deadline &&
      BigInt(entry.monotonicNs) <= completed
  );
  const absentMarkers = run.observations.reacquisition.absentMarkers;
  const boundary = runtimePoll.find(
    (entry) =>
      entry.phase === 'reacquisition-poll' &&
      BigInt(entry.monotonicNs) >= deadline &&
      BigInt(entry.monotonicNs) <= completed
  );
  const boundaryNegative =
    boundary !== undefined &&
    targetDescriptors(boundary).length === 0 &&
    !(
      boundary.markers.opening > absentMarkers.opening &&
      boundary.markers.ready > absentMarkers.ready
    );
  return {
    descriptor: polls.some((entry) => targetDescriptors(entry).length > 0),
    markers: polls.some(
      (entry) =>
        entry.markers.opening > absentMarkers.opening && entry.markers.ready > absentMarkers.ready
    ),
    deadline,
    hasDeadlineObservation: boundary !== undefined,
    boundaryNegative,
  };
}

export function recomputePredicates(run, context) {
  const initial = run.observations.initial;
  const absent = run.observations.absent;
  const returned = run.observations.returned;
  const bounded = boundedPostReturnObservations(context.runtimePoll, run);
  const initialSelection = selectExactTargetHidraw(run.device.initialInventory, {
    vendorId: '0fd9',
    productId: '0080',
    serial: run.device.serial,
  });
  const returnedSelection = selectExactTargetHidraw(run.device.returnedInventory, {
    vendorId: '0fd9',
    productId: '0080',
    serial: run.device.serial,
  });
  const permissionExact =
    permissionBoundaryExact(initial.runtime, run, context.initial.node, context.initial.node) &&
    permissionBoundaryExact(returned.runtime, run, context.initial.node, context.returned.node) &&
    initialSelection.devicePath === context.initial.node.devicePath &&
    sameDeviceAccessBoundary(context.initial.node.stat, initialSelection.stat.value) &&
    returnedSelection.devicePath === context.returned.node.devicePath &&
    sameDeviceAccessBoundary(context.initial.node.stat, returnedSelection.stat.value) &&
    context.returned.node.devicePath === context.initial.node.devicePath;
  const lifecycleStable = [
    absent.runtime.lifecycle,
    returned.runtime.lifecycle,
    ...context.runtimePoll.map((entry) => entry.lifecycle),
  ].every((lifecycle) => sameTopLevelLifecycle(initial.runtime.lifecycle, lifecycle));
  return {
    complete: true,
    interventionFree: verifyInvocationAudit(run),
    permissionBoundaryExact: permissionExact,
    hostEpochChanged: hostEpochChanged(initial.host, returned.host),
    dynamicViewTracksHost:
      dynamicStageMatchesHost({
        hostNode: context.initial.node,
        dynamic: initial.runtime.observer.paths.dynamic.stat,
      }) &&
      dynamicStageMatchesHost({
        hostNode: null,
        dynamic: absent.runtime.observer.paths.dynamic.stat,
      }) &&
      dynamicStageMatchesHost({
        hostNode: context.returned.node,
        dynamic: returned.runtime.observer.paths.dynamic.stat,
      }),
    topLevelLifecycleUnchanged: lifecycleStable,
    baselineAcquired: baselineAcquired(initial.runtime),
    descriptorAbsent: descriptorAbsent(absent.runtime),
    postReturnDescriptorObserved: bounded.descriptor,
    postReturnLogMarkersObserved: bounded.markers,
    deadlineBoundaryConsistent: (bounded.descriptor && bounded.markers) || bounded.boundaryNegative,
  };
}

function verifyClaimBoundary(run) {
  assertion(
    sha256Canonical(run.claimBoundary) === sha256Canonical(H041_CLAIM_BOUNDARY) &&
      run.claimBoundary.excludes.some((claim) => claim.includes('physical button')) &&
      run.claimBoundary.excludes.some((claim) => claim.includes('production acceptance')) &&
      run.claimBoundary.excludes.some((claim) => claim.includes('reboot')),
    'H-041 claim boundary is incomplete or expanded'
  );
}

function verifyCleanup(run, initialScope) {
  const cleanupTuple = exactPresentHostTuple(run.cleanup.host, run.device.serial, 'cleanup');
  assertion(
    run.cleanup.containerId === run.companion.containerId &&
      run.cleanup.containerRemoved === true &&
      run.cleanup.hostConfigurationChanged === false &&
      run.cleanup.productionConfigurationChanged === false &&
      run.cleanup.successful === true &&
      run.cleanup.error === null &&
      run.cleanup.host.scope.bootId === initialScope.bootId &&
      run.cleanup.host.scope.mountNamespace === initialScope.mountNamespace &&
      run.cleanup.owners.length === 1 &&
      run.cleanup.owners[0].devicePath === cleanupTuple.node.devicePath &&
      run.cleanup.owners.every(
        ({ owner }) =>
          owner.observed === true && owner.usageError === false && owner.pids.length === 0
      ) &&
      dateTimeMs(run.windows.reacquisition.completedAt, 'reacquisition complete') <=
        dateTimeMs(run.cleanup.startedAt, 'cleanup start') &&
      dateTimeMs(run.cleanup.startedAt, 'cleanup start') <=
        dateTimeMs(run.cleanup.completedAt, 'cleanup complete') &&
      dateTimeMs(run.cleanup.completedAt, 'cleanup complete') ===
        dateTimeMs(run.completedAt, 'run complete'),
    'H-041 cleanup is invalid'
  );
}

export async function verifyDynamicReacquisitionRun(filePath) {
  const runPath = path.resolve(filePath);
  const run = await readJson(runPath);
  const schema = await readJson(
    path.join(LAB_DIRECTORY, 'schemas/dynamic-reacquisition-run.schema.json')
  );
  assertSchema(compileSchema(schema), run, 'H-041');
  const { evidenceSha256, ...evidence } = run;
  assertion(sha256Canonical(evidence) === evidenceSha256, 'H-041 canonical hash mismatch');

  await verifyCollector(runPath, run);
  const historical = await verifyInputs(runPath, run);
  assertion(
    run.device.vendorId === '0fd9' &&
      run.device.productId === '0080' &&
      run.device.serial === historical.h039.device.serial &&
      run.device.model === historical.h039.device.model &&
      run.companion.imageReference === OFFICIAL_IMAGE &&
      run.companion.imageId === EXPECTED_IMAGE_ID &&
      run.companion.version === 'v4.3.3' &&
      run.companion.revision === EXPECTED_IMAGE_REVISION &&
      run.companion.staticDevices.length === 0,
    'H-041 exact device or Companion identity is invalid'
  );
  assertion(
    run.host.osId === 'fedora' &&
      run.host.osVersion === '43' &&
      run.host.kernel === historical.h039.host.kernel &&
      run.host.architecture === historical.h039.host.architecture &&
      run.host.machine === historical.h039.host.machine &&
      sha256Canonical(run.host.principal) === sha256Canonical(historical.h039.host.principal) &&
      run.host.graphicalSession.Name === run.host.principal.user &&
      run.host.graphicalSession.Active === 'yes' &&
      run.host.graphicalSession.State === 'active' &&
      run.host.graphicalSession.Class === 'user' &&
      run.host.graphicalSession.Remote === 'no' &&
      ['wayland', 'x11'].includes(run.host.graphicalSession.Type) &&
      typeof run.host.docker.version.Server?.Version === 'string' &&
      typeof run.host.docker.info.ServerVersion === 'string',
    'H-041 did not bind the exact post-login Fedora host'
  );

  const preflight = exactPresentHostTuple(
    run.observations.preflight.host,
    run.device.serial,
    'preflight'
  );
  assertion(
    preflight.node.owner?.applicable === true &&
      preflight.node.owner.observed === true &&
      preflight.node.owner.usageError === false &&
      preflight.node.owner.errorCode === null &&
      Array.isArray(preflight.node.owner.pids) &&
      preflight.node.owner.pids.length === 0,
    'H-041 preflight host-scope owner observation is invalid'
  );
  const initial = exactPresentHostTuple(
    run.observations.initial.host,
    run.device.serial,
    'initial'
  );
  assertAbsentHostSnapshot(run.observations.absent.host, run.device.serial);
  const returned = exactPresentHostTuple(
    run.observations.returned.host,
    run.device.serial,
    'returned'
  );
  assertion(
    run.device.initialPath === initial.node.devicePath &&
      run.device.returnedPath === returned.node.devicePath &&
      run.device.initialRdevHex === initial.node.stat.rdevHex &&
      run.device.returnedRdevHex === returned.node.stat.rdevHex &&
      run.device.transition === classifyDeviceTransition(initial.node, returned.node) &&
      hostEpochChanged(run.observations.preflight.host, run.observations.initial.host) === false &&
      [
        run.observations.preflight.host.scope,
        run.observations.initial.host.scope,
        run.observations.absent.host.scope,
        run.observations.returned.host.scope,
      ].every(
        (scope) =>
          scope.bootId === run.observations.initial.host.scope.bootId &&
          scope.mountNamespace === run.observations.initial.host.scope.mountNamespace
      ),
    'H-041 device transition or host scope is invalid'
  );

  for (const [label, runtime] of [
    ['initial', run.observations.initial.runtime],
    ['absent', run.observations.absent.runtime],
    ['returned', run.observations.returned.runtime],
  ]) {
    verifyRuntime(runtime, run, label);
  }
  verifyLifecycleBindings(run);
  const [hostPollBytes, runtimePollBytes, initialLogBytes, absentLogBytes, finalLogBytes] =
    await Promise.all([
      verifiedArtifact(runPath, run.observations.artifacts.hostPoll, 'host poll'),
      verifiedArtifact(runPath, run.observations.artifacts.runtimePoll, 'runtime poll'),
      verifiedArtifact(runPath, run.observations.artifacts.initialLogs, 'initial logs'),
      verifiedArtifact(runPath, run.observations.artifacts.absentLogs, 'absent logs'),
      verifiedArtifact(runPath, run.observations.artifacts.finalLogs, 'final logs'),
    ]);
  const hostPoll = parseJsonLines(hostPollBytes, 'host poll');
  const runtimePoll = verifyRuntimePoll(parseJsonLines(runtimePollBytes, 'runtime poll'), run);
  verifyHostPoll(hostPoll, run);
  const markerPaths = [run.companion.compatibilityPath, run.companion.dynamicPath];
  const recomputedMarkers = {
    initial: countAcquisitionMarkers(
      initialLogBytes.toString('utf8'),
      run.device.serial,
      markerPaths
    ),
    absent: countAcquisitionMarkers(
      absentLogBytes.toString('utf8'),
      run.device.serial,
      markerPaths
    ),
    final: countAcquisitionMarkers(finalLogBytes.toString('utf8'), run.device.serial, markerPaths),
  };
  assertion(
    sha256Canonical(run.observations.reacquisition.initialMarkers) ===
      sha256Canonical(recomputedMarkers.initial) &&
      sha256Canonical(run.observations.reacquisition.absentMarkers) ===
        sha256Canonical(recomputedMarkers.absent) &&
      sha256Canonical(run.observations.reacquisition.finalMarkers) ===
        sha256Canonical(recomputedMarkers.final) &&
      sha256Canonical(run.observations.initial.runtime.markers) ===
        sha256Canonical(recomputedMarkers.initial) &&
      sha256Canonical(run.observations.absent.runtime.markers) ===
        sha256Canonical(recomputedMarkers.absent) &&
      sha256Canonical(run.observations.returned.runtime.markers) ===
        sha256Canonical(recomputedMarkers.final),
    'H-041 acquisition marker receipts do not match the exact log artifacts'
  );

  verifyChronology(run);
  const predicates = recomputePredicates(run, { initial, returned, runtimePoll });
  assertion(
    hasExactKeys(run.predicates, PREDICATE_KEYS) &&
      PREDICATE_KEYS.every((key) => run.predicates[key] === predicates[key]),
    'H-041 predicate receipt does not match independent recomputation'
  );
  const outcome = classifyH041Outcome(predicates);
  assertion(
    sha256Canonical(run.outcome) === sha256Canonical(outcome),
    'H-041 outcome does not match its predicate matrix'
  );
  const reacquisitionElapsed =
    BigInt(run.windows.reacquisition.completedMonotonicNs) -
    BigInt(run.windows.reacquisition.startedMonotonicNs);
  const bounded = boundedPostReturnObservations(runtimePoll, run);
  assertion(
    run.windows.reacquisition.deadlineExpired ===
      reacquisitionElapsed >= BigInt(run.windows.reacquisition.timeoutSeconds) * 1_000_000_000n,
    'H-041 deadline receipt is invalid'
  );
  if (outcome.status === 'refuted') {
    assertion(
      run.windows.reacquisition.deadlineExpired === true &&
        bounded.hasDeadlineObservation === true &&
        bounded.boundaryNegative === true,
      'H-041 refutation lacks a complete expired observation'
    );
  }
  assertion(
    run.observations.reacquisition.currentDescriptorObserved ===
      predicates.postReturnDescriptorObserved &&
      run.observations.reacquisition.postReturnLogMarkersObserved ===
        predicates.postReturnLogMarkersObserved,
    'H-041 reacquisition summary disagrees with bounded polling'
  );
  verifyClaimBoundary(run);
  verifyCleanup(run, run.observations.initial.host.scope);

  const initialWorker = run.observations.initial.runtime.observer.surfaceWorkers[0] ?? null;
  const finalWorker = run.observations.returned.runtime.observer.surfaceWorkers[0] ?? null;
  const workerMechanism =
    initialWorker !== null &&
    finalWorker !== null &&
    sameSurfaceWorker(exactWorkerIdentity(initialWorker), exactWorkerIdentity(finalWorker))
      ? 'same-worker'
      : finalWorker === null
        ? 'no-final-worker'
        : 'automatic-replacement-worker';
  return {
    schemaVersion: 'overlaykit-h041-verification/v1',
    hypothesis: 'H-041',
    outcome: outcome.status,
    stage: outcome.stage,
    evidenceSha256,
    deviceSerial: run.device.serial,
    predicates,
    workerMechanism,
    runnerDeviceIo: false,
    virtualInvocationCount: 0,
    cleaned: true,
    verified: true,
  };
}

const modulePath = fileURLToPath(import.meta.url);
if (process.argv[1] && path.resolve(process.argv[1]) === modulePath) {
  const inputPath = process.argv[2];
  if (!inputPath) throw new Error('Usage: node lab/h041/verify.mjs <run.json>');
  process.stdout.write(
    `${JSON.stringify(await verifyDynamicReacquisitionRun(path.resolve(inputPath)), null, 2)}\n`
  );
}
