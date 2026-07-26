#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { mkdir, readFile, readdir, readlink, rename, unlink, writeFile } from 'node:fs/promises';
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
import {
  classifyDeviceTransition,
  parseProcStartTicks,
  sha256,
  sha256Canonical,
} from '../h039/reconnect-lib.mjs';
import { inventoryHostHidraw, selectExactTargetHidraw } from './host-inventory.mjs';
import {
  H041_CLAIM_BOUNDARY,
  classifyH041Outcome,
  countAcquisitionMarkers,
  descriptorMatchesDynamicNode,
  dynamicStageMatchesHost,
  hostEpochChanged,
  runId as createRunId,
  sameTopLevelLifecycle,
} from './reacquisition-lib.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const OFFICIAL_IMAGE =
  'ghcr.io/bitfocus/companion/companion:v4.3.3@sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e';
const EXPECTED_IMAGE_ID = 'sha256:e7d24e3b0e32b0edb799f262493536cb1a47d307af4e6527551427e09266bf10';
const EXPECTED_IMAGE_REVISION = '06a7406709d6a858039333a8988047296ef3aa4a';
const EXPECTED_H037_SHA256 = '22d8f1d440a521af2ec8dd75cbfa68db09b7140c85f90bc48310aa78d27d6e9c';
const EXPECTED_H039_SHA256 = 'e78ed04dd10469e863b33e4fa497ddc745a20574fb18095c2bde7cf3fdb594ce';
const EXPECTED_H040_SHA256 = '04b3b9aedeb51e1bd5d6c1bd4e68e9d284951d2b21276aea3f5a180f0fe2a108';
const DEFAULT_H037 = 'artifacts/h037/acquisition-2026-07-25.json';
const DEFAULT_H039 = 'artifacts/h039/h039-2026-07-25T22-12-14-212Z-e6c2b45e/run.json';
const DEFAULT_H040 = 'artifacts/h040/h040-2026-07-25T22-53-48-398Z-94d8ac80/run.json';
const DYNAMIC_ROOT = '/host-dev';
const CONTAINER_ENTRYPOINT = '/h041-entrypoint.sh';
const CONTAINER_OBSERVER = '/h041-container-observer.mjs';
const TARGET_VENDOR_ID = '0fd9';
const TARGET_PRODUCT_ID = '0080';
const SOURCE_FILES = [
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

function parseArgs(argv) {
  const parsed = {
    h037: DEFAULT_H037,
    h039: DEFAULT_H039,
    h040: DEFAULT_H040,
    evidenceDirectory: null,
    transitionWindowSeconds: 120,
    baselineWindowSeconds: 30,
    absentDescriptorWindowSeconds: 5,
    reacquisitionWindowSeconds: 30,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--h037') parsed.h037 = argv[++index] ?? '';
    else if (argument === '--h039') parsed.h039 = argv[++index] ?? '';
    else if (argument === '--h040') parsed.h040 = argv[++index] ?? '';
    else if (argument === '--evidence-dir') parsed.evidenceDirectory = argv[++index] ?? '';
    else if (argument === '--transition-seconds') {
      parsed.transitionWindowSeconds = Number(argv[++index]);
    } else if (argument === '--baseline-seconds') {
      parsed.baselineWindowSeconds = Number(argv[++index]);
    } else if (argument === '--absent-descriptor-seconds') {
      parsed.absentDescriptorWindowSeconds = Number(argv[++index]);
    } else if (argument === '--reacquisition-seconds') {
      parsed.reacquisitionWindowSeconds = Number(argv[++index]);
    } else {
      throw new Error(`Unknown H-041 argument: ${argument}`);
    }
  }
  const boundedInteger = (value, minimum, maximum, label) => {
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
      throw new Error(`${label} must be between ${minimum} and ${maximum} seconds`);
    }
  };
  boundedInteger(parsed.transitionWindowSeconds, 20, 300, 'H-041 transition window');
  boundedInteger(parsed.baselineWindowSeconds, 10, 90, 'H-041 baseline window');
  boundedInteger(parsed.absentDescriptorWindowSeconds, 1, 30, 'H-041 absent descriptor window');
  if (parsed.reacquisitionWindowSeconds !== 30) {
    throw new Error('H-041 reacquisition window must be exactly 30 seconds');
  }
  return parsed;
}

function repositoryPath(relativePath, label) {
  const absolutePath = path.resolve(REPOSITORY_ROOT, relativePath);
  if (!absolutePath.startsWith(`${REPOSITORY_ROOT}${path.sep}`)) {
    throw new Error(`${label} must remain inside the repository`);
  }
  return absolutePath;
}

function sourceHashes() {
  return Object.fromEntries(
    SOURCE_FILES.map((relativePath) => [
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
    throw new Error('H-041 could not bind the current principal group identities');
  }
  const groups = observedGids
    .map((observedGid, index) => ({ gid: observedGid, name: observedNames[index] }))
    .sort((left, right) => left.gid - right.gid);
  const principal = {
    user: user.stdout.trim(),
    uid: Number(uid.stdout.trim()),
    primaryGroup: primaryGroup.stdout.trim(),
    gid: Number(gid.stdout.trim()),
    groups,
  };
  if (
    principal.user !== expectedUser ||
    !Number.isSafeInteger(principal.uid) ||
    !Number.isSafeInteger(principal.gid) ||
    principal.primaryGroup.length === 0
  ) {
    throw new Error('H-041 current principal identity is incomplete');
  }
  return principal;
}

async function observeHostIdentity(expectedUser) {
  const [osReleaseText, kernel, machine, principal] = await Promise.all([
    readFile('/etc/os-release', 'utf8'),
    command('uname', ['-r']),
    command('uname', ['-m']),
    observePrincipal(expectedUser),
  ]);
  const release = parseOsRelease(osReleaseText);
  if (!release.ID || !release.VERSION_ID) {
    throw new Error('H-041 could not identify the current Linux distribution');
  }
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
    throw new Error(`H-041 expected one exact present hidraw node at ${label}`);
  }
  return matches[0];
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

function validateCanonicalEvidence(run, expected) {
  const { evidenceSha256, ...evidence } = run;
  if (
    run.schemaVersion !== expected.schemaVersion ||
    run.hypothesis !== expected.hypothesis ||
    evidenceSha256 !== expected.evidenceSha256 ||
    sha256Canonical(evidence) !== evidenceSha256
  ) {
    throw new Error(`H-041 rejected stale or invalid ${expected.hypothesis} evidence`);
  }
}

function validateH037(bytes, run) {
  validateCanonicalEvidence(run, {
    schemaVersion: 'overlaykit-h037-acquisition/v1',
    hypothesis: 'H-037',
    evidenceSha256: EXPECTED_H037_SHA256,
  });
  if (
    run.input?.device?.usbVendorId !== TARGET_VENDOR_ID ||
    run.input?.device?.usbProductId !== TARGET_PRODUCT_ID ||
    run.input?.companion?.image !== OFFICIAL_IMAGE ||
    run.input?.companion?.imageId !== EXPECTED_IMAGE_ID ||
    run.positive?.signals?.panelOpening !== true ||
    run.positive?.signals?.panelReady !== true ||
    run.positive?.process?.ownsDevice !== true ||
    run.positive?.process?.surfaceUid !== 1000 ||
    !run.positive.process.groups.includes(run.input.host.supplementaryGroupId) ||
    run.after?.positiveContainerExists !== false
  ) {
    throw new Error('H-041 H-037 control lacks the required positive acquisition guarantees');
  }
  for (const [relativePath, expectedHash] of Object.entries(run.collector.sourceSha256)) {
    const absolutePath = repositoryPath(relativePath, `H-037 source ${relativePath}`);
    if (sha256(readFileSync(absolutePath)) !== expectedHash) {
      throw new Error(`H-041 detected stale H-037 source: ${relativePath}`);
    }
  }
  return {
    schemaVersion: 'overlaykit-h041-h037-validation/v1',
    hypothesis: 'H-037',
    fileSha256: sha256(bytes),
    evidenceSha256: run.evidenceSha256,
    imageId: run.input.companion.imageId,
    deviceSerial: run.input.device.serial,
    canonicalHashValid: true,
    sourceHashesValid: true,
    positiveAcquisitionValid: true,
    historicalGovernanceManifestContentHash: run.collector.governanceManifestContentHash ?? null,
    verified: true,
  };
}

function validateH039Receipt(run, receipt) {
  validateCanonicalEvidence(run, {
    schemaVersion: 'overlaykit-h039-reconnect-run/v1',
    hypothesis: 'H-039',
    evidenceSha256: EXPECTED_H039_SHA256,
  });
  if (
    receipt.schemaVersion !== 'overlaykit-h039-verification/v1' ||
    receipt.hypothesis !== 'H-039' ||
    receipt.outcome !== 'refuted' ||
    receipt.stage !== 'companion-reacquisition' ||
    receipt.evidenceSha256 !== run.evidenceSha256 ||
    receipt.topLevelLifecycleUnchanged !== true ||
    receipt.configurationUnchanged !== true ||
    receipt.virtualInvocationCount !== 0 ||
    receipt.cleaned !== true ||
    receipt.verified !== true
  ) {
    throw new Error('H-041 H-039 verification receipt is incomplete');
  }
}

function validateH040Receipt(run, receipt) {
  validateCanonicalEvidence(run, {
    schemaVersion: 'overlaykit-h040-docker-mapping-run/v1',
    hypothesis: 'H-040',
    evidenceSha256: EXPECTED_H040_SHA256,
  });
  if (
    receipt.schemaVersion !== 'overlaykit-h040-verification/v1' ||
    receipt.hypothesis !== 'H-040' ||
    receipt.outcome !== 'supported' ||
    receipt.evidenceSha256 !== run.evidenceSha256 ||
    receipt.h039EvidenceSha256 !== EXPECTED_H039_SHA256 ||
    Object.values(receipt.predicates ?? {}).some((value) => value !== true) ||
    receipt.metadataOnly !== true ||
    receipt.cleaned !== true ||
    receipt.verified !== true
  ) {
    throw new Error('H-041 H-040 verification receipt is incomplete');
  }
}

async function independentReceipt(verifierPath, evidencePath, label) {
  const observed = await command(process.execPath, [verifierPath, evidencePath], {
    cwd: REPOSITORY_ROOT,
  });
  const text = `${observed.stdout}${observed.stderr}`;
  let receipt;
  try {
    receipt = JSON.parse(text);
  } catch {
    throw new Error(`H-041 could not parse ${label} independent verification receipt`);
  }
  return { text, receipt };
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

function compactHostTimeline(entries) {
  return `${entries.map((entry) => JSON.stringify(entry)).join('\n')}\n`;
}

function auditEntry(entries, entry) {
  entries.push({
    at: new Date().toISOString(),
    monotonicNs: process.hrtime.bigint().toString(),
    ...entry,
  });
}

function invocationAudit(entries) {
  const allowedKinds = new Set([
    'docker-run',
    'docker-inspect',
    'docker-observe',
    'docker-logs',
    'physical-disconnect-window',
    'physical-reconnect-window',
    'docker-stop',
  ]);
  const forbidden = entries.filter((entry) => !allowedKinds.has(entry.kind));
  const runnerDeviceOpenCount = entries.filter((entry) => entry.kind === 'device-open').length;
  const runnerDeviceReadCount = entries.filter((entry) => entry.kind === 'device-read').length;
  const runnerDeviceWriteCount = entries.filter((entry) => entry.kind === 'device-write').length;
  const virtualInvocationCount = entries.filter((entry) => entry.kind === 'virtual-press').length;
  const restartRescanReconfigureCount = entries.filter((entry) =>
    ['docker-restart', 'docker-recreate', 'companion-rescan', 'companion-reconfigure'].includes(
      entry.kind
    )
  ).length;
  const productionConfigurationMutationCount = entries.filter(
    (entry) => entry.kind === 'production-configuration-mutation'
  ).length;
  const passed =
    forbidden.length === 0 &&
    runnerDeviceOpenCount === 0 &&
    runnerDeviceReadCount === 0 &&
    runnerDeviceWriteCount === 0 &&
    virtualInvocationCount === 0 &&
    restartRescanReconfigureCount === 0 &&
    productionConfigurationMutationCount === 0;
  return {
    mode: 'runner-metadata-observation-with-bounded-companion-target-io',
    runnerDeviceOpenCount,
    runnerDeviceReadCount,
    runnerDeviceWriteCount,
    virtualInvocationCount,
    restartRescanReconfigureCount,
    productionConfigurationMutationCount,
    interventionFree: passed,
    entries,
    forbidden,
    passed,
  };
}

async function inspectCompanion(containerName, invocationEntries, phase) {
  auditEntry(invocationEntries, {
    kind: 'docker-inspect',
    phase,
    target: containerName,
    operation: 'metadata',
  });
  const inspected = JSON.parse((await command('docker', ['inspect', containerName])).stdout)[0];
  if (!inspected?.State?.Running || !Number.isSafeInteger(inspected.State.Pid)) {
    throw new Error(`H-041 Companion container is not running at ${phase}`);
  }
  const hostPid = inspected.State.Pid;
  const [procStat, pidNamespace, mountNamespace, cgroup] = await Promise.all([
    readFile(`/proc/${hostPid}/stat`, 'utf8'),
    readlink(`/proc/${hostPid}/ns/pid`),
    readlink(`/proc/${hostPid}/ns/mnt`),
    readFile(`/proc/${hostPid}/cgroup`, 'utf8'),
  ]);
  const mounts = (inspected.Mounts ?? []).map((entry) => ({
    type: entry.Type,
    source: entry.Source,
    destination: entry.Destination,
    rw: entry.RW,
    propagation: entry.Propagation ?? '',
  }));
  const declaredMounts = (inspected.HostConfig?.Mounts ?? []).map((entry) => ({
    type: entry.Type,
    source: entry.Source,
    target: entry.Target,
    readOnly: entry.ReadOnly ?? false,
    bindOptions: entry.BindOptions ?? null,
  }));
  return {
    containerId: inspected.Id,
    name: inspected.Name?.replace(/^\//u, '') ?? containerName,
    imageId: inspected.Image,
    running: inspected.State.Running,
    healthy: inspected.State.Health?.Status === 'healthy',
    healthStatus: inspected.State.Health?.Status ?? null,
    startedAt: inspected.State.StartedAt,
    restartCount: inspected.RestartCount,
    hostPid,
    hostPidStartTicks: parseProcStartTicks(procStat.trim()),
    hostPidNamespace: pidNamespace,
    hostMountNamespace: mountNamespace,
    hostCgroup: cgroup.trim(),
    cgroupNamespaceMode: inspected.HostConfig?.CgroupnsMode ?? null,
    restartPolicy: inspected.HostConfig?.RestartPolicy?.Name ?? null,
    autoRemove: inspected.HostConfig?.AutoRemove ?? false,
    networkMode: inspected.HostConfig?.NetworkMode ?? null,
    privileged: inspected.HostConfig?.Privileged ?? null,
    readOnlyRootfs: inspected.HostConfig?.ReadonlyRootfs ?? false,
    capAdd: inspected.HostConfig?.CapAdd ?? [],
    capDrop: inspected.HostConfig?.CapDrop ?? [],
    securityOpt: inspected.HostConfig?.SecurityOpt ?? [],
    groupAdd: inspected.HostConfig?.GroupAdd ?? [],
    pidsLimit: inspected.HostConfig?.PidsLimit ?? null,
    memory: inspected.HostConfig?.Memory ?? null,
    deviceCgroupRules: inspected.HostConfig?.DeviceCgroupRules ?? [],
    devices: inspected.HostConfig?.Devices ?? [],
    tmpfs: inspected.HostConfig?.Tmpfs ?? {},
    user: inspected.Config?.User ?? null,
    environment: inspected.Config?.Env ?? [],
    labels: inspected.Config?.Labels ?? {},
    entrypoint: inspected.Config?.Entrypoint ?? [],
    command: inspected.Config?.Cmd ?? [],
    mounts,
    declaredMounts,
  };
}

function flattenLifecycle(container, observer) {
  return {
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
}

async function observeContainer(
  containerName,
  { dynamicPath, compatibilityPath, major, minor, serial, phase },
  invocationEntries
) {
  auditEntry(invocationEntries, {
    kind: 'docker-observe',
    phase,
    target: containerName,
    operation: 'proc-fd-stat-only',
  });
  const observerCommand = command('docker', [
    'exec',
    '--user',
    '1000:1000',
    '--env',
    `H041_DYNAMIC_PATH=${dynamicPath}`,
    '--env',
    `H041_COMPAT_PATH=${compatibilityPath}`,
    '--env',
    `H041_DEVICE_MAJOR=${major}`,
    '--env',
    `H041_DEVICE_MINOR=${minor}`,
    containerName,
    '/app/node-runtimes/main/bin/node',
    CONTAINER_OBSERVER,
  ]);
  auditEntry(invocationEntries, {
    kind: 'docker-logs',
    phase,
    target: containerName,
    operation: 'read-container-stdout-stderr',
  });
  const [observed, logs, container] = await Promise.all([
    observerCommand,
    command('docker', ['logs', '--timestamps', containerName]),
    inspectCompanion(containerName, invocationEntries, phase),
  ]);
  let observer;
  try {
    observer = JSON.parse(observed.stdout);
  } catch {
    throw new Error(`H-041 container observer emitted invalid JSON at ${phase}`);
  }
  if (
    observer.schemaVersion !== 'overlaykit-h041-container-observation/v1' ||
    observer.metadataOnly !== true
  ) {
    throw new Error(`H-041 container observer receipt is invalid at ${phase}`);
  }
  const logText = `${logs.stdout}${logs.stderr}`;
  const markers = countAcquisitionMarkers(logText, serial, [compatibilityPath, dynamicPath]);
  return {
    capturedAt: new Date().toISOString(),
    monotonicNs: process.hrtime.bigint().toString(),
    phase,
    container,
    lifecycle: flattenLifecycle(container, observer),
    observer,
    logText,
    markers,
  };
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

function postReturnMarkersObserved(absentMarkers, currentMarkers) {
  return (
    currentMarkers.opening > absentMarkers.opening && currentMarkers.ready > absentMarkers.ready
  );
}

function permissionBoundaryExact(runtime, expected) {
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
      entry.destination === DYNAMIC_ROOT &&
      entry.rw === false
  );
  const declaredDynamicMounts = container.declaredMounts.filter(
    (entry) =>
      entry.type === 'bind' &&
      entry.source === '/dev' &&
      entry.target === DYNAMIC_ROOT &&
      entry.readOnly === true &&
      entry.bindOptions?.NonRecursive === true
  );
  const scriptMounts = container.mounts.filter(
    (entry) =>
      entry.type === 'bind' &&
      [CONTAINER_ENTRYPOINT, CONTAINER_OBSERVER].includes(entry.destination) &&
      entry.rw === false
  );
  const declaredScriptMounts = container.declaredMounts.filter(
    (entry) =>
      entry.type === 'bind' &&
      [CONTAINER_ENTRYPOINT, CONTAINER_OBSERVER].includes(entry.target) &&
      entry.readOnly === true
  );
  return (
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
    container.groupAdd.map(Number).includes(expected.deviceGid) &&
    container.pidsLimit === 128 &&
    container.memory === 1024 * 1024 * 1024 &&
    JSON.stringify(container.deviceCgroupRules) === JSON.stringify([expected.cgroupRule]) &&
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
    environment.H041_DEVICE_GID === String(expected.deviceGid) &&
    environment.H041_DYNAMIC_PATH === expected.dynamicPath &&
    environment.H041_COMPAT_PATH === observer.paths.compat.path &&
    !Object.keys(environment).some((key) => key.includes('OVERLAYKIT')) &&
    container.labels['dev.overlaykit.hypothesis'] === 'H-041' &&
    JSON.stringify(container.entrypoint) === JSON.stringify(['/bin/bash']) &&
    JSON.stringify(container.command) === JSON.stringify([CONTAINER_ENTRYPOINT]) &&
    dynamicMounts.length === 1 &&
    declaredDynamicMounts.length === 1 &&
    scriptMounts.length === 2 &&
    declaredScriptMounts.length === 2 &&
    container.mounts.length === 3 &&
    container.declaredMounts.length === 3 &&
    scriptMounts.every((entry) => {
      const relativePath =
        entry.destination === CONTAINER_ENTRYPOINT ? 'entrypoint.sh' : 'container-observer.mjs';
      return entry.source === path.join(LAB_DIRECTORY, relativePath);
    }) &&
    declaredScriptMounts.every((entry) => {
      const relativePath =
        entry.target === CONTAINER_ENTRYPOINT ? 'entrypoint.sh' : 'container-observer.mjs';
      return entry.source === path.join(LAB_DIRECTORY, relativePath);
    }) &&
    observer.pid1.uid === 1000 &&
    observer.pid1.gid === 1000 &&
    JSON.stringify([...observer.pid1.groups].sort((left, right) => left - right)) ===
      JSON.stringify([1000, expected.deviceGid].sort((left, right) => left - right)) &&
    observer.paths.compat.lstat.kind === 'value' &&
    observer.paths.compat.lstat.value.isSymbolicLink === true &&
    observer.paths.compat.linkTarget === expected.dynamicPath
  );
}

async function waitForBaseline(options) {
  const started = process.hrtime.bigint();
  let last = null;
  while (process.hrtime.bigint() - started < BigInt(options.timeoutSeconds) * 1_000_000_000n) {
    last = await observeContainer(
      options.containerName,
      { ...options.runtime, phase: 'baseline-poll' },
      options.invocationEntries
    );
    options.runtimePolls.push(last);
    if (baselineAcquired(last)) return last;
    await sleep(500);
  }
  throw new Error(
    `H-041 Companion did not establish the required baseline within ${options.timeoutSeconds}s`
  );
}

async function waitForAbsentDescriptor(options) {
  const started = process.hrtime.bigint();
  let last = null;
  while (process.hrtime.bigint() - started < BigInt(options.timeoutSeconds) * 1_000_000_000n) {
    last = await observeContainer(
      options.containerName,
      { ...options.runtime, phase: 'absent-poll' },
      options.invocationEntries
    );
    options.runtimePolls.push(last);
    if (descriptorAbsent(last)) return last;
    await sleep(250);
  }
  return last;
}

async function waitForReacquisition(options) {
  const startedMonotonicNs = BigInt(options.startedMonotonicNs);
  const deadline = startedMonotonicNs + BigInt(options.timeoutSeconds) * 1_000_000_000n;
  let current = null;
  let currentDescriptorObserved = false;
  let postReturnLogMarkersObserved = false;
  let deadlineBoundaryNegative = null;
  do {
    current = await observeContainer(
      options.containerName,
      { ...options.runtime, phase: 'reacquisition-poll' },
      options.invocationEntries
    );
    options.runtimePolls.push(current);
    const observedMonotonicNs = BigInt(current.monotonicNs);
    const descriptorObservedNow = targetDescriptors(current).length > 0;
    const logMarkersObservedNow = postReturnMarkersObserved(options.absentMarkers, current.markers);
    if (observedMonotonicNs <= deadline) {
      currentDescriptorObserved ||= descriptorObservedNow;
      postReturnLogMarkersObserved ||= logMarkersObservedNow;
      if (currentDescriptorObserved && postReturnLogMarkersObserved) break;
    }
    if (observedMonotonicNs >= deadline) {
      deadlineBoundaryNegative = !descriptorObservedNow && !logMarkersObservedNow;
    }
    if (observedMonotonicNs < deadline) await sleep(500);
  } while (BigInt(current.monotonicNs) < deadline);
  const completedMonotonicNs = process.hrtime.bigint();
  const deadlineExpired = completedMonotonicNs >= deadline;
  return {
    startedAt: options.startedAt,
    startedMonotonicNs: startedMonotonicNs.toString(),
    completedAt: new Date().toISOString(),
    completedMonotonicNs: completedMonotonicNs.toString(),
    timeoutSeconds: options.timeoutSeconds,
    deadlineExpired,
    currentDescriptorObserved,
    postReturnLogMarkersObserved,
    deadlineBoundaryConsistent:
      !deadlineExpired ||
      (currentDescriptorObserved && postReturnLogMarkersObserved) ||
      deadlineBoundaryNegative === true,
    runtime: current,
  };
}

function runtimePollText(runtimePolls) {
  return `${runtimePolls
    .map(({ logText: _logText, ...entry }) => JSON.stringify(entry))
    .join('\n')}\n`;
}

const arguments_ = parseArgs(process.argv.slice(2));
const [nodeMajor, nodeMinor] = process.versions.node.split('.').map(Number);
if (nodeMajor !== 22 || nodeMinor < 20) {
  throw new Error('H-041 requires Node >=22.20 and <23');
}

const id = createRunId();
const evidenceDirectory = path.resolve(
  REPOSITORY_ROOT,
  arguments_.evidenceDirectory ?? path.join('artifacts/h041', id)
);
if (!evidenceDirectory.startsWith(`${REPOSITORY_ROOT}${path.sep}`)) {
  throw new Error('H-041 evidence directory must remain inside the repository');
}
await mkdir(evidenceDirectory, { recursive: true });
if ((await readdir(evidenceDirectory)).length > 0) {
  throw new Error('H-041 evidence directory must be empty before the run');
}
const candidateRunPath = path.join(evidenceDirectory, 'run.candidate.json');
const completedRunPath = path.join(evidenceDirectory, 'run.json');
const verificationReceiptPath = path.join(evidenceDirectory, 'verification.json');
const failurePath = path.join(evidenceDirectory, 'failure.json');

const h037Path = repositoryPath(arguments_.h037, 'H-037 input');
const h039Path = repositoryPath(arguments_.h039, 'H-039 input');
const h040Path = repositoryPath(arguments_.h040, 'H-040 input');
const [h037Bytes, h039Bytes, h040Bytes] = await Promise.all([
  readFile(h037Path),
  readFile(h039Path),
  readFile(h040Path),
]);
const h037 = JSON.parse(h037Bytes);
const h039 = JSON.parse(h039Bytes);
const h040 = JSON.parse(h040Bytes);
const h037Validation = validateH037(h037Bytes, h037);
const [h039Independent, h040Independent] = await Promise.all([
  independentReceipt(path.join(REPOSITORY_ROOT, 'lab/h039/verify.mjs'), h039Path, 'H-039'),
  independentReceipt(path.join(REPOSITORY_ROOT, 'lab/h040/verify.mjs'), h040Path, 'H-040'),
]);
validateH039Receipt(h039, h039Independent.receipt);
validateH040Receipt(h040, h040Independent.receipt);
if (h037.input.device.serial !== h039.device.serial || h039.device.serial !== h040.device.serial) {
  throw new Error('H-041 predecessor evidence does not bind one exact MK.2 serial');
}

await Promise.all([
  writeFile(
    path.join(evidenceDirectory, 'h037-validation.json'),
    `${JSON.stringify(h037Validation, null, 2)}\n`,
    { mode: 0o600 }
  ),
  writeFile(path.join(evidenceDirectory, 'h039-verification.json'), h039Independent.text, {
    mode: 0o600,
  }),
  writeFile(path.join(evidenceDirectory, 'h040-verification.json'), h040Independent.text, {
    mode: 0o600,
  }),
]);

const observedHost = await observeHostIdentity(h039.host.principal.user);
if (
  observedHost.osId !== h039.host.osId ||
  observedHost.osVersion !== h039.host.osVersion ||
  observedHost.kernel !== h039.host.kernel ||
  observedHost.architecture !== h039.host.architecture ||
  observedHost.machine !== h039.host.machine ||
  sha256Canonical(observedHost.principal) !== sha256Canonical(h039.host.principal)
) {
  throw new Error('H-041 current host or principal differs from the bounded H-039 host');
}
const session = await graphicalSession(observedHost.principal.user);
const serial = h039.device.serial;
const hostTimeline = [];
const present = await waitForStableHostState('present', serial, {
  timeoutMs: 10_000,
  previousDevicePath: h040.device.returnedPath,
  timeline: hostTimeline,
});
const mappingHost = present.snapshot;
const mappingNode = exactNode(mappingHost, 'preflight');
if (!mappingNode.owner?.observed || mappingNode.owner.pids.length > 0) {
  throw new Error(
    'H-041 requires the exact MK.2 present with no owner observed in the host namespace'
  );
}
const initialInventory = await inventoryHostHidraw();
const selectedInventory = selectExactTargetHidraw(initialInventory, {
  vendorId: TARGET_VENDOR_ID,
  productId: TARGET_PRODUCT_ID,
  serial,
});
if (
  selectedInventory.devicePath !== mappingNode.devicePath ||
  selectedInventory.stat.stable !== true ||
  selectedInventory.stat.matchesClass !== true ||
  !sameDeviceAccessBoundary(mappingNode.stat, selectedInventory.stat.value) ||
  mappingNode.stat.uid !== 0 ||
  mappingNode.stat.mode !== '0660' ||
  mappingNode.stat.isCharacterDevice !== true
) {
  throw new Error('H-041 all-hidraw inventory disagrees with the exact host observer');
}
const deviceGid = mappingNode.stat.gid;
if (
  deviceGid !== h037.input.host.supplementaryGroupId ||
  !observedHost.principal.groups.some((group) => group.gid === deviceGid)
) {
  throw new Error('H-041 current principal or predecessor evidence lacks the device group');
}

const governanceVerify = await command('npm', ['run', 'governance:verify'], {
  cwd: REPOSITORY_ROOT,
});
const governanceVerifyText = `${governanceVerify.stdout}${governanceVerify.stderr}`;
const manifestBytes = await readFile(
  path.join(REPOSITORY_ROOT, '.overlaykit/governance/manifest.json')
);
const manifest = JSON.parse(manifestBytes);
const initialSourceSha256 = sourceHashes();
if (
  manifest.changes?.['CHG-0012'] !==
  initialSourceSha256['.overlaykit/governance/changes/CHG-0012.json']
) {
  throw new Error('H-041 change contract is not bound by the verified manifest');
}
await Promise.all([
  writeFile(path.join(evidenceDirectory, 'governance-manifest.json'), manifestBytes, {
    mode: 0o600,
  }),
  writeFile(path.join(evidenceDirectory, 'governance-verify.txt'), governanceVerifyText, {
    mode: 0o600,
  }),
]);

const [imageResult, dockerVersionResult, dockerInfoResult] = await Promise.all([
  command('docker', ['image', 'inspect', OFFICIAL_IMAGE]),
  command('docker', ['version', '--format', '{{json .}}']),
  command('docker', ['info', '--format', '{{json .}}']),
]);
const image = JSON.parse(imageResult.stdout)[0];
const dockerVersion = JSON.parse(dockerVersionResult.stdout);
const dockerInfo = JSON.parse(dockerInfoResult.stdout);
if (
  image?.Id !== EXPECTED_IMAGE_ID ||
  !image.RepoDigests?.includes(
    'ghcr.io/bitfocus/companion/companion@sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e'
  ) ||
  image.Config?.Labels?.['org.opencontainers.image.revision'] !== EXPECTED_IMAGE_REVISION ||
  dockerVersion.Server === null ||
  typeof dockerInfo.ServerVersion !== 'string'
) {
  throw new Error('H-041 could not bind the exact Companion image or Docker runtime');
}

const basename = path.basename(mappingNode.devicePath);
if (!/^hidraw[0-9]+$/u.test(basename)) {
  throw new Error('H-041 target device does not have an exact hidraw basename');
}
const compatibilityPath = `/dev/${basename}`;
const dynamicPath = `${DYNAMIC_ROOT}/${basename}`;
const cgroupRule = `c ${mappingNode.stat.major}:${mappingNode.stat.minor} rw`;
const containerName = `h041-companion-${sha256(id).slice(0, 12)}`;
const invocationEntries = [];
const runtimePolls = [];
const startedAt = new Date().toISOString();
let containerCreated = false;
let containerId = null;
let initialRuntime = null;
let absentRuntime = null;
let finalRuntime = null;
let run = null;
let primaryError = null;

try {
  const runArguments = [
    'run',
    '--detach',
    '--rm',
    '--name',
    containerName,
    '--label',
    'dev.overlaykit.hypothesis=H-041',
    '--network',
    'none',
    '--cgroupns',
    'private',
    '--read-only',
    '--tmpfs',
    '/companion:rw,nosuid,nodev,noexec,size=268435456,uid=1000,gid=1000,mode=0700',
    '--tmpfs',
    '/tmp:rw,nosuid,nodev,size=67108864,uid=1000,gid=1000,mode=1777',
    '--cap-drop',
    'ALL',
    '--cap-add',
    'SETUID',
    '--cap-add',
    'SETGID',
    '--security-opt',
    'no-new-privileges',
    '--pids-limit',
    '128',
    '--memory',
    '1g',
    '--user',
    '0:0',
    '--group-add',
    String(deviceGid),
    '--device-cgroup-rule',
    cgroupRule,
    '--mount',
    `type=bind,src=/dev,dst=${DYNAMIC_ROOT},readonly,bind-recursive=disabled`,
    '--mount',
    `type=bind,src=${path.join(LAB_DIRECTORY, 'entrypoint.sh')},dst=${CONTAINER_ENTRYPOINT},readonly`,
    '--mount',
    `type=bind,src=${path.join(LAB_DIRECTORY, 'container-observer.mjs')},dst=${CONTAINER_OBSERVER},readonly`,
    '--env',
    'H041_UID=1000',
    '--env',
    'H041_GID=1000',
    '--env',
    `H041_DEVICE_GID=${deviceGid}`,
    '--env',
    `H041_DYNAMIC_PATH=${dynamicPath}`,
    '--env',
    `H041_COMPAT_PATH=${compatibilityPath}`,
    '--entrypoint',
    '/bin/bash',
    OFFICIAL_IMAGE,
    CONTAINER_ENTRYPOINT,
  ];
  auditEntry(invocationEntries, {
    kind: 'docker-run',
    phase: 'setup',
    target: containerName,
    imageReference: OFFICIAL_IMAGE,
    dynamicSource: '/dev',
    dynamicDestination: DYNAMIC_ROOT,
    dynamicReadOnly: true,
    bindRecursive: false,
    compatibilityPath,
    dynamicPath,
    cgroupRule,
    deviceGid,
    staticDevices: [],
    runnerDeviceIo: false,
    companionTargetIoExpected: true,
    configBaseDirectory: '/companion',
    ephemeralConfig: true,
    labLabel: 'dev.overlaykit.hypothesis=H-041',
  });
  const created = await command('docker', runArguments);
  containerCreated = true;
  containerId = created.stdout.trim();
  if (!/^[0-9a-f]{64}$/u.test(containerId)) {
    throw new Error('H-041 docker run did not return one exact container identity');
  }

  const runtimeOptions = {
    dynamicPath,
    compatibilityPath,
    major: mappingNode.stat.major,
    minor: mappingNode.stat.minor,
    serial,
  };
  initialRuntime = await waitForBaseline({
    containerName,
    runtime: runtimeOptions,
    timeoutSeconds: arguments_.baselineWindowSeconds,
    invocationEntries,
    runtimePolls,
  });
  if (
    initialRuntime.container.containerId !== containerId ||
    !permissionBoundaryExact(initialRuntime, {
      deviceGid,
      cgroupRule,
      dynamicPath,
    })
  ) {
    throw new Error('H-041 runtime does not match the declared exact permission boundary');
  }
  const initialHost = captureHostSnapshot(serial, {
    includeOwners: true,
    previousDevicePath: mappingNode.devicePath,
  });
  const initialNode = exactNode(initialHost, 'initial');
  if (
    hostEpochChanged(mappingHost, initialHost) ||
    !sameDeviceAccessBoundary(mappingNode.stat, initialNode.stat) ||
    !sameDeviceAccessBoundary(initialNode.stat, initialRuntime.observer.paths.dynamic.stat.value) ||
    !sameDeviceAccessBoundary(initialNode.stat, initialRuntime.observer.paths.compat.stat.value) ||
    !dynamicStageMatchesHost({
      hostNode: initialNode,
      dynamic: initialRuntime.observer.paths.dynamic.stat,
    })
  ) {
    throw new Error('H-041 host epoch or dynamic view changed while establishing baseline');
  }

  const disconnectChallenge = sha256(`${id}:${serial}:disconnect`).slice(0, 12);
  const disconnectWindow = openWindow(
    'disconnect',
    disconnectChallenge,
    arguments_.transitionWindowSeconds,
    'DESCONECTA físicamente el cable USB del Stream Deck MK.2'
  );
  auditEntry(invocationEntries, {
    kind: 'physical-disconnect-window',
    phase: 'disconnect',
    challenge: disconnectChallenge,
    expectedActor: 'human-principal',
  });
  process.stdout.write(
    `H-041 ${disconnectChallenge}: ${disconnectWindow.instruction} (${arguments_.transitionWindowSeconds}s).\n`
  );
  const absentStable = await waitForStableHostState('absent', serial, {
    timeoutMs: arguments_.transitionWindowSeconds * 1000,
    previousDevicePath: initialNode.devicePath,
    timeline: hostTimeline,
  });
  const absentHost = absentStable.snapshot;
  absentRuntime = await waitForAbsentDescriptor({
    containerName,
    runtime: runtimeOptions,
    timeoutSeconds: arguments_.absentDescriptorWindowSeconds,
    invocationEntries,
    runtimePolls,
  });
  closeWindow(disconnectWindow);
  if (absentRuntime === null) {
    throw new Error('H-041 could not observe Companion at stable physical absence');
  }

  const reconnectChallenge = sha256(
    `${id}:${serial}:reconnect:${disconnectWindow.closedMonotonicNs}`
  ).slice(0, 12);
  const reconnectWindow = openWindow(
    'reconnect',
    reconnectChallenge,
    arguments_.transitionWindowSeconds,
    'RECONECTA físicamente el cable USB del mismo Stream Deck MK.2'
  );
  auditEntry(invocationEntries, {
    kind: 'physical-reconnect-window',
    phase: 'reconnect',
    challenge: reconnectChallenge,
    expectedActor: 'human-principal',
  });
  process.stdout.write(
    `H-041 ${reconnectChallenge}: ${reconnectWindow.instruction} (${arguments_.transitionWindowSeconds}s).\n`
  );
  const returnedStable = await waitForStableHostState('present', serial, {
    timeoutMs: arguments_.transitionWindowSeconds * 1000,
    previousDevicePath: initialNode.devicePath,
    timeline: hostTimeline,
  });
  const returnedHost = returnedStable.snapshot;
  const returnedNode = exactNode(returnedHost, 'returned');
  const returnedInventory = await inventoryHostHidraw();
  const returnedSelection = selectExactTargetHidraw(returnedInventory, {
    vendorId: TARGET_VENDOR_ID,
    productId: TARGET_PRODUCT_ID,
    serial,
  });
  closeWindow(reconnectWindow);

  const reacquisition = await waitForReacquisition({
    containerName,
    runtime: runtimeOptions,
    timeoutSeconds: arguments_.reacquisitionWindowSeconds,
    absentMarkers: absentRuntime.markers,
    startedAt: returnedHost.capturedAt,
    startedMonotonicNs: returnedHost.monotonicNs,
    invocationEntries,
    runtimePolls,
  });
  finalRuntime = reacquisition.runtime;
  const finalSourceSha256 = sourceHashes();
  const sourceStable = JSON.stringify(initialSourceSha256) === JSON.stringify(finalSourceSha256);
  if (!sourceStable) {
    throw new Error('H-041 source changed during the physical experiment');
  }

  const preliminaryAudit = invocationAudit(invocationEntries);
  const dynamicInitialMatchesHost = dynamicStageMatchesHost({
    hostNode: initialNode,
    dynamic: initialRuntime.observer.paths.dynamic.stat,
  });
  const dynamicAbsent = dynamicStageMatchesHost({
    hostNode: null,
    dynamic: absentRuntime.observer.paths.dynamic.stat,
  });
  const dynamicReturnedMatchesHost = dynamicStageMatchesHost({
    hostNode: returnedNode,
    dynamic: finalRuntime.observer.paths.dynamic.stat,
  });
  const permissionExact =
    permissionBoundaryExact(initialRuntime, { deviceGid, cgroupRule, dynamicPath }) &&
    permissionBoundaryExact(finalRuntime, { deviceGid, cgroupRule, dynamicPath }) &&
    returnedSelection.stat.stable === true &&
    returnedSelection.stat.matchesClass === true &&
    sameDeviceAccessBoundary(mappingNode.stat, returnedNode.stat) &&
    sameDeviceAccessBoundary(mappingNode.stat, returnedSelection.stat.value) &&
    sameDeviceAccessBoundary(returnedNode.stat, finalRuntime.observer.paths.dynamic.stat.value) &&
    sameDeviceAccessBoundary(returnedNode.stat, finalRuntime.observer.paths.compat.stat.value) &&
    returnedNode.devicePath === initialNode.devicePath;
  const predicates = {
    complete: true,
    interventionFree: preliminaryAudit.interventionFree,
    permissionBoundaryExact: permissionExact,
    hostEpochChanged: hostEpochChanged(initialHost, returnedHost),
    dynamicViewTracksHost: dynamicInitialMatchesHost && dynamicAbsent && dynamicReturnedMatchesHost,
    topLevelLifecycleUnchanged:
      sameTopLevelLifecycle(initialRuntime.lifecycle, absentRuntime.lifecycle) &&
      sameTopLevelLifecycle(initialRuntime.lifecycle, finalRuntime.lifecycle),
    baselineAcquired: baselineAcquired(initialRuntime),
    descriptorAbsent: descriptorAbsent(absentRuntime),
    postReturnDescriptorObserved: reacquisition.currentDescriptorObserved,
    postReturnLogMarkersObserved: reacquisition.postReturnLogMarkersObserved,
    deadlineBoundaryConsistent: reacquisition.deadlineBoundaryConsistent,
  };
  const outcome = classifyH041Outcome(predicates);

  const hostPoll = compactHostTimeline(hostTimeline);
  const runtimePoll = runtimePollText(runtimePolls);
  const artifactWrites = {
    'host-poll.jsonl': hostPoll,
    'runtime-poll.jsonl': runtimePoll,
    'logs-initial.txt': initialRuntime.logText,
    'logs-absent.txt': absentRuntime.logText,
    'logs-final.txt': finalRuntime.logText,
  };
  await Promise.all(
    Object.entries(artifactWrites).map(([name, contents]) =>
      writeFile(path.join(evidenceDirectory, name), contents, { mode: 0o600 })
    )
  );

  const withoutLogs = ({ logText: _logText, ...value }) => value;
  run = {
    schemaVersion: 'overlaykit-h041-dynamic-reacquisition-run/v1',
    hypothesis: 'H-041',
    runId: id,
    startedAt,
    completedAt: null,
    outcome,
    collector: {
      node: process.version,
      repository: (
        await command('git', ['config', '--get', 'remote.origin.url'], {
          cwd: REPOSITORY_ROOT,
        })
      ).stdout.trim(),
      commit: (await command('git', ['rev-parse', 'HEAD'], { cwd: REPOSITORY_ROOT })).stdout.trim(),
      sourceSha256: finalSourceSha256,
      sourceStable,
      governance: {
        manifestSnapshotPath: 'governance-manifest.json',
        manifestFileSha256: sha256(manifestBytes),
        manifestContentHash: manifest.contentHash,
        changeSha256: manifest.changes['CHG-0012'],
        verifyReceiptPath: 'governance-verify.txt',
        verifyReceiptSha256: sha256(governanceVerifyText),
        planHash: manifest.planHash,
      },
    },
    inputs: {
      h037: {
        path: path.relative(REPOSITORY_ROOT, h037Path),
        fileSha256: sha256(h037Bytes),
        evidenceSha256: h037.evidenceSha256,
        validationReceipt: {
          path: 'h037-validation.json',
          sha256: sha256(`${JSON.stringify(h037Validation, null, 2)}\n`),
        },
      },
      h039: {
        path: path.relative(REPOSITORY_ROOT, h039Path),
        fileSha256: sha256(h039Bytes),
        evidenceSha256: h039.evidenceSha256,
        verificationReceipt: {
          path: 'h039-verification.json',
          sha256: sha256(h039Independent.text),
        },
      },
      h040: {
        path: path.relative(REPOSITORY_ROOT, h040Path),
        fileSha256: sha256(h040Bytes),
        evidenceSha256: h040.evidenceSha256,
        verificationReceipt: {
          path: 'h040-verification.json',
          sha256: sha256(h040Independent.text),
        },
      },
    },
    host: {
      ...observedHost,
      graphicalSession: session.selected,
      docker: {
        version: dockerVersion,
        info: dockerInfo,
      },
    },
    device: {
      vendorId: TARGET_VENDOR_ID,
      productId: TARGET_PRODUCT_ID,
      model: h039.device.model,
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
      finalLifecycle: finalRuntime.lifecycle,
      workerLifecycle: {
        initial: initialRuntime.observer.surfaceWorkers,
        absent: absentRuntime.observer.surfaceWorkers,
        final: finalRuntime.observer.surfaceWorkers,
      },
    },
    windows: {
      disconnect: disconnectWindow,
      reconnect: reconnectWindow,
      reacquisition: {
        startedAt: reacquisition.startedAt,
        startedMonotonicNs: reacquisition.startedMonotonicNs,
        completedAt: reacquisition.completedAt,
        completedMonotonicNs: reacquisition.completedMonotonicNs,
        timeoutSeconds: reacquisition.timeoutSeconds,
        deadlineExpired: reacquisition.deadlineExpired,
      },
    },
    observations: {
      preflight: {
        host: mappingHost,
      },
      initial: {
        host: initialHost,
        runtime: withoutLogs(initialRuntime),
      },
      absent: {
        host: absentHost,
        runtime: withoutLogs(absentRuntime),
      },
      returned: {
        host: returnedHost,
        runtime: withoutLogs(finalRuntime),
      },
      reacquisition: {
        currentDescriptorObserved: reacquisition.currentDescriptorObserved,
        postReturnLogMarkersObserved: reacquisition.postReturnLogMarkersObserved,
        initialMarkers: initialRuntime.markers,
        absentMarkers: absentRuntime.markers,
        finalMarkers: finalRuntime.markers,
      },
      artifacts: {
        hostPoll: { path: 'host-poll.jsonl', sha256: sha256(hostPoll) },
        runtimePoll: { path: 'runtime-poll.jsonl', sha256: sha256(runtimePoll) },
        initialLogs: {
          path: 'logs-initial.txt',
          sha256: sha256(initialRuntime.logText),
        },
        absentLogs: {
          path: 'logs-absent.txt',
          sha256: sha256(absentRuntime.logText),
        },
        finalLogs: {
          path: 'logs-final.txt',
          sha256: sha256(finalRuntime.logText),
        },
      },
    },
    predicates,
    invocationAudit: null,
    claimBoundary: H041_CLAIM_BOUNDARY,
  };
} catch (error) {
  primaryError = error;
} finally {
  const cleanupStartedAt = new Date().toISOString();
  let cleanupError = null;
  if (containerCreated) {
    try {
      auditEntry(invocationEntries, {
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
  const cleanupHost = captureHostSnapshot(serial, {
    includeOwners: true,
    previousDevicePath: mappingNode.devicePath,
  });
  const cleanupOwners = cleanupHost.hidraw
    .filter((entry) => entry.serialMatches)
    .map((entry) => ({
      devicePath: entry.devicePath,
      owner: entry.owner ?? ownerObservation(entry.devicePath),
    }));
  const cleanup = {
    startedAt: cleanupStartedAt,
    completedAt: new Date().toISOString(),
    containerId,
    containerRemoved,
    host: cleanupHost,
    owners: cleanupOwners,
    hostConfigurationChanged: false,
    productionConfigurationChanged: false,
    successful:
      containerRemoved &&
      cleanupError === null &&
      cleanupHost.state === 'present' &&
      cleanupOwners.length === 1 &&
      cleanupOwners.every(({ owner }) => owner.observed && owner.pids.length === 0),
    error: cleanupError,
  };
  if (run && cleanup.successful) {
    run.completedAt = cleanup.completedAt;
    run.invocationAudit = invocationAudit(invocationEntries);
    run.cleanup = cleanup;
    const evidence = { ...run, evidenceSha256: sha256Canonical(run) };
    await writeFile(candidateRunPath, `${JSON.stringify(evidence, null, 2)}\n`, {
      mode: 0o600,
    });
  } else {
    const failureMessage =
      primaryError instanceof Error
        ? primaryError.message
        : primaryError === null
          ? 'H-041 completed its observation but cleanup failed closed'
          : String(primaryError);
    await writeFile(
      failurePath,
      `${JSON.stringify(
        {
          schemaVersion: 'overlaykit-h041-failure/v1',
          hypothesis: 'H-041',
          runId: id,
          classification: 'inconclusive',
          failedAt: new Date().toISOString(),
          message: failureMessage,
          provisional:
            run === null
              ? null
              : {
                  outcome: run.outcome,
                  predicates: run.predicates,
                },
          cleanup,
        },
        null,
        2
      )}\n`,
      { mode: 0o600 }
    );
  }
  if (!cleanup.successful && primaryError === null) {
    primaryError = new Error('H-041 evidence completed but cleanup failed closed');
  }
}

if (primaryError !== null) throw primaryError;

try {
  const verification = await command(
    process.execPath,
    [path.join(LAB_DIRECTORY, 'verify.mjs'), candidateRunPath],
    { cwd: REPOSITORY_ROOT }
  );
  const receipt = JSON.parse(verification.stdout);
  if (
    receipt.schemaVersion !== 'overlaykit-h041-verification/v1' ||
    receipt.hypothesis !== 'H-041' ||
    receipt.verified !== true ||
    receipt.cleaned !== true
  ) {
    throw new Error('H-041 independent verifier returned a malformed receipt');
  }
  await writeFile(verificationReceiptPath, `${JSON.stringify(receipt, null, 2)}\n`, {
    mode: 0o600,
  });
  await rename(candidateRunPath, completedRunPath);
  process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
} catch (error) {
  await unlink(candidateRunPath).catch(() => {});
  const message =
    error instanceof Error
      ? `H-041 independent verification failed: ${error.message}`
      : `H-041 independent verification failed: ${String(error)}`;
  await writeFile(
    failurePath,
    `${JSON.stringify(
      {
        schemaVersion: 'overlaykit-h041-failure/v1',
        hypothesis: 'H-041',
        runId: id,
        classification: 'inconclusive',
        failedAt: new Date().toISOString(),
        message,
        provisional:
          run === null
            ? null
            : {
                outcome: run.outcome,
                predicates: run.predicates,
              },
        cleanup: run?.cleanup ?? null,
      },
      null,
      2
    )}\n`,
    { mode: 0o600 }
  );
  throw new Error(message, { cause: error });
}
process.stdout.write(`${completedRunPath}\n`);
