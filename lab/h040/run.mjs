#!/usr/bin/env node

import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
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
import {
  classifyMappingOutcome,
  dynamicMatchesHost,
  hostEpochChanged,
  normalizeProbeStat,
  staticIdentityUnchanged,
} from './probe-lib.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const STATIC_PATH = '/tmp/h040-static-hidraw';
const DYNAMIC_ROOT = '/host-dev';
const IMAGE_REFERENCE = 'node:22';
const DEFAULT_H039 = 'artifacts/h039/h039-2026-07-25T22-12-14-212Z-e6c2b45e/run.json';
const SOURCE_FILES = [
  '.overlaykit/governance/changes/CHG-0011.json',
  'lab/h035/inventory-lib.mjs',
  'lab/h038/physical-lib.mjs',
  'lab/h039/host-observer.mjs',
  'lab/h039/reconnect-lib.mjs',
  'lab/h039/schemas/reconnect-run.schema.json',
  'lab/h039/verify.mjs',
  'lab/h040/probe-lib.mjs',
  'lab/h040/probe-lib.test.mjs',
  'lab/h040/run.mjs',
  'lab/h040/schema.test.mjs',
  'lab/h040/schemas/docker-mapping-run.schema.json',
  'lab/h040/verify.mjs',
  'lab/h040/verify.test.mjs',
];
const H040_CLAIM_BOUNDARY = Object.freeze({
  proves: [
    'post-login structural device mapping behavior on the exact Fedora 43 host and physical MK.2 identity',
    'one long-lived metadata-only probe container across one human-bounded USB disappearance and return',
    'static Docker device mapping persistence compared only within the container namespace',
    'dynamic read-only host-device-directory visibility compared to the current host node epoch',
    'removal of the exact probe container and an empty host-scope fuser observation for the currently enumerable MK.2 node after the run',
  ],
  excludes: [
    'Companion acquisition, recovery, commands, configuration, or rendered pixels',
    'device reads, device writes, physical key presses, and virtual button invocation',
    'production acceptance of a dynamic device-directory bind or its security posture',
    'udev, systemd, supervisor, rescan, restart, recreation, native deployment, or reboot behavior',
    'pre-login availability, OBS truth, and support beyond the exact tested identities',
  ],
});
const PROBE_SCRIPT = String.raw`
import { statSync } from 'node:fs';

function decode(rdev) {
  return {
    major: Number(((rdev >> 8n) & 0xfffn) | ((rdev >> 32n) & 0xfffff000n)),
    minor: Number((rdev & 0xffn) | ((rdev >> 12n) & 0xffffff00n)),
  };
}

const target = process.env.H040_STAT_PATH;
if (typeof target !== 'string' || !target.startsWith('/')) {
  throw new Error('H040_STAT_PATH must be absolute');
}
try {
  const observed = statSync(target, { bigint: true });
  const { major, minor } = decode(observed.rdev);
  process.stdout.write(JSON.stringify({
    kind: 'value',
    path: target,
    value: {
      stDev: observed.dev.toString(),
      inode: observed.ino.toString(),
      ctimeNs: observed.ctimeNs.toString(),
      rdev: observed.rdev.toString(),
      rdevHex: major.toString(16) + ':' + minor.toString(16),
      major,
      minor,
      isCharacterDevice: observed.isCharacterDevice(),
    },
  }));
} catch (error) {
  if (error?.code !== 'ENOENT') throw error;
  process.stdout.write(JSON.stringify({ kind: 'missing', path: target, code: 'ENOENT' }));
}
`;

function parseArgs(argv) {
  const parsed = {
    h039: DEFAULT_H039,
    evidenceDirectory: null,
    transitionWindowSeconds: 120,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--h039') parsed.h039 = argv[++index] ?? '';
    else if (argument === '--evidence-dir') parsed.evidenceDirectory = argv[++index] ?? '';
    else if (argument === '--transition-seconds') {
      parsed.transitionWindowSeconds = Number(argv[++index]);
    } else {
      throw new Error(`Unknown H-040 argument: ${argument}`);
    }
  }
  if (
    !Number.isSafeInteger(parsed.transitionWindowSeconds) ||
    parsed.transitionWindowSeconds < 20 ||
    parsed.transitionWindowSeconds > 300
  ) {
    throw new Error('H-040 USB transition window must be between 20 and 300 seconds');
  }
  return parsed;
}

function createRunId() {
  return `h040-${new Date().toISOString().replaceAll(/[:.]/gu, '-')}-${randomBytes(4).toString('hex')}`;
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
    throw new Error('H-040 could not bind the current principal group identities');
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
    throw new Error('H-040 current principal identity is incomplete');
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
    throw new Error('H-040 could not identify the current Linux distribution');
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
    throw new Error(`H-040 expected one exact present hidraw node at ${label}`);
  }
  return matches[0];
}

function sourceHashes() {
  return Object.fromEntries(
    SOURCE_FILES.map((relativePath) => [
      relativePath,
      sha256(readFileSync(path.join(REPOSITORY_ROOT, relativePath))),
    ])
  );
}

function validateHistoricalH039(bytes, run, verifierReceipt) {
  const { evidenceSha256, ...evidence } = run;
  let verification;
  try {
    verification = JSON.parse(verifierReceipt);
  } catch {
    throw new Error('H-040 could not parse the H-039 independent verification receipt');
  }
  if (
    run.schemaVersion !== 'overlaykit-h039-reconnect-run/v1' ||
    run.hypothesis !== 'H-039' ||
    run.outcome?.status !== 'refuted' ||
    run.outcome?.stage !== 'companion-reacquisition' ||
    sha256Canonical(evidence) !== evidenceSha256 ||
    !run.cleanup?.successful ||
    run.invocationAudit?.virtualInvocationCount !== 0 ||
    run.device?.vendorId !== '0fd9' ||
    run.device?.productId !== '0080' ||
    verification.schemaVersion !== 'overlaykit-h039-verification/v1' ||
    verification.hypothesis !== 'H-039' ||
    verification.evidenceSha256 !== evidenceSha256 ||
    verification.verified !== true
  ) {
    throw new Error('H-040 requires intact independently verified H-039 refutation evidence');
  }
  return {
    fileSha256: sha256(bytes),
    evidenceSha256,
  };
}

function sameProbeLifecycle(before, after) {
  return (
    before.containerId === after.containerId &&
    before.startedAt === after.startedAt &&
    before.restartCount === after.restartCount &&
    before.hostPid === after.hostPid &&
    before.pid1StartTicks === after.pid1StartTicks &&
    before.running &&
    after.running
  );
}

async function inspectProbe(containerName, invocationEntries) {
  invocationEntries.push({
    kind: 'docker-inspect',
    target: containerName,
    metadataOnly: true,
  });
  const inspected = JSON.parse((await command('docker', ['inspect', containerName])).stdout)[0];
  if (!inspected?.State?.Running || !Number.isSafeInteger(inspected.State.Pid)) {
    throw new Error('H-040 probe container is not running');
  }
  const procStat = await readFile(`/proc/${inspected.State.Pid}/stat`, 'utf8');
  const devices = inspected.HostConfig?.Devices ?? [];
  const mounts = inspected.Mounts ?? [];
  return {
    containerId: inspected.Id,
    name: inspected.Name?.replace(/^\//u, '') ?? containerName,
    imageId: inspected.Image,
    running: inspected.State.Running,
    startedAt: inspected.State.StartedAt,
    restartCount: inspected.RestartCount,
    hostPid: inspected.State.Pid,
    pid1StartTicks: parseProcStartTicks(procStat.trim()),
    restartPolicy: inspected.HostConfig?.RestartPolicy?.Name ?? null,
    autoRemove: inspected.HostConfig?.AutoRemove ?? false,
    networkMode: inspected.HostConfig?.NetworkMode ?? null,
    privileged: inspected.HostConfig?.Privileged ?? null,
    readOnlyRootfs: inspected.HostConfig?.ReadonlyRootfs ?? false,
    capDrop: inspected.HostConfig?.CapDrop ?? [],
    securityOpt: inspected.HostConfig?.SecurityOpt ?? [],
    groupAdd: inspected.HostConfig?.GroupAdd ?? [],
    pidsLimit: inspected.HostConfig?.PidsLimit ?? null,
    memory: inspected.HostConfig?.Memory ?? null,
    deviceCgroupRules: inspected.HostConfig?.DeviceCgroupRules ?? null,
    user: inspected.Config?.User ?? null,
    command: inspected.Config?.Cmd ?? [],
    devices: devices.map((entry) => ({
      pathOnHost: entry.PathOnHost,
      pathInContainer: entry.PathInContainer,
      cgroupPermissions: entry.CgroupPermissions,
    })),
    mounts: mounts.map((entry) => ({
      type: entry.Type,
      source: entry.Source,
      destination: entry.Destination,
      rw: entry.RW,
    })),
  };
}

async function probeStat(containerName, view, targetPath, invocationEntries) {
  invocationEntries.push({
    kind: 'docker-stat',
    view,
    path: targetPath,
    operation: 'fs.statSync',
    metadataOnly: true,
  });
  const observed = await command('docker', [
    'exec',
    '--env',
    `H040_STAT_PATH=${targetPath}`,
    containerName,
    'node',
    '--input-type=module',
    '--eval',
    PROBE_SCRIPT,
  ]);
  let receipt;
  try {
    receipt = JSON.parse(observed.stdout);
  } catch {
    throw new Error(`H-040 ${view} stat did not produce one JSON receipt`);
  }
  if (normalizeProbeStat(receipt) === null) {
    throw new Error(`H-040 ${view} stat receipt is malformed`);
  }
  return receipt;
}

async function observeStage(containerName, hostSnapshot, hostNode, stage, invocationEntries) {
  const dynamicPath =
    hostNode === null
      ? path.posix.join(DYNAMIC_ROOT, path.basename(hostSnapshot.priorPath.path))
      : path.posix.join(DYNAMIC_ROOT, path.basename(hostNode.devicePath));
  const [staticReceipt, dynamicReceipt] = await Promise.all([
    probeStat(containerName, `${stage}-static`, STATIC_PATH, invocationEntries),
    probeStat(containerName, `${stage}-dynamic`, dynamicPath, invocationEntries),
  ]);
  return {
    capturedAt: new Date().toISOString(),
    monotonicNs: process.hrtime.bigint().toString(),
    host: hostSnapshot,
    static: staticReceipt,
    dynamic: dynamicReceipt,
  };
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

function invocationAudit(entries) {
  const allowedKinds = new Set(['docker-run', 'docker-inspect', 'docker-stat', 'docker-stop']);
  const forbidden = entries.filter((entry) => {
    if (!allowedKinds.has(entry.kind) || entry.metadataOnly !== true) return true;
    return entry.kind === 'docker-stat' && entry.operation !== 'fs.statSync';
  });
  const deviceReads = entries.filter((entry) => entry.kind === 'device-read').length;
  const deviceWrites = entries.filter((entry) => entry.kind === 'device-write').length;
  const virtualInvocationCount = entries.filter((entry) => entry.kind === 'virtual-press').length;
  const metadataOnly =
    forbidden.length === 0 &&
    deviceReads === 0 &&
    deviceWrites === 0 &&
    virtualInvocationCount === 0;
  return {
    mode: 'metadata-only',
    metadataOnly,
    deviceReads,
    deviceWrites,
    virtualInvocationCount,
    entries,
    forbidden,
    passed: metadataOnly,
  };
}

const arguments_ = parseArgs(process.argv.slice(2));
const [nodeMajor, nodeMinor] = process.versions.node.split('.').map(Number);
if (nodeMajor !== 22 || nodeMinor < 20) {
  throw new Error('H-040 requires Node >=22.20 and <23');
}

const id = createRunId();
const evidenceDirectory = path.resolve(
  REPOSITORY_ROOT,
  arguments_.evidenceDirectory ?? path.join('artifacts/h040', id)
);
if (!evidenceDirectory.startsWith(`${REPOSITORY_ROOT}${path.sep}`)) {
  throw new Error('H-040 evidence directory must remain inside the repository');
}
await mkdir(evidenceDirectory, { recursive: true });
if ((await readdir(evidenceDirectory)).length > 0) {
  throw new Error('H-040 evidence directory must be empty before the run');
}

const h039Path = path.resolve(REPOSITORY_ROOT, arguments_.h039);
if (!h039Path.startsWith(`${REPOSITORY_ROOT}${path.sep}`)) {
  throw new Error('H-040 H-039 input must remain inside the repository');
}
const h039Bytes = await readFile(h039Path);
const h039 = JSON.parse(h039Bytes);
const h039Verification = await command(
  process.execPath,
  [path.join(REPOSITORY_ROOT, 'lab/h039/verify.mjs'), h039Path],
  { cwd: REPOSITORY_ROOT }
);
const h039VerificationText = `${h039Verification.stdout}${h039Verification.stderr}`;
const h039Receipt = validateHistoricalH039(h039Bytes, h039, h039VerificationText);
await writeFile(path.join(evidenceDirectory, 'h039-verification.json'), h039VerificationText, {
  mode: 0o600,
});

const observedHost = await observeHostIdentity(h039.host.principal.user);
const principal = observedHost.principal;
if (
  observedHost.osId !== h039.host.osId ||
  observedHost.osVersion !== h039.host.osVersion ||
  observedHost.kernel !== h039.host.kernel ||
  observedHost.architecture !== h039.host.architecture ||
  observedHost.machine !== h039.host.machine ||
  sha256Canonical(principal) !== sha256Canonical(h039.host.principal)
) {
  throw new Error('H-040 current host or principal differs from the bounded H-039 host');
}
const session = await graphicalSession(principal.user);
const serial = h039.device.serial;
const previousNode = exactNode(h039.observations.reconnected, 'historical H-039 return');
const hostTimeline = [];
const present = await waitForStableHostState('present', serial, {
  timeoutMs: 10_000,
  previousDevicePath: previousNode.devicePath,
  timeline: hostTimeline,
});
const mappingHost = present.snapshot;
const mappingNode = exactNode(mappingHost, 'mapping baseline');
if (!mappingNode.owner?.observed || mappingNode.owner.pids.length > 0) {
  throw new Error(
    'H-040 requires the exact MK.2 to be present with no owner observed in the host namespace'
  );
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
  manifest.changes?.['CHG-0011'] !==
  initialSourceSha256['.overlaykit/governance/changes/CHG-0011.json']
) {
  throw new Error('H-040 change contract is not bound by the verified manifest');
}
await Promise.all([
  writeFile(path.join(evidenceDirectory, 'governance-manifest.json'), manifestBytes, {
    mode: 0o600,
  }),
  writeFile(path.join(evidenceDirectory, 'governance-verify.txt'), governanceVerifyText, {
    mode: 0o600,
  }),
]);

const image = JSON.parse(
  (await command('docker', ['image', 'inspect', IMAGE_REFERENCE])).stdout
)[0];
if (!image?.Id || !Array.isArray(image.RepoDigests) || image.RepoDigests.length === 0) {
  throw new Error('H-040 could not bind the probe image identity');
}

const containerName = `h040-probe-${sha256(id).slice(0, 12)}`;
const invocationEntries = [];
const startedAt = new Date().toISOString();
let containerCreated = false;
let probeContainerId = null;
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
    'dev.overlaykit.hypothesis=H-040',
    '--network',
    'none',
    '--read-only',
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    '--pids-limit',
    '32',
    '--memory',
    '128m',
    '--user',
    '65534:65534',
    '--device',
    `${mappingNode.devicePath}:${STATIC_PATH}:m`,
    '--mount',
    `type=bind,src=/dev,dst=${DYNAMIC_ROOT},readonly`,
    IMAGE_REFERENCE,
    'sleep',
    'infinity',
  ];
  invocationEntries.push({
    kind: 'docker-run',
    name: containerName,
    imageReference: IMAGE_REFERENCE,
    staticHostPath: mappingNode.devicePath,
    staticContainerPath: STATIC_PATH,
    staticCgroupPermissions: 'm',
    dynamicHostPath: '/dev',
    dynamicContainerPath: DYNAMIC_ROOT,
    dynamicReadOnly: true,
    user: '65534:65534',
    network: 'none',
    readOnlyRootfs: true,
    capDrop: ['ALL'],
    noNewPrivileges: true,
    command: ['sleep', 'infinity'],
    metadataOnly: true,
  });
  const created = await command('docker', runArguments);
  containerCreated = true;
  probeContainerId = created.stdout.trim();
  if (!/^[0-9a-f]{64}$/u.test(probeContainerId)) {
    throw new Error('H-040 docker run did not return one exact container identity');
  }
  const lifecycleBefore = await inspectProbe(containerName, invocationEntries);
  if (
    lifecycleBefore.containerId !== probeContainerId ||
    lifecycleBefore.imageId !== image.Id ||
    lifecycleBefore.restartPolicy !== 'no' ||
    lifecycleBefore.autoRemove !== true ||
    lifecycleBefore.networkMode !== 'none' ||
    lifecycleBefore.privileged !== false ||
    !lifecycleBefore.readOnlyRootfs ||
    JSON.stringify(lifecycleBefore.capDrop) !== JSON.stringify(['ALL']) ||
    JSON.stringify(lifecycleBefore.securityOpt) !== JSON.stringify(['no-new-privileges']) ||
    lifecycleBefore.groupAdd.length !== 0 ||
    lifecycleBefore.pidsLimit !== 32 ||
    lifecycleBefore.memory !== 128 * 1024 * 1024 ||
    lifecycleBefore.deviceCgroupRules !== null ||
    lifecycleBefore.user !== '65534:65534' ||
    JSON.stringify(lifecycleBefore.command) !== JSON.stringify(['sleep', 'infinity']) ||
    lifecycleBefore.devices.length !== 1 ||
    lifecycleBefore.devices[0].pathOnHost !== mappingNode.devicePath ||
    lifecycleBefore.devices[0].pathInContainer !== STATIC_PATH ||
    lifecycleBefore.devices[0].cgroupPermissions !== 'm' ||
    lifecycleBefore.mounts.filter(
      (entry) =>
        entry.type === 'bind' &&
        entry.source === '/dev' &&
        entry.destination === DYNAMIC_ROOT &&
        entry.rw === false
    ).length !== 1
  ) {
    throw new Error('H-040 probe runtime does not match the declared metadata-only isolation');
  }

  const initialHost = captureHostSnapshot(serial, {
    includeOwners: true,
    previousDevicePath: mappingNode.devicePath,
  });
  const initialNode = exactNode(initialHost, 'initial observation');
  if (
    hostEpochChanged(mappingNode, initialNode) !== false ||
    !initialNode.owner?.observed ||
    initialNode.owner.pids.length > 0
  ) {
    throw new Error(
      'H-040 host epoch or host-namespace owner observation changed while the probe was starting'
    );
  }
  const initialObservation = await observeStage(
    containerName,
    initialHost,
    initialNode,
    'initial',
    invocationEntries
  );

  const disconnectChallenge = sha256(`${id}:${serial}:disconnect`).slice(0, 12);
  const disconnectWindow = openWindow(
    'disconnect',
    disconnectChallenge,
    arguments_.transitionWindowSeconds,
    'DESCONECTA físicamente el cable USB del Stream Deck MK.2'
  );
  process.stdout.write(
    `H-040 ${disconnectChallenge}: ${disconnectWindow.instruction} (${arguments_.transitionWindowSeconds}s).\n`
  );
  const absentStable = await waitForStableHostState('absent', serial, {
    timeoutMs: arguments_.transitionWindowSeconds * 1000,
    previousDevicePath: initialNode.devicePath,
    timeline: hostTimeline,
  });
  const absentHost = absentStable.snapshot;
  const absentObservation = await observeStage(
    containerName,
    absentHost,
    null,
    'absent',
    invocationEntries
  );
  closeWindow(disconnectWindow);

  const reconnectChallenge = sha256(
    `${id}:${serial}:reconnect:${disconnectWindow.closedMonotonicNs}`
  ).slice(0, 12);
  const reconnectWindow = openWindow(
    'reconnect',
    reconnectChallenge,
    arguments_.transitionWindowSeconds,
    'RECONECTA físicamente el cable USB del mismo Stream Deck MK.2'
  );
  process.stdout.write(
    `H-040 ${reconnectChallenge}: ${reconnectWindow.instruction} (${arguments_.transitionWindowSeconds}s).\n`
  );
  const returnedStable = await waitForStableHostState('present', serial, {
    timeoutMs: arguments_.transitionWindowSeconds * 1000,
    previousDevicePath: initialNode.devicePath,
    timeline: hostTimeline,
  });
  const returnedHost = returnedStable.snapshot;
  const returnedNode = exactNode(returnedHost, 'returned observation');
  const returnedObservation = await observeStage(
    containerName,
    returnedHost,
    returnedNode,
    'returned',
    invocationEntries
  );
  closeWindow(reconnectWindow);
  const lifecycleAfter = await inspectProbe(containerName, invocationEntries);
  if (!sameProbeLifecycle(lifecycleBefore, lifecycleAfter)) {
    throw new Error('H-040 probe container lifecycle changed during the mapping observation');
  }

  const staticNormalized = [
    initialObservation.static,
    absentObservation.static,
    returnedObservation.static,
  ].map(normalizeProbeStat);
  const dynamicAbsentNormalized = normalizeProbeStat(absentObservation.dynamic);
  const computed = {
    complete: true,
    metadataOnly: invocationAudit(invocationEntries).metadataOnly,
    dynamicInitialMatchesHost: dynamicMatchesHost(initialObservation.dynamic, initialNode),
    dynamicReturnedMatchesHost: dynamicMatchesHost(returnedObservation.dynamic, returnedNode),
    dynamicAbsent:
      dynamicAbsentNormalized?.kind === 'missing' && dynamicAbsentNormalized.code === 'ENOENT',
    staticPersists: staticNormalized.every((receipt) => receipt?.kind === 'value'),
    staticUnchanged: staticIdentityUnchanged(
      initialObservation.static,
      absentObservation.static,
      returnedObservation.static
    ),
    hostEpochChanged: hostEpochChanged(initialNode, returnedNode),
  };
  if (Object.values(computed).some((value) => typeof value !== 'boolean')) {
    throw new Error(
      'H-040 mapping predicates are incomplete and cannot support or refute the claim'
    );
  }
  const classification = classifyMappingOutcome(computed);
  if (classification === 'inconclusive') {
    throw new Error('H-040 mapping observation is inconclusive');
  }
  const failedPredicates = Object.entries(computed)
    .filter(([, value]) => value === false)
    .map(([key]) => key);
  const outcome =
    classification === 'supported'
      ? {
          status: 'supported',
          stage: 'complete',
          reason:
            'The dynamic host-directory view followed absence and the new host epoch while the static Docker device view retained its original container identity.',
        }
      : {
          status: 'refuted',
          stage: 'mapping-observation',
          reason: `The complete metadata-only observation contradicted H-040 predicates: ${failedPredicates.join(', ')}.`,
        };

  const timelineText = `${hostTimeline.map((entry) => JSON.stringify(entry)).join('\n')}\n`;
  await writeFile(path.join(evidenceDirectory, 'host-poll.jsonl'), timelineText, {
    mode: 0o600,
  });
  const finalSourceSha256 = sourceHashes();
  if (JSON.stringify(initialSourceSha256) !== JSON.stringify(finalSourceSha256)) {
    throw new Error('H-040 source changed during the physical experiment');
  }
  run = {
    schemaVersion: 'overlaykit-h040-docker-mapping-run/v1',
    hypothesis: 'H-040',
    runId: id,
    startedAt,
    completedAt: null,
    outcome,
    collector: {
      node: process.version,
      commit: (await command('git', ['rev-parse', 'HEAD'], { cwd: REPOSITORY_ROOT })).stdout.trim(),
      sourceSha256: finalSourceSha256,
      sourceStable: true,
      governance: {
        manifestSnapshotPath: 'governance-manifest.json',
        manifestFileSha256: sha256(manifestBytes),
        manifestContentHash: manifest.contentHash,
        changeSha256: manifest.changes['CHG-0011'],
        verifyReceiptPath: 'governance-verify.txt',
        verifyReceiptSha256: sha256(governanceVerifyText),
        planHash: manifest.planHash,
      },
    },
    inputs: {
      h039Path: path.relative(REPOSITORY_ROOT, h039Path),
      h039FileSha256: h039Receipt.fileSha256,
      h039EvidenceSha256: h039Receipt.evidenceSha256,
      h039VerifyReceipt: {
        path: 'h039-verification.json',
        sha256: sha256(h039VerificationText),
      },
    },
    host: {
      observedAt: observedHost.observedAt,
      osId: observedHost.osId,
      osVersion: observedHost.osVersion,
      kernel: observedHost.kernel,
      architecture: observedHost.architecture,
      machine: observedHost.machine,
      principal,
      graphicalSession: session.selected,
    },
    device: {
      vendorId: h039.device.vendorId,
      productId: h039.device.productId,
      model: h039.device.model,
      serial,
      major: initialNode.stat.major,
      minor: initialNode.stat.minor,
      initialPath: initialNode.devicePath,
      returnedPath: returnedNode.devicePath,
      transition: classifyDeviceTransition(initialNode, returnedNode),
    },
    probe: {
      name: containerName,
      containerId: lifecycleBefore.containerId,
      imageReference: IMAGE_REFERENCE,
      imageId: image.Id,
      repoDigests: image.RepoDigests,
      privileged: false,
      staticPath: STATIC_PATH,
      dynamicRoot: DYNAMIC_ROOT,
      lifecycleBefore,
      lifecycleAfter,
      lifecycleUnchanged: true,
      security: {
        network: 'none',
        readOnlyRootfs: true,
        capDrop: ['ALL'],
        noNewPrivileges: true,
        user: '65534:65534',
        staticCgroupPermissions: 'm',
        dynamicReadOnly: true,
      },
    },
    windows: {
      disconnect: disconnectWindow,
      reconnect: reconnectWindow,
    },
    observations: {
      initial: initialObservation,
      absent: absentObservation,
      returned: returnedObservation,
      hostPollArtifact: {
        path: 'host-poll.jsonl',
        sha256: sha256(timelineText),
      },
    },
    predicates: computed,
    invocationAudit: null,
    claimBoundary: H040_CLAIM_BOUNDARY,
  };
} catch (error) {
  primaryError = error;
  throw error;
} finally {
  const cleanupStartedAt = new Date().toISOString();
  let cleanupError = null;
  if (containerCreated) {
    try {
      invocationEntries.push({
        kind: 'docker-stop',
        target: containerName,
        timeoutSeconds: 5,
        metadataOnly: true,
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
    containerId: probeContainerId,
    containerRemoved,
    host: cleanupHost,
    owners: cleanupOwners,
    hostConfigurationChanged: false,
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
    await writeFile(
      path.join(evidenceDirectory, 'run.json'),
      `${JSON.stringify(evidence, null, 2)}\n`,
      { mode: 0o600 }
    );
  } else {
    const failureMessage =
      primaryError instanceof Error
        ? primaryError.message
        : primaryError === null
          ? 'H-040 completed its mapping observation but cleanup failed closed'
          : String(primaryError);
    await writeFile(
      path.join(evidenceDirectory, 'failure.json'),
      `${JSON.stringify(
        {
          schemaVersion: 'overlaykit-h040-failure/v1',
          hypothesis: 'H-040',
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
    throw new Error('H-040 evidence completed but cleanup failed closed');
  }
}

const completedRunPath = path.join(evidenceDirectory, 'run.json');
await command(process.execPath, [path.join(LAB_DIRECTORY, 'verify.mjs'), completedRunPath], {
  cwd: REPOSITORY_ROOT,
  inherit: true,
});
process.stdout.write(`${completedRunPath}\n`);
