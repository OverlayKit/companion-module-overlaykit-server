import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { classifyFuserResult } from '../h035/inventory-lib.mjs';
import {
  CLAIM_BOUNDARY,
  COMPANION_IMAGE,
  acquisitionSignals,
  parseFdListing,
  parseProcessTable,
  sha256,
  sha256Canonical,
  stripAnsi,
} from './acquisition-lib.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const SOURCE_FILES = [
  '.overlaykit/governance/changes/CHG-0008.json',
  'lab/h037/acquisition-lib.mjs',
  'lab/h037/run.mjs',
  'lab/h037/schemas/acquisition.schema.json',
];

function command(program, args) {
  const result = spawnSync(program, args, {
    cwd: REPOSITORY_ROOT,
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  return {
    program,
    args,
    exitCode: result.status,
    signal: result.signal,
    errorCode: result.error?.code ?? null,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

function required(program, args) {
  const result = command(program, args);
  if (result.errorCode !== null || result.exitCode !== 0) {
    throw new Error(
      `${program} ${args.join(' ')} failed (${result.errorCode ?? result.exitCode}): ${
        result.stderr
      }`
    );
  }
  return result;
}

function parseArgs(argv) {
  const result = {
    inventory: 'artifacts/h035/host-inventory-2026-07-25.json',
    out: 'artifacts/h037/acquisition-2026-07-25.json',
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--inventory') {
      result.inventory = argv[index + 1] ?? '';
      index += 1;
    } else if (argument === '--out') {
      result.out = argv[index + 1] ?? '';
      index += 1;
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }
  return result;
}

function readJson(filePath) {
  return JSON.parse(readFileSync(filePath, 'utf8'));
}

function sourceHashes() {
  return Object.fromEntries(
    SOURCE_FILES.map((relativePath) => [
      relativePath,
      sha256(readFileSync(path.join(REPOSITORY_ROOT, relativePath))),
    ])
  );
}

function ownerObservation(devicePath) {
  const result = command('fuser', ['-v', devicePath]);
  const classification = classifyFuserResult(result);
  return {
    observed: classification.observed,
    usageError: classification.usageError,
    exitCode: result.exitCode,
    errorCode: result.errorCode,
    pids: classification.pids,
    stdout: result.stdout.trim(),
    stderr: result.stderr.trim(),
  };
}

function inspectContainer(name) {
  return JSON.parse(required('docker', ['inspect', name]).stdout)[0];
}

function containerExists(name) {
  return command('docker', ['inspect', name]).exitCode === 0;
}

function stopContainer(name) {
  if (!containerExists(name)) return { existed: false, stopped: true };
  const result = command('docker', ['stop', '--timeout', '10', name]);
  return {
    existed: true,
    stopped: result.exitCode === 0,
    exitCode: result.exitCode,
    stderr: result.stderr.trim(),
  };
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitFor(name, predicate, description, timeoutMs = 20_000) {
  const started = Date.now();
  let last = null;
  while (Date.now() - started < timeoutMs) {
    const inspect = inspectContainer(name);
    const logsResult = command('docker', ['logs', name]);
    const logs = stripAnsi(`${logsResult.stdout}${logsResult.stderr}`);
    last = { inspect, logs };
    if (predicate(last)) return last;
    await sleep(250);
  }
  throw new Error(`${name} did not reach ${description}: ${last?.logs ?? 'no logs'}`);
}

function processEvidence(name, devicePath) {
  const id = required('docker', ['exec', name, 'id']).stdout.trim();
  const groups = required('docker', ['exec', name, 'id', '-G'])
    .stdout.trim()
    .split(/\s+/u)
    .filter(Boolean)
    .map(Number);
  const processesResult = required('docker', [
    'exec',
    name,
    'ps',
    '-eo',
    'pid=,ppid=,uid=,gid=,comm=,args=',
  ]);
  const processes = parseProcessTable(processesResult.stdout);
  const surface = processes.find(
    (process) => typeof process.args === 'string' && process.args.includes('SurfaceThread.js')
  );
  if (!surface?.pid) throw new Error(`${name} lacks a SurfaceThread.js process`);
  const fdResult = required('docker', ['exec', name, 'ls', '-l', `/proc/${surface.pid}/fd`]);
  const fileDescriptors = parseFdListing(fdResult.stdout);
  const top = required('docker', [
    'top',
    name,
    '-eo',
    'pid,ppid,user,group,comm,args',
  ]).stdout.trim();
  return {
    id,
    groups,
    processes,
    surfacePid: surface.pid,
    surfaceUid: surface.uid,
    surfaceGid: surface.gid,
    fileDescriptors,
    ownsDevice: fileDescriptors.some(({ target }) => target === devicePath),
    hostProcessTable: top,
  };
}

function containerSummary(inspect) {
  return {
    id: inspect.Id,
    imageId: inspect.Image,
    state: inspect.State.Status,
    healthy: inspect.State.Health?.Status === 'healthy',
    hostPid: inspect.State.Pid,
    user: inspect.Config.User,
    autoRemove: inspect.HostConfig.AutoRemove,
    privileged: inspect.HostConfig.Privileged,
    devices: inspect.HostConfig.Devices,
    groupAdd: inspect.HostConfig.GroupAdd ?? [],
    tmpfs: inspect.HostConfig.Tmpfs,
  };
}

async function runControl({ name, devicePath, serial, groupId, exposeDevice, addGroup }) {
  if (containerExists(name)) throw new Error(`Refusing to reuse existing container ${name}`);
  const args = [
    'run',
    '--detach',
    '--rm',
    '--name',
    name,
    '--tmpfs',
    '/companion:uid=1000,gid=1000,mode=0700',
  ];
  if (exposeDevice) {
    args.push('--device', `${devicePath}:${devicePath}:rwm`);
  }
  if (addGroup) {
    args.push('--group-add', String(groupId));
  }
  args.push(COMPANION_IMAGE);
  const containerId = required('docker', args).stdout.trim();
  const observed = await waitFor(
    name,
    ({ inspect, logs }) => {
      const signals = acquisitionSignals(logs, devicePath, serial);
      return (
        inspect.State.Health?.Status === 'healthy' &&
        (addGroup ? signals.panelReady : signals.openFailed)
      );
    },
    addGroup ? 'healthy acquired panel' : 'healthy open failure'
  );
  const process = processEvidence(name, devicePath);
  return {
    name,
    containerId,
    container: containerSummary(observed.inspect),
    logs: observed.logs,
    signals: acquisitionSignals(observed.logs, devicePath, serial),
    process,
  };
}

const args = parseArgs(process.argv.slice(2));
const inventoryPath = path.resolve(REPOSITORY_ROOT, args.inventory);
const outputPath = path.resolve(REPOSITORY_ROOT, args.out);
const inventoryBytes = readFileSync(inventoryPath);
const inventory = JSON.parse(inventoryBytes);
if (inventory.hypothesis !== 'H-035' || inventory.hidraw.matches.length !== 1) {
  throw new Error('H-037 requires one verified H-035 hidraw match');
}
const device = inventory.hidraw.matches[0];
const serial = device.hid.unique;
if (!serial) throw new Error('H-037 requires the MK.2 serial from H-035');
const groupId = device.before.gid;
const hostUid = inventory.host.principal.uid;
if (hostUid !== 1000) throw new Error(`H-037 image identity expects host uid 1000, got ${hostUid}`);

const suffix = `${process.pid}-${Date.now()}`;
const noDeviceName = `overlaykit-h037-no-device-${suffix}`;
const noGroupName = `overlaykit-h037-no-group-${suffix}`;
const positiveName = `overlaykit-h037-positive-${suffix}`;
const startedAt = new Date().toISOString();
const before = {
  owner: ownerObservation(device.devicePath),
  noDeviceContainerExists: containerExists(noDeviceName),
  noGroupContainerExists: containerExists(noGroupName),
  positiveContainerExists: containerExists(positiveName),
};
let noDevice = null;
let noGroup = null;
let positive = null;
let noDeviceStop = null;
let noGroupStop = null;
let positiveStop = null;

try {
  noDevice = await runControl({
    name: noDeviceName,
    devicePath: device.devicePath,
    serial,
    groupId,
    exposeDevice: false,
    addGroup: false,
  });
  noDeviceStop = stopContainer(noDeviceName);
  await waitForRemoval(noDeviceName);

  noGroup = await runControl({
    name: noGroupName,
    devicePath: device.devicePath,
    serial,
    groupId,
    exposeDevice: true,
    addGroup: false,
  });
  noGroupStop = stopContainer(noGroupName);
  await waitForRemoval(noGroupName);

  positive = await runControl({
    name: positiveName,
    devicePath: device.devicePath,
    serial,
    groupId,
    exposeDevice: true,
    addGroup: true,
  });
} finally {
  if (noDeviceStop === null) noDeviceStop = stopContainer(noDeviceName);
  if (noGroupStop === null) noGroupStop = stopContainer(noGroupName);
  positiveStop = stopContainer(positiveName);
}

async function waitForRemoval(name, timeoutMs = 15_000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (!containerExists(name)) return;
    await sleep(100);
  }
  throw new Error(`Temporary container ${name} was not removed`);
}

await waitForRemoval(noDeviceName);
await waitForRemoval(noGroupName);
await waitForRemoval(positiveName);
const image = JSON.parse(required('docker', ['image', 'inspect', COMPANION_IMAGE]).stdout)[0];
const manifest = readJson(path.join(REPOSITORY_ROOT, '.overlaykit/governance/manifest.json'));
const evidence = {
  schemaVersion: 'overlaykit-h037-acquisition/v1',
  hypothesis: 'H-037',
  startedAt,
  finishedAt: new Date().toISOString(),
  collector: {
    repository: required('git', ['config', '--get', 'remote.origin.url']).stdout.trim(),
    commit: required('git', ['rev-parse', 'HEAD']).stdout.trim(),
    node: process.version,
    sourceSha256: sourceHashes(),
    governanceManifestContentHash: manifest.contentHash,
  },
  input: {
    h035Path: path.relative(REPOSITORY_ROOT, inventoryPath),
    h035FileSha256: sha256(inventoryBytes),
    h035EvidenceSha256: inventory.evidenceSha256,
    host: {
      osVersion: inventory.host.osRelease.VERSION_ID,
      kernel: inventory.host.kernel,
      architecture: inventory.host.architecture,
      uid: hostUid,
      supplementaryGroupId: groupId,
    },
    device: {
      usbVendorId: inventory.usb.target.vendorId,
      usbProductId: inventory.usb.target.productId,
      devicePath: device.devicePath,
      hidId: device.hid.id,
      model: device.hid.name,
      serial,
    },
    companion: {
      image: COMPANION_IMAGE,
      imageId: image.Id,
      repoDigests: image.RepoDigests,
      version: image.Config.Labels['org.opencontainers.image.version'],
      revision: image.Config.Labels['org.opencontainers.image.revision'],
      architecture: image.Architecture,
      os: image.Os,
    },
  },
  before,
  noDevice: { ...noDevice, stop: noDeviceStop },
  deviceWithoutGroup: { ...noGroup, stop: noGroupStop },
  positive: { ...positive, stop: positiveStop },
  after: {
    owner: ownerObservation(device.devicePath),
    noDeviceContainerExists: containerExists(noDeviceName),
    noGroupContainerExists: containerExists(noGroupName),
    positiveContainerExists: containerExists(positiveName),
  },
  claimBoundary: CLAIM_BOUNDARY,
};
const result = { ...evidence, evidenceSha256: sha256Canonical(evidence) };
mkdirSync(path.dirname(outputPath), { recursive: true });
writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`, {
  encoding: 'utf8',
  mode: 0o600,
});
process.stdout.write(
  `${JSON.stringify({
    outputPath,
    evidenceSha256: result.evidenceSha256,
    noDeviceOpenFailed: result.noDevice.signals.openFailed,
    noGroupOpenFailed: result.deviceWithoutGroup.signals.openFailed,
    positiveReady: result.positive.signals.panelReady,
    positiveOwnsDevice: result.positive.process.ownsDevice,
    cleaned:
      !result.after.noDeviceContainerExists &&
      !result.after.noGroupContainerExists &&
      !result.after.positiveContainerExists,
  })}\n`
);
