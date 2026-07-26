import {
  accessSync,
  closeSync,
  constants,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  CLAIM_BOUNDARY,
  TARGET_USB,
  canonicalJson,
  classifyFuserResult,
  matchesTargetHid,
  parseProperties,
  sha256,
  sha256Canonical,
  stableDeviceSnapshot,
} from './inventory-lib.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const COLLECTOR_FILES = [
  '.overlaykit/governance/changes/CHG-0006.json',
  'lab/h035/inventory-lib.mjs',
  'lab/h035/inventory.mjs',
  'lab/h035/schemas/inventory.schema.json',
];

function command(program, args) {
  const result = spawnSync(program, args, { encoding: 'utf8' });
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

function requiredCommand(program, args) {
  const result = command(program, args);
  if (result.errorCode !== null || result.exitCode !== 0) {
    throw new Error(
      `${program} ${args.join(' ')} failed (${result.errorCode ?? result.exitCode}): ${result.stderr}`
    );
  }
  return result.stdout.trim();
}

function readPropertiesFile(filePath) {
  return parseProperties(readFileSync(filePath, 'utf8'));
}

function octalMode(mode) {
  return (mode & 0o7777).toString(8).padStart(4, '0');
}

function accessResult(devicePath, flag) {
  try {
    accessSync(devicePath, flag);
    return { allowed: true, errorCode: null };
  } catch (error) {
    return { allowed: false, errorCode: error?.code ?? 'UNKNOWN' };
  }
}

function openProbe(devicePath, flags) {
  try {
    const descriptor = openSync(devicePath, flags);
    closeSync(descriptor);
    return { opened: true, errorCode: null };
  } catch (error) {
    return { opened: false, errorCode: error?.code ?? 'UNKNOWN' };
  }
}

function deviceSnapshot(devicePath, ueventText) {
  const stat = statSync(devicePath);
  return stableDeviceSnapshot({
    mode: octalMode(stat.mode),
    uid: stat.uid,
    gid: stat.gid,
    rdev: stat.rdev,
    ueventSha256: sha256(ueventText),
  });
}

function inspectOwners(devicePath) {
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

function processDetails(pid) {
  const result = command('ps', ['-p', String(pid), '-o', 'pid=,ppid=,user=,comm=,args=']);
  return {
    pid,
    observed: result.exitCode === 0,
    detail: result.stdout.trim(),
  };
}

function companionProcesses() {
  const result = command('ps', ['-eo', 'pid=,ppid=,user=,comm=,args=']);
  const lines = result.stdout
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(
      (line) =>
        line !== '' &&
        /\bcompanion\b/iu.test(line) &&
        !line.startsWith(`${process.pid} `) &&
        !line.includes('lab/h035/inventory.mjs')
    );
  return {
    observed: result.errorCode === null && result.exitCode === 0,
    exitCode: result.exitCode,
    errorCode: result.errorCode,
    matches: lines,
  };
}

function groupDatabase() {
  const groups = new Map();
  for (const line of readFileSync('/etc/group', 'utf8').split(/\r?\n/u)) {
    const fields = line.split(':');
    if (fields.length >= 3) groups.set(Number(fields[2]), fields[0]);
  }
  return groups;
}

function inspectPrincipal() {
  const names = groupDatabase();
  return {
    user: requiredCommand('id', ['-un']),
    uid: process.getuid(),
    primaryGroup: requiredCommand('id', ['-gn']),
    gid: process.getgid(),
    groups: process
      .getgroups()
      .map((gid) => ({ gid, name: names.get(gid) ?? null }))
      .sort((left, right) => left.gid - right.gid),
  };
}

function inspectHidrawNode(name) {
  const classPath = path.join('/sys/class/hidraw', name);
  const eventPath = path.join(classPath, 'device', 'uevent');
  const beforeUevent = readFileSync(eventPath, 'utf8');
  const properties = parseProperties(beforeUevent);
  if (!matchesTargetHid(properties)) return null;

  const devicePath = path.join('/dev', name);
  const before = deviceSnapshot(devicePath, beforeUevent);
  const ownersBefore = inspectOwners(devicePath);
  const udev = command('udevadm', ['info', '--query=property', `--name=${devicePath}`]);
  const access = {
    read: accessResult(devicePath, constants.R_OK),
    write: accessResult(devicePath, constants.W_OK),
  };
  const opens = {
    readOnlyNonblocking: openProbe(devicePath, constants.O_RDONLY | constants.O_NONBLOCK),
    readWriteNonblocking: openProbe(devicePath, constants.O_RDWR | constants.O_NONBLOCK),
  };
  const afterUevent = readFileSync(eventPath, 'utf8');
  const after = deviceSnapshot(devicePath, afterUevent);
  const ownersAfter = inspectOwners(devicePath);
  const ownerPids = [...new Set([...ownersBefore.pids, ...ownersAfter.pids])].sort(
    (left, right) => left - right
  );

  return {
    name,
    devicePath,
    sysfsDevicePath: realpathSync(path.join(classPath, 'device')),
    hid: {
      id: properties.HID_ID,
      name: properties.HID_NAME ?? null,
      physicalPath: properties.HID_PHYS ?? null,
      unique: properties.HID_UNIQ ?? null,
    },
    udev: {
      observed: udev.errorCode === null && udev.exitCode === 0,
      exitCode: udev.exitCode,
      errorCode: udev.errorCode,
      properties: parseProperties(udev.stdout),
      stderr: udev.stderr.trim(),
    },
    before,
    access,
    opens,
    owners: {
      before: ownersBefore,
      after: ownersAfter,
      processes: ownerPids.map(processDetails),
    },
    after,
    identityStable: canonicalJson(before) === canonicalJson(after),
    ioOperations: {
      bytesRead: 0,
      bytesWritten: 0,
      implementation: 'open-and-close-only',
    },
  };
}

function inspectHidraw() {
  let names;
  try {
    names = readdirSync('/sys/class/hidraw').filter((name) => /^hidraw[0-9]+$/u.test(name));
  } catch (error) {
    return { observed: false, errorCode: error?.code ?? 'UNKNOWN', matches: [] };
  }

  const matches = names
    .sort((left, right) => left.localeCompare(right))
    .map(inspectHidrawNode)
    .filter((value) => value !== null);
  return { observed: true, errorCode: null, matches };
}

function parseArgs(argv) {
  const result = { out: null };
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--out') {
      result.out = argv[index + 1] ?? null;
      index += 1;
    } else {
      throw new Error(`Unknown argument: ${argv[index]}`);
    }
  }
  return result;
}

function sourceHashes() {
  return Object.fromEntries(
    COLLECTOR_FILES.map((relativePath) => [
      relativePath,
      sha256(readFileSync(path.join(REPOSITORY_ROOT, relativePath))),
    ])
  );
}

const args = parseArgs(process.argv.slice(2));
const lsusb = command('lsusb', []);
const lsusbMatches = lsusb.stdout
  .split(/\r?\n/u)
  .map((line) => line.trim())
  .filter((line) => line.toLowerCase().includes(`${TARGET_USB.vendorId}:${TARGET_USB.productId}`));
const hidraw = inspectHidraw();
const evidence = {
  schemaVersion: 'overlaykit-h035-host-inventory/v1',
  hypothesis: 'H-035',
  collectedAt: new Date().toISOString(),
  collector: {
    repository: requiredCommand('git', ['config', '--get', 'remote.origin.url']),
    commit: requiredCommand('git', ['rev-parse', 'HEAD']),
    workingTreeClean: requiredCommand('git', ['status', '--porcelain']) === '',
    node: process.version,
    sourceSha256: sourceHashes(),
    governanceManifestContentHash: JSON.parse(
      readFileSync(path.join(REPOSITORY_ROOT, '.overlaykit/governance/manifest.json'), 'utf8')
    ).contentHash,
  },
  host: {
    osRelease: readPropertiesFile('/etc/os-release'),
    kernel: os.release(),
    architecture: os.arch(),
    hostname: os.hostname(),
    principal: inspectPrincipal(),
  },
  usb: {
    target: TARGET_USB,
    observed: lsusb.errorCode === null && lsusb.exitCode === 0,
    exitCode: lsusb.exitCode,
    errorCode: lsusb.errorCode,
    matches: lsusbMatches,
    stderr: lsusb.stderr.trim(),
  },
  hidraw,
  companionProcesses: companionProcesses(),
  claimBoundary: CLAIM_BOUNDARY,
};
const result = { ...evidence, evidenceSha256: sha256Canonical(evidence) };
const serialized = `${JSON.stringify(result, null, 2)}\n`;

if (args.out !== null) {
  const outputPath = path.resolve(args.out);
  mkdirSync(path.dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, serialized, { encoding: 'utf8', mode: 0o600 });
  process.stdout.write(
    `${JSON.stringify({
      outputPath,
      evidenceSha256: result.evidenceSha256,
      usbMatches: result.usb.matches.length,
      hidrawMatches: result.hidraw.matches.length,
    })}\n`
  );
} else {
  process.stdout.write(serialized);
}

const supported =
  result.usb.observed &&
  result.usb.matches.length > 0 &&
  result.hidraw.observed &&
  result.hidraw.matches.length > 0 &&
  result.hidraw.matches.every(
    (node) =>
      node.identityStable &&
      node.access.read.allowed &&
      node.access.write.allowed &&
      node.opens.readOnlyNonblocking.opened &&
      node.opens.readWriteNonblocking.opened &&
      node.owners.before.observed &&
      node.owners.after.observed
  );
if (!supported) process.exitCode = 2;
