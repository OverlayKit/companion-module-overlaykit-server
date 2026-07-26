import {
  existsSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  realpathSync,
  statSync,
} from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  TARGET_USB,
  classifyFuserResult,
  matchesTargetHid,
  parseProperties,
} from '../h035/inventory-lib.mjs';
import { parseProcStartTicks, sha256 } from './reconnect-lib.mjs';

function syncCommand(program, args) {
  const result = spawnSync(program, args, {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  return {
    exitCode: result.status,
    signal: result.signal,
    errorCode: result.error?.code ?? null,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

function readOptional(filePath) {
  try {
    return { kind: 'value', value: readFileSync(filePath, 'utf8').trim() };
  } catch (error) {
    if (error?.code === 'ENOENT') return { kind: 'missing', code: 'ENOENT' };
    return { kind: 'error', code: error?.code ?? 'UNKNOWN' };
  }
}

export function currentMountNamespace() {
  return readlinkSync('/proc/self/ns/mnt');
}

export function decodeLinuxDeviceNumber(rdevValue) {
  const rdev = BigInt(rdevValue);
  return {
    major: Number(((rdev >> 8n) & 0xfffn) | ((rdev >> 32n) & 0xfffff000n)),
    minor: Number((rdev & 0xffn) | ((rdev >> 12n) & 0xffffff00n)),
  };
}

function octalMode(value) {
  return (BigInt(value) & 0o7777n).toString(8).padStart(4, '0');
}

function statReceipt(devicePath) {
  try {
    const observed = statSync(devicePath, { bigint: true });
    const { major, minor } = decodeLinuxDeviceNumber(observed.rdev);
    return {
      kind: 'value',
      value: {
        stDev: observed.dev.toString(),
        inode: observed.ino.toString(),
        ctimeNs: observed.ctimeNs.toString(),
        mode: octalMode(observed.mode),
        uid: Number(observed.uid),
        gid: Number(observed.gid),
        rdev: observed.rdev.toString(),
        major,
        minor,
        rdevHex: `${major.toString(16)}:${minor.toString(16)}`,
        isCharacterDevice: observed.isCharacterDevice(),
      },
    };
  } catch (error) {
    if (error?.code === 'ENOENT') return { kind: 'missing', code: 'ENOENT' };
    return { kind: 'error', code: error?.code ?? 'UNKNOWN' };
  }
}

function processReceipt(pid) {
  const stat = readOptional(`/proc/${pid}/stat`);
  const status = readOptional(`/proc/${pid}/status`);
  const commandLine = readOptional(`/proc/${pid}/cmdline`);
  const cgroup = readOptional(`/proc/${pid}/cgroup`);
  return {
    pid,
    startTicks: stat.kind === 'value' ? parseProcStartTicks(stat.value) : null,
    statusSha256: status.kind === 'value' ? sha256(status.value) : null,
    commandLine:
      commandLine.kind === 'value' ? commandLine.value.replaceAll('\u0000', ' ').trim() : null,
    cgroup: cgroup.kind === 'value' ? cgroup.value : null,
  };
}

export function ownerObservation(devicePath) {
  if (!existsSync(devicePath)) {
    return {
      applicable: false,
      observed: false,
      usageError: false,
      pids: [],
      exitCode: null,
      errorCode: 'ENOENT',
      stdout: '',
      stderr: '',
      processes: [],
    };
  }
  const result = syncCommand('fuser', ['-v', devicePath]);
  const classification = classifyFuserResult(result);
  return {
    applicable: true,
    observed: classification.observed,
    usageError: classification.usageError,
    pids: classification.pids,
    exitCode: result.exitCode,
    errorCode: result.errorCode,
    stdout: result.stdout.trim(),
    stderr: result.stderr.trim(),
    processes: classification.pids.map(processReceipt),
  };
}

function usbIdentityAt(directory) {
  const vendor = readOptional(path.join(directory, 'idVendor'));
  const product = readOptional(path.join(directory, 'idProduct'));
  if (vendor.kind !== 'value' || product.kind !== 'value') return null;
  if (
    vendor.value.toLowerCase() !== TARGET_USB.vendorId ||
    product.value.toLowerCase() !== TARGET_USB.productId
  ) {
    return null;
  }
  const property = (name) => readOptional(path.join(directory, name));
  const value = (name) => {
    const result = property(name);
    return result.kind === 'value' ? result.value : null;
  };
  const uevent = property('uevent');
  return {
    sysfsPath: realpathSync(directory),
    vendorId: vendor.value.toLowerCase(),
    productId: product.value.toLowerCase(),
    serial: value('serial'),
    product: value('product'),
    manufacturer: value('manufacturer'),
    busNumber: value('busnum'),
    deviceNumber: value('devnum'),
    devicePath: value('devpath'),
    dev: value('dev'),
    ueventSha256: uevent.kind === 'value' ? sha256(uevent.value) : null,
  };
}

function scanUsb(expectedSerial, errors) {
  let entries;
  try {
    entries = readdirSync('/sys/bus/usb/devices');
  } catch (error) {
    errors.push({ layer: 'usb-sysfs', code: error?.code ?? 'UNKNOWN' });
    return [];
  }
  return entries
    .sort((left, right) => left.localeCompare(right))
    .flatMap((entry) => {
      try {
        const identity = usbIdentityAt(path.join('/sys/bus/usb/devices', entry));
        return identity === null
          ? []
          : [{ ...identity, serialMatches: identity.serial === expectedSerial }];
      } catch (error) {
        errors.push({
          layer: 'usb-sysfs-entry',
          entry,
          code: error?.code ?? 'UNKNOWN',
        });
        return [];
      }
    });
}

function usbAncestor(hidDevicePath) {
  let cursor = hidDevicePath;
  while (cursor !== '/' && cursor.startsWith('/sys/')) {
    const identity = usbIdentityAt(cursor);
    if (identity !== null) return identity;
    const parent = path.dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  return null;
}

function hidrawReceipt(name, expectedSerial, includeOwners, errors) {
  const classPath = path.join('/sys/class/hidraw', name);
  try {
    const hidDevicePath = realpathSync(path.join(classPath, 'device'));
    const hidUeventText = readFileSync(path.join(classPath, 'device', 'uevent'), 'utf8');
    const hid = parseProperties(hidUeventText);
    if (!matchesTargetHid(hid)) return null;
    const classUeventText = readFileSync(path.join(classPath, 'uevent'), 'utf8');
    const classProperties = parseProperties(classUeventText);
    const devicePath = path.join('/dev', classProperties.DEVNAME ?? name);
    const before = statReceipt(devicePath);
    const owner = includeOwners ? ownerObservation(devicePath) : null;
    const after = statReceipt(devicePath);
    const ancestor = usbAncestor(hidDevicePath);
    const udev = syncCommand('udevadm', ['info', '--query=property', `--path=${classPath}`]);
    const expectedMajor = Number(classProperties.MAJOR);
    const expectedMinor = Number(classProperties.MINOR);
    const stable =
      before.kind === 'value' &&
      after.kind === 'value' &&
      JSON.stringify(before.value) === JSON.stringify(after.value);
    const nodeMatchesClass =
      stable &&
      before.value.isCharacterDevice &&
      before.value.major === expectedMajor &&
      before.value.minor === expectedMinor;
    return {
      name,
      classPath,
      hidDevicePath,
      devicePath,
      serialMatches: hid.HID_UNIQ === expectedSerial,
      hid: {
        id: hid.HID_ID ?? null,
        unique: hid.HID_UNIQ ?? null,
        name: hid.HID_NAME ?? null,
        physicalPath: hid.HID_PHYS ?? null,
        ueventSha256: sha256(hidUeventText),
      },
      classDevice: {
        devName: classProperties.DEVNAME ?? null,
        major: expectedMajor,
        minor: expectedMinor,
        ueventSha256: sha256(classUeventText),
      },
      usbAncestor: ancestor,
      before,
      owner,
      after,
      nodeStable: stable,
      nodeMatchesClass,
      stat: stable ? before.value : null,
      udev: {
        observed: udev.errorCode === null && udev.exitCode === 0,
        exitCode: udev.exitCode,
        errorCode: udev.errorCode,
        properties: parseProperties(udev.stdout),
        stderr: udev.stderr.trim(),
      },
    };
  } catch (error) {
    errors.push({ layer: 'hidraw', name, code: error?.code ?? 'UNKNOWN' });
    return null;
  }
}

function scanHidraw(expectedSerial, includeOwners, errors) {
  let entries;
  try {
    entries = readdirSync('/sys/class/hidraw').filter((entry) => /^hidraw[0-9]+$/u.test(entry));
  } catch (error) {
    errors.push({ layer: 'hidraw-class', code: error?.code ?? 'UNKNOWN' });
    return [];
  }
  return entries
    .sort((left, right) => Number(left.slice(6)) - Number(right.slice(6)))
    .map((entry) => hidrawReceipt(entry, expectedSerial, includeOwners, errors))
    .filter((entry) => entry !== null);
}

function priorPathState(previousDevicePath) {
  if (!previousDevicePath) return { path: null, stat: { kind: 'missing', code: 'UNSET' } };
  return { path: previousDevicePath, stat: statReceipt(previousDevicePath) };
}

export function classifyHostSnapshot(snapshot) {
  const exactUsb = snapshot.usb.filter((entry) => entry.serialMatches);
  const exactHidraw = snapshot.hidraw.filter((entry) => entry.serialMatches);
  if (snapshot.errors.length > 0 || !snapshot.lsusb.observed) return 'observation-error';
  if (exactUsb.length > 1 || exactHidraw.length > 1) return 'ambiguous';
  if (
    exactUsb.length === 1 &&
    exactHidraw.length === 1 &&
    exactHidraw[0].usbAncestor?.serial === snapshot.expectedSerial &&
    exactHidraw[0].nodeStable &&
    exactHidraw[0].nodeMatchesClass
  ) {
    return 'present';
  }
  if (
    snapshot.lsusb.matches.length === 0 &&
    exactUsb.length === 0 &&
    exactHidraw.length === 0 &&
    snapshot.usb.length === 0 &&
    snapshot.hidraw.length === 0 &&
    snapshot.priorPath.stat.kind === 'missing'
  ) {
    return 'absent';
  }
  return 'transitional';
}

export function captureHostSnapshot(
  expectedSerial,
  { includeOwners = false, previousDevicePath = null } = {}
) {
  const errors = [];
  const lsusbResult = syncCommand('lsusb', []);
  const snapshot = {
    capturedAt: new Date().toISOString(),
    monotonicNs: process.hrtime.bigint().toString(),
    expectedSerial,
    scope: {
      mountNamespace: currentMountNamespace(),
      bootId: readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(),
    },
    lsusb: {
      observed: lsusbResult.errorCode === null && lsusbResult.exitCode === 0,
      exitCode: lsusbResult.exitCode,
      errorCode: lsusbResult.errorCode,
      matches: lsusbResult.stdout
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) =>
          line.toLowerCase().includes(`${TARGET_USB.vendorId}:${TARGET_USB.productId}`)
        ),
      stderr: lsusbResult.stderr.trim(),
    },
    usb: scanUsb(expectedSerial, errors),
    hidraw: scanHidraw(expectedSerial, includeOwners, errors),
    priorPath: priorPathState(previousDevicePath),
    errors,
  };
  return { ...snapshot, state: classifyHostSnapshot(snapshot) };
}

function compactSnapshot(snapshot) {
  return {
    capturedAt: snapshot.capturedAt,
    monotonicNs: snapshot.monotonicNs,
    state: snapshot.state,
    usb: snapshot.usb.map((entry) => ({
      serial: entry.serial,
      busNumber: entry.busNumber,
      deviceNumber: entry.deviceNumber,
      sysfsPath: entry.sysfsPath,
    })),
    hidraw: snapshot.hidraw.map((entry) => ({
      serial: entry.hid.unique,
      devicePath: entry.devicePath,
      hidDevicePath: entry.hidDevicePath,
      rdevHex: entry.stat?.rdevHex ?? null,
      inode: entry.stat?.inode ?? null,
    })),
    errors: snapshot.errors,
  };
}

export async function waitForStableHostState(
  expectedState,
  expectedSerial,
  { timeoutMs, pollMs = 100, consecutive = 3, previousDevicePath = null, timeline = [] }
) {
  const started = Date.now();
  let stableCount = 0;
  let last = null;
  while (Date.now() - started < timeoutMs) {
    last = captureHostSnapshot(expectedSerial, { previousDevicePath });
    timeline.push({ stage: expectedState, ...compactSnapshot(last) });
    stableCount = last.state === expectedState ? stableCount + 1 : 0;
    if (stableCount >= consecutive) {
      const full = captureHostSnapshot(expectedSerial, {
        includeOwners: expectedState === 'present',
        previousDevicePath,
      });
      timeline.push({ stage: `${expectedState}-full`, ...compactSnapshot(full) });
      if (full.state === expectedState) return { snapshot: full, timeline };
      stableCount = 0;
    }
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  throw new Error(
    `Host did not reach stable ${expectedState} within ${timeoutMs}ms; last state: ${last?.state ?? 'none'}`
  );
}
