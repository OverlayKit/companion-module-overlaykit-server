import { readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import path from 'node:path';

const LIVE_FILESYSTEM = Object.freeze({
  readdirSync,
  readFileSync,
  realpathSync,
  statSync,
});

const HIDRAW_NAME = /^hidraw(0|[1-9][0-9]*)$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const USB_ID = /^[0-9a-f]{1,8}$/iu;

export const TARGET_MK2 = Object.freeze({
  vendorId: '0fd9',
  productId: '0080',
});

export class HostInventorySelectionError extends Error {
  constructor(code, details = {}) {
    super(code);
    this.name = 'HostInventorySelectionError';
    this.code = code;
    this.details = details;
  }
}

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function normalizeUsbId(value) {
  if (typeof value !== 'string' || !USB_ID.test(value)) return null;
  const parsed = BigInt(`0x${value}`);
  if (parsed > 0xffffn) return null;
  return parsed.toString(16).padStart(4, '0');
}

function normalizeDecimal(value, { positive = false } = {}) {
  if (typeof value !== 'string' || !DECIMAL.test(value)) return null;
  const parsed = BigInt(value);
  if (positive ? parsed <= 0n : parsed < 0n) return null;
  return parsed.toString();
}

function errorCode(error, fallback = 'UNKNOWN') {
  return typeof error?.code === 'string' && error.code !== '' ? error.code : fallback;
}

function observationError(stage, filePath, error, fallback) {
  return {
    stage,
    path: filePath,
    code: errorCode(error, fallback),
  };
}

export function parseProperties(text) {
  if (typeof text !== 'string') return null;
  const properties = {};
  for (const line of text.split(/\r?\n/u)) {
    const separator = line.indexOf('=');
    if (separator <= 0) continue;
    const key = line.slice(0, separator);
    if (Object.hasOwn(properties, key)) return null;
    properties[key] = line.slice(separator + 1);
  }
  return properties;
}

export function parseHidId(value) {
  const match =
    typeof value === 'string'
      ? /^([0-9a-f]{1,8}):([0-9a-f]{1,8}):([0-9a-f]{1,8})$/iu.exec(value)
      : null;
  if (match === null) return null;
  const bus = normalizeUsbId(match[1]);
  const vendorId = normalizeUsbId(match[2]);
  const productId = normalizeUsbId(match[3]);
  return bus === null || vendorId === null || productId === null
    ? null
    : { bus, vendorId, productId };
}

export function parseHidUevent(text) {
  const properties = parseProperties(text);
  if (properties === null) return null;
  const identity = parseHidId(properties.HID_ID);
  if (identity === null) return null;
  return {
    id: properties.HID_ID,
    ...identity,
    unique: properties.HID_UNIQ || null,
    name: properties.HID_NAME || null,
    physicalPath: properties.HID_PHYS || null,
  };
}

export function parseClassDeviceNumber(text) {
  const match = typeof text === 'string' ? /^([0-9]+):([0-9]+)$/u.exec(text.trim()) : null;
  if (match === null) return null;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  if (!Number.isSafeInteger(major) || major < 0 || !Number.isSafeInteger(minor) || minor < 0) {
    return null;
  }
  return { major, minor };
}

export function decodeLinuxDeviceNumber(value) {
  const rdev = BigInt(value);
  return {
    major: Number(((rdev >> 8n) & 0xfffn) | ((rdev >> 32n) & 0xfffff000n)),
    minor: Number((rdev & 0xffn) | ((rdev >> 12n) & 0xffffff00n)),
  };
}

function readText(filesystem, filePath) {
  const value = filesystem.readFileSync(filePath, 'utf8');
  if (typeof value !== 'string') {
    const error = new TypeError('filesystem read did not return text');
    error.code = 'EINVAL';
    throw error;
  }
  return value;
}

function readOptionalText(filesystem, filePath) {
  try {
    return { kind: 'value', value: readText(filesystem, filePath).trim() };
  } catch (error) {
    if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') {
      return { kind: 'missing' };
    }
    throw error;
  }
}

function optionalUsbProperty(filesystem, directory, name) {
  const receipt = readOptionalText(filesystem, path.join(directory, name));
  return receipt.kind === 'value' && receipt.value !== '' ? receipt.value : null;
}

function resolveUsbAncestor(filesystem, hidDevicePath) {
  let cursor = hidDevicePath;
  while (path.isAbsolute(cursor)) {
    const vendorPath = path.join(cursor, 'idVendor');
    const productPath = path.join(cursor, 'idProduct');
    const vendor = readOptionalText(filesystem, vendorPath);
    const product = readOptionalText(filesystem, productPath);

    if (vendor.kind === 'value' || product.kind === 'value') {
      if (vendor.kind !== 'value' || product.kind !== 'value') {
        const error = new Error('partial USB identity');
        error.code = 'EINVAL';
        throw error;
      }
      const vendorId = normalizeUsbId(vendor.value);
      const productId = normalizeUsbId(product.value);
      if (vendorId === null || productId === null) {
        const error = new Error('invalid USB identity');
        error.code = 'EINVAL';
        throw error;
      }
      return {
        sysfsPath: cursor,
        vendorId,
        productId,
        serial: optionalUsbProperty(filesystem, cursor, 'serial'),
        manufacturer: optionalUsbProperty(filesystem, cursor, 'manufacturer'),
        product: optionalUsbProperty(filesystem, cursor, 'product'),
        busNumber: optionalUsbProperty(filesystem, cursor, 'busnum'),
        deviceNumber: optionalUsbProperty(filesystem, cursor, 'devnum'),
        devicePath: optionalUsbProperty(filesystem, cursor, 'devpath'),
      };
    }

    const parent = path.dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
  return null;
}

function statValue(observed) {
  if (typeof observed?.isCharacterDevice !== 'function') {
    const error = new TypeError('invalid stat result');
    error.code = 'EINVAL';
    throw error;
  }
  const rdev = BigInt(observed.rdev);
  const { major, minor } = decodeLinuxDeviceNumber(rdev);
  return {
    stDev: BigInt(observed.dev).toString(),
    inode: BigInt(observed.ino).toString(),
    ctimeNs: BigInt(observed.ctimeNs).toString(),
    mode: (BigInt(observed.mode) & 0o7777n).toString(8).padStart(4, '0'),
    uid: Number(observed.uid),
    gid: Number(observed.gid),
    rdev: rdev.toString(),
    major,
    minor,
    rdevHex: `${major.toString(16)}:${minor.toString(16)}`,
    isCharacterDevice: observed.isCharacterDevice(),
  };
}

function statReceipt(filesystem, devicePath) {
  try {
    return {
      kind: 'value',
      value: statValue(filesystem.statSync(devicePath, { bigint: true })),
    };
  } catch (error) {
    return {
      kind: error?.code === 'ENOENT' ? 'missing' : 'error',
      code: errorCode(error),
    };
  }
}

function sameStatValue(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function hidrawOrder(left, right) {
  const leftMatch = HIDRAW_NAME.exec(left);
  const rightMatch = HIDRAW_NAME.exec(right);
  if (leftMatch !== null && rightMatch !== null) {
    const leftIndex = BigInt(leftMatch[1]);
    const rightIndex = BigInt(rightMatch[1]);
    if (leftIndex < rightIndex) return -1;
    if (leftIndex > rightIndex) return 1;
    return 0;
  }
  if (leftMatch !== null) return -1;
  if (rightMatch !== null) return 1;
  return left.localeCompare(right);
}

function inspectHidrawEntry(filesystem, sysClassRoot, devRoot, rawName) {
  const name = typeof rawName === 'string' ? rawName : String(rawName);
  const validName = HIDRAW_NAME.test(name);
  const classPath = validName ? path.join(sysClassRoot, name) : null;
  const devicePath = validName ? path.join(devRoot, name) : null;
  const errors = [];
  const entry = {
    name,
    classPath,
    devicePath,
    hidDevicePath: null,
    hid: null,
    classDevice: null,
    usbAncestor: null,
    stat: {
      before: null,
      after: null,
      stable: false,
      value: null,
      matchesClass: false,
    },
    errors,
  };

  if (!validName) {
    errors.push({
      stage: 'entry-name',
      path: sysClassRoot,
      code: 'EINVAL',
    });
    return entry;
  }

  const hidDeviceLink = path.join(classPath, 'device');
  try {
    entry.hidDevicePath = filesystem.realpathSync(hidDeviceLink);
  } catch (error) {
    errors.push(observationError('hid-device-realpath', hidDeviceLink, error));
  }

  const hidUeventPath = path.join(hidDeviceLink, 'uevent');
  try {
    entry.hid = parseHidUevent(readText(filesystem, hidUeventPath));
    if (entry.hid === null) {
      errors.push({
        stage: 'hid-uevent-parse',
        path: hidUeventPath,
        code: 'EINVAL',
      });
    }
  } catch (error) {
    errors.push(observationError('hid-uevent-read', hidUeventPath, error));
  }

  const classDevPath = path.join(classPath, 'dev');
  try {
    entry.classDevice = parseClassDeviceNumber(readText(filesystem, classDevPath));
    if (entry.classDevice === null) {
      errors.push({
        stage: 'class-dev-parse',
        path: classDevPath,
        code: 'EINVAL',
      });
    }
  } catch (error) {
    errors.push(observationError('class-dev-read', classDevPath, error));
  }

  entry.stat.before = statReceipt(filesystem, devicePath);
  if (entry.stat.before.kind !== 'value') {
    errors.push({
      stage: 'device-stat-before',
      path: devicePath,
      code: entry.stat.before.code,
    });
  }

  if (entry.hidDevicePath !== null) {
    try {
      entry.usbAncestor = resolveUsbAncestor(filesystem, entry.hidDevicePath);
    } catch (error) {
      errors.push(observationError('usb-ancestor', entry.hidDevicePath, error));
    }
  }

  entry.stat.after = statReceipt(filesystem, devicePath);
  if (entry.stat.after.kind !== 'value') {
    errors.push({
      stage: 'device-stat-after',
      path: devicePath,
      code: entry.stat.after.code,
    });
  }

  entry.stat.stable =
    entry.stat.before.kind === 'value' &&
    entry.stat.after.kind === 'value' &&
    sameStatValue(entry.stat.before.value, entry.stat.after.value);
  entry.stat.value = entry.stat.stable ? entry.stat.before.value : null;
  entry.stat.matchesClass =
    entry.stat.stable &&
    entry.classDevice !== null &&
    entry.stat.value.major === entry.classDevice.major &&
    entry.stat.value.minor === entry.classDevice.minor;

  return entry;
}

function validateFilesystem(filesystem) {
  for (const method of ['readdirSync', 'readFileSync', 'realpathSync', 'statSync']) {
    if (typeof filesystem?.[method] !== 'function') {
      throw new TypeError(`filesystem.${method} must be a function`);
    }
  }
}

export function inventoryHostHidraw({
  filesystem = LIVE_FILESYSTEM,
  sysClassRoot = '/sys/class/hidraw',
  devRoot = '/dev',
} = {}) {
  validateFilesystem(filesystem);
  if (!path.isAbsolute(sysClassRoot) || !path.isAbsolute(devRoot)) {
    throw new TypeError('inventory roots must be absolute paths');
  }
  const names = filesystem.readdirSync(sysClassRoot);
  if (!Array.isArray(names)) throw new TypeError('hidraw class inventory must be an array');
  return [...names]
    .map((name) => (typeof name === 'string' ? name : String(name)))
    .sort(hidrawOrder)
    .map((name) => inspectHidrawEntry(filesystem, sysClassRoot, devRoot, name));
}

function normalizedStatValue(value) {
  if (!isPlainRecord(value)) return null;
  const expectedKeys = [
    'ctimeNs',
    'gid',
    'inode',
    'isCharacterDevice',
    'major',
    'minor',
    'mode',
    'rdev',
    'rdevHex',
    'stDev',
    'uid',
  ];
  if (
    JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(expectedKeys) ||
    normalizeDecimal(value.stDev) === null ||
    normalizeDecimal(value.inode, { positive: true }) === null ||
    normalizeDecimal(value.ctimeNs) === null ||
    normalizeDecimal(value.rdev) === null ||
    typeof value.mode !== 'string' ||
    !/^[0-7]{4}$/u.test(value.mode) ||
    !Number.isSafeInteger(value.uid) ||
    value.uid < 0 ||
    !Number.isSafeInteger(value.gid) ||
    value.gid < 0 ||
    !Number.isSafeInteger(value.major) ||
    value.major < 0 ||
    !Number.isSafeInteger(value.minor) ||
    value.minor < 0 ||
    typeof value.rdevHex !== 'string' ||
    typeof value.isCharacterDevice !== 'boolean'
  ) {
    return null;
  }
  const decoded = decodeLinuxDeviceNumber(value.rdev);
  if (
    decoded.major !== value.major ||
    decoded.minor !== value.minor ||
    value.rdevHex.toLowerCase() !== `${value.major.toString(16)}:${value.minor.toString(16)}`
  ) {
    return null;
  }
  return {
    stDev: normalizeDecimal(value.stDev),
    inode: normalizeDecimal(value.inode, { positive: true }),
    ctimeNs: normalizeDecimal(value.ctimeNs),
    mode: value.mode,
    uid: value.uid,
    gid: value.gid,
    rdev: normalizeDecimal(value.rdev),
    major: value.major,
    minor: value.minor,
    rdevHex: value.rdevHex.toLowerCase(),
    isCharacterDevice: value.isCharacterDevice,
  };
}

function normalizedStatReceipt(receipt) {
  if (!isPlainRecord(receipt) || receipt.kind !== 'value') return null;
  return normalizedStatValue(receipt.value);
}

function sameDeviceNumber(left, right) {
  return left.major === right.major && left.minor === right.minor;
}

function failSelection(code, details = {}) {
  throw new HostInventorySelectionError(code, details);
}

export function selectExactTargetHidraw(entries, { vendorId, productId, serial } = {}) {
  const normalizedVendor = normalizeUsbId(vendorId);
  const normalizedProduct = normalizeUsbId(productId);
  if (
    !Array.isArray(entries) ||
    normalizedVendor === null ||
    normalizedProduct === null ||
    typeof serial !== 'string' ||
    serial === '' ||
    serial.includes('\u0000')
  ) {
    failSelection('INVALID_SELECTION_INPUT');
  }

  for (const entry of entries) {
    if (!isPlainRecord(entry) || !Array.isArray(entry.errors)) {
      failSelection('INVALID_INVENTORY');
    }
  }
  const entriesWithErrors = entries
    .filter((entry) => entry.errors.length > 0)
    .map((entry) => entry.name);
  if (entriesWithErrors.length > 0) {
    failSelection('INVENTORY_INCOMPLETE', { entries: entriesWithErrors });
  }

  const candidates = entries.filter(
    (entry) =>
      entry.hid?.vendorId === normalizedVendor &&
      entry.hid?.productId === normalizedProduct &&
      entry.hid?.unique === serial &&
      entry.usbAncestor?.vendorId === normalizedVendor &&
      entry.usbAncestor?.productId === normalizedProduct &&
      entry.usbAncestor?.serial === serial
  );
  if (candidates.length === 0) {
    failSelection('TARGET_NOT_FOUND');
  }
  if (candidates.length !== 1) {
    failSelection('TARGET_AMBIGUOUS', {
      entries: candidates.map((entry) => entry.name),
    });
  }

  const candidate = candidates[0];
  const before = normalizedStatReceipt(candidate.stat?.before);
  const after = normalizedStatReceipt(candidate.stat?.after);
  if (before === null || after === null) {
    failSelection('TARGET_STAT_INVALID', { entry: candidate.name });
  }
  if (!sameStatValue(before, after)) {
    failSelection('TARGET_NODE_UNSTABLE', { entry: candidate.name });
  }
  if (!before.isCharacterDevice) {
    failSelection('TARGET_NODE_NOT_CHARACTER', { entry: candidate.name });
  }
  if (
    !isPlainRecord(candidate.classDevice) ||
    !Number.isSafeInteger(candidate.classDevice.major) ||
    candidate.classDevice.major < 0 ||
    !Number.isSafeInteger(candidate.classDevice.minor) ||
    candidate.classDevice.minor < 0 ||
    !sameDeviceNumber(before, candidate.classDevice)
  ) {
    failSelection('TARGET_NODE_CLASS_MISMATCH', { entry: candidate.name });
  }

  for (const entry of entries) {
    if (entry === candidate) continue;
    if (
      !isPlainRecord(entry.classDevice) ||
      !Number.isSafeInteger(entry.classDevice.major) ||
      entry.classDevice.major < 0 ||
      !Number.isSafeInteger(entry.classDevice.minor) ||
      entry.classDevice.minor < 0
    ) {
      failSelection('INVENTORY_INCOMPLETE', { entries: [entry.name] });
    }
    const otherBefore = normalizedStatReceipt(entry.stat?.before);
    const otherAfter = normalizedStatReceipt(entry.stat?.after);
    if (otherBefore === null || otherAfter === null) {
      failSelection('INVENTORY_INCOMPLETE', { entries: [entry.name] });
    }
    if (
      sameDeviceNumber(before, entry.classDevice) ||
      sameDeviceNumber(before, otherBefore) ||
      sameDeviceNumber(before, otherAfter)
    ) {
      failSelection('DEVICE_NUMBER_NOT_UNIQUE', {
        selected: candidate.name,
        conflicting: entry.name,
        major: before.major,
        minor: before.minor,
      });
    }
  }

  return candidate;
}
