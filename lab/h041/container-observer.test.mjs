import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  decodeLinuxDeviceNumber,
  descriptorIsInScope,
  isSurfaceThreadCmdline,
  parseCgroup,
  parseCmdline,
  parseCompatibilityLinkTarget,
  parseNamespace,
  parseObservationEnvironment,
  parseProcStat,
  parseProcStatus,
  parseUnsignedInteger,
  statIdentity,
} from './container-observer.mjs';

function encodeLinuxDeviceNumber(major, minor) {
  const majorValue = BigInt(major);
  const minorValue = BigInt(minor);
  return (
    ((majorValue & 0xfffn) << 8n) |
    (minorValue & 0xffn) |
    ((majorValue & ~0xfffn) << 32n) |
    ((minorValue & ~0xffn) << 12n)
  );
}

function statFixture({
  rdev = encodeLinuxDeviceNumber(241, 0),
  character = true,
  symlink = false,
} = {}) {
  return {
    dev: 7n,
    ino: 1417n,
    ctimeNs: 1_785_020_102_949_329_753n,
    mode: character ? 0o20660n : symlink ? 0o120777n : 0o100644n,
    uid: 0n,
    gid: 1002n,
    rdev,
    isCharacterDevice: () => character,
    isSymbolicLink: () => symlink,
  };
}

test('validates the exact bounded H-041 paths and target device number', () => {
  assert.deepEqual(
    parseObservationEnvironment({
      H041_DYNAMIC_PATH: '/host-dev/hidraw12',
      H041_COMPAT_PATH: '/dev/hidraw12',
      H041_DEVICE_MAJOR: '241',
      H041_DEVICE_MINOR: '0',
    }),
    {
      dynamicPath: '/host-dev/hidraw12',
      compatPath: '/dev/hidraw12',
      target: { major: 241, minor: 0 },
    }
  );
  assert.throws(
    () =>
      parseObservationEnvironment({
        H041_DYNAMIC_PATH: '/host-dev/hidraw0',
        H041_COMPAT_PATH: '/dev/hidraw1',
        H041_DEVICE_MAJOR: '241',
        H041_DEVICE_MINOR: '0',
      }),
    /same hidraw index/u
  );
  assert.throws(
    () =>
      parseObservationEnvironment({
        H041_DYNAMIC_PATH: '/host-dev/../dev/hidraw0',
        H041_COMPAT_PATH: '/dev/hidraw0',
        H041_DEVICE_MAJOR: '241',
        H041_DEVICE_MINOR: '0',
      }),
    /must match/u
  );
  assert.throws(() => parseUnsignedInteger('1e3', 'value'), /unsigned decimal/u);
  assert.throws(() => parseUnsignedInteger('0', 'value', { positive: true }), /range/u);
  assert.equal(parseCompatibilityLinkTarget('/host-dev/hidraw12'), '/host-dev/hidraw12');
  assert.throws(() => parseCompatibilityLinkTarget('../host-dev/hidraw12'), /must match/u);
});

test('parses PID, PPID, and field 22 when a proc command contains parentheses', () => {
  const fields4Through21 = Array.from({ length: 18 }, (_, index) => String(index + 40));
  const parsed = parseProcStat(
    `93 (Surface Thread (MK.2)) S ${[
      '39',
      ...fields4Through21.slice(1),
      '1290730',
      'ignored-field-23',
    ].join(' ')}`
  );
  assert.deepEqual(parsed, {
    pid: 93,
    ppid: 39,
    startTicks: 1_290_730,
    command: 'Surface Thread (MK.2)',
    state: 'S',
  });
  assert.throws(() => parseProcStat('93 (SurfaceThread) S 1 2 3'), /field 22/u);
  assert.throws(
    () =>
      parseProcStat(`93 (SurfaceThread) S ${[...fields4Through21, '9007199254740992'].join(' ')}`),
    /supported integer range/u
  );
});

test('parses exact UID, GID, supplementary groups, cgroup, and namespaces', () => {
  const status = [
    'Name:\tnode',
    'Uid:\t1000\t1000\t1000\t1000',
    'Gid:\t1000\t1000\t1000\t1000',
    'Groups:\t1000 1002',
  ].join('\n');
  assert.deepEqual(parseProcStatus(status), {
    uid: 1000,
    gid: 1000,
    groups: [1000, 1002],
  });
  assert.deepEqual(
    parseProcStatus(['Uid:\t0\t0\t0\t0', 'Gid:\t0\t0\t0\t0', 'Groups:'].join('\n')),
    { uid: 0, gid: 0, groups: [] }
  );
  assert.equal(parseCgroup('0::/docker/h041\n'), '0::/docker/h041');
  assert.equal(parseNamespace('pid:[4026533001]', 'pid'), 'pid:[4026533001]');
  assert.equal(parseNamespace('mnt:[4026533002]', 'mnt'), 'mnt:[4026533002]');
  assert.throws(
    () => parseProcStatus(['Uid:\t1000\t1000\t1000\t1000', 'Groups:\t1000 1002'].join('\n')),
    /Gid/u
  );
  assert.throws(() => parseCgroup('not-a-cgroup'), /malformed/u);
  assert.throws(() => parseNamespace('user:[4026533001]', 'pid'), /unexpected prefix/u);
});

test('parses NUL-delimited cmdlines and selects only an exact SurfaceThread basename', () => {
  const cmdline = parseCmdline(
    Buffer.from(
      '/app/node-runtimes/node22/bin/node\u0000--enable-source-maps\u0000/app/SurfaceThread.js\u0000'
    )
  );
  assert.deepEqual(cmdline, [
    '/app/node-runtimes/node22/bin/node',
    '--enable-source-maps',
    '/app/SurfaceThread.js',
  ]);
  assert.equal(isSurfaceThreadCmdline(cmdline), true);
  assert.equal(isSurfaceThreadCmdline(['/app/NotSurfaceThread.js']), false);
  assert.equal(isSurfaceThreadCmdline(['--label=SurfaceThread.js']), false);
  assert.deepEqual(parseCmdline(Buffer.alloc(0)), []);
});

test('decodes and normalizes Linux character-device metadata without device I/O', () => {
  const encoded = encodeLinuxDeviceNumber(0x1234, 0x56789);
  assert.deepEqual(decodeLinuxDeviceNumber(encoded), {
    major: 0x1234,
    minor: 0x56789,
  });
  assert.deepEqual(statIdentity(statFixture()), {
    stDev: '7',
    inode: '1417',
    ctimeNs: '1785020102949329753',
    mode: '0660',
    uid: 0,
    gid: 1002,
    rdev: '61696',
    rdevHex: 'f1:0',
    major: 241,
    minor: 0,
    isCharacterDevice: true,
    isSymbolicLink: false,
  });
});

test('keeps only hidraw or target-major character descriptors', () => {
  const target = statIdentity(statFixture());
  const otherCharacter = statIdentity(statFixture({ rdev: encodeLinuxDeviceNumber(1, 3) }));
  const regular = statIdentity(statFixture({ character: false }));
  assert.equal(descriptorIsInScope('/dev/hidraw0', target, 241), true);
  assert.equal(descriptorIsInScope('/host-dev/hidraw0 (deleted)', target, 241), true);
  assert.equal(descriptorIsInScope('/unexpected/device', target, 241), true);
  assert.equal(descriptorIsInScope('/dev/null', otherCharacter, 241), false);
  assert.equal(descriptorIsInScope('/dev/hidraw0', regular, 241), false);
  assert.equal(descriptorIsInScope('/dev/hidraw0', target, 0), false);
});
