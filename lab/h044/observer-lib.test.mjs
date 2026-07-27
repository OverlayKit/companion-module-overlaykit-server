import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';

import {
  OBSERVER_DOCKER_INSPECT_FORMAT,
  OBSERVER_DOCKER_PS_FORMAT,
  OBSERVER_DOCKER_UNIX_HOST,
  OBSERVER_DOCKER_VERSION_FORMAT,
  ObserverCommandError,
  ObserverFilesystemError,
  ObserverPolicyError,
  buildCapabilityAudit,
  captureDockerAdmission,
  captureGitAdmission,
  captureLsusbAdmission,
  captureObservationFrame,
  createCommandAuditor,
  createFilesystemAuditor,
  decodeLinuxDeviceNumber,
  filesystemReceiptResultExact,
  frameAuditBindingExact,
  isSurfaceThreadCmdline,
  parseCgroup,
  parseCmdline,
  parseDeviceNumber,
  parseDockerInspect,
  parseDockerLogs,
  parseDockerPs,
  parseDockerVersion,
  parseLsusb,
  parseNamespace,
  parseOsRelease,
  parseProcStat,
  parseProcStatus,
  statIdentity,
  validateObserverCommand,
} from './observer-lib.mjs';

const CONTAINER_ID = '78c013a0b101e9f4d93195e5f3b3e6184aa69019ba2b5f0ea472085f156d986c';
const IMAGE_ID = 'sha256:e7d24e3b0e32b0edb799f262493536cb1a47d307af4e6527551427e09266bf10';
const SERIAL = 'A00SA5492OQMLF';
const PROTECTED_MAIN = '6c329234caddf9e34126be04149f768673bdb8bf';
const HEAD = '9e2156e6fc222222222222222222222222222222';
const EMPTY_SHA256 = createHash('sha256').update('').digest('hex');

function clocks() {
  let wall = Date.parse('2026-07-26T16:20:34.000Z');
  let monotonic = 78_174_100_000_000n;
  return {
    wallNow() {
      const value = new Date(wall).toISOString();
      wall += 1;
      return value;
    },
    monotonicNowNs() {
      const value = monotonic;
      monotonic += 1_000_000n;
      return value;
    },
  };
}

function enoent(targetPath) {
  const error = new Error(`missing ${targetPath}`);
  error.code = 'ENOENT';
  return error;
}

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
  inode = 1480n,
} = {}) {
  return {
    dev: 7n,
    ino: inode,
    ctimeNs: 1_785_082_803_368_821_699n,
    mode: character ? 0o20660n : symlink ? 0o120777n : 0o100644n,
    uid: 0n,
    gid: 1002n,
    rdev,
    isCharacterDevice: () => character,
    isSymbolicLink: () => symlink,
  };
}

function procStat(pid, ppid, startTicks) {
  return `${pid} (node) S ${[
    String(ppid),
    ...Array.from({ length: 17 }, () => '0'),
    String(startTicks),
  ].join(' ')}\n`;
}

function procStatus(pid) {
  return [
    'Name:\tnode',
    'Uid:\t1000\t1000\t1000\t1000',
    'Gid:\t1000\t1000\t1000\t1000',
    'Groups:\t1000 1002',
    `NSpid:\t${pid}`,
    '',
  ].join('\n');
}

function filesystemFixture({ serial = SERIAL } = {}) {
  const hidPath = '/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0/0003:0FD9:0080.0016';
  const usbPath = '/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2';
  const procRoot = '/proc/1238461/root/proc';
  const files = new Map([
    [
      '/etc/os-release',
      'NAME=Fedora Linux\nID=fedora\nVERSION_ID=43\nPRETTY_NAME="Fedora Linux 43"\n',
    ],
    ['/proc/sys/kernel/random/boot_id', '11111111-2222-4333-8444-555555555555\n'],
    ['/proc/sys/kernel/hostname', 'linux-host\n'],
    [
      '/sys/class/hidraw/hidraw0/device/uevent',
      [
        'HID_ID=0003:00000FD9:00000080',
        `HID_UNIQ=${serial}`,
        'HID_NAME=Elgato Stream Deck MK.2',
        'HID_PHYS=usb-0000:00:14.0-2/input0',
        '',
      ].join('\n'),
    ],
    ['/sys/class/hidraw/hidraw0/dev', '241:0\n'],
    [`${usbPath}/idVendor`, '0fd9\n'],
    [`${usbPath}/idProduct`, '0080\n'],
    [`${usbPath}/serial`, `${serial}\n`],
    [`${usbPath}/manufacturer`, 'Elgato\n'],
    [`${usbPath}/product`, 'Stream Deck MK.2\n'],
    [`${usbPath}/busnum`, '1\n'],
    [`${usbPath}/devnum`, '18\n'],
    [`${usbPath}/devpath`, '2\n'],
    [`${usbPath}/dev`, '189:17\n'],
    [`${procRoot}/1/stat`, procStat(1, 0, 7_808_679)],
    [`${procRoot}/1/status`, procStatus(1)],
    [`${procRoot}/1/cmdline`, Buffer.from('./node-runtimes/main/bin/node\u0000./main.js\u0000')],
    [`${procRoot}/1/cgroup`, '0::/\n'],
    [`${procRoot}/73/stat`, procStat(73, 1, 7_808_716)],
    [`${procRoot}/73/status`, procStatus(73)],
    [
      `${procRoot}/73/cmdline`,
      Buffer.from(
        '/app/node-runtimes/node22/bin/node\u0000--enable-source-maps\u0000/app/SurfaceThread.js\u0000'
      ),
    ],
    [`${procRoot}/73/cgroup`, '0::/\n'],
    ['/proc/1238461/cgroup', `0::/system.slice/docker-${CONTAINER_ID}.scope\n`],
  ]);
  const directories = new Map([
    ['/sys/class/hidraw', ['hidraw0']],
    [procRoot, ['1', '73']],
    [`${procRoot}/73/fd`, []],
  ]);
  const links = new Map([
    [`${procRoot}/1/ns/pid`, 'pid:[4026533784]'],
    [`${procRoot}/1/ns/mnt`, 'mnt:[4026533781]'],
    [`${procRoot}/73/ns/pid`, 'pid:[4026533784]'],
    [`${procRoot}/73/ns/mnt`, 'mnt:[4026533781]'],
  ]);
  const realpaths = new Map([['/sys/class/hidraw/hidraw0/device', hidPath]]);
  const stats = new Map([['/dev/hidraw0', statFixture()]]);

  function lookup(map, targetPath) {
    if (!map.has(targetPath)) throw enoent(targetPath);
    return map.get(targetPath);
  }

  return {
    readFileSync(targetPath, encoding) {
      const value = lookup(files, targetPath);
      if (encoding === 'utf8' && Buffer.isBuffer(value)) return value.toString('utf8');
      return value;
    },
    readdirSync(targetPath) {
      return [...lookup(directories, targetPath)];
    },
    realpathSync(targetPath) {
      return lookup(realpaths, targetPath);
    },
    statSync(targetPath) {
      return lookup(stats, targetPath);
    },
    lstatSync(targetPath) {
      return lookup(stats, targetPath);
    },
    readlinkSync(targetPath) {
      return lookup(links, targetPath);
    },
  };
}

function dockerVersionOutput() {
  return JSON.stringify({
    Client: { Version: '28.3.3', ApiVersion: '1.51' },
    Server: { Version: '28.3.3', ApiVersion: '1.51' },
  });
}

function dockerPsOutput({ state = 'running', includeTarget = true } = {}) {
  if (!includeTarget) return '';
  return `${JSON.stringify({
    ID: CONTAINER_ID,
    State: state,
  })}\n`;
}

function dockerInspectOutput() {
  return JSON.stringify({
    Id: CONTAINER_ID,
    Image: IMAGE_ID,
    State: {
      Status: 'running',
      Running: true,
      Pid: 1_238_461,
      StartedAt: '2026-07-26T16:19:06.805378786Z',
    },
    RestartCount: 0,
    CgroupnsMode: 'private',
  });
}

function dockerArgs(command, ...args) {
  return ['--host', OBSERVER_DOCKER_UNIX_HOST, command, ...args];
}

function dockerSubcommand(args) {
  return args[0] === '--host' && args[1] === OBSERVER_DOCKER_UNIX_HOST ? args[2] : null;
}

function commandRunner({
  state = 'running',
  includeTarget = true,
  forbidInspect = false,
  lsusbOutput = 'Bus 001 Device 018: ID 0fd9:0080 Elgato Stream Deck MK.2\n',
  psOutput = null,
} = {}) {
  const calls = [];
  async function runner(executable, args, options) {
    calls.push({ executable, args: [...args], options: { ...options } });
    if (executable === 'git' && args[0] === 'rev-parse') {
      return { exitCode: 0, signal: null, stdout: `${HEAD}\n`, stderr: '' };
    }
    if (executable === 'git' && args[0] === 'merge-base') {
      return { exitCode: 0, signal: null, stdout: '', stderr: '' };
    }
    if (executable === 'git' && args[0] === 'remote') {
      return {
        exitCode: 0,
        signal: null,
        stdout: 'https://github.com/OverlayKit/companion-module-overlaykit-server.git\n',
        stderr: '',
      };
    }
    if (executable === 'lsusb') {
      return {
        exitCode: 0,
        signal: null,
        stdout: lsusbOutput,
        stderr: '',
      };
    }
    if (executable === 'docker' && dockerSubcommand(args) === 'version') {
      return { exitCode: 0, signal: null, stdout: dockerVersionOutput(), stderr: '' };
    }
    if (executable === 'docker' && dockerSubcommand(args) === 'ps') {
      return {
        exitCode: 0,
        signal: null,
        stdout: psOutput ?? dockerPsOutput({ state, includeTarget }),
        stderr: '',
      };
    }
    if (executable === 'docker' && dockerSubcommand(args) === 'inspect') {
      if (forbidInspect) throw new Error('inspect must not be invoked');
      return { exitCode: 0, signal: null, stdout: dockerInspectOutput(), stderr: '' };
    }
    if (executable === 'docker' && dockerSubcommand(args) === 'logs') {
      if (forbidInspect) throw new Error('logs must not be invoked');
      return {
        exitCode: 0,
        signal: null,
        stdout: [
          `2026-07-26T16:20:00.000000001Z Opening surface panel: streamdeck:${SERIAL}`,
          `2026-07-26T16:20:01.000000002Z Surface panel ready: streamdeck:${SERIAL}`,
          '',
        ].join('\n'),
        stderr: '',
      };
    }
    throw new Error(`unexpected command ${executable} ${args.join(' ')}`);
  }
  return { runner, calls };
}

function makeAuditors(options = {}) {
  const clock = clocks();
  const { filesystemOptions = {}, ...commandOptions } = options;
  const commands = commandRunner(commandOptions);
  return {
    commandAuditor: createCommandAuditor({
      runner: commands.runner,
      wallNow: clock.wallNow,
      monotonicNowNs: clock.monotonicNowNs,
    }),
    filesystemAuditor: createFilesystemAuditor({
      filesystem: filesystemFixture(filesystemOptions),
      wallNow: clock.wallNow,
      monotonicNowNs: clock.monotonicNowNs,
    }),
    frameClocks: clock,
    calls: commands.calls,
  };
}

function target() {
  return {
    serial: SERIAL,
    vendorId: '0fd9',
    productId: '0080',
    containerId: CONTAINER_ID,
    deviceMajor: 241,
    deviceMinor: 0,
  };
}

test('admits only the exact read-only command surface', () => {
  assert.equal(validateObserverCommand('git', ['rev-parse', 'HEAD']), 'gitRevParse');
  assert.equal(
    validateObserverCommand('git', ['merge-base', '--is-ancestor', PROTECTED_MAIN, 'HEAD']),
    'gitMergeBaseAncestor'
  );
  assert.equal(validateObserverCommand('lsusb', []), 'lsusb');
  assert.equal(
    validateObserverCommand('docker', [
      ...dockerArgs('ps'),
      '--all',
      '--no-trunc',
      '--filter',
      `id=${CONTAINER_ID}`,
      '--format',
      OBSERVER_DOCKER_PS_FORMAT,
    ]),
    'dockerPs'
  );
  assert.equal(
    validateObserverCommand('docker', [
      ...dockerArgs('version'),
      '--format',
      OBSERVER_DOCKER_VERSION_FORMAT,
    ]),
    'dockerVersion'
  );
  assert.equal(
    validateObserverCommand('docker', [
      ...dockerArgs('inspect'),
      '--format',
      OBSERVER_DOCKER_INSPECT_FORMAT,
      CONTAINER_ID,
    ]),
    'dockerInspect'
  );
  assert.throws(
    () => validateObserverCommand('docker', dockerArgs('exec', CONTAINER_ID, 'true')),
    ObserverPolicyError
  );
  assert.throws(
    () => validateObserverCommand('docker', dockerArgs('top', CONTAINER_ID)),
    ObserverPolicyError
  );
  assert.throws(
    () => validateObserverCommand('docker', ['version', '--format', '{{json .}}']),
    ObserverPolicyError
  );
  assert.throws(
    () =>
      validateObserverCommand('docker', ['ps', '--all', '--no-trunc', '--format', '{{json .}}']),
    ObserverPolicyError
  );
  assert.throws(
    () => validateObserverCommand('docker', dockerArgs('restart', CONTAINER_ID)),
    ObserverPolicyError
  );
  assert.throws(() => validateObserverCommand('nsenter', ['-t', '1']), ObserverPolicyError);
  assert.throws(() => validateObserverCommand('kill', ['1']), ObserverPolicyError);
  assert.throws(
    () =>
      validateObserverCommand(
        'docker',
        dockerArgs('inspect', '--format', '{{json .}}', CONTAINER_ID)
      ),
    ObserverPolicyError
  );
});

test('command receipts preserve exact outputs, hashes, timing, limits, and cardinality', async () => {
  const clock = clocks();
  const calls = [];
  const auditor = createCommandAuditor({
    runner: async (executable, args, options) => {
      calls.push({ executable, args, options });
      return {
        exitCode: 0,
        signal: null,
        stdout: 'one\n',
        stderr: 'warning\n',
      };
    },
    wallNow: clock.wallNow,
    monotonicNowNs: clock.monotonicNowNs,
    maxBufferBytes: 1024,
    timeoutMs: 500,
  });
  const observed = await auditor.invoke('lsusb', []);
  assert.equal(observed.receipt.stdout.text, 'one\n');
  assert.equal(observed.receipt.stdout.sha256, createHash('sha256').update('one\n').digest('hex'));
  assert.equal(observed.receipt.stderr.text, 'warning\n');
  assert.equal(observed.receipt.stdout.lineCount, 1);
  assert.deepEqual(observed.receipt.args, []);
  assert.deepEqual(observed.receipt.limits, { maxBufferBytes: 1024, timeoutMs: 500 });
  assert.deepEqual(observed.receipt.cardinality, { global: 1, kind: 1 });
  assert.deepEqual(calls[0].options, { maxBufferBytes: 1024, timeoutMs: 500 });
  await assert.rejects(() => auditor.invoke('lsusb', []), /CARDINALITY/u);
  assert.equal(auditor.snapshot().receipts.length, 1);
  assert.equal(auditor.snapshot().rejectedAttempts.length, 1);
});

test('command failures still leave an exact receipt', async () => {
  const clock = clocks();
  const auditor = createCommandAuditor({
    runner: async () => {
      const error = new Error('spawn failed');
      error.code = 'ENOENT';
      error.stdout = '';
      error.stderr = 'not found\n';
      throw error;
    },
    wallNow: clock.wallNow,
    monotonicNowNs: clock.monotonicNowNs,
  });
  await assert.rejects(
    () => auditor.invoke('lsusb', []),
    (error) =>
      error instanceof ObserverCommandError &&
      error.receipt.errorCode === 'ENOENT' &&
      error.receipt.stderr.text === 'not found\n'
  );
  assert.equal(auditor.snapshot().receipts.length, 1);
});

test('filesystem wrapper records metadata without permitting hidraw content access', () => {
  const clock = clocks();
  const fixture = filesystemFixture();
  const auditor = createFilesystemAuditor({
    filesystem: fixture,
    wallNow: clock.wallNow,
    monotonicNowNs: clock.monotonicNowNs,
  });
  assert.match(auditor.filesystem.readFileSync('/etc/os-release'), /Fedora/u);
  assert.deepEqual(auditor.filesystem.readdirSync('/sys/class/hidraw'), ['hidraw0']);
  assert.equal(
    auditor.filesystem.realpathSync('/sys/class/hidraw/hidraw0/device'),
    '/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0/0003:0FD9:0080.0016'
  );
  assert.equal(auditor.filesystem.statSync('/dev/hidraw0').isCharacterDevice(), true);
  assert.throws(() => auditor.filesystem.readFileSync('/dev/hidraw0'), ObserverPolicyError);
  assert.throws(() => auditor.filesystem.readFileSync('/tmp/not-allowed'), ObserverPolicyError);
  assert.throws(
    () => auditor.filesystem.readFileSync('/sys/class/hidraw/missing'),
    ObserverFilesystemError
  );
  const snapshot = auditor.snapshot();
  assert.deepEqual(
    snapshot.receipts.map((receipt) => receipt.disposition),
    ['observed', 'observed', 'observed', 'observed', 'missing']
  );
  assert.equal(snapshot.receipts[0].result.sha256.length, 64);
  assert.equal(snapshot.receipts[0].result.encoding, 'utf8');
  assert.match(snapshot.receipts[0].result.text, /Fedora/u);
  assert.equal(snapshot.receipts[0].result.bytes.encoding, 'base64');
  assert.equal(
    Buffer.from(snapshot.receipts[0].result.bytes.base64, 'base64').toString('utf8'),
    snapshot.receipts[0].result.text
  );
  assert.deepEqual(snapshot.receipts[1].result.entries, ['hidraw0']);
  assert.equal(
    snapshot.receipts[2].result.value,
    '/sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0/0003:0FD9:0080.0016'
  );
  assert.equal(snapshot.receipts[3].result.metadata.major, 241);
  assert.equal(snapshot.receipts.every(filesystemReceiptResultExact), true);

  const textTamper = structuredClone(snapshot.receipts[0]);
  textTamper.result.text += 'tampered';
  assert.equal(filesystemReceiptResultExact(textTamper), false);
  const bytesTamper = structuredClone(snapshot.receipts[0]);
  bytesTamper.result.bytes.base64 = Buffer.from('different', 'utf8').toString('base64');
  assert.equal(filesystemReceiptResultExact(bytesTamper), false);
  const entriesTamper = structuredClone(snapshot.receipts[1]);
  entriesTamper.result.entries.push('hidraw1');
  assert.equal(filesystemReceiptResultExact(entriesTamper), false);
  const valueTamper = structuredClone(snapshot.receipts[2]);
  valueTamper.result.value += '-tampered';
  assert.equal(filesystemReceiptResultExact(valueTamper), false);
  const metadataTamper = structuredClone(snapshot.receipts[3]);
  metadataTamper.result.metadata.inode = '999';
  assert.equal(filesystemReceiptResultExact(metadataTamper), false);
  assert.equal(snapshot.rejectedAttempts.length, 2);
});

test('non-UTF-8 filesystem bytes remain exact base64 with no invented text', () => {
  const clock = clocks();
  const fixture = filesystemFixture();
  const filesystem = {
    ...fixture,
    readFileSync(targetPath, ...args) {
      if (targetPath === '/proc/h044-binary-fixture') return Buffer.from([0xff, 0x00, 0x80]);
      return fixture.readFileSync(targetPath, ...args);
    },
  };
  const auditor = createFilesystemAuditor({
    filesystem,
    wallNow: clock.wallNow,
    monotonicNowNs: clock.monotonicNowNs,
  });
  auditor.filesystem.readFileSync('/proc/h044-binary-fixture');
  const [receipt] = auditor.snapshot().receipts;
  assert.equal(receipt.result.encoding, 'base64');
  assert.equal(receipt.result.text, null);
  assert.equal(receipt.result.bytes.base64, '/wCA');
  assert.equal(receipt.result.byteLength, 3);
  assert.equal(filesystemReceiptResultExact(receipt), true);
});

test('pure parsers reject ambiguity and retain exact volatile identity fields', () => {
  assert.deepEqual(parseLsusb('Bus 001 Device 018: ID 0FD9:0080 Elgato Stream Deck MK.2\n'), [
    {
      busNumber: '1',
      deviceNumber: '18',
      vendorId: '0fd9',
      productId: '0080',
      description: 'Elgato Stream Deck MK.2',
      line: 'Bus 001 Device 018: ID 0FD9:0080 Elgato Stream Deck MK.2',
    },
  ]);
  assert.throws(
    () =>
      parseLsusb(
        'Bus 001 Device 018: ID 0fd9:0080 MK.2\nBus 001 Device 018: ID 0fd9:0080 duplicate\n'
      ),
    /duplicate/u
  );
  assert.deepEqual(parseDockerVersion(dockerVersionOutput()), {
    client: { version: '28.3.3', apiVersion: '1.51' },
    server: { version: '28.3.3', apiVersion: '1.51' },
  });
  const expandedVersion = JSON.parse(dockerVersionOutput());
  expandedVersion.Server.Platform = { Name: 'not admitted' };
  assert.throws(() => parseDockerVersion(JSON.stringify(expandedVersion)), /lacks/u);
  assert.equal(parseDockerPs(dockerPsOutput())[0].containerId, CONTAINER_ID);
  const expandedPs = JSON.parse(dockerPsOutput());
  expandedPs.Labels = 'not admitted';
  assert.throws(() => parseDockerPs(`${JSON.stringify(expandedPs)}\n`), /exact/u);
  assert.equal(parseDockerInspect(dockerInspectOutput()).hostPid, 1_238_461);
  const expandedInspect = JSON.parse(dockerInspectOutput());
  expandedInspect.State.Health = { Status: 'healthy', Log: [{ Output: 'not admitted' }] };
  assert.throws(() => parseDockerInspect(JSON.stringify(expandedInspect)), /incomplete/u);
  const logs = parseDockerLogs(
    [
      `2026-07-26T16:20:00.000000001Z Opening surface panel: streamdeck:${SERIAL} - Elgato Stream Deck MK.2`,
      `2026-07-26T16:20:00.500000001Z Opening surface panel: streamdeck:${SERIAL}suffix`,
      '',
    ].join('\n'),
    `2026-07-26T16:20:01.000000002Z Surface panel ready: streamdeck:${SERIAL}\n`,
    SERIAL
  );
  assert.equal(logs.openingCount, 1);
  assert.equal(logs.readyCount, 1);
  assert.notEqual(logs.relevantLinesSha256, EMPTY_SHA256);
  assert.deepEqual(parseOsRelease('ID=fedora\nVERSION_ID=43\nPRETTY_NAME="Fedora 43"\n'), {
    id: 'fedora',
    versionId: '43',
    prettyName: 'Fedora 43',
  });
  assert.equal(parseDeviceNumber('189:017'), '189:17');
  assert.equal(parseNamespace('pid:[4026533784]', 'pid'), 'pid:[4026533784]');
  assert.equal(parseCgroup('0::/\n'), '0::/');
});

test('proc and stat parsers preserve lineage, credentials, namespaces, and device identity', () => {
  assert.deepEqual(parseProcStat(procStat(73, 1, 7_808_716)), {
    pid: 73,
    ppid: 1,
    startTicks: 7_808_716,
    command: 'node',
    state: 'S',
  });
  assert.deepEqual(parseProcStatus(procStatus(73)), {
    uid: 1000,
    gid: 1000,
    groups: [1000, 1002],
    namespacePids: [73],
  });
  assert.deepEqual(parseCmdline(Buffer.from('/app/node\u0000/app/SurfaceThread.js\u0000')), [
    '/app/node',
    '/app/SurfaceThread.js',
  ]);
  assert.equal(isSurfaceThreadCmdline(['/app/node', '/app/SurfaceThread.js']), true);
  assert.equal(isSurfaceThreadCmdline(['/app/NotSurfaceThread.js']), false);
  const identity = statIdentity(statFixture());
  assert.equal(identity.major, 241);
  assert.equal(identity.minor, 0);
  assert.deepEqual(decodeLinuxDeviceNumber(encodeLinuxDeviceNumber(0x1234, 0x56789)), {
    major: 0x1234,
    minor: 0x56789,
  });
});

test('captures one complete running frame through injected read-only dependencies', async () => {
  const setup = makeAuditors();
  const lsusbAdmission = await captureLsusbAdmission(setup.commandAuditor);
  const dockerAdmission = await captureDockerAdmission(setup.commandAuditor);
  const frame = await captureObservationFrame({
    frameId: 'frame-1',
    commandAuditor: setup.commandAuditor,
    filesystemAuditor: setup.filesystemAuditor,
    lsusbAdmission,
    dockerAdmission,
    target: target(),
    logSince: '2026-07-26T16:19:06.805378786Z',
    wallNow: setup.frameClocks.wallNow,
    monotonicNowNs: setup.frameClocks.monotonicNowNs,
  });

  assert.equal(
    frame.complete,
    true,
    JSON.stringify({ errors: frame.errors, hidraw: frame.device.hidrawEntries })
  );
  assert.deepEqual(frame.errors, []);
  assert.equal(frame.device.usbEpochs.length, 1);
  assert.equal(frame.device.usbEpochs[0].usbDev, '189:17');
  assert.equal(frame.device.usbEpochs[0].stat.inode, '1480');
  assert.equal(frame.docker.lifecycle.containerId, CONTAINER_ID);
  assert.equal(frame.docker.lifecycle.pid1StartTicks, 7_808_679);
  assert.equal(frame.docker.lifecycle.hostCgroup.includes(CONTAINER_ID), true);
  assert.equal(frame.processes.pid1.pid, 1);
  assert.equal(frame.processes.surfaceWorkers.length, 1);
  assert.equal(frame.processes.surfaceWorkers[0].parentStartTicks, 7_808_679);
  assert.equal(frame.processes.surfaceWorkers[0].fileDescriptors.length, 0);
  assert.equal(frame.docker.markers.openingCount, 1);
  assert.equal(frame.docker.markers.readyCount, 1);
  assert.deepEqual(Object.keys(frame.observationCutoff), ['at', 'monotonicNs']);
  assert.equal(frame.docker.logWindow.until, frame.observationCutoff.at);
  assert.equal(Date.parse(frame.observationCutoff.at) <= Date.parse(frame.endedAt), true);
  assert.equal(BigInt(frame.observationCutoff.monotonicNs) <= BigInt(frame.endedMonotonicNs), true);
  assert.equal(frame.absence.exact, true);
  assert.equal(frame.nonEligible.exact, false);
  const commandSnapshot = setup.commandAuditor.snapshot();
  const filesystemSnapshot = setup.filesystemAuditor.snapshot();
  assert.deepEqual(frame.auditBinding.commandReceiptIndexes, [2, 3, 4]);
  assert.deepEqual(
    frame.auditBinding.filesystemReceiptIndexes,
    filesystemSnapshot.receipts.map((receipt) => receipt.index)
  );
  assert.equal(
    frameAuditBindingExact(frame, commandSnapshot.receipts, filesystemSnapshot.receipts),
    true
  );
  for (const index of frame.auditBinding.commandReceiptIndexes) {
    const receipt = commandSnapshot.receipts[index];
    assert.equal(Date.parse(receipt.startedAt) >= Date.parse(frame.startedAt), true);
    assert.equal(Date.parse(receipt.endedAt) <= Date.parse(frame.endedAt), true);
    assert.equal(BigInt(receipt.startedMonotonicNs) >= BigInt(frame.startedMonotonicNs), true);
    assert.equal(BigInt(receipt.endedMonotonicNs) <= BigInt(frame.endedMonotonicNs), true);
  }
  const logsReceipt = commandSnapshot.receipts[frame.auditBinding.commandReceiptIndexes.at(-1)];
  assert.equal(logsReceipt.kind, 'dockerLogs');
  assert.equal(Date.parse(logsReceipt.endedAt) > Date.parse(frame.observationCutoff.at), true);
  assert.equal(
    BigInt(logsReceipt.endedMonotonicNs) > BigInt(frame.observationCutoff.monotonicNs),
    true
  );
  const logsCall = setup.calls.find(
    (call) => call.executable === 'docker' && dockerSubcommand(call.args) === 'logs'
  );
  assert.equal(logsCall.args[logsCall.args.indexOf('--until') + 1], frame.observationCutoff.at);
  assert.deepEqual(
    setup.calls
      .filter((call) => call.executable === 'docker')
      .map((call) => dockerSubcommand(call.args)),
    ['version', 'ps', 'inspect', 'logs']
  );
  assert.equal(
    setup.calls.some(
      (call) =>
        call.executable === 'docker' &&
        ['exec', 'top', 'attach', 'restart', 'stop'].includes(dockerSubcommand(call.args))
    ),
    false
  );
});

test('frame binding rejects forged cutoff ownership while allowing logs to finish later', async () => {
  const setup = makeAuditors();
  const lsusbAdmission = await captureLsusbAdmission(setup.commandAuditor);
  const dockerAdmission = await captureDockerAdmission(setup.commandAuditor);
  const frame = await captureObservationFrame({
    frameId: 'frame-cutoff-binding',
    commandAuditor: setup.commandAuditor,
    filesystemAuditor: setup.filesystemAuditor,
    lsusbAdmission,
    dockerAdmission,
    target: target(),
    logSince: '2026-07-26T16:19:06.805378786Z',
    wallNow: setup.frameClocks.wallNow,
    monotonicNowNs: setup.frameClocks.monotonicNowNs,
  });
  const commandReceipts = setup.commandAuditor.snapshot().receipts;
  const filesystemReceipts = setup.filesystemAuditor.snapshot().receipts;
  assert.equal(frameAuditBindingExact(frame, commandReceipts, filesystemReceipts), true);

  const cutoffTamper = structuredClone(frame);
  cutoffTamper.observationCutoff.at = cutoffTamper.endedAt;
  cutoffTamper.observationCutoff.monotonicNs = cutoffTamper.endedMonotonicNs;
  assert.equal(frameAuditBindingExact(cutoffTamper, commandReceipts, filesystemReceipts), false);

  const receiptTamper = structuredClone(commandReceipts);
  const logsReceipt = receiptTamper[frame.auditBinding.commandReceiptIndexes.at(-1)];
  logsReceipt.args[logsReceipt.args.indexOf('--until') + 1] = frame.endedAt;
  assert.equal(frameAuditBindingExact(frame, receiptTamper, filesystemReceipts), false);
});

test('rejects an admission object that is not bound to its exact audited command output', async () => {
  const setup = makeAuditors();
  const lsusbAdmission = await captureLsusbAdmission(setup.commandAuditor);
  const dockerAdmission = await captureDockerAdmission(setup.commandAuditor);
  const forged = structuredClone(lsusbAdmission);
  forged.devices[0].deviceNumber = '19';
  await assert.rejects(
    () =>
      captureObservationFrame({
        frameId: 'frame-forged',
        commandAuditor: setup.commandAuditor,
        filesystemAuditor: setup.filesystemAuditor,
        lsusbAdmission: forged,
        dockerAdmission,
        target: target(),
        logSince: '2026-07-26T16:19:06.805378786Z',
        wallNow: setup.frameClocks.wallNow,
        monotonicNowNs: setup.frameClocks.monotonicNowNs,
      }),
    /LSUSB_ADMISSION_UNBOUND/u
  );
  assert.equal(
    setup.calls.filter(
      (call) => call.executable === 'docker' && dockerSubcommand(call.args) === 'ps'
    ).length,
    0
  );
});

test('a completely inventoried target-device absence remains complete and descriptor-safe', async () => {
  const setup = makeAuditors({
    filesystemOptions: { serial: 'OTHER-SERIAL' },
    lsusbOutput: '',
  });
  const lsusbAdmission = await captureLsusbAdmission(setup.commandAuditor);
  const dockerAdmission = await captureDockerAdmission(setup.commandAuditor);
  const frame = await captureObservationFrame({
    frameId: 'frame-device-absent',
    commandAuditor: setup.commandAuditor,
    filesystemAuditor: setup.filesystemAuditor,
    lsusbAdmission,
    dockerAdmission,
    target: target(),
    logSince: '2026-07-26T16:19:06.805378786Z',
    wallNow: setup.frameClocks.wallNow,
    monotonicNowNs: setup.frameClocks.monotonicNowNs,
  });
  assert.equal(frame.complete, true, JSON.stringify(frame.errors));
  assert.equal(frame.device.complete, true);
  assert.equal(frame.device.present, false);
  assert.deepEqual(frame.device.usbEpochs, []);
  assert.equal(frame.processes.surfaceWorkers.length, 1);
  assert.equal(frame.processes.surfaceWorkers[0].descriptorTableStable, true);
});

test('a matching USB row without an exact HID/sysfs identity is inconclusive', async () => {
  const setup = makeAuditors({ filesystemOptions: { serial: 'OTHER-SERIAL' } });
  const lsusbAdmission = await captureLsusbAdmission(setup.commandAuditor);
  const dockerAdmission = await captureDockerAdmission(setup.commandAuditor);
  const frame = await captureObservationFrame({
    frameId: 'frame-device-ambiguous',
    commandAuditor: setup.commandAuditor,
    filesystemAuditor: setup.filesystemAuditor,
    lsusbAdmission,
    dockerAdmission,
    target: target(),
    logSince: '2026-07-26T16:19:06.805378786Z',
    wallNow: setup.frameClocks.wallNow,
    monotonicNowNs: setup.frameClocks.monotonicNowNs,
  });
  assert.equal(frame.complete, false);
  assert.equal(frame.device.complete, false);
  assert.equal(frame.device.present, false);
  assert.equal(frame.device.lsusbMatches.length, 1);
  assert.deepEqual(frame.device.usbEpochs, []);
});

test('an exact absent historical container skips inspect, logs, and proc observation', async () => {
  const setup = makeAuditors({ includeTarget: false, forbidInspect: true });
  const lsusbAdmission = await captureLsusbAdmission(setup.commandAuditor);
  const dockerAdmission = await captureDockerAdmission(setup.commandAuditor);
  const frame = await captureObservationFrame({
    frameId: 'frame-1',
    commandAuditor: setup.commandAuditor,
    filesystemAuditor: setup.filesystemAuditor,
    lsusbAdmission,
    dockerAdmission,
    target: target(),
    logSince: '2026-07-26T16:19:06.805378786Z',
    wallNow: setup.frameClocks.wallNow,
    monotonicNowNs: setup.frameClocks.monotonicNowNs,
  });
  assert.equal(frame.complete, true, JSON.stringify(frame.errors));
  assert.deepEqual(frame.absence, {
    historicalContainerAbsent: true,
    exact: true,
  });
  assert.equal(frame.docker.lifecycle, null);
  assert.equal(frame.processes.procRoot, null);
  assert.equal(frame.docker.markers.openingCount, 0);
  assert.equal(frame.docker.markers.readyCount, 0);
  assert.equal(frame.docker.markers.relevantLinesSha256, EMPTY_SHA256);
  assert.deepEqual(frame.auditBinding.commandReceiptIndexes, [2]);
  const dockerPsReceipt =
    setup.commandAuditor.snapshot().receipts[frame.auditBinding.commandReceiptIndexes[0]];
  assert.deepEqual(frame.observationCutoff, {
    at: dockerPsReceipt.endedAt,
    monotonicNs: dockerPsReceipt.endedMonotonicNs,
  });
  assert.equal(
    frameAuditBindingExact(
      frame,
      setup.commandAuditor.snapshot().receipts,
      setup.filesystemAuditor.snapshot().receipts
    ),
    true
  );
  assert.deepEqual(
    setup.calls
      .filter((call) => call.executable === 'docker')
      .map((call) => dockerSubcommand(call.args)),
    ['version', 'ps']
  );
});

test('a filtered docker ps row for an unrelated container fails closed', async () => {
  const setup = makeAuditors({
    forbidInspect: true,
    psOutput: `${JSON.stringify({ ID: 'a'.repeat(64), State: 'running' })}\n`,
  });
  const lsusbAdmission = await captureLsusbAdmission(setup.commandAuditor);
  const dockerAdmission = await captureDockerAdmission(setup.commandAuditor);
  const frame = await captureObservationFrame({
    frameId: 'frame-filter-contradiction',
    commandAuditor: setup.commandAuditor,
    filesystemAuditor: setup.filesystemAuditor,
    lsusbAdmission,
    dockerAdmission,
    target: target(),
    logSince: '2026-07-26T16:19:06.805378786Z',
    wallNow: setup.frameClocks.wallNow,
    monotonicNowNs: setup.frameClocks.monotonicNowNs,
  });
  assert.equal(frame.complete, false);
  assert.equal(frame.absence.exact, false);
  assert.equal(
    frame.errors.some((entry) => entry.stage === 'docker-ps'),
    true
  );
});

test('a failed required filesystem access remains explicit and makes the frame incomplete', async () => {
  const clock = clocks();
  const commands = commandRunner({ includeTarget: false, forbidInspect: true });
  const fixture = filesystemFixture();
  const filesystem = {
    ...fixture,
    readFileSync(targetPath, ...args) {
      if (targetPath === '/proc/sys/kernel/hostname') {
        const error = new Error('permission denied');
        error.code = 'EACCES';
        throw error;
      }
      return fixture.readFileSync(targetPath, ...args);
    },
  };
  const commandAuditor = createCommandAuditor({
    runner: commands.runner,
    wallNow: clock.wallNow,
    monotonicNowNs: clock.monotonicNowNs,
  });
  const filesystemAuditor = createFilesystemAuditor({
    filesystem,
    wallNow: clock.wallNow,
    monotonicNowNs: clock.monotonicNowNs,
  });
  const lsusbAdmission = await captureLsusbAdmission(commandAuditor);
  const dockerAdmission = await captureDockerAdmission(commandAuditor);
  const frame = await captureObservationFrame({
    frameId: 'frame-failed-read',
    commandAuditor,
    filesystemAuditor,
    lsusbAdmission,
    dockerAdmission,
    target: target(),
    logSince: '2026-07-26T16:19:06.805378786Z',
    wallNow: clock.wallNow,
    monotonicNowNs: clock.monotonicNowNs,
  });
  assert.equal(frame.complete, false);
  assert.equal(frame.host.hostname, null);
  assert.equal(
    frame.errors.some((entry) => entry.stage === 'host-hostname'),
    true
  );
  assert.equal(
    filesystemAuditor
      .snapshot()
      .receipts.some(
        (receipt) =>
          receipt.path === '/proc/sys/kernel/hostname' &&
          receipt.disposition === 'error' &&
          receipt.errorCode === 'EACCES'
      ),
    true
  );
});

test('an exact stopped historical container is complete noneligible without inspect or logs', async () => {
  const setup = makeAuditors({ state: 'exited', forbidInspect: true });
  const lsusbAdmission = await captureLsusbAdmission(setup.commandAuditor);
  const dockerAdmission = await captureDockerAdmission(setup.commandAuditor);
  const frame = await captureObservationFrame({
    frameId: 'frame-1',
    commandAuditor: setup.commandAuditor,
    filesystemAuditor: setup.filesystemAuditor,
    lsusbAdmission,
    dockerAdmission,
    target: target(),
    logSince: '2026-07-26T16:19:06.805378786Z',
    wallNow: setup.frameClocks.wallNow,
    monotonicNowNs: setup.frameClocks.monotonicNowNs,
  });
  assert.equal(frame.complete, true, JSON.stringify(frame.errors));
  assert.deepEqual(frame.nonEligible, {
    containerNotRunning: true,
    exact: true,
  });
  assert.equal(frame.absence.exact, true);
  assert.equal(frame.docker.targetState, 'exited');
  assert.equal(frame.docker.lifecycle, null);
  const dockerPsReceipt =
    setup.commandAuditor.snapshot().receipts[frame.auditBinding.commandReceiptIndexes[0]];
  assert.deepEqual(frame.observationCutoff, {
    at: dockerPsReceipt.endedAt,
    monotonicNs: dockerPsReceipt.endedMonotonicNs,
  });
  assert.equal(
    frameAuditBindingExact(
      frame,
      setup.commandAuditor.snapshot().receipts,
      setup.filesystemAuditor.snapshot().receipts
    ),
    true
  );
  assert.deepEqual(
    setup.calls
      .filter((call) => call.executable === 'docker')
      .map((call) => dockerSubcommand(call.args)),
    ['version', 'ps']
  );
});

test('global capability audit proves exact two-frame cardinality and zero prohibited capabilities', async () => {
  const setup = makeAuditors({ includeTarget: false, forbidInspect: true });
  await captureGitAdmission(setup.commandAuditor, { protectedMainCommit: PROTECTED_MAIN });
  const lsusbAdmission = await captureLsusbAdmission(setup.commandAuditor);
  const dockerAdmission = await captureDockerAdmission(setup.commandAuditor);
  const frames = [];
  for (const frameId of ['frame-1', 'frame-2']) {
    frames.push(
      await captureObservationFrame({
        frameId,
        commandAuditor: setup.commandAuditor,
        filesystemAuditor: setup.filesystemAuditor,
        lsusbAdmission,
        dockerAdmission,
        target: target(),
        logSince: '2026-07-26T16:19:06.805378786Z',
        wallNow: setup.frameClocks.wallNow,
        monotonicNowNs: setup.frameClocks.monotonicNowNs,
      })
    );
  }
  const audit = buildCapabilityAudit({
    commandAuditor: setup.commandAuditor,
    filesystemAuditor: setup.filesystemAuditor,
    frames,
  });
  assert.equal(audit.mode, 'live-readonly-capability-bounded');
  assert.equal(audit.complete, true);
  assert.equal(audit.exact, true);
  assert.equal(audit.frameCount, 2);
  assert.equal(audit.lsusbCount, 1);
  assert.equal(audit.unrecordedObservationCount, 0);
  assert.deepEqual(audit.allowedProcessCounts, {
    git: 3,
    lsusb: 1,
    dockerVersion: 1,
    dockerPs: 2,
    dockerInspect: 0,
    dockerLogs: 0,
  });
  assert.equal(audit.commandCount, 7);
  assert.deepEqual(
    audit.commandReceipts.slice(0, 3).map((receipt) => receipt.kind),
    ['git', 'git', 'git']
  );
  assert.equal(
    audit.commandReceipts.every((receipt) => receipt.stdout.text !== undefined),
    true
  );
  assert.equal(
    Object.values(audit.prohibitedCounts).every((count) => count === 0),
    true
  );
  assert.equal(
    audit.filesystemReceipts.every(
      (receipt) =>
        receipt.path.startsWith('/etc/') ||
        receipt.path.startsWith('/proc/') ||
        receipt.path.startsWith('/sys/') ||
        receipt.path.startsWith('/dev/')
    ),
    true
  );
  assert.deepEqual(
    frames.flatMap((frame) => frame.auditBinding.commandReceiptIndexes),
    [5, 6]
  );
  assert.deepEqual(
    frames
      .flatMap((frame) => frame.auditBinding.filesystemReceiptIndexes)
      .sort((left, right) => left - right),
    audit.filesystemReceipts.map((receipt) => receipt.index)
  );

  const missingBinding = structuredClone(frames);
  missingBinding[1].auditBinding.filesystemReceiptIndexes.pop();
  assert.equal(
    buildCapabilityAudit({
      commandAuditor: setup.commandAuditor,
      filesystemAuditor: setup.filesystemAuditor,
      frames: missingBinding,
    }).exact,
    false
  );
  const duplicateBinding = structuredClone(frames);
  duplicateBinding[1].auditBinding.commandReceiptIndexes.push(6);
  assert.equal(
    buildCapabilityAudit({
      commandAuditor: setup.commandAuditor,
      filesystemAuditor: setup.filesystemAuditor,
      frames: duplicateBinding,
    }).exact,
    false
  );
  const timingTamper = structuredClone(frames);
  timingTamper[0].endedAt = timingTamper[0].startedAt;
  assert.equal(
    buildCapabilityAudit({
      commandAuditor: setup.commandAuditor,
      filesystemAuditor: setup.filesystemAuditor,
      frames: timingTamper,
    }).exact,
    false
  );
});
