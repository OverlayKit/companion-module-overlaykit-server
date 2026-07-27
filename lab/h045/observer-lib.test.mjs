import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  OBSERVER_ACCEPTED_DEVICE,
  OBSERVER_ACCEPTED_IMAGE_ID,
  OBSERVER_COMMAND_ENVIRONMENT_POLICY,
  OBSERVER_DOCKER_ANCESTOR_FILTER,
  OBSERVER_DOCKER_INSPECT_FORMAT,
  OBSERVER_DOCKER_PS_FORMAT,
  OBSERVER_DOCKER_UNIX_HOST,
  OBSERVER_DOCKER_VERSION_FORMAT,
  ObserverPolicyError,
  buildCapabilityAudit,
  captureDockerAdmission,
  captureGitAdmission,
  captureLsusbAdmission,
  captureObservationFrame,
  createCommandAuditor,
  createFilesystemAuditor,
  frameAuditBindingExact,
  parseDockerInspect,
  parseDockerInventory,
  validateObserverCommand,
} from './observer-lib.mjs';

const TARGET_SERIAL = 'TEST-H045-PRIMARY';
const OTHER_SERIAL = 'TEST-H045-OTHER';
const CONTAINER_A = 'a'.repeat(64);
const CONTAINER_B = 'b'.repeat(64);
const PROTECTED_MAIN = 'e7c9406dc75d6d8c9cb771d9d62d4fd1359b975d';
const SOURCE_CONTRACT = '2dc13d02f3d054fe54cb253869134c872e965601';
const TARGET = Object.freeze({
  serial: TARGET_SERIAL,
  vendorId: OBSERVER_ACCEPTED_DEVICE.vendorId,
  productId: OBSERVER_ACCEPTED_DEVICE.productId,
});

function clocks() {
  let wall = Date.parse('2026-07-27T00:00:00.000Z');
  let monotonic = 80_000_000_000_000n;
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
  inode = 2000n,
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

function deviceFixture({
  name = 'hidraw0',
  hidSerial = TARGET_SERIAL,
  usbSerial = hidSerial,
  busNumber = '1',
  deviceNumber = '18',
  usbSegment = '1-2',
  major = 241,
  minor = 0,
  nodeMajor = major,
  nodeMinor = minor,
  character = true,
} = {}) {
  return {
    name,
    hidSerial,
    usbSerial,
    busNumber,
    deviceNumber,
    usbSegment,
    major,
    minor,
    nodeMajor,
    nodeMinor,
    character,
  };
}

function filesystemFixture({ devices = [deviceFixture()], hostPid = 1_238_461 } = {}) {
  const files = new Map([
    [
      '/etc/os-release',
      'NAME=Fedora Linux\nID=fedora\nVERSION_ID=43\nPRETTY_NAME="Fedora Linux 43"\n',
    ],
    ['/proc/sys/kernel/random/boot_id', '11111111-2222-4333-8444-555555555555\n'],
    ['/proc/sys/kernel/hostname', 'h045-test-host\n'],
  ]);
  const directories = new Map([['/sys/class/hidraw', devices.map((entry) => entry.name)]]);
  const links = new Map();
  const realpaths = new Map();
  const stats = new Map();

  for (const [index, device] of devices.entries()) {
    const hidPath =
      `/sys/devices/pci0000:00/0000:00:14.0/usb1/${device.usbSegment}/` +
      `${device.usbSegment}:1.0/0003:0FD9:0080.${String(index + 1).padStart(4, '0')}`;
    const usbPath = `/sys/devices/pci0000:00/0000:00:14.0/usb1/${device.usbSegment}`;
    const nodePath = `/dev/${device.name}`;
    files.set(
      `/sys/class/hidraw/${device.name}/device/uevent`,
      [
        'HID_ID=0003:00000FD9:00000080',
        `HID_UNIQ=${device.hidSerial}`,
        'HID_NAME=Elgato Stream Deck MK.2',
        `HID_PHYS=usb-0000:00:14.0-${device.usbSegment.slice(2)}/input0`,
        '',
      ].join('\n')
    );
    files.set(`/sys/class/hidraw/${device.name}/dev`, `${device.major}:${device.minor}\n`);
    files.set(`${usbPath}/idVendor`, `${OBSERVER_ACCEPTED_DEVICE.vendorId}\n`);
    files.set(`${usbPath}/idProduct`, `${OBSERVER_ACCEPTED_DEVICE.productId}\n`);
    files.set(`${usbPath}/serial`, `${device.usbSerial}\n`);
    files.set(`${usbPath}/manufacturer`, 'Elgato\n');
    files.set(`${usbPath}/product`, 'Stream Deck MK.2\n');
    files.set(`${usbPath}/busnum`, `${device.busNumber}\n`);
    files.set(`${usbPath}/devnum`, `${device.deviceNumber}\n`);
    files.set(`${usbPath}/devpath`, `${device.usbSegment.slice(2)}\n`);
    files.set(`${usbPath}/dev`, `189:${17 + index}\n`);
    realpaths.set(`/sys/class/hidraw/${device.name}/device`, hidPath);
    stats.set(
      nodePath,
      statFixture({
        rdev: encodeLinuxDeviceNumber(device.nodeMajor, device.nodeMinor),
        character: device.character,
        inode: BigInt(2000 + index),
      })
    );
  }

  const procRoot = `/proc/${hostPid}/root/proc`;
  files.set(`${procRoot}/1/stat`, procStat(1, 0, 7_808_679));
  files.set(`${procRoot}/1/status`, procStatus(1));
  files.set(
    `${procRoot}/1/cmdline`,
    Buffer.from('./node-runtimes/main/bin/node\u0000./main.js\u0000')
  );
  files.set(`${procRoot}/1/cgroup`, '0::/\n');
  files.set(`${procRoot}/73/stat`, procStat(73, 1, 7_808_716));
  files.set(`${procRoot}/73/status`, procStatus(73));
  files.set(
    `${procRoot}/73/cmdline`,
    Buffer.from(
      '/app/node-runtimes/node22/bin/node\u0000--enable-source-maps\u0000/app/SurfaceThread.js\u0000'
    )
  );
  files.set(`${procRoot}/73/cgroup`, '0::/\n');
  files.set(`/proc/${hostPid}/cgroup`, `0::/system.slice/docker-${CONTAINER_A}.scope\n`);
  directories.set(procRoot, ['1', '73']);
  directories.set(`${procRoot}/73/fd`, []);
  links.set(`${procRoot}/1/ns/pid`, 'pid:[4026533784]');
  links.set(`${procRoot}/1/ns/mnt`, 'mnt:[4026533781]');
  links.set(`${procRoot}/73/ns/pid`, 'pid:[4026533784]');
  links.set(`${procRoot}/73/ns/mnt`, 'mnt:[4026533781]');

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

function lsusbOutput(devices) {
  return devices
    .map(
      (device) =>
        `Bus ${device.busNumber.padStart(3, '0')} Device ${device.deviceNumber.padStart(3, '0')}: ` +
        `ID ${OBSERVER_ACCEPTED_DEVICE.vendorId}:${OBSERVER_ACCEPTED_DEVICE.productId} ` +
        'Elgato Stream Deck MK.2'
    )
    .join('\n')
    .concat(devices.length === 0 ? '' : '\n');
}

function dockerVersionOutput() {
  return JSON.stringify({
    Client: { Version: '28.3.3', ApiVersion: '1.51' },
    Server: { Version: '28.3.3', ApiVersion: '1.51' },
  });
}

function dockerPsOutput(rows) {
  return rows
    .map((row) => JSON.stringify({ ID: row.containerId, State: row.state }))
    .join('\n')
    .concat(rows.length === 0 ? '' : '\n');
}

function dockerInspectOutput({
  containerId = CONTAINER_A,
  imageId = OBSERVER_ACCEPTED_IMAGE_ID,
  state = 'running',
  hostPid = 1_238_461,
} = {}) {
  const running = state === 'running';
  return JSON.stringify({
    Id: containerId,
    Image: imageId,
    State: {
      Status: state,
      Running: running,
      Pid: running ? hostPid : 0,
      StartedAt: '2026-07-26T15:00:00.000000000Z',
    },
    RestartCount: 0,
    CgroupnsMode: 'host',
  });
}

function commandRunner({
  lsusbDevices = [deviceFixture()],
  inventories = [[{ containerId: CONTAINER_A, state: 'running' }]],
  inspectImageId = OBSERVER_ACCEPTED_IMAGE_ID,
  inspectState = 'running',
  hostPid = 1_238_461,
  logSerial = TARGET_SERIAL,
  onInvoke = () => {},
} = {}) {
  const calls = [];
  let psIndex = 0;
  async function runner(executable, args, options) {
    calls.push({
      executable,
      args: [...args],
      options: structuredClone(options),
    });
    const kind = validateObserverCommand(executable, args);
    onInvoke({ kind, executable, args: [...args] });
    if (kind === 'gitRevParse') {
      return { exitCode: 0, signal: null, stdout: `${SOURCE_CONTRACT}\n`, stderr: '' };
    }
    if (kind === 'gitMergeBaseAncestor') {
      return { exitCode: 0, signal: null, stdout: '', stderr: '' };
    }
    if (kind === 'gitRemoteGetUrl') {
      return {
        exitCode: 0,
        signal: null,
        stdout: 'https://github.com/OverlayKit/companion-module-overlaykit-server.git\n',
        stderr: '',
      };
    }
    if (kind === 'lsusb') {
      return {
        exitCode: 0,
        signal: null,
        stdout: lsusbOutput(lsusbDevices),
        stderr: '',
      };
    }
    if (kind === 'dockerVersion') {
      return { exitCode: 0, signal: null, stdout: dockerVersionOutput(), stderr: '' };
    }
    if (kind === 'dockerPs') {
      const rows = inventories[Math.min(psIndex, inventories.length - 1)] ?? [];
      psIndex += 1;
      return { exitCode: 0, signal: null, stdout: dockerPsOutput(rows), stderr: '' };
    }
    if (kind === 'dockerInspect') {
      return {
        exitCode: 0,
        signal: null,
        stdout: dockerInspectOutput({
          containerId: args.at(-1),
          imageId: inspectImageId,
          state: inspectState,
          hostPid,
        }),
        stderr: '',
      };
    }
    if (kind === 'dockerLogs') {
      return {
        exitCode: 0,
        signal: null,
        stdout: `2026-07-27T00:00:00.000000000Z Opening surface panel: streamdeck:${logSerial}\n`,
        stderr: `2026-07-27T00:00:00.001000000Z Surface panel ready: streamdeck:${logSerial}\n`,
      };
    }
    throw new Error(`unhandled fake command ${kind}`);
  }
  return { calls, runner };
}

function makeContext({
  filesystemDevices = [deviceFixture()],
  lsusbDevices = filesystemDevices,
  ...commandOptions
} = {}) {
  const clock = clocks();
  const commands = commandRunner({ lsusbDevices, ...commandOptions });
  return {
    clock,
    commands,
    commandAuditor: createCommandAuditor({
      runner: commands.runner,
      wallNow: clock.wallNow,
      monotonicNowNs: clock.monotonicNowNs,
      environment: {
        PATH: '/usr/bin:/bin',
        DOCKER_HOST: 'tcp://example.invalid:2375',
        DOCKER_CONTEXT: 'remote-context',
        DOCKER_TLS_VERIFY: '1',
        DOCKER_CERT_PATH: '/tmp/poison',
        DOCKER_API_VERSION: '0.0',
      },
    }),
    filesystemAuditor: createFilesystemAuditor({
      filesystem: filesystemFixture({
        devices: filesystemDevices,
        hostPid: commandOptions.hostPid,
      }),
      wallNow: clock.wallNow,
      monotonicNowNs: clock.monotonicNowNs,
    }),
  };
}

async function captureAdmissions(context) {
  const git = await captureGitAdmission(context.commandAuditor, {
    protectedMainCommit: PROTECTED_MAIN,
    sourceContractCommit: SOURCE_CONTRACT,
  });
  const lsusb = await captureLsusbAdmission(context.commandAuditor);
  const docker = await captureDockerAdmission(context.commandAuditor);
  return { git, lsusb, docker };
}

async function captureFrame(context, admissions, frameId = 'frame-1') {
  return captureObservationFrame({
    frameId,
    commandAuditor: context.commandAuditor,
    filesystemAuditor: context.filesystemAuditor,
    lsusbAdmission: admissions.lsusb,
    dockerAdmission: admissions.docker,
    target: TARGET,
    logSince: '2026-07-26T23:59:00.000Z',
    wallNow: context.clock.wallNow,
    monotonicNowNs: context.clock.monotonicNowNs,
  });
}

test('admits only the exact image-ancestor Docker Unix-socket command surface', () => {
  assert.equal(validateObserverCommand('git', ['rev-parse', 'HEAD']), 'gitRevParse');
  assert.equal(
    validateObserverCommand('git', ['merge-base', '--is-ancestor', SOURCE_CONTRACT, 'HEAD']),
    'gitMergeBaseAncestor'
  );
  assert.equal(validateObserverCommand('lsusb', []), 'lsusb');
  assert.equal(
    validateObserverCommand('docker', [
      '--host',
      OBSERVER_DOCKER_UNIX_HOST,
      'version',
      '--format',
      OBSERVER_DOCKER_VERSION_FORMAT,
    ]),
    'dockerVersion'
  );
  assert.equal(
    validateObserverCommand('docker', [
      '--host',
      OBSERVER_DOCKER_UNIX_HOST,
      'ps',
      '--all',
      '--no-trunc',
      '--filter',
      OBSERVER_DOCKER_ANCESTOR_FILTER,
      '--format',
      OBSERVER_DOCKER_PS_FORMAT,
    ]),
    'dockerPs'
  );
  assert.equal(
    validateObserverCommand('docker', [
      '--host',
      OBSERVER_DOCKER_UNIX_HOST,
      'inspect',
      '--format',
      OBSERVER_DOCKER_INSPECT_FORMAT,
      CONTAINER_A,
    ]),
    'dockerInspect'
  );
  for (const args of [
    ['ps'],
    ['--host', 'tcp://example.invalid:2375', 'ps'],
    ['--host', OBSERVER_DOCKER_UNIX_HOST, 'ps', '--all'],
    [
      '--host',
      OBSERVER_DOCKER_UNIX_HOST,
      'ps',
      '--all',
      '--no-trunc',
      '--filter',
      `id=${CONTAINER_A}`,
      '--format',
      OBSERVER_DOCKER_PS_FORMAT,
    ],
    [
      '--host',
      OBSERVER_DOCKER_UNIX_HOST,
      'ps',
      '--all',
      '--no-trunc',
      '--filter',
      'ancestor=ghcr.io/bitfocus/companion/companion:v4.3.3',
      '--format',
      OBSERVER_DOCKER_PS_FORMAT,
    ],
    ['--host', OBSERVER_DOCKER_UNIX_HOST, 'exec', CONTAINER_A, 'true'],
    ['--host', OBSERVER_DOCKER_UNIX_HOST, 'inspect', '--format', '{{json .Config}}', CONTAINER_A],
  ]) {
    assert.throws(() => validateObserverCommand('docker', args), ObserverPolicyError);
  }
});

test('passes only the exact closed fixed environment and signal-free limits to the runner', async () => {
  const clock = clocks();
  let observedOptions = null;
  let poisonedReads = 0;
  const environment = {};
  for (const key of [
    'GIT_DIR',
    'GIT_WORK_TREE',
    'GIT_OBJECT_DIRECTORY',
    'GIT_CONFIG_COUNT',
    'GIT_CONFIG_GLOBAL',
    'GIT_CONFIG_NOSYSTEM',
    'LD_PRELOAD',
    'LD_LIBRARY_PATH',
    'PATH',
    'DOCKER_HOST',
  ]) {
    Object.defineProperty(environment, key, {
      enumerable: true,
      get() {
        poisonedReads += 1;
        throw new Error(`poisoned environment getter executed: ${key}`);
      },
    });
  }
  const auditor = createCommandAuditor({
    runner: async (_executable, _args, options) => {
      observedOptions = options;
      return { exitCode: 0, signal: null, stdout: dockerVersionOutput(), stderr: '' };
    },
    wallNow: clock.wallNow,
    monotonicNowNs: clock.monotonicNowNs,
    environment,
  });
  await auditor.invoke('docker', [
    '--host',
    OBSERVER_DOCKER_UNIX_HOST,
    'version',
    '--format',
    OBSERVER_DOCKER_VERSION_FORMAT,
  ]);
  assert.equal(poisonedReads, 0);
  assert.deepEqual(Object.keys(observedOptions).sort(), ['env', 'maxBufferBytes']);
  assert.equal(observedOptions.maxBufferBytes, 4 * 1024 * 1024);
  assert.deepEqual(observedOptions.env, OBSERVER_COMMAND_ENVIRONMENT_POLICY.fixed);
  assert.deepEqual(Object.keys(observedOptions.env).sort(), [
    'DOCKER_CONFIG',
    'GIT_CONFIG_COUNT',
    'GIT_CONFIG_GLOBAL',
    'GIT_CONFIG_NOSYSTEM',
    'LANG',
    'LC_ALL',
  ]);
  assert.deepEqual(
    auditor.snapshot().receipts[0].environmentPolicy,
    OBSERVER_COMMAND_ENVIRONMENT_POLICY
  );
  assert.deepEqual(auditor.snapshot().receipts[0].limits, {
    maxBufferBytes: 4 * 1024 * 1024,
    timeoutMs: null,
    overflow: 'drain-without-signal',
  });
});

test('Git admission records HEAD, two ancestry checks, and origin in four receipts', async () => {
  const context = makeContext();
  const git = await captureGitAdmission(context.commandAuditor, {
    protectedMainCommit: PROTECTED_MAIN,
    sourceContractCommit: SOURCE_CONTRACT,
  });
  assert.equal(git.head, SOURCE_CONTRACT);
  assert.equal(git.protectedMainIsAncestor, true);
  assert.equal(git.sourceContractIsAncestor, true);
  assert.deepEqual(git.commandReceiptIndexes, [0, 1, 2, 3]);
  assert.deepEqual(context.commandAuditor.snapshot().commandCardinality, {
    gitRevParse: 1,
    gitMergeBaseAncestor: 2,
    gitRemoteGetUrl: 1,
    lsusb: 0,
    dockerVersion: 0,
    dockerPs: 0,
    dockerInspect: 0,
    dockerLogs: 0,
  });
});

test('Docker parsers preserve zero, one, and multiple rows and reject expanded projections', () => {
  assert.deepEqual(parseDockerInventory(''), []);
  assert.deepEqual(
    parseDockerInventory(dockerPsOutput([{ containerId: CONTAINER_A, state: 'running' }])),
    [{ containerId: CONTAINER_A, state: 'running' }]
  );
  assert.equal(
    parseDockerInventory(
      dockerPsOutput([
        { containerId: CONTAINER_A, state: 'running' },
        { containerId: CONTAINER_B, state: 'exited' },
      ])
    ).length,
    2
  );
  assert.throws(() =>
    parseDockerInventory(
      `${JSON.stringify({ ID: CONTAINER_A, State: 'running', Names: 'forbidden' })}\n`
    )
  );
  assert.throws(() =>
    parseDockerInventory(
      dockerPsOutput([
        { containerId: CONTAINER_A, state: 'running' },
        { containerId: CONTAINER_A, state: 'running' },
      ])
    )
  );
});

test('minimal inspect requires exact accepted .Image and state-consistent PID', () => {
  const running = parseDockerInspect(dockerInspectOutput());
  assert.equal(running.imageId, OBSERVER_ACCEPTED_IMAGE_ID);
  assert.equal(running.running, true);
  assert.equal(running.hostPid, 1_238_461);
  const stopped = parseDockerInspect(dockerInspectOutput({ state: 'exited' }));
  assert.equal(stopped.running, false);
  assert.equal(stopped.hostPid, 0);
  assert.throws(() =>
    parseDockerInspect(
      dockerInspectOutput({
        imageId: `sha256:${'f'.repeat(64)}`,
      })
    )
  );
  const overBroad = JSON.parse(dockerInspectOutput());
  overBroad.Config = { Env: ['SECRET=forbidden'] };
  assert.throws(() => parseDockerInspect(JSON.stringify(overBroad)));
});

test('public filesystem surface is sealed outside observer-owned frame scopes', () => {
  const clock = clocks();
  const auditor = createFilesystemAuditor({
    filesystem: filesystemFixture(),
    wallNow: clock.wallNow,
    monotonicNowNs: clock.monotonicNowNs,
  });
  for (const [operation, targetPath] of [
    ['statSync', '/dev/hidraw0'],
    ['readFileSync', '/dev/hidraw0'],
    ['readFileSync', '/etc/shadow'],
    ['readFileSync', '/proc/1238461/root/proc/73/environ'],
    ['readFileSync', '/sys/kernel/uevent_seqnum'],
  ]) {
    assert.throws(
      () => auditor.filesystem[operation](targetPath),
      (error) => error instanceof ObserverPolicyError && error.code === 'FILESYSTEM_SCOPE_REQUIRED'
    );
  }
  assert.equal(Object.hasOwn(auditor.filesystem, 'openSync'), false);
  assert.equal(auditor.snapshot().receipts.length, 0);
  assert.equal(auditor.snapshot().rejectedAttempts.length, 5);
  assert.equal(auditor.snapshot().policyExact, false);
});

test('zero ancestor rows are explicit and skip inspect, logs, and proc observation', async () => {
  const context = makeContext({ inventories: [[]] });
  const admissions = await captureAdmissions(context);
  const frame = await captureFrame(context, admissions);
  assert.equal(frame.complete, true);
  assert.equal(frame.docker.inventory.status, 'none');
  assert.equal(frame.docker.inventory.matchCount, 0);
  assert.deepEqual(frame.docker.inventory.matches, []);
  assert.equal(frame.docker.lifecycle, null);
  assert.equal(frame.processes.procRoot, null);
  assert.deepEqual(
    context.commandAuditor
      .snapshot()
      .receipts.slice(6)
      .map((receipt) => receipt.kind),
    ['dockerPs']
  );
});

test('multiple ancestor rows are complete raw ambiguity and never trigger detail commands', async () => {
  const context = makeContext({
    inventories: [
      [
        { containerId: CONTAINER_A, state: 'running' },
        { containerId: CONTAINER_B, state: 'running' },
      ],
    ],
  });
  const admissions = await captureAdmissions(context);
  const frame = await captureFrame(context, admissions);
  assert.equal(frame.complete, true);
  assert.equal(frame.docker.inventory.status, 'multiple');
  assert.equal(frame.docker.inventory.matchCount, 2);
  assert.equal(frame.errors.length, 0);
  assert.equal(frame.docker.lifecycle, null);
  assert.deepEqual(
    context.commandAuditor
      .snapshot()
      .receipts.slice(6)
      .map((receipt) => receipt.kind),
    ['dockerPs']
  );
});

test('one running exact-image row captures minimal inspect, bounded logs, and host proc', async () => {
  const context = makeContext();
  const admissions = await captureAdmissions(context);
  const frame = await captureFrame(context, admissions);
  assert.equal(frame.complete, true);
  assert.equal(frame.docker.inventory.status, 'unique');
  assert.equal(frame.docker.inventory.selector.imageId, OBSERVER_ACCEPTED_IMAGE_ID);
  assert.equal(frame.docker.inventory.selector.filter, OBSERVER_DOCKER_ANCESTOR_FILTER);
  assert.equal(frame.docker.lifecycle.imageId, OBSERVER_ACCEPTED_IMAGE_ID);
  assert.equal(frame.processes.stable, true);
  assert.equal(frame.processes.pid1.pid, 1);
  assert.equal(frame.processes.surfaceWorkers.length, 1);
  assert.equal(frame.docker.markers.openingCount, 1);
  assert.equal(frame.docker.markers.readyCount, 1);
  const snapshot = context.commandAuditor.snapshot();
  assert.deepEqual(
    snapshot.receipts.slice(6).map((receipt) => receipt.kind),
    ['dockerPs', 'dockerInspect', 'dockerLogs']
  );
  assert.equal(
    frameAuditBindingExact(frame, snapshot.receipts, context.filesystemAuditor.snapshot().receipts),
    true
  );
});

test('accepted serial remains unique when another MK.2 is also inventoried', async () => {
  const primary = deviceFixture();
  const other = deviceFixture({
    name: 'hidraw1',
    hidSerial: OTHER_SERIAL,
    usbSerial: OTHER_SERIAL,
    busNumber: '1',
    deviceNumber: '19',
    usbSegment: '1-3',
    major: 241,
    minor: 1,
  });
  const context = makeContext({
    filesystemDevices: [primary, other],
    inventories: [[]],
  });
  const admissions = await captureAdmissions(context);
  const frame = await captureFrame(context, admissions);
  assert.equal(frame.complete, true);
  assert.equal(frame.device.status, 'unique');
  assert.equal(frame.device.selectedEpoch.serial, TARGET_SERIAL);
  assert.equal(frame.device.lsusbMatches.length, 2);
});

test('regular target node is incomplete even when HID, USB, and lsusb identities match', async () => {
  const context = makeContext({
    filesystemDevices: [deviceFixture({ character: false })],
    inventories: [[]],
  });
  const admissions = await captureAdmissions(context);
  const frame = await captureFrame(context, admissions);
  assert.equal(frame.complete, false);
  assert.equal(frame.device.status, 'inconclusive');
  assert.equal(frame.device.selectedEpoch, null);
  assert.ok(frame.errors.some((entry) => entry.code === 'TARGET_NODE_NOT_CHARACTER'));
});

test('target node and hidraw class device-number mismatch is incomplete', async () => {
  const context = makeContext({
    filesystemDevices: [deviceFixture({ nodeMajor: 242 })],
    inventories: [[]],
  });
  const admissions = await captureAdmissions(context);
  const frame = await captureFrame(context, admissions);
  assert.equal(frame.complete, false);
  assert.equal(frame.device.status, 'inconclusive');
  assert.equal(frame.device.selectedEpoch, null);
  assert.ok(frame.errors.some((entry) => entry.code === 'TARGET_NODE_CLASS_MISMATCH'));
});

test('target device number duplicated by another hidraw entry is incomplete', async () => {
  const primary = deviceFixture();
  const duplicate = deviceFixture({
    name: 'hidraw1',
    hidSerial: OTHER_SERIAL,
    usbSerial: OTHER_SERIAL,
    busNumber: '1',
    deviceNumber: '19',
    usbSegment: '1-3',
    major: primary.major,
    minor: primary.minor,
  });
  const context = makeContext({
    filesystemDevices: [primary, duplicate],
    inventories: [[]],
  });
  const admissions = await captureAdmissions(context);
  const frame = await captureFrame(context, admissions);
  assert.equal(frame.complete, false);
  assert.equal(frame.device.status, 'inconclusive');
  assert.equal(frame.device.selectedEpoch, null);
  assert.ok(frame.errors.some((entry) => entry.code === 'DEVICE_NUMBER_NOT_UNIQUE'));
});

test('only another MK.2 cannot prove accepted-serial absence from serial-less lsusb', async () => {
  const other = deviceFixture({
    hidSerial: OTHER_SERIAL,
    usbSerial: OTHER_SERIAL,
  });
  const context = makeContext({
    filesystemDevices: [other],
    inventories: [[]],
  });
  const admissions = await captureAdmissions(context);
  const frame = await captureFrame(context, admissions);
  assert.equal(frame.complete, false);
  assert.equal(frame.device.status, 'inconclusive');
  assert.equal(frame.device.selectedEpoch, null);
  assert.ok(frame.errors.some((entry) => entry.code === 'DEVICE_CORRELATION_INCOMPLETE'));
});

test('accepted serial mismatch between HID and USB is explicit inconclusive evidence', async () => {
  const mismatch = deviceFixture({
    hidSerial: TARGET_SERIAL,
    usbSerial: OTHER_SERIAL,
  });
  const context = makeContext({
    filesystemDevices: [mismatch],
    inventories: [[]],
  });
  const admissions = await captureAdmissions(context);
  const frame = await captureFrame(context, admissions);
  assert.equal(frame.complete, false);
  assert.equal(frame.device.status, 'inconclusive');
  assert.equal(frame.device.targetSerialContradictionCount, 1);
});

test('stale lsusb presence with absent sysfs target is not exact absence', async () => {
  const context = makeContext({
    filesystemDevices: [],
    lsusbDevices: [deviceFixture()],
    inventories: [[]],
  });
  const admissions = await captureAdmissions(context);
  const frame = await captureFrame(context, admissions);
  assert.equal(frame.complete, false);
  assert.equal(frame.device.status, 'inconclusive');
  assert.equal(frame.device.lsusbMatches.length, 1);
});

test('inspect image mismatch fails before logs or proc target observation', async () => {
  const context = makeContext({
    inspectImageId: `sha256:${'f'.repeat(64)}`,
  });
  const admissions = await captureAdmissions(context);
  const frame = await captureFrame(context, admissions);
  assert.equal(frame.complete, false);
  assert.equal(frame.docker.inspectExact, false);
  assert.equal(frame.docker.lifecycle, null);
  assert.deepEqual(
    context.commandAuditor
      .snapshot()
      .receipts.slice(6)
      .map((receipt) => receipt.kind),
    ['dockerPs', 'dockerInspect']
  );
});

test('one non-running exact-image row is complete and skips impossible proc and logs', async () => {
  const context = makeContext({
    inventories: [[{ containerId: CONTAINER_A, state: 'exited' }]],
    inspectState: 'exited',
  });
  const admissions = await captureAdmissions(context);
  const frame = await captureFrame(context, admissions);
  assert.equal(frame.complete, true);
  assert.equal(frame.docker.lifecycle.running, false);
  assert.equal(frame.docker.lifecycle.hostPid, 0);
  assert.equal(frame.processes.procRoot, null);
  assert.deepEqual(
    context.commandAuditor
      .snapshot()
      .receipts.slice(6)
      .map((receipt) => receipt.kind),
    ['dockerPs', 'dockerInspect']
  );
});

test('running deployment with exact accepted device absence still binds target markers', async () => {
  const context = makeContext({
    filesystemDevices: [],
    lsusbDevices: [],
  });
  const admissions = await captureAdmissions(context);
  const frame = await captureFrame(context, admissions);
  assert.equal(frame.complete, true);
  assert.equal(frame.device.status, 'none');
  assert.equal(frame.docker.markers.serialAvailable, true);
  assert.equal(frame.docker.markers.openingCount, 1);
  assert.equal(frame.docker.markers.readyCount, 1);
  assert.equal(typeof frame.docker.markers.relevantLinesSha256, 'string');
});

test('frame input rejects historical volatile target fields', async () => {
  const context = makeContext({ inventories: [[]] });
  const admissions = await captureAdmissions(context);
  await assert.rejects(
    captureObservationFrame({
      frameId: 'frame-1',
      commandAuditor: context.commandAuditor,
      filesystemAuditor: context.filesystemAuditor,
      lsusbAdmission: admissions.lsusb,
      dockerAdmission: admissions.docker,
      target: {
        ...TARGET,
        containerId: CONTAINER_A,
      },
      logSince: '2026-07-26T23:59:00.000Z',
      wallNow: context.clock.wallNow,
      monotonicNowNs: context.clock.monotonicNowNs,
    }),
    ObserverPolicyError
  );
});

test('two frames produce an exact capability audit with four Git receipts and zero prohibitions', async () => {
  const context = makeContext({
    inventories: [
      [{ containerId: CONTAINER_A, state: 'running' }],
      [{ containerId: CONTAINER_A, state: 'running' }],
    ],
  });
  const admissions = await captureAdmissions(context);
  const first = await captureFrame(context, admissions, 'frame-1');
  const second = await captureFrame(context, admissions, 'frame-2');
  const audit = buildCapabilityAudit({
    commandAuditor: context.commandAuditor,
    filesystemAuditor: context.filesystemAuditor,
    frames: [first, second],
  });
  assert.equal(first.complete, true);
  assert.equal(second.complete, true);
  assert.equal(audit.exact, true);
  assert.equal(audit.allowedProcessCounts.git, 4);
  assert.equal(audit.allowedProcessCounts.dockerPs, 2);
  assert.equal(audit.allowedProcessCounts.dockerInspect, 2);
  assert.equal(audit.allowedProcessCounts.dockerLogs, 2);
  assert.ok(Object.values(audit.prohibitedCounts).every((count) => count === 0));
});

test('an observed child signal is counted and can never be reported as zero capability', async () => {
  const context = makeContext({
    inventories: [
      [{ containerId: CONTAINER_A, state: 'running' }],
      [{ containerId: CONTAINER_A, state: 'running' }],
    ],
  });
  const admissions = await captureAdmissions(context);
  const first = await captureFrame(context, admissions, 'frame-1');
  const second = await captureFrame(context, admissions, 'frame-2');
  const commandSnapshot = context.commandAuditor.snapshot();
  commandSnapshot.receipts[0].exitCode = null;
  commandSnapshot.receipts[0].signal = 'SIGTERM';
  const audit = buildCapabilityAudit({
    commandAuditor: { snapshot: () => structuredClone(commandSnapshot) },
    filesystemAuditor: context.filesystemAuditor,
    frames: [first, second],
  });
  assert.equal(audit.exact, false);
  assert.equal(audit.complete, false);
  assert.equal(audit.prohibitedCounts.signal, 1);
});

test('shadow, proc environ, and unenumerated sysfs attempts prevent an exact capability audit', async () => {
  let filesystemAuditor;
  let injected = false;
  const prohibitedPaths = [
    '/etc/shadow',
    '/proc/1238461/root/proc/73/environ',
    '/sys/kernel/uevent_seqnum',
  ];
  const context = makeContext({
    inventories: [
      [{ containerId: CONTAINER_A, state: 'running' }],
      [{ containerId: CONTAINER_A, state: 'running' }],
    ],
    onInvoke({ kind }) {
      if (kind !== 'dockerPs' || injected) return;
      injected = true;
      for (const targetPath of prohibitedPaths) {
        assert.throws(
          () => filesystemAuditor.filesystem.readFileSync(targetPath),
          (error) =>
            error instanceof ObserverPolicyError && error.code === 'FILESYSTEM_SCOPE_REQUIRED'
        );
      }
    },
  });
  filesystemAuditor = context.filesystemAuditor;
  const admissions = await captureAdmissions(context);
  const first = await captureFrame(context, admissions, 'frame-1');
  const second = await captureFrame(context, admissions, 'frame-2');
  const audit = buildCapabilityAudit({
    commandAuditor: context.commandAuditor,
    filesystemAuditor: context.filesystemAuditor,
    frames: [first, second],
  });
  const snapshot = context.filesystemAuditor.snapshot();
  assert.equal(first.complete, true);
  assert.equal(second.complete, true);
  assert.equal(snapshot.policyExact, false);
  assert.deepEqual(
    snapshot.rejectedAttempts.map((attempt) => attempt.path),
    prohibitedPaths
  );
  assert.ok(snapshot.receipts.every((receipt) => !prohibitedPaths.includes(receipt.path)));
  assert.equal(audit.exact, false);
  assert.equal(audit.complete, false);
});

test('two multiple-match frames remain an exact audit with zero inspect, logs, or proc target reads', async () => {
  const rows = [
    { containerId: CONTAINER_A, state: 'running' },
    { containerId: CONTAINER_B, state: 'running' },
  ];
  const context = makeContext({
    inventories: [rows, rows],
  });
  const admissions = await captureAdmissions(context);
  const first = await captureFrame(context, admissions, 'frame-1');
  const second = await captureFrame(context, admissions, 'frame-2');
  const audit = buildCapabilityAudit({
    commandAuditor: context.commandAuditor,
    filesystemAuditor: context.filesystemAuditor,
    frames: [first, second],
  });
  assert.equal(first.complete, true);
  assert.equal(second.complete, true);
  assert.equal(audit.exact, true);
  assert.equal(audit.allowedProcessCounts.dockerPs, 2);
  assert.equal(audit.allowedProcessCounts.dockerInspect, 0);
  assert.equal(audit.allowedProcessCounts.dockerLogs, 0);
  assert.equal(first.processes.procRoot, null);
  assert.equal(second.processes.procRoot, null);
});

test('frame binding rejects forged inventory ownership without touching dependencies', async () => {
  const context = makeContext({ inventories: [[]] });
  const admissions = await captureAdmissions(context);
  const frame = await captureFrame(context, admissions);
  const commands = context.commandAuditor.snapshot().receipts;
  const filesystem = context.filesystemAuditor.snapshot().receipts;
  assert.equal(frameAuditBindingExact(frame, commands, filesystem), true);
  const forged = structuredClone(frame);
  forged.auditBinding.commandReceiptIndexes = [];
  assert.equal(frameAuditBindingExact(forged, commands, filesystem), false);
});
