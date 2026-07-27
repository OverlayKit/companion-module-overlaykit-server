import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import {
  H045_ACCEPTED_IMAGE_ID,
  H045_ACCEPTED_IMAGE_REFERENCE,
  H045_PREDICATE_KEYS,
  classifyDynamicFrames,
  classificationExactShape,
  frameExactShape,
  sha256Canonical,
} from './classifier-lib.mjs';

const SHA256 = 'a'.repeat(64);
const CONTAINER_ID = 'c'.repeat(64);

function stat({ inode = '4001', ctimeNs = '1900000000000000000' } = {}) {
  return {
    stDev: '7',
    inode,
    ctimeNs,
    mode: '0660',
    uid: 0,
    gid: 1002,
    rdev: '61696',
    rdevHex: 'f1:0',
    major: 241,
    minor: 0,
    isCharacterDevice: true,
  };
}

function epoch({
  deviceNumber = '42',
  hidGeneration = '0042',
  inode = '4001',
  ctimeNs = '1900000000000000000',
} = {}) {
  return {
    serial: 'A00SA5492OQMLF',
    busNumber: '1',
    deviceNumber,
    usbDevicePath: '2',
    usbDev: `189:${Number(deviceNumber) - 1}`,
    hidDevicePath: `/sys/devices/pci0000:00/usb1/1-2/` + `0003:0FD9:0080.${hidGeneration}`,
    devicePath: '/dev/hidraw0',
    stat: stat({ inode, ctimeNs }),
  };
}

function lifecycle({ containerId = CONTAINER_ID, hostPid = 4242 } = {}) {
  return {
    containerId,
    imageId: H045_ACCEPTED_IMAGE_ID,
    startedAt: '2026-07-27T03:00:00.000Z',
    restartCount: 0,
    hostPid,
    pid1StartTicks: 7000,
    pidNamespace: 'pid:[4026533001]',
    mountNamespace: 'mnt:[4026533002]',
    cgroup: '0::/',
    hostCgroup: `0::/system.slice/docker-${containerId}.scope`,
    cgroupNamespaceMode: 'private',
  };
}

function pid1({ hostPid = 4242, startTicks = 7000 } = {}) {
  return {
    hostPid,
    startTicks,
    pidNamespace: 'pid:[4026533001]',
    mountNamespace: 'mnt:[4026533002]',
    cgroup: '0::/',
  };
}

function worker({ pid = 73, startTicks = 7100, parentStartTicks = 7000 } = {}) {
  return {
    pid,
    startTicks,
    ppid: 1,
    parentStartTicks,
    uid: 1000,
    gid: 1000,
    groups: [1000, 1002],
    cmdline: [
      '/app/node-runtimes/node22/bin/node',
      '--enable-source-maps',
      '/app/SurfaceThread.js',
    ],
    cgroup: '0::/',
    pidNamespace: 'pid:[4026533001]',
    mountNamespace: 'mnt:[4026533002]',
  };
}

function deployment({
  containerId = CONTAINER_ID,
  state = 'running',
  workers = [worker()],
  descriptors = [],
  currentPid1 = pid1(),
} = {}) {
  return {
    complete: true,
    exact: true,
    container: {
      id: containerId,
      imageReference: H045_ACCEPTED_IMAGE_REFERENCE,
      imageId: H045_ACCEPTED_IMAGE_ID,
      state,
    },
    lifecycle: lifecycle({
      containerId,
      hostPid: currentPid1?.hostPid ?? 0,
    }),
    pid1: currentPid1,
    workers,
    descriptors,
    markers: {
      opening: 0,
      ready: 0,
      relevantLinesSha256: sha256(Buffer.alloc(0)),
    },
  };
}

function sealFrame(frame) {
  const body = structuredClone(frame);
  delete body.digestSha256;
  return { ...body, digestSha256: sha256Canonical(body) };
}

function framesFor({
  matches = [deployment()],
  rows = matches.map((match) => ({
    containerId: match.container.id,
    state: match.container.state,
  })),
  devicePresent = true,
} = {}) {
  const common = {
    complete: true,
    host: {
      hostname: 'fixture-host',
      bootId: 'fixture-boot',
      osRelease: JSON.stringify({
        id: 'fixture',
        versionId: '1',
        prettyName: 'Fixture Linux',
      }),
    },
    device: {
      complete: true,
      present: devicePresent,
      identity: devicePresent
        ? {
            serial: 'A00SA5492OQMLF',
            vendorId: '0fd9',
            productId: '0080',
            epoch: epoch(),
          }
        : null,
    },
    deploymentInventory: {
      complete: true,
      exact: true,
      selector: {
        imageReference: H045_ACCEPTED_IMAGE_REFERENCE,
        imageId: H045_ACCEPTED_IMAGE_ID,
      },
      rows,
      matches,
    },
  };
  return [
    sealFrame({
      id: 'frame-1',
      startedAt: '2026-07-27T03:00:10.000Z',
      endedAt: '2026-07-27T03:00:10.900Z',
      startedMonotonicNs: '200000000000',
      endedMonotonicNs: '200900000000',
      observationCutoff: {
        at: '2026-07-27T03:00:10.800Z',
        monotonicNs: '200800000000',
      },
      ...structuredClone(common),
      auditBinding: {
        commandReceiptIndexes: [0, 1, 2, 3, 4],
        filesystemReceiptIndexes: [0],
      },
    }),
    sealFrame({
      id: 'frame-2',
      startedAt: '2026-07-27T03:00:10.900Z',
      endedAt: '2026-07-27T03:00:11.800Z',
      startedMonotonicNs: '200900000000',
      endedMonotonicNs: '201800000000',
      observationCutoff: {
        at: '2026-07-27T03:00:11.700Z',
        monotonicNs: '201700000000',
      },
      ...structuredClone(common),
      auditBinding: {
        commandReceiptIndexes: [5, 6, 7, 8, 9],
        filesystemReceiptIndexes: [1],
      },
    }),
  ];
}

const PROTECTED_MAIN_COMMIT = 'e7c9406dc75d6d8c9cb771d9d62d4fd1359b975d';
const SOURCE_CONTRACT_COMMIT = '2dc13d02f3d054fe54cb253869134c872e965601';
const DOCKER_ENDPOINT = 'unix:///var/run/docker.sock';
const DOCKER_VERSION_FORMAT =
  '{"Client":{"Version":{{json .Client.Version}},"ApiVersion":{{json .Client.APIVersion}}},' +
  '"Server":{"Version":{{json .Server.Version}},"ApiVersion":{{json .Server.APIVersion}}}}';
const DOCKER_PS_FORMAT = '{"ID":{{json .ID}},"State":{{json .State}}}';
const DOCKER_INSPECT_FORMAT =
  '{"Id":{{json .Id}},"Image":{{json .Image}},"State":{' +
  '"Status":{{json .State.Status}},"Running":{{json .State.Running}},' +
  '"Pid":{{json .State.Pid}},"StartedAt":{{json .State.StartedAt}}},' +
  '"RestartCount":{{json .RestartCount}},' +
  '"CgroupnsMode":{{json .HostConfig.CgroupnsMode}}}';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function environmentPolicy() {
  return {
    mode: 'closed-fixed',
    inheritedKeys: [],
    fixed: {
      DOCKER_CONFIG: '/nonexistent/overlaykit-h045-docker-config',
      GIT_CONFIG_COUNT: '0',
      GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_CONFIG_NOSYSTEM: '1',
      LANG: 'C',
      LC_ALL: 'C',
    },
  };
}

function outputReceipt(text = '') {
  const bytes = Buffer.from(text, 'utf8');
  return {
    encoding: 'utf8',
    text,
    base64: bytes.toString('base64'),
    byteLength: bytes.byteLength,
    lineCount:
      text === ''
        ? 0
        : text.endsWith('\n')
          ? text.slice(0, -1).split('\n').length
          : text.split('\n').length,
    sha256: sha256(bytes),
  };
}

function commandSpecs(observedFrames) {
  const specs = [
    {
      kind: 'git',
      observerKind: 'gitRevParse',
      executable: 'git',
      args: ['rev-parse', 'HEAD'],
    },
    {
      kind: 'git',
      observerKind: 'gitMergeBaseAncestor',
      executable: 'git',
      args: ['merge-base', '--is-ancestor', PROTECTED_MAIN_COMMIT, 'HEAD'],
    },
    {
      kind: 'git',
      observerKind: 'gitMergeBaseAncestor',
      executable: 'git',
      args: ['merge-base', '--is-ancestor', SOURCE_CONTRACT_COMMIT, 'HEAD'],
    },
    {
      kind: 'git',
      observerKind: 'gitRemoteGetUrl',
      executable: 'git',
      args: ['remote', 'get-url', 'origin'],
    },
    {
      kind: 'lsusb',
      executable: 'lsusb',
      args: [],
      frames: observedFrames,
    },
    {
      kind: 'dockerVersion',
      executable: 'docker',
      args: ['--host', DOCKER_ENDPOINT, 'version', '--format', DOCKER_VERSION_FORMAT],
    },
  ];
  for (const frame of observedFrames) {
    const indexes = [];
    const add = (spec) => {
      indexes.push(specs.length);
      specs.push({ ...spec, frame });
    };
    add({
      kind: 'dockerPs',
      executable: 'docker',
      args: [
        '--host',
        DOCKER_ENDPOINT,
        'ps',
        '--all',
        '--no-trunc',
        '--filter',
        `ancestor=${H045_ACCEPTED_IMAGE_ID}`,
        '--format',
        DOCKER_PS_FORMAT,
      ],
      phase: 'before',
    });
    const rows = frame.deploymentInventory.rows;
    const selected = frame.deploymentInventory.matches[0];
    if (rows.length === 1) {
      add({
        kind: 'dockerInspect',
        executable: 'docker',
        args: [
          '--host',
          DOCKER_ENDPOINT,
          'inspect',
          '--format',
          DOCKER_INSPECT_FORMAT,
          rows[0].containerId,
        ],
        phase: 'before',
      });
      if (selected?.container.state === 'running') {
        add({
          kind: 'dockerLogs',
          executable: 'docker',
          args: [
            '--host',
            DOCKER_ENDPOINT,
            'logs',
            '--timestamps',
            '--since',
            '2026-07-27T03:00:00.000Z',
            '--until',
            frame.observationCutoff.at,
            rows[0].containerId,
          ],
          phase: 'after',
        });
      }
    }
    frame.auditBinding.commandReceiptIndexes = indexes;
  }
  return specs;
}

function commandStdout(spec) {
  if (spec.observerKind === 'gitRevParse') return `${SOURCE_CONTRACT_COMMIT}\n`;
  if (spec.observerKind === 'gitRemoteGetUrl') {
    return 'https://github.com/OverlayKit/companion-module-overlaykit-server.git\n';
  }
  if (spec.kind === 'lsusb') {
    const frame = spec.frames.find((entry) => entry.device.present);
    if (frame === undefined) return '';
    const epoch = frame.device.identity.epoch;
    return (
      `Bus ${epoch.busNumber.padStart(3, '0')} ` +
      `Device ${epoch.deviceNumber.padStart(3, '0')}: ` +
      'ID 0fd9:0080 Elgato Stream Deck MK.2\n'
    );
  }
  if (spec.kind === 'dockerVersion') {
    return (
      JSON.stringify({
        Client: { Version: '28.0.0', ApiVersion: '1.48' },
        Server: { Version: '28.0.0', ApiVersion: '1.48' },
      }) + '\n'
    );
  }
  if (spec.kind === 'dockerPs') {
    return (
      spec.frame.deploymentInventory.rows
        .map((row) => JSON.stringify({ ID: row.containerId, State: row.state }))
        .join('\n') + (spec.frame.deploymentInventory.rows.length === 0 ? '' : '\n')
    );
  }
  if (spec.kind === 'dockerInspect') {
    const row = spec.frame.deploymentInventory.rows[0];
    const selected = spec.frame.deploymentInventory.matches[0];
    const running = selected?.container.state === 'running';
    return (
      JSON.stringify({
        Id: row.containerId,
        Image: H045_ACCEPTED_IMAGE_ID,
        State: {
          Status: row.state,
          Running: running,
          Pid: running ? selected.lifecycle.hostPid : 0,
          StartedAt: running ? selected.lifecycle.startedAt : '0001-01-01T00:00:00Z',
        },
        RestartCount: running ? selected.lifecycle.restartCount : 0,
        CgroupnsMode: running ? selected.lifecycle.cgroupNamespaceMode : 'private',
      }) + '\n'
    );
  }
  return '';
}

function commandReceipts(observedFrames) {
  const ordinals = new Map();
  return commandSpecs(observedFrames).map((spec, index) => {
    const ordinalKey = spec.kind === 'git' ? spec.observerKind : spec.kind;
    const ordinal = (ordinals.get(ordinalKey) ?? 0) + 1;
    ordinals.set(ordinalKey, ordinal);
    const frame = spec.frame;
    const afterCutoff = spec.phase === 'after';
    const wall =
      frame === undefined
        ? '2026-07-27T03:00:09.000Z'
        : afterCutoff
          ? frame.observationCutoff.at
          : frame.startedAt;
    const monotonic =
      frame === undefined
        ? `${199000000000 + index}`
        : afterCutoff
          ? frame.observationCutoff.monotonicNs
          : `${BigInt(frame.startedMonotonicNs) + BigInt(index + 1)}`;
    return {
      index,
      kind: spec.kind,
      ...(spec.observerKind === undefined ? {} : { observerKind: spec.observerKind }),
      ordinal,
      executable: spec.executable,
      args: spec.args,
      startedAt: wall,
      endedAt: wall,
      startedMonotonicNs: monotonic,
      endedMonotonicNs: monotonic,
      durationNs: '0',
      limits: {
        maxBufferBytes: 4 * 1024 * 1024,
        timeoutMs: null,
        overflow: 'drain-without-signal',
      },
      environmentPolicy: environmentPolicy(),
      exitCode: 0,
      signal: null,
      stdout: outputReceipt(commandStdout(spec)),
      stderr: outputReceipt(),
      cardinality: {
        global: index + 1,
        kind: ordinal,
      },
      errorCode: null,
    };
  });
}

function filesystemStat(overrides = {}) {
  return {
    stDev: '7',
    inode: '4001',
    ctimeNs: '1900000000000000000',
    mode: '0660',
    uid: 0,
    gid: 1002,
    rdev: '61696',
    rdevHex: 'f1:0',
    major: 241,
    minor: 0,
    isCharacterDevice: true,
    isSymbolicLink: false,
    ...overrides,
  };
}

function descriptorEvidence(descriptor = '20') {
  return {
    descriptor,
    target: '/dev/hidraw0',
    lstat: filesystemStat({
      inode: '5001',
      mode: '0777',
      rdev: '0',
      rdevHex: '0:0',
      major: 0,
      isCharacterDevice: false,
      isSymbolicLink: true,
    }),
    stat: filesystemStat(),
  };
}

function nonCharacterDescriptorEvidence({
  descriptor = '9',
  target = 'socket:[4242]',
  targetMajor = false,
} = {}) {
  return {
    descriptor,
    target,
    lstat: filesystemStat({
      inode: '5002',
      mode: '0777',
      rdev: '0',
      rdevHex: '0:0',
      major: 0,
      isCharacterDevice: false,
      isSymbolicLink: true,
    }),
    stat: filesystemStat({
      inode: '6002',
      mode: '0600',
      ...(targetMajor
        ? {}
        : {
            rdev: '0',
            rdevHex: '0:0',
            major: 0,
          }),
      isCharacterDevice: false,
    }),
  };
}

function procStatText(pid, ppid, startTicks) {
  return `${pid} (fixture) S ${[
    String(ppid),
    ...Array.from({ length: 17 }, () => '0'),
    String(startTicks),
  ].join(' ')}\n`;
}

function procStatusText({ pid, uid, gid, groups }) {
  return [
    'Name:\tfixture',
    `Uid:\t${uid}\t${uid}\t${uid}\t${uid}`,
    `Gid:\t${gid}\t${gid}\t${gid}\t${gid}`,
    `Groups:\t${groups.join(' ')}`,
    `NSpid:\t${pid}`,
    '',
  ].join('\n');
}

function fixtureDevice(frame) {
  const identity = frame.device.identity;
  return {
    name: 'hidraw0',
    serial: identity.serial,
    busNumber: identity.epoch.busNumber,
    deviceNumber: identity.epoch.deviceNumber,
    usbDevicePath: identity.epoch.usbDevicePath,
    usbDev: identity.epoch.usbDev,
    hidDevicePath: identity.epoch.hidDevicePath,
    devicePath: identity.epoch.devicePath,
    stat: filesystemStat(),
  };
}

function conflictingDevice() {
  return {
    name: 'hidraw1',
    serial: 'B0000000000000',
    busNumber: '1',
    deviceNumber: '43',
    usbDevicePath: '3',
    usbDev: '189:42',
    hidDevicePath: '/sys/devices/pci0000:00/usb1/1-3/0003:0FD9:0080.0043',
    devicePath: '/dev/hidraw1',
    stat: filesystemStat({ inode: '4002' }),
  };
}

function filesystemSpecs(frame, { rawDescriptors = null, extraDevices = [] } = {}) {
  const devices = [...(frame.device.present ? [fixtureDevice(frame)] : []), ...extraDevices];
  const specs = [
    ['readFileSync', '/etc/os-release', 'ID=fixture\nVERSION_ID=1\nPRETTY_NAME="Fixture Linux"\n'],
    ['readFileSync', '/proc/sys/kernel/random/boot_id', 'fixture-boot\n'],
    ['readFileSync', '/proc/sys/kernel/hostname', 'fixture-host\n'],
    ['readdirSync', '/sys/class/hidraw', devices.map((entry) => entry.name)],
  ];
  for (const device of devices) {
    const classPath = `/sys/class/hidraw/${device.name}`;
    const ancestorPath = device.hidDevicePath;
    specs.push(
      ['realpathSync', `${classPath}/device`, ancestorPath],
      [
        'readFileSync',
        `${classPath}/device/uevent`,
        `HID_ID=0003:00000FD9:00000080\nHID_UNIQ=${device.serial}\n`,
      ],
      ['readFileSync', `${classPath}/dev`, `${device.stat.major}:${device.stat.minor}\n`],
      ['statSync', device.devicePath, device.stat],
      ['readFileSync', `${ancestorPath}/idVendor`, '0fd9\n'],
      ['readFileSync', `${ancestorPath}/idProduct`, '0080\n'],
      ['readFileSync', `${ancestorPath}/serial`, `${device.serial}\n`],
      ['readFileSync', `${ancestorPath}/manufacturer`, 'Elgato\n'],
      ['readFileSync', `${ancestorPath}/product`, 'Stream Deck MK.2\n'],
      ['readFileSync', `${ancestorPath}/busnum`, `${device.busNumber}\n`],
      ['readFileSync', `${ancestorPath}/devnum`, `${device.deviceNumber}\n`],
      ['readFileSync', `${ancestorPath}/devpath`, `${device.usbDevicePath}\n`],
      ['statSync', device.devicePath, device.stat]
    );
  }
  for (const device of devices) {
    const lstat = device.lstat ?? device.stat;
    specs.push(
      ['lstatSync', device.devicePath, lstat],
      ['statSync', device.devicePath, device.stat]
    );
    if (lstat.isSymbolicLink) {
      specs.push(['readlinkSync', device.devicePath, device.linkTarget]);
    }
  }
  for (const device of devices.filter((entry) => entry.serial === 'A00SA5492OQMLF')) {
    specs.push(['readFileSync', `${device.hidDevicePath}/dev`, `${device.usbDev}\n`]);
  }
  const selected =
    frame.deploymentInventory.rows.length === 1 ? frame.deploymentInventory.matches[0] : null;
  if (selected?.container.state === 'running' && selected.lifecycle !== null) {
    const procRoot = `/proc/${selected.lifecycle.hostPid}/root/proc`;
    const rawPid1 =
      selected.pid1 === null
        ? []
        : [
            {
              pid: 1,
              startTicks: selected.pid1.startTicks,
              ppid: 0,
              uid: 0,
              gid: 0,
              groups: [0],
              cmdline: ['/app/node-runtimes/main/bin/node', '/app/main.js'],
              cgroup: selected.pid1.cgroup,
              pidNamespace: selected.pid1.pidNamespace,
              mountNamespace: selected.pid1.mountNamespace,
            },
          ];
    const processes = [...rawPid1, ...selected.workers];
    const processEntries = processes.map((entry) => String(entry.pid));
    specs.push(['readdirSync', procRoot, processEntries]);
    for (const process of processes) {
      const directory = `${procRoot}/${process.pid}`;
      specs.push(
        [
          'readFileSync',
          `${directory}/stat`,
          procStatText(process.pid, process.ppid, process.startTicks),
        ],
        ['readFileSync', `${directory}/status`, procStatusText(process)],
        ['readFileSync', `${directory}/cmdline`, `${process.cmdline.join('\u0000')}\u0000`],
        ['readFileSync', `${directory}/cgroup`, `${process.cgroup}\n`],
        ['readlinkSync', `${directory}/ns/pid`, process.pidNamespace],
        ['readlinkSync', `${directory}/ns/mnt`, process.mountNamespace]
      );
    }
    specs.push(['readdirSync', procRoot, processEntries]);
    const descriptors = rawDescriptors ?? selected.descriptors;
    for (const [workerIndex, entry] of selected.workers.entries()) {
      if (!frame.device.present) continue;
      const fdPath = `${procRoot}/${entry.pid}/fd`;
      const workerDescriptors = workerIndex === 0 ? descriptors : [];
      specs.push([
        'readdirSync',
        fdPath,
        workerDescriptors.map((descriptor) => descriptor.descriptor),
      ]);
      for (const descriptor of workerDescriptors) {
        const descriptorPath = `${fdPath}/${descriptor.descriptor}`;
        specs.push(
          ['lstatSync', descriptorPath, descriptor.lstat],
          ['readlinkSync', descriptorPath, descriptor.target],
          ['statSync', descriptorPath, descriptor.stat]
        );
      }
      specs.push([
        'readdirSync',
        fdPath,
        workerDescriptors.map((descriptor) => descriptor.descriptor),
      ]);
    }
    specs.push([
      'readFileSync',
      `/proc/${selected.lifecycle.hostPid}/cgroup`,
      `${selected.lifecycle.hostCgroup}\n`,
    ]);
  }
  return specs;
}

function filesystemResult(operation, value) {
  if (operation === 'readFileSync') {
    const bytes = Buffer.from(value, 'utf8');
    return {
      cardinality: 1,
      byteLength: bytes.byteLength,
      bytes: {
        encoding: 'base64',
        base64: bytes.toString('base64'),
        byteLength: bytes.byteLength,
        sha256: sha256(bytes),
      },
      encoding: 'utf8',
      text: value,
      sha256: sha256(bytes),
    };
  }
  if (operation === 'readdirSync') {
    return {
      entries: value,
      cardinality: value.length,
      sha256: sha256(Buffer.from(JSON.stringify(value), 'utf8')),
    };
  }
  if (operation === 'realpathSync' || operation === 'readlinkSync') {
    return {
      value,
      cardinality: 1,
      sha256: sha256(Buffer.from(value, 'utf8')),
    };
  }
  return {
    cardinality: 1,
    metadata: value,
    sha256: sha256(Buffer.from(JSON.stringify(value), 'utf8')),
  };
}

function filesystemReceipts(
  observedFrames,
  { rawDescriptorsByFrame = [], extraDevicesByFrame = [] } = {}
) {
  const receipts = [];
  const ordinals = new Map();
  for (const [frameIndex, frame] of observedFrames.entries()) {
    const indexes = [];
    const definitions = filesystemSpecs(frame, {
      rawDescriptors: rawDescriptorsByFrame[frameIndex] ?? null,
      extraDevices: extraDevicesByFrame[frameIndex] ?? [],
    });
    for (const [operation, path, value] of definitions) {
      const index = receipts.length;
      const ordinal = (ordinals.get(operation) ?? 0) + 1;
      ordinals.set(operation, ordinal);
      const monotonic = `${BigInt(frame.startedMonotonicNs) + BigInt(100 + indexes.length)}`;
      receipts.push({
        index,
        operation,
        path,
        startedAt: frame.startedAt,
        endedAt: frame.startedAt,
        startedMonotonicNs: monotonic,
        endedMonotonicNs: monotonic,
        durationNs: '0',
        disposition: 'observed',
        result: filesystemResult(operation, value),
        errorCode: null,
        cardinality: {
          global: index + 1,
          operation: ordinal,
        },
      });
      indexes.push(index);
    }
    frame.auditBinding.filesystemReceiptIndexes = indexes;
  }
  return receipts;
}

function capabilityAudit(observedFrames, filesystemOptions = {}) {
  const commandReceiptsValue = commandReceipts(observedFrames);
  const filesystemReceiptsValue = filesystemReceipts(observedFrames, filesystemOptions);
  for (const frame of observedFrames) reseal(frame);
  const allowedProcessCounts = Object.fromEntries(
    ['git', 'lsusb', 'dockerVersion', 'dockerPs', 'dockerInspect', 'dockerLogs'].map((kind) => [
      kind,
      commandReceiptsValue.filter((receipt) => receipt.kind === kind).length,
    ])
  );
  return {
    mode: 'live-readonly-dynamic-acquisition-capability-bounded',
    environmentPolicy: environmentPolicy(),
    commandReceipts: commandReceiptsValue,
    filesystemReceipts: filesystemReceiptsValue,
    allowedProcessCounts,
    commandCount: commandReceiptsValue.length,
    filesystemReceiptCount: filesystemReceiptsValue.length,
    complete: true,
    exact: true,
    frameCount: 2,
    lsusbCount: 1,
    unrecordedObservationCount: 0,
    prohibitedCounts: {
      externalNetwork: 0,
      unrestrictedContainerInventory: 0,
      dockerExec: 0,
      hidrawOpen: 0,
      hidrawRead: 0,
      hidrawWrite: 0,
      hidrawIoctl: 0,
      signal: 0,
      lifecycleMutation: 0,
      configurationMutation: 0,
      mountMutation: 0,
      cgroupMutation: 0,
      sysfsWrite: 0,
      productionMutation: 0,
    },
  };
}

function canonicalInput() {
  const observedFrames = framesFor();
  return {
    frames: observedFrames,
    capabilityAudit: capabilityAudit(observedFrames),
    sourceAdmissionExact: true,
  };
}

function reseal(frame) {
  Object.assign(frame, sealFrame(frame));
}

function classifyMutation(mutate) {
  const input = canonicalInput();
  const framesBefore = sha256Canonical(input.frames);
  const auditBefore = sha256Canonical(input.capabilityAudit);
  mutate(input);
  if (
    sha256Canonical(input.capabilityAudit) === auditBefore &&
    sha256Canonical(input.frames) !== framesBefore &&
    input.frames.every(frameExactShape)
  ) {
    input.capabilityAudit = capabilityAudit(input.frames);
  }
  return classifyDynamicFrames(input);
}

function assertDisposition(result, disposition, reasonCode) {
  assert.equal(classificationExactShape(result), true);
  assert.equal(result.disposition, disposition);
  assert.equal(result.reasonCode, reasonCode);
  assert.deepEqual(result.receipts, disposition === 'candidate' ? result.receipts : []);
}

test('emits one authority-void cutoff-only dynamic tuple for two exact stable frames', () => {
  const result = classifyDynamicFrames(canonicalInput());
  assert.equal(classificationExactShape(result), true);
  assert.equal(result.disposition, 'candidate');
  assert.equal(result.stage, 'dynamic-readonly-acquisition');
  assert.equal(result.reasonCode, 'cutoff-bound-dynamic-tuple');
  assert.deepEqual(Object.keys(result.predicates), H045_PREDICATE_KEYS);
  assert.equal(Object.values(result.predicates).every(Boolean), true);
  assert.equal(result.receipts.length, 1);

  const receipt = result.receipts[0];
  assert.equal(receipt.authority, 'none');
  assert.equal(receipt.action, null);
  assert.equal(receipt.authorizesAction, false);
  assert.equal(receipt.validAtCutoffOnly, true);
  assert.equal(receipt.revalidatedAtCutoff, true);
  assert.equal(receipt.requiresRevalidation, true);
  assert.equal(receipt.cutoff.monotonicNs, '201700000000');
  assert.equal(receipt.exposure.milliseconds, 1700);
  assert.equal(receipt.identity.deployment.container.id, CONTAINER_ID);
  assert.equal(receipt.identity.deployment.worker.pid, 73);
  assert.deepEqual(receipt.identity.deployment.descriptors, []);
  assert.deepEqual(receipt.sources.acceptedImage, {
    imageReference: H045_ACCEPTED_IMAGE_REFERENCE,
    imageId: H045_ACCEPTED_IMAGE_ID,
  });
  const { receiptSha256, ...body } = receipt;
  assert.equal(receiptSha256, sha256Canonical(body));
  assert.equal(
    /historical|signalTarget|executableAction|retry|continuity|futureValidity/u.test(
      JSON.stringify(receipt)
    ),
    false
  );
});

test('is deterministic and does not mutate admitted input', () => {
  const input = canonicalInput();
  const before = sha256Canonical(input);
  const first = classifyDynamicFrames(input);
  const second = classifyDynamicFrames(input);
  assert.deepEqual(second, first);
  assert.equal(sha256Canonical(input), before);
});

test('accepts a different coherent current tuple without any historical volatile identity input', () => {
  const input = canonicalInput();
  const newContainerId = 'e'.repeat(64);
  for (const frame of input.frames) {
    const selected = frame.deploymentInventory.matches[0];
    selected.container.id = newContainerId;
    frame.deploymentInventory.rows[0].containerId = newContainerId;
    selected.lifecycle.containerId = newContainerId;
    selected.lifecycle.hostCgroup = `0::/system.slice/docker-${newContainerId}.scope`;
    selected.lifecycle.hostPid = 9001;
    selected.pid1.hostPid = 9001;
    selected.lifecycle.pid1StartTicks = 8800;
    selected.pid1.startTicks = 8800;
    selected.workers[0].pid = 501;
    selected.workers[0].startTicks = 8900;
    selected.workers[0].parentStartTicks = 8800;
    reseal(frame);
  }
  input.capabilityAudit = capabilityAudit(input.frames);
  assert.deepEqual(Object.keys(input).sort(), [
    'capabilityAudit',
    'frames',
    'sourceAdmissionExact',
  ]);
  const result = classifyDynamicFrames(input);
  assert.equal(result.disposition, 'candidate');
  assert.equal(result.receipts[0].identity.deployment.container.id, newContainerId);
  assert.equal(result.receipts[0].identity.deployment.worker.pid, 501);
});

test('validates exact frame digests independently', () => {
  const input = canonicalInput();
  assert.equal(frameExactShape(input.frames[0]), true);
  input.frames[0].host.hostname = 'tampered';
  assert.equal(frameExactShape(input.frames[0]), false);
});

for (const [label, mutate, reasonCode] of [
  [
    'zero accepted-image matches',
    (input) => {
      for (const frame of input.frames) {
        frame.deploymentInventory.rows = [];
        frame.deploymentInventory.matches = [];
        reseal(frame);
      }
    },
    'accepted-image-deployment-absent',
  ],
  [
    'stable non-running deployment',
    (input) => {
      for (const frame of input.frames) {
        const selected = frame.deploymentInventory.matches[0];
        selected.container.state = 'exited';
        frame.deploymentInventory.rows[0].state = 'exited';
        selected.lifecycle = null;
        selected.pid1 = null;
        selected.workers = [];
        reseal(frame);
      }
    },
    'deployment-not-running',
  ],
  [
    'device absent',
    (input) => {
      for (const frame of input.frames) {
        frame.device.present = false;
        frame.device.identity = null;
        reseal(frame);
      }
    },
    'device-absent',
  ],
  [
    'stable worker absence',
    (input) => {
      for (const frame of input.frames) {
        frame.deploymentInventory.matches[0].workers = [];
        reseal(frame);
      }
    },
    'surface-worker-absent',
  ],
  [
    'current descriptor present',
    (input) => {
      for (const frame of input.frames) {
        frame.deploymentInventory.matches[0].descriptors = [descriptorEvidence('20')];
        reseal(frame);
      }
    },
    'current-descriptor-present',
  ],
]) {
  test(`withholds complete stable non-eligibility: ${label}`, () => {
    const result = classifyMutation(mutate);
    assertDisposition(result, 'withheld', reasonCode);
  });
}

for (const [label, mutate, stage, reasonCode] of [
  [
    'source admission false',
    (input) => {
      input.sourceAdmissionExact = false;
    },
    'source-admission',
    'source-admission-inexact',
  ],
  [
    'historical volatile ID supplied as an extra input',
    (input) => {
      input.historicalContainerId = 'f'.repeat(64);
    },
    'source-admission',
    'source-admission-inexact',
  ],
  [
    'only one frame',
    (input) => {
      input.frames.pop();
    },
    'frame-admission',
    'two-complete-frames-required',
  ],
  [
    'incomplete frame',
    (input) => {
      input.frames[1].complete = false;
      reseal(input.frames[1]);
    },
    'frame-admission',
    'incomplete-or-invalid-live-frame',
  ],
  [
    'inexact deployment inventory',
    (input) => {
      input.frames[1].deploymentInventory.exact = false;
      reseal(input.frames[1]);
    },
    'frame-admission',
    'incomplete-or-invalid-live-frame',
  ],
  [
    'frame digest tampering',
    (input) => {
      input.frames[1].digestSha256 = 'b'.repeat(64);
    },
    'frame-admission',
    'incomplete-or-invalid-live-frame',
  ],
  [
    'selector broadening by container name',
    (input) => {
      input.frames[1].deploymentInventory.selector.containerName = 'companion';
      reseal(input.frames[1]);
    },
    'frame-admission',
    'incomplete-or-invalid-live-frame',
  ],
  [
    'accepted image selector mismatch',
    (input) => {
      for (const frame of input.frames) {
        frame.deploymentInventory.selector.imageId = `sha256:${'b'.repeat(64)}`;
        reseal(frame);
      }
    },
    'selector-boundary',
    'accepted-image-selector-inexact',
  ],
  [
    'accepted image match mismatch',
    (input) => {
      for (const frame of input.frames) {
        const selected = frame.deploymentInventory.matches[0];
        selected.container.imageId = `sha256:${'b'.repeat(64)}`;
        selected.lifecycle.imageId = `sha256:${'b'.repeat(64)}`;
        reseal(frame);
      }
    },
    'selector-boundary',
    'accepted-image-match-inexact',
  ],
  [
    'multiple accepted-image deployments',
    (input) => {
      const otherId = 'd'.repeat(64);
      for (const frame of input.frames) {
        frame.deploymentInventory.rows.push({
          containerId: otherId,
          state: 'running',
        });
        frame.deploymentInventory.matches = [];
        reseal(frame);
      }
    },
    'deployment-selection',
    'multiple-image-matches',
  ],
  [
    'one raw row without one exact inspected match',
    (input) => {
      for (const frame of input.frames) {
        frame.deploymentInventory.matches = [];
        reseal(frame);
      }
    },
    'capability-audit',
    'capability-audit-incomplete-or-inexact',
  ],
  [
    'fabricated inspected match without a raw row',
    (input) => {
      for (const frame of input.frames) {
        frame.deploymentInventory.rows = [];
        reseal(frame);
      }
    },
    'capability-audit',
    'capability-audit-incomplete-or-inexact',
  ],
  [
    'deployment presence drift',
    (input) => {
      input.frames[1].deploymentInventory.rows = [];
      input.frames[1].deploymentInventory.matches = [];
      reseal(input.frames[1]);
    },
    'live-drift',
    'deployment-presence-drift',
  ],
  [
    'container identity drift',
    (input) => {
      const selected = input.frames[1].deploymentInventory.matches[0];
      const otherId = 'd'.repeat(64);
      selected.container.id = otherId;
      input.frames[1].deploymentInventory.rows[0].containerId = otherId;
      selected.lifecycle.containerId = otherId;
      selected.lifecycle.hostCgroup = `0::/system.slice/docker-${otherId}.scope`;
      reseal(input.frames[1]);
    },
    'live-drift',
    'deployment-row-drift',
  ],
  [
    'container state drift',
    (input) => {
      input.frames[1].deploymentInventory.matches[0].container.state = 'paused';
      input.frames[1].deploymentInventory.rows[0].state = 'paused';
      reseal(input.frames[1]);
    },
    'live-drift',
    'deployment-row-drift',
  ],
  [
    'PID 1 drift',
    (input) => {
      const selected = input.frames[1].deploymentInventory.matches[0];
      selected.pid1.startTicks += 1;
      selected.lifecycle.pid1StartTicks += 1;
      selected.workers[0].parentStartTicks += 1;
      reseal(input.frames[1]);
    },
    'live-drift',
    'deployment-identity-or-lifecycle-drift',
  ],
  [
    'worker ambiguity',
    (input) => {
      for (const frame of input.frames) {
        frame.deploymentInventory.matches[0].workers.push(worker({ pid: 74, startTicks: 7200 }));
        reseal(frame);
      }
    },
    'identity',
    'worker-ambiguity',
  ],
  [
    'worker presence drift',
    (input) => {
      input.frames[1].deploymentInventory.matches[0].workers = [];
      reseal(input.frames[1]);
    },
    'identity',
    'worker-presence-drift',
  ],
  [
    'worker PID reuse',
    (input) => {
      input.frames[1].deploymentInventory.matches[0].workers[0].startTicks += 1;
      reseal(input.frames[1]);
    },
    'identity',
    'worker-identity-drift',
  ],
  [
    'worker parent drift',
    (input) => {
      input.frames[1].deploymentInventory.matches[0].workers[0].parentStartTicks += 1;
      reseal(input.frames[1]);
    },
    'capability-audit',
    'capability-audit-incomplete-or-inexact',
  ],
  [
    'worker namespace drift',
    (input) => {
      const selected = input.frames[1].deploymentInventory.matches[0];
      selected.workers[0].pidNamespace = 'pid:[4026533999]';
      reseal(input.frames[1]);
    },
    'contradictory-evidence',
    'deployment-observation-contradiction',
  ],
  [
    'device epoch drift',
    (input) => {
      input.frames[1].device.identity.epoch.deviceNumber = '43';
      reseal(input.frames[1]);
    },
    'capability-audit',
    'capability-audit-incomplete-or-inexact',
  ],
  [
    'descriptor state drift',
    (input) => {
      input.frames[1].deploymentInventory.matches[0].descriptors = [descriptorEvidence('20')];
      reseal(input.frames[1]);
    },
    'live-drift',
    'descriptor-state-drift',
  ],
  [
    'marker drift',
    (input) => {
      input.frames[1].deploymentInventory.matches[0].markers.ready += 1;
      reseal(input.frames[1]);
    },
    'capability-audit',
    'capability-audit-incomplete-or-inexact',
  ],
  [
    'host drift',
    (input) => {
      input.frames[1].host.bootId = 'fixture-boot-2';
      reseal(input.frames[1]);
    },
    'capability-audit',
    'capability-audit-incomplete-or-inexact',
  ],
  [
    'frame reordering',
    (input) => {
      input.frames[1].startedAt = '2026-07-27T03:00:10.800Z';
      input.frames[1].startedMonotonicNs = '200800000000';
      reseal(input.frames[1]);
    },
    'temporal-boundary',
    'frame-order-invalid',
  ],
  [
    'exposure over five seconds',
    (input) => {
      input.frames[1].startedAt = '2026-07-27T03:00:15.000Z';
      input.frames[1].endedAt = '2026-07-27T03:00:15.200Z';
      input.frames[1].startedMonotonicNs = '205000000000';
      input.frames[1].endedMonotonicNs = '205200000000';
      input.frames[1].observationCutoff = {
        at: '2026-07-27T03:00:15.100Z',
        monotonicNs: '205100000000',
      };
      reseal(input.frames[1]);
    },
    'temporal-boundary',
    'exposure-window-exceeded',
  ],
  [
    'running deployment without PID 1',
    (input) => {
      for (const frame of input.frames) {
        const selected = frame.deploymentInventory.matches[0];
        selected.pid1 = null;
        selected.workers = [];
        reseal(frame);
      }
    },
    'capability-audit',
    'capability-audit-incomplete-or-inexact',
  ],
  [
    'environment policy drift',
    (input) => {
      input.capabilityAudit.environmentPolicy.fixed.LANG = 'en_US.UTF-8';
    },
    'capability-audit',
    'capability-audit-incomplete-or-inexact',
  ],
  [
    'capability audit inexact',
    (input) => {
      input.capabilityAudit.exact = false;
    },
    'capability-audit',
    'capability-audit-incomplete-or-inexact',
  ],
  [
    'unrecorded observation',
    (input) => {
      input.capabilityAudit.unrecordedObservationCount = 1;
    },
    'capability-audit',
    'capability-audit-incomplete-or-inexact',
  ],
  [
    'prohibited docker exec capability',
    (input) => {
      input.capabilityAudit.prohibitedCounts.dockerExec = 1;
    },
    'capability-audit',
    'prohibited-capability-observed',
  ],
  [
    'prohibited signal capability',
    (input) => {
      input.capabilityAudit.prohibitedCounts.signal = 1;
    },
    'capability-audit',
    'prohibited-capability-observed',
  ],
]) {
  test(`fails closed without a receipt: ${label}`, () => {
    const result = classifyMutation(mutate);
    assert.equal(classificationExactShape(result), true);
    assert.equal(result.disposition, 'inconclusive');
    assert.equal(result.stage, stage);
    assert.equal(result.reasonCode, reasonCode);
    assert.deepEqual(result.receipts, []);
  });
}

test('rejects the original HIGH exploit with fake minimal receipts and empty bindings', () => {
  const input = canonicalInput();
  for (const frame of input.frames) {
    frame.auditBinding = {
      commandReceiptIndexes: [],
      filesystemReceiptIndexes: [],
    };
    reseal(frame);
  }
  input.capabilityAudit.commandReceipts = [{ kind: 'lsusb' }];
  input.capabilityAudit.filesystemReceipts = [];
  input.capabilityAudit.allowedProcessCounts = {
    git: 0,
    lsusb: 1,
    dockerVersion: 0,
    dockerPs: 0,
    dockerInspect: 0,
    dockerLogs: 0,
  };
  input.capabilityAudit.commandCount = 1;
  input.capabilityAudit.filesystemReceiptCount = 0;
  const result = classifyDynamicFrames(input);
  assertDisposition(result, 'inconclusive', 'capability-audit-incomplete-or-inexact');
  assert.equal(result.stage, 'capability-audit');
});

test('binds the current device serial to ADR-0006 and rejects a regular hidraw node', () => {
  const wrongSerial = classifyMutation((input) => {
    for (const frame of input.frames) {
      frame.device.identity.serial = 'A0000000000000';
      frame.device.identity.epoch.serial = 'A0000000000000';
      reseal(frame);
    }
  });
  assertDisposition(wrongSerial, 'inconclusive', 'accepted-device-serial-inexact');
  assert.equal(wrongSerial.stage, 'identity');

  const regularNode = classifyMutation((input) => {
    for (const frame of input.frames) {
      frame.device.identity.epoch.stat.isCharacterDevice = false;
      reseal(frame);
    }
  });
  assertDisposition(regularNode, 'inconclusive', 'accepted-device-node-inexact');
  assert.equal(regularNode.stage, 'identity');
});

for (const [label, mutate] of [
  [
    'remote Docker endpoint',
    (input) => {
      input.capabilityAudit.commandReceipts.find((receipt) => receipt.kind === 'dockerPs').args[1] =
        'tcp://127.0.0.1:2375';
    },
  ],
  [
    'broadened Docker ancestor filter',
    (input) => {
      input.capabilityAudit.commandReceipts.find((receipt) => receipt.kind === 'dockerPs').args[6] =
        'ancestor=companion';
    },
  ],
  [
    'expanded Docker row projection',
    (input) => {
      input.capabilityAudit.commandReceipts.find((receipt) => receipt.kind === 'dockerPs').args[8] =
        '{{json .}}';
    },
  ],
  [
    'command output digest mismatch',
    (input) => {
      input.capabilityAudit.commandReceipts[0].stdout.sha256 = '0'.repeat(64);
    },
  ],
  [
    'command limit drift',
    (input) => {
      input.capabilityAudit.commandReceipts[0].limits.timeoutMs = 1_500;
    },
  ],
  [
    'command overflow policy drift',
    (input) => {
      input.capabilityAudit.commandReceipts[0].limits.overflow = 'kill';
    },
  ],
]) {
  test(`rejects independently audited command evidence: ${label}`, () => {
    const result = classifyMutation(mutate);
    assertDisposition(result, 'inconclusive', 'capability-audit-incomplete-or-inexact');
    assert.equal(result.stage, 'capability-audit');
  });
}

for (const [label, mutate] of [
  [
    'inherited PATH poison',
    (input) => {
      input.capabilityAudit.environmentPolicy.inheritedKeys.push('PATH');
    },
  ],
  [
    'receipt-only Docker environment poison',
    (input) => {
      input.capabilityAudit.commandReceipts[0].environmentPolicy.fixed.DOCKER_HOST =
        'tcp://127.0.0.1:2375';
    },
  ],
  [
    'receipt-only Git isolation drift',
    (input) => {
      input.capabilityAudit.commandReceipts[0].environmentPolicy.fixed.GIT_CONFIG_NOSYSTEM = '0';
    },
  ],
]) {
  test(`rejects closed child environment drift: ${label}`, () => {
    const result = classifyMutation(mutate);
    assertDisposition(result, 'inconclusive', 'capability-audit-incomplete-or-inexact');
    assert.equal(result.stage, 'capability-audit');
  });
}

test('requires canonical signal absence in both command receipts and prohibited counts', () => {
  const uncountedSignal = canonicalInput();
  uncountedSignal.capabilityAudit.commandReceipts[0].signal = 'SIGTERM';
  assertDisposition(
    classifyDynamicFrames(uncountedSignal),
    'inconclusive',
    'capability-audit-incomplete-or-inexact'
  );

  const countedSignal = canonicalInput();
  countedSignal.capabilityAudit.commandReceipts[0].signal = 'SIGTERM';
  countedSignal.capabilityAudit.prohibitedCounts.signal = 1;
  assertDisposition(
    classifyDynamicFrames(countedSignal),
    'inconclusive',
    'prohibited-capability-observed'
  );
});

test('rejects command output at the declared 4 MiB boundary plus one byte', () => {
  const input = canonicalInput();
  input.capabilityAudit.commandReceipts[0].stdout = outputReceipt('x'.repeat(4 * 1024 * 1024 + 1));
  const result = classifyDynamicFrames(input);
  assertDisposition(result, 'inconclusive', 'capability-audit-incomplete-or-inexact');
  assert.equal(result.stage, 'capability-audit');
});

test('rejects filesystem read and directory limits at boundary plus one', () => {
  const oversizedRead = canonicalInput();
  oversizedRead.capabilityAudit.filesystemReceipts[0].result = filesystemResult(
    'readFileSync',
    'x'.repeat(1024 * 1024 + 1)
  );
  assert.equal(
    classifyDynamicFrames(oversizedRead).reasonCode,
    'capability-audit-incomplete-or-inexact'
  );

  const oversizedHidraw = canonicalInput();
  const inventory = oversizedHidraw.capabilityAudit.filesystemReceipts.find(
    (receipt) => receipt.path === '/sys/class/hidraw'
  );
  inventory.result = filesystemResult(
    'readdirSync',
    Array.from({ length: 65 }, (_, index) => `hidraw${index}`)
  );
  assert.equal(
    classifyDynamicFrames(oversizedHidraw).reasonCode,
    'capability-audit-incomplete-or-inexact'
  );

  const oversizedProc = canonicalInput();
  const procInventory = oversizedProc.capabilityAudit.filesystemReceipts.find((receipt) =>
    /^\/proc\/[1-9][0-9]*\/root\/proc$/u.test(receipt.path)
  );
  procInventory.result = filesystemResult(
    'readdirSync',
    Array.from({ length: 1_025 }, (_, index) => String(index + 1))
  );
  assert.equal(
    classifyDynamicFrames(oversizedProc).reasonCode,
    'capability-audit-incomplete-or-inexact'
  );
});

test('rejects filesystem path and receipt-count limits at boundary plus one', () => {
  const oversizedPath = canonicalInput();
  oversizedPath.capabilityAudit.filesystemReceipts[0].path = `/sys/devices/usb1/${'x'.repeat(4_097)}/idVendor`;
  assert.equal(
    classifyDynamicFrames(oversizedPath).reasonCode,
    'capability-audit-incomplete-or-inexact'
  );

  const oversizedFrame = canonicalInput();
  oversizedFrame.frames[0].auditBinding.filesystemReceiptIndexes = Array.from(
    { length: 16_385 },
    (_, index) => index
  );
  reseal(oversizedFrame.frames[0]);
  assert.equal(
    classifyDynamicFrames(oversizedFrame).reasonCode,
    'capability-audit-incomplete-or-inexact'
  );

  const oversizedRun = canonicalInput();
  oversizedRun.capabilityAudit.filesystemReceipts = Array.from({ length: 32_769 }, () => ({}));
  oversizedRun.capabilityAudit.filesystemReceiptCount = 32_769;
  assert.equal(
    classifyDynamicFrames(oversizedRun).reasonCode,
    'capability-audit-incomplete-or-inexact'
  );
});

test('rejects realpath/readlink result values at the 4096-byte boundary plus one', () => {
  const ascii = 'x'.repeat(4_097);
  const multibyte = `${'é'.repeat(2_048)}a`;
  assert.equal(Buffer.byteLength(ascii, 'utf8'), 4_097);
  assert.equal(Buffer.byteLength(multibyte, 'utf8'), 4_097);
  assert.equal(multibyte.length < 4_096, true);

  for (const [operation, value] of [
    ['realpathSync', ascii],
    ['readlinkSync', multibyte],
  ]) {
    const input = canonicalInput();
    const receipt = input.capabilityAudit.filesystemReceipts.find(
      (entry) => entry.operation === operation
    );
    receipt.result = filesystemResult(operation, value);
    assertDisposition(
      classifyDynamicFrames(input),
      'inconclusive',
      'capability-audit-incomplete-or-inexact'
    );
  }
});

test('rejects dynamic command receipt reuse across frames', () => {
  const input = canonicalInput();
  input.frames[1].auditBinding.commandReceiptIndexes = [
    ...input.frames[0].auditBinding.commandReceiptIndexes,
  ];
  reseal(input.frames[1]);
  const result = classifyDynamicFrames(input);
  assertDisposition(result, 'inconclusive', 'capability-audit-incomplete-or-inexact');
  assert.equal(result.stage, 'capability-audit');
});

test('rejects a hidden Docker row present only in digest-exact raw stdout', () => {
  const input = canonicalInput();
  const receipt = input.capabilityAudit.commandReceipts.find(
    (candidate) => candidate.kind === 'dockerPs'
  );
  const hiddenRow = JSON.stringify({
    ID: 'd'.repeat(64),
    State: 'running',
  });
  receipt.stdout = outputReceipt(`${receipt.stdout.text}${hiddenRow}\n`);
  const result = classifyDynamicFrames(input);
  assertDisposition(result, 'inconclusive', 'capability-audit-incomplete-or-inexact');
  assert.equal(result.stage, 'capability-audit');
});

test('rejects raw non-running inspect lifecycle drift discarded by nullable projection', () => {
  const input = canonicalInput();
  for (const frame of input.frames) {
    frame.deploymentInventory.rows[0].state = 'exited';
    const selected = frame.deploymentInventory.matches[0];
    selected.container.state = 'exited';
    selected.lifecycle = null;
    selected.pid1 = null;
    selected.workers = [];
    selected.descriptors = [];
    reseal(frame);
  }
  input.capabilityAudit = capabilityAudit(input.frames);
  const receipt = input.capabilityAudit.commandReceipts.find(
    (candidate) => candidate.kind === 'dockerInspect'
  );
  const rawInspect = JSON.parse(receipt.stdout.text);
  rawInspect.State.StartedAt = '2026-07-27T03:00:01.000Z';
  rawInspect.RestartCount = 1;
  receipt.stdout = outputReceipt(`${JSON.stringify(rawInspect)}\n`);
  const result = classifyDynamicFrames(input);
  assertDisposition(result, 'inconclusive', 'capability-audit-incomplete-or-inexact');
  assert.equal(result.stage, 'capability-audit');
});

test('rejects projected selector drift while command receipts remain canonical', () => {
  const input = canonicalInput();
  input.frames[0].deploymentInventory.selector.imageId = `sha256:${'b'.repeat(64)}`;
  reseal(input.frames[0]);
  const result = classifyDynamicFrames(input);
  assertDisposition(result, 'inconclusive', 'accepted-image-selector-inexact');
  assert.equal(result.stage, 'selector-boundary');
});

test('rejects a coherent two-frame proc projection not supported by raw receipts', () => {
  const input = canonicalInput();
  for (const frame of input.frames) {
    const selected = frame.deploymentInventory.matches[0];
    selected.lifecycle.pid1StartTicks = 8000;
    selected.lifecycle.pidNamespace = 'pid:[4026533991]';
    selected.lifecycle.mountNamespace = 'mnt:[4026533992]';
    selected.lifecycle.cgroup = '0::/changed';
    selected.pid1.startTicks = 8000;
    selected.pid1.pidNamespace = 'pid:[4026533991]';
    selected.pid1.mountNamespace = 'mnt:[4026533992]';
    selected.pid1.cgroup = '0::/changed';
    selected.workers[0] = {
      ...selected.workers[0],
      startTicks: 8100,
      parentStartTicks: 8000,
      uid: 1001,
      gid: 1001,
      groups: [1001],
      cmdline: ['/different/node', '/app/SurfaceThread.js'],
      cgroup: '0::/changed-worker',
      pidNamespace: 'pid:[4026533991]',
      mountNamespace: 'mnt:[4026533992]',
    };
    reseal(frame);
  }
  const result = classifyDynamicFrames(input);
  assertDisposition(result, 'inconclusive', 'capability-audit-incomplete-or-inexact');
  assert.equal(result.stage, 'capability-audit');
});

test('rejects a coherent host cgroup projection not supported by raw receipts', () => {
  const input = canonicalInput();
  for (const frame of input.frames) {
    frame.deploymentInventory.matches[0].lifecycle.hostCgroup = '0::/changed';
    reseal(frame);
  }
  const result = classifyDynamicFrames(input);
  assertDisposition(result, 'inconclusive', 'capability-audit-incomplete-or-inexact');
  assert.equal(result.stage, 'capability-audit');
});

test('rejects normalized descriptor absence when raw FD evidence shows the target', () => {
  const input = canonicalInput();
  const hidden = descriptorEvidence('20');
  input.capabilityAudit = capabilityAudit(input.frames, {
    rawDescriptorsByFrame: [[hidden], [hidden]],
  });
  const result = classifyDynamicFrames(input);
  assertDisposition(result, 'inconclusive', 'capability-audit-incomplete-or-inexact');
  assert.equal(result.stage, 'capability-audit');
});

test('projects an audited character FD that matches only the accepted target major', () => {
  const input = canonicalInput();
  const hidden = {
    ...descriptorEvidence('21'),
    target: '/dev/overlaykit-alias',
  };
  input.capabilityAudit = capabilityAudit(input.frames, {
    rawDescriptorsByFrame: [[hidden], [hidden]],
  });
  const result = classifyDynamicFrames(input);
  assertDisposition(result, 'inconclusive', 'capability-audit-incomplete-or-inexact');
  assert.equal(result.stage, 'capability-audit');
});

for (const [label, rawDescriptor] of [
  ['socket FD', nonCharacterDescriptorEvidence()],
  [
    'hidraw-path non-character FD',
    nonCharacterDescriptorEvidence({
      descriptor: '10',
      target: '/dev/hidraw0',
    }),
  ],
  [
    'target-major non-character FD',
    nonCharacterDescriptorEvidence({
      descriptor: '11',
      target: 'pipe:[4242]',
      targetMajor: true,
    }),
  ],
]) {
  test(`consumes but does not project an audited ${label}`, () => {
    const input = canonicalInput();
    input.capabilityAudit = capabilityAudit(input.frames, {
      rawDescriptorsByFrame: [[rawDescriptor], [rawDescriptor]],
    });
    const result = classifyDynamicFrames(input);
    assertDisposition(result, 'candidate', 'cutoff-bound-dynamic-tuple');
    assert.equal(result.predicates.descriptorStable, true);
    assert.equal(result.predicates.descriptorAbsent, true);
    assert.equal(result.receipts.length, 1);
  });
}

test('rejects an audited FD whose lstat is not the procfs descriptor symlink', () => {
  const input = canonicalInput();
  const rawDescriptor = nonCharacterDescriptorEvidence();
  rawDescriptor.lstat.isSymbolicLink = false;
  input.capabilityAudit = capabilityAudit(input.frames, {
    rawDescriptorsByFrame: [[rawDescriptor], [rawDescriptor]],
  });
  const result = classifyDynamicFrames(input);
  assertDisposition(result, 'inconclusive', 'capability-audit-incomplete-or-inexact');
  assert.equal(result.stage, 'capability-audit');
});

test('rejects a second non-target hidraw entry reusing the accepted device number', () => {
  const input = canonicalInput();
  input.capabilityAudit = capabilityAudit(input.frames, {
    extraDevicesByFrame: [[conflictingDevice()], [conflictingDevice()]],
  });
  const result = classifyDynamicFrames(input);
  assertDisposition(result, 'inconclusive', 'capability-audit-incomplete-or-inexact');
  assert.equal(result.stage, 'capability-audit');
});

test('rejects duplicate HID uevent properties even with exact receipt digests', () => {
  const input = canonicalInput();
  const receipt = input.capabilityAudit.filesystemReceipts.find((entry) =>
    entry.path.endsWith('/device/uevent')
  );
  receipt.result = filesystemResult(
    'readFileSync',
    `${receipt.result.text}HID_UNIQ=A00SA5492OQMLF\n`
  );
  const result = classifyDynamicFrames(input);
  assertDisposition(result, 'inconclusive', 'capability-audit-incomplete-or-inexact');
  assert.equal(result.stage, 'capability-audit');
});

test('binds raw lsusb bus/device identity and serial-less exact absence', () => {
  const present = canonicalInput();
  const presentLsusb = present.capabilityAudit.commandReceipts.find(
    (receipt) => receipt.kind === 'lsusb'
  );
  presentLsusb.stdout = outputReceipt('Bus 001 Device 043: ID 0fd9:0080 Elgato Stream Deck MK.2\n');
  const mismatch = classifyDynamicFrames(present);
  assertDisposition(mismatch, 'inconclusive', 'capability-audit-incomplete-or-inexact');
  assert.equal(mismatch.stage, 'capability-audit');

  const absentFrames = framesFor({ devicePresent: false });
  const absent = {
    frames: absentFrames,
    capabilityAudit: capabilityAudit(absentFrames),
    sourceAdmissionExact: true,
  };
  const absentLsusb = absent.capabilityAudit.commandReceipts.find(
    (receipt) => receipt.kind === 'lsusb'
  );
  absentLsusb.stdout = outputReceipt('Bus 001 Device 042: ID 0fd9:0080 Elgato Stream Deck MK.2\n');
  const stale = classifyDynamicFrames(absent);
  assertDisposition(stale, 'inconclusive', 'capability-audit-incomplete-or-inexact');
  assert.equal(stale.stage, 'capability-audit');
});

test('binds parsed os-release content to the normalized host projection', () => {
  const input = canonicalInput();
  for (const frame of input.frames) {
    frame.host.osRelease = JSON.stringify({
      id: 'other',
      versionId: '1',
      prettyName: 'Other Linux',
    });
    reseal(frame);
  }
  const result = classifyDynamicFrames(input);
  assertDisposition(result, 'inconclusive', 'capability-audit-incomplete-or-inexact');
  assert.equal(result.stage, 'capability-audit');
});

for (const [label, mutate] of [
  [
    'zero lifecycle PID',
    (frame) => {
      frame.deploymentInventory.matches[0].lifecycle.hostPid = 0;
    },
  ],
  [
    'malformed namespace identity',
    (frame) => {
      frame.deploymentInventory.matches[0].workers[0].pidNamespace = 'pid:[fixture]';
    },
  ],
  [
    'contradictory rdev and major number',
    (frame) => {
      frame.device.identity.epoch.stat.major += 1;
    },
  ],
]) {
  test(`rejects structurally impossible live identity: ${label}`, () => {
    const input = canonicalInput();
    mutate(input.frames[0]);
    reseal(input.frames[0]);
    const result = classifyDynamicFrames(input);
    assertDisposition(result, 'inconclusive', 'incomplete-or-invalid-live-frame');
    assert.equal(result.stage, 'frame-admission');
  });
}

test('rejects malformed descriptor evidence before classification', () => {
  const input = canonicalInput();
  input.frames[0].deploymentInventory.matches[0].descriptors = [{ descriptor: '20' }];
  reseal(input.frames[0]);
  const result = classifyDynamicFrames(input);
  assertDisposition(result, 'inconclusive', 'incomplete-or-invalid-live-frame');
  assert.equal(result.stage, 'frame-admission');
});

for (const [label, prohibitedPath] of [
  ['shadow file', '/etc/shadow'],
  ['process environment', '/proc/4242/root/proc/73/environ'],
  ['unrelated sysfs node', '/sys/kernel/security/lockdown'],
]) {
  test(`rejects prohibited filesystem evidence: ${label}`, () => {
    const input = canonicalInput();
    input.capabilityAudit.filesystemReceipts[0].path = prohibitedPath;
    const result = classifyDynamicFrames(input);
    assertDisposition(result, 'inconclusive', 'capability-audit-incomplete-or-inexact');
    assert.equal(result.stage, 'capability-audit');
  });
}

function appendBoundFilesystemReceipt(input, path) {
  const frame = input.frames[1];
  const template =
    input.capabilityAudit.filesystemReceipts[frame.auditBinding.filesystemReceiptIndexes[0]];
  const extra = structuredClone(template);
  extra.index = input.capabilityAudit.filesystemReceipts.length;
  extra.path = path;
  extra.cardinality.global = extra.index + 1;
  extra.cardinality.operation =
    input.capabilityAudit.filesystemReceipts.filter(
      (receipt) => receipt.operation === extra.operation
    ).length + 1;
  input.capabilityAudit.filesystemReceipts.push(extra);
  input.capabilityAudit.filesystemReceiptCount += 1;
  frame.auditBinding.filesystemReceiptIndexes.push(extra.index);
  reseal(frame);
}

for (const [label, path] of [
  ['prohibited path', '/etc/shadow'],
  ['allowed-looking unrelated sysfs path', '/sys/devices/unrelated/idVendor'],
  ['allowed-looking unrelated proc path', '/proc/999/cgroup'],
]) {
  test(`rejects an extra bound digest-exact filesystem receipt: ${label}`, () => {
    const input = canonicalInput();
    appendBoundFilesystemReceipt(input, path);
    const result = classifyDynamicFrames(input);
    assertDisposition(result, 'inconclusive', 'capability-audit-incomplete-or-inexact');
    assert.equal(result.stage, 'capability-audit');
  });
}

test('classification shape rejects authority expansion and receipt tampering', () => {
  const result = classifyDynamicFrames(canonicalInput());
  result.receipts[0].authority = 'signal';
  assert.equal(classificationExactShape(result), false);

  const second = classifyDynamicFrames(canonicalInput());
  second.receipts[0].identity.deployment.worker.pid += 1;
  assert.equal(classificationExactShape(second), false);
});
