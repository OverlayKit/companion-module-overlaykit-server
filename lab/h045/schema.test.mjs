import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';
import {
  H045_ACCEPTED_IMAGE_ID,
  H045_ACCEPTED_IMAGE_REFERENCE,
  H045_ACCEPTED_PRODUCT_ID,
  H045_ACCEPTED_SERIAL_BINDING,
  H045_ACCEPTED_VENDOR_ID,
  H045_ADR_0006_SHA256,
  H045_CHG_0018_SHA256,
  H045_CHG_0019_SHA256,
  H045_CHG_0020_SHA256,
  H045_GOVERNANCE_MANIFEST_SHA256,
  H045_GOVERNANCE_PLAN_SHA256,
  H045_MANIFEST_CONTENT_HASH,
  H045_NODE_ARCH,
  H045_NODE_BINARY_BYTE_LENGTH,
  H045_NODE_BINARY_SHA256,
  H045_NODE_PLATFORM,
  H045_NODE_VERSION,
  H045_PLAN_HASH,
  H045_PROTECTED_MAIN_COMMIT,
  H045_REPOSITORY,
  H045_REQUIRED_SOURCE_PATHS,
  H045_SOURCE_CONTRACT_COMMIT,
  H045_STABLE_TARGET_INPUT,
  sourceSetSha256,
} from './admission-lib.mjs';
import { H045_PREDICATE_KEYS, classifyDynamicFrames, sha256Canonical } from './classifier-lib.mjs';

const SHA256 = 'a'.repeat(64);
const PREDECESSOR_RESERVATION_SHA256 =
  '27ee9aa2c70adb56682564c6ddc80c43cc40e6a5c5e1edacc23327648aad2f24';
const PREDECESSOR_FAILURE_SHA256 =
  '710b3b28760239f5971c961f8b0011a18c439c10a4974f548c435ff2a4507fc0';
const CONTAINER_ID = 'c'.repeat(64);
const ACCEPTED_SERIAL = 'A00SA5492OQMLF';
const CHG_0020_URL = new URL('../../.overlaykit/governance/changes/CHG-0020.json', import.meta.url);
const GOVERNANCE_MANIFEST_URL = new URL(
  '../../.overlaykit/governance/manifest.json',
  import.meta.url
);
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

const SOURCE_ADMISSION_KEYS = Object.freeze([
  'h044PublicReceiptExact',
  'h044SemanticEvidenceExact',
  'acceptedDecisionExact',
  'acceptedTargetContextExact',
  'historicalBoundaryExact',
  'chg0018Exact',
  'chg0019Exact',
  'chg0020Exact',
  'adr0006Exact',
  'repositoryRemoteExact',
  'observedHeadWellFormed',
  'protectedMainExact',
  'sourceContractExact',
  'protectedMainAncestryExact',
  'sourceContractAncestryExact',
  'runtimeBinaryExact',
  'targetInputExact',
  'governanceExact',
  'sourceSetExact',
  'sourceStable',
  'allExact',
]);

const REQUIRED_CASE_IDS = Object.freeze([
  'multiple-image-matches',
  'selector-broadening',
  'descendant-image-mismatch',
  'hidden-container-row',
  'deployment-presence-drift',
  'container-drift',
  'pid1-drift',
  'worker-ambiguity',
  'pid-reuse',
  'parent-drift',
  'namespace-drift',
  'device-absence',
  'device-epoch-drift',
  'descriptor-recovery',
  'marker-change',
  'frame-reorder',
  'exposure-over-limit',
  'missing-command-audit',
  'duplicate-receipts',
  'input-tampering',
  'source-drift',
  'environment-policy-drift',
  'prohibited-capability',
]);

const CLAIM_BOUNDARY = Object.freeze({
  proves: Object.freeze([
    'one capability-bounded dynamic read-only observation derived only from the exact accepted Companion image and MK.2 identity without a historical volatile target identifier',
    'two adjacent complete frames no more than 5000 milliseconds apart with exact image-filter cardinality, current device epoch, Docker lifecycle, PID 1, SurfaceThread, descriptor, marker, and audit receipts',
    'one cutoff-bound authority-void dynamic tuple receipt only for one stable running non-healthy deployment, or zero receipts with withheld for complete current non-eligibility',
    'fail-closed inconclusive classification for multiplicity, selector ambiguity, contradiction, inaccessible evidence, PID reuse, inter-frame drift, source drift, or incomplete audit',
    'exact audited cardinality of allowed local Git, lsusb, Docker Unix-socket, and filesystem metadata observations with zero prohibited capabilities',
  ]),
  excludes: Object.freeze([
    'validity after the second-frame cutoff, continuity from H-043, atomicity, race freedom, PID-reuse-safe action, or a closed check-action interval',
    'authorization or safety of SIGTERM, pidfd, any signal, command, restart, rescan, retry, executable action, watcher, controller, or supervisor',
    'physical disconnect or reconnect, hidraw open or I/O, Docker lifecycle mutation, namespace entry, configuration change, installation, production policy, publication, or release',
    'configuration continuity, button delivery, rendered pixels, operator perception, OBS truth, product acceptance, security, or acceptable downtime',
    'multiple-device behavior, image upgrade discovery, pre-login behavior, reboot recovery, long-outage recovery, or production recovery policy',
    'an expansion or satisfaction of accepted SPEC-0001 or SPEC-0002',
    'a successor ADR or architectural authority beyond ADR-0006',
  ]),
});

function clone(value) {
  return structuredClone(value);
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function sourceMap() {
  return H045_REQUIRED_SOURCE_PATHS.map((path) => ({
    path,
    sha256: sha256(path),
  }));
}

function sourceAdmission(exact = true) {
  return Object.fromEntries(SOURCE_ADMISSION_KEYS.map((key) => [key, exact]));
}

function deviceStat() {
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
  };
}

function deviceEpoch() {
  return {
    serial: ACCEPTED_SERIAL,
    busNumber: '1',
    deviceNumber: '42',
    usbDevicePath: '2',
    usbDev: '189:41',
    hidDevicePath: '/sys/devices/pci0000:00/usb1/1-2/1-2:1.0/0003:0FD9:0080.0042',
    devicePath: '/dev/hidraw0',
    stat: deviceStat(),
  };
}

function lifecycle() {
  return {
    containerId: CONTAINER_ID,
    imageId: H045_ACCEPTED_IMAGE_ID,
    startedAt: '2026-07-27T03:00:00.000Z',
    restartCount: 0,
    hostPid: 4242,
    pid1StartTicks: 7000,
    pidNamespace: 'pid:[4026533001]',
    mountNamespace: 'mnt:[4026533002]',
    cgroup: '0::/',
    hostCgroup: `0::/system.slice/docker-${CONTAINER_ID}.scope`,
    cgroupNamespaceMode: 'private',
  };
}

function pid1() {
  return {
    hostPid: 4242,
    startTicks: 7000,
    pidNamespace: 'pid:[4026533001]',
    mountNamespace: 'mnt:[4026533002]',
    cgroup: '0::/',
  };
}

function worker() {
  return {
    pid: 73,
    startTicks: 7100,
    ppid: 1,
    parentStartTicks: 7000,
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

function deployment() {
  return {
    complete: true,
    exact: true,
    container: {
      id: CONTAINER_ID,
      imageReference: H045_ACCEPTED_IMAGE_REFERENCE,
      imageId: H045_ACCEPTED_IMAGE_ID,
      state: 'running',
    },
    lifecycle: lifecycle(),
    pid1: pid1(),
    workers: [worker()],
    descriptors: [],
    markers: {
      opening: 0,
      ready: 0,
      relevantLinesSha256: sha256(''),
    },
  };
}

function sealFrame(frame) {
  const body = clone(frame);
  delete body.digestSha256;
  return { ...body, digestSha256: sha256Canonical(body) };
}

function reseal(frame) {
  Object.assign(frame, sealFrame(frame));
}

function frames() {
  const selected = deployment();
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
      present: true,
      identity: {
        serial: ACCEPTED_SERIAL,
        vendorId: H045_ACCEPTED_VENDOR_ID,
        productId: H045_ACCEPTED_PRODUCT_ID,
        epoch: deviceEpoch(),
      },
    },
    deploymentInventory: {
      complete: true,
      exact: true,
      selector: {
        imageReference: H045_ACCEPTED_IMAGE_REFERENCE,
        imageId: H045_ACCEPTED_IMAGE_ID,
      },
      rows: [
        {
          containerId: CONTAINER_ID,
          state: 'running',
        },
      ],
      matches: [selected],
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
      ...clone(common),
      auditBinding: {
        commandReceiptIndexes: [],
        filesystemReceiptIndexes: [],
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
      ...clone(common),
      auditBinding: {
        commandReceiptIndexes: [],
        filesystemReceiptIndexes: [],
      },
    }),
  ];
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
      args: ['merge-base', '--is-ancestor', H045_PROTECTED_MAIN_COMMIT, 'HEAD'],
    },
    {
      kind: 'git',
      observerKind: 'gitMergeBaseAncestor',
      executable: 'git',
      args: ['merge-base', '--is-ancestor', H045_SOURCE_CONTRACT_COMMIT, 'HEAD'],
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
  if (spec.observerKind === 'gitRevParse') return `${H045_SOURCE_CONTRACT_COMMIT}\n`;
  if (spec.observerKind === 'gitRemoteGetUrl') return `${H045_REPOSITORY}\n`;
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
      ...(spec.observerKind === undefined
        ? {}
        : {
            observerKind: spec.observerKind,
          }),
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

function filesystemSpecs(frame) {
  const specs = [
    ['readFileSync', '/etc/os-release', 'ID=fixture\nVERSION_ID=1\nPRETTY_NAME="Fixture Linux"\n'],
    ['readFileSync', '/proc/sys/kernel/random/boot_id', 'fixture-boot\n'],
    ['readFileSync', '/proc/sys/kernel/hostname', 'fixture-host\n'],
    ['readdirSync', '/sys/class/hidraw', frame.device.present ? ['hidraw0'] : []],
  ];
  if (frame.device.present) {
    const identity = frame.device.identity;
    const classPath = '/sys/class/hidraw/hidraw0';
    const ancestorPath = identity.epoch.hidDevicePath;
    specs.push(
      ['realpathSync', `${classPath}/device`, ancestorPath],
      [
        'readFileSync',
        `${classPath}/device/uevent`,
        `HID_ID=0003:00000FD9:00000080\nHID_UNIQ=${identity.serial}\n`,
      ],
      ['readFileSync', `${classPath}/dev`, '241:0\n'],
      ['statSync', identity.epoch.devicePath, filesystemStat()],
      ['readFileSync', `${ancestorPath}/idVendor`, '0fd9\n'],
      ['readFileSync', `${ancestorPath}/idProduct`, '0080\n'],
      ['readFileSync', `${ancestorPath}/serial`, `${identity.serial}\n`],
      ['readFileSync', `${ancestorPath}/manufacturer`, 'Elgato\n'],
      ['readFileSync', `${ancestorPath}/product`, 'Stream Deck MK.2\n'],
      ['readFileSync', `${ancestorPath}/busnum`, `${identity.epoch.busNumber}\n`],
      ['readFileSync', `${ancestorPath}/devnum`, `${identity.epoch.deviceNumber}\n`],
      ['readFileSync', `${ancestorPath}/devpath`, `${identity.epoch.usbDevicePath}\n`],
      ['statSync', identity.epoch.devicePath, filesystemStat()],
      ['lstatSync', identity.epoch.devicePath, filesystemStat()],
      ['statSync', identity.epoch.devicePath, filesystemStat()],
      ['readFileSync', `${ancestorPath}/dev`, `${identity.epoch.usbDev}\n`]
    );
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
    for (const entry of selected.workers) {
      if (!frame.device.present) continue;
      const fdPath = `${procRoot}/${entry.pid}/fd`;
      specs.push([
        'readdirSync',
        fdPath,
        selected.descriptors.map((descriptor) => descriptor.descriptor),
      ]);
      for (const descriptor of selected.descriptors) {
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
        selected.descriptors.map((descriptor) => descriptor.descriptor),
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

function filesystemReceipts(observedFrames) {
  const receipts = [];
  const ordinals = new Map();
  for (const frame of observedFrames) {
    const indexes = [];
    for (const [operation, path, value] of filesystemSpecs(frame)) {
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

function capabilityAudit(observedFrames) {
  const commands = commandReceipts(observedFrames);
  const files = filesystemReceipts(observedFrames);
  for (const frame of observedFrames) reseal(frame);
  const allowedProcessCounts = Object.fromEntries(
    ['git', 'lsusb', 'dockerVersion', 'dockerPs', 'dockerInspect', 'dockerLogs'].map((kind) => [
      kind,
      commands.filter((receipt) => receipt.kind === kind).length,
    ])
  );
  return {
    mode: 'live-readonly-dynamic-acquisition-capability-bounded',
    environmentPolicy: environmentPolicy(),
    commandReceipts: commands,
    filesystemReceipts: files,
    allowedProcessCounts,
    commandCount: commands.length,
    filesystemReceiptCount: files.length,
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

function collector() {
  const sourcesBefore = sourceMap();
  const reviewedSourceSetSha256 = sourceSetSha256(sourcesBefore);
  return {
    reviewAuthorization: {
      grant: `CHG-0020:h045-one-readonly-replacement-attempt:sha256:${reviewedSourceSetSha256}`,
      sourceSetSha256: reviewedSourceSetSha256,
      semantics: 'one-live-read-only-replacement-attempt',
    },
    attemptLedger: {
      predecessorReservationRelativePath: 'artifacts/h045/live-attempt/reservation.json',
      predecessorFailureRelativePath: 'artifacts/h045/live-attempt/failure.json',
      predecessorReservationSha256: PREDECESSOR_RESERVATION_SHA256,
      predecessorFailureSha256: PREDECESSOR_FAILURE_SHA256,
      reservationRelativePath: 'artifacts/h045/h045-chg-0020-attempt-1/reservation.json',
      completionRelativePath: 'artifacts/h045/h045-chg-0020-attempt-1/completion.json',
      reservationSha256: SHA256,
      semantics: 'fixed-local-linked-one-shot-replacement-ledger',
    },
    runtime: {
      node: H045_NODE_VERSION,
      platform: H045_NODE_PLATFORM,
      arch: H045_NODE_ARCH,
      binarySha256: H045_NODE_BINARY_SHA256,
      binaryByteLength: H045_NODE_BINARY_BYTE_LENGTH,
    },
    repository: H045_REPOSITORY,
    observedHead: H045_SOURCE_CONTRACT_COMMIT,
    protectedMain: {
      commit: H045_PROTECTED_MAIN_COMMIT,
      isAncestor: true,
    },
    sourceContract: {
      commit: H045_SOURCE_CONTRACT_COMMIT,
      isAncestor: true,
    },
    sourcesBefore,
    sourcesAfter: clone(sourcesBefore),
    sourceStable: true,
    governance: {
      verified: true,
      planHash: H045_PLAN_HASH,
      planSha256: H045_GOVERNANCE_PLAN_SHA256,
      manifestContentHash: H045_MANIFEST_CONTENT_HASH,
      manifestSha256: H045_GOVERNANCE_MANIFEST_SHA256,
      changes: {
        'CHG-0018': H045_CHG_0018_SHA256,
        'CHG-0019': H045_CHG_0019_SHA256,
        'CHG-0020': H045_CHG_0020_SHA256,
      },
      decisions: {
        'ADR-0006': H045_ADR_0006_SHA256,
      },
      requiredSourcePaths: [...H045_REQUIRED_SOURCE_PATHS],
    },
  };
}

function hostileMatrix() {
  const cases = REQUIRED_CASE_IDS.map((id) => ({
    id,
    inputSha256: sha256(id),
    expectedDisposition: 'inconclusive',
    actualDisposition: 'inconclusive',
    expectedReceiptCount: 0,
    actualReceiptCount: 0,
    stage: 'hostile-matrix',
    reasonCode: id,
    passed: true,
  }));
  return {
    schemaVersion: 'overlaykit-h045-hostile-matrix/v1',
    requiredCaseIds: [...REQUIRED_CASE_IDS],
    caseCount: cases.length,
    passedCount: cases.length,
    allPassed: true,
    cases,
  };
}

function acceptedTarget() {
  return {
    imageReference: H045_ACCEPTED_IMAGE_REFERENCE,
    imageId: H045_ACCEPTED_IMAGE_ID,
    vendorId: H045_ACCEPTED_VENDOR_ID,
    productId: H045_ACCEPTED_PRODUCT_ID,
    serial: ACCEPTED_SERIAL,
    serialBinding: clone(H045_ACCEPTED_SERIAL_BINDING),
  };
}

function supportedRun() {
  const observedFrames = frames();
  const audit = capabilityAudit(observedFrames);
  const admission = sourceAdmission();
  const liveClassification = classifyDynamicFrames({
    frames: observedFrames,
    capabilityAudit: audit,
    sourceAdmissionExact: admission.allExact,
  });
  return {
    schemaVersion: 'overlaykit-h045-live-run/v2',
    hypothesis: 'H-045',
    runId: 'h045-2026-07-27T03-00-10-000Z-deadbeef',
    startedAt: '2026-07-27T03:00:10.000Z',
    completedAt: '2026-07-27T03:00:12.000Z',
    outcome: {
      status: 'supported',
      stage: 'dynamic-readonly-acquisition',
      reasonCode: 'complete-live-classification-and-hostile-matrix-exact',
    },
    collector: collector(),
    input: clone(H045_STABLE_TARGET_INPUT),
    sourceAdmission: admission,
    acceptedTarget: acceptedTarget(),
    frames: observedFrames,
    capabilityAudit: audit,
    liveClassification,
    hostileMatrix: hostileMatrix(),
    claimBoundary: clone(CLAIM_BOUNDARY),
    evidenceSha256: SHA256,
  };
}

function reclassify(run, { rebuildAudit = false } = {}) {
  if (rebuildAudit) run.capabilityAudit = capabilityAudit(run.frames);
  run.liveClassification = classifyDynamicFrames({
    frames: run.frames,
    capabilityAudit: run.capabilityAudit,
    sourceAdmissionExact: run.sourceAdmission.allExact,
  });
}

const schema = JSON.parse(
  await readFile(new URL('./schemas/live-run.schema.json', import.meta.url), 'utf8')
);
const validate = new Ajv2020({
  strict: true,
  allErrors: true,
  validateFormats: false,
}).compile(schema);

function assertAccepted(value, message) {
  assert.equal(validate(value), true, `${message}: ${JSON.stringify(validate.errors)}`);
}

function assertRejected(value, message) {
  assert.equal(validate(value), false, message);
}

test('accepts supported candidate with one authority-void dynamic tuple receipt', () => {
  const run = supportedRun();
  assert.equal(schema.$id, 'overlaykit-h045-live-run/v2');
  assert.equal(run.liveClassification.disposition, 'candidate');
  assert.equal(run.liveClassification.receipts.length, 1);
  assertAccepted(run, 'candidate supported run');

  const legacyEnvelope = supportedRun();
  legacyEnvelope.schemaVersion = 'overlaykit-h045-live-run/v1';
  assertRejected(legacyEnvelope, 'legacy CHG-0019 live envelope');
});

test('accepts supported withheld for exact current accepted-image absence', () => {
  const run = supportedRun();
  for (const frame of run.frames) {
    frame.deploymentInventory.rows = [];
    frame.deploymentInventory.matches = [];
    reseal(frame);
  }
  reclassify(run, { rebuildAudit: true });
  assert.equal(run.liveClassification.disposition, 'withheld');
  assert.equal(run.liveClassification.reasonCode, 'accepted-image-deployment-absent');
  assertAccepted(run, 'absent withheld run');
});

test('accepts supported withheld for exact nonrunning deployment with nullable process evidence', () => {
  const run = supportedRun();
  for (const frame of run.frames) {
    frame.deploymentInventory.rows[0].state = 'exited';
    const selected = frame.deploymentInventory.matches[0];
    selected.container.state = 'exited';
    selected.lifecycle = null;
    selected.pid1 = null;
    selected.workers = [];
    selected.descriptors = [];
    reseal(frame);
  }
  reclassify(run, { rebuildAudit: true });
  assert.equal(run.liveClassification.disposition, 'withheld');
  assert.equal(run.liveClassification.reasonCode, 'deployment-not-running');
  assertAccepted(run, 'nonrunning withheld run');
});

test('accepts supported withheld for an exact current target descriptor', () => {
  const run = supportedRun();
  for (const frame of run.frames) {
    frame.deploymentInventory.matches[0].descriptors = [descriptorEvidence()];
    reseal(frame);
  }
  reclassify(run, { rebuildAudit: true });
  assert.equal(run.liveClassification.disposition, 'withheld');
  assert.equal(run.liveClassification.reasonCode, 'current-descriptor-present');
  assertAccepted(run, 'descriptor-present withheld run');
});

test('accepts an inconclusive source-admission result with zero receipts', () => {
  const run = supportedRun();
  run.sourceAdmission = sourceAdmission(false);
  reclassify(run);
  run.outcome = {
    status: 'inconclusive',
    stage: 'source-admission',
    reasonCode: 'source-admission-inexact',
  };
  assert.equal(run.liveClassification.disposition, 'inconclusive');
  assertAccepted(run, 'inconclusive source run');
});

test('accepts a refuted prohibited-capability result only with zero candidate receipts', () => {
  const run = supportedRun();
  run.capabilityAudit.commandReceipts[0].exitCode = null;
  run.capabilityAudit.commandReceipts[0].signal = 'SIGTERM';
  run.capabilityAudit.prohibitedCounts.signal = 1;
  reclassify(run);
  run.outcome = {
    status: 'refuted',
    stage: 'capability-boundary',
    reasonCode: 'prohibited-capability-observed',
  };
  assert.equal(run.liveClassification.disposition, 'inconclusive');
  assertAccepted(run, 'refuted capability run');
});

test('triple-locks classifier predicate keys, hostile case order, and claim boundary literals', () => {
  assert.deepEqual(schema.$defs.predicates.required, H045_PREDICATE_KEYS);
  assert.deepEqual(
    schema.$defs.requiredSourcePaths.prefixItems.map((entry) => entry.const),
    H045_REQUIRED_SOURCE_PATHS
  );
  assert.equal(schema.$defs.requiredSourcePaths.minItems, H045_REQUIRED_SOURCE_PATHS.length);
  assert.equal(schema.$defs.requiredSourcePaths.maxItems, H045_REQUIRED_SOURCE_PATHS.length);
  assert.equal(schema.$defs.filesystemResultPath.properties.value.maxLength, 4096);
  assert.deepEqual(
    schema.$defs.hostileMatrix.properties.requiredCaseIds.prefixItems.map((entry) => entry.const),
    REQUIRED_CASE_IDS
  );
  assert.deepEqual(
    schema.$defs.claimBoundary.properties.proves.prefixItems.map((entry) => entry.const),
    CLAIM_BOUNDARY.proves
  );
  assert.deepEqual(
    schema.$defs.claimBoundary.properties.excludes.prefixItems.map((entry) => entry.const),
    CLAIM_BOUNDARY.excludes
  );

  const run = supportedRun();
  run.liveClassification.predicates.unknownPredicate = true;
  assertRejected(run, 'unknown predicate');

  const wrongCaseOrder = supportedRun();
  wrongCaseOrder.hostileMatrix.requiredCaseIds.reverse();
  wrongCaseOrder.hostileMatrix.cases.reverse();
  assertRejected(wrongCaseOrder, 'hostile case reordering');

  const narrowedClaim = supportedRun();
  narrowedClaim.claimBoundary.excludes.pop();
  assertRejected(narrowedClaim, 'claim boundary narrowing');
});

test('pins the two replacement sources and exact CHG-0020 governance bytes', async () => {
  assert.equal(H045_REQUIRED_SOURCE_PATHS.length, 24);
  assert.equal(
    H045_REQUIRED_SOURCE_PATHS.includes('.overlaykit/governance/changes/CHG-0020.json'),
    true
  );
  assert.equal(H045_REQUIRED_SOURCE_PATHS.includes('lab/h046/environment-seam.test.mjs'), true);

  const [chg0020Bytes, manifestBytes] = await Promise.all([
    readFile(CHG_0020_URL),
    readFile(GOVERNANCE_MANIFEST_URL),
  ]);
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  assert.equal(sha256(chg0020Bytes), H045_CHG_0020_SHA256);
  assert.equal(sha256(manifestBytes), H045_GOVERNANCE_MANIFEST_SHA256);
  assert.equal(manifest.contentHash, H045_MANIFEST_CONTENT_HASH);
  assert.equal(manifest.changes['CHG-0020'], H045_CHG_0020_SHA256);

  const governanceSchema = schema.$defs.collector.properties.governance.properties;
  assert.equal(governanceSchema.changes.properties['CHG-0020'].const, H045_CHG_0020_SHA256);
  assert.equal(governanceSchema.manifestContentHash.const, H045_MANIFEST_CONTENT_HASH);
  assert.equal(governanceSchema.manifestSha256.const, H045_GOVERNANCE_MANIFEST_SHA256);

  const run = supportedRun();
  assert.deepEqual(run.collector.governance.changes, {
    'CHG-0018': H045_CHG_0018_SHA256,
    'CHG-0019': H045_CHG_0019_SHA256,
    'CHG-0020': H045_CHG_0020_SHA256,
  });
  assertAccepted(run, 'exact CHG-0020 governance closure');

  const missingSuccessor = supportedRun();
  delete missingSuccessor.collector.governance.changes['CHG-0020'];
  assertRejected(missingSuccessor, 'missing CHG-0020 governance binding');

  const driftedSuccessor = supportedRun();
  driftedSuccessor.collector.governance.changes['CHG-0020'] = '0'.repeat(64);
  assertRejected(driftedSuccessor, 'CHG-0020 governance byte drift');
});

test('binds the review authorization to the canonical ordered source-map digest', () => {
  const run = supportedRun();
  const digest = sourceSetSha256(run.collector.sourcesBefore);
  assert.equal(run.collector.reviewAuthorization.sourceSetSha256, digest);
  assert.equal(
    run.collector.reviewAuthorization.grant,
    `CHG-0020:h045-one-readonly-replacement-attempt:sha256:${digest}`
  );
  assert.equal(
    run.collector.reviewAuthorization.semantics,
    'one-live-read-only-replacement-attempt'
  );
  assert.equal(sourceSetSha256(run.collector.sourcesAfter), digest);
  assertAccepted(run, 'source-bound review authorization');

  const malformedGrant = supportedRun();
  malformedGrant.collector.reviewAuthorization.grant = `CHG-0020:h045-one-readonly-replacement-attempt:${malformedGrant.collector.reviewAuthorization.sourceSetSha256}`;
  assertRejected(malformedGrant, 'malformed review authorization grant');

  const predecessorGrant = supportedRun();
  predecessorGrant.collector.reviewAuthorization.grant = `CHG-0019:one-readonly-run:sha256:${predecessorGrant.collector.reviewAuthorization.sourceSetSha256}`;
  assertRejected(predecessorGrant, 'consumed predecessor authorization grant');

  const predecessorSemantics = supportedRun();
  predecessorSemantics.collector.reviewAuthorization.semantics = 'one-live-read-only-attempt';
  assertRejected(predecessorSemantics, 'consumed predecessor authorization semantics');

  const expandedReview = supportedRun();
  expandedReview.collector.reviewAuthorization.ledger = 'not part of run evidence';
  assertRejected(expandedReview, 'lateral review ledger expansion');
});

test('requires the exact canonical predecessor-linked one-shot replacement ledger', () => {
  const run = supportedRun();
  assert.deepEqual(run.collector.attemptLedger, {
    predecessorReservationRelativePath: 'artifacts/h045/live-attempt/reservation.json',
    predecessorFailureRelativePath: 'artifacts/h045/live-attempt/failure.json',
    predecessorReservationSha256: PREDECESSOR_RESERVATION_SHA256,
    predecessorFailureSha256: PREDECESSOR_FAILURE_SHA256,
    reservationRelativePath: 'artifacts/h045/h045-chg-0020-attempt-1/reservation.json',
    completionRelativePath: 'artifacts/h045/h045-chg-0020-attempt-1/completion.json',
    reservationSha256: SHA256,
    semantics: 'fixed-local-linked-one-shot-replacement-ledger',
  });
  assertAccepted(run, 'canonical linked replacement attempt ledger');

  const missing = supportedRun();
  delete missing.collector.attemptLedger;
  assertRejected(missing, 'missing canonical linked replacement attempt ledger');

  const expanded = supportedRun();
  expanded.collector.attemptLedger.attempt = 'h045-chg-0020-attempt-1';
  assertRejected(expanded, 'expanded attempt ledger');

  const predecessorReservationPath = supportedRun();
  predecessorReservationPath.collector.attemptLedger.predecessorReservationRelativePath =
    'artifacts/h045/h045-chg-0020-attempt-1/reservation.json';
  assertRejected(predecessorReservationPath, 'predecessor reservation path drift');

  const predecessorFailurePath = supportedRun();
  predecessorFailurePath.collector.attemptLedger.predecessorFailureRelativePath =
    'artifacts/h045/h045-chg-0020-attempt-1/failure.json';
  assertRejected(predecessorFailurePath, 'predecessor failure path drift');

  const predecessorReservationDigest = supportedRun();
  predecessorReservationDigest.collector.attemptLedger.predecessorReservationSha256 = '0'.repeat(
    64
  );
  assertRejected(predecessorReservationDigest, 'predecessor reservation digest drift');

  const predecessorFailureDigest = supportedRun();
  predecessorFailureDigest.collector.attemptLedger.predecessorFailureSha256 = '0'.repeat(64);
  assertRejected(predecessorFailureDigest, 'predecessor failure digest drift');

  const reservationPath = supportedRun();
  reservationPath.collector.attemptLedger.reservationRelativePath =
    'artifacts/h045/live-attempt/reservation.json';
  assertRejected(reservationPath, 'replacement reservation reuses predecessor path');

  const completionPath = supportedRun();
  completionPath.collector.attemptLedger.completionRelativePath =
    'artifacts/h045/h045-chg-0020-attempt-2/completion.json';
  assertRejected(completionPath, 'replacement completion path drift');

  const reservationDigest = supportedRun();
  reservationDigest.collector.attemptLedger.reservationSha256 = 'not-a-sha256';
  assertRejected(reservationDigest, 'reservation digest drift');

  const semantics = supportedRun();
  semantics.collector.attemptLedger.semantics = 'fixed-local-one-shot-ledger';
  assertRejected(semantics, 'attempt ledger semantics drift');
});

test('rejects the exact offline fixture schema and boundary from the live schema', () => {
  const run = supportedRun();
  run.schemaVersion = 'overlaykit-h045-offline-fixture/v1';
  const sourceSetDigest = run.collector.reviewAuthorization.sourceSetSha256;
  delete run.collector.reviewAuthorization;
  delete run.collector.attemptLedger;
  run.collector.offlineSourceBinding = {
    sourceSetSha256: sourceSetDigest,
    semantics: 'offline-non-authorizing-source-binding',
  };
  run.collector.offlineAttemptLedger = {
    reservationSha256: SHA256,
    semantics: 'explicit-offline-fixture-ledger',
  };
  assertRejected(run, 'offline fixture inner run');

  const offlineWrapper = {
    fixtureBoundary: {
      mode: 'offline-fixture',
      canonical: false,
      authorizing: false,
      live: false,
      persistence: 'explicit-fixture-only',
    },
    fixtureResult: {
      run,
      runPath: '/tmp/h045-offline-fixture/run.json',
    },
  };
  assertRejected(offlineWrapper, 'offline fixture wrapper');
});

test('rejects authority, action, duplicate receipt, and unknown volatile target expansion', () => {
  const authority = supportedRun();
  authority.liveClassification.receipts[0].authority = 'signal';
  assertRejected(authority, 'authority expansion');

  const action = supportedRun();
  action.liveClassification.receipts[0].action = {
    type: 'signal',
  };
  assertRejected(action, 'action expansion');

  const duplicate = supportedRun();
  duplicate.liveClassification.receipts.push(clone(duplicate.liveClassification.receipts[0]));
  assertRejected(duplicate, 'duplicate receipt');

  const volatileInput = supportedRun();
  volatileInput.input.workerPid = 73;
  assertRejected(volatileInput, 'historical volatile input');

  const volatileTopLevel = supportedRun();
  volatileTopLevel.signalTarget = {
    pid: 73,
  };
  assertRejected(volatileTopLevel, 'top-level signal target');
});

test('rejects selector broadening, multiplicity unsafe-positive, and accepted image mismatch', () => {
  const broad = supportedRun();
  broad.frames[0].deploymentInventory.selector.containerName = 'companion';
  assertRejected(broad, 'selector broadening');

  const multiple = supportedRun();
  for (const frame of multiple.frames) {
    frame.deploymentInventory.rows.push({
      containerId: 'd'.repeat(64),
      state: 'running',
    });
    frame.deploymentInventory.matches = [];
    reseal(frame);
  }
  assert.equal(multiple.liveClassification.disposition, 'candidate');
  assertRejected(multiple, 'multiple-image unsafe-positive');

  const imageMismatch = supportedRun();
  imageMismatch.input.imageId = `sha256:${'0'.repeat(64)}`;
  assertRejected(imageMismatch, 'accepted input image mismatch');
});

test('rejects malformed frame/audit bindings and evidence digest shape', () => {
  const duplicateBinding = supportedRun();
  duplicateBinding.frames[0].auditBinding.commandReceiptIndexes = [6, 6, 8];
  assertRejected(duplicateBinding, 'duplicate audit binding');

  const expandedBinding = supportedRun();
  expandedBinding.frames[0].auditBinding.action = 'signal';
  assertRejected(expandedBinding, 'audit binding action');

  const evidence = supportedRun();
  evidence.evidenceSha256 = 'not-a-sha256';
  assertRejected(evidence, 'evidence digest shape');
});

test('rejects impossible numeric, namespace, and character-device identities', () => {
  const zeroPid = supportedRun();
  zeroPid.frames[0].deploymentInventory.matches[0].lifecycle.hostPid = 0;
  assertRejected(zeroPid, 'zero lifecycle PID');

  const namespace = supportedRun();
  namespace.frames[0].deploymentInventory.matches[0].workers[0].pidNamespace = 'pid:[fixture]';
  assertRejected(namespace, 'malformed namespace identity');

  const regularNode = supportedRun();
  regularNode.frames[0].device.identity.epoch.stat.isCharacterDevice = false;
  assertRejected(regularNode, 'accepted target represented by a regular node');

  const malformedDescriptor = supportedRun();
  malformedDescriptor.frames[0].deploymentInventory.matches[0].descriptors = [
    {
      descriptor: '20',
      target: '/dev/hidraw0',
      lstat: filesystemStat(),
      stat: filesystemStat(),
    },
  ];
  assertRejected(malformedDescriptor, 'descriptor lstat is not a symbolic link');
});

test('rejects runtime, ancestry, source order, and source stability claims that contradict support', () => {
  const runtime = supportedRun();
  runtime.collector.runtime.node = 'v22.20.1';
  assertRejected(runtime, 'runtime drift');

  const ancestry = supportedRun();
  ancestry.collector.sourceContract.isAncestor = false;
  assertRejected(ancestry, 'source-contract ancestry drift');

  const sourceOrder = supportedRun();
  sourceOrder.collector.sourcesBefore.reverse();
  assertRejected(sourceOrder, 'source order drift');

  const sourceStable = supportedRun();
  sourceStable.collector.sourceStable = false;
  assertRejected(sourceStable, 'unsupported source stability');

  const missingPlan = supportedRun();
  missingPlan.collector.sourcesBefore = missingPlan.collector.sourcesBefore.filter(
    (entry) => entry.path !== '.overlaykit/governance/plan.json'
  );
  assertRejected(missingPlan, 'missing reviewed governance plan bytes');

  const planBytes = supportedRun();
  planBytes.collector.governance.planSha256 = '0'.repeat(64);
  assertRejected(planBytes, 'governance plan byte drift');

  const manifestBytes = supportedRun();
  manifestBytes.collector.governance.manifestSha256 = '0'.repeat(64);
  assertRejected(manifestBytes, 'governance manifest byte drift');
});

test('rejects malformed raw command and filesystem receipts, remote Docker, and action fields', () => {
  const commandAction = supportedRun();
  commandAction.capabilityAudit.commandReceipts[0].action = 'signal';
  assertRejected(commandAction, 'command action expansion');

  const remoteDocker = supportedRun();
  remoteDocker.capabilityAudit.commandReceipts[5].args[1] = 'tcp://127.0.0.1:2375';
  assertRejected(remoteDocker, 'remote Docker endpoint');

  const commandBufferLimit = supportedRun();
  commandBufferLimit.capabilityAudit.commandReceipts[0].limits.maxBufferBytes += 1;
  assertRejected(commandBufferLimit, 'command max-buffer broadening');

  const commandTimeout = supportedRun();
  commandTimeout.capabilityAudit.commandReceipts[0].limits.timeoutMs = 1500;
  assertRejected(commandTimeout, 'command timeout broadening');

  const commandOverflow = supportedRun();
  commandOverflow.capabilityAudit.commandReceipts[0].limits.overflow = 'kill';
  assertRejected(commandOverflow, 'command overflow policy drift');

  const inheritedEnvironment = supportedRun();
  inheritedEnvironment.capabilityAudit.environmentPolicy.inheritedKeys = ['PATH'];
  assertRejected(inheritedEnvironment, 'inherited environment poison');

  const commandEnvironment = supportedRun();
  commandEnvironment.capabilityAudit.commandReceipts[0].environmentPolicy.fixed.DOCKER_HOST =
    'tcp://127.0.0.1:2375';
  assertRejected(commandEnvironment, 'receipt environment poison');

  const uncountedSignal = supportedRun();
  uncountedSignal.capabilityAudit.commandReceipts[0].exitCode = null;
  uncountedSignal.capabilityAudit.commandReceipts[0].signal = 'SIGTERM';
  assertRejected(uncountedSignal, 'candidate command signal without prohibited count');

  const signalTarget = supportedRun();
  signalTarget.capabilityAudit.commandReceipts[6].signalTarget = CONTAINER_ID;
  assertRejected(signalTarget, 'command signal target');

  const malformedFilesystem = supportedRun();
  delete malformedFilesystem.capabilityAudit.filesystemReceipts[0].result.bytes;
  assertRejected(malformedFilesystem, 'malformed filesystem receipt');

  const broadFilesystem = supportedRun();
  broadFilesystem.capabilityAudit.filesystemReceipts[0].path = '/home/rod/.ssh/config';
  assertRejected(broadFilesystem, 'broad filesystem path');

  const shadowFilesystem = supportedRun();
  shadowFilesystem.capabilityAudit.filesystemReceipts[0].path = '/etc/shadow';
  assertRejected(shadowFilesystem, 'shadow filesystem path');

  const processEnvironment = supportedRun();
  processEnvironment.capabilityAudit.filesystemReceipts[0].path = '/proc/4242/root/proc/73/environ';
  assertRejected(processEnvironment, 'process environment path');

  const unrelatedSysfs = supportedRun();
  unrelatedSysfs.capabilityAudit.filesystemReceipts[0].path = '/sys/devices/unrelated/idVendor';
  assertRejected(unrelatedSysfs, 'unrelated sysfs attribute path');

  const oversizedPathResult = supportedRun();
  const realpath = oversizedPathResult.capabilityAudit.filesystemReceipts.find(
    (receipt) => receipt.operation === 'realpathSync'
  );
  realpath.result.value = 'x'.repeat(4097);
  assertRejected(oversizedPathResult, 'realpath result over 4096 code points');
});

test('rejects command and filesystem byte/path limits at boundary plus one', () => {
  const commandOutput = supportedRun();
  commandOutput.capabilityAudit.commandReceipts[0].stdout.byteLength = 4 * 1024 * 1024 + 1;
  assertRejected(commandOutput, 'command output over 4 MiB');

  const filesystemRead = supportedRun();
  filesystemRead.capabilityAudit.filesystemReceipts[0].result.byteLength = 1024 * 1024 + 1;
  assertRejected(filesystemRead, 'filesystem read over 1 MiB');

  const filesystemNestedRead = supportedRun();
  filesystemNestedRead.capabilityAudit.filesystemReceipts[0].result.bytes.byteLength =
    1024 * 1024 + 1;
  assertRejected(filesystemNestedRead, 'nested filesystem read over 1 MiB');

  const filesystemPath = supportedRun();
  filesystemPath.capabilityAudit.filesystemReceipts[0].path = `/proc/${'9'.repeat(4084)}/cgroup`;
  assert.equal(filesystemPath.capabilityAudit.filesystemReceipts[0].path.length, 4097);
  assertRejected(filesystemPath, 'filesystem path over 4096 code points');
});

test('rejects directory cardinality limits at boundary plus one', () => {
  const hidrawDirectory = supportedRun();
  const hidrawReceipt = hidrawDirectory.capabilityAudit.filesystemReceipts.find(
    (receipt) => receipt.operation === 'readdirSync' && receipt.path === '/sys/class/hidraw'
  );
  hidrawReceipt.result.entries = Array.from({ length: 65 }, (_, index) => `hidraw${index}`);
  hidrawReceipt.result.cardinality = 65;
  assertRejected(hidrawDirectory, 'hidraw directory over 64 entries');

  const procDirectory = supportedRun();
  const procReceipt = procDirectory.capabilityAudit.filesystemReceipts.find(
    (receipt) =>
      receipt.operation === 'readdirSync' && /^\/proc\/[1-9][0-9]*\/root\/proc$/u.test(receipt.path)
  );
  procReceipt.result.entries = Array.from({ length: 1025 }, (_, index) => String(index + 1));
  procReceipt.result.cardinality = 1025;
  assertRejected(procDirectory, 'proc directory over 1024 entries');
});

test('rejects filesystem receipt binding and run limits at boundary plus one', () => {
  const frameBinding = supportedRun();
  frameBinding.frames[0].auditBinding.filesystemReceiptIndexes = Array.from(
    { length: 16385 },
    (_, index) => index
  );
  assertRejected(frameBinding, 'frame filesystem binding over 16384 receipts');

  const auditRun = supportedRun();
  const receipt = auditRun.capabilityAudit.filesystemReceipts[0];
  auditRun.capabilityAudit.filesystemReceipts = Array(32769).fill(receipt);
  auditRun.capabilityAudit.filesystemReceiptCount = 32769;
  assertRejected(auditRun, 'run filesystem audit over 32768 receipts');
});
