import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';

import { H043_REPLAY_ARCHIVE_PATH, readHistoricalEvidence } from './admission-lib.mjs';
import { classifyLiveFrames, sha256Canonical } from './classifier-lib.mjs';
import { H044_CLAIM_BOUNDARY, evaluateHostileMatrix, outcomeFor, runH044 } from './run.mjs';
import {
  INDEPENDENT_CLAIM_BOUNDARY,
  INDEPENDENT_REQUIRED_SOURCE_PATHS,
  verifyRun,
} from './verify.mjs';

const REPOSITORY_ROOT = path.resolve(new URL('../../', import.meta.url).pathname);
const REPOSITORY = 'https://github.com/OverlayKit/companion-module-overlaykit-server.git';
const PROTECTED_MAIN_COMMIT = '6c329234caddf9e34126be04149f768673bdb8bf';
const SOURCE_CONTRACT_COMMIT = '9e2156e7ddc38ebe223824a07f682421b7ee0589';
const PLAN_HASH = 'bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4';
const MANIFEST_CONTENT_HASH = 'b36032589f0d652ceffd6aafee502e551b4f86779149be4b9ac1c38636a17013';
const CHANGE_SHA256 = '858fcc7fde8bf6abd73e58f56224c3eae238ecf46ae70e92aca92f886937e576';
const DOCKER_HOST_PREFIX = ['--host', 'unix:///var/run/docker.sock'];
const DOCKER_VERSION_FORMAT =
  '{"Client":{"Version":{{json .Client.Version}},' +
  '"ApiVersion":{{json .Client.APIVersion}}},' +
  '"Server":{"Version":{{json .Server.Version}},' +
  '"ApiVersion":{{json .Server.APIVersion}}}}';
const DOCKER_PS_FORMAT = '{"ID":{{json .ID}},"State":{{json .State}}}';
const DOCKER_INSPECT_FORMAT =
  '{"Id":{{json .Id}},"Image":{{json .Image}},"State":{' +
  '"Status":{{json .State.Status}},"Running":{{json .State.Running}},' +
  '"Pid":{{json .State.Pid}},"StartedAt":{{json .State.StartedAt}}},' +
  '"RestartCount":{{json .RestartCount}},"CgroupnsMode":{{json .HostConfig.CgroupnsMode}}}';
const CONTAINER_ID = '78c013a0b101e9f4d93195e5f3b3e6184aa69019ba2b5f0ea472085f156d986c';
const IMAGE_ID = 'sha256:e7d24e3b0e32b0edb799f262493536cb1a47d307af4e6527551427e09266bf10';
const SERIAL = 'A00SA5492OQMLF';

const temporaryDirectory = await mkdtemp(path.join(tmpdir(), 'overlaykit-h044-verify-'));
after(async () => {
  await rm(temporaryDirectory, { recursive: true, force: true });
});

function clocks() {
  let wall = Date.parse('2026-07-26T20:00:00.000Z');
  let monotonic = 100_000_000_000n;
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

function filesystemFixture() {
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
        `HID_UNIQ=${SERIAL}`,
        'HID_NAME=Elgato Stream Deck MK.2',
        'HID_PHYS=usb-0000:00:14.0-2/input0',
        '',
      ].join('\n'),
    ],
    ['/sys/class/hidraw/hidraw0/dev', '241:0\n'],
    [`${usbPath}/idVendor`, '0fd9\n'],
    [`${usbPath}/idProduct`, '0080\n'],
    [`${usbPath}/serial`, `${SERIAL}\n`],
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

function injectedRunner({ containerStates = ['running', 'running'], logLines = '' } = {}) {
  let psIndex = 0;
  return async function runner(executable, args) {
    if (executable === 'git' && args[0] === 'rev-parse') {
      return { exitCode: 0, signal: null, stdout: `${SOURCE_CONTRACT_COMMIT}\n`, stderr: '' };
    }
    if (executable === 'git' && args[0] === 'merge-base') {
      return { exitCode: 0, signal: null, stdout: '', stderr: '' };
    }
    if (executable === 'git' && args[0] === 'remote') {
      return { exitCode: 0, signal: null, stdout: `${REPOSITORY}\n`, stderr: '' };
    }
    if (executable === 'lsusb') {
      return {
        exitCode: 0,
        signal: null,
        stdout: `Bus 001 Device 018: ID 0fd9:0080 Elgato Stream Deck MK.2\n`,
        stderr: '',
      };
    }
    const dockerArgs =
      executable === 'docker' &&
      args[0] === DOCKER_HOST_PREFIX[0] &&
      args[1] === DOCKER_HOST_PREFIX[1]
        ? args.slice(DOCKER_HOST_PREFIX.length)
        : null;
    if (dockerArgs?.[0] === 'version') {
      return {
        exitCode: 0,
        signal: null,
        stdout: JSON.stringify({
          Client: { Version: '28.3.3', ApiVersion: '1.51' },
          Server: { Version: '28.3.3', ApiVersion: '1.51' },
        }),
        stderr: '',
      };
    }
    if (dockerArgs?.[0] === 'ps') {
      const state = containerStates[Math.min(psIndex, containerStates.length - 1)];
      psIndex += 1;
      return {
        exitCode: 0,
        signal: null,
        stdout: `${JSON.stringify({
          ID: CONTAINER_ID,
          State: state,
        })}\n`,
        stderr: '',
      };
    }
    if (dockerArgs?.[0] === 'inspect') {
      return {
        exitCode: 0,
        signal: null,
        stdout: JSON.stringify({
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
        }),
        stderr: '',
      };
    }
    if (dockerArgs?.[0] === 'logs') {
      return { exitCode: 0, signal: null, stdout: logLines, stderr: '' };
    }
    throw new Error(`unexpected injected command ${executable} ${args.join(' ')}`);
  };
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function lineCount(text) {
  if (text === '') return 0;
  const body = text.endsWith('\n') ? text.slice(0, -1) : text;
  return body === '' ? 0 : body.split('\n').length;
}

function output(text) {
  const bytes = Buffer.from(text, 'utf8');
  return {
    encoding: 'utf8',
    text,
    base64: bytes.toString('base64'),
    byteLength: bytes.byteLength,
    lineCount: lineCount(text),
    sha256: sha256(bytes),
  };
}

function filesystemReadResult(text) {
  const bytes = Buffer.from(text, 'utf8');
  const digest = sha256(bytes);
  return {
    cardinality: 1,
    byteLength: bytes.byteLength,
    bytes: {
      encoding: 'base64',
      base64: bytes.toString('base64'),
      byteLength: bytes.byteLength,
      sha256: digest,
    },
    encoding: 'utf8',
    text,
    sha256: digest,
  };
}

function deviceIdentity(candidate) {
  return {
    serial: candidate.identity.device.serial,
    vendorId: candidate.identity.device.vendorId,
    productId: candidate.identity.device.productId,
    epoch: structuredClone(candidate.identity.device.revalidationEpoch),
  };
}

function pid1Identity(candidate) {
  const lifecycle = candidate.identity.lifecycle;
  return {
    hostPid: lifecycle.hostPid,
    startTicks: lifecycle.pid1StartTicks,
    pidNamespace: lifecycle.pidNamespace,
    mountNamespace: lifecycle.mountNamespace,
    cgroup: lifecycle.cgroup,
  };
}

function sealFrame(frame) {
  const body = structuredClone(frame);
  delete body.digestSha256;
  return { ...body, digestSha256: sha256Canonical(body) };
}

function frames(candidate) {
  const common = {
    complete: true,
    host: {
      hostname: 'h044-verifier-fixture',
      bootId: '00000000-0000-4000-8000-000000000044',
      osRelease: '{"id":"linux","prettyName":"H-044 verifier fixture","versionId":"1"}',
    },
    device: {
      complete: true,
      present: true,
      identity: deviceIdentity(candidate),
    },
    lifecycle: structuredClone(candidate.identity.lifecycle),
    pid1: pid1Identity(candidate),
    workers: [structuredClone(candidate.identity.worker)],
    descriptors: [],
    markers: {
      opening: 0,
      ready: 0,
      relevantLinesSha256: sha256Canonical([]),
    },
    absence: {
      historicalContainerAbsent: false,
      exact: true,
    },
  };
  return [
    sealFrame({
      id: 'frame-1',
      startedAt: '2026-07-26T18:00:00.000Z',
      endedAt: '2026-07-26T18:00:00.900Z',
      startedMonotonicNs: '1000000000',
      endedMonotonicNs: '1900000000',
      ...structuredClone(common),
    }),
    sealFrame({
      id: 'frame-2',
      startedAt: '2026-07-26T18:00:00.900Z',
      endedAt: '2026-07-26T18:00:01.800Z',
      startedMonotonicNs: '1900000000',
      endedMonotonicNs: '2800000000',
      ...structuredClone(common),
    }),
  ];
}

function dockerPs(candidate) {
  return `${JSON.stringify({
    ID: candidate.identity.lifecycle.containerId,
    State: 'running',
  })}\n`;
}

function dockerInspect(candidate) {
  const lifecycle = candidate.identity.lifecycle;
  return JSON.stringify({
    Id: lifecycle.containerId,
    Image: lifecycle.imageId,
    State: {
      Status: 'running',
      Running: true,
      Pid: lifecycle.hostPid,
      StartedAt: lifecycle.startedAt,
    },
    RestartCount: lifecycle.restartCount,
    CgroupnsMode: lifecycle.cgroupNamespaceMode,
  });
}

function commandSpecs(candidate) {
  const epoch = candidate.identity.device.revalidationEpoch;
  const ps = dockerPs(candidate);
  const inspect = dockerInspect(candidate);
  const version = JSON.stringify({
    Client: { Version: '28.3.3', ApiVersion: '1.51' },
    Server: { Version: '28.3.3', ApiVersion: '1.51' },
  });
  const containerId = candidate.identity.lifecycle.containerId;
  const logSince = candidate.identity.lifecycle.startedAt;
  return [
    {
      observerKind: 'gitRevParse',
      kind: 'git',
      executable: 'git',
      args: ['rev-parse', 'HEAD'],
      stdout: `${SOURCE_CONTRACT_COMMIT}\n`,
      at: 10,
      ns: 10_000_000n,
    },
    {
      observerKind: 'gitMergeBaseAncestor',
      kind: 'git',
      executable: 'git',
      args: ['merge-base', '--is-ancestor', PROTECTED_MAIN_COMMIT, 'HEAD'],
      stdout: '',
      at: 30,
      ns: 30_000_000n,
    },
    {
      observerKind: 'gitRemoteGetUrl',
      kind: 'git',
      executable: 'git',
      args: ['remote', 'get-url', 'origin'],
      stdout: `${REPOSITORY}\n`,
      at: 50,
      ns: 50_000_000n,
    },
    {
      kind: 'lsusb',
      executable: 'lsusb',
      args: [],
      stdout:
        `Bus ${epoch.busNumber.padStart(3, '0')} Device ` +
        `${epoch.deviceNumber.padStart(3, '0')}: ID 0fd9:0080 Elgato Stream Deck MK.2\n`,
      at: 70,
      ns: 70_000_000n,
    },
    {
      kind: 'dockerVersion',
      executable: 'docker',
      args: [...DOCKER_HOST_PREFIX, 'version', '--format', DOCKER_VERSION_FORMAT],
      stdout: version,
      at: 90,
      ns: 90_000_000n,
    },
    {
      kind: 'dockerPs',
      executable: 'docker',
      args: [
        ...DOCKER_HOST_PREFIX,
        'ps',
        '--all',
        '--no-trunc',
        '--filter',
        `id=${containerId}`,
        '--format',
        DOCKER_PS_FORMAT,
      ],
      stdout: ps,
      at: 1_100,
      ns: 1_100_000_000n,
    },
    {
      kind: 'dockerInspect',
      executable: 'docker',
      args: [...DOCKER_HOST_PREFIX, 'inspect', '--format', DOCKER_INSPECT_FORMAT, containerId],
      stdout: inspect,
      at: 1_200,
      ns: 1_200_000_000n,
    },
    {
      kind: 'dockerLogs',
      executable: 'docker',
      args: [
        ...DOCKER_HOST_PREFIX,
        'logs',
        '--timestamps',
        '--since',
        logSince,
        '--until',
        '2026-07-26T18:00:00.800Z',
        containerId,
      ],
      stdout: '',
      at: 1_300,
      ns: 1_300_000_000n,
    },
    {
      kind: 'dockerPs',
      executable: 'docker',
      args: [
        ...DOCKER_HOST_PREFIX,
        'ps',
        '--all',
        '--no-trunc',
        '--filter',
        `id=${containerId}`,
        '--format',
        DOCKER_PS_FORMAT,
      ],
      stdout: ps,
      at: 2_000,
      ns: 2_000_000_000n,
    },
    {
      kind: 'dockerInspect',
      executable: 'docker',
      args: [...DOCKER_HOST_PREFIX, 'inspect', '--format', DOCKER_INSPECT_FORMAT, containerId],
      stdout: inspect,
      at: 2_100,
      ns: 2_100_000_000n,
    },
    {
      kind: 'dockerLogs',
      executable: 'docker',
      args: [
        ...DOCKER_HOST_PREFIX,
        'logs',
        '--timestamps',
        '--since',
        logSince,
        '--until',
        '2026-07-26T18:00:01.700Z',
        containerId,
      ],
      stdout: '',
      at: 2_200,
      ns: 2_200_000_000n,
    },
  ];
}

function commandReceipts(candidate) {
  const observerCounts = {};
  return commandSpecs(candidate).map((spec, index) => {
    const observerKind = spec.observerKind ?? spec.kind;
    observerCounts[observerKind] = (observerCounts[observerKind] ?? 0) + 1;
    const startedAt = new Date(Date.parse('2026-07-26T17:59:59.000Z') + spec.at).toISOString();
    const endedAt = new Date(Date.parse(startedAt) + 5).toISOString();
    const receipt = {
      index,
      kind: spec.kind,
      ordinal: observerCounts[observerKind],
      executable: spec.executable,
      args: spec.args,
      startedAt,
      endedAt,
      startedMonotonicNs: spec.ns.toString(),
      endedMonotonicNs: (spec.ns + 5_000_000n).toString(),
      durationNs: '5000000',
      limits: {
        maxBufferBytes: 8 * 1024 * 1024,
        timeoutMs: 1_500,
      },
      exitCode: 0,
      signal: null,
      stdout: output(spec.stdout),
      stderr: output(''),
      cardinality: {
        global: index + 1,
        kind: observerCounts[observerKind],
      },
      errorCode: null,
    };
    if (spec.observerKind !== undefined) {
      return {
        index: receipt.index,
        kind: receipt.kind,
        observerKind: spec.observerKind,
        ordinal: receipt.ordinal,
        executable: receipt.executable,
        args: receipt.args,
        startedAt: receipt.startedAt,
        endedAt: receipt.endedAt,
        startedMonotonicNs: receipt.startedMonotonicNs,
        endedMonotonicNs: receipt.endedMonotonicNs,
        durationNs: receipt.durationNs,
        limits: receipt.limits,
        exitCode: receipt.exitCode,
        signal: receipt.signal,
        stdout: receipt.stdout,
        stderr: receipt.stderr,
        cardinality: receipt.cardinality,
        errorCode: receipt.errorCode,
      };
    }
    return receipt;
  });
}

function filesystemReceipts() {
  return [
    {
      startedAt: '2026-07-26T18:00:00.400Z',
      endedAt: '2026-07-26T18:00:00.405Z',
      startedMonotonicNs: '1400000000',
      endedMonotonicNs: '1405000000',
    },
    {
      startedAt: '2026-07-26T18:00:01.400Z',
      endedAt: '2026-07-26T18:00:01.405Z',
      startedMonotonicNs: '2400000000',
      endedMonotonicNs: '2405000000',
    },
  ].map((time, index) => ({
    index,
    operation: 'readFileSync',
    path: '/proc/sys/kernel/random/boot_id',
    ...time,
    durationNs: '5000000',
    disposition: 'observed',
    result: filesystemReadResult(`fixture-boot-id-${index}`),
    errorCode: null,
    cardinality: {
      global: index + 1,
      operation: index + 1,
    },
  }));
}

function capabilityAudit(candidate) {
  const commands = commandReceipts(candidate);
  const filesystem = filesystemReceipts();
  return {
    mode: 'live-readonly-capability-bounded',
    complete: true,
    exact: true,
    frameCount: 2,
    lsusbCount: 1,
    unrecordedObservationCount: 0,
    commandReceipts: commands,
    filesystemReceipts: filesystem,
    allowedProcessCounts: {
      git: 3,
      lsusb: 1,
      dockerVersion: 1,
      dockerPs: 2,
      dockerInspect: 2,
      dockerLogs: 2,
    },
    commandCount: commands.length,
    filesystemReceiptCount: filesystem.length,
    prohibitedCounts: {
      externalNetwork: 0,
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

async function sourceReceipts() {
  return Promise.all(
    INDEPENDENT_REQUIRED_SOURCE_PATHS.map(async (relativePath) => ({
      path: relativePath,
      sha256: sha256(await readFile(path.join(REPOSITORY_ROOT, relativePath))),
    }))
  );
}

function sourceAdmission() {
  return {
    h043ArchiveExact: true,
    h043RunExact: true,
    h043VerificationExact: true,
    h043EvidenceExact: true,
    h043CandidateTokenExact: true,
    chg0016Exact: true,
    adr0006Exact: true,
    protectedMainAncestryExact: true,
    governanceExact: true,
    sourceSetExact: true,
    allExact: true,
  };
}

let generatedRunPromise;

async function syntheticRun() {
  generatedRunPromise ??= (async () => {
    const clock = clocks();
    const { run } = await runH044({
      outputRoot: path.join(temporaryDirectory, 'producer'),
      wallNow: clock.wallNow,
      monotonicNowNs: clock.monotonicNowNs,
      runner: injectedRunner(),
      filesystem: filesystemFixture(),
    });
    return run;
  })();
  return structuredClone(await generatedRunPromise);
}

async function writeFixture(name, mutate = () => {}, { rebind = true } = {}) {
  const run = await syntheticRun();
  mutate(run);
  if (rebind) {
    const { evidenceSha256: _evidenceSha256, ...body } = run;
    run.evidenceSha256 = sha256Canonical(body);
  }
  const fixturePath = path.join(temporaryDirectory, `${name}.json`);
  await writeFile(fixturePath, `${JSON.stringify(run, null, 2)}\n`);
  return fixturePath;
}

test('independently verifies a complete synthetic candidate run', async () => {
  const verification = await verifyRun(await writeFixture('golden'));
  assert.equal(verification.outcome, 'supported', JSON.stringify(verification));
  assert.equal(verification.verified, true);
  assert.equal(verification.sourceAdmissionAllExact, true);
  assert.equal(verification.commandAuditExact, true);
  assert.equal(verification.filesystemAuditExact, true);
  assert.equal(verification.auditBindingExact, true);
  assert.equal(verification.framesReconstructed, true);
  assert.equal(verification.frameCompletenessExact, true);
  assert.deepEqual(verification.recomputedFrameCompleteness, [true, true]);
  assert.equal(verification.classificationExact, true);
  assert.equal(verification.receiptExact, true);
  assert.equal(verification.hostileMatrixExact, true);
  assert.equal(verification.claimBoundaryExact, true);
  assert.equal(verification.producerAgreement, true);
});

test('independently verifies exited-to-paused container drift as inconclusive before withheld', async () => {
  const clock = clocks();
  const { run, runPath } = await runH044({
    outputRoot: path.join(temporaryDirectory, 'container-state-drift'),
    wallNow: clock.wallNow,
    monotonicNowNs: clock.monotonicNowNs,
    runner: injectedRunner({ containerStates: ['exited', 'paused'] }),
    filesystem: filesystemFixture(),
  });
  assert.equal(run.liveClassification.disposition, 'inconclusive');
  assert.equal(run.liveClassification.reasonCode, 'container-or-pid1-identity-drift');
  const verification = await verifyRun(runPath);
  assert.equal(verification.outcome, 'inconclusive', JSON.stringify(verification));
  assert.equal(verification.stage, 'live-drift');
  assert.equal(verification.reasonCode, 'container-or-pid1-identity-drift');
  assert.equal(verification.commandAuditExact, true);
  assert.equal(verification.framesReconstructed, true);
  assert.equal(verification.frameCompletenessExact, true);
  assert.equal(verification.producerAgreement, true);
});

test('does not treat a serial substring suffix as an exact surface marker', async () => {
  const clock = clocks();
  const line =
    `2026-07-26T16:20:00.000000001Z ` + `Opening surface panel: streamdeck:${SERIAL}suffix\n`;
  const { run, runPath } = await runH044({
    outputRoot: path.join(temporaryDirectory, 'marker-substring'),
    wallNow: clock.wallNow,
    monotonicNowNs: clock.monotonicNowNs,
    runner: injectedRunner({ logLines: line }),
    filesystem: filesystemFixture(),
  });
  assert.deepEqual(
    run.frames.map((frame) => frame.markers.opening),
    [0, 0]
  );
  const verification = await verifyRun(runPath);
  assert.equal(verification.outcome, 'supported', JSON.stringify(verification));
  assert.equal(verification.commandAuditExact, true);
  assert.equal(verification.framesReconstructed, true);
  assert.equal(verification.producerAgreement, true);
});

test('rejects outer evidence hash tampering before semantic reconstruction', async () => {
  const fixturePath = await writeFixture(
    'evidence-tamper',
    (run) => {
      run.evidenceSha256 = '0'.repeat(64);
    },
    { rebind: false }
  );
  await assert.rejects(() => verifyRun(fixturePath), /evidence hash mismatch/u);
});

test('refutes a non-Unix Docker endpoint without trusting declared audit exactness', async () => {
  const fixturePath = await writeFixture('command-tamper', (run) => {
    const receipt = run.capabilityAudit.commandReceipts.find((entry) => entry.kind === 'dockerPs');
    receipt.args[1] = 'tcp://127.0.0.1:2375';
  });
  const verification = await verifyRun(fixturePath);
  assert.equal(verification.outcome, 'refuted');
  assert.equal(verification.stage, 'capability-boundary');
  assert.equal(verification.reasonCode, 'prohibited-capability-observed');
  assert.equal(verification.commandAuditExact, false);
});

test('refutes Docker inspect Running true with a contradictory paused status', async () => {
  const fixturePath = await writeFixture('inspect-status-contradiction', (run) => {
    const receipt = run.capabilityAudit.commandReceipts.find(
      (entry) => entry.kind === 'dockerInspect'
    );
    const inspected = JSON.parse(receipt.stdout.text);
    inspected.State.Status = 'paused';
    receipt.stdout = output(JSON.stringify(inspected));
  });
  const verification = await verifyRun(fixturePath);
  assert.equal(verification.outcome, 'refuted');
  assert.equal(verification.stage, 'independent-verification');
  assert.equal(verification.reasonCode, 'producer-verifier-disagreement');
  assert.equal(verification.commandAuditExact, false);
});

test('turns producer-classifier disagreement into a refuted verification', async () => {
  const fixturePath = await writeFixture('producer-disagreement', (run) => {
    run.liveClassification.reasonCode = 'producer-only-claim';
  });
  const verification = await verifyRun(fixturePath);
  assert.equal(verification.outcome, 'refuted');
  assert.equal(verification.stage, 'independent-verification');
  assert.equal(verification.reasonCode, 'producer-verifier-disagreement');
  assert.equal(verification.classificationExact, false);
  assert.equal(verification.producerAgreement, false);
});

test('refutes raw proc-byte tampering even when every nested digest is rebound', async () => {
  const fixturePath = await writeFixture('proc-byte-tamper', (run) => {
    const receipt = run.capabilityAudit.filesystemReceipts.find((entry) =>
      entry.path.endsWith('/73/stat')
    );
    const tampered = receipt.result.text.replace('7808716', '7808717');
    receipt.result = filesystemReadResult(tampered);
  });
  const verification = await verifyRun(fixturePath);
  assert.equal(verification.outcome, 'refuted');
  assert.equal(verification.stage, 'independent-verification');
  assert.equal(verification.framesReconstructed, false);
  assert.equal(verification.producerAgreement, false);
});

test('refutes an incomplete frame flipped to complete when a bound receipt records an error', async () => {
  const fixturePath = await writeFixture('forged-frame-complete', (run) => {
    const receipts = run.capabilityAudit.filesystemReceipts;
    const previous = receipts.at(-1);
    const frame = run.frames[1];
    const index = receipts.length;
    const operation = 'readFileSync';
    const operationCardinality =
      receipts.filter((receipt) => receipt.operation === operation).length + 1;
    frame.complete = false;
    receipts.push({
      index,
      operation,
      path: '/proc/self/mountinfo',
      startedAt: previous.endedAt,
      endedAt: previous.endedAt,
      startedMonotonicNs: previous.endedMonotonicNs,
      endedMonotonicNs: previous.endedMonotonicNs,
      durationNs: '0',
      disposition: 'error',
      result: {
        cardinality: 0,
        sha256: sha256(Buffer.alloc(0)),
      },
      errorCode: 'EIO',
      cardinality: {
        global: index + 1,
        operation: operationCardinality,
      },
    });
    run.capabilityAudit.filesystemReceiptCount = receipts.length;
    frame.auditBinding.filesystemReceiptIndexes.push(index);

    // Model the hostile producer tamper: discard the independently observable
    // incomplete state, declare complete, then reseal all producer decisions.
    frame.complete = true;
    Object.assign(frame, sealFrame(frame));
    run.liveClassification = classifyLiveFrames({
      historicalCandidate: run.historicalCandidate,
      frames: run.frames,
      capabilityAudit: run.capabilityAudit,
      sourceAdmissionExact: true,
    });
    assert.equal(run.liveClassification.disposition, 'candidate');
    run.outcome = outcomeFor(
      run.sourceAdmission,
      run.capabilityAudit,
      run.liveClassification,
      run.hostileMatrix
    );
    assert.equal(run.outcome.status, 'supported');
  });
  const verification = await verifyRun(fixturePath);
  assert.equal(verification.filesystemAuditExact, true);
  assert.equal(verification.framesReconstructed, true);
  assert.equal(verification.frameCompletenessExact, false);
  assert.deepEqual(verification.recomputedFrameCompleteness, [true, false]);
  assert.equal(verification.outcome, 'refuted');
  assert.equal(verification.stage, 'independent-verification');
  assert.equal(verification.reasonCode, 'producer-verifier-disagreement');
});

test('refutes declared device absence when the audited lsusb and sysfs transcript still sees it', async () => {
  const fixturePath = await writeFixture('contradictory-device-absence', (run) => {
    for (const frame of run.frames) {
      frame.device = { complete: true, present: false, identity: null };
      Object.assign(frame, sealFrame(frame));
    }
    run.liveClassification = classifyLiveFrames({
      historicalCandidate: run.historicalCandidate,
      frames: run.frames,
      capabilityAudit: run.capabilityAudit,
      sourceAdmissionExact: true,
    });
    assert.equal(run.liveClassification.disposition, 'withheld');
  });
  const verification = await verifyRun(fixturePath);
  assert.equal(verification.outcome, 'refuted');
  assert.equal(verification.framesReconstructed, false);
  assert.equal(verification.commandAuditExact, false);
});

test('triple-locks claim boundary and refutes hostile-matrix oracle drift', async () => {
  assert.notStrictEqual(INDEPENDENT_CLAIM_BOUNDARY, H044_CLAIM_BOUNDARY);
  assert.deepEqual(INDEPENDENT_CLAIM_BOUNDARY, H044_CLAIM_BOUNDARY);
  const fixturePath = await writeFixture('matrix-drift', (run) => {
    run.hostileMatrix.cases[0].inputSha256 = '0'.repeat(64);
  });
  const verification = await verifyRun(fixturePath);
  assert.equal(verification.outcome, 'refuted');
  assert.equal(verification.stage, 'hostile-matrix');
  assert.equal(verification.reasonCode, 'hostile-case-failed');
  assert.equal(verification.hostileMatrixExact, false);
});
