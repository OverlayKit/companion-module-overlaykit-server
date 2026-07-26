import { readFile, readlink } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { command } from '../h034/lib/util.mjs';
import { parseProcStartTicks } from '../h039/reconnect-lib.mjs';
import {
  countAcquisitionMarkers,
  descriptorMatchesDynamicNode,
} from '../h041/reacquisition-lib.mjs';
import { rfc3339NanoToEpochNs } from './signal-lib.mjs';

export const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
export const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
export const H041_DIRECTORY = path.resolve(LAB_DIRECTORY, '../h041');
export const OFFICIAL_IMAGE =
  'ghcr.io/bitfocus/companion/companion:v4.3.3@sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e';
export const EXPECTED_IMAGE_ID =
  'sha256:e7d24e3b0e32b0edb799f262493536cb1a47d307af4e6527551427e09266bf10';
export const EXPECTED_IMAGE_REVISION = '06a7406709d6a858039333a8988047296ef3aa4a';
export const DYNAMIC_ROOT = '/host-dev';
export const CONTAINER_ENTRYPOINT = '/h041-entrypoint.sh';
export const CONTAINER_OBSERVER = '/h041-container-observer.mjs';
export const CONTAINER_SIGNAL_HELPER = '/h042-signal-helper.mjs';
export const HEALTHCHECK_COMMAND =
  'sh -c curl -fSsq http://localhost:${COMPANION_ADMIN_PORT:-8000}/';

export const H042_REQUIRED_SOURCES = Object.freeze(
  [
    '.overlaykit/governance/changes/CHG-0012.json',
    '.overlaykit/governance/changes/CHG-0013.json',
    'lab/h034/lib/util.mjs',
    'lab/h035/inventory-lib.mjs',
    'lab/h037/acquisition-lib.mjs',
    'lab/h038/physical-lib.mjs',
    'lab/h039/host-observer.mjs',
    'lab/h039/reconnect-lib.mjs',
    'lab/h039/schemas/reconnect-run.schema.json',
    'lab/h039/verify.mjs',
    'lab/h040/probe-lib.mjs',
    'lab/h040/schemas/docker-mapping-run.schema.json',
    'lab/h040/verify.mjs',
    'lab/h041/container-observer.mjs',
    'lab/h041/container-observer.test.mjs',
    'lab/h041/entrypoint.sh',
    'lab/h041/host-inventory.mjs',
    'lab/h041/host-inventory.test.mjs',
    'lab/h041/reacquisition-lib.mjs',
    'lab/h041/reacquisition-lib.test.mjs',
    'lab/h041/run.mjs',
    'lab/h041/schema.test.mjs',
    'lab/h041/schemas/dynamic-reacquisition-run.schema.json',
    'lab/h041/verify.mjs',
    'lab/h041/verify.test.mjs',
    'lab/h042/runtime-lib.mjs',
    'lab/h042/runtime-lib.test.mjs',
    'lab/h042/schema.test.mjs',
    'lab/h042/schemas/surface-worker-recycle-run.schema.json',
    'lab/h042/signal-helper.mjs',
    'lab/h042/signal-helper.test.mjs',
    'lab/h042/signal-lib.mjs',
    'lab/h042/signal-lib.test.mjs',
    'lab/h042/run.mjs',
    'lab/h042/run.test.mjs',
    'lab/h042/verify.mjs',
    'lab/h042/verify.test.mjs',
  ].sort()
);

export function auditEntry(entries, entry) {
  entries.push({
    at: new Date().toISOString(),
    monotonicNs: process.hrtime.bigint().toString(),
    ...entry,
  });
}

function timestampedLines(text, stream) {
  return text
    .split(/\r?\n/u)
    .filter(Boolean)
    .map((line, index) => {
      const separator = line.indexOf(' ');
      const timestamp = separator > 0 ? line.slice(0, separator) : '';
      return {
        line,
        stream,
        index,
        timestamp,
        nanoseconds: rfc3339NanoToEpochNs(timestamp),
      };
    });
}

export function normalizeDockerLogs(stdout, stderr) {
  const records = [...timestampedLines(stdout, 'stdout'), ...timestampedLines(stderr, 'stderr')];
  if (records.some((entry) => entry.nanoseconds === null)) {
    throw new Error('H-042 docker logs contain a line without an RFC3339Nano timestamp');
  }
  records.sort((left, right) => {
    if (left.nanoseconds < right.nanoseconds) return -1;
    if (left.nanoseconds > right.nanoseconds) return 1;
    if (left.stream !== right.stream) return left.stream.localeCompare(right.stream);
    return left.index - right.index;
  });
  for (let index = 1; index < records.length; index += 1) {
    const previous = records[index - 1];
    const current = records[index];
    const acquisitionRelevant = (entry) =>
      entry.line.includes('Opening surface panel:') || entry.line.includes('Surface panel ready:');
    if (
      previous.nanoseconds === current.nanoseconds &&
      previous.stream !== current.stream &&
      (acquisitionRelevant(previous) || acquisitionRelevant(current))
    ) {
      throw new Error(
        'H-042 cannot order acquisition markers with equal cross-stream Docker timestamps'
      );
    }
  }
  return {
    text: `${records.map((entry) => entry.line).join('\n')}\n`,
    records: records.map(({ nanoseconds, ...entry }) => ({
      ...entry,
      epochNanoseconds: nanoseconds.toString(),
    })),
  };
}

export function buildDockerRunArguments({
  containerName,
  dynamicPath,
  compatibilityPath,
  deviceGid,
  cgroupRule,
}) {
  return [
    'run',
    '--detach',
    '--rm',
    '--name',
    containerName,
    '--label',
    'dev.overlaykit.hypothesis=H-042',
    '--network',
    'none',
    '--cgroupns',
    'private',
    '--read-only',
    '--tmpfs',
    '/companion:rw,nosuid,nodev,noexec,size=268435456,uid=1000,gid=1000,mode=0700',
    '--tmpfs',
    '/tmp:rw,nosuid,nodev,size=67108864,uid=1000,gid=1000,mode=1777',
    '--cap-drop',
    'ALL',
    '--cap-add',
    'SETUID',
    '--cap-add',
    'SETGID',
    '--security-opt',
    'no-new-privileges',
    '--pids-limit',
    '128',
    '--memory',
    '1g',
    '--user',
    '0:0',
    '--group-add',
    String(deviceGid),
    '--device-cgroup-rule',
    cgroupRule,
    '--mount',
    `type=bind,src=/dev,dst=${DYNAMIC_ROOT},readonly,bind-recursive=disabled`,
    '--mount',
    `type=bind,src=${path.join(H041_DIRECTORY, 'entrypoint.sh')},dst=${CONTAINER_ENTRYPOINT},readonly`,
    '--mount',
    `type=bind,src=${path.join(H041_DIRECTORY, 'container-observer.mjs')},dst=${CONTAINER_OBSERVER},readonly`,
    '--mount',
    `type=bind,src=${path.join(LAB_DIRECTORY, 'signal-helper.mjs')},dst=${CONTAINER_SIGNAL_HELPER},readonly`,
    '--env',
    'H041_UID=1000',
    '--env',
    'H041_GID=1000',
    '--env',
    `H041_DEVICE_GID=${deviceGid}`,
    '--env',
    `H041_DYNAMIC_PATH=${dynamicPath}`,
    '--env',
    `H041_COMPAT_PATH=${compatibilityPath}`,
    '--entrypoint',
    '/bin/bash',
    OFFICIAL_IMAGE,
    CONTAINER_ENTRYPOINT,
  ];
}

export async function inspectCompanion(containerName, entries, phase) {
  auditEntry(entries, {
    kind: 'docker-inspect',
    phase,
    target: containerName,
    operation: 'metadata',
  });
  const inspected = JSON.parse((await command('docker', ['inspect', containerName])).stdout)[0];
  if (!inspected?.State?.Running || !Number.isSafeInteger(inspected.State.Pid)) {
    throw new Error(`H-042 Companion container is not running at ${phase}`);
  }
  const hostPid = inspected.State.Pid;
  const [procStat, pidNs, mountNs, cgroup] = await Promise.all([
    readFile(`/proc/${hostPid}/stat`, 'utf8'),
    readlink(`/proc/${hostPid}/ns/pid`),
    readlink(`/proc/${hostPid}/ns/mnt`),
    readFile(`/proc/${hostPid}/cgroup`, 'utf8'),
  ]);
  const mounts = (inspected.Mounts ?? []).map((entry) => ({
    type: entry.Type,
    source: entry.Source,
    destination: entry.Destination,
    rw: entry.RW,
    propagation: entry.Propagation ?? '',
  }));
  const declaredMounts = (inspected.HostConfig?.Mounts ?? []).map((entry) => ({
    type: entry.Type,
    source: entry.Source,
    target: entry.Target,
    readOnly: entry.ReadOnly ?? false,
    bindOptions: entry.BindOptions ?? null,
  }));
  return {
    containerId: inspected.Id,
    name: inspected.Name?.replace(/^\//u, '') ?? containerName,
    imageId: inspected.Image,
    running: inspected.State.Running,
    healthy: inspected.State.Health?.Status === 'healthy',
    healthStatus: inspected.State.Health?.Status ?? null,
    startedAt: inspected.State.StartedAt,
    restartCount: inspected.RestartCount,
    hostPid,
    hostPidStartTicks: parseProcStartTicks(procStat.trim()),
    hostPidNamespace: pidNs,
    hostMountNamespace: mountNs,
    hostCgroup: cgroup.trim(),
    cgroupNamespaceMode: inspected.HostConfig?.CgroupnsMode ?? null,
    restartPolicy: inspected.HostConfig?.RestartPolicy?.Name ?? null,
    autoRemove: inspected.HostConfig?.AutoRemove ?? false,
    networkMode: inspected.HostConfig?.NetworkMode ?? null,
    privileged: inspected.HostConfig?.Privileged ?? null,
    readOnlyRootfs: inspected.HostConfig?.ReadonlyRootfs ?? false,
    capAdd: inspected.HostConfig?.CapAdd ?? [],
    capDrop: inspected.HostConfig?.CapDrop ?? [],
    securityOpt: inspected.HostConfig?.SecurityOpt ?? [],
    groupAdd: inspected.HostConfig?.GroupAdd ?? [],
    pidsLimit: inspected.HostConfig?.PidsLimit ?? null,
    memory: inspected.HostConfig?.Memory ?? null,
    deviceCgroupRules: inspected.HostConfig?.DeviceCgroupRules ?? [],
    devices: inspected.HostConfig?.Devices ?? [],
    tmpfs: inspected.HostConfig?.Tmpfs ?? {},
    user: inspected.Config?.User ?? null,
    environment: inspected.Config?.Env ?? [],
    labels: inspected.Config?.Labels ?? {},
    entrypoint: inspected.Config?.Entrypoint ?? [],
    command: inspected.Config?.Cmd ?? [],
    mounts,
    declaredMounts,
  };
}

export function flattenLifecycle(container, observer) {
  return {
    containerId: container.containerId,
    imageId: container.imageId,
    startedAt: container.startedAt,
    restartCount: container.restartCount,
    hostPid: container.hostPid,
    pid1StartTicks: observer.pid1.startTicks,
    pidNamespace: observer.pid1.pidNamespace,
    mountNamespace: observer.pid1.mountNamespace,
    cgroup: observer.pid1.cgroup,
    hostCgroup: container.hostCgroup,
    cgroupNamespaceMode: container.cgroupNamespaceMode,
  };
}

export async function observeContainer(
  containerName,
  { dynamicPath, compatibilityPath, major, minor, serial, phase },
  entries
) {
  auditEntry(entries, {
    kind: 'docker-exec-observer',
    phase,
    target: containerName,
    user: '1000:1000',
    command: ['/app/node-runtimes/main/bin/node', CONTAINER_OBSERVER],
    operation: 'proc-fd-stat-only',
  });
  const observerCommand = command('docker', [
    'exec',
    '--user',
    '1000:1000',
    '--env',
    `H041_DYNAMIC_PATH=${dynamicPath}`,
    '--env',
    `H041_COMPAT_PATH=${compatibilityPath}`,
    '--env',
    `H041_DEVICE_MAJOR=${major}`,
    '--env',
    `H041_DEVICE_MINOR=${minor}`,
    containerName,
    '/app/node-runtimes/main/bin/node',
    CONTAINER_OBSERVER,
  ]);
  auditEntry(entries, {
    kind: 'docker-logs',
    phase,
    target: containerName,
    operation: 'read-container-stdout-stderr',
  });
  const [observed, logs, container] = await Promise.all([
    observerCommand,
    command('docker', ['logs', '--timestamps', containerName]),
    inspectCompanion(containerName, entries, phase),
  ]);
  const observer = JSON.parse(observed.stdout);
  if (
    observer.schemaVersion !== 'overlaykit-h041-container-observation/v1' ||
    observer.metadataOnly !== true
  ) {
    throw new Error(`H-042 container observer receipt is invalid at ${phase}`);
  }
  const revalidatedContainer = await inspectCompanion(
    containerName,
    entries,
    `${phase}-revalidate`
  );
  if (
    container.containerId !== revalidatedContainer.containerId ||
    container.startedAt !== revalidatedContainer.startedAt ||
    container.restartCount !== revalidatedContainer.restartCount ||
    container.hostPid !== revalidatedContainer.hostPid ||
    container.hostPidStartTicks !== revalidatedContainer.hostPidStartTicks ||
    revalidatedContainer.hostPidStartTicks !== observer.pid1.startTicks ||
    revalidatedContainer.hostPidNamespace !== observer.pid1.pidNamespace ||
    revalidatedContainer.hostMountNamespace !== observer.pid1.mountNamespace
  ) {
    throw new Error(`H-042 runtime identity changed during observation at ${phase}`);
  }
  const normalizedLogs = normalizeDockerLogs(logs.stdout, logs.stderr);
  return {
    capturedAt: new Date().toISOString(),
    monotonicNs: process.hrtime.bigint().toString(),
    phase,
    container: revalidatedContainer,
    lifecycle: flattenLifecycle(revalidatedContainer, observer),
    observer,
    logText: normalizedLogs.text,
    logRecords: normalizedLogs.records,
    markers: countAcquisitionMarkers(normalizedLogs.text, serial, [compatibilityPath, dynamicPath]),
  };
}

export function targetDescriptors(runtime) {
  return runtime.observer.surfaceWorkers.flatMap((worker) =>
    worker.fileDescriptors.filter((descriptor) =>
      descriptorMatchesDynamicNode(descriptor, runtime.observer.paths.dynamic.stat)
    )
  );
}

export function baselineAcquired(runtime) {
  return (
    runtime.observer.surfaceWorkers.length === 1 &&
    runtime.markers.opening > 0 &&
    runtime.markers.ready > 0 &&
    targetDescriptors(runtime).length > 0 &&
    runtime.observer.pid1.uid === 1000 &&
    runtime.observer.pid1.gid === 1000
  );
}

export function descriptorAbsent(runtime) {
  return (
    runtime.observer.paths.dynamic.stat.kind === 'missing' &&
    runtime.observer.paths.compat.stat.kind === 'missing' &&
    runtime.observer.surfaceWorkers.every((worker) => worker.fileDescriptors.length === 0)
  );
}

function optionSet(value) {
  return typeof value === 'string' ? [...value.split(',')].sort().join(',') : null;
}

export function permissionBoundaryExact(runtime, expected) {
  const { container, observer } = runtime;
  const environment = Object.fromEntries(
    container.environment.map((entry) => {
      const separator = entry.indexOf('=');
      return [entry.slice(0, separator), entry.slice(separator + 1)];
    })
  );
  const expectedMounts = [
    [DYNAMIC_ROOT, '/dev'],
    [CONTAINER_ENTRYPOINT, path.join(H041_DIRECTORY, 'entrypoint.sh')],
    [CONTAINER_OBSERVER, path.join(H041_DIRECTORY, 'container-observer.mjs')],
    [CONTAINER_SIGNAL_HELPER, path.join(LAB_DIRECTORY, 'signal-helper.mjs')],
  ];
  return (
    container.imageId === EXPECTED_IMAGE_ID &&
    container.restartPolicy === 'no' &&
    container.autoRemove === true &&
    container.networkMode === 'none' &&
    container.cgroupNamespaceMode === 'private' &&
    container.privileged === false &&
    container.readOnlyRootfs === true &&
    JSON.stringify([...container.capAdd].sort()) === JSON.stringify(['CAP_SETGID', 'CAP_SETUID']) &&
    JSON.stringify(container.capDrop) === JSON.stringify(['ALL']) &&
    JSON.stringify([...container.securityOpt].sort()) === JSON.stringify(['no-new-privileges']) &&
    JSON.stringify(container.groupAdd.map(Number).sort((left, right) => left - right)) ===
      JSON.stringify([expected.deviceGid]) &&
    container.pidsLimit === 128 &&
    container.memory === 1024 * 1024 * 1024 &&
    JSON.stringify(container.deviceCgroupRules) === JSON.stringify([expected.cgroupRule]) &&
    container.devices.length === 0 &&
    JSON.stringify(Object.keys(container.tmpfs).sort()) ===
      JSON.stringify(['/companion', '/tmp']) &&
    optionSet(container.tmpfs['/companion']) ===
      optionSet('rw,nosuid,nodev,noexec,size=268435456,uid=1000,gid=1000,mode=0700') &&
    optionSet(container.tmpfs['/tmp']) ===
      optionSet('rw,nosuid,nodev,size=67108864,uid=1000,gid=1000,mode=1777') &&
    container.user === '0:0' &&
    environment.COMPANION_CONFIG_BASEDIR === '/companion' &&
    environment.H041_UID === '1000' &&
    environment.H041_GID === '1000' &&
    environment.H041_DEVICE_GID === String(expected.deviceGid) &&
    environment.H041_DYNAMIC_PATH === expected.dynamicPath &&
    environment.H041_COMPAT_PATH === observer.paths.compat.path &&
    !Object.keys(environment).some((key) => key.includes('OVERLAYKIT')) &&
    container.labels['dev.overlaykit.hypothesis'] === 'H-042' &&
    JSON.stringify(container.entrypoint) === JSON.stringify(['/bin/bash']) &&
    JSON.stringify(container.command) === JSON.stringify([CONTAINER_ENTRYPOINT]) &&
    container.mounts.length === expectedMounts.length &&
    container.declaredMounts.length === expectedMounts.length &&
    expectedMounts.every(([destination, source]) =>
      container.mounts.some(
        (entry) =>
          entry.type === 'bind' &&
          entry.destination === destination &&
          entry.source === source &&
          entry.rw === false &&
          entry.propagation === 'rprivate'
      )
    ) &&
    expectedMounts.every(([target, source]) =>
      container.declaredMounts.some(
        (entry) =>
          entry.type === 'bind' &&
          entry.source === source &&
          entry.target === target &&
          entry.readOnly === true &&
          (target !== DYNAMIC_ROOT || entry.bindOptions?.NonRecursive === true)
      )
    ) &&
    observer.pid1.uid === 1000 &&
    observer.pid1.gid === 1000 &&
    JSON.stringify([...observer.pid1.groups].sort((left, right) => left - right)) ===
      JSON.stringify([1000, expected.deviceGid].sort((left, right) => left - right)) &&
    observer.paths.compat.lstat.kind === 'value' &&
    observer.paths.compat.lstat.value.isSymbolicLink === true &&
    observer.paths.compat.linkTarget === expected.dynamicPath
  );
}

export function runtimePollText(runtimePolls) {
  return `${runtimePolls
    .map(({ logText: _logText, logRecords: _logRecords, ...entry }) => JSON.stringify(entry))
    .join('\n')}\n`;
}

export function parseDockerEvents(text) {
  return text
    .split(/\r?\n/u)
    .filter(Boolean)
    .map((line) => JSON.parse(line.replace(/("timeNano"\s*:\s*)([0-9]+)/u, '$1"$2"')))
    .map((event) => ({
      type: event.Type,
      action: event.Action,
      status: event.status ?? null,
      id: event.id ?? event.Actor?.ID ?? null,
      time: event.time ?? null,
      timeNano:
        typeof event.timeNano === 'string' && /^[0-9]+$/u.test(event.timeNano)
          ? event.timeNano
          : null,
      attributes: event.Actor?.Attributes ?? {},
    }));
}

function isExecEvent(event) {
  return (
    event.action === 'exec_die' ||
    event.action.startsWith('exec_create: ') ||
    event.action.startsWith('exec_start: ')
  );
}

function isKnownHealthStatusEvent(event) {
  return ['health_status: starting', 'health_status: healthy'].includes(event.action);
}

function analyzeExecEnvelope(events, commands) {
  const execEvents = events.filter(isExecEvent);
  const creates = execEvents.filter((event) => event.action.startsWith('exec_create: '));
  const records = creates.map((created) => {
    const command = created.action.slice('exec_create: '.length);
    const kind = commands.get(command) ?? null;
    const execId = typeof created.attributes.execID === 'string' ? created.attributes.execID : null;
    const duplicateCreateCount =
      execId === null
        ? 0
        : creates.filter((candidate) => candidate.attributes.execID === execId).length;
    const starts =
      execId === null
        ? []
        : execEvents.filter(
            (event) =>
              event.action === `exec_start: ${command}` && event.attributes.execID === execId
          );
    const dies =
      execId === null
        ? []
        : execEvents.filter(
            (event) =>
              event.action === 'exec_die' &&
              event.attributes.execID === execId &&
              event.attributes.exitCode === '0'
          );
    const ordered =
      [created, ...starts, ...dies].every(
        (event) => typeof event.timeNano === 'string' && /^[0-9]+$/u.test(event.timeNano)
      ) &&
      starts.length === 1 &&
      dies.length === 1 &&
      BigInt(created.timeNano) < BigInt(starts[0].timeNano) &&
      BigInt(starts[0].timeNano) < BigInt(dies[0].timeNano);
    return {
      command,
      kind,
      execId,
      created,
      starts,
      dies,
      complete:
        kind !== null &&
        execId !== null &&
        duplicateCreateCount === 1 &&
        starts.length === 1 &&
        dies.length === 1 &&
        ordered,
    };
  });
  const unknownExecEvents = execEvents.filter((event) => {
    const execId = typeof event.attributes.execID === 'string' ? event.attributes.execID : null;
    if (execId === null) return true;
    const matchingCreates = records.filter((record) => record.execId === execId);
    if (matchingCreates.length !== 1 || matchingCreates[0].kind === null) return true;
    const [record] = matchingCreates;
    if (event.action.startsWith('exec_create: ')) return event !== record.created;
    if (event.action.startsWith('exec_start: ')) {
      return event.action !== `exec_start: ${record.command}`;
    }
    return event.action !== 'exec_die' || event.attributes.exitCode !== '0';
  });
  const incompleteExecIds = records
    .filter((record) => !record.complete)
    .map((record) => record.execId ?? '<missing>')
    .sort();
  return {
    execEvents,
    creates,
    records,
    unknownExecEvents,
    incompleteExecIds,
    complete: unknownExecEvents.length === 0 && incompleteExecIds.length === 0,
  };
}

function healthcheckSummary(analysis) {
  const records = analysis.records.filter((record) => record.kind === 'healthcheck');
  const complete = records.filter((record) => record.complete);
  return {
    command: HEALTHCHECK_COMMAND,
    createCount: records.length,
    tripletCount: complete.length,
    execIds: complete.map((record) => record.execId).sort(),
    complete: records.every((record) => record.complete),
  };
}

export function analyzeExperimentEvents(
  events,
  {
    containerId,
    helperCommand,
    observerCommand,
    expectedObserverExecCount,
    experimentStartedAt,
    experimentBoundaryAt,
  }
) {
  const startedNs = rfc3339NanoToEpochNs(experimentStartedAt);
  const boundaryNs = rfc3339NanoToEpochNs(experimentBoundaryAt);
  if (
    !Array.isArray(events) ||
    typeof containerId !== 'string' ||
    startedNs === null ||
    boundaryNs === null ||
    boundaryNs < startedNs
  ) {
    return { passed: false, reason: 'invalid-event-envelope' };
  }
  const unscopedEvents = events.filter(
    (event) => event.type !== 'container' || event.id !== containerId
  );
  const scoped = events.filter((event) => event.type === 'container' && event.id === containerId);
  const timestampsWithinWindow = scoped.every(
    (event) =>
      typeof event.timeNano === 'string' &&
      /^[0-9]+$/u.test(event.timeNano) &&
      BigInt(event.timeNano) >= startedNs &&
      BigInt(event.timeNano) <= boundaryNs
  );
  const execAnalysis = analyzeExecEnvelope(
    scoped,
    new Map([
      [helperCommand, 'helper'],
      [observerCommand, 'observer'],
      [HEALTHCHECK_COMMAND, 'healthcheck'],
    ])
  );
  const helperRecords = execAnalysis.records.filter((record) => record.kind === 'helper');
  const helperCreates = helperRecords.map((record) => record.created);
  const execId = helperCreates.length === 1 ? helperRecords[0].execId : null;
  const helperStarts = helperRecords.flatMap((record) => record.starts);
  const helperDies = helperRecords.flatMap((record) => record.dies);
  const forbiddenActions = scoped.filter((event) =>
    ['kill', 'stop', 'die', 'restart', 'destroy', 'oom'].includes(event.action)
  );
  const nonExecEvents = scoped.filter((event) => !isExecEvent(event));
  const create = nonExecEvents.filter((event) => event.action === 'create');
  const start = nonExecEvents.filter((event) => event.action === 'start');
  const healthStatusEvents = nonExecEvents.filter(isKnownHealthStatusEvent);
  const unexpectedActions = nonExecEvents.filter(
    (event) =>
      event.action !== 'create' && event.action !== 'start' && !isKnownHealthStatusEvent(event)
  );
  const containerStartExact =
    create.length === 1 &&
    start.length === 1 &&
    BigInt(create[0].timeNano) < BigInt(start[0].timeNano);
  const observerCreates = execAnalysis.records
    .filter((record) => record.kind === 'observer')
    .map((record) => record.created);
  const execBoundaryExact =
    Number.isSafeInteger(expectedObserverExecCount) &&
    expectedObserverExecCount >= 0 &&
    helperCreates.length === 1 &&
    observerCreates.length === expectedObserverExecCount &&
    execAnalysis.complete;
  const ordered = helperRecords.length === 1 && helperRecords[0].complete;
  return {
    passed:
      ordered &&
      forbiddenActions.length === 0 &&
      execBoundaryExact &&
      unscopedEvents.length === 0 &&
      timestampsWithinWindow &&
      containerStartExact &&
      unexpectedActions.length === 0,
    experimentStartedAt,
    experimentBoundaryAt,
    execId,
    helperCreateCount: helperCreates.length,
    helperStartCount: helperStarts.length,
    helperDieZeroCount: helperDies.length,
    ordered,
    forbiddenActions,
    containerStartExact,
    healthStatusEvents,
    unexpectedActions,
    execCreateCount: execAnalysis.creates.length,
    observerExecCount: observerCreates.length,
    healthcheck: healthcheckSummary(execAnalysis),
    unknownExecEvents: execAnalysis.unknownExecEvents,
    incompleteExecIds: execAnalysis.incompleteExecIds,
    unscopedEvents,
    timestampsWithinWindow,
    execBoundaryExact,
  };
}

export function analyzeCleanupEvents(
  events,
  { containerId, experimentBoundaryAt, classifiedAt, eventsUntilAt }
) {
  const boundaryNs = rfc3339NanoToEpochNs(experimentBoundaryAt);
  const classifiedNs = rfc3339NanoToEpochNs(classifiedAt);
  const untilNs = rfc3339NanoToEpochNs(eventsUntilAt);
  if (
    !Array.isArray(events) ||
    typeof containerId !== 'string' ||
    boundaryNs === null ||
    classifiedNs === null ||
    untilNs === null ||
    classifiedNs < boundaryNs ||
    untilNs < classifiedNs
  ) {
    return { passed: false, reason: 'invalid-cleanup-event-envelope' };
  }
  const unscopedEvents = events.filter(
    (event) => event.type !== 'container' || event.id !== containerId
  );
  const scoped = events.filter((event) => event.type === 'container' && event.id === containerId);
  const timestampsValid = scoped.every(
    (event) =>
      typeof event.timeNano === 'string' &&
      /^[0-9]+$/u.test(event.timeNano) &&
      BigInt(event.timeNano) > boundaryNs &&
      BigInt(event.timeNano) <= untilNs
  );
  const gapEvents = timestampsValid
    ? scoped.filter((event) => BigInt(event.timeNano) <= classifiedNs)
    : [];
  const cleanupEvents = timestampsValid
    ? scoped.filter((event) => BigInt(event.timeNano) > classifiedNs)
    : [];
  const healthcheckCommands = new Map([[HEALTHCHECK_COMMAND, 'healthcheck']]);
  const gapExec = analyzeExecEnvelope(gapEvents, healthcheckCommands);
  const cleanupExec = analyzeExecEnvelope(cleanupEvents, healthcheckCommands);
  const gapNonExec = gapEvents.filter((event) => !isExecEvent(event));
  const gapHealthStatusEvents = gapNonExec.filter(isKnownHealthStatusEvent);
  const gapUnknownActions = gapNonExec.filter((event) => !isKnownHealthStatusEvent(event));
  const cleanupNonExec = cleanupEvents.filter((event) => !isExecEvent(event));
  const cleanupHealthStatusEvents = cleanupNonExec.filter(isKnownHealthStatusEvent);
  const cleanupLifecycleEvents = cleanupNonExec.filter((event) => !isKnownHealthStatusEvent(event));
  const exact = (action) => cleanupLifecycleEvents.filter((event) => event.action === action);
  const stop = exact('stop');
  const die = exact('die');
  const destroy = exact('destroy');
  const kill = exact('kill');
  const kill15 = kill.filter((event) => event.attributes.signal === '15');
  const kill9 = kill.filter((event) => event.attributes.signal === '9');
  const unknownCleanupActions = cleanupLifecycleEvents.filter(
    (event) => !['kill', 'die', 'stop', 'destroy'].includes(event.action)
  );
  const lifecycleTimestampsValid = cleanupLifecycleEvents.every(
    (event) =>
      typeof event.timeNano === 'string' &&
      /^[0-9]+$/u.test(event.timeNano) &&
      BigInt(event.timeNano) > classifiedNs
  );
  const lifecycleOrdered =
    stop.length === 1 &&
    die.length === 1 &&
    die[0].attributes.exitCode === '137' &&
    destroy.length === 1 &&
    kill.length === 2 &&
    kill15.length === 1 &&
    kill9.length === 1 &&
    lifecycleTimestampsValid &&
    BigInt(kill15[0].timeNano) < BigInt(kill9[0].timeNano) &&
    BigInt(kill9[0].timeNano) < BigInt(stop[0].timeNano) &&
    BigInt(stop[0].timeNano) < BigInt(die[0].timeNano) &&
    BigInt(die[0].timeNano) < BigInt(destroy[0].timeNano);
  const gapBoundaryExact = gapExec.complete && gapUnknownActions.length === 0;
  const cleanupBoundaryExact =
    cleanupExec.complete && unknownCleanupActions.length === 0 && lifecycleOrdered;
  return {
    passed:
      scoped.length > 0 &&
      timestampsValid &&
      unscopedEvents.length === 0 &&
      gapBoundaryExact &&
      cleanupBoundaryExact,
    experimentBoundaryAt,
    classifiedAt,
    eventsUntilAt,
    eventCount: scoped.length,
    timestampsValid,
    unscopedEvents,
    gap: {
      eventCount: gapEvents.length,
      healthcheck: healthcheckSummary(gapExec),
      healthStatusEvents: gapHealthStatusEvents,
      unknownExecEvents: gapExec.unknownExecEvents,
      incompleteExecIds: gapExec.incompleteExecIds,
      unknownActions: gapUnknownActions,
      boundaryExact: gapBoundaryExact,
    },
    cleanup: {
      eventCount: cleanupEvents.length,
      stopCount: stop.length,
      dieCount: die.length,
      destroyCount: destroy.length,
      killCount: kill.length,
      kill15Count: kill15.length,
      kill9Count: kill9.length,
      dieExitCode: die.length === 1 ? (die[0].attributes.exitCode ?? null) : null,
      healthcheck: healthcheckSummary(cleanupExec),
      healthStatusEvents: cleanupHealthStatusEvents,
      unknownExecEvents: cleanupExec.unknownExecEvents,
      incompleteExecIds: cleanupExec.incompleteExecIds,
      unknownActions: unknownCleanupActions,
      lifecycleOrdered,
      boundaryExact: cleanupBoundaryExact,
    },
  };
}

export function invocationAudit(entries) {
  const allowed = new Set([
    'docker-run',
    'docker-inspect',
    'docker-exec-observer',
    'docker-logs',
    'physical-disconnect-window',
    'physical-reconnect-window',
    'docker-exec-signal',
    'experiment-classified',
    'docker-events-experiment',
    'docker-stop',
    'docker-ps-cleanup',
    'docker-events-cleanup',
  ]);
  const forbidden = entries.filter((entry) => !allowed.has(entry.kind));
  const signals = entries.filter((entry) => entry.kind === 'docker-exec-signal');
  const byKind = (kind) => entries.filter((entry) => entry.kind === kind);
  const cleanup = byKind('docker-stop')[0];
  const classification = byKind('experiment-classified')[0];
  const cleanupAfterClassification =
    classification !== undefined &&
    cleanup !== undefined &&
    BigInt(cleanup.monotonicNs) > BigInt(classification.monotonicNs);
  const signalExact =
    signals.length === 1 &&
    signals[0].signal === 'SIGTERM' &&
    signals[0].user === '1000:1000' &&
    signals[0].exitCode === 0 &&
    Array.isArray(signals[0].command) &&
    signals[0].command.at(-1) === CONTAINER_SIGNAL_HELPER;
  const exactCardinality =
    byKind('docker-run').length === 1 &&
    byKind('physical-disconnect-window').length === 1 &&
    byKind('physical-reconnect-window').length === 1 &&
    signals.length === 1 &&
    byKind('docker-events-experiment').length === 1 &&
    byKind('experiment-classified').length === 1 &&
    byKind('docker-stop').length === 1 &&
    byKind('docker-ps-cleanup').length === 1 &&
    byKind('docker-events-cleanup').length === 1;
  const strictChronology = entries.every(
    (entry, index) =>
      typeof entry.monotonicNs === 'string' &&
      /^[0-9]+$/u.test(entry.monotonicNs) &&
      (index === 0 || BigInt(entry.monotonicNs) > BigInt(entries[index - 1].monotonicNs))
  );
  const causalKinds = [
    'docker-run',
    'physical-disconnect-window',
    'physical-reconnect-window',
    'docker-exec-signal',
    'docker-events-experiment',
    'experiment-classified',
    'docker-stop',
    'docker-ps-cleanup',
    'docker-events-cleanup',
  ];
  const causalEntries = causalKinds.map((kind) => byKind(kind)[0]);
  const causalOrder =
    causalEntries.every((entry) => entry !== undefined) &&
    causalEntries.every(
      (entry, index) =>
        index === 0 || BigInt(entry.monotonicNs) > BigInt(causalEntries[index - 1].monotonicNs)
    );
  return {
    mode: 'metadata-observation-plus-one-source-bound-surface-sigterm',
    entries,
    forbidden,
    signalCount: signals.length,
    signalExact,
    exactCardinality,
    strictChronology,
    causalOrder,
    cleanupAfterClassification,
    runnerDeviceOpenCount: entries.filter((entry) => entry.kind === 'device-open').length,
    runnerDeviceReadCount: entries.filter((entry) => entry.kind === 'device-read').length,
    runnerDeviceWriteCount: entries.filter((entry) => entry.kind === 'device-write').length,
    virtualInvocationCount: entries.filter((entry) => entry.kind === 'virtual-press').length,
    forbiddenLifecycleCount: entries.filter((entry) =>
      ['docker-kill', 'docker-restart', 'docker-recreate', 'companion-rescan'].includes(entry.kind)
    ).length,
    passed:
      forbidden.length === 0 &&
      signalExact &&
      exactCardinality &&
      strictChronology &&
      causalOrder &&
      cleanupAfterClassification,
  };
}
